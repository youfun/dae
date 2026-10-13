# Landscape Flow Edge PoC

dae stays a kernel eBPF proxy. This PoC only adds a container-side adapter so a **new** Landscape flow can hand packets to that datapath. It does not replace Mihomo, and it does not attach dae to the router host LAN or WAN.

## Boundary

```diagram
Landscape host                         dae-edge container netns
┌─────────────────────┐                ┌──────────────────────────────┐
│ new test flow only  │ VLAN 0xc00|id  │ eth0 ingress                 │
│ Mihomo flow 1 stays │───────────────▶│ pref 1 adapter pop + UNSPEC  │
└─────────────────────┘                │ pref 2 dae LAN ingress       │
                                       └──────────────┬───────────────┘
                                                      ┃ proxy / direct
                                                      ▼
                                                 container eth0 egress
```

Landscape pushes an skb VLAN tag with `bpf_skb_vlan_push(skb, ETH_P_8021Q, 0xc00|flow_id)` and redirects into the container veth. The official route handler pops that tag and returns `TC_ACT_OK`, which ends direct-action classification, so dae never sees the packet. The adapter uses the same pop, then returns `TC_ACT_UNSPEC`.

The adapter does not know flow ids. Flow 1 and the new test flow are distinguished only by which Docker target Landscape installs. A stopped or unregistered `dae-edge` can blackhole only the flow whose target points at it.

## What is generic in dae

`global.tc_classic: true` forces classic TC on first attach. The default remains the existing choice: TCX unless a classic filter is already present or the kernel rejects TCX. LAN-only ingress stays at priority 2. The adapter uses priority 1 and handle major `0x4c41`, outside the `0x2022`/`0x2023` range dae deletes as stale on startup.

## Startup

1. On the router, create a new unused packet flow. Do not assume its id is 2. Do not edit flow 1, and do not hardcode the id in dae.
2. Set that flow's Docker target to container name `dae-edge`. Bind only a test client or one exact test domain. The recommended endpoint is `api.ipify.org`.
3. Mount Landscape's `unix_link` directory read-only at `/ld_unix_link`.
4. Start the compose file in this directory. The entrypoint attaches the adapter and waits until `tc filter show dev eth0 ingress` contains `pref 1`, then starts `dae run`.
5. The adapter sends one unframed JSON object to `/ld_unix_link/register.sock` and half-closes:

```json
{"id":"<container-id>","ifindex":<host-peer-ifindex>}
```

It repeats every 60 seconds, including after success.

## DNS rule

LAN client DNS queries enter DNS flow 0. A rule whose own `flow_id` is the dae packet flow is never consulted for those queries, so the client keeps Mihomo's `198.18.0.0/15` Fake-IP and dae cannot dial it.

These two ids are different:

| Field | Value |
| --- | --- |
| DNS rule `flow_id` | Client DNS entry flow, normally `0` |
| `mark.flow_id` | The new dae packet flow, never flow 1 |
| `mark.action` | `redirect` |

Use an upstream that returns a real A record, such as DNSPod or Ali DoH. Do not use the `mihomo-dns` Fake-IP upstream. Prefer `filter: only_ipv4` until the node has IPv6. Match one exact domain with `match_type: full`. Do not add a second rule that redirects the resolver hostname or IP onto the dae flow; that sends the upstream query through the edge and recurses. Landscape cannot update a rule across flows, so a rule created on the wrong flow must be deleted and replaced.

```json
{
  "name": "dae-edge api.ipify.org",
  "enable": true,
  "index": 0,
  "flow_id": 0,
  "source": [
    {"match_type": "full", "value": "api.ipify.org"}
  ],
  "upstream_id": "<REAL_IP_UPSTREAM_ID>",
  "filter": "only_ipv4",
  "mark": {
    "action": {"t": "redirect"},
    "flow_id": "<NEW_DAE_FLOW_ID>",
    "allow_reuse_port": false
  }
}
```

`<NEW_DAE_FLOW_ID>` is the packet flow whose Docker target is `dae-edge`. After creating the rule, flush that domain's DNS cache and confirm the answer is a public address, not `198.18.0.0/15`.

## Rollback

Stop or remove the `dae-edge` container. Disable the test DNS or flow rule, then delete or disable the new flow target. Do not change flow 1, and do not restart the Mihomo edge.

## Limits

- TCP and UDP are what dae's LAN ingress redirects. ICMP and other L4 are parsed as unsupported and passed by dae with `TC_ACT_OK` after the adapter has already continued.
- IPv4 and IPv6 both use the skb VLAN tag. IPv6 forwarding inside the container still depends on `auto_config_kernel_parameter` and a working container route.
- The container needs `NET_ADMIN`, `BPF`, and `SYS_ADMIN` for clsact, classic TC, and the dae netns. It does not need host network or host pid.
- Domain routing still needs the client to receive a real IP. The DNS rule above must live on the client DNS flow (`flow_id` 0) and mark the returned address onto the dae packet flow. A rule owned by the dae flow does not match LAN queries. Do not point the upstream at Mihomo Fake-IP.
- Leave `wan_interface` empty. Setting it to the same container NIC makes the interface dual-role, and dae then attaches ingress at priority 1, the same slot as the adapter. LAN-only keeps dae at priority 2. dae's own sockets still use `so_mark_from_dae`; do not add a host `wan_interface`.
- On a Docker bridge, dae stores the original frame source as the reply destination MAC. `tproxy_dae0_ingress` writes that MAC back and `bpf_redirect`s to eth0, returning `TC_ACT_OK`. A later eth0 egress or dae0 filter cannot change the frame after that redirect. `LANDSCAPE_EDGE_GATEWAY_MAC=auto` learns the container default-route neighbor and writes `/run/dae/reply_gateway_mac` before `dae run`. dae copies that into `reply_gateway_mac` and, only when it is non-zero, rewrites a non-matching reply destination immediately before the redirect. The stored binding stays the original source. The flag stays off unless set, and the default reply destination is unchanged.
- `BPF_PROG_RUN` cannot construct `skb->vlan_present`, so the object test only checks that an untagged frame returns `TC_ACT_UNSPEC` and does not call pop. The namespace test checks that a pref 1 `TC_ACT_UNSPEC` filter executes the pref 2 filter. Pop of a real Landscape skb tag still has to be confirmed on the router with `tc filter show` and a packet capture inside the container.

## Acceptance on a real Landscape router

| Check | Pass |
| --- | --- |
| New flow created, flow 1 unchanged | UI/API shows a different flow id and target |
| Test client or test domain only | Other clients still use Mihomo |
| Adapter pref 1 before dae pref 2 | `tc filter show dev eth0 ingress` lists both, adapter major is not `0x2023` |
| TCP through the test domain | Connection uses the `min_moving_avg` group |
| UDP/QUIC through the test domain | Same group, or an explicit block if the sample routing blocks UDP/443 |
| DNS rule on client flow 0, mark redirects to the new dae flow | `api.ipify.org` answers a real public IP, not `198.18.0.0/15`; rule `flow_id` is 0 and `mark.flow_id` is the dae flow |
| IPv4 and IPv6 | Both families that the node supports leave via the container, not the host LAN |
| Restart `dae-edge` | Registration returns within 60 seconds and the test flow recovers |
| Stop `dae-edge` | Only the test flow fails; flow 1 still proxies |
| Rollback | Test flow target removed; flow 1 config hash unchanged |
