#!/bin/sh
# Adapter first, dae second. dae startup only deletes handles 0x2022/0x2023,
# so the pref-1 adapter (major 0x4c41) survives that sweep.
set -eu

object="${LANDSCAPE_EDGE_OBJECT:-/usr/local/lib/dae/landscape_edge.o}"
iface="${LANDSCAPE_EDGE_IFACE:-eth0}"
config="${DAE_CONFIG:-/etc/dae/config.dae}"

gateway_args=""
if [ "${LANDSCAPE_EDGE_GATEWAY_MAC:-}" = "auto" ]; then
	gateway_args="--gateway-mac auto"
elif [ -n "${LANDSCAPE_EDGE_GATEWAY_MAC:-}" ]; then
	gateway_args="--gateway-mac ${LANDSCAPE_EDGE_GATEWAY_MAC}"
fi

# A fresh veth has a route before ARP. One ping fills the neighbor entry
# that --gateway-mac auto reads.
if [ -n "$gateway_args" ]; then
	ping -c 1 -W 1 "$(ip -4 route show dev "$iface" default | awk '{print $3; exit}')" >/dev/null 2>&1 || true
fi

dae landscape-edge --interface "$iface" --object "$object" $gateway_args &
edge_pid=$!
trap 'kill "$edge_pid" 2>/dev/null || true' EXIT INT TERM

# Check before dae run. dae moves the serve path into daens, so a later tc
# lookup from this shell no longer sees the container eth0. The gateway file
# must exist before dae loads eBPF: the rewrite is a load-time constant, and
# a later eth0 filter cannot run after dae0's redirect returns TC_ACT_OK.
tc_bin=$(command -v tc || true)
if [ -z "$tc_bin" ] && [ -x /sbin/tc ]; then
	tc_bin=/sbin/tc
fi
i=0
while [ "$i" -lt 50 ]; do
	ready=0
	if [ -n "$tc_bin" ] && "$tc_bin" filter show dev "$iface" ingress 2>/dev/null | grep -q 'pref 1'; then
		ready=1
	fi
	if [ -n "$gateway_args" ] && [ ! -s /run/dae/reply_gateway_mac ]; then
		ready=0
	fi
	if [ "$ready" -eq 1 ]; then
		break
	fi
	i=$((i + 1))
	sleep 0.1
done
if [ -z "$tc_bin" ] || ! "$tc_bin" filter show dev "$iface" ingress 2>/dev/null | grep -q 'pref 1'; then
	echo "landscape adapter did not attach at pref 1" >&2
	exit 1
fi
if [ -n "$gateway_args" ] && [ ! -s /run/dae/reply_gateway_mac ]; then
	echo "landscape adapter did not publish the container gateway MAC" >&2
	exit 1
fi

exec dae run --disable-pidfile -c "$config"
