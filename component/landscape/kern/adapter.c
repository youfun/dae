// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
//
// Landscape Flow Edge adapter. Landscape pushes an skb VLAN tag
// (bpf_skb_vlan_push, ETH_P_8021Q, VID 0xc00|flow_id) and redirects the packet
// into this container. Official route mode pops that tag and returns
// TC_ACT_OK, which ends direct-action classification. This program returns
// TC_ACT_UNSPEC so the next classic filter, dae LAN ingress at pref 2, runs.
//
// The __sk_buff prefix below is the stable UAPI context, not a kernel struct.
// Offsets are fixed by the BPF ABI (vlan_present at 84, vlan_tci at 86).

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef int __s32;

#define SEC(name) __attribute__((section(name), used))

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_SHOT 2
#define PACKET_HOST 0

#define LAND_REDIRECT_NETNS_VLAN_ID 0x0c00
#define LAND_REDIRECT_NETNS_VLAN_ID_MASK 0x0f00

struct __sk_buff {
	__u32 len;           /* 0 */
	__u32 pkt_type;      /* 4 */
	__u32 mark;          /* 8 */
	__u32 queue_mapping; /* 12 */
	__u32 protocol;      /* 16 */
	__u32 vlan_present;  /* 20 */
	__u32 vlan_tci;      /* 24: VID in the low 12 bits, plus PCP */
};

static long (*bpf_skb_vlan_pop)(struct __sk_buff *skb) = (void *)19;
static long (*bpf_skb_change_type)(struct __sk_buff *skb, __u32 type) = (void *)32;

SEC("tc")
int landscape_edge_ingress(struct __sk_buff *skb)
{
	__u32 tci;
	volatile __u32 vid_mask = 0x0fff;

	if (!skb->vlan_present)
		return TC_ACT_UNSPEC;

	/*
	 * vlan_tci is PCP in bits 13-15 plus the VID. Mask through a volatile
	 * so clang cannot delete the 12-bit cut. A PCP-only match would pop a
	 * foreign VLAN.
	 */
	tci = skb->vlan_tci & vid_mask;
	tci &= LAND_REDIRECT_NETNS_VLAN_ID_MASK;
	if (tci != LAND_REDIRECT_NETNS_VLAN_ID)
		return TC_ACT_UNSPEC;

	if (bpf_skb_vlan_pop(skb))
		return TC_ACT_SHOT;

	/*
	 * Landscape route mode marks the redirected frame PACKET_HOST before
	 * the container stack or a later classifier sees it. A failure here
	 * still continues: the VLAN is already gone, and hiding the packet
	 * from dae is worse than leaving pkt_type unchanged.
	 */
	bpf_skb_change_type(skb, PACKET_HOST);
	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
