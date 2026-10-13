/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

// Package landscape is a thin Flow Edge adapter. It pops the VLAN marker that
// Landscape pushes before redirecting a packet into a container, then returns
// TC_ACT_UNSPEC so the next classic TC filter (dae LAN ingress) still runs.
// It does not implement proxy protocols, health checks, or node selection.
package landscape

// VID encoding from Landscape v0.26.3 landscape-ebpf/src/bpf/base/tp.h.
// Injection uses bpf_skb_vlan_push(skb, ETH_P_8021Q, 0xc00|flow_id), so the
// tag arrives as skb metadata (vlan_present / vlan_tci), not an inline header.
const (
	VLANID              uint16 = 0x0c00
	VLANIDMask          uint16 = 0x0f00
	FlowIDMask          uint16 = 0x00ff
	VLANPresent         uint32 = 1
	EthP8021Q           uint16 = 0x8100
	TCActUnspec         int32  = -1
	TCActOK             int32  = 0
	TCActShot           int32  = 2
	PacketHost          uint32 = 0
	RegisterPath               = "/ld_unix_link/register.sock"
	ReplyGatewayMACPath        = "/run/dae/reply_gateway_mac"
)

// IsLandscapeTag reports whether tci is a Landscape flow marker.
// The high nibble of the VID must be 0xc; the low 8 bits are the flow id.
// Flow id is not interpreted here: a new test flow must not be hardcoded.
func IsLandscapeTag(tci uint16) bool {
	return tci&0x0fff&VLANIDMask == VLANID
}

// VidMaskAndMatch is the instruction-level form of the adapter check:
// mask PCP off, then compare the VID nibble. A foreign VLAN with only the
// PCP bits set must not match.
func VidMaskAndMatch(tci uint32) bool {
	vid := tci & 0x0fff
	return vid&uint32(VLANIDMask) == uint32(VLANID)
}

// FlowID extracts the low 8 bits. Callers must not treat any value as reserved.
func FlowID(tci uint16) uint8 {
	return uint8(tci & FlowIDMask)
}

// Decide is the userspace mirror of the TC program. It exists so the pop and
// continuation rules can be tested without a kernel.
//
// A Landscape tag is popped and the packet is marked PACKET_HOST, matching
// Landscape route mode, except the action is TC_ACT_UNSPEC rather than
// TC_ACT_OK. TC_ACT_OK ends direct-action classification, so dae's later
// filter would never see the packet. A pop failure is dropped. Untagged
// packets, and tagged packets that are not a Landscape marker, are left
// unchanged and also continue, so container-local traffic still reaches dae.
func Decide(vlanPresent uint32, tci uint16) (action int32, pop bool, changeType bool) {
	if vlanPresent == 0 || !IsLandscapeTag(tci) {
		return TCActUnspec, false, false
	}
	return TCActUnspec, true, true
}
