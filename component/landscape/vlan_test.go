/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package landscape

import "testing"

func TestIsLandscapeTag(t *testing.T) {
	cases := []struct {
		tci  uint16
		want bool
	}{
		{0x0c00, true},
		{0x0c01, true},
		{0x0cff, true},
		{0x0c7f, true},
		{0x0000, false},
		{0x0b00, false},
		{0x0d01, false},
		{0x1c00, true},
		{0x8100, false},
	}
	for _, tc := range cases {
		if got := IsLandscapeTag(tc.tci); got != tc.want {
			t.Errorf("IsLandscapeTag(%#x)=%v, want %v", tc.tci, got, tc.want)
		}
	}
}

func TestFlowIDIsNotHardcoded(t *testing.T) {
	if FlowID(0x0c00) != 0 || FlowID(0x0c01) != 1 || FlowID(0x0cff) != 0xff {
		t.Fatal("flow id must be the low 8 bits and must not reserve flow 1")
	}
	if !IsLandscapeTag(0x0c01) {
		t.Fatal("existing Mihomo flow 1 is still a Landscape tag; isolation is a deployment rule, not a datapath special case")
	}
}

func TestDecideContinuesAfterPop(t *testing.T) {
	action, pop, changeType := Decide(VLANPresent, 0x0c2a)
	if action != TCActUnspec || !pop || !changeType {
		t.Fatalf("tagged landscape packet: action=%d pop=%v changeType=%v", action, pop, changeType)
	}
	if action == TCActOK {
		t.Fatal("TC_ACT_OK would hide the packet from dae pref 2")
	}
}

func TestVidMaskIgnoresPCP(t *testing.T) {
	if !VidMaskAndMatch(0x0c2a) || !VidMaskAndMatch(0x000c2a) {
		t.Fatal("VID 0xc2a must match with or without a zero PCP")
	}
	// PCP 1 sits in bit 13. The VID is 0x42a, which is not a Landscape tag.
	if VidMaskAndMatch(0x2000 | 0x042a) {
		t.Fatal("PCP bits must be masked before the 0xc00 comparison")
	}
	if VidMaskAndMatch(0x0064) {
		t.Fatal("ordinary VLAN 100 must not match")
	}
}

func TestDecideContinuesUntagged(t *testing.T) {
	action, pop, changeType := Decide(0, 0)
	if action != TCActUnspec || pop || changeType {
		t.Fatalf("untagged: action=%d pop=%v changeType=%v", action, pop, changeType)
	}
	action, pop, changeType = Decide(VLANPresent, 0x0064)
	if action != TCActUnspec || pop || changeType {
		t.Fatalf("foreign tag: action=%d pop=%v changeType=%v", action, pop, changeType)
	}
}
