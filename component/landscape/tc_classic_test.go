/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package landscape

import "testing"

// Pref and handle are part of the contract with dae, which is Linux-only and
// cannot be imported from this package on other GOOS values. These constants
// are asserted here so a future edit cannot silently collide with dae.
func TestAdapterDoesNotUseDaeHandles(t *testing.T) {
	const (
		daeStaleMajorA uint16 = 0x2022
		daeStaleMajorB uint16 = 0x2023
		daeLanIngress  uint16 = 2
	)
	if Pref != 1 {
		t.Fatalf("pref=%d, want 1 so it runs before dae LAN ingress pref %d", Pref, daeLanIngress)
	}
	if Pref >= daeLanIngress {
		t.Fatal("adapter must be a lower classic priority than dae LAN ingress")
	}
	if HandleMajor == daeStaleMajorA || HandleMajor == daeStaleMajorB {
		t.Fatalf("handle major %#x is deleted by dae startup purge", HandleMajor)
	}
	if HandleMajor == 0 {
		t.Fatal("handle major must be explicit")
	}
}
