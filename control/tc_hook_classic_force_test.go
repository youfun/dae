/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
)

func TestForceClassicSkipsTCXWhenNoForeignFilterExists(t *testing.T) {
	var tcxCalls int
	var classicCalls int
	backend := tcHookBackend{
		classicFiltersPresent: func(tcHookSpec) (bool, error) { return false, nil },
		attachTCX: func(tcHookSpec, tcxHookPosition) (tcxHookAttachment, error) {
			tcxCalls++
			return nil, ciliumLink.ErrNotSupported
		},
		replaceClassic: func(tcHookSpec) error {
			classicCalls++
			return nil
		},
		deleteClassic: func(tcHookSpec) error { return nil },
	}
	set := newTCHookSetWithBackend(logrus.New(), backend)
	spec := tcHookSpec{
		Scope:        tcHookScopeHost,
		Ifindex:      1,
		Ifname:       "eth0",
		Direction:    tcHookIngress,
		Priority:     2,
		Handle:       0x20230004,
		Name:         "dae_lan_ingress",
		Program:      &ebpf.Program{},
		ForceClassic: true,
	}
	group := &tcHookGroup{entries: map[uint16]*tcHookEntry{}}
	if err := set.attachLocked(group, spec); err != nil {
		t.Fatal(err)
	}
	if tcxCalls != 0 || classicCalls != 1 {
		t.Fatalf("tcxCalls=%d classicCalls=%d, want classic without probing TCX", tcxCalls, classicCalls)
	}
	if group.mode != tcHookModeClassic {
		t.Fatalf("mode=%v, want classic", group.mode)
	}
}

func TestDefaultStillTriesTCXWhenNoForeignFilterExists(t *testing.T) {
	backend := tcHookBackend{
		classicFiltersPresent: func(tcHookSpec) (bool, error) { return false, nil },
		attachTCX: func(tcHookSpec, tcxHookPosition) (tcxHookAttachment, error) {
			return &recordingTCXHook{}, nil
		},
		replaceClassic: func(tcHookSpec) error {
			t.Fatal("default attach must not force classic TC")
			return nil
		},
		deleteClassic: func(tcHookSpec) error { return nil },
	}
	set := newTCHookSetWithBackend(logrus.New(), backend)
	spec := tcHookSpec{
		Scope:     tcHookScopeHost,
		Ifindex:   1,
		Ifname:    "eth0",
		Direction: tcHookIngress,
		Priority:  2,
		Handle:    0x20230004,
		Name:      "dae_lan_ingress",
		Program:   &ebpf.Program{},
	}
	group := &tcHookGroup{entries: map[uint16]*tcHookEntry{}}
	if err := set.attachLocked(group, spec); err != nil {
		t.Fatal(err)
	}
	if group.mode != tcHookModeTCX {
		t.Fatalf("mode=%v, want TCX when tc_classic is unset", group.mode)
	}
}

type recordingTCXHook struct{}

func (recordingTCXHook) Update(*ebpf.Program) error { return nil }
func (recordingTCXHook) Close() error               { return nil }
