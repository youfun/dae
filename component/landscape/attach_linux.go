//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package landscape

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// Pref is below dae's LAN-only ingress priority of 2, and matches the
	// slot Landscape's own handler occupies. Do not move dae to this pref:
	// that would replace the adapter instead of running after it.
	Pref uint16 = 1
	// ReplyPref is unused. dae's dae0 redirect returns TC_ACT_OK, so a later
	// classic filter cannot rewrite the frame that already left. The opt-in
	// rewrite lives in dae's own program, before that redirect.
	ReplyPref  uint16 = 2
	EgressPref        = ReplyPref
	// HandleMajor is intentionally outside dae's stale-filter sweep
	// (0x2022 and 0x2023). dae startup must not delete this filter.
	HandleMajor uint16 = 0x4c41
	filterName         = "ld_edge"
)

// Adapter is one classic TC ingress filter. Close deletes only that filter.
type Adapter struct {
	link    netlink.Link
	filter  netlink.Filter
	program *ebpf.Program
}

func Attach(ifname, objectPath string) (*Adapter, error) {
	return AttachWithGateway(ifname, objectPath, nil)
}

// AttachWithGateway attaches the ingress adapter. A non-nil gateway is not
// installed as an eth0 filter: dae's dae0 program redirects and returns
// TC_ACT_OK, so a later filter never sees the frame. The caller writes the
// learned gateway into dae's reply_gateway_mac instead. A nil gateway keeps
// ingress-only behavior.
func AttachWithGateway(ifname, objectPath string, gateway net.HardwareAddr) (*Adapter, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("landscape adapter interface %s: %w", ifname, err)
	}
	program, err := LoadProgram(objectPath)
	if err != nil {
		return nil, err
	}
	adapter, err := attachProgram(link, program)
	if err != nil {
		_ = program.Close()
		return nil, err
	}
	if len(gateway) != 0 && len(gateway) != 6 {
		_ = adapter.Close()
		return nil, fmt.Errorf("gateway MAC must be 6 bytes")
	}
	return adapter, nil
}

func attachProgram(link netlink.Link, program *ebpf.Program) (*Adapter, error) {
	if err := ensureClsact(link); err != nil {
		return nil, err
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(HandleMajor, Pref),
			Protocol:  unix.ETH_P_ALL,
			Priority:  Pref,
		},
		Fd:           program.FD(),
		Name:         filterName,
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return nil, fmt.Errorf("attach landscape adapter on %s: %w", link.Attrs().Name, err)
	}
	return &Adapter{link: link, filter: filter, program: program}, nil
}

func ensureClsact(link netlink.Link) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add clsact qdisc on %s: %w", link.Attrs().Name, err)
	}
	return nil
}

// Close removes only the adapter filter. It does not delete clsact, because
// dae may still hold pref 2 on the same qdisc during shutdown ordering.
func (a *Adapter) Close() error {
	if a == nil {
		return nil
	}
	var err error
	if a.filter != nil {
		if delErr := netlink.FilterDel(a.filter); delErr != nil && !errors.Is(delErr, unix.ENOENT) && !errors.Is(delErr, unix.ENODEV) {
			err = fmt.Errorf("detach landscape adapter: %w", delErr)
		}
	}
	if a.program != nil {
		if closeErr := a.program.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}
	return err
}

func (a *Adapter) Ifindex() int {
	if a == nil || a.link == nil {
		return 0
	}
	return a.link.Attrs().Index
}
