//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package landscape

import (
	"fmt"
	"net"
)

const (
	Pref        uint16 = 1
	EgressPref  uint16 = 1
	HandleMajor uint16 = 0x4c41
)

type Adapter struct{}

func Attach(ifname, objectPath string) (*Adapter, error) {
	return AttachWithGateway(ifname, objectPath, nil)
}

func AttachWithGateway(ifname, objectPath string, gateway net.HardwareAddr) (*Adapter, error) {
	return nil, fmt.Errorf("landscape adapter attach requires linux")
}

func (a *Adapter) Close() error { return nil }

func (a *Adapter) Ifindex() int { return 0 }
