/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package landscape

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Options configures one edge process. None of these values select a
// Landscape flow; flow membership is a router-side target, not an adapter flag.
type Options struct {
	Interface     string
	ObjectPath    string
	RegisterPath  string
	ContainerID   string
	PeerIfindex   uint32
	RetryInterval time.Duration
	GatewayMAC    net.HardwareAddr
	Logger        *log.Logger
}

// Edge owns the pref-1 filter and the registration loop. Stopping it removes
// only this container's adapter. It cannot see or modify another flow.
type Edge struct {
	adapter *Adapter
	logger  *log.Logger
}

func Run(ctx context.Context, opts Options) error {
	if opts.Interface == "" {
		return fmt.Errorf("landscape edge interface is required")
	}
	if opts.RegisterPath == "" {
		opts.RegisterPath = RegisterPath
	}
	if opts.Logger == nil {
		opts.Logger = log.New(os.Stderr, "landscape-edge: ", log.LstdFlags)
	}
	enroll, err := resolveEnroll(opts)
	if err != nil {
		return err
	}
	adapter, err := AttachWithGateway(opts.Interface, opts.ObjectPath, opts.GatewayMAC)
	if err != nil {
		return err
	}
	defer adapter.Close()
	if len(opts.GatewayMAC) == 6 {
		if err := WriteReplyGatewayMAC(opts.GatewayMAC); err != nil {
			return err
		}
		opts.Logger.Printf("wrote reply_gateway_mac %s for dae; dae0 rewrites a non-matching reply destination before redirect", opts.GatewayMAC)
	}
	opts.Logger.Printf("attached classic TC pref %d handle %#x on %s ifindex %d; registering container %s peer ifindex %d",
		Pref, uint32(HandleMajor)<<16|uint32(Pref), opts.Interface, adapter.Ifindex(), enroll.ID, enroll.Ifindex)
	return registerLoop(ctx, opts, enroll)
}

// GatewayMACFor returns the MAC of the interface's IPv4 default-route
// gateway. A missing route is not an error: the caller keeps ingress-only
// mode. The address is learned at start, not hardcoded to a Landscape flow.
func GatewayMACFor(ifname string) (net.HardwareAddr, error) {
	gateway, err := defaultGateway(ifname)
	if err != nil || gateway == nil {
		return nil, err
	}
	mac, err := neighborMAC(ifname, gateway)
	if err != nil {
		return nil, err
	}
	if mac == nil {
		return nil, fmt.Errorf("no neighbor entry for gateway %s on %s", gateway, ifname)
	}
	return mac, nil
}

func defaultGateway(ifname string) (net.IP, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("read ipv4 routes: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return nil, scanner.Err()
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[0] != ifname || fields[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			return nil, fmt.Errorf("parse gateway %q: %w", fields[2], err)
		}
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]), nil
	}
	return nil, scanner.Err()
}

func neighborMAC(ifname string, gateway net.IP) (net.HardwareAddr, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("read arp: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return nil, scanner.Err()
	}
	want := gateway.String()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || fields[0] != want || fields[5] != ifname {
			continue
		}
		mac, err := net.ParseMAC(fields[3])
		if err != nil || len(mac) != 6 || isZeroMAC(mac) {
			continue
		}
		return mac, nil
	}
	return nil, scanner.Err()
}

// WriteReplyGatewayMAC publishes the learned container gateway for dae's
// opt-in reply_gateway_mac. dae reads this file before loading eBPF. The
// value is not a host WAN or bridge MAC.
func WriteReplyGatewayMAC(mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return fmt.Errorf("reply gateway MAC must be 6 bytes")
	}
	if err := os.MkdirAll("/run/dae", 0o755); err != nil {
		return fmt.Errorf("create reply gateway directory: %w", err)
	}
	path := ReplyGatewayMACPath
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(mac.String()+"\n"), 0o644); err != nil {
		return fmt.Errorf("write reply gateway MAC: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("publish reply gateway MAC: %w", err)
	}
	return nil
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

func resolveEnroll(opts Options) (Enroll, error) {
	id := opts.ContainerID
	if id == "" {
		cgroupV2 := false
		if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
			cgroupV2 = true
		}
		mountinfo, err := os.ReadFile("/proc/self/mountinfo")
		if err != nil && cgroupV2 {
			return Enroll{}, fmt.Errorf("read mountinfo: %w", err)
		}
		hostname, _ := os.Hostname()
		id, err = ReadContainerID(string(mountinfo), cgroupV2, hostname)
		if err != nil {
			return Enroll{}, err
		}
	}
	peer := opts.PeerIfindex
	if peer == 0 {
		ifindex, err := ReadSysfsInt(filepath.Join("/sys/class/net", opts.Interface, "ifindex"))
		if err != nil {
			return Enroll{}, err
		}
		iflink, err := ReadSysfsInt(filepath.Join("/sys/class/net", opts.Interface, "iflink"))
		if err != nil {
			return Enroll{}, err
		}
		peerIndex, err := PeerIfindex(ifindex, iflink)
		if err != nil {
			return Enroll{}, err
		}
		peer = uint32(peerIndex)
	}
	return Enroll{ID: id, Ifindex: peer}, nil
}

func registerLoop(ctx context.Context, opts Options, enroll Enroll) error {
	interval := NextRetry(opts.RetryInterval)
	for {
		if err := dialAndSend(opts.RegisterPath, enroll); err != nil {
			opts.Logger.Printf("register via %s failed: %v; retry in %s", opts.RegisterPath, err, interval)
		} else {
			opts.Logger.Printf("registered %s ifindex %d via %s; refresh in %s", enroll.ID, enroll.Ifindex, opts.RegisterPath, interval)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func dialAndSend(path string, enroll Enroll) error {
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	return SendEnroll(conn, enroll)
}
