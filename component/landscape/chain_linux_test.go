//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package landscape

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestClassicPref1UnspecReachesPref2(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("network namespace TC test requires root")
	}
	continueProgram := schedCLSConst(t, "ld_edge_next", TCActUnspec)
	defer continueProgram.Close()
	dropProgram := schedCLSConst(t, "ld_edge_drop", TCActShot)
	defer dropProgram.Close()

	nsName := fmt.Sprintf("ldedge%x", os.Getpid()&0xffff)
	hostName := fmt.Sprintf("ldh%x", os.Getpid()&0xffff)
	peerName := fmt.Sprintf("ldp%x", os.Getpid()&0xffff)
	_ = runIP("link", "del", hostName)
	_ = runIP("netns", "del", nsName)
	if err := runIP("netns", "add", nsName); err != nil {
		t.Skipf("creating a network namespace requires CAP_SYS_ADMIN: %v", err)
	}
	t.Cleanup(func() {
		_ = runIP("link", "del", hostName)
		_ = runIP("netns", "del", nsName)
	})
	for _, args := range [][]string{
		{"link", "add", hostName, "type", "veth", "peer", "name", peerName},
		{"link", "set", peerName, "netns", nsName},
		{"addr", "add", "10.205.0.1/30", "dev", hostName},
		{"link", "set", hostName, "up"},
		{"netns", "exec", nsName, "ip", "addr", "add", "10.205.0.2/30", "dev", peerName},
		{"netns", "exec", nsName, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsName, "ip", "link", "set", peerName, "up"},
	} {
		if err := runIP(args...); err != nil {
			t.Fatal(err)
		}
	}
	link, err := netlink.LinkByName(hostName)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := attachProgram(link, continueProgram)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	if adapter.filter.Attrs().Priority != Pref || adapter.filter.Attrs().Handle>>16 != uint32(HandleMajor) {
		t.Fatalf("adapter priority=%d handle=%#x", adapter.filter.Attrs().Priority, adapter.filter.Attrs().Handle)
	}

	drop := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2023, 4),
			Protocol:  unix.ETH_P_ALL,
			Priority:  2,
		},
		Fd:           dropProgram.FD(),
		Name:         "dae_pref2",
		DirectAction: true,
	}
	if err := netlink.FilterReplace(drop); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.FilterDel(drop) })

	assertPing(t, nsName, "10.205.0.1", false)
}

func TestAdapterObjectPopsLandscapeVLAN(t *testing.T) {
	object := os.Getenv("LANDSCAPE_EDGE_OBJECT")
	if object == "" {
		t.Skip("set LANDSCAPE_EDGE_OBJECT to the ELF from scripts/build-landscape-adapter.sh")
	}
	program, err := LoadProgram(object)
	if err != nil {
		t.Fatal(err)
	}
	defer program.Close()
	out, err := program.Run(&ebpf.RunOptions{Data: []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x00,
	}})
	if err != nil {
		t.Skipf("BPF_PROG_RUN is unavailable for this object: %v", err)
	}
	if int32(out) != TCActUnspec {
		t.Fatalf("untagged packet action=%d, want TC_ACT_UNSPEC without a pop", out)
	}
}

func TestRegisterReconnectsAfterRefusal(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "register.sock")
	refused := make(chan struct{})
	accepted := make(chan Enroll, 1)
	go serveOneRefusalThenAccept(t, sockPath, refused, accepted)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- registerLoop(ctx, Options{
			RegisterPath:  sockPath,
			RetryInterval: 40 * time.Millisecond,
			Logger:        log.New(os.Stderr, "", 0),
		}, Enroll{ID: "0123456789ab", Ifindex: 9})
	}()

	select {
	case <-refused:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not refuse the first registration")
	}
	select {
	case got := <-accepted:
		if got.ID != "0123456789ab" || got.Ifindex != 9 {
			t.Fatalf("accepted enroll %#v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("registration did not retry after the socket disappeared")
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("register loop did not stop")
	}
}

func serveOneRefusalThenAccept(t *testing.T, sockPath string, refused chan struct{}, accepted chan Enroll) {
	t.Helper()
	listener := listenUnix(t, sockPath)
	conn, err := listener.Accept()
	if err != nil {
		t.Error(err)
		return
	}
	_ = conn.Close()
	_ = listener.Close()
	close(refused)
	time.Sleep(30 * time.Millisecond)

	listener = listenUnix(t, sockPath)
	defer listener.Close()
	conn, err = listener.Accept()
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if n == 0 && err != nil {
		t.Error(err)
		return
	}
	var got Enroll
	if err := json.Unmarshal(buf[:n], &got); err != nil {
		t.Error(err)
		return
	}
	accepted <- got
}

func listenUnix(t *testing.T, sockPath string) net.Listener {
	t.Helper()
	_ = os.Remove(sockPath)
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func schedCLSConst(t *testing.T, name string, result int32) *ebpf.Program {
	t.Helper()
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: name,
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, result),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("loading a TC program requires BPF privileges: %v", err)
		}
		t.Fatal(err)
	}
	return program
}

func runIP(args ...string) error {
	output, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v: %w: %s", args, err, output)
	}
	return nil
}

func assertPing(t *testing.T, nsName, target string, shouldPass bool) {
	t.Helper()
	err := exec.Command("ip", "netns", "exec", nsName, "ping", "-q", "-c", "1", "-W", "1", target).Run()
	if shouldPass && err != nil {
		t.Fatalf("packet did not pass the TC chain: %v", err)
	}
	if !shouldPass && err == nil {
		t.Fatal("pref 2 did not run after pref 1 returned TC_ACT_UNSPEC")
	}
}
