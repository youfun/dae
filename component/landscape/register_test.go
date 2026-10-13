/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package landscape

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestMarshalEnrollIsUnframed(t *testing.T) {
	payload, err := MarshalEnroll(Enroll{ID: "abc123abc123", Ifindex: 18})
	if err != nil {
		t.Fatal(err)
	}
	if payload[len(payload)-1] == '\n' {
		t.Fatal("enroll JSON must not be newline framed")
	}
	var got Enroll
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "abc123abc123" || got.Ifindex != 18 {
		t.Fatalf("decoded %#v", got)
	}
	if _, err := MarshalEnroll(Enroll{}); err == nil {
		t.Fatal("empty enroll must be rejected")
	}
}

func TestReadContainerID(t *testing.T) {
	mountinfo := "38 29 0:31 /docker/containers/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef /sys/fs/cgroup rw\n"
	id, err := ReadContainerID(mountinfo, true, "short")
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 64 {
		t.Fatalf("id=%s", id)
	}
	id, err = ReadContainerID("no containers here", false, "0123456789ab")
	if err != nil || id != "0123456789ab" {
		t.Fatalf("hostname fallback id=%s err=%v", id, err)
	}
	if _, err := ReadContainerID("containers subvolumes /docker/0123456789ab", true, "not-an-id"); err == nil {
		t.Fatal("subvolume line must not supply the id")
	}
}

func TestPeerIfindex(t *testing.T) {
	peer, err := PeerIfindex(4, 18)
	if err != nil || peer != 18 {
		t.Fatalf("peer=%d err=%v", peer, err)
	}
	if _, err := PeerIfindex(4, 4); err == nil {
		t.Fatal("equal indexes are not a veth pair")
	}
}

func TestSendEnrollHalfCloses(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- SendEnroll(client, Enroll{ID: "0123456789ab", Ifindex: 7})
	}()
	buf := make([]byte, 128)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var got Enroll
	if err := json.Unmarshal(buf[:n], &got); err != nil {
		t.Fatal(err)
	}
	if got.Ifindex != 7 {
		t.Fatalf("ifindex=%d", got.Ifindex)
	}
	// Half-close must surface as EOF, not a second JSON value.
	n, err = server.Read(buf)
	if n != 0 || err == nil {
		t.Fatalf("after half-close read n=%d err=%v", n, err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestNextRetryDefaultsToLandscapeInterval(t *testing.T) {
	if NextRetry(0) != 60*time.Second {
		t.Fatal("successful and failed enrolls both retry on Landscape's 60s interval")
	}
	if NextRetry(time.Millisecond) != time.Millisecond {
		t.Fatal("explicit interval must be preserved for tests")
	}
}
