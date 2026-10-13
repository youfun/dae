/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package landscape

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

const DefaultRetryInterval = 60 * time.Second

// Enroll is the unframed JSON object Landscape reads from register.sock.
// id is the container id. ifindex is the host-side veth peer index, which
// sysfs exposes as the container interface's iflink when it differs from ifindex.
type Enroll struct {
	ID      string `json:"id"`
	Ifindex uint32 `json:"ifindex"`
}

var containerIDPattern = regexp.MustCompile(`(?:^|/)([a-f0-9]{64}|[a-f0-9]{12})(?:/|$)`)
var hostnameIDPattern = regexp.MustCompile(`^[a-f0-9]{12}$|^[a-f0-9]{64}$`)

// MarshalEnroll writes one JSON object and no trailing newline. Landscape
// reads until EOF, so the sender must half-close after this payload.
func MarshalEnroll(enroll Enroll) ([]byte, error) {
	if enroll.ID == "" {
		return nil, errors.New("landscape enroll id is empty")
	}
	if enroll.Ifindex == 0 {
		return nil, errors.New("landscape enroll ifindex is zero")
	}
	payload, err := json.Marshal(enroll)
	if err != nil {
		return nil, err
	}
	if !json.Valid(payload) || strings.Contains(string(payload), "\n") {
		return nil, errors.New("landscape enroll payload must be one JSON object")
	}
	return payload, nil
}

// ReadContainerID mirrors Landscape's mountinfo scan: a 64- or 12-hex id on a
// cgroup v2 mount path that mentions containers and is not a btrfs subvolume.
// The hostname fallback covers Docker's default hostname, which is the short id.
func ReadContainerID(mountinfo string, cgroupV2 bool, hostname string) (string, error) {
	if cgroupV2 {
		for _, line := range strings.Split(mountinfo, "\n") {
			if !strings.Contains(line, "containers") || strings.Contains(line, "subvolumes") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			if id := extractContainerID(fields[3]); id != "" {
				return id, nil
			}
		}
	}
	if hostnameIDPattern.MatchString(hostname) {
		return hostname, nil
	}
	return "", errors.New("container id not found")
}

func extractContainerID(path string) string {
	match := containerIDPattern.FindStringSubmatch(path)
	if match == nil {
		return ""
	}
	return match[1]
}

// PeerIfindex returns the host veth index for a container interface.
// Landscape treats ifindex != iflink as the paired-veth signal.
func PeerIfindex(ifindex, iflink int) (int, error) {
	if ifindex <= 0 || iflink <= 0 {
		return 0, fmt.Errorf("invalid interface indexes ifindex=%d iflink=%d", ifindex, iflink)
	}
	if ifindex == iflink {
		return 0, fmt.Errorf("interface ifindex %d has no distinct peer", ifindex)
	}
	return iflink, nil
}

// SendEnroll writes one unframed JSON object and half-closes the write side.
func SendEnroll(conn net.Conn, enroll Enroll) error {
	payload, err := MarshalEnroll(enroll)
	if err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return conn.Close()
}

// NextRetry is the reconnect delay. A successful send still waits: Landscape
// re-enrolls every 60 seconds so a restarted router learns the edge again.
func NextRetry(interval time.Duration) time.Duration {
	if interval <= 0 {
		return DefaultRetryInterval
	}
	return interval
}

// ReadSysfsInt reads a /sys/class/net value such as ifindex or iflink.
func ReadSysfsInt(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var value int
	if _, err := fmt.Sscan(strings.TrimSpace(string(raw)), &value); err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("non-positive value in %s", path)
	}
	return value, nil
}
