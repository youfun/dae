//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package landscape

import (
	"bytes"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

const programSection = "tc"

// LoadProgram reads a classic SchedCLS ELF. The object is produced by
// scripts/build-landscape-adapter.sh from kern/adapter.c. It is not generated
// into this package, so a checkout without clang still builds the Go tests.
func LoadProgram(path string) (*ebpf.Program, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read landscape adapter object: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse landscape adapter object: %w", err)
	}
	programSpec := spec.Programs[programSection]
	if programSpec == nil {
		for _, candidate := range spec.Programs {
			if candidate.SectionName == programSection || candidate.Name == "landscape_edge_ingress" {
				programSpec = candidate
				break
			}
		}
	}
	if programSpec == nil {
		return nil, fmt.Errorf("landscape adapter object %s has no %s program", path, programSection)
	}
	programSpec.Type = ebpf.SchedCLS
	program, err := ebpf.NewProgram(programSpec)
	if err != nil {
		return nil, fmt.Errorf("load landscape adapter program: %w", err)
	}
	return program, nil
}
