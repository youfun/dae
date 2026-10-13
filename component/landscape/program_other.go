//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package landscape

import (
	"fmt"
	"runtime"
)

// Program is unused off Linux. The type alias keeps call sites compiling
// without pulling a BPF loader into darwin tests.
type unsupportedProgram struct{}

func LoadProgram(path string) (*unsupportedProgram, error) {
	return nil, fmt.Errorf("landscape adapter requires linux, not %s/%s", runtime.GOOS, runtime.GOARCH)
}
