/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestTcClassicDefaultsFalse(t *testing.T) {
	conf, err := New([]*config_parser.Section{
		{Name: "global"},
		{Name: "routing"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if conf.Global.TcClassic {
		t.Fatal("tc_classic must stay off unless the config sets it")
	}
	if conf.Global.ReplyGatewayMAC != "" {
		t.Fatal("reply_gateway_mac must stay empty unless the config sets it")
	}
}
