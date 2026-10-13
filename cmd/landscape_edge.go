/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/component/landscape"
	"github.com/spf13/cobra"
)

func waitForGatewayMAC(ifname string, timeout time.Duration) (net.HardwareAddr, error) {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		mac, err := landscape.GatewayMACFor(ifname)
		if err == nil && mac != nil {
			return mac, nil
		}
		last = err
		if time.Now().After(deadline) {
			if last == nil {
				return nil, fmt.Errorf("no default gateway on %s", ifname)
			}
			return nil, last
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func init() {
	var (
		iface         string
		objectPath    string
		registerPath  string
		containerID   string
		peerIfindex   uint32
		retryInterval time.Duration
		gatewayMAC    string
	)
	command := &cobra.Command{
		Use:   "landscape-edge",
		Short: "Attach the Landscape VLAN adapter and register this container.",
		Long: `Attach a classic TC ingress filter at pref 1 that pops Landscape's
flow VLAN marker and returns TC_ACT_UNSPEC, then register this container with
Landscape. Start this before dae so dae's LAN ingress lands at pref 2 and sees
the decapsulated packet. This command does not proxy traffic and does not
select a Landscape flow.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			var gateway net.HardwareAddr
			switch gatewayMAC {
			case "":
			case "auto":
				learned, err := waitForGatewayMAC(iface, 5*time.Second)
				if err != nil {
					return err
				}
				gateway = learned
			default:
				parsed, err := net.ParseMAC(gatewayMAC)
				if err != nil {
					return fmt.Errorf("gateway MAC: %w", err)
				}
				gateway = parsed
			}
			return landscape.Run(ctx, landscape.Options{
				Interface:     iface,
				ObjectPath:    objectPath,
				RegisterPath:  registerPath,
				ContainerID:   containerID,
				PeerIfindex:   peerIfindex,
				RetryInterval: retryInterval,
				GatewayMAC:    gateway,
				Logger:        log.New(os.Stderr, "landscape-edge: ", log.LstdFlags),
			})
		},
	}
	command.Flags().StringVarP(&iface, "interface", "i", "eth0", "Container interface that receives Landscape redirects.")
	command.Flags().StringVarP(&objectPath, "object", "o", "/usr/local/lib/dae/landscape_edge.o", "Compiled adapter ELF from scripts/build-landscape-adapter.sh.")
	command.Flags().StringVar(&registerPath, "register-sock", landscape.RegisterPath, "Landscape registration socket.")
	command.Flags().StringVar(&containerID, "container-id", "", "Override container id discovery. Not a flow id.")
	command.Flags().Uint32Var(&peerIfindex, "peer-ifindex", 0, "Override host veth ifindex. Zero reads iflink from sysfs.")
	command.Flags().DurationVar(&retryInterval, "retry-interval", landscape.DefaultRetryInterval, "Registration refresh interval, including after success.")
	command.Flags().StringVar(&gatewayMAC, "gateway-mac", "", "Publish this MAC as dae's opt-in reply_gateway_mac. \"auto\" learns the interface default-route neighbor. Empty leaves dae's historical reply destination unchanged.")
	rootCmd.AddCommand(command)
}
