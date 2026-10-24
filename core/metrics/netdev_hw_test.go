// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ccfos/huatuo/internal/bpf"
	"github.com/ccfos/huatuo/internal/matcher"

	"github.com/safchain/ethtool"
)

func TestNetdevHwDevices(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		driver    string
		pattern   string
		driverErr error
		want      bool
	}{
		{
			name:    "mlx5",
			driver:  "mlx5_core",
			pattern: "eth.*",
			want:    true,
		},
		{
			name:    "i40e",
			driver:  "i40e",
			pattern: "eth.*",
			want:    true,
		},
		{
			name:    "ixgbe",
			driver:  "ixgbe",
			pattern: "eth.*",
			want:    true,
		},
		{
			name:    "bnxt",
			driver:  "bnxt_en",
			pattern: "eth.*",
			want:    true,
		},
		{
			name:    "virtio",
			driver:  "virtio_net",
			pattern: "eth.*",
			want:    true,
		},
		{
			name:    "unsupported driver",
			driver:  "veth",
			pattern: "eth.*",
		},
		{
			name:    "excluded device",
			driver:  "mlx5_core",
			pattern: "ens.*",
		},
		{
			name:   "empty whitelist",
			driver: "mlx5_core",
		},
		{
			name:      "driver query failure",
			pattern:   "eth.*",
			driverErr: errors.New("ioctl unavailable"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			devices, err := matcher.NewListMatcher([]string{tt.pattern})
			if err != nil {
				t.Fatal(err)
			}
			got := netdevHwDevices([]string{"eth0"}, devices, func(string) (ethtool.DrvInfo, error) {
				return ethtool.DrvInfo{Driver: tt.driver}, tt.driverErr
			})
			driver, found := got["eth0"]
			if found != tt.want {
				t.Fatalf("selected devices = %v, want eth0 selected=%t", got, tt.want)
			}
			if found && driver.Driver != tt.driver {
				t.Errorf("selected driver = %q, want %q", driver.Driver, tt.driver)
			}
		})
	}
}

type netdevHwBPFStub struct {
	bpf.BPF
	dumpErr error
}

func (s *netdevHwBPFStub) DumpMapByName(name string) ([]bpf.MapItem, error) {
	if name != "rx_sw_dropped_stats" {
		return nil, fmt.Errorf("unexpected map %q", name)
	}
	return nil, s.dumpErr
}

func (s *netdevHwBPFStub) Close() error { return nil }

func TestNetdevHwUpdate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		dropped  uint64
		missed   uint64
		software uint64
		want     float64
	}{
		{
			name:     "missed takes precedence",
			dropped:  100,
			missed:   7,
			software: 30,
			want:     7,
		},
		{
			name:     "subtract software drops",
			dropped:  100,
			software: 30,
			want:     70,
		},
		{
			name:     "only software drops",
			dropped:  30,
			software: 30,
		},
		{
			name:     "software exceeds total",
			dropped:  20,
			software: 30,
		},
		{name: "no drops"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			stats := filepath.Join(root, "eth0", "statistics")
			if err := os.MkdirAll(stats, 0o755); err != nil {
				t.Fatal(err)
			}
			for name, value := range map[string]uint64{"rx_dropped": tt.dropped, "rx_missed_errors": tt.missed} {
				if err := os.WriteFile(filepath.Join(stats, name), fmt.Appendf(nil, "%d\n", value), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			collector := &netdevHw{
				ifaceList:             map[string]*ethtool.DrvInfo{"eth0": {Driver: "mlx5_core"}},
				ifaceSwDroppedCounter: map[string]uint64{"eth0": tt.software},
				sysNetPath:            root,
			}
			if err := collector.prog.Publish(&netdevHwBPFStub{}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := collector.prog.UnPublish(); err != nil {
					t.Error(err)
				}
			})
			metrics, err := collector.Update()
			if err != nil {
				t.Fatal(err)
			}
			if len(metrics) != 1 {
				t.Fatalf("Update returned %d metrics, want 1", len(metrics))
			}
			got := metrics[0]
			if got.Name() != "rx_dropped_total" || got.Value != tt.want {
				t.Errorf("metric = %s %v, want rx_dropped_total %v", got.Name(), got.Value, tt.want)
			}
			labels := got.Labels()
			if labels["device"] != "eth0" || labels["driver"] != "mlx5_core" {
				t.Errorf("labels = %v, want device=eth0 driver=mlx5_core", labels)
			}
		})
	}
}

func TestNetdevHwUpdateMapFailure(t *testing.T) {
	t.Parallel()
	expectedErr := errors.New("software-drop map unavailable")
	collector := &netdevHw{}
	if err := collector.prog.Publish(&netdevHwBPFStub{dumpErr: expectedErr}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := collector.prog.UnPublish(); err != nil {
			t.Error(err)
		}
	})

	metrics, err := collector.Update()
	if !errors.Is(err, expectedErr) || len(metrics) != 0 {
		t.Fatalf("Update() = (%v, %v), want no metrics and %v", metrics, err, expectedErr)
	}
}
