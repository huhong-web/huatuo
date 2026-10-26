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

package v1

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/ccfos/huatuo/internal/cgroups/paths"
	"github.com/ccfos/huatuo/internal/cgroups/subsystem"

	"github.com/opencontainers/runtime-spec/specs-go"
)

func TestCpuUsageReadsCPUAcctSubsystem(t *testing.T) {
	root := t.TempDir()
	oldRoot := paths.RootfsDefaultPath
	paths.RootfsDefaultPath = root
	t.Cleanup(func() { paths.RootfsDefaultPath = oldRoot })

	path := filepath.Join("test", "usage")
	writeCgroupFile(t, paths.Path(subsystem.SubsystemCPUAcct, path, "cpuacct.stat"), "user 100\nsystem 50\n")
	writeCgroupFile(t, paths.Path(subsystem.SubsystemCPUAcct, path, "cpuacct.usage"), "1500000\n")

	usage, err := (&CgroupV1{}).CpuUsage(path)
	if err != nil {
		t.Fatal(err)
	}

	wantUser := 100 * microsecondsInSecond / clockTicks
	wantSystem := 50 * microsecondsInSecond / clockTicks
	if usage.User != wantUser || usage.System != wantSystem || usage.Usage != 1500 {
		t.Errorf("CpuUsage() = %+v, want User=%d System=%d Usage=1500", usage, wantUser, wantSystem)
	}
}

func TestCpuQuotaAndPeriodEffectiveCPUCount(t *testing.T) {
	root := t.TempDir()
	oldRoot := paths.RootfsDefaultPath
	paths.RootfsDefaultPath = root
	t.Cleanup(func() { paths.RootfsDefaultPath = oldRoot })

	tests := []struct {
		name   string
		cpuset string
		want   uint64
	}{
		{name: "cpuset", cpuset: "0-3", want: 4},
		{name: "missing", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("test", tt.name)
			writeCgroupFile(t, paths.Path(subsystem.SubsystemCPU, path, "cpu.cfs_period_us"), "100000\n")
			writeCgroupFile(t, paths.Path(subsystem.SubsystemCPU, path, "cpu.cfs_quota_us"), "-1\n")
			if tt.cpuset != "" {
				writeCgroupFile(t, paths.Path(subsystem.SubsystemCPUSet, path, "cpuset.cpus"), tt.cpuset+"\n")
			}

			quota, err := (&CgroupV1{}).CpuQuotaAndPeriod(path)
			if err != nil {
				t.Fatal(err)
			}
			if quota.EffectiveCPUCount != tt.want {
				t.Errorf("EffectiveCPUCount = %d, want %d", quota.EffectiveCPUCount, tt.want)
			}
		})
	}
}

func writeCgroupFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestHybridRuntimeProperties(t *testing.T) {
	period, quota, memory := uint64(100000), int64(123451), int64(768*1024*1024)
	properties, err := hybridProperties(&specs.LinuxResources{
		CPU: &specs.LinuxCPU{
			Period: &period,
			Quota:  &quota,
		},
		Memory: &specs.LinuxMemory{Limit: &memory},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := make(map[string]any)
	for _, property := range properties {
		got[property.Name] = property.Value.Value()
	}
	for name, want := range map[string]uint64{
		"CPUQuotaPerSecUSec": 1234510,
		"CPUQuotaPeriodUSec": period,
		"MemoryMax":          uint64(memory),
	} {
		if got[name] != want {
			t.Errorf("%s = %v, want %v", name, got[name], want)
		}
	}

	quota = -1
	properties, err = hybridProperties(&specs.LinuxResources{CPU: &specs.LinuxCPU{Quota: &quota}})
	if err != nil {
		t.Fatal(err)
	}
	if properties[0].Value.Value() != uint64(math.MaxUint64) {
		t.Errorf("unlimited quota = %v", properties[0])
	}
	properties, err = hybridProperties(&specs.LinuxResources{CPU: &specs.LinuxCPU{
		Period: &period,
		Quota:  &quota,
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, property := range properties {
		if property.Name == "MemoryMax" {
			t.Fatal("CPU-only update changes memory limit")
		}
	}
}

func TestHybridRuntimeRejectsInvalidResources(t *testing.T) {
	period := uint64(100000)
	for _, quota := range []int64{-2, 0, 1, 999, math.MaxInt64} {
		if _, err := hybridProperties(&specs.LinuxResources{CPU: &specs.LinuxCPU{
			Period: &period,
			Quota:  &quota,
		}}); err == nil {
			t.Errorf("quota %d accepted", quota)
		}
	}

	quota := int64(50000)
	if _, err := hybridProperties(&specs.LinuxResources{CPU: &specs.LinuxCPU{Quota: &quota}}); err == nil {
		t.Error("quota without period accepted")
	}
	for _, period := range []uint64{0, 999, 1000001} {
		if _, err := hybridProperties(&specs.LinuxResources{CPU: &specs.LinuxCPU{
			Period: &period,
			Quota:  &quota,
		}}); err == nil {
			t.Errorf("period %d accepted", period)
		}
	}

	if _, err := hybridProperties(&specs.LinuxResources{CPU: &specs.LinuxCPU{Period: &period}}); err == nil {
		t.Error("period-only update accepted")
	}
	for _, shares := range []uint64{0, 1, 262145} {
		if _, err := hybridProperties(&specs.LinuxResources{CPU: &specs.LinuxCPU{Shares: &shares}}); err == nil {
			t.Errorf("CPU shares %d accepted", shares)
		}
	}
	for _, shares := range []uint64{2, 262144} {
		if _, err := hybridProperties(&specs.LinuxResources{CPU: &specs.LinuxCPU{Shares: &shares}}); err != nil {
			t.Errorf("CPU shares %d: %v", shares, err)
		}
	}

	memory := int64(-2)
	for _, resources := range []*specs.LinuxResources{
		nil,
		{Memory: &specs.LinuxMemory{Limit: &memory}},
		{CPU: &specs.LinuxCPU{Cpus: "0"}},
		{Pids: &specs.LinuxPids{Limit: 1}},
	} {
		if _, err := hybridProperties(resources); err == nil {
			t.Errorf("invalid resources accepted: %+v", resources)
		}
	}
}

func TestHybridPendingRuntimeLifecycle(t *testing.T) {
	c, err := NewHybrid()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteRuntime(); err == nil {
		t.Fatal("delete without runtime accepted")
	}
	if err := c.NewRuntime("test", &specs.LinuxResources{}); err != nil {
		t.Fatal(err)
	}
	if err := c.NewRuntime("other", &specs.LinuxResources{}); err == nil {
		t.Fatal("existing runtime replaced")
	}
	quota, period := int64(50000), uint64(100000)
	if err := c.UpdateRuntime(&specs.LinuxResources{CPU: &specs.LinuxCPU{
		Period: &period,
		Quota:  &quota,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteRuntime(); err != nil {
		t.Fatal(err)
	}
	if err := c.AddProc(uint64(os.Getpid())); err == nil {
		t.Fatal("PID added without runtime")
	}
	if err := c.DeleteRuntime(); err == nil {
		t.Fatal("double delete accepted")
	}
}
