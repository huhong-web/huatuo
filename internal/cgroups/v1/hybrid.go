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
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ccfos/huatuo/internal/cgroups/paths"
	"github.com/ccfos/huatuo/internal/cgroups/pids"

	extcgroups "github.com/containerd/cgroups/v3"
	extv1 "github.com/containerd/cgroups/v3/cgroup1"
	systemd "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// Runtime operations predate context propagation; bound each manager request
// until the Cgroup interface accepts a caller context.
const systemdTimeout = 10 * time.Second

// CgroupHybrid leaves controller ownership with PID 1. Moving only the v1
// memberships allows systemd to move them back to the unified membership later.
type CgroupHybrid struct {
	*CgroupV1
	runtimeName   string
	properties    []systemd.Property
	unitName      string
	controlGroup  string
	parent        extv1.Cgroup
	parentUnified string
}

// SystemdRunning follows sd_booted and excludes containers whose PID 1 is not
// the host manager. A running manager's D-Bus failure must not trigger fallback.
func SystemdRunning() bool {
	info, err := os.Stat("/run/systemd/system")
	if err != nil || !info.IsDir() {
		return false
	}
	comm, err := os.ReadFile("/proc/1/comm")
	return err == nil && strings.TrimSpace(string(comm)) == "systemd"
}

func NewHybrid() (*CgroupHybrid, error) {
	legacy, err := New()
	if err != nil {
		return nil, err
	}

	return &CgroupHybrid{CgroupV1: legacy}, nil
}

func (c *CgroupHybrid) NewRuntime(path string, spec *specs.LinuxResources) error {
	if c.runtimeName != "" {
		return errors.New("hybrid runtime already exists")
	}

	name := strings.TrimPrefix(path, "/")
	if name == "" || strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("hybrid runtime name must be a single unit name: %q", path)
	}

	properties, err := hybridProperties(spec)
	if err != nil {
		return err
	}

	c.runtimeName = name
	c.properties = properties

	return nil
}

func (c *CgroupHybrid) UpdateRuntime(spec *specs.LinuxResources) error {
	if c.runtimeName == "" {
		return errors.New("hybrid runtime is not initialized")
	}

	properties, err := hybridProperties(spec)
	if err != nil {
		return err
	}
	if c.unitName == "" {
		// Later properties override earlier ones, just as SetUnitProperties does.
		for _, property := range properties {
			replaced := false
			for i := range c.properties {
				if c.properties[i].Name == property.Name {
					c.properties[i] = property
					replaced = true
					break
				}
			}
			if !replaced {
				c.properties = append(c.properties, property)
			}
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.TODO(), systemdTimeout)
	defer cancel()
	conn, err := systemd.NewWithContext(ctx)
	if err != nil {
		return fmt.Errorf("connect hybrid runtime to systemd: %w", err)
	}

	defer conn.Close()
	return conn.SetUnitPropertiesContext(ctx, c.unitName, true, properties...)
}

func (c *CgroupHybrid) AddProc(pid uint64) error {
	if c.runtimeName == "" {
		return errors.New("hybrid runtime is not initialized")
	}
	if c.unitName != "" {
		return errors.New("hybrid runtime scope already has its process")
	}
	if pid == 0 || pid > math.MaxInt32 {
		return fmt.Errorf("invalid runtime PID %d", pid)
	}

	// Capture every original controller before PID 1 moves the process.
	parent, err := extv1.Load(extv1.PidPath(int(pid)))
	if err != nil {
		return fmt.Errorf("load runtime parent: %w", err)
	}

	_, unified, err := extcgroups.ParseCgroupFileUnified(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return err
	}
	if unified == "" {
		return errors.New("hybrid runtime has no unified membership")
	}

	ctx, cancel := context.WithTimeout(context.TODO(), systemdTimeout)
	defer cancel()
	conn, err := systemd.NewWithContext(ctx)
	if err != nil {
		return fmt.Errorf("connect hybrid runtime to systemd: %w", err)
	}

	defer conn.Close()
	unit := fmt.Sprintf("%s-%d.scope", c.runtimeName, pid)
	description := "Huatuo runtime resource limits " + rand.Text()
	properties := []systemd.Property{
		systemd.PropDescription(description),
		systemd.PropPids(uint32(pid)),
		hybridProperty("CPUAccounting", true),
		hybridProperty("MemoryAccounting", true),
	}

	properties = append(properties, c.properties...)
	result := make(chan string, 1)
	if _, err := conn.StartTransientUnitContext(ctx, unit, "fail", properties, result); err != nil {
		createErr := fmt.Errorf("create hybrid runtime scope %s: %w", unit, err)
		var busErr dbus.Error
		if errors.As(err, &busErr) && busErr.Name == "org.freedesktop.systemd1.UnitExists" {
			return createErr
		}
		// A lost reply can hide an accepted creation. The unique description
		// distinguishes our request from a pre-existing unit with the same name.
		owned, checkErr := ownsHybridScope(unit, description)
		if checkErr != nil {
			return errors.Join(createErr, fmt.Errorf("verify scope ownership before rollback: %w", checkErr))
		}
		if !owned {
			return createErr
		}
		c.unitName, c.parent, c.parentUnified = unit, parent, unified
		if restoreErr := c.restoreProcess(pid); restoreErr != nil {
			return errors.Join(createErr, restoreErr)
		}
		return errors.Join(createErr, c.DeleteRuntime())
	}

	// The accepted request owns this unit. Recovery above requires the unique
	// marker instead; UnitExists never grants ownership of an existing unit.
	c.unitName, c.parent, c.parentUnified = unit, parent, unified
	select {
	case status := <-result:
		if status != "done" {
			err = fmt.Errorf("start hybrid runtime scope %s: %s", unit, status)
		}
	case <-ctx.Done():
		err = ctx.Err()
	}

	if err == nil {
		var property *systemd.Property
		property, err = conn.GetUnitTypePropertyContext(ctx, unit, "Scope", "ControlGroup")
		if err == nil {
			var ok bool
			c.controlGroup, ok = property.Value.Value().(string)
			if !ok || c.controlGroup == "" {
				err = errors.New("systemd returned an empty runtime control group")
			}
		}
	}

	if err != nil {
		// The process may already be in the scope even when its start job fails.
		if restoreErr := c.restoreProcess(pid); restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		return errors.Join(err, c.DeleteRuntime())
	}

	return nil
}

func ownsHybridScope(unit, description string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), systemdTimeout)
	defer cancel()
	conn, err := systemd.NewWithContext(ctx)
	if err != nil {
		return false, err
	}

	defer conn.Close()
	property, err := conn.GetUnitPropertyContext(ctx, unit, "Description")
	if unitNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return property.Value.Value() == description, nil
}

func (c *CgroupHybrid) restoreProcess(pid uint64) error {
	// Empty every v1 controller before the unified membership. PID 1 prunes
	// the scope as soon as unified is empty and will not retry a busy v1 leaf.
	if err := c.parent.AddProc(pid); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("restore PID %d controller parents: %w", pid, err)
	}

	file := paths.Path("unified", c.parentUnified, "cgroup.procs")
	if err := os.WriteFile(file, []byte(strconv.FormatUint(pid, 10)), 0); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("restore PID %d unified parent: %w", pid, err)
	}

	return nil
}

func (c *CgroupHybrid) DeleteRuntime() error {
	if c.runtimeName == "" {
		return errors.New("hybrid runtime is not initialized")
	}
	if c.unitName == "" {
		c.runtimeName, c.properties = "", nil
		return nil
	}

	ctx, cancel := context.WithTimeout(context.TODO(), systemdTimeout)
	defer cancel()
	conn, err := systemd.NewWithContext(ctx)
	if err != nil {
		return fmt.Errorf("connect hybrid cleanup to systemd: %w", err)
	}

	defer conn.Close()
	if c.controlGroup == "" {
		property, err := conn.GetUnitTypePropertyContext(ctx, c.unitName, "Scope", "ControlGroup")
		if err != nil {
			if unitNotFound(err) {
				c.clearRuntime()
				return nil
			}
			return fmt.Errorf("locate owned scope for cleanup: %w", err)
		}
		c.controlGroup, _ = property.Value.Value().(string)
		if c.controlGroup == "" {
			return errors.New("owned scope has no control group for safe cleanup")
		}
	}

	file := paths.Path("unified", c.controlGroup)
	processes, err := pids.Tasks(file, "cgroup.procs")
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, pid := range processes {
		if err := c.restoreProcess(uint64(pid)); err != nil {
			return err
		}
	}
	processes, err = pids.Tasks(file, "cgroup.procs")
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(processes) != 0 {
		return errors.New("owned runtime scope is populated; refusing to stop its processes")
	}

	result := make(chan string, 1)
	if _, err := conn.StopUnitContext(ctx, c.unitName, "replace", result); err != nil {
		if !unitNotFound(err) {
			return err
		}
		// PID 1 can collect an empty transient scope before StopUnit arrives.
		result <- "done"
	}

	select {
	case status := <-result:
		if status != "done" {
			return fmt.Errorf("stop hybrid runtime scope %s: %s", c.unitName, status)
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	c.clearRuntime()

	return nil
}

func (c *CgroupHybrid) clearRuntime() {
	c.parent = nil
	c.runtimeName, c.unitName, c.controlGroup, c.parentUnified = "", "", "", ""
	c.properties = nil
}

func unitNotFound(err error) bool {
	var busErr dbus.Error
	return errors.As(err, &busErr) && busErr.Name == "org.freedesktop.systemd1.NoSuchUnit"
}

func hybridProperty(name string, value any) systemd.Property {
	return systemd.Property{
		Name:  name,
		Value: dbus.MakeVariant(value),
	}
}

func hybridProperties(spec *specs.LinuxResources) ([]systemd.Property, error) {
	if spec == nil {
		return nil, errors.New("hybrid runtime resources are nil")
	}
	if len(spec.Devices) != 0 || spec.Pids != nil || spec.BlockIO != nil || len(spec.HugepageLimits) != 0 ||
		spec.Network != nil || len(spec.Rdma) != 0 || len(spec.Unified) != 0 {
		return nil, errors.New("hybrid runtime scope supports only CPU and memory limits")
	}
	//nolint:staticcheck // Reject deprecated kernel-memory fields instead of silently ignoring limits.
	if memory := spec.Memory; memory != nil && (memory.Reservation != nil || memory.Swap != nil ||
		memory.Kernel != nil || memory.KernelTCP != nil || memory.Swappiness != nil ||
		memory.DisableOOMKiller != nil || memory.UseHierarchy != nil || memory.CheckBeforeUpdate != nil) {
		return nil, errors.New("hybrid runtime scope supports only the hard memory limit")
	}

	var properties []systemd.Property
	if cpu := spec.CPU; cpu != nil {
		if cpu.Burst != nil || cpu.RealtimeRuntime != nil || cpu.RealtimePeriod != nil ||
			cpu.Cpus != "" || cpu.Mems != "" || cpu.Idle != nil {
			return nil, errors.New("hybrid runtime scope supports only CPU quota, period and shares")
		}
		if cpu.Shares != nil {
			if *cpu.Shares < 2 || *cpu.Shares > 262144 {
				return nil, errors.New("hybrid CPU shares must be between 2 and 262144")
			}
			properties = append(properties, hybridProperty("CPUShares", *cpu.Shares))
		}
		if cpu.Period != nil && cpu.Quota == nil {
			return nil, errors.New("hybrid CPU period requires a quota")
		}
		if cpu.Period != nil && (*cpu.Period < 1000 || *cpu.Period > 1000000) {
			return nil, errors.New("hybrid CPU period must be between 1000 and 1000000 microseconds")
		}
		if cpu.Quota != nil {
			quota := uint64(math.MaxUint64)
			if *cpu.Quota != -1 {
				if *cpu.Quota < 1000 {
					return nil, errors.New("hybrid CPU quota must be at least 1000 microseconds or -1 for unlimited")
				}
				if cpu.Period == nil {
					return nil, errors.New("hybrid CPU quota needs a nonzero period")
				}
				if uint64(*cpu.Quota) > math.MaxUint64/microsecondsInSecond {
					return nil, errors.New("hybrid CPU quota overflows microseconds per second")
				}
				quota = uint64(*cpu.Quota) * microsecondsInSecond / *cpu.Period
			}
			properties = append(properties, hybridProperty("CPUQuotaPerSecUSec", quota))
		}
		if cpu.Period != nil {
			properties = append(properties, hybridProperty("CPUQuotaPeriodUSec", *cpu.Period))
		}
	}

	if spec.Memory != nil && spec.Memory.Limit != nil {
		if *spec.Memory.Limit < -1 {
			return nil, errors.New("hybrid memory limit must be nonnegative or -1 for unlimited")
		}
		properties = append(properties, hybridProperty("MemoryMax", uint64(*spec.Memory.Limit)))
	}

	return properties, nil
}
