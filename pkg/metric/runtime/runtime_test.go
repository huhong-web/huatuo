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

package runtime

import (
	"maps"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/ccfos/huatuo/internal/version"
	"github.com/ccfos/huatuo/pkg/metric"
)

func TestRegisterCollector(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		expected  []string
	}{
		{
			name:      "register with huatuo namespace",
			namespace: "huatuo",
			expected:  []string{"huatuo_go_goroutines", "huatuo_process_start_time_seconds"},
		},
		{
			name:      "register with null namespace",
			namespace: "",
			expected:  []string{"go_goroutines", "process_start_time_seconds"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			RegisterCollector(reg, tt.namespace, nil)
			families, err := reg.Gather()
			if err != nil {
				t.Fatalf("Gather() returned error: %v", err)
			}
			metricSet := make(map[string]struct{}, len(families))
			for _, f := range families {
				metricSet[f.GetName()] = struct{}{}
			}
			for _, exp := range tt.expected {
				if _, ok := metricSet[exp]; !ok {
					t.Errorf("expected metric %q to be registered", exp)
				}
			}
		})
	}
}

func TestRegisterCollectorProcessMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	RegisterCollector(reg, "huatuo", nil)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() returned error: %v", err)
	}

	hasProcessCPU := false
	hasProcessOpenFDs := false
	for _, f := range families {
		name := f.GetName()
		if name == "huatuo_process_cpu_seconds_total" {
			hasProcessCPU = true
		}
		if name == "huatuo_process_open_fds" {
			hasProcessOpenFDs = true
		}
	}

	if !hasProcessCPU {
		t.Errorf("expected process_cpu_seconds_total metric with namespace prefix")
	}
	if !hasProcessOpenFDs {
		t.Errorf("expected process_open_fds metric with namespace prefix")
	}
}

func TestRegisterCollectorGoMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	RegisterCollector(reg, "huatuo", nil)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() returned error: %v", err)
	}

	hasGoGoroutines := false
	hasGoThreads := false
	for _, f := range families {
		name := f.GetName()
		if name == "huatuo_go_goroutines" {
			hasGoGoroutines = true
		}
		if name == "huatuo_go_threads" {
			hasGoThreads = true
		}
	}

	if !hasGoGoroutines {
		t.Errorf("expected go_goroutines metric with namespace prefix")
	}
	if !hasGoThreads {
		t.Errorf("expected go_threads metric with namespace prefix")
	}
}

func TestRegisterCollectorNoDuplicate(t *testing.T) {
	reg := prometheus.NewRegistry()
	RegisterCollector(reg, "test", nil)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() returned error: %v", err)
	}

	seen := make(map[string]int)
	for _, f := range families {
		name := f.GetName()
		seen[name]++
	}

	for name, count := range seen {
		if count > 1 {
			t.Errorf("metric %q registered %d times, want 1", name, count)
		}
	}
}

func TestRegisterCollectorBuildInfo(t *testing.T) {
	info := &version.Info{
		Name:         "huatuo-bamai",
		Version:      "2.3.0",
		GitCommit:    "0123456789abcdef",
		GitTreeState: "dirty",
		BuildTime:    "20261028120000",
		GoVersion:    "go1.24.3",
		Compiler:     "gc",
		Platform:     "linux/amd64",
	}
	tests := []struct {
		name       string
		namespace  string
		info       *version.Info
		metricName string
	}{
		{
			name:       "bamai namespace",
			namespace:  "huatuo_bamai",
			info:       info,
			metricName: "huatuo_bamai_build_info",
		},
		{
			name:       "empty namespace",
			info:       info,
			metricName: "build_info",
		},
		{
			name:      "development build",
			namespace: "huatuo_bamai",
			info: &version.Info{
				Name:         "huatuo-bamai",
				Version:      version.Devel,
				GitCommit:    version.Devel,
				GitTreeState: "unknown",
				BuildTime:    version.Devel,
				GoVersion:    "go1.24.3",
				Compiler:     "gc",
				Platform:     "linux/arm64",
			},
			metricName: "huatuo_bamai_build_info",
		},
		{
			name:       "without build information",
			namespace:  "huatuo_apiserver",
			metricName: "huatuo_apiserver_build_info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			RegisterCollector(reg, tt.namespace, tt.info)
			families, err := reg.Gather()
			if err != nil {
				t.Fatalf("Gather() returned error: %v", err)
			}

			var buildInfo *dto.MetricFamily
			for _, family := range families {
				if family.GetName() == tt.metricName {
					buildInfo = family
					break
				}
			}
			if tt.info == nil {
				if buildInfo != nil {
					t.Fatalf("unexpected %s without application build information", tt.metricName)
				}
				return
			}

			if buildInfo == nil {
				t.Fatalf("expected %s to be registered", tt.metricName)
			}
			if buildInfo.GetType() != dto.MetricType_GAUGE || len(buildInfo.Metric) != 1 {
				t.Fatalf("expected one build-info gauge, got %v", buildInfo)
			}
			sample := buildInfo.Metric[0]
			if sample.GetGauge().GetValue() != 1 {
				t.Errorf("build-info value = %v, want 1", sample.GetGauge().GetValue())
			}

			labels := make(map[string]string, len(sample.Label))
			for _, label := range sample.Label {
				labels[label.GetName()] = label.GetValue()
			}
			wantLabels := map[string]string{
				"name":             tt.info.Name,
				"version":          tt.info.Version,
				"git_commit":       tt.info.GitCommit,
				"git_tree_state":   tt.info.GitTreeState,
				"build_time":       tt.info.BuildTime,
				"go_version":       tt.info.GoVersion,
				"compiler":         tt.info.Compiler,
				"platform":         tt.info.Platform,
				metric.LabelHost:   metric.DefaultHostname(),
				metric.LabelRegion: metric.DefaultRegion(),
			}
			if !maps.Equal(labels, wantLabels) {
				t.Errorf("build-info labels = %v, want %v", labels, wantLabels)
			}
		})
	}
}
