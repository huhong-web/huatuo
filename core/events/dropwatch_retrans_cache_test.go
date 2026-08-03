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

package events

import (
	"net"
	"testing"
	"time"

	"huatuo-bamai/internal/packet"
	"huatuo-bamai/pkg/types"
)

func TestCausalToDropLocation(t *testing.T) {
	tests := []struct {
		causal RetransDropCausal
		want   string
	}{
		{RetransDropDirect, "host_software"},
		{RetransDrop5Tuple, "host_software"},
		{RetransNoDrop, "network_or_host_hardware"},
		{RetransDropNone, ""},
	}

	for _, tt := range tests {
		t.Run(tt.causal.String(), func(t *testing.T) {
			got := causalToDropLocation(tt.causal)
			if got != tt.want {
				t.Errorf("causalToDropLocation(%v) = %q, want %q", tt.causal, got, tt.want)
			}
		})
	}
}

func TestDropwatchRetransCacheCorrelate(t *testing.T) {
	cache := newDropwatchRetransCache(2 * time.Second)
	cache.enable()

	key := makeConnKey("10.0.0.1", "10.0.0.2", 1234, 80)
	cache.entries[key] = []dropwatchRetransCacheEntry{
		{
			ev:       &types.DropWatchTracing{PacketSkbAddr: "0xdeadbeef", Layers: tcpPacketLayers("10.0.0.1", "10.0.0.2", 1234, 80)},
			expiryAt: time.Now().Add(time.Second),
		},
	}

	tests := []struct {
		name       string
		retrans    *types.TCPRetransTracing
		wantCausal RetransDropCausal
	}{
		{
			name:       "skb_match",
			retrans:    &types.TCPRetransTracing{TCPSaddr: "10.0.0.1", TCPDaddr: "10.0.0.2", TCPSport: 1234, TCPDport: 80, SkbAddr: "0xdeadbeef"},
			wantCausal: RetransDropDirect,
		},
		{
			name:       "5tuple_match",
			retrans:    &types.TCPRetransTracing{TCPSaddr: "10.0.0.1", TCPDaddr: "10.0.0.2", TCPSport: 1234, TCPDport: 80, SkbAddr: "0xother"},
			wantCausal: RetransDrop5Tuple,
		},
		{
			name:       "no_match",
			retrans:    &types.TCPRetransTracing{TCPSaddr: "10.0.0.3", TCPDaddr: "10.0.0.4", TCPSport: 9999, TCPDport: 80},
			wantCausal: RetransNoDrop,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			causal, _ := cache.correlate(tt.retrans)
			if causal != tt.wantCausal {
				t.Errorf("correlate() = %v, want %v", causal, tt.wantCausal)
			}
		})
	}
}

func TestDropwatchRetransCacheAddCleansExpired(t *testing.T) {
	cache := newDropwatchRetransCache(time.Second)
	cache.enable()
	now := time.Now()
	cache.entries = map[connKey][]dropwatchRetransCacheEntry{
		"expired": {
			{expiryAt: now.Add(-time.Second)},
		},
		"live": {
			{expiryAt: now.Add(time.Second)},
		},
	}

	cache.add(&types.DropWatchTracing{
		Layers: tcpPacketLayers("10.0.0.1", "10.0.0.2", 1234, 80),
	})

	if _, ok := cache.entries["expired"]; ok {
		t.Error("expired entries should be removed")
	}
	if got := len(cache.entries["live"]); got != 1 {
		t.Errorf("live entries = %d, want 1", got)
	}
}

func TestDropwatchRetransCacheLifecycle(t *testing.T) {
	cache := newDropwatchRetransCache(time.Second)
	event := &types.DropWatchTracing{
		Layers: tcpPacketLayers("10.0.0.1", "10.0.0.2", 1234, 80),
	}
	retrans := &types.TCPRetransTracing{
		TCPSaddr: "10.0.0.1",
		TCPDaddr: "10.0.0.2",
		TCPSport: 1234,
		TCPDport: 80,
	}

	cache.add(event)
	if got := len(cache.entries); got != 0 {
		t.Fatalf("disabled cache entries = %d, want 0", got)
	}
	if causal, _ := cache.correlate(retrans); causal != RetransDropNone {
		t.Fatalf("disabled cache correlation = %v, want %v", causal, RetransDropNone)
	}

	cache.enable()
	cache.add(event)
	if got := len(cache.entries); got != 1 {
		t.Fatalf("enabled cache entries = %d, want 1", got)
	}

	cache.disable()
	if got := len(cache.entries); got != 0 {
		t.Fatalf("disabled cache entries after reset = %d, want 0", got)
	}
	if causal, _ := cache.correlate(retrans); causal != RetransDropNone {
		t.Fatalf("disabled cache correlation after reset = %v, want %v", causal, RetransDropNone)
	}
}

func tcpPacketLayers(saddr, daddr string, sport, dport uint16) *packet.Packet {
	return &packet.Packet{
		IPv4: &packet.IPv4{Saddr: net.ParseIP(saddr), Daddr: net.ParseIP(daddr)},
		TCP:  &packet.TCP{Sport: sport, Dport: dport},
	}
}
