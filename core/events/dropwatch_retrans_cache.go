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
	"sync"
	"time"

	"huatuo-bamai/internal/packet"
	"huatuo-bamai/pkg/types"
)

type dropwatchRetransCacheEntry struct {
	ev       *types.DropWatchTracing
	expiryAt time.Time
}

type dropwatchRetransCache struct {
	mu            sync.Mutex
	isEnabled     bool
	entries       map[connKey][]dropwatchRetransCacheEntry
	window        time.Duration
	lastCleanupAt time.Time
}

var globalDropwatchRetransCache = newDropwatchRetransCache(2 * time.Second)

func newDropwatchRetransCache(window time.Duration) *dropwatchRetransCache {
	return &dropwatchRetransCache{
		entries: make(map[connKey][]dropwatchRetransCacheEntry),
		window:  window,
	}
}

func (c *dropwatchRetransCache) enable() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isEnabled {
		return
	}
	c.isEnabled = true
	c.resetLocked()
}

func (c *dropwatchRetransCache) disable() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isEnabled {
		return
	}
	c.isEnabled = false
	c.resetLocked()
}

func (c *dropwatchRetransCache) resetLocked() {
	c.entries = make(map[connKey][]dropwatchRetransCacheEntry)
	c.lastCleanupAt = time.Time{}
}

func (c *dropwatchRetransCache) add(ev *types.DropWatchTracing) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isEnabled {
		return
	}

	key, ok := makeDropKeyFromLayers(ev.Layers)
	if !ok {
		return
	}

	now := time.Now()
	c.cleanupExpired(now)
	c.entries[key] = append(c.entries[key], dropwatchRetransCacheEntry{
		ev:       ev,
		expiryAt: now.Add(c.window),
	})
}

func makeDropKeyFromLayers(p *packet.Packet) (connKey, bool) {
	if p == nil || p.TCP == nil {
		return "", false
	}
	var saddr, daddr string
	switch {
	case p.IPv4 != nil:
		saddr = p.IPv4.Saddr.String()
		daddr = p.IPv4.Daddr.String()
	case p.IPv6 != nil:
		saddr = p.IPv6.Saddr.String()
		daddr = p.IPv6.Daddr.String()
	default:
		return "", false
	}
	return makeConnKey(saddr, daddr, p.TCP.Sport, p.TCP.Dport), true
}

func (c *dropwatchRetransCache) correlate(retrans *types.TCPRetransTracing) (RetransDropCausal, *types.DropWatchTracing) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isEnabled {
		return RetransDropNone, nil
	}

	key := makeRetransKey(retrans)
	now := time.Now()
	entries, ok := c.entries[key]
	if !ok {
		return RetransNoDrop, nil
	}

	best := RetransNoDrop
	var bestDrop *types.DropWatchTracing
	live := []dropwatchRetransCacheEntry{}

	for _, e := range entries {
		if now.After(e.expiryAt) {
			continue
		}
		live = append(live, e)

		causal := ClassifyDropwatchRetransCausal(e.ev, retrans)
		if causal == RetransDropDirect {
			best = RetransDropDirect
			bestDrop = e.ev
			break
		}
		if causal == RetransDrop5Tuple && best != RetransDropDirect {
			best = RetransDrop5Tuple
			bestDrop = e.ev
		}
	}

	c.entries[key] = live
	return best, bestDrop
}

func (c *dropwatchRetransCache) cleanupExpired(now time.Time) {
	if !c.lastCleanupAt.IsZero() && now.Sub(c.lastCleanupAt) < c.window {
		return
	}

	for key, entries := range c.entries {
		live := make([]dropwatchRetransCacheEntry, 0, len(entries))
		for _, entry := range entries {
			if !now.After(entry.expiryAt) {
				live = append(live, entry)
			}
		}
		if len(live) == 0 {
			delete(c.entries, key)
			continue
		}
		c.entries[key] = live
	}

	c.lastCleanupAt = now
}

func causalToDropLocation(causal RetransDropCausal) string {
	switch causal {
	case RetransDropDirect, RetransDrop5Tuple:
		return "host_software"
	case RetransNoDrop:
		return "network_or_host_hardware"
	default:
		return ""
	}
}
