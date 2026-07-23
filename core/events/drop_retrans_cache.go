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

type dropCacheEntry struct {
	ev       *types.DropWatchTracing
	expiryAt time.Time
}

type dropCache struct {
	mu            sync.Mutex
	isEnabled     bool
	entries       map[connKey][]dropCacheEntry
	window        time.Duration
	lastCleanupAt time.Time
}

var globalDropCache = newDropCache(2 * time.Second)

func newDropCache(window time.Duration) *dropCache {
	return &dropCache{
		entries: make(map[connKey][]dropCacheEntry),
		window:  window,
	}
}

func (c *dropCache) enable() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isEnabled {
		return
	}
	c.isEnabled = true
	c.resetLocked()
}

func (c *dropCache) disable() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isEnabled {
		return
	}
	c.isEnabled = false
	c.resetLocked()
}

func (c *dropCache) resetLocked() {
	c.entries = make(map[connKey][]dropCacheEntry)
	c.lastCleanupAt = time.Time{}
}

func (c *dropCache) add(ev *types.DropWatchTracing) {
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
	c.entries[key] = append(c.entries[key], dropCacheEntry{
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
		saddr = p.IPv4.Src.String()
		daddr = p.IPv4.Dst.String()
	case p.IPv6 != nil:
		saddr = p.IPv6.Src.String()
		daddr = p.IPv6.Dst.String()
	default:
		return "", false
	}
	return makeConnKey(saddr, daddr, p.TCP.SrcPort, p.TCP.DstPort), true
}

func (c *dropCache) correlate(retrans *types.TCPRetransTracing) (RetransDropCausal, *types.DropWatchTracing) {
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

	var best RetransDropCausal = RetransNoDrop
	var bestDrop *types.DropWatchTracing
	live := []dropCacheEntry{}

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

func (c *dropCache) cleanupExpired(now time.Time) {
	if !c.lastCleanupAt.IsZero() && now.Sub(c.lastCleanupAt) < c.window {
		return
	}

	for key, entries := range c.entries {
		live := make([]dropCacheEntry, 0, len(entries))
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
