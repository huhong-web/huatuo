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
	"fmt"

	"huatuo-bamai/pkg/types"
)

type RetransDropCausal uint8

const (
	RetransDropNone RetransDropCausal = iota
	RetransDropDirect
	RetransDrop5Tuple
	RetransNoDrop
)

func (c RetransDropCausal) String() string {
	switch c {
	case RetransDropDirect:
		return "drop_direct"
	case RetransDrop5Tuple:
		return "drop_5tuple"
	case RetransNoDrop:
		return "no_drop"
	default:
		return ""
	}
}

type connKey string

func makeConnKey(saddr, daddr string, sport, dport uint16) connKey {
	if saddr < daddr || (saddr == daddr && sport <= dport) {
		return connKey(fmt.Sprintf("%s:%d-%s:%d", saddr, sport, daddr, dport))
	}
	return connKey(fmt.Sprintf("%s:%d-%s:%d", daddr, dport, saddr, sport))
}

func CorrelateDropRetrans(drop *types.DropWatchTracing, retrans *types.TCPRetransTracing) RetransDropCausal {
	return ClassifyDropwatchRetransCausal(drop, retrans)
}

func ClassifyDropwatchRetransCausal(drop *types.DropWatchTracing, retrans *types.TCPRetransTracing) RetransDropCausal {
	if drop.PacketSkbAddr != "" && retrans.SkbAddr != "" && drop.PacketSkbAddr == retrans.SkbAddr {
		return RetransDropDirect
	}

	if drop.Layers == nil || drop.Layers.TCP == nil {
		return RetransDropNone
	}

	return dropLayerMatchCausal(drop, retrans)
}

func dropLayerMatchCausal(drop *types.DropWatchTracing, retrans *types.TCPRetransTracing) RetransDropCausal {
	var saddr, daddr string
	switch {
	case drop.Layers.IPv4 != nil:
		saddr = drop.Layers.IPv4.Src.String()
		daddr = drop.Layers.IPv4.Dst.String()
	case drop.Layers.IPv6 != nil:
		saddr = drop.Layers.IPv6.Src.String()
		daddr = drop.Layers.IPv6.Dst.String()
	default:
		return RetransDropNone
	}
	sport := drop.Layers.TCP.SrcPort
	dport := drop.Layers.TCP.DstPort

	if (saddr == retrans.Saddr && daddr == retrans.Daddr &&
		sport == retrans.Sport && dport == retrans.Dport) ||
		(saddr == retrans.Daddr && daddr == retrans.Saddr &&
			sport == retrans.Dport && dport == retrans.Sport) {
		return RetransDrop5Tuple
	}
	return RetransDropNone
}

func makeRetransKey(ev *types.TCPRetransTracing) connKey {
	return makeConnKey(ev.Saddr, ev.Daddr, ev.Sport, ev.Dport)
}

func BuildRetransCorrelationReport(drop *types.DropWatchTracing, retrans *types.TCPRetransTracing) string {
	causal := ClassifyDropwatchRetransCausal(drop, retrans)

	switch causal {
	case RetransDropDirect:
		return "DROP caused RETRANS directly (same sk_buff): " +
			retrans.Saddr + ":" + fmtU16(retrans.Sport) + " > " +
			retrans.Daddr + ":" + fmtU16(retrans.Dport) +
			" phase=" + retrans.Phase + " reason=" + retrans.Reason

	case RetransDrop5Tuple:
		return "DROP and RETRANS share same connection: " +
			retrans.Saddr + ":" + fmtU16(retrans.Sport) + " > " +
			retrans.Daddr + ":" + fmtU16(retrans.Dport) +
			" phase=" + retrans.Phase + " reason=" + retrans.Reason

	default:
		return ""
	}
}

func fmtU16(v uint16) string {
	return fmt.Sprintf("%d", v)
}
