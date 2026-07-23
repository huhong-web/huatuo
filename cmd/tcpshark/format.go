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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"huatuo-bamai/internal/packet"
	"huatuo-bamai/internal/toolstream"
	"huatuo-bamai/internal/utils/bytesutil"
	"huatuo-bamai/internal/utils/kernaddr"
	"huatuo-bamai/pkg/types"
)

const tcpFlagsSynAck uint8 = 0x12 // SYN(0x02) | ACK(0x10)

// writer is the single write destination for a tcpshark session.
type writer interface {
	Write(ev *types.TCPRetransTracing) error
}

type textWriter struct{ w io.Writer }

func (s *textWriter) Write(ev *types.TCPRetransTracing) error {
	detail := fmt.Sprintf(
		"[%s/%s] %s:%d > %s:%d state=%s",
		ev.Phase,
		ev.Reason,
		ev.Saddr,
		ev.Sport,
		ev.Daddr,
		ev.Dport,
		ev.State,
	)
	if ev.EventType == "tcp_retransmit_synack" {
		detail += " [SYNACK]"
	}
	if ev.SkbAddr != "" {
		detail += " skb=" + ev.SkbAddr
	}
	if ev.TCPSeq != 0 || ev.TCPEndSeq != 0 || ev.TCPAck != 0 {
		detail += fmt.Sprintf(" seq=%d", ev.TCPSeq)
		if ev.TCPEndSeq != 0 {
			detail += fmt.Sprintf(" end=%d", ev.TCPEndSeq)
		}
		detail += fmt.Sprintf(" ack=%d", ev.TCPAck)
	}
	if ev.TCPFlags != "" {
		detail += " flags=" + ev.TCPFlags
	}
	_, err := fmt.Fprintf(
		s.w,
		"%s %s pid=%d[%s] ca=%d retrans=%d\n",
		ev.ObservedTimestamp,
		detail,
		ev.Pid,
		ev.Comm,
		ev.CaState,
		ev.IcskRetransmits,
	)
	return err
}

type jsonWriter struct{ w io.Writer }

func (s *jsonWriter) Write(ev *types.TCPRetransTracing) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = s.w.Write(b)
	return err
}

type socketWriter struct{ client *toolstream.Client }

func (s *socketWriter) Write(ev *types.TCPRetransTracing) error {
	return s.client.Send(ev)
}

type writerOption struct {
	outputFmt string
	sockPath  string
	toolName  string
	version   string
	taskID    string
}

func newWriter(opt *writerOption) (writer, func(), error) {
	if opt.sockPath != "" {
		client, err := toolstream.NewClient(toolstream.ClientOptions{
			SockPath: opt.sockPath,
			ToolName: opt.toolName,
			Version:  opt.version,
			TaskID:   opt.taskID,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("tcpshark: --output-storage: %w", err)
		}
		return &socketWriter{client: client}, client.End, nil
	}

	switch opt.outputFmt {
	case outputJSON:
		return &jsonWriter{w: os.Stdout}, func() {}, nil
	default:
		return &textWriter{w: os.Stdout}, func() {}, nil
	}
}

func formatEvent(ev *retransEvent) *types.TCPRetransTracing {
	tcpFlagsRaw := ev.TCPFlags
	if ev.EventType == retransEventSynack {
		tcpFlagsRaw = tcpFlagsSynAck
	}
	tcpFlags := packet.FormatTCPFlags(tcpFlagsRaw)
	phase, reason := classifyEvent(ev, tcpFlags)

	var saddr, daddr string
	switch ev.Family {
	case unix.AF_INET:
		saddr = net.IP(ev.Saddr[:]).String()
		daddr = net.IP(ev.Daddr[:]).String()
	case unix.AF_INET6:
		saddr = net.IP(ev.SaddrV6[:]).String()
		daddr = net.IP(ev.DaddrV6[:]).String()
	}

	eventTypeStr := "unknown"
	switch ev.EventType {
	case retransEventSKU:
		eventTypeStr = "tcp_retransmit_skb"
	case retransEventSynack:
		eventTypeStr = "tcp_retransmit_synack"
	case retransEventTLP:
		eventTypeStr = "tcp_send_loss_probe"
	}

	return &types.TCPRetransTracing{
		ObservedTimestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Comm:               bytesutil.ToStr(ev.Comm[:]),
		Pid:                ev.TgidPid >> 32,
		MemcgCssAddr:       ev.MemcgCssAddr,
		NetNamespaceCookie: ev.NetCookie,
		NetNamespaceInode:  ev.NetInode,
		Saddr:              saddr,
		Daddr:              daddr,
		Sport:              ev.Sport,
		Dport:              ev.Dport,
		Family:             ev.Family,
		State:              tcpStateNameRaw(uint8(ev.State)),
		Phase:              phase.String(),
		Reason:             reason.String(),
		EventType:          eventTypeStr,
		CaState:            ev.CaState,
		IcskRetransmits:    ev.IcskRetransmits,
		IcskPending:        ev.IcskPending,
		ReordSeen:          ev.ReordSeen,
		DsackDups:          ev.DsackDups,
		TCPSeq:             ev.TCPSeq,
		TCPAck:             ev.TCPAck,
		TCPEndSeq:          ev.TCPEndSeq,
		TCPFlags:           tcpFlags,
		SkbAddr:            kernaddr.Format(ev.SkbAddr),
	}
}

func classifyEvent(ev *retransEvent, tcpFlags string) (packet.RetransPhase, packet.RetransReason) {
	switch ev.EventType {
	case retransEventSynack:
		return packet.RetransPhaseConnect, packet.RetransReasonRTO
	case retransEventTLP:
		return packet.RetransPhaseData, packet.RetransReasonTLP
	default:
		return packet.ClassifyRetrans(
			uint8(ev.State),
			tcpFlags,
			ev.CaState,
			ev.ReordSeen,
			ev.DsackDups,
		)
	}
}

func tcpStateNameRaw(state uint8) string {
	names := []string{
		"unknown", "ESTABLISHED", "SYN_SENT", "SYN_RECV",
		"FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE",
		"CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "NEW_SYN_RECV",
	}
	if int(state) < len(names) {
		return names[state]
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}
