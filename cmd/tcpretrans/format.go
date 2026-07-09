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
	"os"

	"huatuo-bamai/internal/toolstream"
	"huatuo-bamai/pkg/types"
)

// writer is the single write destination for a tcpretrans session.
type writer interface {
	Write(ev *types.TCPRetransTracing) error
}

type textWriter struct{ w io.Writer }

func (s *textWriter) Write(ev *types.TCPRetransTracing) error {
	detail := fmt.Sprintf("[%s/%s] %s:%d > %s:%d state=%s",
		ev.Phase, ev.Reason, ev.Saddr, ev.Sport, ev.Daddr, ev.Dport, ev.State)
	if ev.EventType == "tcp_retransmit_synack" {
		detail += " [SYNACK]"
	}
	if ev.SkbAddr != "" {
		detail += " skb=" + ev.SkbAddr
	}
	if ev.TCPSeq != 0 || ev.TCPAck != 0 {
		detail += fmt.Sprintf(" seq=%d ack=%d", ev.TCPSeq, ev.TCPAck)
	}
	_, err := fmt.Fprintf(s.w, "%s %s pid=%d[%s] ca=%d retrans=%d\n",
		ev.ObservedTimestamp, detail, ev.Pid, ev.Comm, ev.CaState, ev.IcskRetransmits)
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

func newWriter(outputFmt string, client *toolstream.Client) writer {
	switch {
	case client != nil:
		return &socketWriter{client: client}
	case outputFmt == "json":
		return &jsonWriter{w: os.Stdout}
	default:
		return &textWriter{w: os.Stdout}
	}
}
