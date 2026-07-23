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
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"huatuo-bamai/pkg/types"
)

type errWriter struct{ err error }

func (w errWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

func TestFormatEventSkbAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		skbAddr uint64
		want    string
		omitted bool
	}{
		{
			name:    "zero pointer",
			omitted: true,
		},
		{
			name:    "kernel pointer",
			skbAddr: 0xffff888012345678,
			want:    "0xffff888012345678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			event := formatEvent(&retransEvent{SkbAddr: tt.skbAddr})
			if event.SkbAddr != tt.want {
				t.Fatalf("SkbAddr = %q, want %q", event.SkbAddr, tt.want)
			}

			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			fields := map[string]any{}
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}

			got, present := fields["skb_addr"]
			if tt.omitted && present {
				t.Fatalf("skb_addr = %v, want omitted", got)
			}
			if !tt.omitted && (!present || got != tt.want) {
				t.Fatalf("skb_addr = %v, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatEventTCPFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ev   *retransEvent
		want string
	}{
		{
			name: "skb flags",
			ev: &retransEvent{
				EventType: retransEventSKU,
				TCPFlags:  0x18,
			},
			want: "ACK|PSH",
		},
		{
			name: "synack flags derived from event type",
			ev: &retransEvent{
				EventType: retransEventSynack,
			},
			want: "SYN|ACK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			event := formatEvent(tt.ev)
			if event.TCPFlags != tt.want {
				t.Fatalf("TCPFlags = %q, want %q", event.TCPFlags, tt.want)
			}

			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			fields := map[string]any{}
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if got := fields["tcp_flags"]; got != tt.want {
				t.Fatalf("tcp_flags = %v, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatEventTLP(t *testing.T) {
	t.Parallel()

	event := formatEvent(&retransEvent{
		EventType: retransEventTLP,
		TCPSeq:    123,
		TCPAck:    100,
	})

	if event.EventType != "tcp_send_loss_probe" {
		t.Errorf("EventType = %q, want tcp_send_loss_probe", event.EventType)
	}
	if event.Phase != "data" {
		t.Errorf("Phase = %q, want data", event.Phase)
	}
	if event.Reason != "TLP" {
		t.Errorf("Reason = %q, want TLP", event.Reason)
	}
	if event.TCPSeq != 123 || event.TCPAck != 100 {
		t.Errorf("sequence fields = (%d, %d), want (123, 100)", event.TCPSeq, event.TCPAck)
	}
}

func TestTextWriterFormatsTCPFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ev   *types.TCPRetransTracing
		want string
	}{
		{
			name: "skb flags",
			ev: &types.TCPRetransTracing{
				ObservedTimestamp: "now",
				TCPFlags:          "ACK|PSH",
			},
			want: " flags=ACK|PSH ",
		},
		{
			name: "synack flags",
			ev: &types.TCPRetransTracing{
				ObservedTimestamp: "now",
				EventType:         "tcp_retransmit_synack",
				TCPFlags:          "SYN|ACK",
			},
			want: " flags=SYN|ACK ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			w := &textWriter{w: &buf}

			if err := w.Write(tt.ev); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if got := buf.String(); !strings.Contains(got, tt.want) {
				t.Fatalf("output = %q, want rendered TCP flags %q", got, tt.want)
			}
		})
	}
}

func TestTextWriterPropagatesIOError(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")
	w := &textWriter{w: errWriter{err: boom}}

	err := w.Write(&types.TCPRetransTracing{ObservedTimestamp: "now"})
	if !errors.Is(err, boom) {
		t.Fatalf("Write() error = %v, want %v", err, boom)
	}
}

func TestJSONWriterPropagatesIOError(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")
	w := &jsonWriter{w: errWriter{err: boom}}

	err := w.Write(&types.TCPRetransTracing{ObservedTimestamp: "now"})
	if !errors.Is(err, boom) {
		t.Fatalf("Write() error = %v, want %v", err, boom)
	}
}
