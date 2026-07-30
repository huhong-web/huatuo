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

package types

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestTCPRetransTracingRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		ev   *TCPRetransTracing
	}{
		{
			name: "full_event",
			ev: &TCPRetransTracing{
				ObservedTimestamp:  "2026-07-08T09:19:52.042035335Z",
				TCPReason:          "reorder_prone_fast",
				Source:             SourceTypesEvent,
				Comm:               "kube-apiserver",
				Pid:                1234,
				ContainerID:        "abc123",
				MemcgCssAddr:       0x1000,
				NetNamespaceCookie: 0x2000,
				NetNamespaceInode:  4026531992,
				Saddr:              "10.0.0.1",
				Daddr:              "10.0.0.2",
				Sport:              6443,
				Dport:              58244,
				State:              "ESTABLISHED",
				Phase:              "data",
				EventType:          "tcp_retransmit_skb",
				CaState:            3,
				IcskRetransmits:    0,
				IcskPending:        6,
				ReordSeen:          10,
				DsackDups:          2,
				TCPSeq:             123456,
				TCPAck:             789012,
				TCPEndSeq:          123999,
				TCPFlags:           "ACK|FIN",
				SkbAddr:            "0xffff888012345678",
				DropLocation:       "network_or_host_hardware",
			},
		},
		{
			name: "minimal_event",
			ev: &TCPRetransTracing{
				ObservedTimestamp: "2026-07-08T00:00:00Z",
				TCPReason:         "RTO",
				Saddr:             "::",
				Daddr:             "::",
				Sport:             80,
				Dport:             443,
				State:             "ESTABLISHED",
				Phase:             "data",
				EventType:         "tcp_retransmit_skb",
			},
		},
		{
			name: "synack_zero_seq",
			ev: &TCPRetransTracing{
				ObservedTimestamp: "2026-07-08T00:00:00Z",
				TCPReason:         "RTO",
				Saddr:             "10.0.0.1",
				Daddr:             "10.0.0.2",
				Sport:             6443,
				Dport:             50000,
				State:             "NEW_SYN_RECV",
				Phase:             "connect",
				EventType:         "tcp_retransmit_synack",
			},
		},
		{
			name: "tlp event",
			ev: &TCPRetransTracing{
				ObservedTimestamp: "2026-07-08T00:00:00Z",
				TCPReason:         "TLP",
				Saddr:             "10.0.0.1",
				Daddr:             "10.0.0.2",
				Sport:             6443,
				Dport:             50000,
				State:             "ESTABLISHED",
				Phase:             "data",
				EventType:         "tcp_send_loss_probe",
				TCPSeq:            123,
				TCPAck:            100,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.ev)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			var got TCPRetransTracing
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}

			if diff := cmp.Diff(tt.ev, &got); diff != "" {
				t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTCPRetransTracingOmitEmpty(t *testing.T) {
	ev := &TCPRetransTracing{
		ObservedTimestamp: "2026-07-08T00:00:00Z",
		TCPReason:         "RTO",
		Saddr:             "10.0.0.1",
		Daddr:             "10.0.0.2",
		Sport:             80,
		Dport:             443,
		State:             "ESTABLISHED",
		Phase:             "data",
		EventType:         "tcp_retransmit_skb",
	}

	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}

	if got := raw["tcp_reason"]; got != "RTO" {
		t.Errorf("tcp_reason = %v, want RTO", got)
	}
	if _, ok := raw["reason"]; ok {
		t.Error("reason field should be absent")
	}
	if _, ok := raw["family"]; ok {
		t.Error("family field should be absent")
	}

	omitFields := []string{
		"container_id", "memcg_css", "net_namespace_cookie", "net_namespace_inode",
		"reord_seen", "dsack_dups", "tcp_end_seq", "tcp_flags",
		"skb_addr", "drop_location", "source",
	}
	for _, f := range omitFields {
		if _, ok := raw[f]; ok {
			t.Errorf("omitempty field %q should be absent, got %v", f, raw[f])
		}
	}
}
