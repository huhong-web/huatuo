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

// RetransPhase is the connection state-machine stage for a TCP retransmission.
type RetransPhase uint8

const (
	RetransPhaseConnect RetransPhase = iota
	RetransPhaseData
	RetransPhaseClose
)

func (p RetransPhase) String() string {
	switch p {
	case RetransPhaseConnect:
		return "connect"
	case RetransPhaseData:
		return "data"
	case RetransPhaseClose:
		return "close"
	default:
		return "unknown"
	}
}

// RetransReason is the trigger subcategory within a phase.
type RetransReason uint8

const (
	RetransReasonRTO RetransReason = iota
	RetransReasonFast
	RetransReasonReorderProneFast
	RetransReasonTLP
	RetransReasonSpurious
	RetransReasonUnknown
)

func (r RetransReason) String() string {
	switch r {
	case RetransReasonRTO:
		return "RTO"
	case RetransReasonFast:
		return "fast_retransmit"
	case RetransReasonReorderProneFast:
		return "reorder_prone_fast"
	case RetransReasonTLP:
		return "TLP"
	case RetransReasonSpurious:
		return "spurious"
	default:
		return "unknown"
	}
}

// TCPRetransTracing is the canonical JSON schema for a TCP retransmission event.
type TCPRetransTracing struct {
	ObservedTimestamp  string `json:"observed_timestamp"`
	TCPReason          string `json:"tcp_reason"` // "RTO", "fast_retransmit", "reorder_prone_fast", "TLP", "spurious", "unknown"
	Source             string `json:"source,omitempty"`
	Comm               string `json:"comm"`
	Pid                uint64 `json:"pid"`
	ContainerID        string `json:"container_id,omitempty"`
	MemcgCssAddr       uint64 `json:"memcg_css,omitempty"`
	NetNamespaceCookie uint64 `json:"net_namespace_cookie,omitempty"`
	NetNamespaceInode  uint32 `json:"net_namespace_inode,omitempty"`

	// Connection identity.
	Saddr string `json:"saddr"`
	Daddr string `json:"daddr"`
	Sport uint16 `json:"sport"`
	Dport uint16 `json:"dport"`

	// TCP state machine.
	State string `json:"tcp_state"` // e.g. "ESTABLISHED", "SYN_SENT", "SYN_RECV"

	// Phase classification.
	Phase string `json:"phase"` // "connect", "data", "close"

	// Event discriminator.
	EventType string `json:"event_type"` // "tcp_retransmit_skb", "tcp_retransmit_synack", or "tcp_send_loss_probe"

	// Congestion control state (raw BPF fields).
	CaState         uint8 `json:"ca_state"`         // icsk_ca_state: 0=Open, 3=Recovery, 4=Loss
	IcskRetransmits uint8 `json:"icsk_retransmits"` // current retrans counter for the connection
	// IcskPending is the raw inet_connection_sock timer state: 0=None,
	// 1=RTO, 3=Probe0, 5=TLP, and 6=REO. Modern kernels keep 2 (DACK)
	// in icsk_ack.pending; the meaning of 4 depends on the kernel version.
	IcskPending uint8 `json:"icsk_pending"`

	ReordSeen uint32 `json:"reord_seen,omitempty"` // tp->reord_seen (cumulative)
	DsackDups uint32 `json:"dsack_dups,omitempty"` // tp->dsack_dups (cumulative)

	// TCP sequence numbers.
	// For tcp_retransmit_skb, tcp_seq/tcp_end_seq come from
	// TCP_SKB_CB(skb), and tcp_ack comes from tcp_sk(sk)->rcv_nxt. The skb in
	// tcp_retransmit_skb is headerless, so tcphdr.seq/ack_seq are not reliable.
	// tcp_flags is the rendered TCP flag set, e.g. "ACK|PSH".
	// For tcp_retransmit_synack, tcp_flags is derived from the event type.
	// For tcp_send_loss_probe, tcp_seq/tcp_ack contain snd_nxt/snd_una and the
	// remaining TCP metadata is unavailable at the probe point.
	TCPSeq    uint32 `json:"tcp_seq"`
	TCPAck    uint32 `json:"tcp_ack"`
	TCPEndSeq uint32 `json:"tcp_end_seq,omitempty"`
	TCPFlags  string `json:"tcp_flags,omitempty"`

	// Kernel internals.
	SkbAddr string `json:"skb_addr,omitempty"` // the sk_buff pointer being retransmitted

	// Correlation with dropwatch / netdev_hw.
	DropLocation string `json:"drop_location,omitempty"` // "host_software", "network_or_host_hardware", or "unknown"
}
