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

package packet

// RetransPhase classifies a TCP retransmission by connection state-machine stage.
// It is derived purely from sk_state and tcp_flags already collected in dropwatch events.
type RetransPhase uint8

const (
	RetransPhaseConnect RetransPhase = iota // 3-way handshake: SYN or SYNACK retrans
	RetransPhaseData                        // ESTABLISHED data transfer
	RetransPhaseClose                       // 4-way teardown: FIN/LAST_ACK/CLOSING
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
// It is orthogonal to RetransPhase.
type RetransReason uint8

const (
	RetransReasonRTO              RetransReason = iota // RTO timeout — worst case, cwnd collapses
	RetransReasonFast                                  // Fast retransmit (dupACK/SACK/RACK), cwnd halves
	RetransReasonReorderProneFast                      // Fast retransmit on a flow with prior reorder history
	RetransReasonTLP                                   // Tail Loss Probe
	RetransReasonSpurious                              // DSACK-verified unnecessary retrans (Layer 1)
	RetransReasonUnknown                               // insufficient data to determine
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

// ICSK_TIME_* constants (stable since 4.x, #define in inet_connection_sock.h:145-150).
const (
	ICSKTimeRetrans    uint8 = 1 // ICSK_TIME_RETRANS
	ICSKTimeProbe0     uint8 = 3 // ICSK_TIME_PROBE0
	ICSKTimeLossProbe  uint8 = 5 // ICSK_TIME_LOSS_PROBE
	ICSKTimeReoTimeout uint8 = 6 // ICSK_TIME_REO_TIMEOUT
)

// ClassifyRetrans determines the phase and reason for a TCP retransmission
// using the classification tree from ca_state + icsk_pending.
//
// Classification tree:
//
//	ca_state=Loss(4)    && pending==0    → RTO (普通 RTO 重传)
//	ca_state=Loss(4)    && pending!=0    → RTO (RTO 恢复期补发)
//	ca_state=Recovery(3)&& pending==6    → fast_retransmit (RACK reo timer)
//	ca_state=Recovery(3)&& pending!=6    → fast_retransmit (dup ACK/SACK)
//	ca_state<=2         && pending==5    → TLP (尾丢包探测)
//	ca_state<=2         && pending!=5    → unknown (TSQ 边角)
//
// Phase is derived from sk_state. Reorder history is used to distinguish
// ReorderProneFast from Fast when ca_state=Recovery.
func ClassifyRetrans(skStateNum uint8, tcpFlags string, caState, icskPending uint8, reordSeen, dsackDups uint32) (RetransPhase, RetransReason) {
	phase := phaseFromState(skStateNum, tcpFlags)
	reason := reasonFromTree(caState, icskPending, reordSeen, dsackDups, phase)
	return phase, reason
}

func phaseFromState(skStateNum uint8, tcpFlags string) RetransPhase {
	switch skStateNum {
	case 2: // SYN_SENT
		return RetransPhaseConnect
	case 3, 12: // SYN_RECV, NEW_SYN_RECV
		return RetransPhaseConnect
	case 1: // ESTABLISHED
		return RetransPhaseData
	case 4, 8, 9, 11: // FIN_WAIT1, CLOSE_WAIT, LAST_ACK, CLOSING
		return RetransPhaseClose
	case 5, 6: // FIN_WAIT2, TIME_WAIT
		return RetransPhaseClose
	default:
		return phaseFromFlags(tcpFlags)
	}
}

func reasonFromTree(caState, icskPending uint8, reordSeen, dsackDups uint32, phase RetransPhase) RetransReason {
	switch caState {
	case 4: // TCP_CA_Loss
		return RetransReasonRTO
	case 3: // TCP_CA_Recovery
		if IsReorderProne(reordSeen, dsackDups) {
			return RetransReasonReorderProneFast
		}
		return RetransReasonFast
	default: // ca_state 0-2 (Open, Disorder, CWR)
		if icskPending == ICSKTimeLossProbe {
			return RetransReasonTLP
		}
		return reasonFromFlagsAndPhase("", phase)
	}
}

// IsReorderProne returns true when the flow has prior reorder history.
// This is a flow-level heuristic (cumulative counters), not a per-event verdict.
func IsReorderProne(reordSeen, dsackDups uint32) bool {
	return reordSeen > 0 || dsackDups > 0
}

func phaseFromFlags(flags string) RetransPhase {
	if flags == "" {
		return RetransPhaseData
	}
	if containsFlag(flags, "SYN") && !containsFlag(flags, "ACK") {
		return RetransPhaseConnect
	}
	if containsFlag(flags, "SYN") && containsFlag(flags, "ACK") {
		return RetransPhaseConnect
	}
	if containsFlag(flags, "FIN") {
		return RetransPhaseClose
	}
	return RetransPhaseData
}

func reasonFromFlagsAndPhase(flags string, phase RetransPhase) RetransReason {
	if phase == RetransPhaseConnect {
		return RetransReasonRTO // SYN/SYNACK retransmits are always RTO-driven
	}
	if phase == RetransPhaseClose {
		return RetransReasonRTO // Close-phase retransmits default to RTO
	}
	return RetransReasonUnknown
}

func containsFlag(flags, flag string) bool {
	for i := 0; i <= len(flags)-len(flag); i++ {
		if flags[i:i+len(flag)] == flag {
			return true
		}
	}
	return false
}
