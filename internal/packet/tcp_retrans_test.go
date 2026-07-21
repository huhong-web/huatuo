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

import (
	"fmt"
	"testing"
)

func TestClassifyRetrans(t *testing.T) {
	tests := []struct {
		name       string
		skState    uint8
		tcpFlags   string
		caState    uint8
		reordSeen  uint32
		dsackDups  uint32
		wantPhase  RetransPhase
		wantReason RetransReason
	}{
		// === Connect phase ===
		{
			name:       "SYN retrans (SYN_SENT)",
			skState:    2,
			tcpFlags:   "SYN",
			caState:    4,
			wantPhase:  RetransPhaseConnect,
			wantReason: RetransReasonRTO,
		},
		{
			name:       "SYN retrans (SYN_SENT) no caState",
			skState:    2,
			tcpFlags:   "SYN",
			caState:    0,
			wantPhase:  RetransPhaseConnect,
			wantReason: RetransReasonRTO,
		},
		{
			name:       "SYNACK retrans (SYN_RECV)",
			skState:    3,
			tcpFlags:   "SYN|ACK",
			caState:    4,
			wantPhase:  RetransPhaseConnect,
			wantReason: RetransReasonRTO,
		},
		{
			name:       "SYNACK retrans (NEW_SYN_RECV)",
			skState:    12,
			tcpFlags:   "SYN|ACK",
			caState:    0,
			wantPhase:  RetransPhaseConnect,
			wantReason: RetransReasonRTO,
		},

		// === Data phase: RTO ===
		{
			name:       "RTO retrans (ESTABLISHED + Loss)",
			skState:    1,
			tcpFlags:   "ACK",
			caState:    4,
			wantPhase:  RetransPhaseData,
			wantReason: RetransReasonRTO,
		},

		// === Data phase: Fast retransmit ===
		{
			name:       "Fast retrans (Recovery)",
			skState:    1,
			tcpFlags:   "ACK",
			caState:    3,
			wantPhase:  RetransPhaseData,
			wantReason: RetransReasonFast,
		},

		// === Data phase: Unknown ===
		{
			name:       "Unknown (Open)",
			skState:    1,
			tcpFlags:   "ACK",
			caState:    0,
			wantPhase:  RetransPhaseData,
			wantReason: RetransReasonUnknown,
		},
		{
			name:       "Unknown (Disorder)",
			skState:    1,
			tcpFlags:   "ACK",
			caState:    1,
			wantPhase:  RetransPhaseData,
			wantReason: RetransReasonUnknown,
		},

		// === Reorder-prone fast retransmit ===
		{
			name:       "Fast retrans + reord_seen>0 → reorder_prone_fast",
			skState:    1,
			tcpFlags:   "ACK",
			caState:    3,
			reordSeen:  1,
			wantPhase:  RetransPhaseData,
			wantReason: RetransReasonReorderProneFast,
		},
		{
			name:       "Fast retrans + dsack_dups>0 → reorder_prone_fast",
			skState:    1,
			tcpFlags:   "ACK",
			caState:    3,
			dsackDups:  2,
			wantPhase:  RetransPhaseData,
			wantReason: RetransReasonReorderProneFast,
		},
		{
			name:       "RTO + reorder fields (irrelevant for RTO)",
			skState:    1,
			tcpFlags:   "ACK",
			caState:    4,
			reordSeen:  5,
			dsackDups:  3,
			wantPhase:  RetransPhaseData,
			wantReason: RetransReasonRTO,
		},

		// === Close phase ===
		{
			name:       "FIN retrans (FIN_WAIT1)",
			skState:    4,
			tcpFlags:   "FIN|ACK",
			caState:    4,
			wantPhase:  RetransPhaseClose,
			wantReason: RetransReasonRTO,
		},
		{
			name:       "FIN retrans (LAST_ACK) no caState",
			skState:    9,
			tcpFlags:   "FIN|ACK",
			caState:    0,
			wantPhase:  RetransPhaseClose,
			wantReason: RetransReasonRTO,
		},
		{
			name:       "CLOSE_WAIT residual data Recovery",
			skState:    8,
			tcpFlags:   "ACK|PSH",
			caState:    3,
			wantPhase:  RetransPhaseClose,
			wantReason: RetransReasonFast,
		},
		{
			name:       "CLOSE_WAIT no caState → RTO fallback",
			skState:    8,
			tcpFlags:   "ACK",
			caState:    0,
			wantPhase:  RetransPhaseClose,
			wantReason: RetransReasonRTO,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPhase, gotReason := ClassifyRetrans(tt.skState, tt.tcpFlags, tt.caState, tt.reordSeen, tt.dsackDups)
			if gotPhase != tt.wantPhase {
				t.Errorf("phase: got %v, want %v", gotPhase, tt.wantPhase)
			}
			if gotReason != tt.wantReason {
				t.Errorf("reason: got %v, want %v", gotReason, tt.wantReason)
			}
		})
	}
}

func TestPhaseAndReasonStrings(t *testing.T) {
	phases := []RetransPhase{RetransPhaseConnect, RetransPhaseData, RetransPhaseClose, RetransPhase(99)}
	wantPhaseStrs := []string{"connect", "data", "close", "unknown"}
	for i, p := range phases {
		if s := p.String(); s != wantPhaseStrs[i] {
			t.Errorf("phase %d: got %q, want %q", p, s, wantPhaseStrs[i])
		}
	}

	reasons := []RetransReason{RetransReasonRTO, RetransReasonFast, RetransReasonReorderProneFast, RetransReasonSpurious, RetransReasonUnknown, RetransReason(99)}
	wantReasonStrs := []string{"RTO", "fast_retransmit", "reorder_prone_fast", "spurious", "unknown", "unknown"}
	for i, r := range reasons {
		if s := r.String(); s != wantReasonStrs[i] {
			t.Errorf("reason %d: got %q, want %q", r, s, wantReasonStrs[i])
		}
	}
}

func TestIsReorderProne(t *testing.T) {
	tests := []struct {
		reordSeen uint32
		dsackDups uint32
		want      bool
	}{
		{0, 0, false},
		{1, 0, true},
		{0, 1, true},
		{3, 2, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("reord_seen=%d,dsack_dups=%d", tt.reordSeen, tt.dsackDups), func(t *testing.T) {
			if got := IsReorderProne(tt.reordSeen, tt.dsackDups); got != tt.want {
				t.Errorf("IsReorderProne(%d, %d) = %v, want %v", tt.reordSeen, tt.dsackDups, got, tt.want)
			}
		})
	}
}

func TestClassifyRetransAllStates(t *testing.T) {
	stateNames := []string{
		"", "ESTABLISHED", "SYN_SENT", "SYN_RECV",
		"FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE",
		"CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "NEW_SYN_RECV",
	}
	connectStates := map[uint8]bool{2: true, 3: true, 12: true}
	dataStates := map[uint8]bool{1: true}
	closeStates := map[uint8]bool{4: true, 5: true, 6: true, 8: true, 9: true, 11: true}

	for state := uint8(1); state <= 12; state++ {
		state := state
		t.Run(fmt.Sprintf("state=%s(%d)", stateNames[state], state), func(t *testing.T) {
			phase, _ := ClassifyRetrans(state, "ACK", 0, 0, 0)

			if connectStates[state] && phase != RetransPhaseConnect {
				t.Errorf("state %s(%d): expected Connect phase, got %v", stateNames[state], state, phase)
			}
			if dataStates[state] && phase != RetransPhaseData {
				t.Errorf("state %s(%d): expected Data phase, got %v", stateNames[state], state, phase)
			}
			if closeStates[state] && phase != RetransPhaseClose {
				t.Errorf("state %s(%d): expected Close phase, got %v", stateNames[state], state, phase)
			}
		})
	}
}
