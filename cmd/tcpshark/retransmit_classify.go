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

import "huatuo-bamai/pkg/types"

func classifyEvent(ev *retransEvent, tcpFlags string) (types.RetransPhase, types.RetransReason) {
	switch ev.EventType {
	case retransEventSynack:
		return types.RetransPhaseConnect, types.RetransReasonRTO
	case retransEventTLP:
		return types.RetransPhaseData, types.RetransReasonTLP
	default:
		return classifyRetrans(
			uint8(ev.State),
			tcpFlags,
			ev.CaState,
			ev.ReordSeen,
			ev.DsackDups,
		)
	}
}

func classifyRetrans(
	skStateNum uint8,
	tcpFlags string,
	caState uint8,
	reordSeen uint32,
	dsackDups uint32,
) (types.RetransPhase, types.RetransReason) {
	phase := phaseFromState(skStateNum, tcpFlags)
	reason := reasonFromTree(caState, reordSeen, dsackDups, phase)
	return phase, reason
}

func phaseFromState(skStateNum uint8, tcpFlags string) types.RetransPhase {
	switch skStateNum {
	case 2: // SYN_SENT
		return types.RetransPhaseConnect
	case 3, 12: // SYN_RECV, NEW_SYN_RECV
		return types.RetransPhaseConnect
	case 1: // ESTABLISHED
		return types.RetransPhaseData
	case 4, 8, 9, 11: // FIN_WAIT1, CLOSE_WAIT, LAST_ACK, CLOSING
		return types.RetransPhaseClose
	case 5, 6: // FIN_WAIT2, TIME_WAIT
		return types.RetransPhaseClose
	default:
		return phaseFromFlags(tcpFlags)
	}
}

func reasonFromTree(
	caState uint8,
	reordSeen uint32,
	dsackDups uint32,
	phase types.RetransPhase,
) types.RetransReason {
	switch caState {
	case 4: // TCP_CA_Loss
		return types.RetransReasonRTO
	case 3: // TCP_CA_Recovery
		if isReorderProne(reordSeen, dsackDups) {
			return types.RetransReasonReorderProneFast
		}
		return types.RetransReasonFast
	default:
		return reasonFromPhase(phase)
	}
}

func isReorderProne(reordSeen, dsackDups uint32) bool {
	return reordSeen > 0 || dsackDups > 0
}

func phaseFromFlags(flags string) types.RetransPhase {
	if flags == "" {
		return types.RetransPhaseData
	}
	if containsFlag(flags, "SYN") && !containsFlag(flags, "ACK") {
		return types.RetransPhaseConnect
	}
	if containsFlag(flags, "SYN") && containsFlag(flags, "ACK") {
		return types.RetransPhaseConnect
	}
	if containsFlag(flags, "FIN") {
		return types.RetransPhaseClose
	}
	return types.RetransPhaseData
}

func reasonFromPhase(phase types.RetransPhase) types.RetransReason {
	if phase == types.RetransPhaseConnect {
		return types.RetransReasonRTO
	}
	if phase == types.RetransPhaseClose {
		return types.RetransReasonRTO
	}
	return types.RetransReasonUnknown
}

func containsFlag(flags, flag string) bool {
	for i := 0; i <= len(flags)-len(flag); i++ {
		if flags[i:i+len(flag)] == flag {
			return true
		}
	}
	return false
}
