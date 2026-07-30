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
	"unsafe"

	"huatuo-bamai/internal/bpf"
)

const (
	retransEventSKU    = 1
	retransEventSynack = 2
	retransEventTLP    = 3
)

const (
	retransEventSize = 128

	retransEventKtimeNSOffset         = 0
	retransEventTgidPidOffset         = 8
	retransEventMemcgCssAddrOffset    = 16
	retransEventSkbAddrOffset         = 24
	retransEventNetCookieOffset       = 32
	retransEventNetInodeOffset        = 40
	retransEventStateOffset           = 44
	retransEventReordSeenOffset       = 48
	retransEventDsackDupsOffset       = 52
	retransEventTCPSeqOffset          = 56
	retransEventTCPAckOffset          = 60
	retransEventTCPEndSeqOffset       = 64
	retransEventSportOffset           = 68
	retransEventDportOffset           = 70
	retransEventFamilyOffset          = 72
	retransEventCaStateOffset         = 74
	retransEventIcskRetransmitsOffset = 75
	retransEventEventTypeOffset       = 76
	retransEventIcskPendingOffset     = 77
	retransEventTCPFlagsOffset        = 78
	retransEventSaddrOffset           = 79
	retransEventDaddrOffset           = 95
	retransEventCommOffset            = 111
	retransEventPadOffset             = 127
)

type retransEvent struct {
	KtimeNS         uint64
	TgidPid         uint64
	MemcgCssAddr    uint64
	SkbAddr         uint64
	NetCookie       uint64
	NetInode        uint32
	State           uint32
	ReordSeen       uint32
	DsackDups       uint32
	TCPSeq          uint32
	TCPAck          uint32
	TCPEndSeq       uint32
	Sport           uint16
	Dport           uint16
	Family          uint16
	CaState         uint8
	IcskRetransmits uint8
	EventType       uint8
	IcskPending     uint8
	TCPFlags        uint8
	Saddr           [16]byte
	Daddr           [16]byte
	Comm            [bpf.TaskCommLen]byte
	Pad             [1]byte
}

var (
	_ [retransEventSize]byte = [unsafe.Sizeof(retransEvent{})]byte{}

	_ [retransEventKtimeNSOffset]byte         = [unsafe.Offsetof(retransEvent{}.KtimeNS)]byte{}
	_ [retransEventTgidPidOffset]byte         = [unsafe.Offsetof(retransEvent{}.TgidPid)]byte{}
	_ [retransEventMemcgCssAddrOffset]byte    = [unsafe.Offsetof(retransEvent{}.MemcgCssAddr)]byte{}
	_ [retransEventSkbAddrOffset]byte         = [unsafe.Offsetof(retransEvent{}.SkbAddr)]byte{}
	_ [retransEventNetCookieOffset]byte       = [unsafe.Offsetof(retransEvent{}.NetCookie)]byte{}
	_ [retransEventNetInodeOffset]byte        = [unsafe.Offsetof(retransEvent{}.NetInode)]byte{}
	_ [retransEventStateOffset]byte           = [unsafe.Offsetof(retransEvent{}.State)]byte{}
	_ [retransEventReordSeenOffset]byte       = [unsafe.Offsetof(retransEvent{}.ReordSeen)]byte{}
	_ [retransEventDsackDupsOffset]byte       = [unsafe.Offsetof(retransEvent{}.DsackDups)]byte{}
	_ [retransEventTCPSeqOffset]byte          = [unsafe.Offsetof(retransEvent{}.TCPSeq)]byte{}
	_ [retransEventTCPAckOffset]byte          = [unsafe.Offsetof(retransEvent{}.TCPAck)]byte{}
	_ [retransEventTCPEndSeqOffset]byte       = [unsafe.Offsetof(retransEvent{}.TCPEndSeq)]byte{}
	_ [retransEventSportOffset]byte           = [unsafe.Offsetof(retransEvent{}.Sport)]byte{}
	_ [retransEventDportOffset]byte           = [unsafe.Offsetof(retransEvent{}.Dport)]byte{}
	_ [retransEventFamilyOffset]byte          = [unsafe.Offsetof(retransEvent{}.Family)]byte{}
	_ [retransEventCaStateOffset]byte         = [unsafe.Offsetof(retransEvent{}.CaState)]byte{}
	_ [retransEventIcskRetransmitsOffset]byte = [unsafe.Offsetof(retransEvent{}.IcskRetransmits)]byte{}
	_ [retransEventEventTypeOffset]byte       = [unsafe.Offsetof(retransEvent{}.EventType)]byte{}
	_ [retransEventIcskPendingOffset]byte     = [unsafe.Offsetof(retransEvent{}.IcskPending)]byte{}
	_ [retransEventTCPFlagsOffset]byte        = [unsafe.Offsetof(retransEvent{}.TCPFlags)]byte{}
	_ [retransEventSaddrOffset]byte           = [unsafe.Offsetof(retransEvent{}.Saddr)]byte{}
	_ [retransEventDaddrOffset]byte           = [unsafe.Offsetof(retransEvent{}.Daddr)]byte{}
	_ [retransEventCommOffset]byte            = [unsafe.Offsetof(retransEvent{}.Comm)]byte{}
	_ [retransEventPadOffset]byte             = [unsafe.Offsetof(retransEvent{}.Pad)]byte{}
)
