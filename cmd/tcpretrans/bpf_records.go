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
)

type retransEvent struct {
	KtimeNS         uint64
	TgidPid         uint64
	MemcgCssAddr    uint64
	SkbAddr         uint64
	NetCookie       uint64
	NetInode        uint32
	State           uint32
	Sport           uint16
	Dport           uint16
	Family          uint16
	Saddr           [4]byte
	Daddr           [4]byte
	SaddrV6         [16]byte
	DaddrV6         [16]byte
	CaState         uint8
	IcskRetransmits uint8
	EventType       uint8
	Pad             uint8
	GoPad           uint16
	IcskPending     uint8
	Pad3            [3]byte
	ReordSeen       uint32
	DsackDups       uint32
	TCPSeq          uint32
	TCPAck          uint32
	Comm            [bpf.TaskCommLen]byte
	TCPEndSeq       uint32
	TCPFlags        uint8
	TailPad         [3]byte
}

var _ = [1]struct{}{}[144-unsafe.Sizeof(retransEvent{})]
