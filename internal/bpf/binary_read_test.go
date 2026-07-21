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

package bpf

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"
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
	Comm            [TaskCommLen]byte
	TCPEndSeq       uint32
	TCPFlags        uint8
	TailPad         [3]byte
}

const retransEventSize = 144

func TestRetransEventBinaryLayout(t *testing.T) {
	if got := unsafe.Sizeof(retransEvent{}); got != retransEventSize {
		t.Fatalf("sizeof(retransEvent) = %d, want %d", got, retransEventSize)
	}

	raw := make([]byte, retransEventSize)
	binary.NativeEndian.PutUint64(raw[0:], 12345)
	binary.NativeEndian.PutUint64(raw[8:], 0x100000001)
	binary.NativeEndian.PutUint64(raw[16:], 0x1000)
	binary.NativeEndian.PutUint64(raw[24:], 0xffff888012345678)
	binary.NativeEndian.PutUint64(raw[32:], 0x2000)
	binary.NativeEndian.PutUint32(raw[40:], 4026531992)
	binary.NativeEndian.PutUint32(raw[44:], 1)
	binary.NativeEndian.PutUint16(raw[48:], 12345)
	binary.NativeEndian.PutUint16(raw[50:], 80)
	binary.NativeEndian.PutUint16(raw[52:], 2)
	copy(raw[54:58], []byte{127, 0, 0, 1})
	copy(raw[58:62], []byte{10, 0, 0, 2})
	copy(raw[62:78], []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	copy(raw[78:94], []byte{16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31})
	raw[94] = 4
	raw[95] = 3
	raw[96] = 1
	binary.NativeEndian.PutUint16(raw[98:], 0)
	raw[100] = 6
	binary.NativeEndian.PutUint32(raw[104:], 10)
	binary.NativeEndian.PutUint32(raw[108:], 5)
	binary.NativeEndian.PutUint32(raw[112:], 123456)
	binary.NativeEndian.PutUint32(raw[116:], 789012)
	copy(raw[120:136], "testcmd\x00")
	binary.NativeEndian.PutUint32(raw[136:], 123999)
	raw[140] = 0x11
	copy(raw[141:144], []byte{0x01, 0x02, 0x03})

	want := retransEvent{
		KtimeNS:         12345,
		TgidPid:         0x100000001,
		MemcgCssAddr:    0x1000,
		SkbAddr:         0xffff888012345678,
		NetCookie:       0x2000,
		NetInode:        4026531992,
		State:           1,
		Sport:           12345,
		Dport:           80,
		Family:          2,
		Saddr:           [4]byte{127, 0, 0, 1},
		Daddr:           [4]byte{10, 0, 0, 2},
		SaddrV6:         [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		DaddrV6:         [16]byte{16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
		CaState:         4,
		IcskRetransmits: 3,
		EventType:       1,
		IcskPending:     6,
		ReordSeen:       10,
		DsackDups:       5,
		TCPSeq:          123456,
		TCPAck:          789012,
		TCPEndSeq:       123999,
		TCPFlags:        0x11,
		TailPad:         [3]byte{0x01, 0x02, 0x03},
	}
	copy(want.Comm[:], "testcmd\x00")

	var fromBinaryRead retransEvent
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &fromBinaryRead); err != nil {
		t.Fatalf("binary.Read: %v", err)
	}
	if fromBinaryRead != want {
		t.Errorf("binary.Read decoded %#v, want %#v", fromBinaryRead, want)
	}

	var fromMemcpy retransEvent
	copy((*[retransEventSize]byte)(unsafe.Pointer(&fromMemcpy))[:], raw)
	if fromMemcpy != want {
		t.Errorf("memcpy decoded %#v, want %#v", fromMemcpy, want)
	}
}
