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

//go:build ignore

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"time"
	"unsafe"

	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/internal/pcapfilter"
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
	TailPad         [8]byte
}

func main() {
	app := &cli.App{
		Name:  "tcpretrans-hexdump",
		Usage: "dump raw retransEvent bytes for debugging",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "bpf-path", Required: true},
			&cli.IntFlag{Name: "duration", Value: 10},
			&cli.StringFlag{Name: "filter", Value: ""},
		},
		Action: func(c *cli.Context) error {
			duration := c.Int("duration")
			bpfPath := c.String("bpf-path")

			if err := bpf.NewManager(&bpf.Option{KeepaliveTimeout: duration}); err != nil {
				return fmt.Errorf("init bpf manager: %w", err)
			}
			defer bpf.Close()

			bpfBytes, err := os.ReadFile(bpfPath)
			if err != nil {
				return fmt.Errorf("read bpf: %w", err)
			}
			bpfName := fmt.Sprintf("tcp_retrans_%d.o", time.Now().UnixNano())
			bpfObj, err := pcapfilter.Load(bpfName, bpfBytes, c.String("filter"), nil)
			if err != nil {
				return fmt.Errorf("load bpf: %w", err)
			}
			defer bpfObj.Close()

			runCtx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
			defer cancel()

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, unix.SIGINT, unix.SIGTERM)
			defer signal.Stop(sig)
			go func() {
				select {
				case <-sig:
					cancel()
				case <-runCtx.Done():
				}
			}()

			reader, err := bpfObj.AttachAndEventPipe(runCtx, "perf_events", 8192)
			if err != nil {
				return fmt.Errorf("attach: %w", err)
			}
			defer reader.Close()

			bpfObj.WaitDetachByBreaker(runCtx, cancel)

			for {
				if runCtx.Err() != nil {
					return nil
				}
				var ev retransEvent
				if err := reader.ReadInto(&ev); err != nil {
					if runCtx.Err() != nil {
						return nil
					}
					continue
				}

				raw := (*[144]byte)(unsafe.Pointer(&ev))
				fmt.Printf("=== EVENT (144 bytes) ===\n")
				fmt.Printf("hex: %s\n", hex.EncodeToString(raw[:]))
				fmt.Printf("  ktime_ns=%d tgid_pid=0x%x\n", ev.KtimeNS, ev.TgidPid)
				fmt.Printf("  memcg_css=0x%x skb_addr=0x%x net_cookie=0x%x net_inum=%d\n", ev.MemcgCssAddr, ev.SkbAddr, ev.NetCookie, ev.NetInode)
				fmt.Printf("  state=%d sport=%d dport=%d family=%d\n", ev.State, ev.Sport, ev.Dport, ev.Family)
				fmt.Printf("  ca_state=%d icsk_retransmits=%d event_type=%d pad=%d\n", ev.CaState, ev.IcskRetransmits, ev.EventType, ev.Pad)
				fmt.Printf("  go_pad=%d icsk_pending=%d pad3=%v\n", ev.GoPad, ev.IcskPending, ev.Pad3)
				fmt.Printf("  reord_seen=%d dsack_dups=%d tcp_seq=%d tcp_ack=%d\n", ev.ReordSeen, ev.DsackDups, ev.TCPSeq, ev.TCPAck)
				fmt.Printf("  comm=%q tail_pad=%v\n", ev.Comm[:], ev.TailPad)

				// Flag anomalies
				if ev.EventType == 0 || ev.EventType > 3 {
					fmt.Printf("  *** ANOMALY: event_type=%d (expected 1/2/3)\n", ev.EventType)
				}
				if ev.Family != 2 && ev.Family != 10 && ev.Family != 0 {
					fmt.Printf("  *** ANOMALY: family=%d (expected 0/2/10)\n", ev.Family)
				}
				if ev.EventType == 2 && ev.State != 12 {
					fmt.Printf("  *** ANOMALY: synack event but state=%d (expected 12)\n", ev.State)
				}
				if ev.EventType == 2 && ev.SkbAddr != 0 {
					fmt.Printf("  *** ANOMALY: synack event but skb_addr=0x%x (expected 0)\n", ev.SkbAddr)
				}
				fmt.Println()
			}
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
}
