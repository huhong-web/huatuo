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
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"
	"unsafe"

	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/internal/packet"
	"huatuo-bamai/internal/pcapfilter"
	"huatuo-bamai/internal/toolstream"
	"huatuo-bamai/internal/utils/bytesutil"
	"huatuo-bamai/internal/utils/kernaddr"
	"huatuo-bamai/pkg/types"
)

//go:generate $BPF_COMPILE $BPF_INCLUDE -s $BPF_DIR/tcp_retrans.c -o $BPF_DIR/tcp_retrans.o

var (
	tcpRetransToolName = "tcpretrans"
	AppVersion         = ""
)

const (
	retransEventSKU    = 1
	retransEventSynack = 2
	retransEventTLP    = 3
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

var _ = [1]struct{}{}[144-unsafe.Sizeof(retransEvent{})]

func loadBPFWithFilter(bpfPath, filterExpr string) (bpf.BPF, error) {
	bpfBytes, err := os.ReadFile(bpfPath)
	if err != nil {
		return nil, fmt.Errorf("read bpf object: %w", err)
	}
	bpfName := fmt.Sprintf("tcp_retrans_%d.o", time.Now().UnixNano())
	return pcapfilter.Load(bpfName, bpfBytes, filterExpr, nil)
}

func formatEvent(ev *retransEvent) *types.TCPRetransTracing {
	phase, reason := classifyEvent(ev)

	var saddr, daddr string
	if ev.Family == unix.AF_INET {
		saddr = net.IP(ev.Saddr[:]).String()
		daddr = net.IP(ev.Daddr[:]).String()
	} else if ev.Family == unix.AF_INET6 {
		saddr = net.IP(ev.SaddrV6[:]).String()
		daddr = net.IP(ev.DaddrV6[:]).String()
	}

	stateStr := tcpStateNameRaw(uint8(ev.State))

	eventTypeStr := "unknown"
	switch ev.EventType {
	case retransEventSKU:
		eventTypeStr = "tcp_retransmit_skb"
	case retransEventSynack:
		eventTypeStr = "tcp_retransmit_synack"
	case retransEventTLP:
		eventTypeStr = "tcp_send_loss_probe"
	}

	return &types.TCPRetransTracing{
		ObservedTimestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Comm:               bytesutil.ToStr(ev.Comm[:]),
		Pid:                ev.TgidPid >> 32,
		MemcgCssAddr:       ev.MemcgCssAddr,
		NetNamespaceCookie: ev.NetCookie,
		NetNamespaceInode:  ev.NetInode,
		Saddr:              saddr,
		Daddr:              daddr,
		Sport:              ev.Sport,
		Dport:              ev.Dport,
		Family:             ev.Family,
		State:              stateStr,
		Phase:              phase.String(),
		Reason:             reason.String(),
		EventType:          eventTypeStr,
		CaState:            ev.CaState,
		IcskRetransmits:    ev.IcskRetransmits,
		IcskPending:        ev.IcskPending,
		ReordSeen:          ev.ReordSeen,
		DsackDups:          ev.DsackDups,
		TCPSeq:             ev.TCPSeq,
		TCPAck:             ev.TCPAck,
		SkbAddr:            kernaddr.Format(ev.SkbAddr),
		ProgMarker:         ev.Pad,
	}
}

func classifyEvent(ev *retransEvent) (packet.RetransPhase, packet.RetransReason) {
	switch ev.EventType {
	case retransEventSynack:
		return packet.RetransPhaseConnect, packet.RetransReasonRTO
	case retransEventTLP:
		return packet.RetransPhaseData, packet.RetransReasonTLP
	default:
		return packet.ClassifyRetrans(uint8(ev.State), "", ev.CaState, ev.IcskPending, ev.ReordSeen, ev.DsackDups)
	}
}

func mainAction(c *cli.Context) error {
	duration := c.Int("duration")
	outputFmt := c.String("output")
	bpfPath := c.String("bpf-path")

	if err := bpf.NewManager(&bpf.Option{KeepaliveTimeout: duration}); err != nil {
		return fmt.Errorf("tcpretrans: init bpf manager: %w", err)
	}
	defer bpf.Close()

	bpfObj, err := loadBPFWithFilter(bpfPath, c.String("filter"))
	if err != nil {
		return fmt.Errorf("tcpretrans: load bpf: %w", err)
	}
	defer bpfObj.Close()

	var sockClient *toolstream.Client
	if path := c.String("output-storage"); path != "" {
		sockClient, err = toolstream.NewClient(toolstream.ClientOptions{
			SockPath: path,
			ToolName: tcpRetransToolName,
			Version:  AppVersion,
			TaskID:   c.String("task-id"),
		})
		if err != nil {
			return fmt.Errorf("--output-storage: %w", err)
		}
		defer sockClient.End()
	}

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if duration > 0 {
		var dcancel context.CancelFunc
		runCtx, dcancel = context.WithTimeout(runCtx, time.Duration(duration)*time.Second)
		defer dcancel()
	}

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

	wr := newWriter(outputFmt, sockClient)

	for {
		if runCtx.Err() != nil {
			return nil
		}

		var ev retransEvent
		if err := reader.ReadInto(&ev); err != nil {
			if runCtx.Err() != nil {
				return nil
			}
			log.Errorf("tcpretrans: read: %v", err)
			continue
		}

		if err := wr.Write(formatEvent(&ev)); err != nil {
			log.Errorf("tcpretrans: send event: %v", err)
			return nil
		}
	}
}

func tcpStateNameRaw(state uint8) string {
	names := []string{
		"unknown", "ESTABLISHED", "SYN_SENT", "SYN_RECV",
		"FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE",
		"CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "NEW_SYN_RECV",
	}
	if int(state) < len(names) {
		return names[state]
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}

func main() {
	app := &cli.App{
		Name:    tcpRetransToolName,
		Version: AppVersion,
		Usage:   "watch TCP retransmissions classified by connection state machine phase",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "bpf-path",
				Usage:    "path to the tcpretrans BPF object file",
				Required: true,
			},
			&cli.IntFlag{
				Name:  "duration",
				Usage: "run for N seconds then exit (0=forever)",
			},
			&cli.StringFlag{
				Name:  "output",
				Value: "text",
				Usage: "output format: json or text; ignored when --output-storage is set",
			},
			&cli.StringFlag{
				Name:  "output-storage",
				Usage: "unix socket path to send events to; when set, --output is ignored",
			},
			&cli.StringFlag{
				Name:  "task-id",
				Usage: "task ID to associate with this session (requires --output-storage)",
			},
			&cli.StringFlag{
				Name:  "filter",
				Usage: "pcap filter expression (tcpdump syntax); empty = all TCP retransmissions",
			},
		},
	}

	app.Action = mainAction
	app.Before = func(c *cli.Context) error {
		if v := c.String("output"); v != "json" && v != "text" {
			return fmt.Errorf("--output: invalid value %q, want json or text", v)
		}
		if c.IsSet("output") && c.String("output-storage") != "" {
			log.Warnf("--output is ignored because --output-storage is set")
		}
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
}
