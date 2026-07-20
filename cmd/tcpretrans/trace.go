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
	"os"
	"os/signal"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/log"
)

func mainAction(c *cli.Context) error {
	duration := c.Int(cliFlagDuration)
	outputFmt := c.String(cliFlagOutput)

	if err := bpf.NewManager(&bpf.Option{KeepaliveTimeout: duration}); err != nil {
		return fmt.Errorf("tcpretrans: init bpf manager: %w", err)
	}
	defer bpf.Close()

	bpfObj, err := loadTCPRetransBPFWithFilter(c.String(cliFlagBpfPath), c.String(cliFlagFilter))
	if err != nil {
		return fmt.Errorf("tcpretrans: load bpf: %w", err)
	}
	defer bpfObj.Close()

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
		return fmt.Errorf("tcpretrans: attach: %w", err)
	}
	defer reader.Close()

	bpfObj.WaitDetachByBreaker(runCtx, cancel)

	sink, sinkCleanup, err := newWriter(&writerOption{
		outputFmt: outputFmt,
		sockPath:  c.String(cliFlagOutputStorage),
		toolName:  tcpRetransToolName,
		version:   AppVersion,
		taskID:    c.String(cliFlagTaskID),
	})
	if err != nil {
		return err
	}
	defer sinkCleanup()

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

		if err := sink.Write(formatEvent(&ev)); err != nil {
			log.Errorf("tcpretrans: send event: %v", err)
			return nil
		}
	}
}
