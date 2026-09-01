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

package events

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"huatuo-bamai/pkg/types"
)

func TestDrainSubprocessOutputContinuesAfterLongLine(t *testing.T) {
	reader, writer := io.Pipe()
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Errorf("close pipe reader: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Errorf("close pipe writer: %v", err)
		}
	})

	var received []byte
	drainDone := make(chan error, 1)
	go func() {
		drainDone <- drainSubprocessOutput(reader, func(fragment []byte) {
			received = append(received, fragment...)
		})
	}()

	const marker = "after-long-line"
	input := strings.Repeat("x", bufio.MaxScanTokenSize+1) + "\n" + marker + "\n"
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := io.WriteString(writer, input)
		writeDone <- errors.Join(writeErr, writer.Close())
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write long subprocess output: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("write long subprocess output: %v", ctx.Err())
	}
	select {
	case err := <-drainDone:
		if err != nil {
			t.Fatalf("drainSubprocessOutput: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("drainSubprocessOutput: %v", ctx.Err())
	}

	if !bytes.Contains(received, []byte(marker)) {
		t.Fatalf("drained output does not contain marker %q", marker)
	}
}

func TestStopTCPSharkWaitsForGracefulExit(t *testing.T) {
	cmd := exec.Command("sh", "-c", "trap 'exit 0' TERM; echo ready; while :; do sleep 1; done")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "ready" {
		t.Fatalf("helper readiness = %q, error = %v", scanner.Text(), scanner.Err())
	}
	if err := stopTCPShark(cmd, done, stdout, nil); err != nil {
		t.Fatalf("stopTCPShark: %v", err)
	}
}

func TestStopTCPSharkAcceptsAlreadyExitedProcess(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	done := make(chan error, 1)
	done <- cmd.Wait()
	if err := stopTCPShark(cmd, done, nil, nil); err != nil {
		t.Fatalf("stopTCPShark: %v", err)
	}
}

func TestHandleTCPRetransmitEventPreservesCorrelationResult(t *testing.T) {
	perfStatus := &types.DropwatchPerfStatus{PerfLost: 1}
	event := &types.TCPRetransmitTracing{
		ContainerID:  "container-id",
		DropLocation: "unknown",
		CorrelationReasons: []types.CorrelationReason{
			types.CorrelationReasonStartupHistoryIncomplete,
		},
		DropwatchPerfStatus: perfStatus,
		DropStack:           "kfree_skb/1",
	}
	if err := handleTCPRetransmitEvent(nil, event); err != nil {
		t.Fatal(err)
	}
	if event.DropLocation != "unknown" {
		t.Fatalf("DropLocation = %q, want finalized result unchanged", event.DropLocation)
	}
	if event.DropwatchPerfStatus != perfStatus {
		t.Fatal("DropwatchPerfStatus changed while saving finalized result")
	}
	if len(event.CorrelationReasons) != 1 ||
		event.CorrelationReasons[0] != types.CorrelationReasonStartupHistoryIncomplete {
		t.Fatalf("CorrelationReasons = %v, want finalized reasons unchanged", event.CorrelationReasons)
	}
	if event.DropStack != "kfree_skb/1" {
		t.Fatalf("DropStack = %q, want finalized stack unchanged", event.DropStack)
	}
}
