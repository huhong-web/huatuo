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

package executil

import (
	"errors"
	"strings"
	"testing"
)

func TestFormatCmdIncludesExecutableAndArguments(t *testing.T) {
	t.Parallel()

	got := formatCmd("/usr/bin/tool", []string{"trace", "--duration", "10"})
	want := "/usr/bin/tool trace --duration 10"
	if got != want {
		t.Fatalf("formatCmd()=%q, want %q", got, want)
	}
}

func TestCommandOutputForError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		output []byte
		want   string
	}{
		{
			name:   "trims surrounding whitespace",
			output: []byte("\n command output \t\n"),
			want:   "command output",
		},
		{
			name:   "truncates oversized output",
			output: []byte(strings.Repeat("x", maxCommandOutputInError+1)),
			want:   strings.Repeat("x", maxCommandOutputInError) + "... (truncated)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := commandOutputForError(tt.output); got != tt.want {
				t.Fatalf("commandOutputForError() length=%d, want length=%d", len(got), len(tt.want))
			}
		})
	}
}

func TestVerifyResultsIncludesFailureDetails(t *testing.T) {
	t.Parallel()

	cmdErr := errors.New("exit status 1")
	err := VerifyResults([]CmdResult{
		{
			Pid:     164879,
			Cmd:     "/usr/bin/tool trace 164879",
			Stdout:  []byte("diagnostic output\n"),
			Stderr:  []byte("attach failed\n"),
			Success: false,
			CmdErr:  cmdErr,
		},
	})
	if err == nil {
		t.Fatal("VerifyResults() error=nil, want non-nil")
	}
	if !errors.Is(err, cmdErr) {
		t.Fatalf("VerifyResults() error=%v, want wrapped command error", err)
	}

	for _, want := range []string{
		`command "/usr/bin/tool trace 164879" failed for pid 164879`,
		"exit status 1",
		`stderr="attach failed"`,
		`stdout="diagnostic output"`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("VerifyResults() error=%q, want substring %q", err, want)
		}
	}
}

func TestVerifyResultsIncludesEveryFailure(t *testing.T) {
	t.Parallel()

	firstErr := errors.New("first failure")
	secondErr := errors.New("second failure")
	err := VerifyResults([]CmdResult{
		{Pid: 101, Cmd: "tool start 101", CmdErr: firstErr},
		{Pid: 202, Cmd: "tool start 202", CmdErr: secondErr},
		{Pid: 303, Cmd: "tool start 303", Success: true},
	})
	if err == nil {
		t.Fatal("VerifyResults() error=nil, want non-nil")
	}
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("VerifyResults() error=%v, want both command errors", err)
	}
	for _, want := range []string{"pid 101", "pid 202"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("VerifyResults() error=%q, want substring %q", err, want)
		}
	}
}
