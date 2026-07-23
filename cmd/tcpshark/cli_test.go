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
	"io"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
)

func TestAppName(t *testing.T) {
	t.Parallel()

	if got := newApp().Name; got != "tcpshark" {
		t.Fatalf("app name = %q, want tcpshark", got)
	}
}

func TestAppModeValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		args          []string
		expectedError string
	}{
		{
			name:          "mode is required",
			args:          []string{"tcpshark", "--bpf-path", "unused.o"},
			expectedError: "Required flag \"mode\" not set",
		},
		{
			name: "retransmit mode",
			args: []string{
				"tcpshark", "--mode", "retransmit", "--bpf-path", "unused.o",
			},
		},
		{
			name: "invalid mode",
			args: []string{
				"tcpshark", "--mode", "invalid", "--bpf-path", "unused.o",
			},
			expectedError: `--mode: invalid value "invalid", want retransmit`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			app := newTestApp(func(_ *cli.Context) error { return nil })
			err := app.Run(tt.args)
			if tt.expectedError == "" {
				if err != nil {
					t.Fatalf("Run() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.expectedError) {
				t.Fatalf("Run() error = %v, want containing %q", err, tt.expectedError)
			}
		})
	}
}

func TestAppTLPFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		flag     string
		expected bool
	}{
		{name: "disabled by default", expected: false},
		{name: "long flag", flag: "--enable-tlp", expected: true},
		{name: "short alias", flag: "--tlp", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var isTLPEnabled bool
			app := newTestApp(func(c *cli.Context) error {
				isTLPEnabled = c.Bool(cliFlagEnableTLP)
				return nil
			})
			args := []string{
				"tcpshark", "--mode", "retransmit", "--bpf-path", "unused.o",
			}
			if tt.flag != "" {
				args = append(args, tt.flag)
			}

			if err := app.Run(args); err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if isTLPEnabled != tt.expected {
				t.Fatalf("TLP enabled = %t, want %t", isTLPEnabled, tt.expected)
			}
		})
	}
}

func newTestApp(action cli.ActionFunc) *cli.App {
	app := newApp()
	app.Action = action
	app.Writer = io.Discard
	app.ErrWriter = io.Discard
	return app
}
