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
	"encoding/json"
	"testing"
)

func TestFormatEventSkbAddr(t *testing.T) {
	tests := []struct {
		name    string
		skbAddr uint64
		want    string
		omitted bool
	}{
		{
			name:    "zero pointer",
			omitted: true,
		},
		{
			name:    "kernel pointer",
			skbAddr: 0xffff888012345678,
			want:    "0xffff888012345678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := formatEvent(&retransEvent{SkbAddr: tt.skbAddr})
			if event.SkbAddr != tt.want {
				t.Fatalf("SkbAddr = %q, want %q", event.SkbAddr, tt.want)
			}

			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var fields map[string]any
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got, present := fields["skb_addr"]
			if tt.omitted && present {
				t.Fatalf("skb_addr = %v, want omitted", got)
			}
			if !tt.omitted && (!present || got != tt.want) {
				t.Fatalf("skb_addr = %v, want %q", got, tt.want)
			}
		})
	}
}
