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

import "testing"

func TestDropReasonNamesResolve(t *testing.T) {
	names := dropReasonNames{
		0: "SKB_DROP_REASON_NOT_SPECIFIED",
		1: "SKB_DROP_REASON_NO_SOCKET",
		3: "SKB_DROP_REASON_TCP_CSUM",
	}

	cases := []struct {
		name  string
		input uint32
		want  string
	}{
		{name: "known reason", input: 0, want: "SKB_DROP_REASON_NOT_SPECIFIED"},
		{name: "another known reason", input: 3, want: "SKB_DROP_REASON_TCP_CSUM"},
		{name: "unknown reason", input: 99, want: "99"},
		{name: "unsupported kernel", input: skbDropReasonNotSupported, want: "NOT_SUPPORTED"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := names.resolve(tc.input)
			if got != tc.want {
				t.Errorf("resolve(%d): got %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestDropReasonNamesNilResolve(t *testing.T) {
	var names dropReasonNames

	cases := []struct {
		name  string
		input uint32
		want  string
	}{
		{name: "zero reason", input: 0, want: "0"},
		{name: "unknown reason", input: 5, want: "5"},
		{name: "unsupported kernel", input: skbDropReasonNotSupported, want: "NOT_SUPPORTED"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := names.resolve(tc.input)
			if got != tc.want {
				t.Errorf("resolve(%d): got %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
