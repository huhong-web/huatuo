#!/usr/bin/env bash
# Copyright 2026 The HuaTuo Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

# Replay the upstream suite without diagnostic workloads or production changes.
set -euo pipefail
export PATH="/usr/local/go/bin:/root/go/bin:$PATH"
export GOCACHE=/root/.cache/go-build
export INTEGRATION_JOBS=3
cd /mnt/host
readonly evidence=/root/native-memory-suite
mkdir -p "$evidence"
exec > >(tee "$evidence/session.log") 2>&1
git config --global --add safe.directory /mnt/host
git diff HEAD --exit-code
git diff --exit-code 6cf654bb3380fd8998bf34d19cf661e6ce31b1a7 -- \
	bpf cmd core internal integration pkg apis go.mod go.sum vendor Makefile build
uname -a
cat /proc/swaps
make install-tools
python3 .github/workflows/scripts/debug-native-memory-suite.py
