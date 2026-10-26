#!/usr/bin/env bash
#
# Copyright 2026 The HuaTuo Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Keep production and test sources identical to the original failed candidate.
set -euo pipefail
export PATH="/usr/local/go/bin:/root/go/bin:$PATH"
export GOCACHE=/root/.cache/go-build
cd /mnt/host
readonly evidence=/root/native-physical-usage-debug
mkdir -p "$evidence"
exec > >(tee "$evidence/session.log") 2>&1
uname -a
git config --global --add safe.directory /mnt/host
git rev-parse HEAD
git diff HEAD --exit-code
make _output/bin/profiler SKIP_PORTABLE_GENERATION=1
mkdir -p _output/bpf
cp bpf/*.o _output/bpf/
sha256sum _output/bin/profiler _output/bpf/native_physical_usage.o > "$evidence/binary-hashes.txt"
dnf -y install strace bpftrace bpftool
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
python3 .github/workflows/scripts/debug-native-physical-usage.py
