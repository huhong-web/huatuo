#!/usr/bin/env bash
# Copyright 2026 The HuaTuo Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

# Keep the tested guest entry unchanged; choose integration only at this boundary.
set -euo pipefail
cd /mnt/host
source .github/workflows/scripts/vm-test/run-in-vm.sh
configure_proxy
export PATH="/usr/local/go/bin:/root/go/bin:$PATH"
export GOCACHE=/root/.cache/go-build
export INTEGRATION_JOBS=3
export JAVA_PROFILER_DOCKER_IMAGE=eclipse-temurin:17-jdk
export JAVA_PROFILER_CONTAINERD_IMAGE=docker.io/library/eclipse-temurin:17-jdk
export NATIVE_PROFILER_DOCKER_IMAGE=busybox:1.36.1
export NATIVE_PROFILER_CONTAINERD_IMAGE=docker.io/library/busybox:1.36.1
readonly evidence=/root/native-memory-suite
mkdir -p "$evidence"
exec > >(tee "$evidence/session.log") 2>&1
git config --global --add safe.directory /mnt/host
git diff HEAD --exit-code
git diff --exit-code 6cf654bb3380fd8998bf34d19cf661e6ce31b1a7 -- . \
	':(exclude).github/workflows/os-distro-qemu-test-reusable.yml' \
	':(exclude).github/workflows/scripts/debug-native-memory-suite.py' \
	':(exclude).github/workflows/scripts/debug-native-memory-suite.sh'
uname -a
cat /proc/swaps
[[ $(wc -l < /proc/swaps) -eq 1 ]] || {
	echo 'baseline requires a fresh VM without swap' >&2
	exit 1
}
if [[ ! -f _output/portable-generated.commit ]]; then
	install_temporary_go_tools
fi
storage_prefetch_pids=()
trap stop_storage_image_prefetch EXIT
prefetch_storage_images
make install-tools
python3 .github/workflows/scripts/debug-native-memory-suite.py
