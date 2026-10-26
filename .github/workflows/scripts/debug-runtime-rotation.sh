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

# Fork-only evidence collection for the two selected Ubuntu regressions.
set -euo pipefail
cd /mnt/host
readonly evidence=/root/runtime-rotation-debug
mkdir -p "$evidence"
exec > >(tee "$evidence/session.log") 2>&1
printf '[DEBUG] begin=%s\n' "$(date -u --iso-8601=ns)"
uname -a
cat /etc/os-release
cat /proc/self/cgroup
findmnt -t cgroup,cgroup2

git config --global --add safe.directory /mnt/host
git rev-parse HEAD
git diff HEAD --exit-code
# Runtime limits uses the default daemon config, which also launches tcpshark.
# Prepare the normal command set without invoking any additional test suite.
make build SKIP_PORTABLE_GENERATION=1
sha256sum _output/bin/huatuo-bamai _output/bin/dropwatch > "$evidence/binary-hashes.txt"

trace_reader=""
trace_instance=""
cleanup() {
	local status=$?
	trap - EXIT
	if [[ -n "$trace_instance" ]]; then
		echo 0 > "$trace_instance/events/cgroup/cgroup_attach_task/enable" || true
		kill "$trace_reader" 2> /dev/null || true
		wait "$trace_reader" 2> /dev/null || true
		rmdir "$trace_instance" || true
	fi
	# Successful cases are deleted by the original runner; failed workspaces
	# contain the complete logs that the console's 160-line dump omits.
	local -a workspaces=(/tmp/huatuo-test.*)
	if ((${#workspaces[@]})); then
		tar --exclude='*/events/*' --exclude='*/fixtures/*' -czf "$evidence/failed-workspaces.tar.gz" "${workspaces[@]}" || status=1
	fi
	printf '[DEBUG] end status=%s time=%s\n' "$status" "$(date -u --iso-8601=ns)"
	exit "$status"
}
shopt -s nullglob
trap cleanup EXIT

trace_root=/sys/kernel/tracing
if [[ ! -d "$trace_root/events" ]]; then
	mkdir -p "$trace_root"
	mount -t tracefs tracefs "$trace_root" || true
fi
if [[ -f "$trace_root/events/cgroup/cgroup_attach_task/enable" ]]; then
	trace_instance="$trace_root/instances/huatuo-runtime-debug-$$"
	mkdir "$trace_instance"
	cat "$trace_instance/events/cgroup/cgroup_attach_task/format" > "$evidence/cgroup-attach-format.txt"
	echo 1 > "$trace_instance/events/cgroup/cgroup_attach_task/enable"
	cat "$trace_instance/trace_pipe" > "$evidence/cgroup-attach.log" &
	trace_reader=$!
else
	printf '[DEBUG] cgroup_attach_task tracepoint unavailable\n' > "$evidence/cgroup-trace-unavailable.txt"
fi

for round in $(seq 1 5); do
	for scenario in test_node_runtime_limits.sh test_basic_storage_localfile_rotation.sh; do
		output="$evidence/${scenario%.sh}-${round}.log"
		status=0
		printf '[DEBUG] case=%s round=%s begin=%s\n' "$scenario" "$round" "$(date -u --iso-8601=ns)"
		timeout --kill-after=10 180 bash integration/run.sh "$scenario" > "$output" 2>&1 || status=$?
		if [[ $status -eq 0 ]] && ! grep -q 'summary: total=1 passed=1 skipped=0 failed=0' "$output"; then status=77; fi
		printf '%s %s %s\n' "$scenario" "$round" "$status" >> "$evidence/results.txt"
		cat "$output"
		for workspace in /tmp/huatuo-test.*; do
			find "$workspace" -type f -name 'huatuo*.log' -exec grep -nEi 'panic:|fatal|level="?(error|panic|fatal)"?' {} + || true
		done
		printf '[DEBUG] case=%s round=%s status=%s end=%s\n' "$scenario" "$round" "$status" "$(date -u --iso-8601=ns)"
	done
done
cat "$evidence/results.txt"
git diff HEAD --exit-code
if awk '$3 != 0 {failed=1} END {exit !failed}' "$evidence/results.txt"; then exit 1; fi
