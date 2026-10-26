#!/usr/bin/env bash
# Copyright 2026 The HuaTuo Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# CI-only natural reproduction: preserve original unit -> integration ordering.
set -euo pipefail
cd /mnt/host
output=/root/runtime-full-debug
[[ ! -e "$output" ]] || {
	echo "diagnostic output already exists: $output" >&2
	exit 1
}
mkdir -p "$output"
exec > >(tee "$output/session.log") 2>&1
base=e8d2b10cfaf20c1847e294399871fea8f265059e
trace_instance=
trace_pid=
journal_pid=
observer_pid=

record_context() {
	date --iso-8601=ns
	cat /proc/uptime /etc/os-release
	uname -a
	systemd --version
	printf 'INTEGRATION_JOBS=%s\n' "${INTEGRATION_JOBS:-unset}"
	for pid in 1 $$ "$PPID"; do
		printf '\nPID %s\n' "$pid"
		readlink "/proc/$pid/exe" || true
		cat "/proc/$pid/cgroup" "/proc/$pid/status" || true
	done
	findmnt -t cgroup,cgroup2
	for name in perf_event_paranoid kptr_restrict; do
		printf '%s=' "$name"
		cat "/proc/sys/kernel/$name"
	done
	docker info --format 'CgroupDriver={{.CgroupDriver}} CgroupVersion={{.CgroupVersion}}' || true
	# Read existing unit properties only; never enable accounting or create a scope.
	awk -F: '$2=="" {print $3}' /proc/self/cgroup | tr / '\n' \
		| while IFS= read -r unit; do
			case "$unit" in
			*.scope | *.slice | *.service)
				systemctl show "$unit" -p ControlGroup -p Delegate -p CPUAccounting \
					-p MemoryAccounting -p CPUQuotaPerSecUSec -p MemoryMax -p ActiveState || true
				;;
			esac
		done
}

cleanup() {
	status=$?
	trap - EXIT
	set +e
	touch "$output/stop-observer"
	if [[ -n "$observer_pid" ]]; then
		for attempt in {1..30}; do
			kill -0 "$observer_pid" 2> /dev/null || break
			sleep 0.1
		done
		if kill -0 "$observer_pid" 2> /dev/null; then kill "$observer_pid"; fi
		wait "$observer_pid"
	fi
	if [[ -n "$trace_instance" ]]; then
		echo 0 > "$trace_instance/tracing_on"
		cat "$trace_instance"/per_cpu/cpu*/stats > "$output/trace-stats.log"
	fi
	for pid in "$trace_pid" "$journal_pid"; do
		if [[ -n "$pid" ]]; then
			kill "$pid"
			wait "$pid"
		fi
	done
	if [[ -n "$trace_instance" ]]; then rmdir "$trace_instance"; fi
	record_context > "$output/context-after.log" 2>&1
	# Preserve retained failure workspaces; successful runtime snapshots are separate.
	find /tmp -maxdepth 1 -type d -name 'huatuo-test.*' -printf '%f\n' > "$output/workspaces.list"
	if [[ -s "$output/workspaces.list" ]]; then
		tar -C /tmp --exclude='*/events/*' --exclude='*/bin/*' --exclude='*.o' \
			--exclude='core' -czf "$output/failed-workspaces.tar.gz" -T "$output/workspaces.list" || status=1
	fi
	if [[ -d _output/storage-image-prefetch ]]; then
		cp -a _output/storage-image-prefetch "$output/"
	fi
	git diff --exit-code HEAD > "$output/worktree-final.diff" || status=1
	git diff --exit-code "$base" HEAD -- . ':!.github/**' > "$output/source-final.diff" || status=1
	printf '%s\n' "$status" > "$output/exit-status"
	exit "$status"
}
trap cleanup EXIT

record_context > "$output/context-before.log" 2>&1
git rev-parse HEAD > "$output/head"
[[ $(git rev-parse HEAD^) == "$base" ]]
git diff --exit-code HEAD
git diff --exit-code "$base" HEAD -- . ':!.github/**' > "$output/source-initial.diff"
find integration -maxdepth 1 -name 'test_*.sh' -printf '%f\n' | sort > "$output/expected-tests.list"
sha256sum internal/cgroups/v1/*.go integration/*.sh > "$output/original-source.sha256"

trace_root=/sys/kernel/tracing
[[ -d "$trace_root/instances" ]] || trace_root=/sys/kernel/debug/tracing
candidate="$trace_root/instances/huatuo-runtime-full-$$"
# Failure to obtain private tracing is an explicit diagnostic failure, never a shared reset.
mkdir "$candidate"
trace_instance=$candidate
echo 4096 > "$trace_instance/buffer_size_kb"
echo mono > "$trace_instance/trace_clock"
for event in cgroup/cgroup_attach_task cgroup/cgroup_mkdir cgroup/cgroup_rmdir sched/sched_process_exec; do
	if [[ -f "$trace_instance/events/$event/enable" ]]; then
		cp "$trace_instance/events/$event/format" "$output/${event//\//-}.format"
		echo 1 > "$trace_instance/events/$event/enable"
	fi
done
[[ -f "$trace_instance/events/cgroup/cgroup_attach_task/enable" ]]
echo 1 > "$trace_instance/tracing_on"
cat "$trace_instance/trace_pipe" > "$output/cgroup-events.log" &
trace_pid=$!
journalctl -f -n 0 --no-pager -o short-monotonic _PID=1 > "$output/pid1-journal.log" 2>&1 &
journal_pid=$!
python3 .github/workflows/scripts/observe-runtime-cgroups.py "$output" > "$output/observer.log" 2>&1 &
observer_pid=$!

make_args=()
if [[ -f _output/portable-generated.commit ]]; then make_args+=(SKIP_PORTABLE_GENERATION=1); fi
run_phase() {
	local phase=$1 status=0
	date --iso-8601=ns > "$output/$phase.start"
	make "$phase" "${make_args[@]}" > >(tee "$output/$phase.log") 2>&1 || status=$?
	date --iso-8601=ns > "$output/$phase.end"
	printf '%s\n' "$status" > "$output/$phase.status"
	for pid in "$observer_pid" "$trace_pid" "$journal_pid"; do
		kill -0 "$pid" || {
			echo "diagnostic observer $pid stopped unexpectedly"
			return 1
		}
	done
	return "$status"
}
run_phase unit
run_phase integration
