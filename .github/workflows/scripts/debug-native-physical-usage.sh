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

# Fork-only diagnostics for the physical-usage failure at 6cf654b.
set -euo pipefail
export PATH="/usr/local/go/bin:/root/go/bin:$PATH"
export GOCACHE=/root/.cache/go-build
cd /mnt/host
readonly evidence=/root/native-physical-usage-debug
mkdir -p "$evidence"
exec > >(tee "$evidence/session.log") 2>&1
printf '[DEBUG] start=%s\n' "$(date -u --iso-8601=ns)"
uname -a
git config --global --add safe.directory /mnt/host
git rev-parse HEAD
git diff HEAD --exit-code
cat _output/portable-generated.commit
make _output/bin/profiler SKIP_PORTABLE_GENERATION=1
mkdir -p _output/bpf
cp bpf/*.o _output/bpf/
sha256sum _output/bin/profiler _output/bpf/native_physical_usage.o > "$evidence/binary-hashes.txt"
cat "$evidence/binary-hashes.txt"
tracefs=/sys/kernel/tracing
[[ -f "$tracefs/kprobe_profile" ]] || tracefs=/sys/kernel/debug/tracing
run_case() {
	local phase=$1 round=$2 status=0 case_pid sampler_pid
	local output="$evidence/${phase}-${round}.log"
	printf '[DEBUG] begin phase=%s round=%s time=%s\n' "$phase" "$round" "$(date -u --iso-8601=ns)"
	if [[ -r "$tracefs/kprobe_profile" ]]; then cat "$tracefs/kprobe_profile" > "$evidence/${phase}-${round}-kprobes-before.txt"; fi
	if [[ -r "$tracefs/kprobe_events" ]]; then cat "$tracefs/kprobe_events" > "$evidence/${phase}-${round}-kprobe-events-before.txt"; fi
	if [[ $phase == traced ]]; then
		timeout 90 strace -ff -ttt -e trace=munmap,kill,wait4,exit,exit_group -o "$evidence/strace-${round}" bash integration/run.sh test_profiler_native_memory_physical_usage.sh > "$output" 2>&1 &
		case_pid=$!
		(
			while kill -0 "$case_pid" 2> /dev/null; do
				date -u --iso-8601=ns
				cat "$tracefs/kprobe_events" "$tracefs/kprobe_profile" 2> /dev/null || true
				sleep 0.2
			done
		) > "$evidence/traced-${round}-kprobes-live.txt" &
		sampler_pid=$!
		wait "$case_pid" || status=$?
		kill "$sampler_pid" 2> /dev/null || true
		wait "$sampler_pid" 2> /dev/null || true
	else
		timeout 90 bash integration/run.sh test_profiler_native_memory_physical_usage.sh > "$output" 2>&1 || status=$?
	fi
	if [[ -r "$tracefs/kprobe_profile" ]]; then cat "$tracefs/kprobe_profile" > "$evidence/${phase}-${round}-kprobes-after.txt"; fi
	if [[ $status -eq 0 ]] && ! grep -q 'summary: total=1 passed=1 skipped=0 failed=0' "$output"; then
		printf '[DEBUG] selected scenario did not execute and pass\n' >> "$output"
		status=77
	fi
	printf '%s %s %s\n' "$phase" "$round" "$status" >> "$evidence/results.txt"
	cat "$output"
	printf '[DEBUG] end phase=%s round=%s status=%s time=%s\n' "$phase" "$round" "$status" "$(date -u --iso-8601=ns)"
}
for round in $(seq 1 10); do run_case baseline "$round"; done
printf '[DEBUG] installing diagnostic tools\n'
dnf -y install strace bpftrace bpftool
cat > "$evidence/pages.bt" << 'BT'
BEGIN { printf("OBSERVER_READY\n"); }
kprobe:folio_add_new_anon_rmap
/comm == "physical_usage_"/
{
    @alloc[pid] = count();
    @owner[arg0] = pid;
    @live[pid] = sum(1);
}
kprobe:folio_remove_rmap_ptes
/@owner[arg0]/
{
    $owner = @owner[arg0];
    @freed[$owner] = sum(arg2);
    @live[$owner] = sum(-1);
    if (pid != $owner) { @other_context[$owner,pid,comm] = count(); }
    delete(@owner[arg0]);
}
tracepoint:sched:sched_process_exit
/comm == "physical_usage_" || comm == "profiler"/
{
    printf("process_exit time_ns=%llu pid=%d comm=%s\n", nsecs, pid, comm);
}
END { clear(@owner); }
BT
bpftrace -B none "$evidence/pages.bt" > "$evidence/pages.log" 2>&1 &
observer=$!
trap 'kill -INT "$observer" 2>/dev/null || true; wait "$observer" 2>/dev/null || true' EXIT
for attempt in $(seq 1 60); do
	grep -q OBSERVER_READY "$evidence/pages.log" && break
	kill -0 "$observer" 2> /dev/null || break
	sleep 1
done
if ! grep -q OBSERVER_READY "$evidence/pages.log"; then
	cat "$evidence/pages.log"
	exit 1
fi
for round in $(seq 1 5); do run_case traced "$round"; done
kill -INT "$observer"
wait "$observer" || true
trap - EXIT
cat "$evidence/pages.log"
printf '[DEBUG] results\n'
cat "$evidence/results.txt"
git diff HEAD --exit-code
printf '[DEBUG] complete=%s\n' "$(date -u --iso-8601=ns)"
if awk '$3 != 0 {failed=1} END {exit !failed}' "$evidence/results.txt"; then
	exit 1
fi
