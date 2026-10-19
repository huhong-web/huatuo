#!/usr/bin/env bash

# Copyright 2026 The HuaTuo Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Verify inherited membership, then the daemon's own startup/steady CPU and
# memory limits, including changed configuration after a graceful restart.

set -euo pipefail

source "${ROOT_DIR}/integration/lib.sh"
source "${ROOT_DIR}/integration/config.sh"
source "${ROOT_DIR}/integration/lib_cgroup.sh"

readonly LIMITS_FIXTURES="${HUATUO_BAMAI_TEST_TMPDIR}/fixtures"
readonly LIMITS_GATE="${LIMITS_FIXTURES}/dev/sda0"
readonly LIMITS_PID_FILE="${HUATUO_BAMAI_TEST_TMPDIR}/huatuo-bamai.pid"
# Bash does not export arrays to the child test process.
readonly CURL_TIMEOUT=(--connect-timeout 2 --max-time 3)

require_commands cmp curl ss findmnt awk mkfifo
[[ -x "${HUATUO_BAMAI_BIN}" ]] || fatal "huatuo-bamai binary missing: ${HUATUO_BAMAI_BIN}"
[[ -f "${HUATUO_BAMAI_TEST_FIXTURES}/dev/sda0" ]] || fatal "XFS device fixture is missing"

LIMITS_PORT=$(allocate_available_port) || fatal "failed to allocate a bamai port"
readonly LIMITS_PORT
HUATUO_BAMAI_METRICS_API="http://127.0.0.1:${LIMITS_PORT}/metrics"

if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
	require_commands systemctl timeout
	timeout --kill-after=1 10 systemctl show --property=Version > /dev/null 2>&1 \
		|| skip "cgroup v2 runtime limits require the systemd manager"
	for limits_controller in cpu memory; do
		grep -qw "${limits_controller}" /sys/fs/cgroup/cgroup.controllers \
			|| skip "cgroup v2 ${limits_controller} controller is unavailable"
	done
	readonly LIMITS_MODE=v2
	readonly LIMITS_CPU_ROOT=/sys/fs/cgroup
	readonly LIMITS_MEMORY_ROOT=/sys/fs/cgroup
	readonly LIMITS_GROUP=/huatuo.slice/huatuo-bamai.slice
	readonly LIMITS_ROOTS=(/sys/fs/cgroup)
else
	readonly LIMITS_MODE=v1
	LIMITS_CPU_ROOT=$(findmnt -rn -t cgroup -O cpu -o TARGET) \
		|| skip "cgroup v1 CPU controller is unavailable"
	LIMITS_MEMORY_ROOT=$(cgroup_memory_root) \
		|| skip "cgroup memory controller is unavailable"
	readonly LIMITS_CPU_ROOT LIMITS_MEMORY_ROOT
	readonly LIMITS_GROUP=/huatuo-bamai
	mapfile -t LIMITS_ROOTS < <(findmnt -rn -t cgroup -o TARGET)
	readonly LIMITS_ROOTS
fi
for limits_root in "${LIMITS_ROOTS[@]}"; do
	[[ ! -d "${limits_root}${LIMITS_GROUP}" ]] \
		|| skip "runtime cgroup already exists: ${limits_root}${LIMITS_GROUP}"
done
[[ -w "${LIMITS_CPU_ROOT}" && -w "${LIMITS_MEMORY_ROOT}" ]] \
	|| skip "CPU and memory cgroup roots must be writable"

limits_observer_pid=""
limits_cpu_path=""
limits_memory_path=""
limits_quota=""
limits_period=""
limits_memory=""

cleanup() {
	local status=$?
	stop_and_wait_by_pid "${limits_observer_pid}" 1 || true
	huatuo_bamai_stop || status=1
	# A startup failure may precede the daemon's signal handler. Only initially
	# absent leaf groups belong to this test; never remove an existing hierarchy.
	if [[ ${LIMITS_MODE} == v2 && -d "${LIMITS_CPU_ROOT}${LIMITS_GROUP}" ]]; then
		timeout --kill-after=1 10 systemctl stop huatuo-bamai.slice || status=1
	fi
	for limits_root in "${LIMITS_ROOTS[@]}"; do
		if [[ -d "${limits_root}${LIMITS_GROUP}" ]]; then
			rmdir "${limits_root}${LIMITS_GROUP}" || status=1
		fi
	done
	exit "${status}"
}
trap cleanup EXIT

limits_locate_cgroup() {
	local pid cpu_path memory_path
	[[ -s "${LIMITS_PID_FILE}" ]] || return 1
	pid=$(< "${LIMITS_PID_FILE}")
	[[ -r /proc/${pid}/cgroup ]] || return 1
	if [[ ${LIMITS_MODE} == v2 ]]; then
		cpu_path=$(awk -F: '$1 == "0" {print $3}' "/proc/${pid}/cgroup")
		memory_path=${cpu_path}
	else
		cpu_path=$(awk -F: '$2 ~ /(^|,)cpu(,|$)/ {print $3}' "/proc/${pid}/cgroup")
		memory_path=$(awk -F: '$2 ~ /(^|,)memory(,|$)/ {print $3}' "/proc/${pid}/cgroup")
	fi
	[[ ${cpu_path} == "${LIMITS_GROUP}" && ${memory_path} == "${LIMITS_GROUP}" ]] || return 1
	limits_cpu_path="${LIMITS_CPU_ROOT}${cpu_path}"
	limits_memory_path="${LIMITS_MEMORY_ROOT}${memory_path}"
	grep -qx "${pid}" "${limits_cpu_path}/cgroup.procs" \
		&& grep -qx "${pid}" "${limits_memory_path}/cgroup.procs"
}

limits_match() {
	local cpu=$1 memory_mib=$2
	if [[ ${LIMITS_MODE} == v2 ]]; then
		read -r limits_quota limits_period < "${limits_cpu_path}/cpu.max" || return 1
		limits_memory=$(< "${limits_memory_path}/memory.max")
	else
		limits_quota=$(< "${limits_cpu_path}/cpu.cfs_quota_us")
		limits_period=$(< "${limits_cpu_path}/cpu.cfs_period_us")
		limits_memory=$(< "${limits_memory_path}/memory.limit_in_bytes")
	fi
	[[ ${limits_memory} == "$((memory_mib * 1024 * 1024))" ]] || return 1
	awk -v quota="${limits_quota}" -v period="${limits_period}" -v cpu="${cpu}" \
		'BEGIN {exit !(quota > 0 && period > 0 && quota == cpu * period)}'
}

limits_assert() {
	local phase=$1 cpu=$2 memory_mib=$3
	wait_until 10 0.1 limits_match "${cpu}" "${memory_mib}" \
		|| fatal "${phase}: CPU=${limits_quota}/${limits_period}, memory=${limits_memory}; expected ${cpu} cores, ${memory_mib} MiB"
	log_info "${phase}: ${limits_cpu_path} CPU=${limits_quota}/${limits_period}, memory=${limits_memory} bytes"
}

limits_observe_startup() {
	local cpu=$1 memory_mib=$2 status=0
	# Opening the write end waits for XFS to open the read end. Withhold bytes
	# until the assertion completes so initialization cannot switch CPU quotas.
	# The parent's readiness/completion deadlines also bound this blocked open.
	exec 3> "${LIMITS_GATE}"
	(
		limits_locate_cgroup || fatal "daemon reached the startup gate outside its runtime cgroup"
		limits_assert startup "${cpu}" "${memory_mib}"
	) || status=$?
	# Release initialization even on assertion failure, allowing normal cleanup.
	cat "${HUATUO_BAMAI_TEST_FIXTURES}/dev/sda0" >&3 || return 1
	return "${status}"
}

limits_process_exited() {
	! kill -0 "$1" 2> /dev/null
}

limits_stop() {
	local phase=$1 pid
	pid=$(< "${LIMITS_PID_FILE}")
	kill -TERM "${pid}"
	wait_until 20 0.1 limits_process_exited "${pid}" || fatal "daemon did not exit gracefully"
	wait "${pid}" || fatal "daemon exited unsuccessfully"
	rm -f "${LIMITS_PID_FILE}"
	for limits_root in "${LIMITS_ROOTS[@]}"; do
		[[ ! -d "${limits_root}${LIMITS_GROUP}" ]] || fatal "runtime cgroup remains after shutdown: ${limits_root}${LIMITS_GROUP}"
	done
	huatuo_bamai_log_check || fatal "daemon logged an error during startup or shutdown"
	mv "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo.log" "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo-${phase}.log"
}

write_runtime_limits_config "${LIMITS_PORT}" 0.75 1.25 512
integration_huatuo_bamai_start : --region dev --procfs-prefix "${HUATUO_BAMAI_TEST_FIXTURES}" \
	--disable-storage --disable-kubelet
limits_pid=$(< "${LIMITS_PID_FILE}")
cmp -s "/proc/$$/cgroup" "/proc/${limits_pid}/cgroup" || fatal "default startup did not inherit cgroup membership"
log_info "default startup inherits the test process's cgroup"
limits_stop inherited

cp -a "${HUATUO_BAMAI_TEST_FIXTURES}" "${LIMITS_FIXTURES}"
limits_old_pid=${limits_pid}
for limits_values in '0.75 1.25 512' '1.5 0.5 768'; do
	read -r limits_startup_cpu limits_cpu limits_memory_mib <<< "${limits_values}"
	write_runtime_limits_config "${LIMITS_PORT}" "${limits_startup_cpu}" "${limits_cpu}" "${limits_memory_mib}"
	rm -f "${LIMITS_GATE}"
	mkfifo "${LIMITS_GATE}"
	limits_observe_startup "${limits_startup_cpu}" "${limits_memory_mib}" \
		> "${HUATUO_BAMAI_TEST_TMPDIR}/startup-${limits_startup_cpu}.log" 2>&1 &
	limits_observer_pid=$!
	integration_huatuo_bamai_start : \
		--region dev --procfs-prefix "${LIMITS_FIXTURES}" \
		--disable-storage --disable-kubelet --enable-cgroup
	# If XFS stops reading the fixture, readiness alone must not hide a lost gate.
	wait_until 10 0.1 limits_process_exited "${limits_observer_pid}" \
		|| fatal "startup observer did not finish; the XFS fixture gate was not released"
	limits_observer_status=0
	wait "${limits_observer_pid}" || limits_observer_status=$?
	limits_observer_pid=""
	cat "${HUATUO_BAMAI_TEST_TMPDIR}/startup-${limits_startup_cpu}.log"
	[[ ${limits_observer_status} -eq 0 ]] || fatal "startup limits check failed"
	limits_pid=$(< "${LIMITS_PID_FILE}")
	[[ ${limits_pid} != "${limits_old_pid}" ]] || fatal "restart reused the previous daemon PID"
	limits_locate_cgroup || fatal "ready daemon is outside its runtime cgroup"
	limits_assert running "${limits_cpu}" "${limits_memory_mib}"
	huatuo_bamai_ready || fatal "daemon is not ready after applying runtime limits"
	limits_stop "${limits_startup_cpu}"
	limits_old_pid=${limits_pid}
done
