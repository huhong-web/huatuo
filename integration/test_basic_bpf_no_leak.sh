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

# Verify process-level BPF reclamation after SIGTERM, including resources held
# by Agent children. Explicit Close and kernel cleanup on exit are both valid.

set -euo pipefail

source "${ROOT_DIR}/integration/lib.sh"
source "${ROOT_DIR}/integration/config.sh"

readonly BPF_LEAK_DIR="${HUATUO_BAMAI_TEST_TMPDIR}/bpf"
readonly BPF_LEAK_EXIT_TIMEOUT=20
readonly BPF_LEAK_RECLAIM_TIMEOUT=20
readonly BPF_LEAK_STABLE_POLLS=2

command -v bpftool > /dev/null || skip "bpftool command is not installed"
command -v jq > /dev/null || skip "jq command is not installed"
command -v ps > /dev/null || skip "ps command is not installed"
BPF_LEAK_PORT=$(allocate_available_port) || fatal "failed to allocate an Agent port"
readonly BPF_LEAK_PORT
HUATUO_BAMAI_METRICS_API="http://127.0.0.1:${BPF_LEAK_PORT}/metrics"

bpf_leak_pid=""
bpf_leak_link_enumeration_available=false
bpf_leak_stable_polls=0

cleanup() {
	local pid start_time current_start_time
	if [[ -z "${bpf_leak_pid}" && -r "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo-bamai.pid" ]]; then
		bpf_leak_pid=$(< "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo-bamai.pid")
	fi
	if [[ -n "${bpf_leak_pid}" ]]; then
		bpf_leak_record_processes || log_warn "cannot refresh Agent descendants during cleanup"
	fi
	if [[ -r "${BPF_LEAK_DIR}/process-identities.tsv" ]]; then
		while read -r pid start_time; do
			current_start_time=$(bpf_leak_process_start_time "${pid}") || continue
			[[ "${current_start_time}" == "${start_time}" ]] || continue
			# The verdict is final; avoid another grace period before forced cleanup.
			stop_by_pid "${pid}" 0 || true
		done < "${BPF_LEAK_DIR}/process-identities.tsv"
	fi
	rm -f "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo-bamai.pid" || log_warn "cannot remove Agent PID file"
}
trap cleanup EXIT

bpf_leak_query() {
	local kind=$1 destination=$2
	local options=(-j)
	[[ "${kind}" == perf ]] || options+=(-f)
	bpftool "${options[@]}" "${kind}" show > "${destination}" 2> "${destination}.err" \
		|| fatal "bpftool ${kind} show failed; stdout: ${destination}; stderr: ${destination}.err"
	jq -e 'type == "array" and all(.[]; type == "object")' "${destination}" > /dev/null \
		|| fatal "invalid bpftool ${kind} JSON: ${destination}"
	if [[ "${kind}" == perf ]]; then
		jq -e 'all(.[]; (.pid | type) == "number" and .pid > 0
			and (.prog_id | type) == "number" and .prog_id > 0)' "${destination}" > /dev/null
	else
		jq -e 'all(.[]; (.id | type) == "number" and .id > 0)' "${destination}" > /dev/null
	fi || fatal "missing IDs in bpftool ${kind} JSON: ${destination}"
}

bpf_leak_snapshot() {
	local phase=$1 kind
	mkdir -p "${BPF_LEAK_DIR}/${phase}" || fatal "cannot create ${phase} snapshot directory"
	for kind in prog map perf; do
		bpf_leak_query "${kind}" "${BPF_LEAK_DIR}/${phase}/${kind}.json"
	done
	if "${bpf_leak_link_enumeration_available}"; then
		bpf_leak_query link "${BPF_LEAK_DIR}/${phase}/link.json"
	else
		echo '[]' > "${BPF_LEAK_DIR}/${phase}/link.json" || fatal "cannot record unavailable BPF links"
	fi
	jq -n --slurpfile prog "${BPF_LEAK_DIR}/${phase}/prog.json" \
		--slurpfile map "${BPF_LEAK_DIR}/${phase}/map.json" \
		--slurpfile link "${BPF_LEAK_DIR}/${phase}/link.json" \
		--slurpfile perf "${BPF_LEAK_DIR}/${phase}/perf.json" \
		'{prog: $prog[0], map: $map[0], link: $link[0], perf: $perf[0]}' \
		> "${BPF_LEAK_DIR}/${phase}.json" || fatal "cannot assemble ${phase} BPF snapshot"
}

bpf_leak_process_start_time() {
	local pid=$1 stat
	local fields=()
	IFS= read -r stat 2> /dev/null < "/proc/${pid}/stat" || return 1
	# Removing pid and comm makes starttime (field 22) array index 19.
	read -r -a fields <<< "${stat##*) }"
	[[ "${fields[19]:-}" =~ ^[0-9]+$ ]] || return 1
	printf '%s\n' "${fields[19]}"
}

bpf_leak_record_processes() {
	local pid start_time current_start_time
	local root_recorded=0
	: > "${BPF_LEAK_DIR}/process-seeds.txt" || return 1
	while read -r pid start_time; do
		[[ "${pid}" != "${bpf_leak_pid}" ]] || root_recorded=1
		current_start_time=$(bpf_leak_process_start_time "${pid}") || continue
		[[ "${current_start_time}" == "${start_time}" ]] || continue
		printf '%s\n' "${pid}" >> "${BPF_LEAK_DIR}/process-seeds.txt" || return 1
	done < "${BPF_LEAK_DIR}/process-identities.tsv"
	ps -e -o pid=,ppid= > "${BPF_LEAK_DIR}/processes.txt" || return 1
	# A child may have been forked by any Agent thread; ps reports the TGID parent.
	awk -v root="${bpf_leak_pid}" -v root_recorded="${root_recorded}" -v test_pid="$$" '
		FILENAME == ARGV[1] { selected[$1] = 1; next }
		{ parent[$1] = $2 }
		END {
			if (!root_recorded && parent[root] == test_pid) selected[root] = 1
			do {
				changed = 0
				for (pid in parent)
					if (!selected[pid] && selected[parent[pid]]) {
						selected[pid] = 1
						changed = 1
					}
			} while (changed)
			for (pid in selected) if (selected[pid]) print pid
		}' "${BPF_LEAK_DIR}/process-seeds.txt" "${BPF_LEAK_DIR}/processes.txt" \
		> "${BPF_LEAK_DIR}/pids.txt" || return 1
	while read -r pid; do
		start_time=$(bpf_leak_process_start_time "${pid}") || continue
		printf '%s\t%s\n' "${pid}" "${start_time}" >> "${BPF_LEAK_DIR}/process-identities.tsv" || return 1
	done < "${BPF_LEAK_DIR}/pids.txt"
	sort -u "${BPF_LEAK_DIR}/process-identities.tsv" -o "${BPF_LEAK_DIR}/process-identities.tsv"
}

bpf_leak_collect_process_resources() {
	local pid file
	bpf_leak_record_processes || fatal "cannot record Agent process identities"
	: > "${BPF_LEAK_DIR}/fdinfo.txt" || fatal "cannot create BPF FD inventory"
	while read -r pid; do
		for file in /proc/"${pid}"/fdinfo/*; do
			[[ -e "${file}" ]] || continue
			# Concurrent closes are expected; a still-existing unreadable FD is not.
			cat "${file}" >> "${BPF_LEAK_DIR}/fdinfo.txt" 2> "${BPF_LEAK_DIR}/fdinfo.err" \
				|| { [[ ! -e "${file}" ]] || fatal "cannot read ${file}"; }
		done
	done < "${BPF_LEAK_DIR}/pids.txt"
	awk '/^(prog|map|link)_id:[[:space:]]+[0-9]+$/ {
		sub(/_id:/, "", $1); printf "{\"kind\":\"%s\",\"id\":%s}\n", $1, $2
	}' "${BPF_LEAK_DIR}/fdinfo.txt" | jq -s . > "${BPF_LEAK_DIR}/fds.json" \
		|| fatal "cannot parse BPF fdinfo"
	if ! "${bpf_leak_link_enumeration_available}" && jq -e 'any(.[]; .kind == "link")' "${BPF_LEAK_DIR}/fds.json" > /dev/null; then
		fatal "Agent holds BPF links but bpftool cannot enumerate them; install a matching bpftool"
	fi
}

bpf_leak_write_next_owned_resources() {
	jq -n --slurpfile before "${BPF_LEAK_DIR}/before.json" \
		--slurpfile running "${BPF_LEAK_DIR}/running.json" \
		--slurpfile previous "${BPF_LEAK_DIR}/owned.json" \
		--slurpfile fd_resources "${BPF_LEAK_DIR}/fds.json" \
		--slurpfile pids "${BPF_LEAK_DIR}/pids.txt" '
		$before[0] as $baseline |
		$running[0] as $current |
		$previous[0] as $previous_owned |
		def fd_ids($kind): [$fd_resources[0][] | select(.kind == $kind) | .id];

		[$current.perf[] | select(.pid as $pid | $pids | index($pid))] as $process_attachments |
		(($previous_owned.program_ids + fd_ids("prog") + [$process_attachments[].prog_id])
			| unique - [$baseline.prog[].id]) as $program_ids |
		[$current.prog[] | select(.id as $id | $program_ids | index($id))] as $owned_programs |
		(($previous_owned.map_ids + fd_ids("map") + [$owned_programs[].map_ids[]?])
			| unique - [$baseline.map[].id]) as $map_ids |
		(($previous_owned.link_ids + fd_ids("link") + [$current.link[] |
			select(.prog_id as $id | $program_ids | index($id)) | .id])
			| unique - [$baseline.link[].id]) as $link_ids |

		[$current.perf[] | select(.prog_id as $id | $program_ids | index($id))] as $perf_attachments |
		[$current.link[] | select(.id as $id | $link_ids | index($id))] as $owned_links |
		{program_ids: $program_ids, map_ids: $map_ids, link_ids: $link_ids,
		 attachment_count: (($perf_attachments | length) + ($owned_links | length))}
		' > "${BPF_LEAK_DIR}/owned.next.json" || fatal "cannot identify Agent BPF resources"
}

bpf_leak_collect_and_check_ready() {
	kill -0 "${bpf_leak_pid}" 2> /dev/null || fatal "Agent exited before BPF inventory"
	bpf_leak_collect_process_resources
	bpf_leak_snapshot running
	bpf_leak_write_next_owned_resources

	# Two unchanged polls require three observations; HTTP readiness alone is insufficient.
	if cmp -s "${BPF_LEAK_DIR}/owned.json" "${BPF_LEAK_DIR}/owned.next.json"; then
		bpf_leak_stable_polls=$((bpf_leak_stable_polls + 1))
	else
		bpf_leak_stable_polls=0
	fi
	mv "${BPF_LEAK_DIR}/owned.next.json" "${BPF_LEAK_DIR}/owned.json" \
		|| fatal "cannot save Agent BPF resource inventory"
	jq -e '(.program_ids | length) > 0 and (.map_ids | length) > 0 and .attachment_count > 0' \
		"${BPF_LEAK_DIR}/owned.json" > /dev/null \
		&& ((bpf_leak_stable_polls >= BPF_LEAK_STABLE_POLLS))
}

bpf_leak_process_exited() {
	! kill -0 "${bpf_leak_pid}" 2> /dev/null
}

bpf_leak_compare_snapshots() {
	local phase=$1
	jq -n --slurpfile owned "${BPF_LEAK_DIR}/owned.json" \
		--slurpfile before "${BPF_LEAK_DIR}/before.json" \
		--slurpfile after "${BPF_LEAK_DIR}/${phase}.json" '
		$owned[0] as $instance |
		$before[0] as $baseline |
		$after[0] as $current |
		def select_ids($objects; $ids): [$objects[] | select(.id as $id | $ids | index($id))];
		def pin_records($snapshot):
			[("prog", "map", "link") as $kind | $snapshot[$kind][] |
			 .id as $id | .pinned[]? | {kind: $kind, id: $id, path: .}];
		{prog: $instance.program_ids, map: $instance.map_ids, link: $instance.link_ids} as $instance_ids |
		(pin_records($current) - pin_records($baseline)) as $new_pins |
		{
		 owned: {
			prog: select_ids($current.prog; $instance.program_ids),
			map: select_ids($current.map; $instance.map_ids),
			link: select_ids($current.link; $instance.link_ids),
			perf: [$current.perf[] | select(.prog_id as $id | $instance.program_ids | index($id))],
			pins: [$new_pins[] | select(. as $pin | $instance_ids[$pin.kind] | index($pin.id))]
		 },
		 unattributed: {
			prog: [$current.prog[] | select(.id as $id |
				([$baseline.prog[].id] + $instance.program_ids) | index($id) | not)],
			map: [$current.map[] | select(.id as $id |
				([$baseline.map[].id] + $instance.map_ids) | index($id) | not)],
			link: [$current.link[] | select(.id as $id |
				([$baseline.link[].id] + $instance.link_ids) | index($id) | not)],
			perf: [($current.perf - $baseline.perf)[] |
				select(.prog_id as $id | $instance.program_ids | index($id) | not)],
			pins: [$new_pins[] | select(. as $pin | $instance_ids[$pin.kind] | index($pin.id) | not)]
		 }
		}
		' > "${BPF_LEAK_DIR}/remaining.json" || fatal "cannot compare BPF resources"
}

bpf_leak_snapshot_and_check_reclaimed() {
	local phase=$1
	bpf_leak_snapshot "${phase}"
	bpf_leak_compare_snapshots "${phase}"
	jq -e 'all(.[]; all(.[]; length == 0))' "${BPF_LEAK_DIR}/remaining.json" > /dev/null
}

mkdir -p "${BPF_LEAK_DIR}"
: > "${BPF_LEAK_DIR}/process-identities.tsv"
# Enumeration arrived in 5.8. Older kernels use perf/raw tracepoint FDs; on
# newer kernels a failed query must not silently weaken the no-leak assertion.
if bpftool -j -f link show > "${BPF_LEAK_DIR}/link-probe.json" 2> "${BPF_LEAK_DIR}/link-probe.err"; then
	jq -e 'type == "array"' "${BPF_LEAK_DIR}/link-probe.json" > /dev/null \
		|| fatal "invalid bpftool link JSON"
	bpf_leak_link_enumeration_available=true
else
	# JSON mode can report errors on stdout while leaving stderr empty.
	jq -r '.. | objects | .error? | select(type == "string")' \
		"${BPF_LEAK_DIR}/link-probe.json" > "${BPF_LEAK_DIR}/link-probe-errors.txt" \
		|| fatal "invalid bpftool link JSON: ${BPF_LEAK_DIR}/link-probe.json"
	cat "${BPF_LEAK_DIR}/link-probe.err" >> "${BPF_LEAK_DIR}/link-probe-errors.txt"
	bpf_leak_link_error=$(< "${BPF_LEAK_DIR}/link-probe-errors.txt")
	if ! kernel_version_le 5 7; then
		fatal "cannot enumerate BPF links: ${bpf_leak_link_error}; see ${BPF_LEAK_DIR}/link-probe.{json,err}"
	fi
	if [[ -n "${bpf_leak_link_error}" ]]; then
		if grep -Eq 'Permission denied|Operation not permitted' "${BPF_LEAK_DIR}/link-probe-errors.txt" \
			|| ! grep -Eq 'Invalid argument|Operation not supported|Function not implemented' "${BPF_LEAK_DIR}/link-probe-errors.txt"; then
			fatal "bpftool link query failed: ${bpf_leak_link_error}; see ${BPF_LEAK_DIR}/link-probe.{json,err}"
		fi
	else
		bpftool link help > "${BPF_LEAK_DIR}/link-help.txt" 2>&1 || true
		if grep -q 'bpftool link' "${BPF_LEAK_DIR}/link-help.txt"; then
			fatal "bpftool link query failed without an error; see ${BPF_LEAK_DIR}/link-probe.{json,err}"
		fi
	fi
	log_info "BPF link enumeration unavailable; checking program/map IDs and perf attachments"
fi

echo '{"program_ids":[],"map_ids":[],"link_ids":[],"attachment_count":0}' > "${BPF_LEAK_DIR}/owned.json"
bpf_leak_snapshot before
integration_huatuo_bamai_start write_bpf_no_leak_config
bpf_leak_pid=$(< "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo-bamai.pid")
wait_until "${WAIT_HUATUO_BAMAI_TIMEOUT}" 1 bpf_leak_collect_and_check_ready \
	|| fatal "Agent did not load and attach BPF with a stable resource inventory"
log_info "Agent BPF inventory: $(jq -c . "${BPF_LEAK_DIR}/owned.json")"

kill -TERM "${bpf_leak_pid}" || fatal "failed to send SIGTERM to Agent pid=${bpf_leak_pid}"
wait_until "${BPF_LEAK_EXIT_TIMEOUT}" 1 bpf_leak_process_exited \
	|| fatal "Agent did not exit within ${BPF_LEAK_EXIT_TIMEOUT}s after SIGTERM"
bpf_leak_exit_status=0
wait "${bpf_leak_pid}" || bpf_leak_exit_status=$?
log_info "Agent exited after SIGTERM: status=${bpf_leak_exit_status}"
rm -f "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo-bamai.pid"

wait_until "${BPF_LEAK_RECLAIM_TIMEOUT}" 1 bpf_leak_snapshot_and_check_reclaimed after \
	|| fatal "cannot prove BPF reclamation within ${BPF_LEAK_RECLAIM_TIMEOUT}s; owned resources or unattributed additions remain: $(< "${BPF_LEAK_DIR}/remaining.json")"
log_info "Agent BPF programs, maps, attachments and pins were reclaimed"
