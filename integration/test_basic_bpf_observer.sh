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

# Verify the observer's external process/FD contract with real kernel resources.
# Workloads create objects; this script owns identity, lifetime and error assertions.

set -euo pipefail

source "${ROOT_DIR}/integration/lib.sh"
source "${ROOT_DIR}/integration/lib_bpf.sh"

readonly BPF_OBSERVER_DIR="${HUATUO_BAMAI_TEST_TMPDIR}/observer"

command -v gcc > /dev/null || skip "gcc command is not installed"
command -v bpftool > /dev/null || skip "bpftool command is not installed"
command -v jq > /dev/null || skip "jq command is not installed"
command -v timeout > /dev/null || skip "timeout command is not installed"
command -v findmnt > /dev/null || skip "findmnt command is not installed"

bpf_observer_pid=""
bpf_observer_socket_server_pid=""
bpf_observer_case=""
bpf_observer_pin_dir=""
bpf_observer_pin_dirs=()

cleanup() {
	local directory
	if [[ -n "${bpf_observer_pid}" ]] && jobs -pr | grep -Fxq "${bpf_observer_pid}"; then
		stop_by_pid "${bpf_observer_pid}" 0 || true
		wait "${bpf_observer_pid}" 2> /dev/null || true
	fi
	if [[ -n "${bpf_observer_socket_server_pid}" ]] && jobs -pr | grep -Fxq "${bpf_observer_socket_server_pid}"; then
		stop_by_pid "${bpf_observer_socket_server_pid}" 0 || true
		wait "${bpf_observer_socket_server_pid}" 2> /dev/null || true
	fi
	for directory in "${bpf_observer_pin_dirs[@]}"; do
		bpf_remove_pin_directory "${directory}" || log_warn "cannot remove workload pins: ${directory}"
	done
}
trap cleanup EXIT

bpf_observer_start() {
	local mode=$1
	shift
	bpf_observer_case=$(mktemp -d "${BPF_OBSERVER_DIR}/${mode}.XXXXXX")
	bpf_observer_pin_dir=$(bpf_create_pin_directory) || fatal "cannot allocate BPF workload pins"
	bpf_observer_pin_dirs+=("${bpf_observer_pin_dir}")
	"${BPF_OBSERVER_DIR}/observer" "${bpf_observer_case}" -- \
		"${BPF_OBSERVER_DIR}/workload" "${mode}" "${bpf_observer_pin_dir}" "$@" \
		> "${bpf_observer_case}/stdout.log" 2> "${bpf_observer_case}/stderr.log" &
	bpf_observer_pid=$!
}

bpf_observer_start_socket() {
	local mode=$1 id=${2:-0}
	bpf_observer_case=$(mktemp -d "${BPF_OBSERVER_DIR}/${mode}.XXXXXX")
	"${BPF_OBSERVER_DIR}/observer" "${bpf_observer_case}" -- \
		"${BPF_OBSERVER_DIR}/socket-workload" "${mode}" "${BPF_OBSERVER_DIR}/socket" "${id}" \
		> "${bpf_observer_case}/stdout.log" 2> "${bpf_observer_case}/stderr.log" &
	bpf_observer_pid=$!
}

assert_bpf_observer_completed() {
	local status=0
	wait_until 20 0.05 process_exited "${bpf_observer_pid}" \
		|| fatal "BPF observer did not complete: ${bpf_observer_case}"
	wait "${bpf_observer_pid}" || status=$?
	bpf_observer_pid=""
	[[ ${status} == 0 ]] || fatal "BPF observer/workload exited ${status}; see ${bpf_observer_case}/stderr.log"
	jq -e '.complete == true and .exit_status == 0' \
		"${bpf_observer_case}/complete.json" > /dev/null \
		|| fatal "expected complete BPF observations; actual: ${bpf_observer_case}/complete.json"
	jq -e -s --slurpfile completion "${bpf_observer_case}/complete.json" \
		'length == $completion[0].record_count' "${bpf_observer_case}/resources.jsonl" > /dev/null \
		|| fatal "BPF observer completion count does not match its journal"
}

assert_bpf_observer_pinned() {
	local kind=$1 pin_name=${2:-$1} recorded_pin=${3:-${2:-$1}} id identity
	bpf_query_pinned "${kind}" "${bpf_observer_pin_dir}/${pin_name}" \
		"${bpf_observer_case}/kernel.json"
	id=$(jq -er '.id | select(type == "number" and . > 0)' "${bpf_observer_case}/kernel.json")
	identity=$(stat -L -c '%d:%i' "${bpf_observer_pin_dir}/${pin_name}")
	jq -e -s --arg kind "${kind}" --argjson id "${id}" \
		--arg path "${bpf_observer_pin_dir}/${recorded_pin}" --arg identity "${identity}" '
		any(.[]; .kind == $kind and .id == $id and .pin? == $path and .pin_identity == $identity)
		' "${bpf_observer_case}/resources.jsonl" > /dev/null \
		|| fatal "expected BPF ${kind} ID ${id} and pin ${pin_name} in observations"
	log_info "observed pinned BPF ${kind} ID ${id}: ${pin_name}"
}

assert_bpf_observer_pin_remaining() {
	local expected=$1
	jq -s '[.[] | select(has("pin")) | {identity: .pin_identity}]' \
		"${bpf_observer_case}/resources.jsonl" > "${bpf_observer_case}/pin-candidates.json"
	bpf_find_remaining_pins "${bpf_observer_case}/pin-candidates.json" "${bpf_observer_case}/remaining-pins.json"
	jq -e --argjson expected "${expected}" 'length == $expected' \
		"${bpf_observer_case}/remaining-pins.json" > /dev/null \
		|| fatal "expected ${expected} surviving Agent pins; actual: $(< "${bpf_observer_case}/remaining-pins.json")"
}

assert_bpf_observer_created() {
	local kind=$1
	jq -e -s --arg kind "${kind}" 'any(.[]; .kind == $kind and .created)' \
		"${bpf_observer_case}/resources.jsonl" > /dev/null \
		|| fatal "expected creation identity before FD close"
}

assert_bpf_observer_attachment() {
	if "${bpf_link_enumeration_available}"; then
		assert_bpf_observer_created link
	else
		jq -e -s 'any(.[]; .kind == "prog" and .legacy_attachment? == true)' \
			"${bpf_observer_case}/resources.jsonl" > /dev/null \
			|| fatal "expected legacy raw attachment program identity"
	fi
}

assert_bpf_observer_map_count() {
	jq -e -s '[.[] | select(.created and .kind == "map") | .id] |
			length == 100 and (unique | length) == 100' \
		"${bpf_observer_case}/resources.jsonl" > /dev/null \
		|| fatal "expected 100 map IDs during ${bpf_observer_mode}"
}

assert_bpf_observer_descendant() {
	jq -e -s --argjson root "$(jq .root_pid "${bpf_observer_case}/complete.json")" \
		'any(.[]; .created and .pid != $root)' "${bpf_observer_case}/resources.jsonl" > /dev/null \
		|| fatal "expected resource identity from the reparented child"
}

assert_bpf_observer_sigterm() {
	jq -e '.sigterm_forwarded == true' "${bpf_observer_case}/complete.json" > /dev/null \
		|| fatal "expected SIGTERM delivery before late resource creation"
}

assert_bpf_observer_borrowed() {
	jq -e -s 'all(.[]; .created == false)' "${bpf_observer_case}/resources.jsonl" > /dev/null \
		|| fatal "borrowed map must not be reported as newly created"
}

assert_bpf_observer_rejected() {
	local expected_error=${1:-} status
	wait_until 5 0.05 process_exited "${bpf_observer_pid}" || fatal "unsupported operation was not rejected"
	status=0
	wait "${bpf_observer_pid}" || status=$?
	bpf_observer_pid=""
	[[ ${status} != 0 ]] || fatal "unsupported observation unexpectedly succeeded"
	jq -e '.complete == false' "${bpf_observer_case}/complete.json" > /dev/null \
		|| fatal "unsupported operation must invalidate observation completeness"
	if [[ -n "${expected_error}" ]]; then
		grep -Fq -- "${expected_error}" "${bpf_observer_case}/stderr.log" \
			|| fatal "expected ${expected_error}; actual: ${bpf_observer_case}/stderr.log"
	fi
}

assert_bpf_observer_reference() {
	local expected=$1
	"${BPF_OBSERVER_DIR}/workload" reference_lookup "${bpf_observer_reference_source}" \
		> "${bpf_observer_case}/reference.json"
	jq -e --argjson expected "${expected}" '.present == $expected' \
		"${bpf_observer_case}/reference.json" > /dev/null \
		|| fatal "expected reference present=${expected}; actual: $(< "${bpf_observer_case}/reference.json")"
}

assert_bpf_observer_socket_attached() {
	local expected=$1
	"${BPF_OBSERVER_DIR}/socket-workload" inspect "${BPF_OBSERVER_DIR}/socket" \
		> "${bpf_observer_case}/socket.json"
	jq -e --argjson expected "${expected}" '.attached == $expected' \
		"${bpf_observer_case}/socket.json" > /dev/null \
		|| fatal "expected socket attachment=${expected}; actual: $(< "${bpf_observer_case}/socket.json")"
}

bpf_observer_program_reclaimed() {
	! bpf_query_by_id prog "$1" "${bpf_observer_case}/program.json"
}

assert_bpf_observer_owned_socket() {
	local expected_attached=$1 id
	assert_bpf_observer_completed
	assert_bpf_observer_created prog
	assert_bpf_observer_socket_attached "${expected_attached}"
	id=$(jq -ers '[.[] | select(.kind == "prog" and .created) | .id] |
		if length == 1 then .[0] else error("expected one owned program") end' \
		"${bpf_observer_case}/resources.jsonl")
	if "${expected_attached}"; then
		bpf_query_by_id prog "${id}" "${bpf_observer_case}/program.json" \
			|| fatal "expected program ID ${id} retained by the external socket"
		"${BPF_OBSERVER_DIR}/socket-workload" detach "${BPF_OBSERVER_DIR}/socket"
	fi
	wait_until 5 0.05 bpf_observer_program_reclaimed "${id}" \
		|| fatal "program ID ${id} survived socket detach; see ${bpf_observer_case}/program.json"
}

assert_bpf_observer_network_boundary() {
	local expected_error=$1
	jq -e --argjson expected "${expected_error}" '.kernel_error == $expected' \
		"${bpf_observer_case}/stdout.log" > /dev/null \
		|| fatal "expected netlink kernel error=${expected_error}; actual: $(< "${bpf_observer_case}/stdout.log")"
}

assert_bpf_observer_network_capability() {
	jq -e '.effective == 0 and .permitted == 0 and .inheritable == 0 and
		.bounded == 0 and .no_new_privs == 1' "${bpf_observer_case}/stdout.log" > /dev/null \
		|| fatal "expected permanent network-administration restriction; actual: $(< "${bpf_observer_case}/stdout.log")"
}

bpf_build_observer_tools "${BPF_OBSERVER_DIR}"
compile_user_fixture "${ROOT_DIR}/integration/testdata/tools/test_bpf_socket_workload.c" \
	"${BPF_OBSERVER_DIR}/socket-workload" -std=gnu11 -O2 -Werror
bpf_probe_link_enumeration "${BPF_OBSERVER_DIR}"

# Workloads must raise their own limit even when the parent starts with little headroom.
ulimit -S -l 64 || fatal "cannot set the observer workload memlock precondition"

for bpf_observer_kind in map prog; do
	bpf_observer_start "${bpf_observer_kind}"
	assert_bpf_observer_completed
	assert_bpf_observer_pinned "${bpf_observer_kind}"
	assert_bpf_observer_created "${bpf_observer_kind}"
done

if "${bpf_link_enumeration_available}"; then
	bpf_observer_start link
	assert_bpf_observer_completed
	assert_bpf_observer_pinned link
	assert_bpf_observer_created link
else
	log_info "kernel has no link enumeration; exercising legacy raw attachment FD lifetime"
fi
bpf_observer_start raw
assert_bpf_observer_completed
assert_bpf_observer_created prog
assert_bpf_observer_attachment

for bpf_observer_mode in race fork_race; do
	bpf_observer_start "${bpf_observer_mode}"
	assert_bpf_observer_completed
	assert_bpf_observer_map_count
	log_info "observed all 100 map creations during ${bpf_observer_mode}"
done

bpf_observer_start orphan
assert_bpf_observer_completed
assert_bpf_observer_pinned map
assert_bpf_observer_descendant

bpf_observer_start late "${BPF_OBSERVER_DIR}/late-ready"
wait_until 5 0.05 test -e "${BPF_OBSERVER_DIR}/late-ready" || fatal "late workload did not become ready"
kill -TERM "${bpf_observer_pid}"
assert_bpf_observer_completed
assert_bpf_observer_pinned map
assert_bpf_observer_sigterm

bpf_observer_borrowed_source=$(bpf_create_pin_directory) || fatal "cannot allocate baseline BPF pin"
bpf_observer_pin_dirs+=("${bpf_observer_borrowed_source}")
"${BPF_OBSERVER_DIR}/workload" map "${bpf_observer_borrowed_source}"
bpf_observer_start borrowed "${bpf_observer_borrowed_source}/map"
assert_bpf_observer_completed
assert_bpf_observer_pinned map borrowed
assert_bpf_observer_borrowed

bpf_observer_start borrowed_map_program "${bpf_observer_borrowed_source}/map"
assert_bpf_observer_completed
assert_bpf_observer_created prog

bpf_observer_start borrowed_data_update "${bpf_observer_borrowed_source}/map"
assert_bpf_observer_completed
assert_bpf_observer_borrowed

for bpf_observer_source_mode in reference_source reference_hash_source reference_program_source; do
	bpf_observer_reference_source=$(bpf_create_pin_directory) || fatal "cannot allocate reference source pins"
	bpf_observer_pin_dirs+=("${bpf_observer_reference_source}")
	"${BPF_OBSERVER_DIR}/workload" "${bpf_observer_source_mode}" "${bpf_observer_reference_source}"
	bpf_observer_start borrowed_map_program "${bpf_observer_reference_source}/outer"
	assert_bpf_observer_rejected "program may mutate a borrowed reference container"
	for bpf_observer_mode in borrowed_reference borrowed_reference_batch; do
		bpf_observer_start "${bpf_observer_mode}" "${bpf_observer_reference_source}"
		assert_bpf_observer_rejected "cannot track references added to a borrowed BPF object"
		assert_bpf_observer_reference false
	done
	"${BPF_OBSERVER_DIR}/workload" reference_fill "${bpf_observer_reference_source}"
	bpf_observer_start reference_hold "${bpf_observer_reference_source}"
	assert_bpf_observer_completed
	assert_bpf_observer_borrowed
	assert_bpf_observer_reference true
	bpf_observer_start reference_clear "${bpf_observer_reference_source}"
	assert_bpf_observer_completed
	assert_bpf_observer_borrowed
	assert_bpf_observer_reference false
	bpf_observer_start owned_reference_clear "${bpf_observer_reference_source}"
	assert_bpf_observer_completed
	assert_bpf_observer_created map
done

bpf_observer_reference_source=$(bpf_create_pin_directory) || fatal "cannot allocate program binding source"
bpf_observer_pin_dirs+=("${bpf_observer_reference_source}")
"${BPF_OBSERVER_DIR}/workload" reference_source "${bpf_observer_reference_source}"
"${BPF_OBSERVER_DIR}/workload" prog "${bpf_observer_reference_source}"
bpf_observer_start borrowed_program_bind "${bpf_observer_reference_source}"
assert_bpf_observer_rejected "cannot track references added to a borrowed BPF object"

for bpf_observer_mode in borrowed_rename borrowed_directory_rename; do
	bpf_observer_start "${bpf_observer_mode}" "${bpf_observer_borrowed_source}/map"
	assert_bpf_observer_completed
	assert_bpf_observer_borrowed
	bpf_observer_renamed_pin=renamed
	if [[ "${bpf_observer_mode}" == borrowed_directory_rename ]]; then
		bpf_observer_renamed_pin=moved/borrowed
	fi
	assert_bpf_observer_pinned map "${bpf_observer_renamed_pin}" borrowed
	assert_bpf_observer_pin_remaining 1
	# Foreign pin changes must neither hide our reference nor create a candidate.
	mv "${bpf_observer_borrowed_source}/map" "${bpf_observer_borrowed_source}/foreign"
	assert_bpf_observer_pin_remaining 1
	rm "${bpf_observer_pin_dir}/${bpf_observer_renamed_pin}"
	assert_bpf_observer_pin_remaining 0
	mv "${bpf_observer_borrowed_source}/foreign" "${bpf_observer_borrowed_source}/map"
done

# The source retains the socket outside the observation tree, even after the
# observed process closes every FD. Existing external references are not ours.
"${BPF_OBSERVER_DIR}/socket-workload" serve "${BPF_OBSERVER_DIR}/socket" \
	"${BPF_OBSERVER_DIR}/socket-ready.json" > "${BPF_OBSERVER_DIR}/socket-server.log" 2>&1 &
bpf_observer_socket_server_pid=$!
wait_until 5 0.05 jq -e '.socket_program_id > 0 and .perf_program_id > 0' \
	"${BPF_OBSERVER_DIR}/socket-ready.json" || fatal "external socket source did not become ready"
bpf_observer_socket_program=$(jq -er .socket_program_id "${BPF_OBSERVER_DIR}/socket-ready.json")
bpf_observer_perf_program=$(jq -er .perf_program_id "${BPF_OBSERVER_DIR}/socket-ready.json")

bpf_observer_start_socket plain
assert_bpf_observer_completed
assert_bpf_observer_socket_attached false
for bpf_observer_mode in borrowed_attach borrowed_attach_highbits borrowed_reuseport; do
	bpf_observer_start_socket "${bpf_observer_mode}" "${bpf_observer_socket_program}"
	assert_bpf_observer_rejected "cannot track attachment of borrowed BPF program"
	assert_bpf_observer_socket_attached false
done
for bpf_observer_mode in borrowed_perf borrowed_perf_highbits; do
	bpf_observer_start_socket "${bpf_observer_mode}" "${bpf_observer_perf_program}"
	assert_bpf_observer_rejected "cannot track attachment of borrowed BPF program"
done
bpf_observer_start_socket owned_perf
assert_bpf_observer_completed
assert_bpf_observer_created prog
bpf_observer_start_socket borrowed_export "${bpf_observer_socket_program}"
assert_bpf_observer_rejected "SCM_RIGHTS descriptor transfer is unsupported"
bpf_observer_start_socket borrowed_test_run "${bpf_observer_socket_program}"
assert_bpf_observer_rejected "test-run may execute unobserved kernel side effects"
bpf_observer_start_socket owned_test_run
assert_bpf_observer_completed
assert_bpf_observer_created prog
# These two invalid device targets exercise pre-execution ioctl selection without
# a /dev/net/tun dependency; they do not claim real TUN/TAP attachment coverage.
for bpf_observer_mode in borrowed_tun_steering borrowed_tun_filter; do
	bpf_observer_start_socket "${bpf_observer_mode}" "${bpf_observer_socket_program}"
	assert_bpf_observer_rejected "cannot track attachment of borrowed BPF program"
done
bpf_observer_start_socket classic_attach
assert_bpf_observer_rejected "opaque classic BPF or firewall attachment is unsupported"
assert_bpf_observer_socket_attached false
bpf_observer_start_socket classic_tun
assert_bpf_observer_rejected "opaque classic BPF attachment is unsupported"
"${BPF_OBSERVER_DIR}/socket-workload" borrowed_attach "${BPF_OBSERVER_DIR}/socket" "${bpf_observer_socket_program}"
bpf_observer_start_socket borrowed_query "${bpf_observer_socket_program}"
assert_bpf_observer_completed
assert_bpf_observer_borrowed
assert_bpf_observer_socket_attached true
bpf_observer_start_socket detach
assert_bpf_observer_completed
assert_bpf_observer_socket_attached false
bpf_observer_start_socket owned_attach
assert_bpf_observer_owned_socket true
bpf_observer_start_socket owned_detach
assert_bpf_observer_owned_socket false

# Queries keep working, but network configuration cannot acquire references via
# tc/XDP or firewall APIs outside the observer's tracer-only capability scope.
bpf_observer_start_socket capability
assert_bpf_observer_completed
assert_bpf_observer_network_capability
for bpf_observer_mode in netlink_query netlink_query_msg netlink_query_mmsg; do
	bpf_observer_start_socket "${bpf_observer_mode}"
	assert_bpf_observer_completed
	assert_bpf_observer_network_boundary 0
done
for bpf_observer_mode in netlink_config netlink_config_msg netlink_config_mmsg; do
	bpf_observer_start_socket "${bpf_observer_mode}"
	assert_bpf_observer_completed
	assert_bpf_observer_network_boundary 1
done
log_info "socket/perf attachment guards and the network capability boundary passed"

bpf_observer_start hardlink "${bpf_observer_borrowed_source}/map"
assert_bpf_observer_rejected
bpf_observer_start mount_namespace
assert_bpf_observer_rejected
bpf_observer_start user_namespace
assert_bpf_observer_rejected "syscall would bypass BPF observation"

bpf_observer_start unsupported
assert_bpf_observer_rejected
log_info "BPF observer recorded short-lived, reparented and shutdown resources; incomplete coverage failed"
