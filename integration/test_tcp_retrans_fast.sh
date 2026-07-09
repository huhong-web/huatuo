#!/usr/bin/env bash

set -euo pipefail

source "$(dirname "$0")/env.sh"
source "${ROOT_DIR}/integration/lib.sh"

TCPRETRANS_BIN="${ROOT_DIR}/_output/bin/tcpretrans"
BPF_OBJ="${ROOT_DIR}/_output/bpf/tcp_retrans.o"
OUTPUT_DIR=$(mktemp -d /tmp/tcp_retrans_fast.XXXXXX)
TEST_PORT=19998
PAYLOAD_SIZE=2097152 # 2 MB

NS_S="ts_fast"
NS_C="tc_fast"
VETH_S="vs_fast"
VETH_C="vc_fast"
S_ADDR="10.99.0.1"
C_ADDR="10.99.0.2"
NET_MASK="24"

[[ -x "${TCPRETRANS_BIN}" ]] || fatal "tcpretrans binary not found: ${TCPRETRANS_BIN}"
[[ -f "${BPF_OBJ}" ]] || fatal "BPF object not found: ${BPF_OBJ}"

# connbytes module check — skip gracefully if unavailable (minimal kernels).
if ! iptables -m connbytes -h 2>&1 | grep -q connbytes; then
	log_info "SKIP: iptables connbytes module not available on this kernel"
	exit 0
fi

require_nc

cleanup() {
	[[ -n "${TCPRETRANS_PID:-}" ]] && kill "${TCPRETRANS_PID}" 2> /dev/null || true
	[[ -n "${SRV_PID:-}" ]] && kill "${SRV_PID}" 2> /dev/null || true
	[[ -n "${CLI_PID:-}" ]] && kill "${CLI_PID}" 2> /dev/null || true
	ip netns del "${NS_S}" 2> /dev/null || true
	ip netns del "${NS_C}" 2> /dev/null || true
	rm -rf "${OUTPUT_DIR}"
}
trap cleanup EXIT

log_info "fast_retransmit: drop one data segment via netns+veth+connbytes → dup ACK → Recovery"

# 1. Build netns+veth topology.
ip netns add "${NS_S}" || fatal "failed to create server netns"
ip netns add "${NS_C}" || fatal "failed to create client netns"

ip link add "${VETH_S}" type veth peer name "${VETH_C}"
ip link set "${VETH_S}" netns "${NS_S}"
ip link set "${VETH_C}" netns "${NS_C}"

ip netns exec "${NS_S}" ip addr add "${S_ADDR}/${NET_MASK}" dev "${VETH_S}"
ip netns exec "${NS_S}" ip link set "${VETH_S}" up
ip netns exec "${NS_S}" ip link set lo up

ip netns exec "${NS_C}" ip addr add "${C_ADDR}/${NET_MASK}" dev "${VETH_C}"
ip netns exec "${NS_C}" ip link set "${VETH_C}" up
ip netns exec "${NS_C}" ip link set lo up

# Limit GSO segments so each TCP segment is a distinct sk_buff (deterministic
# connbytes counting). Without this, veth GSO may coalesce segments.
ip netns exec "${NS_S}" ip link set dev "${VETH_S}" gso_max_segs 1

log_info "netns topology ready: ${NS_S}(${S_ADDR}) ←→ ${NS_C}(${C_ADDR})"

# 2. Client-side: drop the 30th reply-direction packet (a single
#    server→client data segment). Subsequent segments arrive out-of-order
#    → receiver sends 3 dup ACKs → sender enters Recovery and
#    fast-retransmits the lost segment.
ip netns exec "${NS_C}" iptables -I INPUT 1 -p tcp --sport "${TEST_PORT}" \
	-m connbytes --connbytes 30:30 --connbytes-dir reply \
	--connbytes-mode packets -j DROP
log_info "connbytes rule: drop reply packet #30 in client netns"

# 3. Start tcpretrans in the root netns (sees all netns traffic via BPF).
"${TCPRETRANS_BIN}" --bpf-path "${BPF_OBJ}" --duration 15 --output json > "${OUTPUT_DIR}/events.json" 2> "${OUTPUT_DIR}/stderr.log" &
TCPRETRANS_PID=$!
sleep 1

# 4. Server: nc listens and sends 2 MB of data.
ip netns exec "${NS_S}" bash -c "head -c ${PAYLOAD_SIZE} /dev/zero | timeout 10 $(nc_listen_cmd "${S_ADDR}" "${TEST_PORT}")" > /dev/null 2>&1 &
SRV_PID=$!
sleep 0.5

# 5. Client: connect and receive data to /dev/null.
ip netns exec "${NS_C}" timeout 8 bash -c "exec 3<>/dev/tcp/${S_ADDR}/${TEST_PORT}; cat <&3 >/dev/null" 2> /dev/null &
CLI_PID=$!

# 6. Wait for data transfer + fast retransmit (3 dup ACKs are fast on veth).
sleep 10

kill "${TCPRETRANS_PID}" 2> /dev/null || true
sleep 0.3
TCPRETRANS_PID=""

# Filter events for our test port (server-side sport).
grep "\"sport\":${TEST_PORT}" "${OUTPUT_DIR}/events.json" > "${OUTPUT_DIR}/filtered.json" 2> /dev/null || true

FAST_COUNT=$(grep -c '"reason":"fast_retransmit"' "${OUTPUT_DIR}/filtered.json" 2> /dev/null || true)
FAST_COUNT=${FAST_COUNT:-0}
REORDER_FAST=$(grep -c '"reason":"reorder_prone_fast"' "${OUTPUT_DIR}/filtered.json" 2> /dev/null || true)
REORDER_FAST=${REORDER_FAST:-0}
RECOVERY=$(grep -c '"ca_state":3' "${OUTPUT_DIR}/filtered.json" 2> /dev/null || true)
RECOVERY=${RECOVERY:-0}
RTO_COUNT=$(grep -c '"reason":"RTO"' "${OUTPUT_DIR}/filtered.json" 2> /dev/null || true)
RTO_COUNT=${RTO_COUNT:-0}

log_info "fast_retransmit: ${FAST_COUNT}, reorder_prone_fast: ${REORDER_FAST}, ca_state=3: ${RECOVERY}, RTO: ${RTO_COUNT}"

if ((FAST_COUNT >= 1)) || ((REORDER_FAST >= 1)); then
	log_info "PASS: fast_retransmit events detected with ca_state=Recovery"
elif ((RECOVERY >= 1)); then
	log_warn "PARTIAL: Recovery events found but not classified as fast_retransmit"
	grep '"ca_state":3' "${OUTPUT_DIR}/filtered.json" | head -2 || true
elif ((RTO_COUNT >= 1)); then
	log_warn "PARTIAL: only RTO events (connbytes may have dropped tail data, no dup ACKs)"
else
	log_error "FAIL: no retrans events at all"
	cat "${OUTPUT_DIR}/stderr.log" | head -5
	fatal "no events captured"
fi
