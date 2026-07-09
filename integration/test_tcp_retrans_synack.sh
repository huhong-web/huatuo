#!/usr/bin/env bash

set -euo pipefail

source "$(dirname "$0")/env.sh"
source "${ROOT_DIR}/integration/lib.sh"

TCPRETRANS_BIN="${ROOT_DIR}/_output/bin/tcpretrans"
BPF_OBJ="${ROOT_DIR}/_output/bpf/tcp_retrans.o"
OUTPUT_DIR=$(mktemp -d /tmp/tcp_retrans_synack.XXXXXX)
TEST_PORT=19994

[[ -x "${TCPRETRANS_BIN}" ]] || fatal "tcpretrans binary not found: ${TCPRETRANS_BIN}"
[[ -f "${BPF_OBJ}" ]] || fatal "BPF object not found: ${BPF_OBJ}"
require_nc

cleanup() {
	[[ -n "${TCPRETRANS_PID:-}" ]] && kill "${TCPRETRANS_PID}" 2> /dev/null || true
	[[ -n "${NC_PID:-}" ]] && kill "${NC_PID}" 2> /dev/null || true
	sleep 0.2
	[[ -n "${TCPRETRANS_PID:-}" ]] && kill -9 "${TCPRETRANS_PID}" 2> /dev/null || true
	iptables -D OUTPUT -p tcp --dport "${TEST_PORT}" --tcp-flags SYN,ACK ACK -j DROP 2> /dev/null || true
	rm -rf "${OUTPUT_DIR}"
}
trap cleanup EXIT

log_info "SYNACK retrans: drop client's final ACK so server retransmits SYNACK via inet_rtx_synack"

# 1. nc holds a listening socket; the kernel completes the 3-way handshake.
timeout 8 $(nc_listen_cmd "127.0.0.1" "${TEST_PORT}") > /dev/null 2>&1 &
NC_PID=$!
sleep 0.5

# 2. Drop the client's pure ACK (handshake completion) to the server.
#    --tcp-flags SYN,ACK ACK = ACK set, SYN NOT set → matches pure ACK, not SYNACK.
#    The server never sees the final ACK → its retransmission timer fires
#    inet_rtx_synack → tcp_retransmit_synack tracepoint fires.
iptables -I OUTPUT 1 -p tcp --dport "${TEST_PORT}" --tcp-flags SYN,ACK ACK -j DROP
log_info "iptables: DROP pure ACK (dport=${TEST_PORT})"

# 3. Start tcpretrans.
"${TCPRETRANS_BIN}" --bpf-path "${BPF_OBJ}" --duration 8 --output json > "${OUTPUT_DIR}/events.json" 2> "${OUTPUT_DIR}/stderr.log" &
TCPRETRANS_PID=$!
sleep 1

# 4. Client connects: SYN → server, SYNACK → client, ACK → dropped.
timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/${TEST_PORT}" 2> /dev/null || true

# 5. Wait for SYNACK retransmissions (initial RTO ~1s, exponential backoff).
sleep 5

kill "${TCPRETRANS_PID}" 2> /dev/null || true
sleep 0.3
TCPRETRANS_PID=""

SYNACK_COUNT=$(grep -c '"event_type":"tcp_retransmit_synack"' "${OUTPUT_DIR}/events.json" 2> /dev/null || true)
SYNACK_COUNT=${SYNACK_COUNT:-0}

log_info "SYNACK events: ${SYNACK_COUNT}"

if ((SYNACK_COUNT >= 1)); then
	log_info "PASS: SYNACK retrans events detected"
else
	log_error "FAIL: expected >=1 synack events"
	cat "${OUTPUT_DIR}/events.json" 2> /dev/null || true
	cat "${OUTPUT_DIR}/stderr.log" 2> /dev/null || true
	fatal "synack test failed"
fi
