#!/usr/bin/env bash

set -euo pipefail

source "$(dirname "$0")/env.sh"
source "${ROOT_DIR}/integration/lib.sh"

TCPRETRANS_BIN="${ROOT_DIR}/_output/bin/tcpretrans"
BPF_OBJ="${ROOT_DIR}/_output/bpf/tcp_retrans.o"
OUTPUT_DIR=$(mktemp -d /tmp/tcp_retrans_test.XXXXXX)

[[ -x "${TCPRETRANS_BIN}" ]] || fatal "tcpretrans binary not found: ${TCPRETRANS_BIN}"
[[ -f "${BPF_OBJ}" ]] || fatal "BPF object not found: ${BPF_OBJ}"

cleanup() {
	[[ -n "${TCPRETRANS_PID:-}" ]] && kill "${TCPRETRANS_PID}" 2> /dev/null || true
	sleep 0.2
	[[ -n "${TCPRETRANS_PID:-}" ]] && kill -9 "${TCPRETRANS_PID}" 2> /dev/null || true
	rm -rf "${OUTPUT_DIR}"
}
trap cleanup EXIT

log_info "S0/EXP1: SYN retrans (connect/RTO) via black-hole IP"

"${TCPRETRANS_BIN}" --bpf-path "${BPF_OBJ}" --duration 6 --output json > "${OUTPUT_DIR}/events.json" 2> "${OUTPUT_DIR}/stderr.log" &
TCPRETRANS_PID=$!
sleep 1

timeout 2 bash -c "exec 3<>/dev/tcp/192.0.2.1/19991" 2> /dev/null || true
sleep 4

kill "${TCPRETRANS_PID}" 2> /dev/null || true
sleep 0.3
TCPRETRANS_PID=""

SYN_COUNT=$(grep -c '"phase":"connect"' "${OUTPUT_DIR}/events.json" 2> /dev/null || true)
SYN_COUNT=${SYN_COUNT:-0}
RTO_COUNT=$(grep -c '"reason":"RTO"' "${OUTPUT_DIR}/events.json" 2> /dev/null || true)
RTO_COUNT=${RTO_COUNT:-0}
SKB_COUNT=$(grep -c '"event_type":"tcp_retransmit_skb"' "${OUTPUT_DIR}/events.json" 2> /dev/null || true)
SKB_COUNT=${SKB_COUNT:-0}

log_info "SYN connect events: ${SYN_COUNT}, RTO events: ${RTO_COUNT}, skb events: ${SKB_COUNT}"

if ((SYN_COUNT >= 1)) && ((RTO_COUNT >= 1)) && ((SKB_COUNT >= 1)); then
	log_info "EXP1 PASS: SYN retrans events detected with phase=connect, reason=RTO"
else
	log_error "EXP1 FAIL: expected >=1 connect/RTO/skb events"
	cat "${OUTPUT_DIR}/events.json" 2> /dev/null || true
	cat "${OUTPUT_DIR}/stderr.log" 2> /dev/null || true
	fatal "EXP1 failed"
fi
