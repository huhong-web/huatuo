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

# Verify that the normal daemon exposes its resolved build identity through HTTP.

set -euo pipefail

source "${ROOT_DIR}/integration/lib.sh"
source "${ROOT_DIR}/integration/config.sh"

require_commands curl jq ss

readonly BUILD_INFO_REGION="build-info-test"
readonly CURL_TIMEOUT=(--connect-timeout 2 --max-time 3)
BUILD_INFO_PORT=$(allocate_available_port) \
	|| fatal "failed to allocate a build-info HTTP port"
readonly BUILD_INFO_PORT
HUATUO_BAMAI_ADDR="http://127.0.0.1:${BUILD_INFO_PORT}"
HUATUO_BAMAI_METRICS_API="${HUATUO_BAMAI_ADDR}/metrics"
export HUATUO_BAMAI_ADDR HUATUO_BAMAI_METRICS_API

cleanup() {
	huatuo_bamai_stop
}
trap cleanup EXIT

assert_build_info() {
	local endpoint response_file error_file status curl_status
	for endpoint in version metrics; do
		response_file="${HUATUO_BAMAI_TEST_TMPDIR}/build-info-${endpoint}.body"
		error_file="${HUATUO_BAMAI_TEST_TMPDIR}/build-info-${endpoint}.curl-error"
		curl_status=0
		status=$(curl -sS "${CURL_TIMEOUT[@]}" \
			-D "${response_file}.headers" -o "${response_file}" -w '%{http_code}' \
			"${HUATUO_BAMAI_ADDR}/${endpoint}" 2> "${error_file}") || curl_status=$?
		log_info "GET /${endpoint}: curl exit=${curl_status}, HTTP status=${status}"
		if [[ ${endpoint} == version || ${curl_status} -ne 0 || ${status} != 200 ]]; then
			report_http_response "GET /${endpoint}" "${response_file}" "${error_file}"
		fi
		[[ ${curl_status} -eq 0 ]] || fatal "GET /${endpoint}: curl exited ${curl_status}"
		assert_eq "${status}" 200 "GET /${endpoint} status" \
			|| fatal "GET /${endpoint}: expected HTTP 200, got ${status}"
	done

	local metrics_file="${HUATUO_BAMAI_TEST_TMPDIR}/build-info-metrics.body"
	local version_file="${HUATUO_BAMAI_TEST_TMPDIR}/build-info-version.body"
	grep -qiE '^Content-Type:[[:space:]]*text/plain([;[:space:]]|$)' "${metrics_file}.headers" \
		|| fatal "GET /metrics: expected text/plain, headers: $(< "${metrics_file}.headers")"
	grep -Fxq '# TYPE huatuo_bamai_build_info gauge' "${metrics_file}" \
		|| fatal "expected huatuo_bamai_build_info to be a Gauge"

	local count sample field value
	count=$(grep -cE '^huatuo_bamai_build_info(\{|[[:space:]])' "${metrics_file}" || true)
	assert_eq "${count}" 1 "build-info sample count" \
		|| fatal "expected one build-info sample, got ${count}"
	sample=$(grep '^huatuo_bamai_build_info{' "${metrics_file}")
	log_info "build-info sample: ${sample}"
	assert_eq "${sample##* }" 1 "build-info gauge value" \
		|| fatal "expected build-info value 1, got ${sample}"
	for field in name version git_commit git_tree_state build_time go_version compiler platform; do
		value=$(jq -er --arg field "${field}" \
			'.data[$field] | select(type == "string" and length > 0) | @json' "${version_file}") \
			|| fatal "GET /version: missing nonempty ${field}"
		[[ ${sample} == *"${field}=${value}"* ]] \
			|| fatal "build-info ${field}: expected ${value}, got ${sample}"
	done
	value=$(jq -cn --arg host "$(uname -n)" '$host')
	[[ ${sample} == *"host=${value}"* && ${sample} == *"region=\"${BUILD_INFO_REGION}\""* ]] \
		|| fatal "build-info: expected host=${value}, region=${BUILD_INFO_REGION}, got ${sample}"
}

integration_huatuo_bamai_start write_build_info_config \
	--region "${BUILD_INFO_REGION}" --procfs-prefix "${HUATUO_BAMAI_TEST_FIXTURES}" \
	--disable-storage --disable-kubelet --log-debug

assert_build_info
assert_log_has_no_failure "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo.log" huatuo-bamai
log_info "build-info matches /version and preserves host/region labels"
