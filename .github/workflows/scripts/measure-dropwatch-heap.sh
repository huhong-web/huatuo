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

# Fork-only measurement harness: each round runs the existing integration case
# in a fresh process. Keep all rounds, including cold starts and failures.
set -euo pipefail
shopt -s nullglob

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)
cd "${root_dir}"
config=.github/workflows/scripts/vm-test/heap-measurement.json
jq -e '
  (.phase == "calibration" or .phase == "validation")
  and (.rounds | type == "number" and . == floor and . >= 1 and . <= 100)
  and (.heap_budget_mib | type == "number" and . == floor and . >= 0 and . <= 4096)
  and (if .phase == "calibration" then .heap_budget_mib == 0 else .heap_budget_mib > 0 end)
' "${config}" > /dev/null || {
	echo "invalid ${config}: use 1..100 rounds, budget 0 for calibration or 1..4096 MiB for validation" >&2
	exit 2
}
phase=$(jq -r .phase "${config}")
rounds=$(jq -r .rounds "${config}")
budget_mib=$(jq -r .heap_budget_mib "${config}")
export DROPWATCH_HEAP_LIMIT_BYTES=$((budget_mib * 1024 * 1024))

output_dir="${root_dir}/_output/dropwatch-heap"
mkdir "${output_dir}"
cp "${config}" "${output_dir}/config.json"
{
	date -u --iso-8601=seconds
	git rev-parse HEAD
	git status --short
	go version
	go version -m _output/bin/dropwatch
	sha256sum _output/bin/dropwatch _output/tools/pprof-tool _output/bpf/net_dropwatch.o
	uname -a
	cat /etc/os-release
	lscpu
	printf 'GOGC=%s GOMEMLIMIT=%s GOMAXPROCS=%s GODEBUG=%s\n' \
		"${GOGC:-unset}" "${GOMEMLIMIT:-unset}" "${GOMAXPROCS:-unset}" "${GODEBUG:-unset}"
	if [[ -r /sys/kernel/btf/vmlinux ]]; then
		wc -c /sys/kernel/btf/vmlinux
		sha256sum /sys/kernel/btf/vmlinux
	fi
	wc -l /proc/kallsyms
	cat /proc/modules
} > "${output_dir}/environment.txt"

for ((round = 1; round <= rounds; round++)); do
	printf -v round_dir '%s/round-%03d' "${output_dir}" "${round}"
	mkdir "${round_dir}"
	export INTEGRATION_ARTIFACTS_DIR="${round_dir}"
	status=0
	bash integration/run.sh test_dropwatch_ratelimit.sh > "${round_dir}/test.log" 2>&1 || status=$?
	resources=("${round_dir}"/workspace/dropwatch.*/resources.json)
	resource_json=null
	if ((${#resources[@]} == 1)) && jq -e '
      .heap_inuse_bytes | type == "number" and . >= 0
    ' "${resources[0]}" > /dev/null; then
		resource_json=$(< "${resources[0]}")
	fi
	jq -n --argjson round "${round}" --argjson exit_code "${status}" \
		--argjson resources "${resource_json}" \
		'{round: $round, exit_code: $exit_code, resources: $resources}' > "${round_dir}/result.json"
	jq -c . "${round_dir}/result.json"
	if [[ ${status} -ne 0 || ${resource_json} == null ]]; then
		tail -n 160 "${round_dir}/test.log" >&2
	fi
done

jq -s --arg phase "${phase}" --argjson budget_mib "${budget_mib}" '
  def stats:
    sort | length as $n
    | if $n == 0 then null else
        {count: $n, min: .[0], max: .[-1], mean: (add / $n),
         median: (if $n % 2 == 0 then (.[($n / 2 - 1)] + .[$n / 2]) / 2
                  else .[($n / 2 | floor)] end),
         p95: .[($n * 0.95 | ceil) - 1]}
      end;
  {phase: $phase, budget_mib: $budget_mib,
   complete: all(.exit_code == 0 and .resources != null),
   heap_bytes: ([.[].resources.heap_inuse_bytes | numbers] | stats), rounds: .}
' "${output_dir}"/round-*/result.json > "${output_dir}/summary.json"
jq 'del(.rounds)' "${output_dir}/summary.json"

# Analyze only after all load windows have finished; retain the original profiles.
worst_round=$(jq -r '[.rounds[] | select(.resources != null)] | max_by(.resources.heap_inuse_bytes) | .round // empty' \
	"${output_dir}/summary.json")
if [[ -n "${worst_round}" ]]; then
	printf -v worst_dir '%s/round-%03d' "${output_dir}" "${worst_round}"
	heap_profiles=("${worst_dir}"/workspace/dropwatch.*/pprof/heap.pprof)
	((${#heap_profiles[@]} == 1))
	go tool pprof -top -sample_index=inuse_space _output/bin/dropwatch "${heap_profiles[0]}" \
		> "${output_dir}/largest-heap.txt"
fi
jq -e '.complete and .heap_bytes.count == (.rounds | length)' "${output_dir}/summary.json" > /dev/null
