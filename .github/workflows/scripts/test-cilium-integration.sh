#!/usr/bin/env bash
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

# Fork-only experiment: preserve each existing runner's result and diagnostics.
set -euo pipefail

assert_test_cilium_report_identity() {
	local report=$1 script=$2
	jq -e --arg name "$script" '
		.schema_version == 1 and .suite == "integration" and .runs_per_test == 1 and
		.execution_counts.total == 1 and (.test_executions | length) == 1 and
		.test_executions[0].test_name == $name and .test_executions[0].run_index == 1
	' "$report" > /dev/null
}

assert_test_cilium_report_passed() {
	local report=$1 report_dir=${1%/*} log
	jq -e '
		.test_executions[0] as $test |
		.status == "completed" and .exit_code == 0 and
		.execution_counts == {total:1, passed:1, failed:0, skipped:0} and
		$test.result == "passed" and $test.exit_code == 0 and
		(all([$test.started_at, $test.finished_at][]; type == "string" and length > 0)) and
		($test.duration_seconds | type == "number" and . >= 0) and
		($test.logs | type == "object") and
		(all([$test.logs.stdout, $test.logs.stderr][];
			type == "string" and length > 0 and (startswith("/") | not) and
			(split("/") | all(. != ".."))))
	' "$report" > /dev/null || return 1
	while IFS= read -r log; do
		[[ -f "$report_dir/$log" && ! -L "$report_dir/$log" ]] || return 1
	done < <(jq -r '.test_executions[0].logs | .stdout, .stderr' "$report")
}

collect_test_cilium_diagnostics() {
	local report_dir=$1 evidence_dir=$2
	mkdir -p "$evidence_dir/runner" || return 1
	# find does not follow namespace fixture symlinks into the host filesystem.
	(cd "$report_dir" && find . -type f \
		\( -name '*.log' -o -name '*.json' -o -name '*.jsonl' -o -name '*.conf' \
		-o -name '*.err' -o -name '*.body' -o -name '*.status' -o -name '*.stdout' \
		-o -name '*.stderr' -o -name '*.out' -o -name '*.txt' -o -name '*.folded' \
		-o -name 'timeout-namespace' -o -path '*/events/*' \) \
		-print0 | tar --null -T - -cf -) | (cd "$evidence_dir/runner" && tar -xf -)
}

run_test_cilium_script() {
	local script=$1 output=$2
	local evidence_dir="$output/${script%.sh}" code=0 result=ERROR test_result=ERROR
	local evidence_status=missing reason='runner summary unavailable' summary report='' log
	local started=$SECONDS elapsed report_saved=false
	mkdir -p "$evidence_dir"
	# A stuck external dependency must not consume the budget for every later case.
	LC_ALL=C timeout --verbose --signal=TERM --kill-after=30s 15m \
		bash integration/run.sh -j 1 "$script" > "$evidence_dir/runner.log" 2>&1 || code=$?
	elapsed=$((SECONDS - started))
	if [[ "$script" == test_basic_runner.sh ]]; then
		# Preserve namespace liveness after the timeout fixture has returned.
		{
			date -u
			lsns -n -t pid -o NS,NPROCS,PID,COMMAND
			ps -eo pid,ppid,stat,comm
		} \
			> "$evidence_dir/pid-namespaces-after.txt" 2>&1 || true
	fi
	cat "$evidence_dir/runner.log"
	if summary=$(
		python3 - "$evidence_dir/runner.log" << 'SUMMARY_PYTHON'
import json
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text()
decoder = json.JSONDecoder()
summaries = []
for match in re.finditer(r"(?m)^\{", text):
    try:
        value, _ = decoder.raw_decode(text[match.start():])
    except json.JSONDecodeError:
        continue
    if isinstance(value, dict) and isinstance(value.get("results_path"), str):
        summaries.append(value)
if len(summaries) != 1:
    raise SystemExit("expected one runner summary with a report path")
print(json.dumps(summaries[0]))
SUMMARY_PYTHON
	); then
		printf '%s\n' "$summary" > "$evidence_dir/summary.json"
		report=$(jq -r .results_path <<< "$summary")
	fi
	if [[ "$report" == /tmp/huatuo-test.*/test_run_results.json && -f "$report" ]]; then
		if cp "$report" "$evidence_dir/result.json"; then report_saved=true; fi
		reason='runner report identity or schema mismatch'
		if assert_test_cilium_report_identity "$report" "$script"; then
			reason=$(jq -r '.test_executions[0].reason // .reason // ""' "$report")
			test_result=$(jq -r '.test_executions[0].result // "ERROR"' "$report")
			case "$test_result" in
			passed)
				test_result=PASS
				if [[ "$code" != 0 ]] || ! assert_test_cilium_report_passed "$report"; then
					test_result=ERROR
					reason='passed result has inconsistent exit, timing, counts or logs'
				fi
				;;
			failed) test_result=FAIL ;;
			skipped) test_result=SKIP ;;
			*)
				test_result=ERROR
				reason='runner report has no terminal test result'
				;;
			esac
		fi
		evidence_status=incomplete
		if collect_test_cilium_diagnostics "${report%/*}" "$evidence_dir" && [[ "$report_saved" == true ]]; then
			evidence_status=complete
			if [[ "$test_result" == PASS ]]; then
				while IFS= read -r log; do
					[[ -f "$evidence_dir/runner/$log" ]] || evidence_status=incomplete
				done < <(jq -r '.test_executions[0].logs | .stdout, .stderr' "$report")
			fi
		fi
	fi
	if [[ "$code" == 124 ]] || { [[ "$code" == 137 ]] && grep -Eq '^timeout: sending signal (TERM|KILL) to command ' "$evidence_dir/runner.log"; }; then
		test_result=TIMEOUT
		reason="15m timeout triggered after ${elapsed}s (runner exit $code)"
	elif [[ "$code" == 137 ]]; then
		test_result=KILLED
		reason="runner killed after ${elapsed}s; SIGKILL/OOM cause unverified"
	fi
	result=$test_result
	if [[ "$evidence_status" != complete ]]; then
		result=ERROR
		reason="${reason:+$reason; }diagnostic evidence $evidence_status"
	fi
	jq -cn --arg script "$script" --arg result "$result" --arg test_result "$test_result" \
		--arg evidence_status "$evidence_status" --arg reason "$reason" --argjson code "$code" --argjson elapsed "$elapsed" \
		'{script:$script, result:$result, test_result:$test_result, evidence_status:$evidence_status,
		  reason:$reason, runner_exit_code:$code, runner_elapsed_seconds:$elapsed}' | tee -a "$output/results.jsonl"
}

run_test_cilium_integration() {
	local output=_output/test-cilium-results script
	local -a scripts=(
		test_basic_runner.sh
		test_iocost.sh
	)
	mkdir -p "$output"
	printf '%s\n' "${scripts[@]}" > "$output/selected-scripts.txt"
	jq -Rn '[inputs]' < "$output/selected-scripts.txt" > "$output/selected-scripts.json"
	: > "$output/results.jsonl"
	for script in "${scripts[@]}"; do
		run_test_cilium_script "$script" "$output"
	done
	jq -se --slurpfile selected "$output/selected-scripts.json" '
		([.[].script] | sort) == ($selected[0] | sort) and
		([.[].script] | unique | length) == ($selected[0] | length) and
		all(.[]; .result == "PASS" and .evidence_status == "complete")
	' "$output/results.jsonl"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then run_test_cilium_integration; fi
