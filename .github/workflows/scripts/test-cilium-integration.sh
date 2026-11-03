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
		-o -name '*.stderr' -o -name '*.out' -o -name '*.txt' -o -name '*.folded' \) \
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
	cat "$evidence_dir/runner.log"
	if summary=$(sed -n '/^{/,/^}/p' "$evidence_dir/runner.log" | jq -se '
		if length == 1 and (.[0].report | type == "string") then .[0]
		else error("expected one runner summary with a report path") end
	'); then
		printf '%s\n' "$summary" > "$evidence_dir/summary.json"
		report=$(jq -r .report <<< "$summary")
	fi
	if [[ "$report" == /tmp/huatuo-test.*/result.json && -f "$report" ]]; then
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
		test_apiserver_continuous_profiling_api.sh
		test_apiserver_continuous_profiling_concurrent_jobs.sh
		test_apiserver_continuous_profiling_control.sh
		test_apiserver_job_recovery.sh
		test_apiserver_profile_disabled.sh
		test_apiserver_profile_filters.sh
		test_apiserver_profiling.sh
		test_apiserver_readiness_metrics.sh
		test_autotracing_cpu_profiler.sh
		test_autotracing_cpusys.sh
		test_autotracing_iotracing.sh
		test_autotracing_irqtracing.sh
		test_autotracing_memburst.sh
		test_autotracing_memory_threshold_snapshot_config.sh
		test_basic_bpf_debug_macro.sh
		test_basic_cgroup_css.sh
		test_basic_cgroup_helpers.sh
		test_basic_cgroup_subsys_id.sh
		test_basic_dockerfile_check.sh
		test_basic_profiler_exit_deadline.sh
		test_basic_profiler_sample_phases.sh
		test_basic_runner.sh
		test_basic_startup_log.sh
		test_basic_storage_elasticsearch_config.sh
		test_basic_storage_elasticsearch_values.sh
		test_basic_storage_localfile_rotation.sh
		test_basic_storage_opensearch_elasticsearch.sh
		test_basic_test_helpers.sh
		test_dropwatch_device_filter.sh
		test_dropwatch_devlink.sh
		test_dropwatch_icmpv6.sh
		test_dropwatch_ipv4_options.sh
		test_dropwatch_netdevsim.sh
		test_dropwatch_ratelimit.sh
		test_dropwatch_reason.sh
		test_events_io_health.sh
		test_events_memory_oom_kill.sh
		test_events_net_rx_latency.sh
		test_events_netdev_bonding_lacp.sh
		test_events_netdev_events.sh
		test_events_sched_tick.sh
		test_events_sched_tick_irqoff.sh
		test_events_tcp_retransmit.sh
		test_io_kernel.sh
		test_iocost.sh
		test_iotracing_ext4.sh
		test_iotracing_xfs.sh
		test_irqtracing_ratelimit.sh
		test_metrics.sh
		test_metrics_exclude_filter.sh
		test_metrics_include_filter.sh
		test_metrics_iotracing.sh
		test_metrics_memory_container.sh
		test_metrics_memory_host.sh
		test_node_build_info.sh
		test_node_cloud_events_api.sh
		test_node_config_api.sh
		test_node_runtime_limits.sh
		test_profiler_benchmark_self_cpu.sh
		test_profiler_config.sh
		test_profiler_finalization.sh
		test_profiler_flamegraph.sh
		test_profiler_java_cpu_container.sh
		test_profiler_java_cpu_multi_pid.sh
		test_profiler_java_exceptions.sh
		test_profiler_java_memory_usage_alloc.sh
		test_profiler_native_cpu.sh
		test_profiler_native_cpu_container.sh
		test_profiler_native_cpu_cpp_symbols.sh
		test_profiler_native_cpu_cpuid.sh
		test_profiler_native_cpu_hardware_pmu.sh
		test_profiler_native_cpu_offcpu.sh
		test_profiler_native_cpu_rust_symbols.sh
		test_profiler_native_cpu_thread_group.sh
		test_profiler_native_memory_container.sh
		test_profiler_native_memory_physical_usage.sh
		test_profiler_native_memory_thread_group.sh
		test_profiler_native_memory_virtual_alloc.sh
		test_profiler_output_flags.sh
		test_profiler_python_cpu_multi_pid.sh
		test_profiler_python_exceptions.sh
		test_profiler_user_kernel_frames.sh
		test_sched_blame.sh
		test_tcp_retransmit_ratelimit.sh
		test_tcp_retransmit_syn.sh
		test_tcp_retransmit_synack.sh
		test_tcp_retransmit_tlp.sh
		test_tcpshark_output_cancellation_blocked.sh
		test_tcpshark_output_cancellation_healthy.sh
		test_tcpshark_output_cancellation_timeout.sh
		test_tcpshark_retransmit_dropwatch_correlation.sh
		test_tcpshark_retransmit_fast.sh
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
