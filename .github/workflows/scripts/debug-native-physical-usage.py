#!/usr/bin/env python3
#
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
#

"""Fork-only observations; no production or integration source is modified."""
import concurrent.futures
import json
from pathlib import Path
import re
import shutil
import signal
import subprocess
import threading
import time

EVIDENCE = Path("/root/native-physical-usage-debug")
PINS = Path("/sys/fs/bpf/huatuo_native_diagnostic")
SCENARIO = "test_profiler_native_memory_physical_usage.sh"
PINS.mkdir(exist_ok=False)
stop_sampling = threading.Event()
reproduced = threading.Event()
pinned = {}
results = []
finalized = set()
(EVIDENCE / "clocks.json").write_text(json.dumps({"realtime_ns": time.time_ns(), "monotonic_ns": time.monotonic_ns()}))


def bpftool(*args):
    result = subprocess.run(["bpftool", "-j", *args], capture_output=True, text=True, timeout=8)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return json.loads(result.stdout)


def sample_maps():
    # Pin only diagnostic candidate maps so their final state survives detach.
    with (EVIDENCE / "map-timeline.jsonl").open("w") as output:
        while not stop_sampling.is_set():
            try:
                programs = bpftool("prog", "show")
                maps = {item["id"]: item for item in bpftool("map", "show")}
                for program in programs:
                    if program.get("name") != "trace_page_free":
                        continue
                    for map_id in program.get("map_ids", []):
                        info = maps.get(map_id, {})
                        if info.get("name") not in ("page_to_stackid", "profiler_state_"):
                            continue
                        if map_id not in pinned:
                            path = PINS / str(map_id)
                            subprocess.run(["bpftool", "map", "pin", "id", str(map_id), str(path)], check=True, capture_output=True, timeout=8)
                            pinned[map_id] = {"map": info, "program": program, "observed_ns": time.time_ns()}
                active_programs = {program["id"] for program in programs}
                for map_id, metadata in pinned.items():
                    if map_id in finalized or metadata["program"]["id"] in active_programs:
                        continue
                    contents = bpftool("map", "dump", "id", str(map_id))
                    (EVIDENCE / f"final-map-{map_id}.json").write_text(json.dumps(contents, indent=2))
                    (PINS / str(map_id)).unlink()
                    finalized.add(map_id)
                states = {}
                for map_id, metadata in pinned.items():
                    if map_id not in finalized and metadata["map"]["name"] == "profiler_state_":
                        states[str(map_id)] = bpftool("map", "dump", "id", str(map_id))
                output.write(json.dumps({"time_ns": time.time_ns(), "programs": programs,
                                         "states": states, "links": bpftool("link", "show")}) + "\n")
                output.flush()
            except Exception as error:
                output.write(json.dumps({"time_ns": time.time_ns(), "error": str(error)}) + "\n")
                output.flush()
            stop_sampling.wait(0.5)


def run_case(phase, number):
    if reproduced.is_set():
        return None
    name = f"{phase}-{number}"
    started = time.time_ns()
    output_path = EVIDENCE / f"{name}.log"
    command = ["timeout", "90", "strace", "-ff", "-ttt", "-e",
               "trace=munmap,kill,wait4,exit,exit_group", "-o", str(EVIDENCE / f"strace-{name}"),
               "bash", "integration/run.sh", SCENARIO]
    with output_path.open("w") as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
    text = output_path.read_text()
    passed = result.returncode == 0 and "summary: total=1 passed=1 skipped=0 failed=0" in text
    record = {"phase": phase, "round": number, "exit_code": result.returncode,
              "passed": passed, "start_ns": started, "end_ns": time.time_ns()}
    print(json.dumps(record), flush=True)
    if not passed:
        reproduced.set()
        for path in re.findall(r"artifacts preserved at (/tmp/[^\s]+)", text):
            if Path(path).is_dir():
                shutil.copytree(path, EVIDENCE / f"artifacts-{name}", dirs_exist_ok=True)
        print(text[-18000:], flush=True)
    return record


observer_source = EVIDENCE / "pages.bt"
observer_source.write_text(r'''BEGIN { printf("OBSERVER_READY\n"); }
kprobe:folio_add_new_anon_rmap /comm == "physical_usage_"/ {
    @owner[arg0] = pid;
    @alloc[pid] = count();
    @last_alloc[pid] = nsecs;
}
kprobe:folio_remove_rmap_ptes /@owner[arg0]/ {
    $owner = @owner[arg0];
    @freed[$owner] = sum(arg2);
    @last_free[$owner] = nsecs;
    if (pid != $owner) { @other_context[$owner,pid,comm] = count(); }
    delete(@owner[arg0]);
}
tracepoint:syscalls:sys_exit_munmap /comm == "physical_usage_"/ {
    @munmap[pid,args.ret] = count();
    @last_munmap[pid] = nsecs;
}
tracepoint:sched:sched_process_exit /comm == "physical_usage_" || comm == "profiler"/ {
    printf("exit ns=%llu pid=%d comm=%s\n", nsecs, pid, comm);
}
END { clear(@owner); }
''')
sampler = threading.Thread(target=sample_maps)
observer_log = (EVIDENCE / "pages.log").open("w")
observer = subprocess.Popen(["bpftrace", "-B", "none", str(observer_source)], stdout=observer_log, stderr=subprocess.STDOUT)
stress = []
try:
    for attempt in range(60):
        if "OBSERVER_READY" in (EVIDENCE / "pages.log").read_text():
            break
        if observer.poll() is not None:
            raise RuntimeError("bpftrace exited: " + (EVIDENCE / "pages.log").read_text())
        time.sleep(1)
    else:
        raise RuntimeError("bpftrace readiness timed out")
    sampler.start()
    for number in range(1, 4):
        results.append(run_case("serial-traced", number))
        if reproduced.is_set():
            break
    # Three independent copies reproduce concurrent profiling pressure without
    # selecting unrelated integration tests. Each runner retains its own workspace.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(run_case, "parallel-traced", number) for number in range(1, 19)]
        for future in futures:
            result = future.result()
            if result is not None:
                results.append(result)
    # Two bounded 32-MiB churners model competing CPU and page-fault activity.
    churn = "import mmap,time; end=time.monotonic()+210; exec('while time.monotonic()<end:\n m=mmap.mmap(-1,32*1024*1024)\n for i in range(0,len(m),4096): m[i]=1\n m.close()')"
    if not reproduced.is_set():
        stress = [subprocess.Popen(["python3", "-c", churn]) for _ in range(2)]
    for number in range(1, 9):
        if reproduced.is_set():
            break
        results.append(run_case("churn-traced", number))
finally:
    for process in stress:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=10)
    stop_sampling.set()
    if sampler.is_alive():
        sampler.join()
    if observer.poll() is None:
        observer.send_signal(signal.SIGINT)
    try:
        observer.wait(timeout=20)
    except subprocess.TimeoutExpired:
        observer.kill()
        observer.wait()
    observer_log.close()
    (EVIDENCE / "pinned-maps.json").write_text(json.dumps(pinned, indent=2))
    for map_id in pinned:
        if map_id in finalized:
            continue
        try:
            contents = bpftool("map", "dump", "id", str(map_id))
            (EVIDENCE / f"final-map-{map_id}.json").write_text(json.dumps(contents, indent=2))
        except Exception as error:
            (EVIDENCE / f"final-map-{map_id}.error").write_text(str(error))
        (PINS / str(map_id)).unlink(missing_ok=True)
    PINS.rmdir()
    (EVIDENCE / "results.json").write_text(json.dumps(results, indent=2))
print("DIAGNOSTICS_COMPLETE", flush=True)
# A reproduced failure is retained as evidence rather than hidden by a green job.
raise SystemExit(0 if len(results) == 29 and all(item["passed"] for item in results) else 1)
