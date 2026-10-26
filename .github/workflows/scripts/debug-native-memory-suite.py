#!/usr/bin/env python3
# Copyright 2026 The HuaTuo Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

"""Observe original-suite scheduling without changing tests or injecting load."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path('/root/native-memory-suite')
TARGET = 'test_profiler_native_memory_physical_usage.sh'
BASE = '6cf654bb3380fd8998bf34d19cf661e6ce31b1a7'


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
    with os.fdopen(fd, 'w') as output:
        json.dump(value, output, indent=2)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def inspect_failure(workspace):
    # Publish the signal before diagnostics so the SSH controller can react now.
    shutil.copytree(workspace, ROOT / 'target-workspace', dirs_exist_ok=True)
    commands = {
        'processes': ['ps', '-eo', 'pid,ppid,pgid,etimes,stat,comm,args'],
        'memory': ['cat', '/proc/meminfo', '/proc/vmstat', '/proc/swaps'],
        'pressure': ['cat', '/proc/pressure/cpu', '/proc/pressure/memory', '/proc/pressure/io'],
        'kernel': ['dmesg', '--ctime'],
        'bpf-programs': ['bpftool', '-j', 'prog', 'show'],
        'bpf-links': ['bpftool', '-j', 'link', 'show'],
    }
    for name, command in commands.items():
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            (ROOT / (name + '.log')).write_text(result.stdout + result.stderr)
        except (OSError, subprocess.TimeoutExpired) as error:
            (ROOT / (name + '.error')).write_text(str(error))


def main():
    ROOT.mkdir(exist_ok=True)
    expected = subprocess.check_output(
        ['git', 'ls-tree', '-r', '--name-only', BASE, 'integration'], text=True).splitlines()
    expected = [path for path in expected if re.fullmatch(r'integration/test_[^/]+\.sh', path)]
    (ROOT / 'expected-tests.json').write_text(json.dumps(expected, indent=2))
    state = {'source_base': BASE, 'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
             'jobs': 3, 'expected_tests': len(expected), 'status': 'building_or_running',
             'target_failure': False, 'active_cases': [], 'events': [], 'target_workspaces': []}
    start = time.time_ns()
    output = (ROOT / 'suite.log').open('w')
    process = subprocess.Popen(['make', 'integration', 'SKIP_PORTABLE_GENERATION=1'], stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
    tail = (ROOT / 'suite.log').open()
    active = set()
    diagnosed = False
    try:
        while True:
            for line in tail.readlines():
                match = re.search(r'start: (test_[\w]+\.sh)', line)
                if match:
                    name = match.group(1)
                    active.add(name)
                    state['events'].append({'event': 'start', 'case': name, 'observed_ns': time.time_ns(),
                                            'active_cases': sorted(active), 'source_line': line.strip()})
                match = re.search(r'(PASS|FAIL|SKIP): (test_[\w]+\.sh)', line)
                if match:
                    name = match.group(2)
                    state['events'].append({'event': match.group(1), 'case': name,
                                            'observed_ns': time.time_ns(), 'active_cases': sorted(active),
                                            'source_line': line.strip()})
                    active.discard(name)
                match = re.search(r'summary: total=(\d+) passed=(\d+) skipped=(\d+) failed=(\d+)', line)
                if match:
                    state['summary'] = dict(zip(('total', 'passed', 'skipped', 'failed'), map(int, match.groups())))
            state['active_cases'] = sorted(active)
            state['observed_ns'] = time.time_ns()
            for log in Path('/tmp').glob('huatuo-test.*/test_profiler_native_memory_physical_usage.*/test.log'):
                try:
                    if log.stat().st_mtime_ns < start:
                        continue
                    text = log.read_text(errors='replace')
                except OSError:
                    continue
                workspace = str(log.parent)
                if workspace not in state['target_workspaces']:
                    state['target_workspaces'].append(workspace)
                if 'physical_usage balance verification failed' in text and not diagnosed:
                    state.update(target_failure=True, failure_kind='physical_usage_balance',
                                 target_failure_observed_ns=time.time_ns(), failure_workspace=workspace)
                    atomic_json(ROOT / 'status.json', state)
                    inspect_failure(log.parent)
                    diagnosed = True
            atomic_json(ROOT / 'status.json', state)
            if process.poll() is not None:
                # Read trailing runner output on the next iteration before publishing completion.
                if state.get('process_exited'):
                    break
                state['process_exited'] = True
            time.sleep(1)
        check = subprocess.run(['git', 'diff', '--exit-code', BASE, '--', 'bpf', 'cmd', 'core', 'internal', 'integration', 'pkg', 'apis', 'go.mod', 'go.sum', 'vendor', 'Makefile', 'build'], capture_output=True, text=True)
        state['source_identity_unchanged'] = check.returncode == 0
        (ROOT / 'source-identity.log').write_text(check.stdout + check.stderr)
        hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in [Path('_output/bin/profiler'), Path('bpf/native_physical_usage.o')] if path.exists()}
        atomic_json(ROOT / 'binary-hashes.json', hashes)
        state['exit_code'] = process.returncode
        state['status'] = 'complete'
        state['target_passed'] = any(event['case'] == TARGET and event['event'] == 'PASS' for event in state['events'])
        state['complete_selection'] = state.get('summary', {}).get('total') == len(expected)
        state['completed_ns'] = time.time_ns()
        atomic_json(ROOT / 'status.json', state)
        print(json.dumps(state, sort_keys=True), flush=True)
        return process.returncode or (0 if state['target_passed'] and state['complete_selection'] and state['source_identity_unchanged'] else 1)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        output.close()
        tail.close()


if __name__ == '__main__':
    raise SystemExit(main())
