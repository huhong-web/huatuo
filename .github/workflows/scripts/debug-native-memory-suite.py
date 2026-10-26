#!/usr/bin/env python3
# Copyright 2026 The HuaTuo Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

"""Observe the unchanged suite and retain its profiler maps for later SSH."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path('/root/native-memory-suite')
PIN_ROOT = Path('/sys/fs/bpf/native-memory-baseline')
TARGET = 'test_profiler_native_memory_physical_usage.sh'
BASE = '6cf654bb3380fd8998bf34d19cf661e6ce31b1a7'
REQUIRED_MAPS = {'page_to_stackid', 'stack_map_a', 'stack_map_b', 'profiler_state_'}
HARNESS_FILES = (
    '.github/workflows/os-distro-qemu-test-reusable.yml',
    '.github/workflows/scripts/debug-native-memory-suite.py',
    '.github/workflows/scripts/debug-native-memory-suite.sh',
)


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def capture_error(state, operation, error):
    message = '{}: {}'.format(operation, error)
    if message not in state.setdefault('capture_errors', []):
        state['capture_errors'].append(message)
        print('DIAGNOSTIC_ERROR ' + message, file=sys.stderr, flush=True)


def publish(state):
    try:
        atomic_json(ROOT / 'status.json', state)
    except OSError as error:
        capture_error(state, 'publish status', error)


def capture_command(state, name, command):
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                errors='replace', timeout=10)
        (ROOT / name).write_text(result.stdout)
        if result.stderr:
            (ROOT / (name + '.stderr')).write_text(result.stderr)
        if result.returncode:
            capture_error(state, name, 'exit {}'.format(result.returncode))
        return result
    except (OSError, subprocess.SubprocessError) as error:
        capture_error(state, name, error)
        return None


def capture_spec(mode):
    if mode == 'physical_usage':
        # Preserve the usage artifact paths and state key consumed by the host.
        return 'retained_profiler', ROOT, REQUIRED_MAPS
    if mode == 'physical_alloc':
        # The pending counters suffice for alloc loss; avoid retaining two extra
        # large stack maps and increasing memory pressure after this mode exits.
        return 'retained_alloc_profiler', ROOT / mode, {'profiler_state_'}
    raise ValueError('unsupported native memory mode: ' + mode)


def retain_profiler(state, target_pid, mode='physical_usage'):
    state_key, folder, required = capture_spec(mode)
    retained = state.get(state_key)
    if retained and retained['target_pid'] != target_pid:
        raise ValueError('another target appeared after profiler capture')
    if (retained and required <= set(retained['pins']) and
            (folder / 'target-process.maps').exists() and (ROOT / 'kernel-symbols.txt').exists() and
            (folder / 'retained-profiler.json').exists()):
        return
    maps = subprocess.run(['bpftool', '-j', 'map', 'show'], check=True,
                          capture_output=True, text=True, timeout=10)
    maps = json.loads(maps.stdout)
    if retained is None:
        for item in maps:
            if item.get('name') != ('page_to_stackid' if mode == 'physical_usage' else 'profiler_state_'):
                continue
            for owner in item.get('pids', []):
                pid = owner['pid']
                try:
                    args = (Path('/proc') / str(pid) / 'cmdline').read_bytes().split(b'\0')
                except OSError:
                    continue
                if b'--memory-mode' not in args or b'--pid' not in args:
                    continue
                mode_index = args.index(b'--memory-mode') + 1
                pid_index = args.index(b'--pid') + 1
                if (mode_index >= len(args) or pid_index >= len(args) or
                        args[mode_index] != mode.encode() or args[pid_index] != str(target_pid).encode()):
                    continue
                retained = {'target_pid': target_pid, 'profiler_pid': pid,
                            'observed_ns': time.time_ns(), 'pins': {}}
                state[state_key] = retained
                break
            if retained:
                break
    if retained is None:
        return  # The fixture starts before the profiler has loaded its maps.
    folder.mkdir(exist_ok=True)
    maps_path = folder / 'target-process.maps'
    if not maps_path.exists():
        maps_path.write_bytes((Path('/proc') / str(target_pid) / 'maps').read_bytes())
    PIN_ROOT.mkdir(exist_ok=True)
    for item in maps:
        name = item.get('name')
        if name not in required or name in retained['pins']:
            continue
        if not any(owner['pid'] == retained['profiler_pid'] for owner in item.get('pids', [])):
            continue
        path = PIN_ROOT / '{}-{}'.format(retained['profiler_pid'], item['id'])
        subprocess.run(['bpftool', 'map', 'pin', 'id', str(item['id']), str(path)],
                       check=True, capture_output=True, text=True, timeout=10)
        retained['pins'][name] = {'path': str(path), 'map': item}
    if not (ROOT / 'kernel-symbols.txt').exists():
        (ROOT / 'kernel-symbols.txt').write_bytes(Path('/proc/kallsyms').read_bytes())
    atomic_json(folder / 'retained-profiler.json', retained)


def snapshot_profiler(state):
    for mode in ('physical_alloc', 'physical_usage'):
        state_key, folder, _ = capture_spec(mode)
        retained = state.get(state_key, {})
        for name, item in retained.get('pins', {}).items():
            capture_command(state, str(folder.relative_to(ROOT) / (name + '.json')),
                            ['bpftool', '-j', 'map', 'dump', 'pinned', item['path']])


def debug_capture_complete(state):
    for mode in ('physical_alloc', 'physical_usage'):
        state_key, folder, required = capture_spec(mode)
        if not (required <= set(state.get(state_key, {}).get('pins', {})) and
                (folder / 'target-process.maps').exists() and
                (folder / 'retained-profiler.json').exists()):
            return False
    return (ROOT / 'kernel-symbols.txt').exists() and not state['capture_errors']


def inspect_failure(state, workspace):
    # Restrict copies to profiler artifacts; workspace/run contains live mounts.
    snapshot_profiler(state)
    target = ROOT / 'target-workspace'
    try:
        target.mkdir(exist_ok=True)
        shutil.copy2(workspace / 'test.log', target / 'test.log')
    except OSError as error:
        capture_error(state, 'copy test.log', error)
    for source in workspace.glob('profiler-physical-usage.*'):
        if not source.is_dir() or source.is_symlink() or source.is_mount():
            continue
        try:
            shutil.copytree(source, target / source.name, symlinks=True,
                            dirs_exist_ok=True,
                            ignore=lambda parent, names: [name for name in names
                                                          if Path(parent, name).is_mount() or
                                                          Path(parent, name).is_symlink()])
        except (OSError, shutil.Error) as error:
            capture_error(state, 'copy profiler artifacts', error)
    commands = {
        'processes.log': ['ps', '-eo', 'pid,ppid,pgid,etimes,stat,comm,args'],
        'memory.log': ['cat', '/proc/meminfo', '/proc/vmstat', '/proc/swaps'],
        'pressure.log': ['cat', '/proc/pressure/cpu', '/proc/pressure/memory', '/proc/pressure/io'],
        'kernel.log': ['dmesg', '--ctime'],
        'bpf-programs.json': ['bpftool', '-j', 'prog', 'show'],
        'bpf-links.json': ['bpftool', '-j', 'link', 'show'],
    }
    for name, command in commands.items():
        capture_command(state, name, command)


def observe_target(state, start, diagnosed):
    runner_failed = any(event['case'] == TARGET and event['event'] == 'FAIL'
                        for event in state.get('events', []))
    for log in Path('/tmp').glob('huatuo-test.*/test_profiler_native_memory_physical_usage.*/test.log'):
        try:
            if log.stat().st_mtime_ns < start:
                continue
            text = log.read_text(errors='replace')
            workspace = str(log.parent)
            if workspace not in state['target_workspaces']:
                state['target_workspaces'].append(workspace)
            balance_failed = 'physical_usage balance verification failed' in text
            alloc_failed = ('physical_alloc byte conversion verification failed' in text or
                            'physical_alloc captured no bytes' in text)
            failure = (balance_failed or '[FAIL]' in text or runner_failed) and not diagnosed
            if failure:
                kind = ('physical_usage_balance' if balance_failed else
                        'physical_alloc_bytes' if alloc_failed else 'native_case_failure')
                state.update(suite_failure=True, target_failure=balance_failed, failure_kind=kind,
                             suite_failure_observed_ns=time.time_ns(), failure_workspace=workspace)
                if balance_failed:
                    state['target_failure_observed_ns'] = state['suite_failure_observed_ns']
                publish(state)  # Report the failure even if retaining its maps failed.
                diagnosed = True
            matches = re.findall(r'running profiler mode=(physical_alloc|physical_usage) pid=(\d+)', text)
            for mode, pid in matches:
                try:
                    retain_profiler(state, int(pid), mode)
                except Exception as error:
                    capture_error(state, 'retain profiler', error)
            if failure:
                inspect_failure(state, log.parent)
        except Exception as error:
            capture_error(state, 'observe ' + str(log), error)
    if runner_failed and not diagnosed:
        state.update(suite_failure=True, failure_kind='native_case_failure',
                     suite_failure_observed_ns=time.time_ns())
        capture_error(state, 'native failure evidence', 'no readable current native test log')
        publish(state)
        diagnosed = True
    return diagnosed


def read_runner_events(state, tail, active):
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
            state['events'].append({'event': match.group(1), 'case': name, 'observed_ns': time.time_ns(),
                                    'active_cases': sorted(active), 'source_line': line.strip()})
            active.discard(name)
        match = re.search(r'summary: total=(\d+) passed=(\d+) skipped=(\d+) failed=(\d+)', line)
        if match:
            state['summary'] = dict(zip(('total', 'passed', 'skipped', 'failed'), map(int, match.groups())))
    state['active_cases'] = sorted(active)
    state['observed_ns'] = time.time_ns()


def main():
    ROOT.mkdir(exist_ok=True)
    expected = subprocess.check_output(
        ['git', 'ls-tree', '-r', '--name-only', BASE, 'integration'], text=True).splitlines()
    expected = [path for path in expected if re.fullmatch(r'integration/test_[^/]+\.sh', path)]
    atomic_json(ROOT / 'expected-tests.json', expected)
    state = {'source_base': BASE, 'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
             'jobs': 3, 'expected_tests': len(expected), 'status': 'building_or_running',
             'target_failure': False, 'suite_failure': False, 'active_cases': [], 'events': [], 'target_workspaces': [],
             'capture_errors': []}
    start = time.time_ns()
    output = (ROOT / 'suite.log').open('w')
    process = subprocess.Popen(['make', 'integration', 'SKIP_PORTABLE_GENERATION=1'], stdout=output,
                               stderr=subprocess.STDOUT, start_new_session=True)
    tail = (ROOT / 'suite.log').open(errors='replace')
    active = set()
    diagnosed = False
    try:
        while True:
            try:
                read_runner_events(state, tail, active)
            except OSError as error:
                capture_error(state, 'read runner log', error)
            diagnosed = observe_target(state, start, diagnosed)
            publish(state)
            if process.poll() is not None:
                # Read trailing runner output once more before publishing completion.
                if state.get('process_exited'):
                    break
                state['process_exited'] = True
            time.sleep(1)
        snapshot_profiler(state)
        paths = ['.'] + [':(exclude)' + path for path in HARNESS_FILES]
        check = capture_command(state, 'source-identity.log', ['git', 'diff', '--exit-code', BASE, '--'] + paths)
        state['source_identity_unchanged'] = check is not None and check.returncode == 0
        hashes = {}
        for path in [Path('_output/bin/profiler'), Path('bpf/native_physical_alloc.o'), Path('bpf/native_physical_usage.o')]:
            try:
                hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as error:
                capture_error(state, 'hash ' + str(path), error)
        try:
            atomic_json(ROOT / 'binary-hashes.json', hashes)
        except OSError as error:
            capture_error(state, 'save binary hashes', error)
        state['suite_exit_code'] = process.returncode
        state['debug_capture_complete'] = debug_capture_complete(state)
        state['status'] = 'complete'
        state['target_passed'] = any(event['case'] == TARGET and event['event'] == 'PASS' for event in state['events'])
        state['complete_selection'] = state.get('summary', {}).get('total') == len(expected)
        state['completed_ns'] = time.time_ns()
        valid = (state['target_passed'] and state['complete_selection'] and
                 state['source_identity_unchanged'] and state['debug_capture_complete'] and
                 not state['capture_errors'])
        state['exit_code'] = process.returncode or (0 if valid else 1)
        if state['exit_code'] == 0:
            for state_key in ('retained_alloc_profiler', 'retained_profiler'):
                for item in state.get(state_key, {}).get('pins', {}).values():
                    try:
                        Path(item['path']).unlink()
                    except OSError as error:
                        capture_error(state, 'release owned pin', error)
            if state['capture_errors']:
                state['exit_code'] = 1
        publish(state)
        print(json.dumps(state, sort_keys=True), flush=True)
        return state['exit_code']
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
