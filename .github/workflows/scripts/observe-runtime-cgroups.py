#!/usr/bin/env python3
# Copyright 2026 The HuaTuo Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Observe daemon/unit-test membership without changing cgroups or test files."""

import glob
import json
import os
from pathlib import Path
import shutil
import sys
import time


def read(path):
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeError):
        return None


def process_state(pid):
    root = Path('/proc') / pid
    comm = read(root / 'comm')
    if not comm or not (comm.startswith('huatuo-') or comm.endswith('.test')):
        return None
    try:
        executable = os.readlink(root / 'exe')
        stat = (root / 'stat').read_text().rsplit(')', 1)[1].split()
        memberships = (root / 'cgroup').read_text().splitlines()
        tids = sorted(int(p.name) for p in (root / 'task').iterdir())
    except (OSError, ValueError):
        return None
    limits = {}
    for entry in memberships:
        _, controllers, group = entry.split(':', 2)
        for controller, files in (
            ('cpu', ('cpu.cfs_quota_us', 'cpu.cfs_period_us')),
            ('memory', ('memory.limit_in_bytes',)),
        ):
            if controller not in controllers.split(','):
                continue
            mount = Path('/sys/fs/cgroup') / controllers
            # Ubuntu hybrid mounts cpu,cpuacct, with cpu also exposed as a symlink.
            if not mount.exists():
                mount = Path('/sys/fs/cgroup') / controller
            limits[controller] = {f: read(mount / group.lstrip('/') / f) for f in files}
    return dict(pid=int(pid), comm=comm, executable=executable, ppid=int(stat[1]),
                start_ticks=int(stat[19]), tids=tids, memberships=memberships,
                limits=limits)


def snapshot_runtime_logs(destination, versions):
    # Successful cases are deleted by the unchanged runner; retain passive snapshots.
    for case in glob.glob('/tmp/huatuo-test.*/test_node_runtime_limits.*'):
        for path in Path(case).rglob('*'):
            if not path.is_file() or path.is_symlink():
                continue
            if path.suffix != '.log' and not path.name.endswith('.pid'):
                continue
            try:
                version = (path.stat().st_mtime_ns, path.stat().st_size)
                if versions.get(str(path)) == version:
                    continue
                target = (destination / 'runtime-snapshots' / Path(case).parent.name
                          / Path(case).name / path.relative_to(case))
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(str(path), str(target))
                versions[str(path)] = version
            except OSError:
                pass  # The original runner may remove a successful workspace concurrently.


def main():
    destination = Path(sys.argv[1])
    previous = {}
    versions = {}
    with (destination / 'processes.jsonl').open('w', buffering=1) as output:
        while not (destination / 'stop-observer').exists():
            current = {}
            for pid in os.listdir('/proc'):
                if pid.isdigit():
                    state = process_state(pid)
                    if state:
                        current[pid] = state
            for pid in previous.keys() | current.keys():
                if previous.get(pid) != current.get(pid):
                    output.write(json.dumps(dict(epoch_ns=time.time_ns(),
                        monotonic_ns=time.monotonic_ns(), pid=int(pid),
                        state=current.get(pid))) + '\n')
            previous = current
            snapshot_runtime_logs(destination, versions)
            time.sleep(0.2)
        snapshot_runtime_logs(destination, versions)


if __name__ == '__main__':
    main()
