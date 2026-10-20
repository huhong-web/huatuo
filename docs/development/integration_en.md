---
title: Integration Test
type: docs
description:
author: HUATUO Team
date: 2026-03-04
weight: 5
---

This integration test validates that **huatuo-bamai** can start correctly with mocked `/proc` and `/sys` filesystems and expose the expected **Prometheus metrics**.

The test runs the real `huatuo-bamai` binary and verifies the `/metrics`endpoint output without relying on the host kernel or hardware.

### What the Script Does
The integration test performs the following steps:

1. Generates a temporary `bamai.conf`
2. Starts `huatuo-bamai` with mocked `procfs` and `sysfs`
3. Waits for the Prometheus `/metrics` endpoint to become available
4. Fetches all metrics from `/metrics`
5. Verifies that all expected metrics exist
6. Stops the service and cleans up resources

If any expected metric is missing, the test fails.

### How to Run
Run the integration test from the project root:

```bash
bash integration/run.sh
```

Pass a file name to run one integration test. The optional second argument is
the repeat count and defaults to 1:

```bash
bash integration/run.sh test_metrics_exclude_filter.sh 10
```

or
```bash
make integration
```
### Prerequisites and Results

Both suites use `integration/run.sh`, which defaults to integration.
`e2e/run.sh` forwards to `--suite e2e`. Existing `make integration`, `make e2e`,
and single-case entry points remain available:

```bash
bash integration/run.sh --suite e2e
bash integration/run.sh --suite e2e test_metrics.sh 2
bash e2e/run.sh test_metrics.sh 2
```

Both suites run in separate UTS and mount namespaces with hostname `huatuo-dev`
and private mount propagation. Integration cases start their own services;
e2e starts the baseline bamai before each case, then stops it and checks its log.
Integration removes workspaces after passed or skipped cases and preserves them
on failure. E2E retains its workspaces.

The runner checks only that `_output` exists, without checking individual
project binaries or BPF objects. Run
`make build` before invoking a runner directly. An existing directory does not
prove that the build is complete; missing artifacts fail when used.

Use the same helper for commands on PATH and executable file paths. Missing
commands skip the case:

```bash
require_commands jq curl ss
require_commands "${PROFILER_TOOL_DIR}/bin/asprof"
```

Use `require_readable` for input files such as certificates. Unreadable inputs
skip the case and report the affected path:

```bash
require_readable "${KUBELET_CERT}" "${KUBELET_KEY}"
```

`skip` prints its reason and exits with 77; `EXIT` cleanup still runs. The runner
classifies 0 as PASS, 77 as SKIP, and other statuses as FAIL. Cleanup failures also
count as FAIL. A suite containing only passed and skipped cases returns 0.
A failure stops subsequent cases and prints the results collected so far.

Each execution counts separately, including repetitions. For example:

```text
summary: total=5 passed=3 skipped=2 failed=0
```

When root privileges or namespace commands are unavailable, both suites count
all selected executions as SKIP.

#### On Failure

- The `huatuo-bamai` service metrics and logs are printed to stdout
- The temporary working directory is kept for debugging

#### On Success

- Output the list of successfully validated metrics

---

### Background Process Cleanup

`stop_and_wait_by_pid PID [TIMEOUT]` stops and waits for a child process,
returning its exit status. An omitted or empty PID returns success immediately,
so callers can pass an initialized PID variable without checking it first.
Clear the variable after waiting; use `|| true` in best-effort cleanup and
assert the exit status when it is part of the test contract.

### Network Namespace Helpers

Network tests can source `integration/lib_namespace.sh` after `lib.sh`:

- `namespace_setup NAME` creates one network namespace and exposes its name as
  `NETNS`. The caller brings up `lo` and configures any addresses it needs.
- `namespace_setup_with_pair PREFIX SERVER_ADDR CLIENT_ADDR [PREFIX_LENGTH]`
  creates two namespaces connected by a veth pair, configures their addresses,
  and brings up the interfaces. The prefix length defaults to 24. Names and
  addresses are exposed through `NETNS_SERVER`, `NETNS_CLIENT`,
  `NETNS_VETH_SERVER`, `NETNS_VETH_CLIENT`, `NETNS_SERVER_ADDR`, and
  `NETNS_CLIENT_ADDR`.
- `namespace_cleanup` deletes the namespaces created by either helper and
  clears their state. Call it from the test's `EXIT` cleanup after stopping
  processes in those namespaces. Repeated cleanup calls are supported.

### How to Add New Metrics Tests
#### 1: Add or Update Fixture Data

If the metric depends on /proc or /sys, add or update mock data under:
```bash
integration/fixtures/
```

The directory structure should match the real kernel filesystem layout.
#### 2: Add Expected Metrics

Create a new file under:
```bash
integration/fixtures/expected_metrics/
├── cpu.txt
├── memory.txt
└── ...
```

Each non-empty, non-comment line represents one expected Prometheus metric line
and must match the /metrics output exactly.

New *.txt files are automatically picked up by the test.

#### 3: Run the Test
```bash
bash integration/run.sh
```
The test fails if any expected metric is missing or mismatched.

### Daemon cgroup resource limits

`test_runtime_limits.sh` checks that default startup inherits the test process's
cgroup. With `--enable-cgroup`, it verifies membership through `/proc/PID/cgroup`
and `cgroup.procs`, reads the startup and steady CPU limits, and checks the
MiB-to-byte conversion for `MemoryLimitMiB`. It then changes all three Runtime
settings and repeats after a graceful stop and restart. It also checks exit
status, removal of the daemon's cgroups, and absence of error/panic/fatal logs.
This verifies configured kernel limits, not CPU throughput or OOM behavior.

The test copies the fixtures and replaces only the copied XFS device with a
FIFO. Its observer waits for XFS to open that device, verifies startup limits,
then supplies the fixture bytes to release initialization. Startup and observer
completion have deadlines; a missing gate is a failure. This depends on the
synchronous XFS constructor running before the steady CPU quota is applied.
No production hooks or real device files are changed.

Run on an isolated Linux test VM with writable CPU and memory controllers.
The same assertions read quota/period and memory files on v1/hybrid hosts, or
`cpu.max`/`memory.max` on pure v2 hosts. V2 also requires a reachable systemd
manager. A host-wide lock prevents concurrent runs of this case; a busy lock,
missing capabilities, or an existing bamai runtime cgroup produces a reported
SKIP. The daemon owns cgroup cleanup. Any remaining group is preserved and fails
the test, because its name alone does not prove ownership. Run separately on
both hierarchies to establish v1 and v2 coverage. Storage and kubelet are disabled.

After building, run this case from the integration directory:

```bash
cd integration
```

```bash
bash run.sh test_runtime_limits.sh
```
