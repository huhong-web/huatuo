---
title: 集成测试
type: docs
description:
author: HUATUO Team
date: 2026-03-04
weight: 5
---

集成测试用于验证 ``huatuo-bamai``在使用模拟的 ``/proc`` 和 ``/sys`` 文件系统时，能够正确启动并对外暴露符合预期的``Prometheus``指标。

测试运行的是真实的可执行文件，并通过校验 ``/metrics`` 接口的输出结果，确保指标采集与暴露逻辑正确，而不依赖宿主机的内核或硬件环境。

### 脚本执行流程

该集成测试脚本主要包含以下步骤：

1. 生成临时的``bamai.conf``配置文件
2. 使用模拟的 ``procfs`` 和 ``sysfs`` 启动 ``huatuo-bamai`` 服务
3. 等待 ``/metrics`` 接口可访问
4. 从 ``/metrics`` 接口拉取所有指标数据
5. 校验所有预期指标是否存在且内容匹配
6. 停止服务并清理相关资源
7. 若任意一个预期指标缺失或不匹配，测试将直接失败

### 运行方式

请在项目根目录下执行集成测试：
```bash
bash integration/run.sh
```

指定文件名可以只运行一个集成测试，第二个参数指定循环次数，默认为 1：

```bash
bash integration/run.sh test_metrics_exclude_filter.sh 10
```

或通过 Makefile 执行：
```bash
make integration
```

### 前置检查与结果汇总

两套测试共用 `integration/run.sh`，默认运行 integration；`e2e/run.sh` 转发到
`--suite e2e`。现有 `make integration`、`make e2e` 和单用例入口继续可用：

```bash
bash integration/run.sh --suite e2e
bash integration/run.sh --suite e2e test_metrics.sh 2
bash e2e/run.sh test_metrics.sh 2
```

两套测试都在独立的 UTS、mount namespace 中运行，hostname 为 `huatuo-dev`，
挂载传播设为 private。integration 由用例启动服务；e2e 在每例之前启动默认 bamai，
结束时停止服务并检查日志。integration 成功或跳过后删除工作目录，失败时保留；
e2e 保留工作目录。

runner 只检查 `_output` 目录是否存在，不逐个检查项目二进制和 BPF 产物。
直接运行脚本前先执行 `make build`；
目录存在不代表构建完整，缺失产物会在实际使用时导致失败。

用例使用同一个函数检查 PATH 中的命令或可执行文件路径，缺失时跳过：

```bash
require_commands jq curl ss
require_commands "${PROFILER_TOOL_DIR}/bin/asprof"
```

证书等输入文件使用 `require_readable` 检查，不可读时输出具体路径并跳过：

```bash
require_readable "${KUBELET_CERT}" "${KUBELET_KEY}"
```

`skip` 输出原因并以 77 退出，仍会执行 `EXIT` 清理。runner 将 0 记为 PASS、
77 记为 SKIP，其他状态记为 FAIL；清理失败也记为 FAIL。只有成功和跳过时，
runner 返回 0。失败时停止后续用例，并输出截至当前的统计。

每次执行都单独计数，包括重复运行，例如：

```text
summary: total=5 passed=3 skipped=2 failed=0
```

两套测试缺少 root 权限或 namespace 命令时，所选用例全部计为 SKIP。

#### 失败时的行为
- ``huatuo-bamai`` 服务指标和日志将直接输出到标准输出，便于问题定位
- 临时工作目录将被保留，用于后续调试分析

#### 成功时的行为
- 显示验证成功的``metrics`` 列表
---

### 后台进程清理

`stop_and_wait_by_pid PID [TIMEOUT]` 停止并等待子进程，返回其退出码。
未传入 PID 或 PID 为空时立即返回成功，调用方可以直接传入已初始化的 PID 变量。
等待结束后清空变量；尽力清理时使用 `|| true`，退出码属于测试契约时应进行断言。

### 网络命名空间辅助函数

网络测试可以在加载 `lib.sh` 后加载 `integration/lib_namespace.sh`：

- `namespace_setup NAME` 创建一个网络命名空间，通过 `NETNS` 暴露名称。
  调用方负责启用 `lo` 并配置所需地址。
- `namespace_setup_with_pair PREFIX SERVER_ADDR CLIENT_ADDR [PREFIX_LENGTH]`
  创建通过 veth 连接的两个命名空间，配置地址并启用接口，地址前缀长度默认为 24。
  命名空间、接口和地址通过 `NETNS_SERVER`、`NETNS_CLIENT`、
  `NETNS_VETH_SERVER`、`NETNS_VETH_CLIENT`、`NETNS_SERVER_ADDR`、
  `NETNS_CLIENT_ADDR` 暴露。
- `namespace_cleanup` 删除上述函数创建的命名空间并清空状态，支持重复调用。
  用例应在 `EXIT` 清理中先停止命名空间内的进程，再调用该函数。

### 如何新增指标测试
#### 第一步：新增或更新模拟数据
如果新增的指标依赖 ``/proc`` 或 ``/sys`` 文件内容，请在以下目录中新增或修改模拟数据：
```bash
integration/fixtures/
```
目录结构需与真实内核文件系统保持一致。

#### 第二步：添加预期指标
在以下目录中新建一个文件：
```bash
integration/fixtures/expected_metrics/
├── cpu.txt
├── memory.txt
└── ...
```
每一行（非空、非注释行）表示一条期望的 Prometheus 指标，指标内容必须与 ``/metrics`` 接口返回结果完全一致，新增的``*.txt`` 文件会被测试脚本自动加载并参与校验。

#### 第三步：运行测试
```bash
bash integration/run.sh
```
当任意一个预期指标缺失或不匹配时，测试将失败。

### Daemon cgroup 资源限额

`test_runtime_limits.sh` 先验证默认启动继承测试进程的 cgroup。启用
`--enable-cgroup` 后，通过 `/proc/PID/cgroup` 和 `cgroup.procs` 验证实际归属，
读取启动、运行两阶段的 CPU 限额，并验证 `MemoryLimitMiB` 到字节的换算。
正常停止后修改三个 Runtime 配置项，重启并重复验证，同时检查退出状态、
daemon cgroup 删除及日志中没有 error/panic/fatal。
这里验证内核限额与配置一致，不测试 CPU 吞吐或 OOM 行为。

用例复制 fixture，仅将副本中的 XFS 设备文件替换为 FIFO。观察进程等待 XFS
打开该设备后检查启动限额，再写入 fixture 数据放行初始化。启动和观察进程完成
均有超时；同步点未被使用时测试失败。这依赖 XFS 构造函数在运行 CPU 限额生效前
同步执行，不增加生产代码测试钩子，也不修改真实设备文件。

在隔离的 Linux 测试 VM 中运行，需要可写的 CPU、memory 控制器。
同一套断言在 v1/hybrid 上读取 quota/period、memory 限额文件，在纯 v2 上读取
`cpu.max`/`memory.max`；v2 还需要可访问的 systemd manager。
缺少能力或已有 bamai runtime cgroup 时报告 SKIP，不复用或删除已有组。
必须分别在两种层级上运行，才能确认 v1、v2 覆盖。用例禁用存储和 kubelet。

构建完成后，进入 integration 目录单独运行：

```bash
cd integration
```

```bash
bash run.sh test_runtime_limits.sh
```
