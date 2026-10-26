---
title: 快速开始
description: 
date: 2026-07-27
type: docs
weight: 1
---

本文提供三条使用路径：[查看示例](#查看示例)、[运行容器](#运行容器)和[源码构建](#源码构建)。在本机运行采集器需要 Linux 环境；容器方式还需安装 Docker，并具备示例所需的权限。

## 查看示例

登录[示例网站](http://console.huatuo.tech)查看内核指标、异常事件和火焰图。示例账户为 `huatuo`，密码为 `huatuo1024`。

- [事件与自动追踪](http://console.huatuo.tech/d/autotracing-event)

  ![事件与自动追踪仪表盘](/docs/img/quickstart-autotracing-event.png)

- [宿主机指标](http://console.huatuo.tech/d/metrics-host)

  ![宿主机指标仪表盘](/docs/img/quickstart-metrics-host.png)

- [容器指标](http://console.huatuo.tech/d/metrics-container)

  ![容器指标仪表盘](/docs/img/quickstart-metrics-container.png)

## 运行容器

![HUATUO 组件数据流](/docs/img/quickstart-data-flow.png)

### Docker

以下镜像默认关闭容器信息获取和 Elasticsearch 存储。启动采集器：

```bash
$ docker run --privileged --pid=host --cgroupns=host --network=host -v /sys:/sys -v /proc:/proc -v /run:/run huatuo/huatuo-bamai:latest
```

在另一个终端获取指标：

```bash
$ curl -s localhost:19704/metrics
```

接口返回 Prometheus 格式的指标时，说明指标服务可访问。事件和自动追踪结果写入容器内的 `huatuo-local` 目录；未触发采集时，目录可能没有记录。可在测试环境构造目标活动或调整对应阈值，再检查记录。

### Docker Compose

在仓库根目录执行以下命令，启动 [Elasticsearch](https://www.elastic.co)、[Prometheus](https://prometheus.io)、[Grafana](https://grafana.com) 和 HUATUO 组件：

```bash
$ docker compose --project-directory ./build/docker up
```

服务启动后访问 [Grafana](http://localhost:3000)，默认管理员账户和密码均为 `admin`。事件与自动追踪面板仅在有对应采集结果时显示数据。数据源和仪表盘配置见[数据源配置](/docs/best-practice/datasource_zh.md)。

![huatuo-bamai 运行流程](/docs/img/quickstart-components.png)

## 源码构建

### 构建镜像

在项目根目录构建包含 `huatuo-bamai`、BPF 对象及工具的镜像：

```bash
$ docker build --network host -t huatuo/huatuo-bamai:latest .
```

### 运行采集器

运行构建出的镜像：

```bash
$ docker run --privileged --pid=host --cgroupns=host --network=host -v /sys:/sys -v /proc:/proc -v /run:/run huatuo/huatuo-bamai:latest
```

也可复制容器 `/home/huatuo-bamai` 下的文件后，在本地运行：

```bash
$ ./huatuo-bamai --region example --config huatuo-bamai.conf
```

长期运行时，按环境选择 [systemd](/docs/deployment/systemd_zh.md) 或 [Kubernetes](/docs/deployment/kubernetes_zh.md) 部署。

## 配置

完整字段、默认值和生效条件见[节点配置](/docs/configuration/huatuo-bamai-configuration_zh.md)。

### 容器信息

HUATUO 通过 kubelet 接口获取 Pod 和容器信息。按实际环境设置端口与证书；`KubeletAuthorizedPort` 和 `KubeletReadOnlyPort` 均为 `0` 时关闭该功能。

```toml
  [Pod]
    KubeletClientCertPath = "/etc/kubernetes/pki/apiserver-kubelet-client.crt,/etc/kubernetes/pki/apiserver-kubelet-client.key"
```

### 存储

指标由 `:19704/metrics` 暴露，需配置 Prometheus 抓取和保存。事件与自动追踪结果按已启用的存储后端写入。以下分别为 Elasticsearch 和本地文件配置示例：

```toml
[Storage.Elasticsearch]
    Address = "http://127.0.0.1:9200"
    Username = "elastic"
    Password = "huatuo-bamai"
    Index = "huatuo_bamai"
```

```toml
# tracer's record data
# Path: all but the last element of path for per tracer
# RotationSizeMiB：单个记录文件轮转前的最大容量
# MaxRotatedFiles：保留的轮转文件数量上限
[Storage.LocalFile]
    Path = "huatuo-local"
    RotationSizeMiB = 100
    MaxRotatedFiles = 10
```

### 事件阈值

按业务负载调整 `huatuo-bamai.conf` 中支持配置的事件和自动追踪阈值。触发条件、适用范围及默认值因采集器而异，应在目标环境验证。

### 资源限制

HUATUO 默认继承启动进程的 cgroup，因此 Kubernetes 和 systemd 部署继续由 kubelet 或 systemd 管理已有的资源限制。直接运行时，可通过 `--enable-cgroup` 启用 HUATUO 自身的限制。

在运行 systemd 的 hybrid 主机上，HUATUO 为 daemon 创建 `huatuo-bamai-<PID>.scope`，由 systemd 通过 D-Bus 应用启动和稳态 CPU 限额及内存限额。scope 初始化失败会导致启动失败。纯 legacy、未运行 systemd 的 hybrid 和 unified 主机保留现有的 runtime cgroup 行为。

配置示例：

```toml
[Runtime]
    StartupCPULimitCores = 0.5
    CPULimitCores = 2.0
    MemoryLimitMiB = 2048
```
