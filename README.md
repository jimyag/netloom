# netloom

[![Go Report Card](https://goreportcard.com/badge/github.com/jimyag/netloom)](https://goreportcard.com/report/github.com/jimyag/netloom)
[![codecov](https://codecov.io/gh/jimyag/netloom/branch/main/graph/badge.svg)](https://codecov.io/gh/jimyag/netloom)
[![License](https://img.shields.io/github/license/jimyag/netloom)](LICENSE)
[![Release](https://img.shields.io/github/v/release/jimyag/netloom)](https://github.com/jimyag/netloom/releases)

`netloom` 是一个面向裸金属节点的 SDN 控制面。它用 OVN/OVSDB 实现 VPC、子网、网关、NAT、LoadBalancer、Provider Network 和策略路由，用 eBPF/TCX 执行安全组与 ACL。

项目不集成 Kubernetes，也不把 ACL 放到 OVN ACL 中执行。控制面描述网络意图，OVN/OVSDB 负责虚拟网络和裸金属 OVS 状态，eBPF/TCX 负责安全策略快速路径。

## 当前状态

核心路径已经实现，并有单元、集成和 Docker e2e 测试覆盖：

- VPC、Subnet、Endpoint、IPAM、Gateway、NAT、LoadBalancer、DNS、DHCP、RouteTable、PolicyRoute。
- OVN Northbound libovsdb writer，直接写 Logical Router、Logical Switch、Logical Switch Port、DHCP Options、Static Route、BFD、NAT、Load Balancer、Health Check 和 DNS。
- 裸金属 agent Linux datapath，支持 netlink/netns 地址、路由、RPDB 策略路由和 Provider Network 本地接口操作。
- 本机 Open_vSwitch OVSDB 同步，管理 Bridge、Controller、Port、Interface、QoS、Queue 和运行状态 external_ids。
- SecurityGroup 规则编译为 Cilium 风格 endpoint policy map，支持 CIDR、CIDRGroup、remote group、endpoint selector、service、entity、FQDN、named port、ICMP、stateful conntrack、reject/log/default-deny。
- eBPF/TCX ACL datapath，支持 IPv4/IPv6、TCP/UDP/ICMP、ingress/egress、workload/node attach、rule counters 和 metrics。
- Policy rollout、SLO/probe/approval/ack/finalize、pressure mitigation、quarantine、audit history 和 Prometheus metrics。
- `policy-explain`、`policy-status`、`route-explain`、desired-state import/export 等运维入口。

仍需要继续强化的是生产部署手册、长期运行压测、复杂 OVN/OVS 集群运维剧本和更完整的故障恢复流程。

## 快速开始

构建：

```bash
go build ./cmd/netloom-controller ./cmd/netloom-agent ./cmd/netloom-dns-observer
```

使用 JSON desired state 启动 controller：

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock \
NETLOOM_RECONCILE_INTERVAL_MS=5000 \
NETLOOM_CONTROLLER_METRICS_ADDR=:9091 \
./netloom-controller
```

在节点上启动 agent：

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_NODE_NAME=node-a \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
NETLOOM_POLICY_STORE=ebpf \
NETLOOM_TCX_WORKLOAD=1 \
NETLOOM_LINUX_DATAPATH=1 \
NETLOOM_LINUX_DATAPATH_MODE=netns \
NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth1 \
NETLOOM_AGENT_METRICS_ADDR=:9092 \
./netloom-agent
```

也可以把 desired state 写入本机 OVSDB，之后 controller/agent 通过 `NETLOOM_OVSDB_ENDPOINT` 从 `Open_vSwitch.external_ids` 读取：

```bash
./netloom-agent desired-state-import -ovsdb unix:/var/run/openvswitch/db.sock < /etc/netloom/state.json
./netloom-agent desired-state-export -ovsdb unix:/var/run/openvswitch/db.sock
```

完整示例和运行说明见 [docs/usage.md](docs/usage.md)。

## 验证

常规验证：

```bash
go test ./...
```

Docker e2e 需要显式打开，并建议按用例拆开跑：

```bash
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Policy' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Provider' -count=1
```

## 文档

- [使用说明](docs/usage.md)
- [eBPF ACL 设计](docs/design/cilium-ebpf-acl.md)
- [与 Cilium / Kube-OVN 的差距分析](docs/analysis/sdn-gap-vs-cilium-kube-ovn.md)

## 开发命令

```bash
task deps
task lint
task test
task test:integration
task test:e2e
task build
```
