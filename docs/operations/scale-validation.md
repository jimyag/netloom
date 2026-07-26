# 容量和长期验证

本文档定义 `netloom` 进入生产前需要完成的容量压测和长周期验证。目标不是只证明单个用例通过，而是找到 VPC、Subnet、Endpoint、SecurityGroup、PolicyRoute、NAT、LB、Provider Queue 和 eBPF policy map 的边界。

## 验证原则

- e2e 用例按组拆跑，不一次性跑全部。
- 每轮压测都保存 desired state、controller status、agent status、metrics 和 policy events。
- 每个规模档位至少覆盖创建、更新、删除、恢复四个阶段。
- 每个失败都要归类到对象图校验、OVN/OVSDB 写入、Linux datapath、eBPF/TCX、policy map pressure 或环境问题。
- 不为兼容旧 schema 保留额外路径；发现模型缺陷时直接修正 desired state schema 或实现。

## 基线验证

提交前本地基线：

```bash
go test ./...
git diff --check
```

Docker e2e 按组运行：

```bash
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Policy' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Provider' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerControllerReconcileIdempotent' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerControllerProgramsDistributedGatewayAndFloatingIPs' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerLinuxPolicyRouting' -count=1
```

## 压测维度

| 维度 | 必测内容 |
| --- | --- |
| VPC | 多 VPC 隔离、命名冲突、重复 reconcile、删除清理。 |
| Subnet | IPv4/IPv6、DHCP、DNS、provider VLAN、router/localnet attachment drift。 |
| Endpoint | 大量 LSP、DHCP attachment、port security、runtime `up` 统计、删除清理。 |
| RouteTable | 静态路由、ECMP 增删、BFD 状态、最小变更更新。 |
| PolicyRoute | priority、L4 match、reroute/drop/reject、Linux RPDB projection、删除清理。 |
| NAT | SNAT、DNAT、Floating IP、端口映射、distributed gateway endpoint binding。 |
| LoadBalancer | TCP/UDP/SCTP VIP、backend 数量、session affinity、health check。 |
| Provider Network | OVS bridge/port/interface、VLAN transition、controller quorum、QoS/Queue、tenant quota。 |
| SecurityGroup | rule tier/priority、default allow/deny、CIDRGroup、selector、identity group、entity、FQDN、named port。 |
| eBPF/TCX | policy map 容量、TCX attach、IPv4/IPv6 TCP/UDP/SCTP/ICMP、stateful conntrack、log/reject/drop。 |
| Rollout | dry-run、batch、pressure-aware shrink、approval、ack、finalize、SLO/probe、rollback、freeze/quarantine。 |

## 建议规模档位

| 档位 | 目标 |
| --- | --- |
| S | 1 VPC、2 subnets、20 endpoints、5 security groups、50 rules。 |
| M | 10 VPC、50 subnets、1k endpoints、100 security groups、2k rules。 |
| L | 50 VPC、500 subnets、10k endpoints、1k security groups、50k rules。 |
| XL | 100+ VPC、1k+ subnets、50k+ endpoints、5k+ security groups、200k+ rules。 |

每个档位都记录：

- controller reconcile latency p50/p95/p99。
- OVN operation count 和 live audit missing/unexpected/drift。
- agent reconcile latency p50/p95/p99。
- policy map entries、pressure percent、recommended capacity。
- TCX attach/update success/failure。
- provider OVSDB drift 和 controller quorum 状态。
- route explain 和 policy explain 抽样结果。

## 长周期 soak

至少运行 72 小时：

1. 每 5 分钟小批量 endpoint 增删。
2. 每 10 分钟 security group rule 更新。
3. 每 15 分钟 policy route 更新。
4. 每 30 分钟 LB backend health 状态变化。
5. 每 60 分钟 provider VLAN 或 queue 配置变更。
6. 每 6 小时触发一次 desired state 导出和状态快照。

观察项：

- controller/agent 是否持续成功 reconcile。
- OVN audit drift 是否被修复而不是累积。
- policy map pressure 是否稳定。
- policy events 是否出现重复失败。
- eBPF map、bpffs、TCX attach 是否泄露或漂移。
- Open_vSwitch external IDs 是否保持在可接受大小。

## 失败注入

必须覆盖：

- 停止一个 OVN NB endpoint。
- 切换 OVN leader。
- 暂停 Open vSwitch DB。
- 拔掉或 down provider parent NIC。
- 人工制造 OVS bridge/port/interface drift。
- 人工制造 OVN managed row column drift。
- 让 FQDN observation 过期。
- 构造超过 policy map 容量的规则。
- 触发 rollout SLO/probe 失败。

每个失败注入都要验证：

- 状态面能看见明确 reason。
- 严格模式按预期 fail closed。
- 恢复条件满足后能自动收敛。
- 不产生持续增长的 orphan OVN/OVSDB 行。

## 通过标准

一个规模档位只有同时满足以下条件才算通过：

- 创建、更新、删除、恢复阶段全部通过。
- `controller-status` 没有持续增长的 OVN health failure。
- live audit 没有持续增长的 missing、unexpected、duplicate、incomplete。
- `agent-status` provider ready，runtime preflight ready。
- policy revision 达到 desired revision。
- policy map pressure 低于预设阈值，或压力缓解行为符合预期。
- 抽样 `policy-explain` 和 `route-explain` 与业务预期一致。
- e2e 分组用例可重复运行。

## 输出物

每轮压测保存：

- desired state。
- controller status/events。
- agent status。
- controller/agent metrics。
- policy entries/rules/events。
- route explain/policy explain 抽样。
- 失败注入步骤和恢复结果。

这些输出物是判断能否进入生产部署的依据。
