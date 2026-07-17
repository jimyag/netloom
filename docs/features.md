# 功能矩阵

本文档记录 `netloom` 当前已经实现的 SDN 能力、主要入口和验证方式。项目目标是裸金属 SDN，不考虑 Kubernetes 集成；安全组和 ACL 由 eBPF/TCX 执行，不落到 OVN ACL。

## 核心网络

| 能力 | 状态 | 实现入口 | 验证 |
| --- | --- | --- | --- |
| VPC | 已实现 | `internal/control`, `internal/ovn` | `go test ./internal/ovn ./tests/integration` |
| Subnet | 已实现 | OVN Logical Switch、router port、localnet port | `TestLibOVSDBTopologyWriterEnsuresSubnetLogicalSwitch`、Docker provider e2e |
| Endpoint | 已实现 | OVN Logical Switch Port、port security、DHCP attachment | `TestLibOVSDBTopologyWriterEnsuresEndpointWithDHCPv4`、Docker idempotence e2e |
| IPAM | 已实现 | `internal/ipam` | `go test ./internal/ipam` |
| DHCP | 已实现 | OVN `DHCP_Options`，支持 DNS、domain、search domain、MTU、lease | `TestDockerControllerProgramsDHCPDNSAndSearchDomains` |
| DNS | 已实现 | OVN DNS records 和 DNS observer runtime observations | `go test ./cmd/netloom-dns-observer ./internal/dnsobserver` |

## 路由和网关

| 能力 | 状态 | 实现入口 | 验证 |
| --- | --- | --- | --- |
| Gateway | 已实现 | OVN logical router metadata、本机 datapath gateway route | `TestLibOVSDBTopologyWriterEnsuresGatewayRouterMetadata` |
| Distributed Gateway | 已实现 | 分布式 gateway metadata 和 NAT logical port 约束 | `TestDockerControllerProgramsDistributedGatewayAndFloatingIPs` |
| Static Route | 已实现 | OVN `Logical_Router_Static_Route` | `TestLibOVSDBTopologyWriterEnsuresRouteTableStaticRoutes` |
| ECMP Static Route | 已实现 | OVN static route 多 nexthop，增删 hop 时最小变更 | `TestBackendCleanupAddsECMPNextHopWithoutDeletingExistingRoutes` |
| BFD | 已实现 | OVN `BFD` row 与 static route reference | `TestLibOVSDBTopologyWriterEnsuresStaticRouteBFD` |
| Policy Route | 已实现 | OVN `Logical_Router_Policy` 和 Linux RPDB projection | `TestDockerLinuxPolicyRoutingProgramsAndCleansRuntimeState`、`TestPlanProgramsLinuxPolicyRoutes` |
| IPv6 Policy Route | 已实现 | OVN/Linux dual-stack path | `TestDockerLinuxPolicyRoutingProgramsIPv6RuntimeState` |

## NAT 和负载均衡

| 能力 | 状态 | 实现入口 | 验证 |
| --- | --- | --- | --- |
| SNAT | 已实现 | OVN `NAT` | Docker controller e2e |
| DNAT | 已实现 | OVN `NAT` | Docker controller e2e |
| Floating IP | 已实现 | OVN `dnat_and_snat` | `TestDockerControllerProgramsDistributedGatewayAndFloatingIPs` |
| Port-mapped NAT | 已实现 | OVN NAT port columns with TCP/UDP/SCTP port mapping | `TestDockerControllerClearsStaleNATPortMetadata` |
| Load Balancer | 已实现 | OVN `Load_Balancer` with protocol-specific TCP/UDP/SCTP VIPs | `TestDockerControllerProgramsLoadBalancerSessionAffinity` |
| LB Health Check | 已实现 | OVN `Load_Balancer_Health_Check` | `TestDockerControllerActiveLBHealthProbeConvergesOVNBackends` |
| Session Affinity | 已实现 | OVN LB options and topology resolver | `TestDesiredStateLoadBalancerSelectionFieldsDriveStableBackendChoice` |

## Provider Network 和本机数据面

| 能力 | 状态 | 实现入口 | 验证 |
| --- | --- | --- | --- |
| Provider Network | 已实现 | OVN localnet port + local OVSDB bridge/port/interface | `TestDockerControllerClearsLocalnetTagWhenProviderVLANIsRemoved` |
| VLAN | 已实现 | localnet tag 和本机 provider interface planning | Docker provider VLAN e2e |
| OVS Bridge/Port/Interface | 已实现 | `internal/linuxdatapath/libovsdb_vswitch.go` | `go test ./internal/linuxdatapath` |
| QoS / Queue | 已实现 | Open_vSwitch QoS/Queue rows and tenant classification | `go test ./internal/linuxdatapath ./internal/ovn` |
| Linux netns/veth | 已实现 | `internal/linuxdatapath` netlink backend | `go test ./internal/linuxdatapath` |
| RPDB policy routing | 已实现 | Linux rule/table projection for policy routes | `TestPlanProgramsLinuxPolicyRoutes` |
| Cleanup of managed datapath state | 已实现 | `NETLOOM_LINUX_DATAPATH_CLEANUP=1` | `go test ./internal/linuxdatapath` |

## 安全组和 eBPF ACL

| 能力 | 状态 | 实现入口 | 验证 |
| --- | --- | --- | --- |
| SecurityGroup | 已实现 | `internal/policy` compiler | `go test ./internal/policy` |
| Endpoint policy map | 已实现 | `internal/dataplane/policymap.go` | `go test ./internal/dataplane` |
| eBPF policy store | 已实现 | `internal/dataplane/ebpf_store.go` | `go test ./internal/dataplane` |
| TCX attach | 已实现 | `internal/dataplane/tcx.go` | Docker shared-interface policy e2e |
| Ingress/Egress | 已实现 | policy compiler + dataplane evaluator | integration and Docker policy e2e |
| CIDR / CIDRGroup | 已实现 | policy compiler | `TestDockerSharedInterfaceExpandsSelectorServiceFQDNAndCIDRGroupPolicies` |
| Remote group / selector | 已实现 | identity group and endpoint selector expansion | `go test ./internal/policy ./tests/integration` |
| Entity rules | 已实现 | `world`, `all`, `cluster`, `host`, `remote-node`, `none` | Docker entity e2e |
| FQDN rules | 已实现 | DNS observer + policy compiler | Docker policy sources e2e |
| Named ports | 已实现 | endpoint named ports expansion | Docker named port e2e |
| SCTP L4 ACL | 已实现 | policy compiler、policy map、TCX IPv4/IPv6 projection | `TestCompileForEndpointEncodesSCTPPorts`、`TestIPv4L4ACLRulesFromProgramProjectsSCTPPort` |
| ICMP and dual-stack | 已实现 | IPv4/IPv6 ICMP policy entries | Docker dual-stack ICMP e2e |
| Stateful conntrack | 已实现 | dataplane evaluator/store metadata | Docker stateful conntrack e2e |
| Reject / Log | 已实现 | policy actions and recorder events | Docker reject/log e2e |
| Default deny/default allow | 已实现 | security group defaults | Docker default allow/egress e2e |

## 运维和状态管理

| 能力 | 状态 | 实现入口 | 验证 |
| --- | --- | --- | --- |
| Desired state file | 已实现 | `NETLOOM_STATE_FILE` | controller/agent tests |
| Desired state in OVSDB | 已实现 | `desired-state-import/export`, `Open_vSwitch.external_ids` | `TestControllerLoadsDesiredStateFromOpenVSwitchExternalID` |
| Policy explain | 已实现 | `netloom-agent policy-explain` | command tests |
| Policy status | 已实现 | `netloom-agent policy-status` | command tests |
| Policy rule observability | 已实现 | agent `/policy/rules` JSON API and Prometheus rule counters | `TestPolicyRulesAPIReportsCatalogAndCounters` |
| Policy update events | 已实现 | agent `/policy/events` JSON API for recent endpoint policy-map update events | `TestPolicyEventsAPIReportsRecentEndpointEvents` |
| Policy map entry inspection | 已实现 | `netloom-agent policy-entries` and agent `/policy/entries/{endpoint}` JSON API for live endpoint policy-map entries | `TestRunPolicyEntriesReportsEndpointMapJSON`、`TestPolicyEntriesAPIReportsEndpointPolicyMapEntries` |
| Route explain | 已实现 | `netloom-agent route-explain` | command tests |
| Endpoint action history | 已实现 | agent `GET /policy/endpoints/actions/history` and `netloom-agent policy-action-history`; endpoint/action/success/limit filters; persists successful and failed lifecycle actions in local OVS `netloom_policy_endpoint_action_history` when OVSDB is configured | `TestPolicyEndpointAPIPersistsActionHistoryToOpenVSwitchExternalID`、`TestPolicyEndpointActionHistoryAPIFiltersEndpointActionAndLimit`、`TestPolicyEndpointActionHistoryRecordsFailedAction`、`TestRunPolicyActionHistoryWithStoreReportsFilteredJSON` |
| Identity group import/feed | 已实现 | `identity-groups-import`, remote feed env vars | controller/agent tests |
| DNS observer | 已实现 | UDP/TCP proxy, AF_PACKET capture, OVSDB observations | `go test ./cmd/netloom-dns-observer` |
| Metrics | 已实现 | controller/agent `/metrics` | command tests |
| Controller status API | 已实现 | controller `/status` JSON API for OVN health/audit/cluster/stale state | `TestControllerStatusAPIExportsLatestOVNStatus` |
| OVN health/audit/maintenance | 已实现 | libovsdb health, audit stats, compact/stale hooks | `go test ./cmd/netloom-controller ./internal/ovn` |
| Policy freeze/unfreeze | 已实现 | agent `/policy/endpoints/{endpoint}/freeze` and `/unfreeze`; optional TTL/expiry; `netloom-agent policy-freeze-state`; persists frozen endpoints in local OVS `netloom_policy_freeze_state` when OVSDB is configured | `TestPolicyEndpointAPIPersistsFreezeStateToOpenVSwitchExternalID`、`TestPolicyEndpointAPIDropsExpiredFreezeStateFromOpenVSwitchExternalID`、`TestReconcileNodeSkipsFrozenPolicyEndpointApply`、`TestRunPolicyFreezeStateWithStoreReportsActiveFrozenEndpoints` |
| Policy rollout | 已实现 | rollout request state, approval, ack, finalize, SLO, HTTP status/body probes, TCP/TLS probes, `/policy/endpoints/rollout/history`, `netloom-agent policy-rollout-history`, and `netloom-agent policy-rollout-state` | agent/control tests、`TestRunPolicyRolloutHistoryWithStoreReportsFilteredJSON`、`TestRunPolicyRolloutStateWithStoreReportsFilteredJSON` |

## 当前缺口

这些不是主路径缺失，但进入生产前还需要补齐：

- 完整部署手册：多节点 OVN/OVS 部署、证书、systemd unit、日志路径和升级顺序。
- 备份恢复手册：OVN NB/SB、Open_vSwitch DB、desired state 和 policy rollout state 的恢复流程。
- 长周期压测：大量 VPC、子网、endpoint、安全组、policy route、LB 和 provider queue 的容量边界。
- 故障剧本：OVN leader failover、OVSDB reconnect、TCX attach 失败、provider parent interface 变化、BPF map pressure。
- 权限和运行时清单：最小 Linux capability、bpffs、memlock、OVS/OVN socket 权限和容器化运行约束。

## 推荐验证命令

日常提交前：

```bash
go test ./...
git diff --check
```

Docker e2e 按用例拆跑：

```bash
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Policy' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Provider' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerControllerReconcileIdempotent' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerControllerProgramsDistributedGatewayAndFloatingIPs' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerLinuxPolicyRouting' -count=1
```
