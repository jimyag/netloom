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
| Provider Network | 已实现 | OVN localnet port + local OVSDB bridge/port/interface，包含 OVS Controller 多目标连接和 master 角色健康汇总 | `TestDockerControllerClearsLocalnetTagWhenProviderVLANIsRemoved`、`TestLibOVSDBProviderSyncerReportsProviderControllerQuorum` |
| VLAN | 已实现 | localnet tag 和本机 provider interface planning | Docker provider VLAN e2e |
| OVS Bridge/Port/Interface | 已实现 | `internal/linuxdatapath/libovsdb_vswitch.go` | `go test ./internal/linuxdatapath` |
| QoS / Queue | 已实现 | Open_vSwitch QoS/Queue rows, tenant classification, and expected row refs in drift status | `go test ./internal/linuxdatapath ./internal/ovn` |
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
| Policy explain | 已实现 | `netloom-agent policy-explain` and agent `/policy/explain` JSON API; reports verdict/reason plus structured `matched_rule` metadata for the matched SecurityGroup rule | `TestRunPolicyExplainReportsSelectorAllow`、`TestPolicyExplainAPIReportsSelectorAllow` |
| Policy status | 已实现 | `netloom-agent policy-status`, agent `/policy/endpoints` JSON API, agent `/policy/endpoints/{endpoint}/revision` revision confirmation API, dry-run `/policy/endpoints/{endpoint}/plan` with policy-map diff entries, rule metadata, and blocking-change risk summary, top policy-map pressure hotspot list with severity, local OVS `netloom_policy_endpoint_status` persistence, `netloom-agent policy-status-export`, and `netloom-agent policy-revision-wait` for endpoint lifecycle revision confirmation | `TestRunPolicyStatusReportsEndpointLifecycleJSON`、`TestPolicyEndpointAPIReportsLifecycleStatus`、`TestPolicyEndpointAPIReportsReadyRevision`、`TestPolicyEndpointAPIReturnsConflictWhenRevisionIsNotReady`、`TestPolicyEndpointAPIPlansDesiredEndpointPolicyMap`、`TestPlanPolicyEndpointReportsBlockingChangeRisk`、`TestRunPolicyStatusExportWithStoreReportsFilteredJSON`、`TestRunPolicyRevisionWaitWithStoreReportsReadyRevision`、`TestRunPolicyRevisionWaitWithStoreTimesOutBeforeTargetRevision`、`TestAgentMetricsPersistsPolicyEndpointStatusToOpenVSwitchExternalID`、`TestReconcileNodeAggregatesPolicyMapPressureSummary` |
| Policy rule observability | 已实现 | agent `/policy/rules` JSON API with endpoint/rule-cookie/rule-ref filters, Prometheus rule counters, local OVS `netloom_policy_rules` persistence, and `netloom-agent policy-rules` | `TestPolicyRulesAPIReportsCatalogAndCounters`、`TestPolicyRulesAPIFiltersByRuleCookie`、`TestRunPolicyRulesWithStoreReportsFilteredJSON`、`TestRunPolicyRulesWithStoreFiltersByRuleRef`、`TestAgentMetricsPersistsPolicyRulesToOpenVSwitchExternalID` |
| Policy update events | 已实现 | agent `/policy/events` JSON API with endpoint/success/remediated/rule-cookie/rule-ref filters, rule cookie/ref attribution, local OVS `netloom_policy_events` persistence, and `netloom-agent policy-events` for recent endpoint policy-map update events | `TestPolicyEventsAPIReportsRecentEndpointEvents`、`TestPolicyEventsAPIFiltersFailedEvents`、`TestRunPolicyEventsWithStoreReportsFilteredJSON`、`TestRunPolicyEventsWithStoreFiltersRemediatedEvents`、`TestAgentMetricsPersistsPolicyEventsToOpenVSwitchExternalID` |
| Policy map entry inspection | 已实现 | `netloom-agent policy-entries`, agent `/policy/entries/{endpoint}` JSON API with rule-cookie/rule-ref filtering and rule metadata attribution, local OVS `netloom_policy_entries` persistence, and `netloom-agent policy-entries-export` for live endpoint policy-map entries | `TestRunPolicyEntriesReportsEndpointMapJSON`、`TestPolicyEntriesAPIReportsEndpointPolicyMapEntries`、`TestPolicyEntriesAPIFiltersEndpointEntriesByRuleCookie`、`TestRunPolicyEntriesExportWithStoreReportsFilteredJSON`、`TestRunPolicyEntriesExportWithStoreFiltersByRuleCookie`、`TestAgentMetricsPersistsPolicyEntriesToOpenVSwitchExternalID` |
| Route explain | 已实现 | `netloom-agent route-explain` and agent `/route/explain` JSON API; reports final action plus structured `policy_route` and `route_table` selections for policy-route/routing debug | `TestRunRouteExplainReportsPolicyRouteReroute`、`TestResolveAllowPolicyRouteContinuesToStaticRoute` |
| Endpoint action history | 已实现 | agent `GET /policy/endpoints/actions/history` and `netloom-agent policy-action-history`; endpoint/action/success/limit filters; persists successful and failed lifecycle actions in local OVS `netloom_policy_endpoint_action_history` when OVSDB is configured | `TestPolicyEndpointAPIPersistsActionHistoryToOpenVSwitchExternalID`、`TestPolicyEndpointActionHistoryAPIFiltersEndpointActionAndLimit`、`TestPolicyEndpointActionHistoryRecordsFailedAction`、`TestRunPolicyActionHistoryWithStoreReportsFilteredJSON` |
| Identity group import/feed/export | 已实现 | `identity-groups-import`, `identity-groups-export`, remote feed env vars, `Open_vSwitch.external_ids:netloom_identity_groups` resolved membership snapshot | controller/agent tests、`TestRunIdentityGroupsExportWithStoreReadsResolvedOpenVSwitchExternalID`、`TestRunIdentityGroupsExportReadsRealOpenVSwitchOVSDB` |
| DNS observer | 已实现 | UDP/TCP proxy, AF_PACKET capture, OVSDB observations, `netloom-agent dns-observations-export` for local observation audit | `go test ./cmd/netloom-dns-observer`、`TestRunDNSObservationsExportWithStoreReadsOpenVSwitchExternalID`、`TestRunDNSObservationsExportReadsRealOpenVSwitchOVSDB` |
| Metrics | 已实现 | controller/agent `/metrics` | command tests |
| Agent runtime selftest | 已实现 | 默认 `netloom-agent` selftest reports policy compile/evaluate, stateful conntrack, TCX status, bpffs, memlock, BPF/NET_ADMIN capabilities, and configured OVSDB/OVN endpoints; long-running reconcile also persists runtime preflight in local OVS status and Prometheus metrics; `NETLOOM_SELFTEST_STRICT_RUNTIME=1` makes selftest required runtime failures fatal; `NETLOOM_RUNTIME_PREFLIGHT_STRICT=1` fail-closes long-running reconcile before policy/TCX/datapath mutation | `TestRunSelfTestCompilesAndEvaluatesPolicy`、`TestRunRuntimePreflightReportsRequiredBPFChecks`、`TestRunRuntimePreflightAcceptsEquivalentCapabilities`、`TestReconcileStateFileOnceWritesAgentStatusToOpenVSwitchExternalID`、`TestReconcileStateFileOnceStrictRuntimePreflightFailsClosed`、`TestAgentMetricsExportsLatestPolicyAndTCXCounters` |
| Agent status CLI | 已实现 | `netloom-agent agent-status` reads local OVS `netloom_agent_status`, including runtime preflight readiness/check details | `TestRunAgentStatusWithStoreReportsOpenVSwitchStatus` |
| Controller status API/CLI | 已实现 | controller `/status` JSON API, `netloom-controller controller-status`, local OVS `netloom_controller_events` persistence, and `netloom-controller controller-events` for OVN health/audit/cluster/stale reconcile history | `TestControllerStatusAPIExportsLatestOVNStatus`、`TestRunControllerStatusWithStoreReportsOpenVSwitchStatus`、`TestRunControllerEventsWithStoreReportsFilteredHistory`、`TestObserveReconcileFailurePersistsControllerEvent` |
| OVN health/audit/maintenance | 已实现 | libovsdb health, endpoint connect status, audit stats, table/field-level drift metrics, compact/stale hooks, DNS `records` column drift detection, endpoint DHCP option attachment drift detection, static-route BFD attachment drift detection, load-balancer health-check options drift detection, and malformed NBCTL row fail-safe incomplete-row accounting | `go test ./cmd/netloom-controller ./internal/ovn`、`TestAuditManagedObjectsFromNBCTLNormalizesDNSRecords`、`TestAuditManagedObjectsFromNBCTLReportsDNSRecordDrift`、`TestNBCTLExecutorManagedOVNRowsResolvesSwitchPortDHCPOptions`、`TestNBCTLExecutorManagedOVNRowsReportsMissingSwitchPortDHCPOptions`、`TestNBCTLExecutorManagedOVNRowsResolvesStaticRouteBFD`、`TestNBCTLExecutorManagedOVNRowsReportsMissingStaticRouteBFD`、`TestNBCTLExecutorAuditCountsMalformedReferenceRowsWithoutPanic` |
| Policy freeze/unfreeze | 已实现 | agent `/policy/endpoints/{endpoint}/freeze` and `/unfreeze`; optional TTL/expiry; keeps frozen policy maps out of normal apply, TCX, rollout, restart cleanup, GC, pressure mitigation deletes, and automatic pressure quarantine; `netloom-agent policy-freeze-state`; persists frozen endpoints in local OVS `netloom_policy_freeze_state` when OVSDB is configured | `TestPolicyEndpointAPIPersistsFreezeStateToOpenVSwitchExternalID`、`TestPolicyEndpointAPIDropsExpiredFreezeStateFromOpenVSwitchExternalID`、`TestReconcileNodeSkipsFrozenPolicyEndpointApply`、`TestReconcilerKeepsFrozenInventoryEndpointMissingAfterRestart`、`TestReconcileNodeKeepsFrozenPolicyEndpointDuringIdleSweep`、`TestReconcileNodeMitigatesPolicyMapPressureKeepsFrozenEndpoint`、`TestReconcileNodeSkipsPressureQuarantineForFrozenEndpoint`、`TestRunPolicyFreezeStateWithStoreReportsActiveFrozenEndpoints` |
| Policy rollout | 已实现 | rollout request state, approval, ack, risk ack gate, risk ack and finalize context in external change-status payloads, strict API completion status, finalize, SLO, HTTP status/body probes, TCP/TLS probes, pressure-aware batch shrinking with hotspot, severity reporting, and Prometheus severity gauge, per-endpoint policy-map diff entries plus aggregated blocking-change risk in rollout plans, frozen endpoint rejection for dry-run and live rollout plans, `/policy/endpoints/rollout/history`, `netloom-agent policy-rollout-history`, and `netloom-agent policy-rollout-state` | agent/control tests、`TestRolloutPolicyEndpointsPressureAwareShrinksBatchSize`、`TestPolicyEndpointAPIRolloutUsesPressureAwareBatchSize`、`TestPolicyEndpointAPIRolloutAppliesMultipleEndpoints`、`TestPolicyEndpointAPIRolloutWaitsForFinalize`、`TestPolicyEndpointAPIRolloutPausesBlockingRiskUntilAcknowledged`、`TestRolloutPolicyEndpointsPausesBlockingRiskUntilRiskAcknowledged`、`TestApplyPolicyRolloutsSyncsRiskAckPendingChangeStatus`、`TestApplyPolicyRolloutsSyncsFinalizePendingChangeStatus`、`TestRolloutPolicyEndpointsAggregatesPlanRisk`、`TestRolloutPolicyEndpointsDryRunFailsFrozenEndpointWithoutApplying`、`TestRunPolicyRolloutHistoryWithStoreReportsFilteredJSON`、`TestRunPolicyRolloutStateWithStoreReportsFilteredJSON` |

## 当前缺口

这些不是主路径缺失，但进入生产前还需要补齐：

- 完整部署手册：多节点 OVN/OVS 部署、证书、systemd unit、日志路径和升级顺序。
- 备份恢复手册：OVN NB/SB、Open_vSwitch DB、desired state 和 policy rollout state 的恢复流程。
- 长周期压测：大量 VPC、子网、endpoint、安全组、policy route、LB 和 provider queue 的容量边界。
- 故障剧本：OVN leader failover、OVSDB reconnect、TCX attach 失败、provider parent interface 变化、BPF map pressure。
- 容器化运行清单：systemd/container unit 中的 capability、mount、rlimit、socket 权限模板。

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
