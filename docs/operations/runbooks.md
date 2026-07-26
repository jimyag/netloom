# 故障处理剧本

本文档记录 `netloom` 生产运行中最常见的故障入口和处理顺序。所有剧本都以先取证、再变更为原则。

## 通用取证

先采集当前状态：

```bash
./netloom-controller controller-status -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-controller controller-events -ovsdb unix:/var/run/openvswitch/db.sock -limit 100
./netloom-agent agent-status -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-agent policy-status -state /etc/netloom/state.json -node node-a
curl -s http://127.0.0.1:9091/status
curl -s http://127.0.0.1:9091/metrics
curl -s http://127.0.0.1:9092/metrics
```

如果问题和特定流量相关，同时采集解释结果：

```bash
./netloom-agent policy-explain -state /etc/netloom/state.json -vpc prod -endpoint vm-a -direction ingress -protocol tcp -remote-ip 10.10.1.20 -dest-port 8080
./netloom-agent route-explain -state /etc/netloom/state.json -vpc prod -source 10.10.0.10 -dest 172.16.0.10 -protocol tcp -dest-port 443
```

## OVN Northbound 不可用

现象：

- controller `/status` 显示 OVN health 失败。
- controller events 中 `ovn_health` 连续失败。
- metrics 中 OVN consecutive failure 增长。

处理：

1. 查看 `controller-status` 中 active endpoint、leader endpoint 和 quorum summary。
2. 如果多 endpoint 配置存在，确认 `NETLOOM_OVN_LIBOVSDB_ENDPOINTS` 覆盖所有 NB 节点。
3. 检查 OVN NB 服务、网络连通性和证书。
4. 恢复任意可达 majority 后等待 controller reconnect。
5. 观察第一个 recovering reconcile 是否成功。

恢复后确认：

- `controller-status` quorum 不是 `lost`。
- `controller-events` 中不再产生新的 `ovn_health=false`。
- live audit missing/unexpected/drift 没有持续增长。

## OVN leader failover

现象：

- active endpoint 发生变化。
- leader endpoint 为空或和预期不一致。
- reconcile latency 暂时升高。

处理：

1. 通过 `controller-status` 查看 leader preference status。
2. 确认 `NETLOOM_OVN_CLUSTER_STATUS_TARGETS` 配置了所有候选 endpoint。
3. 如果当前 leader 不可达，先恢复 OVN 集群，而不是修改 desired state。
4. 如果 failover 后 reconcile 成功，继续观察，不需要手工清理 Netloom-managed rows。

## OVN live audit 出现 drift

现象：

- controller status 或 metrics 中 missing、unexpected、duplicate、incomplete 增长。
- field-level drift 指向 DHCP、DNS、LSP、LRP、NAT、LB、PolicyRoute 或 static route。

处理：

1. 确认 desired state 是当前预期版本。
2. 等待一个完整 controller reconcile 周期。
3. 如果 drift 仍存在，查看 `controller-events` 中 table 和 field 维度的 drift。
4. 对 Netloom-managed 资源，优先让 controller steady-state repair 修复。
5. 如果资源由外部系统手工改写，移除外部写入来源，再触发 reconcile。

不要直接手工改 Netloom-managed OVN 行作为长期修复；否则下一轮 reconcile 仍会覆盖。

## TCX attach 失败

现象：

- agent status 中 TCX 不 ready。
- runtime preflight 指向 bpffs、memlock、BPF capability 或 NET_ADMIN 问题。
- policy map 已编译但没有进入 fast path。

处理：

1. 确认 `/sys/fs/bpf` 已挂载 bpffs。
2. 确认 agent 具备 `CAP_BPF` 或等价能力，以及 `CAP_NET_ADMIN`。
3. 确认 memlock/rlimit 满足 BPF map 和 program 加载。
4. 确认 workload interface 存在且未被其他 datapath 独占。
5. 使用 `NETLOOM_RUNTIME_PREFLIGHT_STRICT=1` 复现 fail-closed 行为，避免半收敛。

恢复后确认：

- `agent-status` runtime preflight ready。
- `/policy/endpoints` 中 endpoint revision ready。
- `policy-events` 没有新的 TCX apply failure。

## Policy map pressure

现象：

- agent metrics 中 policy-map pressure 接近阈值。
- `/policy/endpoints` 报告 top hotspot、recommended capacity 或 overflow。
- policy apply event 失败或触发 pressure remediation。

处理：

1. 查询 hotspot endpoint 和 rule ref。
2. 使用 `policy-entries` 查看该 endpoint 的 live map entry。
3. 检查是否存在过大的 CIDRGroup、FQDN 解析膨胀、selector 扩散或过宽 entity rule。
4. 对高风险变更先使用 dry-run rollout plan。
5. 必要时对单 endpoint quarantine 或 freeze，避免反复失败影响其他 endpoint。

恢复后确认：

- pressure percent 下降。
- latest event success。
- endpoint revision 达到 desired revision。

## Provider parent interface 异常

现象：

- provider network ready=false。
- agent status 出现 `parent-down`、`link-missing`、`link-drift`、`parent-isolation-conflict`、`ovsdb-port-drift`、`ovsdb-interface-drift`。

处理：

1. 核对 `NETLOOM_PROVIDER_NETWORK_LINKS` 和 desired state 中 provider name 是否一致。
2. 检查物理 NIC 是否存在、up、未被错误 provider 共享。
3. 对 `isolation=exclusive` 的 provider，确认没有其他 provider 使用同一 parent。
4. 如果 OVSDB drift 来自外部手工修改，先停止外部写入，再让 agent reconcile。
5. 开启 cleanup 前先确认 stale provider bridge/port/interface 都是 Netloom-owned。

恢复后确认：

- `agent-status` provider ready=true。
- OVSDB mapping 存在并指向预期 bridge。
- subnet localnet VLAN 和本机 provider port 一致。

## PolicyRoute 不符合预期

现象：

- 业务流量没有按预期 reroute/drop/reject。
- 普通 route 可达，但策略路由路径不对。

处理：

1. 使用 `route-explain` 输入 source、destination、protocol、port。
2. 检查命中的 policy route priority、match 和 action。
3. 确认 OVN Logical Router Policy 和 Linux RPDB projection 都已收敛。
4. 如果是 L4 match，确认 protocol 和 dest/source port 与 desired state 一致。
5. 如果 action 是 reroute，确认 next hop 在对应 VPC 和路由域内可达。

## LB backend 健康检查异常

现象：

- LB VIP 存在但 backend 不被选中。
- health-check refs drift 或 backend probe 失败。

处理：

1. 查看 controller events 中 LB health probe 结果。
2. 确认 backend IP 属于期望 VPC/subnet，端口和协议匹配。
3. 检查 health check interval、timeout、success/failure threshold。
4. 观察 OVN Load_Balancer 和 Load_Balancer_Health_Check managed row drift。
5. 恢复 backend 后等待 controller 收敛 health 状态。

## FQDN policy 不生效

现象：

- `remote_fqdns` 规则没有生成预期 CIDR entry。
- DNS observer 没有 observation。

处理：

1. 确认 `netloom-dns-observer` 使用 OVSDB 写入 observations。
2. 检查 UDP/TCP proxy 或 AF_PACKET capture 是否能看到 DNS response。
3. 确认 DNS record 未过期。
4. 查询 agent policy entries，确认 hostname 已展开为 A/AAAA 地址。
5. 如果解析结果过多，检查 `NETLOOM_FQDN_ENDPOINT_MAX_IP_PER_HOSTNAME` 和 policy map pressure。
