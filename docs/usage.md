# 使用说明

本文档描述 `netloom` 在裸金属环境中的基本使用方式。当前项目不集成 Kubernetes，也不依赖 Kubernetes CRD；所有网络意图来自 desired state JSON 或写入本机 Open_vSwitch OVSDB 的 desired state。

如果要先跑通最短路径，看 [快速开始](quickstart.md)。如果只想快速确认目前实现了哪些能力，先看 [当前实现状态](current-status.md)。如果要查完整能力和测试入口，看 [功能矩阵](features.md)。

## 能力清单

| 能力 | 实现位置 | 说明 |
| --- | --- | --- |
| VPC / Subnet / Endpoint / IPAM | controller + OVN NB | 创建逻辑路由器、逻辑交换机、端口、地址和端口安全。 |
| DHCP / DNS | OVN NB | 为 endpoint 绑定 DHCP options，并维护 OVN DNS records。 |
| Gateway / NAT / LoadBalancer | OVN NB | 支持 SNAT、DNAT、Floating IP、OVN LB、SCTP/TCP/UDP frontend、健康检查和 subnet 绑定。 |
| RouteTable / PolicyRoute | OVN NB + Linux datapath | 支持静态路由、ECMP、BFD、reroute/drop 策略路由、本机 RPDB 投影和 SCTP/TCP/UDP 端口匹配。 |
| Provider Network | OVN localnet + OVSDB | 管理 localnet port、本机 OVS Bridge、Controller、Port、Interface、QoS、Queue。 |
| SecurityGroup / ACL | eBPF policy map + TCX | 安全组不写 OVN ACL，规则由 eBPF/TCX 执行，支持 TCP、UDP、SCTP、ICMP。 |
| Policy rollout | agent | 支持 dry-run、batch、approval、ack、finalize、SLO、HTTP status/body probe、TCP/TLS probe、rollback、quarantine。 |
| 运维观测 | OVSDB external_ids + metrics + CLI | 输出 controller/agent 状态、policy status、explain、Prometheus metrics。 |

## 构建

```bash
go test ./...
go build ./cmd/netloom-controller ./cmd/netloom-agent ./cmd/netloom-dns-observer
```

## 前置条件

裸金属节点需要先准备好基础运行环境：

| 组件 | 用途 |
| --- | --- |
| OVN Northbound DB | controller 写入 VPC、子网、端口、路由、NAT、LB、DHCP、DNS 等逻辑网络对象。 |
| Open vSwitch DB | agent 写入 provider bridge、port、interface、QoS、Queue、运行状态和可选 desired state。 |
| Linux netlink 权限 | agent 创建或清理 netns、veth、地址、路由、RPDB rule 和 provider parent link。 |
| bpffs / memlock / CAP_BPF | `NETLOOM_POLICY_STORE=ebpf` 和 TCX ACL fast path 需要 BPF map 与程序加载能力。 |
| provider parent NIC | `NETLOOM_PROVIDER_NETWORK_LINKS` 指向的物理口或上联口，例如 `physnet-a=eth1`。 |

安全组和 ACL 不写 OVN ACL；OVN 负责拓扑和服务对象，eBPF/TCX 负责 endpoint ingress/egress 策略执行。

不带 `NETLOOM_STATE_FILE` 和 `NETLOOM_OVSDB_ENDPOINT` 启动 `netloom-agent` 时，会运行本地 selftest。
selftest 会验证策略编译、stateful conntrack、policy event/counter 路径，并输出 runtime preflight：
`bpffs`、`memlock`、`cap_bpf_or_sys_admin`、`cap_net_admin`、OVSDB endpoint 和 OVN NB endpoint。
默认只报告 runtime 问题；设置 `NETLOOM_SELFTEST_STRICT_RUNTIME=1` 后，必要检查失败会让 selftest 直接失败。
长运行 agent 可以设置 `NETLOOM_RUNTIME_PREFLIGHT_STRICT=1`，在必要 runtime check 失败时
fail closed，不继续写 policy map、TCX 或本机 datapath，并把失败写入 `netloom_agent_status`。

## Desired State 示例

保存为 `/etc/netloom/state.json`：

```json
{
  "vpcs": [
    {"name": "prod"}
  ],
  "provider_networks": [
    {
      "name": "physnet-a",
      "isolation": "exclusive",
      "controller_targets": ["tcp:192.0.2.10:6653"],
      "nodes": [
        {"node": "node-a", "interface": "eth1"}
      ],
      "qos": {
        "egress_rate_bps": 1000000000
      },
      "tenant_queues": [
        {
          "tenant": "prod",
          "queue_id": 10,
          "protocol": "tcp",
          "ports": [{"from": 443, "to": 443}],
          "max_rate_bps": 500000000
        }
      ]
    }
  ],
  "subnets": [
    {
      "name": "apps",
      "vpc": "prod",
      "cidr": "10.10.0.0/24",
      "gateway": "10.10.0.1",
      "provider_network": "physnet-a",
      "vlan": 100,
      "dhcp": {
        "enabled": true,
        "dns_servers": ["10.10.0.53"],
        "domain_name": "prod.local"
      }
    }
  ],
  "endpoints": [
    {
      "id": "vm-a",
      "vpc": "prod",
      "subnet": "apps",
      "ip": "10.10.0.10",
      "mac": "02:00:00:00:00:10",
      "node": "node-a",
      "security_groups": ["web"],
      "labels": {"app": "web", "env": "prod"},
      "named_ports": [
        {"name": "http", "protocol": "tcp", "port": 8080}
      ]
    }
  ],
  "gateways": [
    {
      "name": "gw-a",
      "vpc": "prod",
      "node": "node-a",
      "external_if": "eth0",
      "lan_ip": "10.10.0.254"
    }
  ],
  "route_tables": [
    {
      "name": "main",
      "vpc": "prod",
      "routes": [
        {
          "destination": "0.0.0.0/0",
          "next_hops": ["10.10.0.254"]
        }
      ]
    }
  ],
  "policy_routes": [
    {
      "name": "via-fw",
      "vpc": "prod",
      "priority": 100,
      "match": {
        "source": "10.10.0.0/24",
        "destination": "172.16.0.0/16",
        "protocol": "tcp",
        "dst_ports": [{"from": 443, "to": 443}]
      },
      "action": {
        "type": "reroute",
        "next_hops": ["10.10.0.253"]
      }
    }
  ],
  "nat_rules": [
    {
      "name": "egress",
      "vpc": "prod",
      "type": "snat",
      "match_cidr": "10.10.0.0/24",
      "external_ip": "198.51.100.10"
    }
  ],
  "load_balancers": [
    {
      "name": "web",
      "vpc": "prod",
      "vip": "10.96.0.10",
      "ports": [
        {
          "name": "http",
          "port": 80,
          "protocol": "tcp",
          "backends": [
            {"ip": "10.10.0.10", "port": 8080, "healthy": true}
          ]
        }
      ],
      "subnets": ["apps"],
      "health_check": {
        "enabled": true,
        "interval": 10,
        "timeout": 30,
        "success_count": 2,
        "failure_count": 4
      }
    }
  ],
  "security_groups": [
    {
      "name": "web",
      "vpc": "prod",
      "tier": 1,
      "rules": [
        {
          "id": "allow-client-http",
          "priority": 10,
          "direction": "ingress",
          "protocol": "tcp",
          "remote_cidr": "10.10.1.0/24",
          "named_ports": ["http"],
          "action": "allow",
          "stateful": true
        },
        {
          "id": "allow-world-https",
          "priority": 20,
          "direction": "egress",
          "protocol": "tcp",
          "remote_entities": ["world"],
          "ports": [{"from": 443, "to": 443}],
          "action": "allow"
        },
        {
          "id": "deny-ssh",
          "priority": 30,
          "direction": "ingress",
          "protocol": "tcp",
          "remote_entities": ["all"],
          "ports": [{"from": 22, "to": 22}],
          "action": "drop"
        }
      ]
    }
  ],
  "dns_records": [
    {
      "name": "api.example.com",
      "ips": ["203.0.113.10"],
      "ttl_seconds": 60,
      "observed_at": "2026-07-12T00:00:00Z"
    }
  ]
}
```

## 运行 Controller

Controller 负责把 desired state 收敛到 OVN Northbound。

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock \
NETLOOM_RECONCILE_INTERVAL_MS=5000 \
NETLOOM_CONTROLLER_METRICS_ADDR=:9091 \
./netloom-controller
```

常用环境变量：

| 变量 | 说明 |
| --- | --- |
| `NETLOOM_STATE_FILE` | desired state JSON 文件路径。 |
| `NETLOOM_OVSDB_ENDPOINT` | 从本机 Open_vSwitch OVSDB 读取 desired state，并写 controller 状态。 |
| `NETLOOM_OVN_LIBOVSDB_ENDPOINT` | OVN NB OVSDB endpoint。 |
| `NETLOOM_OVN_LIBOVSDB_ENDPOINTS` | 多 OVN NB endpoint，适合集群模式。 |
| `NETLOOM_RECONCILE_INTERVAL_MS` | 周期 reconcile 间隔；未设置时执行一次。 |
| `NETLOOM_CONTROLLER_METRICS_ADDR` | controller Prometheus metrics 监听地址。 |

## 运行 Agent

Agent 负责本机 Linux datapath、Provider OVSDB、eBPF/TCX ACL 和 policy rollout。

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_NODE_NAME=node-a \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
NETLOOM_POLICY_STORE=ebpf \
NETLOOM_TCX_WORKLOAD=1 \
NETLOOM_LINUX_DATAPATH=1 \
NETLOOM_LINUX_DATAPATH_MODE=netns \
NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth1 \
NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-b=172.30.0.12 \
NETLOOM_LINUX_DATAPATH_CLEANUP=1 \
NETLOOM_AGENT_METRICS_ADDR=:9092 \
./netloom-agent
```

常用环境变量：

| 变量 | 说明 |
| --- | --- |
| `NETLOOM_NODE_NAME` | 当前裸金属节点名，用于筛选本节点 endpoint、gateway 和 provider network。 |
| `NETLOOM_OVSDB_ENDPOINT` | 本机 Open_vSwitch OVSDB endpoint。 |
| `NETLOOM_POLICY_STORE` | 设置为 `ebpf` 时使用 eBPF policy store。 |
| `NETLOOM_TCX_IFACE` | 在指定节点接口上 attach TCX ACL。 |
| `NETLOOM_TCX_WORKLOAD` | 设置为 `1` 时为工作负载 veth attach TCX ACL。 |
| `NETLOOM_LINUX_DATAPATH` | 设置为 `1` 时启用 Linux datapath。 |
| `NETLOOM_LINUX_DATAPATH_MODE` | `local` 或 `netns`。 |
| `NETLOOM_PROVIDER_NETWORK_LINKS` | provider network 到本机 parent interface 的映射，例如 `physnet-a=eth1`。 |
| `NETLOOM_NODE_UNDERLAYS` | 节点 underlay 地址映射，用于跨节点路由。 |
| `NETLOOM_LINUX_DATAPATH_CLEANUP` | 设置为 `1` 时清理本机托管的旧地址、路由和 rule。 |
| `NETLOOM_AGENT_METRICS_ADDR` | agent Prometheus metrics 监听地址。 |

## 推荐运行顺序

1. 准备 OVN NB 和本机 Open_vSwitch DB socket。
2. 写好 `/etc/netloom/state.json`，或用 `desired-state-import` 写入本机 OVSDB。
3. 启动 controller，确认 OVN NB 中生成 logical router、logical switch、port、route、NAT、LB、DHCP/DNS row。
4. 在每个裸金属节点启动 agent，确认本机 provider bridge、Linux datapath、eBPF policy map 和 TCX attach 状态。
5. 用 `policy-status`、`policy-explain`、`route-explain` 和 `/metrics` 做功能验证。

## 最小验收清单

下面这组检查用于判断主路径是否已经跑通。它不替代 e2e，但适合作为裸金属节点上的人工验收步骤。

| 能力 | 验收方式 | 预期结果 |
| --- | --- | --- |
| VPC / Subnet / Endpoint | `controller-status`、OVN NB logical router/switch/port | desired state 中的 VPC、子网和 endpoint 都被写入 OVN。 |
| DHCP / DNS | `controller-events`、OVN NB `DHCP_Options`/`DNS` | endpoint 绑定 DHCP options，DNS records 没有 drift。 |
| Gateway / NAT / LB | `controller-status`、OVN NB router NAT/LB rows | SNAT、DNAT/Floating IP、LB VIP 和 health check 与 desired state 一致。 |
| RouteTable / PolicyRoute | `route-explain`、OVN router static route/policy rows | 普通路由、ECMP/BFD 和策略路由选择结果符合预期。 |
| Provider Network | `agent-status`、Open_vSwitch bridge/port/interface/qos/queue | 本机 provider bridge、VLAN、QoS/Queue 和 controller 连接状态正常。 |
| Linux datapath | `agent-status`、`ip netns`、`ip rule`、`ip route` | 工作负载 netns/veth、地址、路由和 RPDB rule 被正确创建。 |
| SecurityGroup / ACL | `policy-status`、`policy-entries`、`policy-explain` | endpoint policy map 已生成，TCX 规则判定与安全组规则一致。 |
| Rollout / lifecycle | `policy-rollout-state`、`policy-action-history` | rollout、freeze、quarantine、rollback 等动作有明确状态和历史记录。 |
| 观测和持久化 | `/metrics`、Open_vSwitch `external_ids` | controller/agent 状态、policy events、rules、entries 和 metrics 可查询。 |

## Desired State 存入 OVSDB

裸金属场景下可以把 desired state 放到本机 Open_vSwitch 数据库，避免 controller/agent 都依赖同一个文件路径。
这里的 OVSDB 存储只保存 Netloom 的输入意图和运行状态，不替代 OVN Northbound DB：

- `Open_vSwitch.external_ids:netloom_desired_state` 保存 desired state JSON。
- `Open_vSwitch.external_ids:netloom_desired_state_revision` 保存 JSON 的 SHA256 revision，用于防止读到不完整或不匹配的状态。
- OVN Northbound DB 仍然是 VPC、子网、端口、路由、NAT、LB、DHCP、DNS 等逻辑网络对象的真实写入目标。
- 本机 Open_vSwitch DB 还保存 provider bridge/port/interface/QoS/Queue，以及 controller/agent 状态和 policy 观测结果。

导入：

```bash
./netloom-agent desired-state-import -ovsdb unix:/var/run/openvswitch/db.sock < /etc/netloom/state.json
```

导出：

```bash
./netloom-agent desired-state-export -ovsdb unix:/var/run/openvswitch/db.sock
```

之后 controller 和 agent 都可以只配置 `NETLOOM_OVSDB_ENDPOINT`，从 `Open_vSwitch.external_ids:netloom_desired_state` 读取 desired state。

## 运维检查

查看 OVSDB 中的运行状态：

```bash
./netloom-controller controller-status -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-controller controller-events -ovsdb unix:/var/run/openvswitch/db.sock -limit 20
./netloom-agent agent-status -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-agent dns-observations-export -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-agent identity-groups-export -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-agent policy-status-export -ovsdb unix:/var/run/openvswitch/db.sock -endpoint prod/vm-a
./netloom-agent policy-revision-wait -ovsdb unix:/var/run/openvswitch/db.sock -endpoint prod/vm-a -revision 3 -timeout 30s
curl -s 'http://127.0.0.1:9092/policy/endpoints/prod/vm-a/revision?target_revision=3&timeout_ms=30000'
./netloom-agent policy-entries-export -ovsdb unix:/var/run/openvswitch/db.sock -endpoint prod/vm-a
./netloom-agent policy-entries-export -ovsdb unix:/var/run/openvswitch/db.sock -rule-cookie 42
./netloom-agent policy-rules -ovsdb unix:/var/run/openvswitch/db.sock -endpoint prod/vm-a
./netloom-agent policy-rules -ovsdb unix:/var/run/openvswitch/db.sock -rule-cookie 42
./netloom-agent policy-rules -ovsdb unix:/var/run/openvswitch/db.sock -rule-ref sg/web/allow-http
./netloom-agent policy-events -ovsdb unix:/var/run/openvswitch/db.sock -endpoint prod/vm-a -limit 20
./netloom-agent policy-events -ovsdb unix:/var/run/openvswitch/db.sock -success false -limit 20
./netloom-agent policy-events -ovsdb unix:/var/run/openvswitch/db.sock -remediated true -limit 20
./netloom-agent policy-events -ovsdb unix:/var/run/openvswitch/db.sock -rule-cookie 42 -limit 20
./netloom-agent policy-events -ovsdb unix:/var/run/openvswitch/db.sock -rule-ref prod/web/allow-http -limit 20
ovs-vsctl get Open_vSwitch . external_ids:netloom_controller_status
ovs-vsctl get Open_vSwitch . external_ids:netloom_controller_events
ovs-vsctl get Open_vSwitch . external_ids:netloom_agent_status
ovs-vsctl get Open_vSwitch . external_ids:netloom_dns_observations
ovs-vsctl get Open_vSwitch . external_ids:netloom_identity_groups
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_endpoint_status
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_entries
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_rules
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_events
```

`controller-status` CLI 会解码 `Open_vSwitch.external_ids:netloom_controller_status`，
用于查看最近一次 controller reconcile 的 desired object 计数、OVN health、OVN audit、
cluster quorum、stale advisory、maintenance 和错误状态。
`controller-events` CLI 会解码 `Open_vSwitch.external_ids:netloom_controller_events`，
用于查看最近 controller reconcile 成功/失败、失败阶段、OVN health、cluster quorum、
audit、stale advisory 和 maintenance 摘要；可用 `-phase`、`-success` 和 `-limit`
过滤。
`agent-status` CLI 会解码 `Open_vSwitch.external_ids:netloom_agent_status`，
用于查看最近一次 agent reconcile 的 policy/eBPF rollout、TCX、runtime preflight、
provider、datapath 和错误状态。
`dns-observations-export` 会解码 `Open_vSwitch.external_ids:netloom_dns_observations`，
用于查看 DNS observer 或外部 DNS feed 当前写入的 FQDN 到 A/AAAA 观测，
这些记录会参与 `remote_fqdns` egress policy 编译。
`identity-groups-export` 默认导出 `Open_vSwitch.external_ids:netloom_identity_groups`，
也就是 agent 根据 desired state、identity group feed 和 endpoint 解析出的当前成员快照；
如果要查看原始导入或远端 feed 观测，可加 `-source observations` 导出
`Open_vSwitch.external_ids:netloom_identity_group_observations`。
`policy-status-export` 会解码 `Open_vSwitch.external_ids:netloom_policy_endpoint_status`，
用于在不重新 reconcile desired state、不访问 agent HTTP listener 的情况下审计 endpoint
policy lifecycle、revision、pressure、drift、last event 和 last stats。
`policy-revision-wait` 会轮询同一个 OVSDB 状态，直到指定 endpoint 的 policy revision
达到目标值，适合在 rollout、变更审批或自动化验证中确认 eBPF policy map 已经落地。
agent HTTP API 也提供 `/policy/endpoints/{endpoint}/revision?target_revision=N`，
用于在线系统直接等待长运行 agent 的最新内存状态；可加 `timeout_ms` 和 `interval_ms`。
`policy-entries-export` 会解码 `Open_vSwitch.external_ids:netloom_policy_entries`，
用于在不访问 agent HTTP listener 的情况下审计最近一次 reconcile 写入的 live policy-map
keys、values、计数器和 remote CIDR。
`policy-rules` 和 `policy-events` 分别解码 `netloom_policy_rules` 与
`netloom_policy_events`，用于查看规则来源、规则级 counter 和 endpoint policy-map
更新事件。

查看安全策略状态：

```bash
./netloom-agent policy-status -state /etc/netloom/state.json -node node-a
./netloom-agent policy-status-export \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -endpoint prod/vm-a
./netloom-agent policy-revision-wait \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -endpoint prod/vm-a \
  -revision 3 \
  -timeout 30s
curl -s \
  'http://127.0.0.1:9092/policy/endpoints/prod/vm-a/revision?target_revision=3&timeout_ms=30000'
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_endpoint_status
./netloom-agent policy-entries -state /etc/netloom/state.json -node node-a -endpoint prod/vm-a
```

`policy-status` 会从 desired state 重新 reconcile 到临时 policy store 后输出状态；
`policy-status-export` 读取 agent 最近一次真实 reconcile 写入本机 OVSDB 的 lifecycle
快照，更适合线下审计正在运行节点的 eBPF policy map 状态。
正常状态下，单个 endpoint 应能看到当前 `revision`、policy-map `entries`、容量压力、
drift 结果、最近一次策略更新时间 `last_seen`，以及最近一次更新事件和统计计数。
`policy-revision-wait` 不会触发 reconcile，只读取本机 OVSDB 中的 live status，并在目标
revision 未按时出现时返回错误。
HTTP revision API 读取长运行 agent 当前内存快照：达到目标 revision 返回 200 和 endpoint
status，endpoint 不存在返回 404，目标 revision 未按时出现返回 409。

解释一条安全策略判定：

```bash
./netloom-agent policy-explain \
  -state /etc/netloom/state.json \
  -vpc prod \
  -endpoint vm-a \
  -direction ingress \
  -protocol tcp \
  -remote-ip 10.10.1.20 \
  -dest-port 8080
```

命中安全组规则时，`policy-explain` 会输出 `matched_rule`，包含 rule cookie、
rule ref、VPC、安全组名称、规则 ID、tier、priority、direction、protocol、action、
stateful 和 log 标记。这个字段用于从一次策略判定直接反查到 Cilium-style policy map
里的规则来源。

解释一条路由判定：

```bash
./netloom-agent route-explain \
  -state /etc/netloom/state.json \
  -vpc prod \
  -source 10.10.0.10 \
  -dest 172.16.0.10 \
  -protocol tcp \
  -dest-port 443
```

`route-explain` 会输出最终 action、选中的 next hop、gateway、NAT/LB 转换结果，
并在命中策略路由时给出结构化 `policy_route` 字段，包括策略路由名称、VPC、
priority、action、match、ECMP next hops 和本次流量选中的 next hop。
如果 allow 类型策略路由继续进入静态路由查找，输出里还会包含 `route_table` 字段，
用于确认最终命中的路由表、目的前缀和静态路由 next hop。

查看 Prometheus metrics：

```bash
curl -s http://127.0.0.1:9091/metrics
curl -s http://127.0.0.1:9092/metrics
```

查看 controller 最新 OVN 健康、集群、audit 和 stale 状态：

```bash
curl -s http://127.0.0.1:9091/status
```

查看最新规则级安全组计数和规则来源：

```bash
curl -s http://127.0.0.1:9092/policy/rules
curl -s http://127.0.0.1:9092/policy/rules/prod/vm-a
curl -s 'http://127.0.0.1:9092/policy/rules?rule_cookie=42'
curl -s 'http://127.0.0.1:9092/policy/rules?rule_ref=sg/web/allow-http'
netloom-agent policy-rules \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -endpoint prod/vm-a
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_rules
```

如果 agent 配置了 `NETLOOM_OVSDB_ENDPOINT`，最近一次 reconcile 的 rule catalog 和
rule counter 合并视图会写入 `Open_vSwitch.external_ids:netloom_policy_rules`。
`policy-rules` CLI 会从本机 OVSDB 读取同一个 key，适合在没有打开 agent HTTP listener
时审计 Cilium-style rule counter 和规则来源映射。
HTTP API 和 CLI 都支持按 endpoint、rule cookie 或 rule ref 过滤，便于从 eBPF/TCX
计数器里的 cookie 反查对应安全组规则。

查看最近 endpoint policy map 更新事件：

```bash
curl -s 'http://127.0.0.1:9092/policy/events?limit=100'
curl -s 'http://127.0.0.1:9092/policy/events/prod/vm-a?limit=20'
```

查看某个 endpoint 当前 live policy map entries：

```bash
curl -s http://127.0.0.1:9092/policy/entries/prod/vm-a
curl -s 'http://127.0.0.1:9092/policy/entries/prod/vm-a?rule_cookie=42'
curl -s 'http://127.0.0.1:9092/policy/entries/prod/vm-a?rule_ref=prod/web/allow-http'
curl -s 'http://127.0.0.1:9092/policy/entries?endpoint=prod/vm-a'
netloom-agent policy-entries-export \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -endpoint prod/vm-a
netloom-agent policy-entries-export \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -rule-cookie 42
netloom-agent policy-entries-export \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -rule-ref prod/web/allow-http
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_entries
```

如果 agent 配置了 `NETLOOM_OVSDB_ENDPOINT`，最近一次 reconcile 的 endpoint
policy-map entries 会写入 `Open_vSwitch.external_ids:netloom_policy_entries`。
HTTP 接口适合在线排查，`policy-entries-export` 适合从本机 OVSDB 做离线审计。
两者都支持 rule cookie 和 rule ref 过滤，并在 entry 里输出 rule ref、VPC、安全组和规则 ID，
便于从规则计数器继续定位实际 policy-map key/value。

临时冻结或恢复某个 endpoint 的 policy map 更新：

```bash
curl -X POST http://127.0.0.1:9092/policy/endpoints/prod/vm-a/freeze
curl -X POST http://127.0.0.1:9092/policy/endpoints/prod/vm-a/freeze \
  -d '{"ttl_seconds":600}'
curl -X POST http://127.0.0.1:9092/policy/endpoints/prod/vm-a/freeze \
  -d '{"expires_at":"2026-07-17T10:30:00Z"}'
curl -s http://127.0.0.1:9092/policy/endpoints | jq '.frozen_endpoints'
curl -s http://127.0.0.1:9092/policy/endpoints | jq '.frozen_endpoint_expiry'
curl -X POST http://127.0.0.1:9092/policy/endpoints/prod/vm-a/unfreeze
```

如果 agent 配置了 `NETLOOM_OVSDB_ENDPOINT`，冻结列表会保存到本机
`Open_vSwitch.external_ids:netloom_policy_freeze_state`。agent 重启后会从
这个 key 恢复冻结状态，直到显式执行 `/unfreeze` 或冻结过期。
冻结状态也会保护对应 endpoint policy map 不被重启 stale cleanup、idle GC
或 policy-map pressure mitigation 删除，也不会被自动 pressure quarantine 改写。
可以直接从本机 OVSDB 查看当前有效冻结状态：

```bash
netloom-agent policy-freeze-state \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -endpoint prod/vm-a
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_freeze_state
```

`policy-freeze-state` CLI 会去重并过滤已经过期的冻结记录，支持按 `endpoint`
查询某个 endpoint 当前是否被冻结。

预览某个 endpoint 下一次 policy-map 更新：

```bash
curl -X POST http://127.0.0.1:9092/policy/endpoints/prod/vm-a/plan
```

`/plan` 是 dry-run，只读取当前 live policy map 并编译最新 desired state，不会写入
eBPF map 或改变 revision。响应里的 `plan` 包含 add/update/delete/unchanged 计数，
以及 `added_entries`、`updated_entries`、`deleted_entries`、`unchanged_entries`
明细；entry 会带 rule ref、VPC、安全组和规则 ID，适合在 approval、ack 或 rollout
前审查实际将变化的 policy-map key/value。`plan.risk` 会标记新增 deny/reject、
更新为 deny/reject、删除 allow entry 这类可能扩大阻断面的变化。

分批预览或执行多个 endpoint 的 staged rollout：

```bash
curl -s -X POST http://127.0.0.1:9092/policy/endpoints/rollout \
  -d '{"endpoints":["prod/vm-a","prod/vm-b"],"batch_size":1,"dry_run":true}'
```

rollout 响应里的每个 `items[].plan` 使用和单 endpoint `/plan` 相同的 diff
结构。`dry_run:true` 只生成每个 endpoint 的 staged 变更计划，不写 live policy map；
正式 rollout 时同一字段可用于确认每个 batch 实际应用前计划的 add/update/delete 明细。
顶层 `rollout.risk` 会聚合所有 endpoint plan 的阻断风险，便于 approval/ack/finalize
检查点先看整次变更的风险面。
API 响应顶层的 `rolled_out` 只表示整次 rollout 已完成并且没有 pending、paused、
cancelled、expired、rollback failure、SLO/probe failure 或剩余 skipped endpoint；
canary 已应用但等待 finalize、promotion limit、pause_after_batches 等部分完成状态都会返回
`rolled_out:false`，需要继续用 `rollout.items[].phase/reason` 判断每个 endpoint 状态。
如果希望 deny/reject 或删除 allow 这类阻断性变更必须先经过人工确认，可以在请求或
desired-state `policy_rollouts[]` 中设置 `risk_ack_required:true`。当 `rollout.risk.blocking_change`
为 true 且没有 `risk_acknowledged:true` 时，live rollout 会以 `risk_ack_pending` 暂停，
不会写入 live policy map；确认后带上 `risk_acknowledged:true` 和可选 `risk_ack_ref`
重新提交即可继续。
如果配置了 `change_status_url`，agent 会把 `risk_ack_required`、`risk_acknowledged`、
`risk_ack_pending`、`risk_ack_ref` 和 `risk_blocking_change` 一起同步给外部变更系统，
便于变更单区分普通暂停和需要人工确认的高风险 eBPF policy-map 变更。
finalize checkpoint 也会同步 `finalize_required`、`finalized`、`finalize_ref`、
`finalize_pending` 和 `finalize_expired`，用于把 canary 后的人工放量确认接入变更系统。

查看 endpoint policy lifecycle 动作历史：

```bash
curl -s http://127.0.0.1:9092/policy/endpoints/actions/history
curl -s 'http://127.0.0.1:9092/policy/endpoints/actions/history?endpoint=prod/vm-a&action=freeze&limit=20'
curl -s 'http://127.0.0.1:9092/policy/endpoints/actions/history?action=regenerate&success=false'
netloom-agent policy-action-history \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -endpoint prod/vm-a \
  -action regenerate \
  -success false
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_endpoint_action_history
```

如果 agent 配置了 `NETLOOM_OVSDB_ENDPOINT`，`delete`、`regenerate`、
`freeze`、`unfreeze`、`quarantine`、`unquarantine` 和 `rollback` 的成功或失败
都会写入 `Open_vSwitch.external_ids:netloom_policy_endpoint_action_history`，用于节点本地审计。
失败记录包含 `success:false` 和 `error`。API 支持按 `endpoint`、`action`、
`success` 和 `limit` 查询最近的相关动作。`policy-action-history` CLI 会从本机
Open_vSwitch OVSDB 读取同一个 key，适合在没有打开 agent HTTP listener 时做节点本地审计。

查看最近的 policy map 更新事件：

```bash
curl -s http://127.0.0.1:9092/policy/events
curl -s 'http://127.0.0.1:9092/policy/events/prod/vm-a?limit=20'
curl -s 'http://127.0.0.1:9092/policy/events?success=false&limit=20'
curl -s 'http://127.0.0.1:9092/policy/events?remediated=true&limit=20'
curl -s 'http://127.0.0.1:9092/policy/events?rule_cookie=42&limit=20'
curl -s 'http://127.0.0.1:9092/policy/events?rule_ref=prod/web/allow-http&limit=20'
netloom-agent policy-events \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -endpoint prod/vm-a \
  -limit 20
netloom-agent policy-events \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -success false \
  -limit 20
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_events
```

如果 agent 配置了 `NETLOOM_OVSDB_ENDPOINT`，最近的 endpoint policy map 更新事件会写入
`Open_vSwitch.external_ids:netloom_policy_events`，包括 endpoint、revision、diff stats、
rule cookies、rule refs、success/error 和 overflow remediation 信息，用于节点重启后继续审计 Cilium-style policy
regeneration 结果。HTTP API 和 CLI 都支持按 endpoint、success、remediated、rule cookie 和 rule ref 过滤，
便于直接定位失败更新或自动 remediation 事件。

查看 endpoint policy rollout 历史：

```bash
curl -s http://127.0.0.1:9092/policy/endpoints/rollout/history
netloom-agent policy-rollout-history \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -source manual \
  -limit 20
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_rollout_history
```

如果 agent 配置了 `NETLOOM_OVSDB_ENDPOINT`，manual 和 desired-state rollout
历史会写入 `Open_vSwitch.external_ids:netloom_policy_rollout_history`。
`policy-rollout-history` CLI 支持按 `source`、`name` 和 `limit` 查询最近的 rollout，
用于查看 approval、ack、finalize、SLO/probe、rollback 等 staged policy rollout 结果。

查看 desired-state policy rollout 的恢复状态：

```bash
netloom-agent policy-rollout-state \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -node node-a
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_rollout_state
```

`policy-rollout-state` CLI 会读取 `Open_vSwitch.external_ids:netloom_policy_rollout_state`，
支持按 `name` 和 `node` 过滤，用于确认 rollout 断点恢复时哪些 endpoint 已经应用、
哪些 rollout 处于 paused 或 failed 状态。

检查本机托管网络对象：

```bash
ip netns list
ip link show
ip rule show
ovs-vsctl show
```

如果 e2e 或本地验证异常中断，先打开清理模式重新运行 agent，再检查是否仍有 Netloom 托管对象残留：

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_NODE_NAME=node-a \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
NETLOOM_LINUX_DATAPATH=1 \
NETLOOM_LINUX_DATAPATH_CLEANUP=1 \
./netloom-agent
```

## 测试

常规测试：

```bash
go test ./...
```

Docker e2e 默认不会自动运行，需要显式打开：

```bash
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Policy' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Provider' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerControllerReconcileIdempotent' -count=1
```

e2e 会操作网络命名空间、veth、OVS/OVN 或容器环境，建议按用例拆开跑，并在异常中断后先检查本机是否残留托管网卡、netns 或 OVSDB row。

## 使用边界

- 这是裸金属 SDN 产品，不做 Kubernetes CRD、CNI 或 kube-apiserver 集成。
- 安全组和 ACL 的执行路径是 eBPF/TCX，不是 OVN ACL。
- OVN/OVSDB 是系统状态源之一，controller/agent 会直接读写相关数据库。
- 当前核心功能已经实现，但生产环境还需要补齐部署拓扑、升级流程、备份恢复、告警规则和长周期压测手册。
