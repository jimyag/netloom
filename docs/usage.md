# 使用说明

本文档描述 `netloom` 在裸金属环境中的基本使用方式。当前项目不集成 Kubernetes，也不依赖 Kubernetes CRD；所有网络意图来自 desired state JSON 或写入本机 Open_vSwitch OVSDB 的 desired state。

如果只想快速确认目前实现了哪些能力，先看 [当前实现状态](current-status.md)。如果要查完整能力和测试入口，看 [功能矩阵](features.md)。

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

## Desired State 存入 OVSDB

裸金属场景下可以把 desired state 放到本机 Open_vSwitch 数据库，避免 controller/agent 都依赖同一个文件路径。

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
./netloom-agent policy-entries-export -ovsdb unix:/var/run/openvswitch/db.sock -endpoint prod/vm-a
./netloom-agent policy-rules -ovsdb unix:/var/run/openvswitch/db.sock -endpoint prod/vm-a
./netloom-agent policy-events -ovsdb unix:/var/run/openvswitch/db.sock -endpoint prod/vm-a -limit 20
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
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_endpoint_status
./netloom-agent policy-entries -state /etc/netloom/state.json -node node-a -endpoint prod/vm-a
```

`policy-status` 会从 desired state 重新 reconcile 到临时 policy store 后输出状态；
`policy-status-export` 读取 agent 最近一次真实 reconcile 写入本机 OVSDB 的 lifecycle
快照，更适合线下审计正在运行节点的 eBPF policy map 状态。

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
netloom-agent policy-rules \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -endpoint prod/vm-a
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_rules
```

如果 agent 配置了 `NETLOOM_OVSDB_ENDPOINT`，最近一次 reconcile 的 rule catalog 和
rule counter 合并视图会写入 `Open_vSwitch.external_ids:netloom_policy_rules`。
`policy-rules` CLI 会从本机 OVSDB 读取同一个 key，适合在没有打开 agent HTTP listener
时审计 Cilium-style rule counter 和规则来源映射。

查看最近 endpoint policy map 更新事件：

```bash
curl -s 'http://127.0.0.1:9092/policy/events?limit=100'
curl -s 'http://127.0.0.1:9092/policy/events/prod/vm-a?limit=20'
```

查看某个 endpoint 当前 live policy map entries：

```bash
curl -s http://127.0.0.1:9092/policy/entries/prod/vm-a
curl -s 'http://127.0.0.1:9092/policy/entries?endpoint=prod/vm-a'
netloom-agent policy-entries-export \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -endpoint prod/vm-a
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_entries
```

如果 agent 配置了 `NETLOOM_OVSDB_ENDPOINT`，最近一次 reconcile 的 endpoint
policy-map entries 会写入 `Open_vSwitch.external_ids:netloom_policy_entries`。
HTTP 接口适合在线排查，`policy-entries-export` 适合从本机 OVSDB 做离线审计。

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
可以直接从本机 OVSDB 查看当前有效冻结状态：

```bash
netloom-agent policy-freeze-state \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -endpoint prod/vm-a
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_freeze_state
```

`policy-freeze-state` CLI 会去重并过滤已经过期的冻结记录，支持按 `endpoint`
查询某个 endpoint 当前是否被冻结。

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
netloom-agent policy-events \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -endpoint prod/vm-a \
  -limit 20
ovs-vsctl get Open_vSwitch . external_ids:netloom_policy_events
```

如果 agent 配置了 `NETLOOM_OVSDB_ENDPOINT`，最近的 endpoint policy map 更新事件会写入
`Open_vSwitch.external_ids:netloom_policy_events`，包括 endpoint、revision、diff stats、
success/error 和 overflow remediation 信息，用于节点重启后继续审计 Cilium-style policy
regeneration 结果。

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
