# 使用说明

本文档描述 `netloom` 在裸金属环境中的基本使用方式。当前项目不集成 Kubernetes，也不依赖 Kubernetes CRD；所有网络意图来自 desired state JSON 或写入本机 Open_vSwitch OVSDB 的 desired state。

## 能力清单

| 能力 | 实现位置 | 说明 |
| --- | --- | --- |
| VPC / Subnet / Endpoint / IPAM | controller + OVN NB | 创建逻辑路由器、逻辑交换机、端口、地址和端口安全。 |
| DHCP / DNS | OVN NB | 为 endpoint 绑定 DHCP options，并维护 OVN DNS records。 |
| Gateway / NAT / LoadBalancer | OVN NB | 支持 SNAT、DNAT、Floating IP、OVN LB、健康检查和 subnet 绑定。 |
| RouteTable / PolicyRoute | OVN NB + Linux datapath | 支持静态路由、ECMP、BFD、reroute/drop 策略路由和本机 RPDB 投影。 |
| Provider Network | OVN localnet + OVSDB | 管理 localnet port、本机 OVS Bridge、Controller、Port、Interface、QoS、Queue。 |
| SecurityGroup / ACL | eBPF policy map + TCX | 安全组不写 OVN ACL，规则由 eBPF/TCX 执行。 |
| Policy rollout | agent | 支持 dry-run、batch、approval、ack、finalize、SLO、HTTP/TCP/TLS probe、rollback、quarantine。 |
| 运维观测 | OVSDB external_ids + metrics + CLI | 输出 controller/agent 状态、policy status、explain、Prometheus metrics。 |

## 构建

```bash
go test ./...
go build ./cmd/netloom-controller ./cmd/netloom-agent ./cmd/netloom-dns-observer
```

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
ovs-vsctl get Open_vSwitch . external_ids:netloom_controller_status
ovs-vsctl get Open_vSwitch . external_ids:netloom_agent_status
```

查看安全策略状态：

```bash
./netloom-agent policy-status -state /etc/netloom/state.json -node node-a
```

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
