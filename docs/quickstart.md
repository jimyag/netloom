# 快速开始

这份文档给出裸金属环境里最短的验证路径。完整配置项和排障命令见 [使用说明](usage.md)，能力边界见 [当前实现状态](current-status.md) 和 [功能矩阵](features.md)。

## 当前已实现的主能力

`netloom` 的核心 SDN 能力已经实现：

- OVN/libovsdb 控制面：VPC、Subnet、Endpoint、DHCP、DNS、Gateway、NAT、LoadBalancer、RouteTable、PolicyRoute。
- 本机数据面：provider bridge/port/interface、VLAN、本机 netns/veth、地址、路由、Linux RPDB policy routing。
- 安全组和 ACL：SecurityGroup 编译成 endpoint policy map，eBPF/TCX 执行 ingress/egress TCP、UDP、SCTP、ICMP，不写 OVN ACL。
- 运维控制：desired state 可来自 JSON 文件或 Open_vSwitch OVSDB，支持 controller/agent 状态、policy explain、route explain、metrics、rollout、freeze、quarantine、rollback 和审计历史。

当前缺的主要是生产交付材料和长期运行验证，包括多节点部署手册、升级/回滚、备份恢复、容量压测、告警规则和故障剧本。

## 1. 先跑本机自检

不带 desired state 启动 agent，会运行本机 selftest。建议先确认二进制、策略编译、policy evaluator、runtime preflight 结果。

```bash
NETLOOM_POLICY_STORE=ebpf \
NETLOOM_TCX_WORKLOAD=1 \
./netloom-agent
```

如果希望 runtime 缺失直接失败：

```bash
NETLOOM_SELFTEST_STRICT_RUNTIME=1 \
NETLOOM_POLICY_STORE=ebpf \
NETLOOM_TCX_WORKLOAD=1 \
./netloom-agent
```

## 2. 准备 desired state

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
      "nodes": [
        {"node": "node-a", "interface": "eth1"}
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
      "labels": {"app": "web"},
      "named_ports": [
        {"name": "http", "protocol": "tcp", "port": 8080}
      ]
    }
  ],
  "route_tables": [
    {
      "name": "main",
      "vpc": "prod",
      "routes": [
        {"destination": "0.0.0.0/0", "next_hops": ["10.10.0.254"]}
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
      "health_check": {"enabled": true}
    }
  ],
  "security_groups": [
    {
      "name": "web",
      "vpc": "prod",
      "rules": [
        {
          "id": "allow-http",
          "priority": 10,
          "direction": "ingress",
          "protocol": "tcp",
          "remote_entities": ["all"],
          "named_ports": ["http"],
          "action": "allow",
          "stateful": true
        },
        {
          "id": "allow-egress-https",
          "priority": 20,
          "direction": "egress",
          "protocol": "tcp",
          "remote_entities": ["world"],
          "ports": [{"from": 443, "to": 443}],
          "action": "allow"
        }
      ]
    }
  ]
}
```

## 3. 可选：把 desired state 存入 OVSDB

裸金属部署可以直接把 desired state 放在本机 Open_vSwitch DB，controller 和 agent 都从同一个 OVSDB key 读取。

```bash
./netloom-agent desired-state-import \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  < /etc/netloom/state.json

./netloom-agent desired-state-export \
  -ovsdb unix:/var/run/openvswitch/db.sock
```

## 4. 启动 controller

controller 负责写 OVN Northbound DB。生产路径使用 libovsdb，不使用旧的 nbctl backend。

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
NETLOOM_RECONCILE_INTERVAL_MS=5000 \
NETLOOM_CONTROLLER_METRICS_ADDR=:9091 \
./netloom-controller
```

如果 desired state 已经导入 Open_vSwitch OVSDB，可以不设置 `NETLOOM_STATE_FILE`。

## 5. 启动每个节点上的 agent

agent 负责本机 OVS、Linux datapath 和 eBPF/TCX policy enforcement。

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_NODE_NAME=node-a \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
NETLOOM_POLICY_STORE=ebpf \
NETLOOM_TCX_WORKLOAD=1 \
NETLOOM_LINUX_DATAPATH=1 \
NETLOOM_LINUX_DATAPATH_MODE=netns \
NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth1 \
NETLOOM_RUNTIME_PREFLIGHT_STRICT=1 \
NETLOOM_AGENT_METRICS_ADDR=:9092 \
./netloom-agent
```

测试或异常中断后需要清理 Netloom 管理的本机对象时，加上：

```bash
NETLOOM_LINUX_DATAPATH_CLEANUP=1
```

## 6. 验证状态

控制面：

```bash
./netloom-controller controller-status \
  -ovsdb unix:/var/run/openvswitch/db.sock

./netloom-controller controller-events \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  -limit 20

curl -s http://127.0.0.1:9091/status
curl -s http://127.0.0.1:9091/metrics
```

节点侧：

```bash
./netloom-agent agent-status \
  -ovsdb unix:/var/run/openvswitch/db.sock

./netloom-agent policy-status \
  -state /etc/netloom/state.json \
  -node node-a

./netloom-agent policy-entries \
  -state /etc/netloom/state.json \
  -node node-a \
  -endpoint prod/vm-a

curl -s http://127.0.0.1:9092/metrics
curl -s http://127.0.0.1:9092/policy/rules
curl -s http://127.0.0.1:9092/policy/entries/prod/vm-a
```

策略判定：

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

路由判定：

```bash
./netloom-agent route-explain \
  -state /etc/netloom/state.json \
  -vpc prod \
  -source 10.10.0.10 \
  -dest 172.16.0.10 \
  -protocol tcp \
  -dest-port 443
```

## 7. 提交前验证

常规验证：

```bash
go test ./...
git diff --check
```

Docker e2e 默认关闭，需要显式启用并按用例拆跑：

```bash
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Policy' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Provider' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerLinuxPolicyRouting' -count=1
```
