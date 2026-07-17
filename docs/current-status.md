# 当前实现状态

本文档按裸金属 SDN 产品视角说明 `netloom` 目前已经实现的能力、主要入口和还没有补齐的生产化内容。

## 已实现的主路径

`netloom` 当前主路径已经实现：controller 负责把 desired state 收敛到 OVN Northbound，agent 负责本机 Open vSwitch、Linux datapath 和 eBPF/TCX 安全策略。

| 类别 | 当前状态 | 说明 |
| --- | --- | --- |
| VPC | 已实现 | 对应 OVN Logical Router。 |
| Subnet | 已实现 | 对应 OVN Logical Switch、router port、localnet port、VLAN、DHCP options。 |
| Endpoint | 已实现 | 对应 OVN Logical Switch Port、地址、port security、DHCP attachment。 |
| Gateway | 已实现 | 支持普通 gateway 和 distributed gateway 元数据。 |
| RouteTable | 已实现 | 支持静态路由、ECMP、BFD 和最小变更更新。 |
| PolicyRoute | 已实现 | 支持 reroute、drop、reject、L4 match，并投影到 OVN LRP 和 Linux RPDB。 |
| NAT | 已实现 | 支持 SNAT、DNAT、Floating IP 和端口映射。 |
| LoadBalancer | 已实现 | 支持 TCP、UDP、SCTP VIP、backend、session affinity、health check。 |
| Provider Network | 已实现 | 支持 OVN localnet、本机 OVS Bridge/Controller/Port/Interface、QoS、Queue。 |
| SecurityGroup | 已实现 | 编译成 Cilium 风格 endpoint policy map。 |
| ACL 执行 | 已实现 | 由 eBPF/TCX 执行 ingress/egress TCP、UDP、SCTP、ICMP，安全组不写 OVN ACL。 |
| Desired State | 已实现 | 支持 JSON 文件，也支持存入本机 Open_vSwitch OVSDB `external_ids`。 |
| 状态和观测 | 已实现 | controller `/status`、agent `/metrics`、policy status、policy explain、route explain、policy rules、policy events、policy entries。 |
| Rollout / lifecycle | 已实现 | 支持 policy dry-run、batch rollout、approval、ack、finalize、SLO/probe、rollback、quarantine、freeze/unfreeze、freeze TTL 和成功/失败 endpoint action history。 |
| Runtime selftest | 已实现 | agent 默认 selftest 验证策略编译/评估、stateful conntrack、runtime preflight，并报告 bpffs、memlock、BPF/NET_ADMIN capability、OVSDB/OVN endpoint 状态。 |

## 运行入口

controller:

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock \
NETLOOM_CONTROLLER_METRICS_ADDR=:9091 \
./netloom-controller
```

agent:

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_NODE_NAME=node-a \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
NETLOOM_POLICY_STORE=ebpf \
NETLOOM_TCX_WORKLOAD=1 \
NETLOOM_LINUX_DATAPATH=1 \
NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth1 \
NETLOOM_AGENT_METRICS_ADDR=:9092 \
./netloom-agent
```

desired state 也可以放到 OVSDB：

```bash
./netloom-agent desired-state-import -ovsdb unix:/var/run/openvswitch/db.sock < /etc/netloom/state.json
./netloom-agent desired-state-export -ovsdb unix:/var/run/openvswitch/db.sock
```

## 功能验证入口

建议先用下面的命令确认 desired state、策略、policy map 和路由逻辑：

```bash
NETLOOM_SELFTEST_STRICT_RUNTIME=1 NETLOOM_POLICY_STORE=ebpf NETLOOM_TCX_WORKLOAD=1 ./netloom-agent
./netloom-agent policy-status -state /etc/netloom/state.json -node node-a
./netloom-agent policy-status-export -ovsdb unix:/var/run/openvswitch/db.sock -endpoint prod/vm-a
./netloom-agent policy-entries -state /etc/netloom/state.json -node node-a -endpoint prod/vm-a
./netloom-agent policy-entries-export -ovsdb unix:/var/run/openvswitch/db.sock -endpoint prod/vm-a
./netloom-agent policy-explain -state /etc/netloom/state.json -vpc prod -endpoint vm-a -direction ingress -protocol tcp -remote-ip 10.10.1.20 -dest-port 8080
./netloom-agent route-explain -state /etc/netloom/state.json -vpc prod -source 10.10.0.10 -dest 172.16.0.10 -protocol tcp -dest-port 443
curl -s http://127.0.0.1:9091/status
./netloom-controller controller-events -ovsdb unix:/var/run/openvswitch/db.sock -limit 20
curl -s http://127.0.0.1:9092/metrics
curl -s http://127.0.0.1:9092/policy/rules
curl -s 'http://127.0.0.1:9092/policy/events?limit=100'
curl -s http://127.0.0.1:9092/policy/entries/prod/vm-a
```

代码级验证：

```bash
go test ./...
```

Docker e2e 需要显式开启，并建议按用例拆跑：

```bash
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Policy' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Provider' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerControllerReconcileIdempotent' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerLinuxPolicyRouting' -count=1
```

## 仍然缺少的内容

下面这些不是核心语义缺失，但会影响生产交付：

- 部署手册：多节点 OVN/OVS 部署、证书、systemd unit、日志目录、升级顺序。
- 备份恢复：OVN NB/SB、Open_vSwitch DB、desired state、rollout state 的备份和恢复流程。
- 容量压测：大量 VPC、子网、endpoint、安全组、policy route、LB、provider queue 的规模边界。
- 故障剧本：OVN leader failover、OVSDB reconnect、TCX attach 失败、provider parent interface 变化、BPF map pressure。
- 容器化运行清单：systemd/container unit 中的 capability、mount、rlimit、socket 权限模板。
- 发布流程：版本号、配置迁移策略、灰度升级和回滚手册。

## 边界

- 这是裸金属 SDN 产品，不集成 Kubernetes。
- 不提供 CRD、CNI plugin contract，也不依赖 kube-apiserver。
- OVN 负责网络拓扑、路由、NAT、LB、DHCP、DNS 等控制面对象。
- SecurityGroup/ACL 由 eBPF/TCX 执行，不使用 OVN ACL。
