# Netloom 文档

`netloom` 目前的核心 SDN 能力已经实现，可以按裸金属产品路径继续做部署、压测和运维交付。

## 先看结论

主路径已经具备：

- OVN/libovsdb 控制面：VPC、Subnet、Endpoint、DHCP、DNS、Gateway、RouteTable、PolicyRoute、NAT、LoadBalancer。
- 本机数据面：Open vSwitch provider bridge/port/interface、VLAN、QoS/Queue、Linux netns/veth、地址、路由、RPDB policy routing。
- 安全策略：SecurityGroup 编译成 Cilium-style endpoint policy map，由 eBPF/TCX 执行 ingress/egress ACL，不使用 OVN ACL。
- 运维能力：desired state 文件或 Open_vSwitch OVSDB、controller/agent 状态、policy/route explain、policy rollout、freeze/quarantine/rollback、metrics 和审计历史。

还没补齐的是生产交付材料和长周期验证，不是核心语义缺失：

- 多节点 OVN/OVS 部署、证书、systemd/container unit、升级和回滚手册。
- OVN NB/SB、Open_vSwitch DB、desired state、rollout state 的备份恢复流程。
- 大规模 VPC、Subnet、Endpoint、SecurityGroup、PolicyRoute、LB、Provider Queue 压测。
- OVN failover、OVSDB reconnect、TCX attach 失败、provider parent link 变化、BPF map pressure 的故障剧本。

## 推荐阅读顺序

1. [当前实现状态](current-status.md)：先确认已经实现了什么、还缺什么。
2. [快速开始](quickstart.md)：用最短 desired state 跑通 controller 和 agent。
3. [使用说明](usage.md)：查看完整运行参数、状态检查、policy lifecycle 和 OVSDB 存储方式。
4. [功能矩阵](features.md)：按 VPC、子网、网关、安全组、策略路由等能力查实现入口和测试入口。
5. [eBPF ACL 设计](design/cilium-ebpf-acl.md)：查看为什么安全组/ACL 放在 eBPF/TCX，而不是 OVN ACL。
6. [差距分析](analysis/sdn-gap-vs-cilium-kube-ovn.md)：查看对 Cilium、Kube-OVN 的取舍和仍需生产化补强的点。

## 最小运行方式

controller 写 OVN Northbound：

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
./netloom-controller
```

agent 写本机 OVS、Linux datapath 和 eBPF/TCX：

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_NODE_NAME=node-a \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
NETLOOM_POLICY_STORE=ebpf \
NETLOOM_TCX_WORKLOAD=1 \
NETLOOM_LINUX_DATAPATH=1 \
NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth1 \
./netloom-agent
```

desired state 也可以直接存到本机 Open_vSwitch OVSDB：

```bash
./netloom-agent desired-state-import -ovsdb unix:/var/run/openvswitch/db.sock < /etc/netloom/state.json
./netloom-agent desired-state-export -ovsdb unix:/var/run/openvswitch/db.sock
```

## 常用验证命令

```bash
go test ./...
git diff --check

./netloom-controller controller-status -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-agent agent-status -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-agent policy-status -state /etc/netloom/state.json -node node-a
./netloom-agent policy-revision-wait -ovsdb unix:/var/run/openvswitch/db.sock -endpoint prod/vm-a -revision 3 -timeout 30s
curl -s 'http://127.0.0.1:9092/policy/endpoints/prod/vm-a/revision?target_revision=3&timeout_ms=30000'
./netloom-agent policy-explain -state /etc/netloom/state.json -vpc prod -endpoint vm-a -direction ingress -protocol tcp -remote-ip 10.10.0.20 -dest-port 80
./netloom-agent route-explain -state /etc/netloom/state.json -vpc prod -source 10.10.0.10 -dest 8.8.8.8 -protocol tcp -dest-port 443
```

Docker e2e 建议按用例拆跑：

```bash
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Policy' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Provider' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerLinuxPolicyRouting' -count=1
```
