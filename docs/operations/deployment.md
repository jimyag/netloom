# 裸金属部署手册

本文档给出生产环境部署 `netloom` 的最小清单。`netloom` 是裸金属 SDN 产品，不接入 Kubernetes；controller 写 OVN Northbound，agent 在每台节点上写本机 Open vSwitch、Linux datapath 和 eBPF/TCX policy。

## 组件布局

| 组件 | 建议位置 | 作用 |
| --- | --- | --- |
| OVN Northbound DB | 3 节点集群 | 保存 VPC、Subnet、Endpoint、Route、PolicyRoute、NAT、LB、DHCP、DNS 等逻辑网络状态。 |
| Open vSwitch DB | 每台计算节点本机 | 保存 provider bridge、port、interface、QoS、Queue，以及 `netloom` 运行状态和可选 desired state。 |
| `netloom-controller` | 2 个或更多管理节点 | 从 desired state 收敛 OVN NB；同一 desired state 下重复运行应保持幂等。 |
| `netloom-agent` | 每台计算节点 | 收敛本机 OVS、Linux route/RPDB、endpoint policy map 和 TCX attach。 |
| `netloom-dns-observer` | 需要 FQDN policy 的节点 | 把 DNS 观测写入本机 Open_vSwitch OVSDB，供 agent 编译 `remote_fqdns` 规则。 |

生产路径使用 `NETLOOM_OVN_LIBOVSDB_ENDPOINT`，不要使用旧 nbctl backend。多个 OVN NB endpoint 直接写成逗号、空白或换行分隔的列表。

## 目录和权限

建议固定以下路径：

| 路径 | 内容 |
| --- | --- |
| `/etc/netloom/state.json` | desired state 文件。也可以把 desired state 导入 Open_vSwitch OVSDB。 |
| `/var/lib/netloom` | 本机持久状态、临时导出、排障快照。 |
| `/var/log/netloom` | controller、agent、dns observer 日志。 |
| `/sys/fs/bpf` | bpffs 挂载点，eBPF policy map 和 TCX 程序需要。 |

agent 需要能访问：

- `/var/run/openvswitch/db.sock`
- `/var/run/ovn/ovnnb_db.sock`，如果 agent 也要做 OVN runtime preflight
- provider parent NIC，例如 `eth1`
- bpffs、memlock、`CAP_BPF` 或等价能力、`CAP_NET_ADMIN`

## OVN endpoint 配置

单 endpoint：

```bash
NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock
```

多 endpoint：

```bash
NETLOOM_OVN_LIBOVSDB_ENDPOINT=tcp:10.0.0.11:6641,tcp:10.0.0.12:6641,tcp:10.0.0.13:6641
```

如果需要 leader 优先，可以配置 OVN cluster status target：

```bash
NETLOOM_OVN_CLUSTER_STATUS_TARGETS=10.0.0.11,10.0.0.12,10.0.0.13
```

controller 会在 status、events 和 metrics 中暴露 active endpoint、leader endpoint、quorum 和 failover 信息。连接失败的 endpoint 会进入短暂冷却，默认 5 秒，可用 `NETLOOM_OVN_LIBOVSDB_ENDPOINT_FAILURE_COOLDOWN_MS` 调整；如果所有 endpoint 都处于冷却，controller 仍会全部重试以保留诊断信号。

## Desired State 发布方式

文件方式适合初期验证：

```bash
install -m 0640 state.json /etc/netloom/state.json
```

OVSDB 方式适合裸金属节点统一读取：

```bash
./netloom-agent desired-state-import \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  < /etc/netloom/state.json

./netloom-agent desired-state-export \
  -ovsdb unix:/var/run/openvswitch/db.sock
```

生产环境建议把 desired state 发布作为一次变更：先导出旧版本，再导入新版本，然后观察 controller 和 agent 状态。

## Controller 启动模板

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_OVN_LIBOVSDB_ENDPOINT=tcp:10.0.0.11:6641,tcp:10.0.0.12:6641,tcp:10.0.0.13:6641 \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
NETLOOM_RECONCILE_INTERVAL_MS=5000 \
NETLOOM_CONTROLLER_METRICS_ADDR=:9091 \
./netloom-controller
```

如果 desired state 存在 Open_vSwitch OVSDB，可以去掉 `NETLOOM_STATE_FILE`。

## Agent 启动模板

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

`NETLOOM_RUNTIME_PREFLIGHT_STRICT=1` 会在必要 runtime check 失败时 fail closed，不继续写 policy map、TCX 或本机 datapath。

## DNS Observer 启动模板

UDP/TCP 代理模式：

```bash
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
./netloom-dns-observer \
  -listen-udp 127.0.0.1:1053 \
  -upstream-udp 8.8.8.8:53 \
  -listen-tcp 127.0.0.1:1053 \
  -upstream-tcp 8.8.8.8:53
```

被动抓包模式：

```bash
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
./netloom-dns-observer -capture-iface eth1
```

## 上线检查

上线前逐项确认：

- `go test ./...` 通过。
- desired state 能通过 controller/agent 加载和对象图校验。
- `./netloom-agent` selftest 通过，严格模式下 runtime preflight 不失败。
- `controller-status` 显示 OVN endpoint connected，quorum 非 lost。
- `agent-status` 显示 provider network ready，TCX attach 成功，policy map 无 drift。
- `policy-explain` 覆盖至少一条允许、一条拒绝、一条默认行为。
- `route-explain` 覆盖普通 route、policy route reroute/drop。
- `curl :9091/metrics` 和 `curl :9092/metrics` 能被监控系统采集。

## 升级顺序

推荐顺序：

1. 备份 OVN NB/SB、Open_vSwitch DB 和 desired state。
2. 在单个非核心节点升级 agent，观察 `agent-status`、policy revision、TCX 和 provider 状态。
3. 分批升级剩余 agent。
4. 升级 standby controller。
5. 升级 active controller。
6. 对比升级前后的 `controller-status`、`agent-status`、OVN audit drift 和 policy events。

回滚时先回滚 controller，再按节点回滚 agent；如果 desired state schema 同步改变，应先恢复旧 desired state。
