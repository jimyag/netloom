# 备份和恢复

本文档描述 `netloom` 裸金属部署中需要备份的状态，以及恢复时的顺序。目标是让 OVN、Open vSwitch、desired state 和 policy lifecycle 状态保持一致。

## 需要备份的内容

| 对象 | 来源 | 原因 |
| --- | --- | --- |
| desired state 文件 | `/etc/netloom/state.json` | 网络意图的主来源。 |
| desired state OVSDB key | `Open_vSwitch.external_ids:netloom_desired_state` | 使用 OVSDB 发布 desired state 时的主来源。 |
| OVN Northbound DB | OVN NB 集群 | VPC、Subnet、Endpoint、Route、PolicyRoute、NAT、LB、DHCP、DNS 实际控制面状态。 |
| OVN Southbound DB | OVN SB 集群 | chassis 和 logical flow runtime 状态，灾难恢复时和 NB 一起保留。 |
| Open_vSwitch DB | 每台计算节点 | provider bridge、port、interface、QoS、Queue、运行状态和 rollout/freeze/history external IDs。 |
| 运维快照 | controller/agent status、events、metrics | 恢复后对比 drift、revision 和失败事件。 |

## 备份命令模板

保存 desired state 文件：

```bash
install -d -m 0750 /var/lib/netloom/backups
cp /etc/netloom/state.json /var/lib/netloom/backups/state.$(date +%Y%m%d%H%M%S).json
```

导出 OVSDB 中的 desired state：

```bash
./netloom-agent desired-state-export \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  > /var/lib/netloom/backups/desired-state.$(date +%Y%m%d%H%M%S).json
```

保存 controller 和 agent 运行状态：

```bash
./netloom-controller controller-status \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  > /var/lib/netloom/backups/controller-status.$(date +%Y%m%d%H%M%S).json

./netloom-agent agent-status \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  > /var/lib/netloom/backups/agent-status.$(date +%Y%m%d%H%M%S).json
```

OVN 和 Open vSwitch DB 的数据库级备份应使用环境中已有的 OVS/OVN 运维工具完成，核心要求是同时保留 NB、SB 和每台计算节点的 Open_vSwitch DB。

## 备份频率

| 频率 | 内容 |
| --- | --- |
| 每次 desired state 变更前 | desired state、controller-status、agent-status。 |
| 每次版本升级前 | desired state、OVN NB/SB、Open_vSwitch DB、controller/agent status。 |
| 每日 | OVN NB/SB、Open_vSwitch DB、desired state、policy rollout/freeze/history external IDs。 |
| 故障处理前 | 先抓 status/events/metrics，再执行修复或清理。 |

## 恢复顺序

推荐恢复顺序：

1. 停止 controller，避免恢复过程中继续写 OVN NB。
2. 停止受影响节点上的 agent，避免继续写本机 OVS、Linux datapath 或 policy map。
3. 恢复 OVN NB/SB 数据库。
4. 恢复每台计算节点的 Open_vSwitch DB。
5. 恢复 desired state 文件，或重新导入 `netloom_desired_state`。
6. 启动 controller，观察 `/status` 和 `controller-events`。
7. 分批启动 agent，观察 `agent-status`、policy revision、provider issue 和 TCX 状态。
8. 使用 `policy-explain`、`route-explain` 和业务连通性用例确认恢复结果。

## 恢复后校验

```bash
./netloom-controller controller-status -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-controller controller-events -ovsdb unix:/var/run/openvswitch/db.sock -limit 50
./netloom-agent agent-status -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-agent policy-status -state /etc/netloom/state.json -node node-a
./netloom-agent route-explain -state /etc/netloom/state.json -vpc prod -source 10.10.0.10 -dest 8.8.8.8
```

重点检查：

- controller OVN health 是否恢复 connected。
- OVN live audit 是否没有持续增长的 missing、unexpected、duplicate、incomplete。
- agent runtime preflight 是否 ready。
- provider network 是否 ready，是否存在 `parent-down`、`link-missing`、`link-drift`。
- endpoint policy revision 是否达到 desired revision。
- policy map pressure 是否低于告警阈值。
- rollout/freeze/quarantine 状态是否符合预期。

## Desired State 回滚

如果新 desired state 引发故障，先恢复旧 desired state：

```bash
./netloom-agent desired-state-import \
  -ovsdb unix:/var/run/openvswitch/db.sock \
  < /var/lib/netloom/backups/desired-state.good.json
```

随后观察 controller 和 agent 收敛。不要直接删除 OVN/OVS 行来绕过 desired state；应该先恢复 desired state，再让 controller/agent 清理多余的 managed state。

## Policy 回滚

单 endpoint 可使用 agent 提供的 policy rollback 能力恢复到 latest successful desired policy。恢复后确认：

```bash
./netloom-agent policy-status -state /etc/netloom/state.json -node node-a
curl -s 'http://127.0.0.1:9092/policy/events?endpoint=prod/vm-a&limit=20'
```

如果 endpoint 已 freeze，先确认 freeze 是否仍然需要；冻结状态会阻止正常 reconcile 覆盖 policy map。
