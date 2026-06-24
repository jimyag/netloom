# netloom

[![Go Report Card](https://goreportcard.com/badge/github.com/jimyag/netloom)](https://goreportcard.com/report/github.com/jimyag/netloom)
[![codecov](https://codecov.io/gh/jimyag/netloom/branch/main/graph/badge.svg)](https://codecov.io/gh/jimyag/netloom)
[![License](https://img.shields.io/github/license/jimyag/netloom)](LICENSE)
[![Release](https://img.shields.io/github/v/release/jimyag/netloom)](https://github.com/jimyag/netloom/releases)

`netloom` 是一个使用 Go 编写的 SDN 软件项目。

## netloom 是什么意思

`netloom` 由 `net` 和 `loom` 两部分组成。

- `net` 表示 network，也就是网络。
- `loom` 表示织机，也有“编织”的意思。

所以 `netloom` 想表达的是：像织布一样去编排和组织网络，把原本分散的节点、链路、地址、路由和策略编织成一张可以统一描述、统一控制的虚拟网络。

这个名字更偏控制面语义，而不是单纯强调某个转发协议或某一种数据面实现。它适合用来描述一个负责 VPC、子网、IPAM、路由、网关和策略集成的 SDN 系统。

## 项目愿景

`netloom` 面向云网络和基础设施网络场景，目标是提供一套可编排的虚拟网络控制面，而不是依赖每台机器上的手工网络配置。

当前的方向包括：

- VPC 与虚拟网络抽象
- 子网与 IPAM 管理
- 逻辑交换与逻辑路由
- Gateway 与 NAT 编排
- 与 eBPF 安全策略能力集成

项目整体会保持简单、清晰、易维护：

- 使用 Go 实现控制面
- API 尽量小且行为明确
- 优先使用易读、易调试、易扩展的组件划分

## 架构方向

当前的设计方向，接近 `OVN + eBPF` 的职责拆分。

`netloom` 负责网络控制面的核心能力：

- VPC 与子网建模
- IPAM
- 逻辑网络拓扑
- 路由意图表达
- Gateway 编排
- VIP、负载均衡挂载等服务连接能力

eBPF 负责安全与可观测性相关能力：

- 类安全组的策略执行
- 主机与工作负载级别的包过滤
- 基于连接状态的策略控制
- 流量观测与排障数据

也就是说：

- `netloom` 负责定义网络
- eBPF 负责执行和观测安全策略

这和“Kube-OVN/OVN 负责虚拟网络，Cilium/eBPF 负责策略与观测”的整体思路接近，但 `netloom` 会保持自己的控制面边界和实现方式。

### 架构草图

```mermaid
flowchart TB
    subgraph Control["控制面"]
        API["netloom API / Controller"]
        MODEL["VPC / Subnet / IPAM / Route Model"]
        API --> MODEL
    end

    subgraph VirtualNet["虚拟网络层"]
        OVN["OVN / 虚拟网络后端"]
        TOPO["Logical Switch / Logical Router / Gateway / NAT / VIP"]
        OVN --> TOPO
    end

    subgraph Policy["安全与观测层"]
        EBPF["eBPF Policy Engine"]
        OBS["Flow / Events / Observability"]
        EBPF --> OBS
    end

    subgraph Nodes["节点与工作负载"]
        NODE1["Node A"]
        NODE2["Node B"]
        POD1["Workload A"]
        POD2["Workload B"]
        NODE1 --> POD1
        NODE2 --> POD2
    end

    API --> OVN
    API --> EBPF
    TOPO --> NODE1
    TOPO --> NODE2
    EBPF --> NODE1
    EBPF --> NODE2

    style API fill:#4a90d9,color:#fff
    style OVN fill:#27ae60,color:#fff
    style EBPF fill:#e67e22,color:#fff
```

这张图表达的是：

- `netloom` 作为控制面，负责管理网络模型与编排逻辑。
- OVN 风格的虚拟网络后端，负责实现逻辑交换、逻辑路由、Gateway、NAT 和 VIP。
- eBPF 负责策略执行和流量观测，不负责定义 VPC、子网或 IPAM。
- 工作负载同时受虚拟网络与 eBPF 策略影响，但两者的职责边界保持分离。

## 为什么不把安全策略全部放进 OVN ACL

OVN ACL 本身很适合做分布式虚拟网络策略，但它不是唯一选择。

这里更倾向于这样分工：

- 虚拟网络、地址分配、VPC、路由等能力放在 SDN 控制面
- 更复杂的安全组能力交给 eBPF

这样做的好处是：

- 网络与安全职责边界更清晰
- 更容易获得更强的策略能力和观测能力
- 降低虚拟网络拓扑与安全实现细节之间的耦合

但这并不意味着系统一定更简单。混合架构会增加控制面和排障复杂度，所以两侧的边界必须保持明确，避免出现多套策略系统同时生效、相互覆盖的问题。

## 范围

计划中的能力：

- 建模虚拟网络与子网
- 分配并回收 IP 地址
- 编排逻辑路由与 Gateway 行为
- 与 eBPF 策略引擎集成
- 提供清晰的面向运维和平台的接口

早期阶段的非目标：

- 从零重写所有数据面能力
- 在同一条路径上混用多套重叠策略系统
- 用过重的抽象隐藏控制面行为

## 当前状态

`netloom` 目前仍处于早期阶段，整体架构还在持续收敛，但仓库里已经有一条可运行的端到端路径。

当前仓库已经包含：

- 控制面模型：VPC、Subnet、Endpoint、RouteTable、PolicyRoute、Gateway、NATRule、SecurityGroup、CIDRGroup；Endpoint 可声明 Cilium 风格 labels 与 named ports。
- 控制面一致性校验：拒绝重复的 VPC/Subnet/Endpoint/SecurityGroup/Gateway 等对象身份，拒绝 Endpoint IP 冲突，并在写入后端前校验 VPC、Subnet、安全组、remote-group 和 LoadBalancer 绑定子网等引用关系。
- Subnet 支持 Kube-OVN `excludeIps` 类似的 `exclude_cidrs` 保留地址段，控制面会拒绝 endpoint 使用被排除的地址，IPAM allocator 也会跳过这些 CIDR。
- OVN 风格拓扑后端：把逻辑交换、逻辑路由、静态 ECMP 路由、策略路由、Gateway、NAT、Service VIP 和 Provider Network 转换为带 `external_ids` 所有权标记的批量 `ovn-nbctl` 事务；Gateway 覆盖集中式 chassis pin 与分布式网关元数据；NAT 覆盖 SNAT、DNAT、Floating IP (`dnat_and_snat`)、分布式 Floating IP 的 `logical_port`/`external_mac` 投影和 OVN NAT 端口映射；同名规则变更会按 desired state 替换旧 NAT 投影，并在控制面拒绝 EIP/端口冲突。仓库内也包含基于本地 OVN NB model 的 `LibOVSDBTopologyWriter`，已支持把 VPC logical router、Subnet logical switch/IPAM other_config、router port、router 类型 switch port、provider localnet port、Endpoint logical switch port 和 DHCP_Options 直接 create/update/delete 到 OVN Northbound OVSDB，作为逐步替换 `ovn-nbctl` 写路径的 typed writer 基础。
- Endpoint 可声明 Kube-OVN 风格静态 `mac`，OVN 后端会把 MAC+IP 写入 logical switch port addresses 和 port security；控制面会拒绝同子网重复 MAC 以及与网关 router port MAC 冲突的静态 MAC。
- Linux 工作负载 datapath：支持本机 `/32`/`/128` 地址路由、`netns + veth` 多工作负载模式，以及基于 RPDB table/rule 的 IPv4/IPv6 策略路由下发；网卡/netns/策略路由操作默认使用 `vishvananda/netlink`/`netns` 后端执行，保留 `NETLOOM_LINUX_DATAPATH_BACKEND=command` 作为 shell 回退路径。
- Cilium 风格策略编译：把安全组规则编译为 endpoint-scoped policy map entry，并把 `remote_cidr`/`remote_group`/`remote_endpoint_selector`/`remote_endpoint_expressions`/`remote_service`/`remote_cidr_group`/`remote_entities`/`remote_fqdns` 保留为可按真实 remote IP 匹配的 CIDR 元数据；重叠 CIDR 会按最长前缀选择更具体规则，精确 identity 命中优先于 CIDR fallback；安全组支持 Cilium `enableDefaultDeny=false` 类似的 `default_deny_ingress=false` / `default_deny_egress=false`，当 endpoint 绑定的所有安全组都显式关闭某方向 default deny 时，会生成最低优先级 wildcard allow，同时显式 drop/reject 仍优先生效；安全组支持 Kube-OVN 风格 `tier` 0/1，较小 tier 会先于较大 tier 生效，同一 tier 内 drop/reject 保持高于 allow/log，非零 rule priority 按 Kube-OVN `1..16384` 范围校验并采用较小数值优先；`remote_cidr` 支持 Cilium `except` 类似的 `except_cidrs` 差集展开；`remote_group` 会展开为 endpoint identity 与精确成员 CIDR，`remote_endpoint_selector`/`remote_endpoint_expressions` 会按 endpoint labels 展开为精确 endpoint identity/CIDR，并支持 Cilium/Kubernetes selector 的 `In`、`NotIn`、`Exists`、`DoesNotExist` 表达式，`remote_service` 采用 Cilium `toServices` 类似的 egress 语义并展开为同 VPC LoadBalancer 的全部 VIP frontend、协议和端口，`remote_cidr_group` 会按 desired-state `cidr_groups` 展开为多条 CIDR 规则，CIDRGroup 支持 Cilium CIDRSet 风格的 `entries[].except_cidrs`；`remote_entities` 支持 `all`/`world`/`world-ipv4`/`world-ipv6`/`cluster`/`private`/`host`/`remote-node`/`none`，其中 `world` 会展开为双栈默认 CIDR 扣除当前 VPC 子网后的外部地址集合，`world-ipv4`/`world-ipv6` 只展开对应 IP family，`none` 不生成规则，`host` 会展开为当前 VPC gateway LAN IP 的 /32 或 /128，`remote-node` 会展开为当前 VPC 中非本节点 gateway LAN IP 的 /32 或 /128，`remote_fqdns` 会按 desired-state `dns_records` 展开为 /32 或 /128 CIDR；支持 Cilium named port 风格的 `named_ports`，ingress 解析本 endpoint 命名端口，egress remote-group 或 remote_endpoint_selector 解析远端成员命名端口；ICMP 规则支持协议级、`icmp_type` 级和 `icmp_type`+`icmp_code` 级匹配；`action=reject` 会在 policy map/evaluator 中保留 reject verdict 与观测事件。
- Cilium 风格连接状态：stateful allow 规则会建立反向 conntrack 状态，反向流命中会刷新空闲时间；长运行 agent 会按 Cilium CT GC 思路清理 idle state，默认 5 分钟，可用 `NETLOOM_CONNTRACK_MAX_IDLE_MS` 调整；策略变化或 endpoint 删除时也会清理旧状态。
- Cilium 风格策略更新：policy map replace 会先计算 add/update/delete/unchanged diff，成功替换后递增 endpoint policy revision 并记录 audit event；audit event 会包含 previous/current revision、diff stats 和成功/失败结果，失败时记录 failed endpoint、attempted revision 与错误但不推进实际 revision；内存 store 具备事务回滚语义；agent 会汇总 policy map entries/capacity/pressure，并输出最高 pressure endpoint，便于定位接近容量上限的策略 map；可用 `NETLOOM_POLICY_GC_MAX_IDLE_MS` 启用非 desired endpoint policy map aging/GC，清理长期运行 agent 中残留的空闲策略状态；`netloom-agent policy-status` 会输出 endpoint policy lifecycle JSON，包括 revision、entries/capacity、pressure、drift、last stats 和 last update event。
- Cilium 风格可观测性：policy evaluator 会记录 allow/drop/conntrack/log 统计，为策略拒绝或无匹配 drop 生成 drop event，并为带 `log` 的规则或 `action=log` 生成 allow/drop policy event；dataplane 提供 `Explain`/`ExplainStateful` 查询接口，可返回 packet tuple 的 verdict、reason、匹配 rule cookie、匹配 entry、PMTU/NDP 特判以及 conntrack/stateful 标记，作为后续 CLI/API “为什么被放行或拒绝”的稳定数据面；agent reconcile 可从策略 telemetry provider 汇总 live rule packet/byte/allow/drop/reject/log counters，并在日志中输出 endpoint/rule 维度的 `policy_rule_stats`；eBPF policy store 会从 live pinned policy map value 读取 counter 字段，TCX attachment 会把 fast path map counters 合并回同一 telemetry 输出；周期 agent 可通过 `NETLOOM_AGENT_METRICS_ADDR` 暴露 Prometheus text metrics endpoint，用于 scrape 最新 reconcile、policy map pressure、policy map live-vs-desired drift、policy rule 和 TCX counters；reconcile drift repair 与 drift audit 都会忽略 counter 增长，避免误判健康 map。
- eBPF/TCX ACL datapath：支持节点接口和工作负载 veth 上的 IPv4/IPv6 CIDR+L4/ICMP ACL attach，TCX map 使用 LPM trie 匹配 peer CIDR、TCP/UDP 端口前缀范围以及 ICMP/ICMPv6 type/code 前缀；TCX L4 ACL map value 会保留 rule cookie、log 标记，并在 fast path 命中时原子递增 packet/byte counters；remote-group 和 remote-endpoint-selector 规则会沿用编译器生成的精确 endpoint CIDR 投影到 TCX fast path，同时 userspace policy map 仍保留 Cilium 风格 remote identity 校验；ICMPv6 使用 next-header 58 编码 type/code；workload fast path 会按 ingress/egress 安全组方向投影到对应 TCX attach 点，agent 自动 attach 会按规则族选择 IPv4、IPv6 或双栈 TCX 程序，双栈场景通过 TCX multi-program anchor 将 IPv6 程序追加到同一接口/方向；TCX attach/update 失败会输出 failed target，TCX rule counters 会按 endpoint 或 shared TCX target 标注，便于定位具体 interface/direction/rule。
- 周期 reconcile：controller 和 agent 都能从 desired-state JSON 文件周期重读状态，controller 会清理从 desired state 删除的 OVN/内存对象，agent 会持有并按需替换 TCX attachment。

策略边界如下：

- `PolicyRoute` 属于 SDN 拓扑意图，由 topology/OVN 路由层处理，支持 reroute/drop 等路由动作；match 支持 source/destination CIDR、protocol、`src_ports` 和 `dst_ports`，OVN 会把多端口范围投影为分组 OR match，Linux datapath 会展开为 source/destination port 组合的 policy rule；reroute 统一使用 `next_hops` 表达单跳或 Kube-OVN/OVN 风格的多 next-hop ECMP，OVN backend 会投影到 `Logical_Router_Policy.nexthops`，Linux datapath 会投影为 multipath policy route，本地 resolver 会基于 flow hash 在 next-hop 集合中做稳定选择并保留完整 `next_hops` 验证视图；OVN backend 会按 desired state 替换同 priority/match 的 policy，避免 next-hop 或 action 更新后旧策略残留；控制面会拒绝同名策略路由或同一 VPC 内重复 priority/match 的策略路由。
- `RouteTable` 的静态路由统一使用 `next_hops` 表达单跳或 ECMP，默认路由、blackhole、单 next-hop 和 OVN `--ecmp` 多 next-hop 更新都会收敛到当前 desired state，本地 resolver 对静态 ECMP 也按 flow hash 选择稳定 next hop；控制面会拒绝同一 VPC 内重复 destination 的静态路由，避免 OVN logical router 上出现歧义路由。
- 控制面会拒绝跨 IP family 的无效意图，包括静态路由 destination/next-hop、SNAT CIDR/external IP、DNAT/Floating IP external/target 以及 LoadBalancer VIP/backend 的 IPv4/IPv6 混配。
- Linux datapath 会把本节点本 VPC 的 `PolicyRoute` 下发为独立 route table 和 `ip rule`/netlink rule，支持 source/destination、TCP/UDP `sport`/`dport`、reroute 和 blackhole/drop；默认 netlink 后端会按 desired state 清理托管表范围内的旧 rule 并刷新当前表，`NETLOOM_POLICY_ROUTE_TABLE_BASE`/`NETLOOM_POLICY_ROUTE_TABLE_SIZE` 可调整表 ID 范围。
- `SecurityGroupRule` 属于 ACL 意图，由 eBPF-style policy map 和 TCX ACL datapath 执行。
- `action=reject` 在 policy map/evaluator 路径会保留为 `reject` verdict，并生成 `policy-reject` drop event；当前 TCX fast path 只能返回 pass/drop，因此可投影的 reject 规则会在 TCX 层按 drop 执行。
- `Endpoint.labels` 与 `Endpoint.named_ports` 可声明 Cilium 风格 endpoint metadata；安全组规则里的 `remote_endpoint_selector` 会用 labels 选择同 VPC endpoint，`remote_endpoint_expressions` 补充 Cilium/Kubernetes selector 的 `In`、`NotIn`、`Exists`、`DoesNotExist` 表达式，二者同时声明时按 AND 匹配并展开为 endpoint identity 与 /32 或 /128；`named_ports` 会在编译阶段解析成具体 TCP/UDP 端口，ingress 使用被保护 endpoint 的命名端口，egress 支持 `remote_group` 或 `remote_endpoint_selector`/`remote_endpoint_expressions` 并按远端成员各自命名端口展开。
- `remote_entities` 采用 Cilium `toEntities`/`fromEntities` 类似语义，支持 `all`、`world`、`world-ipv4`、`world-ipv6`、`cluster`、`private`、`host`、`remote-node` 和 `none`；`all` 会展开为 IPv4/IPv6 默认 CIDR，`world` 表示当前 VPC 子网之外的外部地址集合，`world-ipv4`/`world-ipv6` 只保留对应 IP family，`cluster` 会展开为当前 VPC 的子网 CIDR，`private` 会展开为 RFC1918 与 ULA CIDR，`host` 会展开为当前 VPC gateway LAN IP 的 /32 或 /128，`remote-node` 会展开为当前 VPC 中非本节点 gateway LAN IP 的 /32 或 /128，`none` 不生成任何策略条目。
- `remote_service` 采用 Cilium `toServices` 类似的 egress-only 语义，引用同 VPC 的 desired-state `LoadBalancer`，编译时把服务 VIP 展开为 /32 或 /128；LoadBalancer 可用 `ports` 声明多个 frontend，规则未显式指定协议或端口时会为每个 frontend 继承对应 protocol/port。
- `remote_cidr` 可声明 `except_cidrs`，编译器会把主 CIDR 拆成排除例外后的最小 CIDR 集合；和 Cilium 一样，例外 CIDR 必须包含在主 CIDR 内，且不和 `remote_cidr_group` 混用。
- `remote_cidr_group` 采用 Cilium `CIDRGroupRef`/`CIDRSet` 类似的安全组 CIDR 集合语义，CIDRGroup 作为 desired-state 对象集中维护可复用 CIDR 列表；既支持 `cidrs` 简写，也支持 `entries` 中为每个 CIDR 声明 `except_cidrs`，编译时会先做 CIDR 差集展开再写入 endpoint policy map。
- `remote_fqdns` 采用 Cilium `toFQDNs` 类似的安全组 egress 语义，支持 `match_name` 和 `match_pattern`，会从 desired-state `dns_records` 与 agent 的 `NETLOOM_DNS_OBSERVATIONS_FILE` 运行时 DNS 观测缓存派生 CIDR policy entry；`match_pattern` 采用 Cilium label wildcard 语义，普通 `*` 不跨 `.`，前缀 `**.` 可匹配一层或多层子域；`dns_records` 可通过 `ttl_seconds` + `observed_at` 表达 DNS cache TTL，过期记录不会编译进策略。
- ACL 不放到 OVN ACL 里实现，避免和 eBPF 策略路径重叠。
- DNAT 和 Floating IP 端口映射会校验协议意图；DNAT external/target 端口相同时投影为 OVN NAT `--portrange`，端口不同时直接创建 OVN `NAT` 行并设置 `external_port_range` 与 `logical_port_range`，Floating IP (`dnat_and_snat`) 端口映射也使用同一原生 NAT row 路径，避免为了端口转换引入额外 Load_Balancer 拓扑；分布式 Floating IP 可声明 OVN 原生的 `logical_port` 与 `external_mac`，两者必须成对出现在 `dnat_and_snat` 规则上；控制面仍把同一个 EIP+端口视为冲突，避免 NAT 投影互相覆盖。
- 控制面 resolver 会解析 DNAT 和 Floating IP (`dnat_and_snat`) 入站目标，用于在单元测试和 selftest 中验证 Kube-OVN 风格 NAT 语义。
- `LoadBalancer` 使用 OVN `lb-add`/`lr-lb-add`/`ls-lb-add` 表达 Kube-OVN 风格的 VPC Service VIP，并统一通过 `ports` 声明同一个 Service VIP 下的多个 frontend 和不同 target port；控制面会拒绝同 VPC 内重复的 VIP+协议+端口；支持 OVN `affinity_timeout` 形式的 ClientIP session affinity，并会投影 `selection_fields`，未显式声明时 session affinity 默认使用 IPv4 `ip_src` 或 IPv6 `ipv6_src`；支持 Kube-OVN/OVN 风格的 `Load_Balancer_Health_Check` 健康检查选项，多 frontend 会按 VIP 幂等复用并更新对应的 health check row；backend 可声明 `healthy=false` 从本地 resolver 与 OVN VIP backend 列表中剔除，未声明时默认健康，控制面要求每个 frontend 至少保留一个健康 backend；state-file controller 可设置 `NETLOOM_LB_HEALTH_PROBE=1` 对启用 health check 的 TCP backend 做主动探测，并按 `success_count`/`failure_count` 跨 reconcile 收敛 healthy 状态；同名 LB 的 VIP、backend 和绑定子网变化会按 desired state 收敛，避免旧 Service VIP 残留。
- 控制面 resolver 会按 VPC、VIP、协议、端口和绑定子网解析 Service VIP，并基于 flow 与 backend 做稳定选择，用于在单元测试和 selftest 中验证负载均衡语义。
- `Subnet` 可以声明 `provider_network` 和 `vlan`，OVN 后端会创建 `localnet` 逻辑端口，用于对接 Kube-OVN 常见的 underlay/provider network 场景；provider/VLAN 变化或 provider 关闭时会重建或删除 localnet port。
- `Subnet` 可以开启 DHCP，OVN 后端会为 endpoint logical switch port 生成并绑定 DHCPv4/DHCPv6 options；IPv4 覆盖 router/server/lease/MTU 等常见 Kube-OVN 子网 DHCP 语义，IPv6 会生成 `server_id` 并在 router port 上启用 `dhcpv6_stateful` RA；当 DHCP 关闭时会清空端口 DHCP 绑定，保持 desired state 收敛。

## 开发

### 依赖要求

- Go `1.26+`
- `task` 用于执行下面的便捷命令

### 常用命令

```bash
# 安装开发工具
task deps

# 执行静态检查
task lint

# 执行测试
task test

# 执行跨模块集成测试
task test:integration

# 执行 Docker 多节点 e2e 测试，需要 Docker 和可用的 privileged 容器能力
task test:e2e

# 重建并修复 e2e lab 环境
task env:doctor

# 构建二进制
task build
```

`task test` 会运行所有 Go 包测试，包括 `tests/integration`；`task test:e2e` 会启动 Docker Compose lab，用多个容器模拟节点，验证 OVN Northbound、控制面 state-file、OVN desired-state 删除、基于 netlink 的 Linux netns 工作负载、跨节点连通性、策略路由输出、运行时 DNS 观测刷新 FQDN 安全组策略、remote-group 安全组策略、eBPF/TCX ACL drop/allow 和 stale namespace cleanup。
`task env:doctor` 会重新构建 `bin/` 下的二进制、清空并重建 Docker e2e lab、等待 OVN NB 就绪，并校验 `node-a/node-b/node-c` 的 privileged netns/eBPF 前置条件，适合在本地环境跑乱后直接恢复。

agent 以 `NETLOOM_STATE_FILE` 运行时可额外设置 `NETLOOM_DNS_OBSERVATIONS_FILE=/path/dns.json`，让每轮 reconcile 合并运行时 DNS 观测记录并刷新 `remote_fqdns` 派生策略；文件可以是 `{"dns_records":[...]}` 文档或 `DNSRecord` 数组，字段与 desired-state `dns_records` 相同。
agent 还提供离线策略解释入口，用于裸金属排障时回答某个 packet tuple 为什么被 allow/drop/reject：`netloom-agent policy-explain -state desired.json -vpc prod -endpoint pod-a -remote-endpoint pod-b -direction ingress -protocol tcp -dest-port 443` 会读取同一 desired-state，按 controller/agent 相同路径编译安全组，并输出 JSON，包含 verdict、reason、匹配 rule cookie、匹配 entry、remote identity/IP、PMTU/NDP 特判和 stateful 标记。`-remote-endpoint` 会自动推导 Cilium 风格 endpoint identity；也可以直接传 `-remote-identity` 和 `-remote-ip`。
agent 还提供 endpoint policy lifecycle 状态入口：`netloom-agent policy-status -state desired.json -node node-a -endpoint pod-a` 会使用同一 policy store 下发/读取该节点策略，并输出 endpoint revision、policy map 使用率、live-vs-desired drift、last stats 和 last update event；设置 `NETLOOM_POLICY_STORE=ebpf` 时会复用 pinned eBPF policy map 和 metadata root 来读取 live map 状态。
agent 可设置 `NETLOOM_POLICY_GC_MAX_IDLE_MS=600000` 启用 policy map aging/GC。本轮 desired endpoint 会被保留，非 desired endpoint 只有在最后一次成功更新超过该窗口后才会删除；eBPF store 会把更新时间写入 policy map metadata，进程重启后仍可按 metadata 清理旧 pinned map。
agent 还提供离线路由解释入口，用于回答某个三/四层 packet tuple 为什么被策略路由 reroute/drop、为什么落到静态路由、使用哪个 ECMP next-hop/gateway 以及是否套用 SNAT/DNAT/LB 转换：`netloom-agent route-explain -state desired.json -vpc prod -source 10.10.0.10 -dest 172.16.1.10 -protocol tcp -source-port 32001 -dest-port 443` 会输出 topology resolver 的 JSON decision，其中 `matched_by=policy-route/<name>`、`route-table/<name>`、`nat/<name>`、`load-balancer/<name>` 或 `no-route` 直接说明命中的控制面对象。
agent 以周期 reconcile 模式运行时可设置 `NETLOOM_AGENT_METRICS_ADDR=:9091`，在 `/metrics` 暴露 Prometheus text metrics，在 `/healthz` 暴露简单健康检查。metrics 包含最近一轮 reconcile 是否成功、耗时、policy map entries/capacity/pressure、policy map live-vs-desired drift、rule-level packet/byte/allow/drop/reject/log counters、累计 policy add/update/delete/failure/rollback counters、reconcile latency histogram 以及 TCX attach failure/rollback 信号。
`netloom-dns-observer` 可作为 DNS proxy/sidecar 前置观测入口使用：它从 `base64-lines`、`hex-lines` 或单个 `raw` DNS wire response 输入中解析 answer/authority/additional 区域的 `A`/`AAAA`/`CNAME` 记录，并原子合并写入同一个 observations 文件，例如 `netloom-dns-observer -observations /tmp/netloom-dns.json < responses.b64`。
仓库内的 `internal/dnsobserver` 包提供同一解析能力，便于后续把数据源替换成 eBPF、NFQUEUE 或真实 DNS proxy 捕获路径，而不改变 agent 的策略编译接口。

controller 以 `NETLOOM_STATE_FILE` 运行时可额外设置 `NETLOOM_LB_HEALTH_PROBE=1`，对开启 `health_check.enabled` 的 TCP LoadBalancer backend 做主动 TCP 探测，并在本轮 reconcile 前把失败 backend 标记为 unhealthy；显式 `healthy=false` 的 backend 视为人工摘除，不会被探测恢复。

controller 使用真实 OVN backend 时会给每次 `ovn-nbctl` 调用设置默认 30 秒超时，避免 OVN NB 卡住时阻塞 reconcile；可通过 `NETLOOM_OVN_NBCTL_TIMEOUT_MS` 调整，设置为 `0` 表示只继承外部 context。NBCTL 瞬时失败默认会做 3 次退避重试，可通过 `NETLOOM_OVN_NBCTL_RETRY_ATTEMPTS`、`NETLOOM_OVN_NBCTL_RETRY_INITIAL_BACKOFF_MS`、`NETLOOM_OVN_NBCTL_RETRY_MAX_BACKOFF_MS` 调整，适用于 OVN DB 重启或 unix socket 短暂抖动场景。live audit 默认沿用 `ovn-nbctl find`；设置 `NETLOOM_OVN_AUDIT_BACKEND=libovsdb` 后会使用本地 OVN NB model 和 libovsdb monitor/cache 读取 live managed rows，endpoint 从 `NETLOOM_OVN_LIBOVSDB_ENDPOINT` 读取，未设置时复用 `NETLOOM_OVN_NBCTL_DB`。
controller 以周期 reconcile 模式运行时可设置 `NETLOOM_CONTROLLER_METRICS_ADDR=:9090`，在 `/metrics` 暴露 Prometheus text metrics，在 `/healthz` 暴露简单健康检查。metrics 包含最近一轮 reconcile 是否成功、耗时、desired object 数量、policy entry 数量、LB health probe 汇总、OVN health latency、连续 OVN health 失败/成功次数、OVN health recovery 状态、OVN planned/executed operation 数、OVN desired-state cleanup/drift 统计、真实 OVN NB 中带 `external_ids:netloom_owner=netloom` 的 live managed row audit 统计，以及累计 reconcile counters 和 latency histogram；live audit 会按 Logical Switch/Router/Port/Policy/NAT/LB/HealthCheck/DHCP 分表输出，并标记重复、缺少身份字段、desired 缺失、live 里多余的托管行，以及 endpoint/gateway/LB/provider 等 Netloom-managed `external_ids` 字段值漂移。audit 查询失败会通过 `netloom_controller_ovn_audit_*` 指标暴露，但不会把已成功的 reconcile 标记为失败。
state-file controller 的失败日志会输出 `reconcile_phase`，用于区分 `ovn_health`、`load_state`、`lb_health` 和 `apply` 阶段失败，并输出 `ovn_health_consecutive_failures`、`ovn_health_consecutive_successes` 和 `ovn_health_recovering`，便于裸金属部署时快速判断是 OVN 可用性、配置文件、健康探测还是拓扑下发问题。

## 参与贡献

参见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

[Apache 2.0](LICENSE)
