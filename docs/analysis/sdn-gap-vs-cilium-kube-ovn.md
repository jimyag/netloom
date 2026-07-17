# Netloom SDN Gap Analysis vs Cilium / Kube-OVN

This note is for the bare-metal Netloom product only. It explicitly ignores Kubernetes integration work and focuses on reusable implementation patterns.

## What Netloom already has

The current codebase already covers the core SDN object model and the main enforcement paths:

- OVN control-plane objects:
  `VPC`, `Subnet`, `Endpoint`, `RouteTable`, `PolicyRoute`, `Gateway`, `NATRule`, `LoadBalancer`
  in [internal/ovn](/home/jimyag/src/github/jimyag/netloom/internal/ovn) with unit and e2e coverage in
  [tests/e2e](/home/jimyag/src/github/jimyag/netloom/tests/e2e) and
  [tests/integration/sdn_integration_test.go](/home/jimyag/src/github/jimyag/netloom/tests/integration/sdn_integration_test.go).
- Linux bare-metal datapath for:
  local/remote endpoint routes, provider VLAN links, policy routing in
  [internal/linuxdatapath](/home/jimyag/src/github/jimyag/netloom/internal/linuxdatapath).
- eBPF-style ACL compilation and TCX attach path in
  [internal/policy](/home/jimyag/src/github/jimyag/netloom/internal/policy),
  [internal/dataplane](/home/jimyag/src/github/jimyag/netloom/internal/dataplane),
  [internal/agent](/home/jimyag/src/github/jimyag/netloom/internal/agent).

So from a "can it model VPC/subnet/gateway/security-group/policy-route and enforce them" perspective, the answer is yes.

## Verified points from Kube-OVN

Kube-OVN does not rely on a KubeVirt-specific OVN package here. Its OVN path is built around `libovsdb`:

- typed OVSDB client construction:
  `/tmp/kube-ovn/pkg/ovsdb/client/client.go`
- typed logical switch / localnet operations:
  `/tmp/kube-ovn/pkg/ovs/ovn-nb-logical_switch_port.go`
- typed health-check CRUD:
  `/tmp/kube-ovn/pkg/ovs/ovn-nb-load_balancer_health_check.go`
- typed logical router policy / static route CRUD and tests:
  `/tmp/kube-ovn/pkg/ovs/ovn-nb-logical_router_policy.go`
  `/tmp/kube-ovn/pkg/ovs/ovn-nb-logical_router_route.go`
  `/tmp/kube-ovn/pkg/ovs/ovn-nb-suite_test.go`

For underlay/provider networking, Kube-OVN also has explicit provider network lifecycle and VLAN sub-interface coverage:

- feature notes:
  `/tmp/kube-ovn/NEXT.md`
- provider network e2e:
  `/tmp/kube-ovn/test/e2e/kube-ovn/underlay/underlay.go`
- VLAN sub-interface create/isolation/cleanup e2e:
  `/tmp/kube-ovn/test/e2e/kube-ovn/underlay/vlan_subinterfaces.go`

## Verified points from Cilium

Cilium's useful reference for your eBPF ACL direction is not "how to do OVN", but how to run a long-lived endpoint policy datapath safely:

- incremental endpoint policy-map updates with wait/revert/finalize:
  `/tmp/cilium/pkg/endpointmanager/manager.go`
- policy-map pressure tracking and metrics:
  `/tmp/cilium/pkg/endpointmanager/policymap_pressure.go`
- pinned per-endpoint LPM trie policy map in BPF:
  `/tmp/cilium/bpf/lib/policy.h`

This is the part Netloom should copy in spirit.

## Missing work worth outsourcing

These are the highest-signal gaps I see now.

### 1. Complete the typed OVSDB client layer

Netloom now uses a typed OVSDB path by default when an OVN Northbound endpoint is configured. The remaining work is to keep shrinking the old command-planner surface in
[internal/ovn](/home/jimyag/src/github/jimyag/netloom/internal/ovn). It has a typed managed-row audit seam:
`ManagedOVNReader` returns `ManagedOVNRow` objects for live state accounting, and `LibOVSDBManagedReader` can read the same managed rows from a real libovsdb monitor/cache using Netloom-local OVN NB models under `internal/ovn/ovsdb/ovnnb`. Those models are pulled into this repository from Kube-OVN's generated OVSDB model package, so Netloom follows Kube-OVN's local model pattern without relying on a `go.mod` replace to the Kube-OVN fork. When `NETLOOM_OVN_LIBOVSDB_ENDPOINT` points at an OVN Northbound endpoint, the state-file controller uses libovsdb for both topology writes and live audit; explicit `NETLOOM_OVN_TOPOLOGY_BACKEND=nbctl` or `NETLOOM_OVN_AUDIT_BACKEND=nbctl` is rejected so the live product path writes OVN state directly to OVSDB. Live audit compares managed-row identities against desired state to report missing and unexpected managed rows, and `LibOVSDBTopologyWriter` can directly create/update VPC logical routers, Subnet logical switches/IPAM `other_config`, router ports, router switch ports, provider localnet ports, Endpoint logical switch ports, DHCP_Options, RouteTable static routes, RouteTable static route BFD rows, PolicyRoute rows, Gateway router metadata, NAT rows, Load_Balancer rows, Load_Balancer_Health_Check rows, and DNS rows in OVN Northbound DB transactions. It also implements lifecycle cleanup for direct OVSDB mode: desired-state removal deletes managed rows by UUID after detaching parent references, first reconcile scans live managed rows to remove orphan objects not present in current desired state, and later steady-state reconcile passes keep scanning for runtime unexpected or incomplete Netloom-managed rows when no desired deletion/replacement cleanup is already in flight. The same steady-state path now repairs core OVN name drift, Logical Router stale options/LB-group references, Router/Router Port disabled drift, and Logical Switch stale ACL/QoS/forwarding/LB-group references, Subnet router/localnet port parent attachment drift, IPv6 router port RA drift, LoadBalancer router/switch parent attachment drift, LoadBalancer `vips`/`protocol`/`selection_fields`/managed `external_ids`/managed session-affinity option drift, Endpoint Logical Switch Port `addresses`, `port_security`, stale `type`, `options`, `tag`, and `enabled` drift, endpoint DHCP option family metadata and LSP DHCP attachment drift, DNS row/switch attachment drift, RouteTable static route row drift, RouteTable static route BFD row drift, PolicyRoute row drift, Gateway router options/external_ids drift, NAT row drift, plus managed LoadBalancer health-check attachment drift, so named Netloom rows can be found again through their expected OVN names, disabled routers or router ports cannot silently blackhole a VPC/subnet, subnet ports and load balancers cannot stay detached from or misattached to logical router/switch parents, IPv6 router advertisements cannot silently lose DHCPv6 stateful mode, ordinary endpoint ports cannot keep stale localnet/router/VLAN roles or wrong address security, DHCP and DNS rows cannot stay stale or detached from desired ports/switches, route/NAT/gateway rows cannot keep stale desired fields, disabled affinity cannot leave `affinity_timeout` behind, load balancer VIP/backend/protocol hashing state cannot remain stale, and enabled health checks are reattached from desired state in the NB DB. Cleanup stats report stale live-row counts for logical switch ports, logical router ports, DHCP options, DNS rows, static route BFD rows, and load-balancer health checks alongside topology objects. It is still not a full typed OVN write client for every topology object.

What is missing:

- typed cache/monitor write support beyond VPC logical routers, Subnet/Endpoint logical switch topology, DHCP_Options, DNS rows, static routes, static route BFD rows, policy routes, Gateway router metadata, NAT rows, Load_Balancer rows, Load_Balancer_Health_Check rows, and live managed-row audit
- clustered OVN DB leader/failover behavior beyond reconnecting a single libovsdb topology client

Reference:

- `/tmp/kube-ovn/pkg/ovsdb/client/client.go`
- `/tmp/kube-ovn/pkg/ovs/ovn-nb-logical_router_policy.go`
- `/tmp/kube-ovn/pkg/ovs/ovn-nb-logical_router_route.go`

This is the single most important control-plane hardening area still missing.

### 2. Provider network management is still too thin for a product

Netloom can create provider VLAN links, discover provider interface inventory, select ready candidate parent interfaces, report per-provider readiness/issues, and sync local OVS `Open_vSwitch` database bridge mappings whenever `NETLOOM_OVSDB_ENDPOINT` is configured. It now turns runtime parent/link drift into explicit provider issues and network-level reasons such as `parent-down`, `link-missing`, and `link-drift`, so underlay breakage remains visible after initial planning succeeds. When OVSDB sync is enabled, the agent creates deterministic OVS bridges, attaches managed provider VLAN links, repairs managed Bridge.Controller and port-to-bridge drift, annotates Bridge/Interface rows with Netloom `external_ids`, writes `external_ids:ovn-bridge-mappings` for OVN localnet resolution, and removes stale Netloom-owned provider bridges when cleanup mode is enabled. Netloom also carries local Kube-OVN-derived `Open_vSwitch` DB models under `internal/ovn/ovsdb/vswitch` and builds typed desired rows for the provider `Open_vSwitch`, `Bridge`, `Controller`, `Port`, `Interface`, `QoS`, and `Queue` tables, so the local underlay state has a structured OVSDB representation rather than only command strings. The bare-metal agent uses the netlink/netns package datapath for NIC, namespace, address, route, and RPDB operations; when `NETLOOM_OVSDB_ENDPOINT` is set, provider OVS state is written through libovsdb transactions against those typed `Open_vSwitch` rows to create/update bridges, provider OpenFlow controller rows, bridge-controller references, ports, interfaces, bridge mappings, wrong-bridge port drift, provider egress QoS rows, provider tenant Queue rows, QoS attachment/queue drift, and cleanup of stale Netloom-owned provider rows instead of issuing `ovs-vsctl` writes. The controller also writes its latest reconcile status into `Open_vSwitch.external_ids:netloom_controller_status`, including desired object counts, OVN health, live audit stats, stale advisory state, maintenance result, and reconcile latency, so a bare-metal node can expose control-plane state directly from OVSDB. The agent writes the matching node-side summary into `Open_vSwitch.external_ids:netloom_agent_status`, including policy/eBPF rollout counters, TCX state, provider health, last error, and reconcile latency. It also reads provider bridge mapping, bridge, port, interface, QoS, Queue, bridge controller connection status, `Controller.status` target/state/role/last_error details, multi-controller local quorum state, and live `Open_vSwitch`/`Bridge`/`Port`/`Interface`/`QoS`/`Queue`/`Controller` UUID path attribution from the same libovsdb monitor/cache: all connected reports `up`, none connected reports `disconnected`, and partial connectivity reports `degraded` with `connected=x/y` detail. The agent reports `ovsdb-bridge-missing`, `ovsdb-mapping-missing`, `ovsdb-port-drift` with `qos-mismatch` detail, `ovsdb-interface-drift`, and `ovsdb-controller-drift` provider issues; those issue details include the live OVSDB row path when available, and strict provider health fails on those OVSDB-backed network issues. Provider networks can now declare `isolation=exclusive`; the datapath rejects parent-interface sharing with any other provider network, reports `parent-isolation-conflict`, and writes the isolation intent into managed OVSDB `external_ids`. Provider networks can declare `controller_targets` to store provider bridge OpenFlow controller intent directly in OVS `Controller` rows referenced by `Bridge.Controller`; removing a target detaches the managed controller from the bridge, and cleanup removes stale Netloom-owned Controller rows. Provider networks can also declare `qos.egress_rate_bps` and optional `qos.egress_burst_bps` to attach OVS `QoS(type=linux-htb)` to the managed provider port. Provider networks can declare `tenant_queues` to create per-tenant OVS `Queue` rows, attach them to `QoS.queues` by queue id, and install OpenFlow `set_queue` rules that classify provider traffic by VPC tenant CIDR, optional TCP/UDP port selectors, endpoint label selectors, inline identity selectors, and reusable identity groups. `identity_groups` are VPC-scoped desired-state objects suitable for external directory or CMDB sync; they support explicit endpoint ids plus selector/expression membership, source/observed_at/ttl_seconds feed metadata, expired feed rejection, local OVSDB feed polling through `Open_vSwitch.external_ids:netloom_identity_group_observations`, authenticated HTTP(S) feed polling through `NETLOOM_IDENTITY_GROUPS_URL` plus optional Bearer token or mTLS, ETag/Last-Modified conditional requests, source-specific failure backoff with cached last-good feeds, incremental `identity_group_patches` upsert/delete documents against the cached last-good remote snapshot, and conflict reporting when two identity group queues for the same provider/tenant overlap. They compile to endpoint-specific `/32` or `/128` queue flows, Queue rows record `netloom_queue_identity_groups` in `external_ids`, and the resolved group snapshot is persisted in `Open_vSwitch.external_ids:netloom_identity_groups` so a bare-metal node can audit current group membership directly from OVSDB. Provider networks can declare `tenant_quotas` with VPC tenants and `max_subnets`/`max_endpoints`; the control plane rejects desired state that exceeds those limits, and the agent reports current tenant usage in provider network status plus Prometheus metrics.
DNS runtime observations also use the local OVSDB path now: `netloom-dns-observer` writes parsed DNS cache snapshots into `Open_vSwitch.external_ids:netloom_dns_observations` when `NETLOOM_OVSDB_ENDPOINT` or `-ovsdb` is configured, and the agent reads that same key before compiling `remote_fqdns` policy entries. It can run as UDP and TCP DNS proxy/capture paths with `-listen-udp`/`-upstream-udp` or `-listen-tcp`/`-upstream-tcp`: queries are forwarded to upstream DNS, responses are returned to clients, and A/AAAA/CNAME answers are merged into the same OVSDB-backed observation snapshot. TCP DNS uses the standard two-byte length-prefixed wire framing and supports multiple queries on the same client connection. It also has an AF_PACKET passive capture path through `-capture-iface`, with IPv4/IPv6 UDP DNS response extraction, VLAN frame handling, `-capture-count`, and `-capture-duration`, so bare-metal nodes can observe DNS without forcing workloads through the proxy path. For netfilter-based datapaths it now has an optional NFQUEUE DNS response capture backend behind the explicit `netloom_nfqueue` build tag, using queued IP-layer payloads and returning `NF_ACCEPT` after observation, while default builds avoid the `libnetfilter_queue` cgo dependency. There is no file fallback for product runtime observations; isolated tests inject the same store interface directly.

What is missing:

- eBPF DNS capture paths beyond the built-in UDP/TCP DNS proxy, AF_PACKET passive UDP response capture, and optional NFQUEUE response capture
- deeper clustered OVS/OVN controller connectivity analysis beyond local multi-controller quorum, local OVSDB row path attribution, OVN cluster-wide quorum, and OVSDB `Controller.status` target/state/role/error detail, such as cross-chassis path attribution

Reference:

- `/tmp/kube-ovn/test/e2e/kube-ovn/underlay/underlay.go`
- `/tmp/kube-ovn/test/e2e/kube-ovn/underlay/vlan_subinterfaces.go`
- `/tmp/kube-ovn/pkg/apis/kubeovn/v1/provider-network.go`

For bare metal, this should become a native Netloom subsystem, not a CRD clone.

### 3. eBPF ACL datapath lacks Cilium-grade operational controls

Netloom already has compile/store/evaluate/TCX attach. It also has policy-map pressure metrics, overflow rejection before programming, configurable fail-closed overflow remediation that clears an endpoint policy map when an oversized desired map cannot be installed, pinned-map drift repair that ignores counter-only changes, explicit live-vs-desired policy-map drift telemetry, attach/update rollback signals, per-endpoint usage accounting, endpoint-scoped lifecycle status with revision, drift, pressure, last stats, and last event, a long-running `/policy/events` API for recent endpoint policy-map update success/failure/remediation events, a long-running `/policy/entries/{endpoint}` API for inspecting live endpoint policy-map keys, values, counters, and remote CIDRs, conservative rule-level CIDR compaction for equivalent adjacent CIDR expansions, SCTP/TCP/UDP/ICMP L4 policy-map encoding, TCX IPv4/IPv6 fast-path projection for SCTP/TCP/UDP/ICMP CIDR rules, TCX fast-path projection for remote-group and remote-endpoint-selector rules when the compiler has an exact endpoint `/32` or `/128` while preserving Cilium-style remote identity checks in the userspace policy map, `netloom-agent policy-status` as a JSON CLI around that status view, a default agent selftest that validates policy compile/evaluate, stateful conntrack, policy event/counter paths, TCX status, bpffs, memlock, BPF/SYS_ADMIN and NET_ADMIN capability readiness, and configured OVSDB/OVN endpoints with fail-closed `NETLOOM_SELFTEST_STRICT_RUNTIME=1`, a long-running `/policy/endpoints` HTTP API around the latest endpoint lifecycle status, `DELETE /policy/endpoints/{endpoint}` for operator-triggered endpoint policy map reset in long-running agents, `POST /policy/endpoints/{endpoint}/plan` for staged dry-run policy update planning without modifying live maps, `POST /policy/endpoints/{endpoint}/regenerate` for Cilium-style forced endpoint policy regeneration from the latest successful desired state, `POST /policy/endpoints/{endpoint}/quarantine` for scoped endpoint isolation with ingress and egress deny-all policy entries, `POST /policy/endpoints/{endpoint}/unquarantine` and `POST /policy/endpoints/{endpoint}/rollback` for restoring the endpoint policy from the latest successful desired state, `POST /policy/endpoints/{endpoint}/freeze` and `/unfreeze` for temporarily holding an endpoint policy map and TCX projection across normal reconcile loops with optional TTL/RFC3339 expiry and local OVS `Open_vSwitch.external_ids:netloom_policy_freeze_state` persistence, filterable `GET /policy/endpoints/actions/history` with optional local OVS `Open_vSwitch.external_ids:netloom_policy_endpoint_action_history` persistence for successful and failed endpoint lifecycle actions with `success` filtering, and `POST /policy/endpoints/rollout` for staged multi-endpoint policy rollout with all-endpoint planning, configurable batch size, pressure-aware automatic batch shrinking, dry-run mode, per-endpoint phase and reason reporting, stop-on-failure blast-radius control, automatic rollback of endpoints already modified in the failed rollout, SLO-gated canary checks based on policy rule drop/reject telemetry, optional multi-window counter-delta evaluation from a pre-rollout baseline, HTTP status/body, TCP, and TLS external traffic probes after each batch, explicit pause/resume controls through `paused` and `pause_after_batches`, explicit operator cancellation through `cancelled`, approval checkpoints through `approval_required`/`approved` with `approval_ref` preserved for external change-ticket audit, HMAC approval signatures, approval expiry fail-closed gates through `approval_expires_at`, fail-closed external approval callbacks carrying rollout revision through `approval_callback_url`, explicit operator acknowledgement checkpoints through `ack_required`/`acknowledged` with `ack_ref` and `ack_pending` status, acknowledgement expiry fail-closed gates through `ack_expires_at`, post-canary finalize checkpoints through `finalize_required`/`finalized` with `finalize_ref` and `finalize_pending` status, finalize expiry fail-closed gates through `finalize_expires_at`, fail-closed external change-status polling carrying rollout revision through `change_poll_url` before any policy-map mutation, external change-system result synchronization through `change_status_url`, and weighted promotion limits through `promotion_percent`. Desired-state `policy_rollouts` now lets the bare-metal agent defer normal policy writes for active rollout nodes, then progressively apply the declared endpoint subset with batch, dry-run, pressure-aware, SLO-gated, probe, pause, cancellation, approval, acknowledgement, finalize, external change poll, promotion, and external change-status synchronization controls while reporting rollout planned/applied/skipped/failed/rolled_back/rollback_failed/slo_failed/probe_failed/paused/cancelled in logs and Prometheus metrics. When desired state is stored in local OVS `Open_vSwitch.external_ids:netloom_desired_state`, operators can declare `policy_rollouts[].dry_run=true` or `policy_rollouts[].cancelled=true` directly in OVSDB to get a staged endpoint rollout plan or auditable cancellation result without mutating live policy maps. Rollout history and external status payloads include rollout revision plus stable per-endpoint reasons for operator pause, operator cancellation, approval/ack/finalize pending, approval/ack/finalize expiry, batch pause, promotion limit, apply failure, SLO/probe rollback, rollout skip, rollback failure, and resumed-applied state. Long-running agents also keep recent manual/desired-state rollout history in memory, persist it in local OVS `Open_vSwitch.external_ids:netloom_policy_rollout_history` when `NETLOOM_OVSDB_ENDPOINT` is configured, and expose it through `GET /policy/endpoints/rollout/history`; revision-isolated paused/failed desired-state rollout resume state is stored in local OVS `Open_vSwitch.external_ids:netloom_policy_rollout_state` through the same OVSDB path. Already-applied endpoints survive restart and are resumed as `resumed_applied` while remaining endpoints continue. It also has configurable non-desired endpoint policy-map aging/GC for long-running bare-metal agents, pressure-triggered mitigation that deletes non-desired managed endpoint maps before the pressured store reaches capacity, and opt-in pressure-triggered endpoint quarantine through `NETLOOM_POLICY_PRESSURE_QUARANTINE`; `NETLOOM_POLICY_PRESSURE_QUARANTINE_THRESHOLD` can be higher than the mitigation threshold so cleanup can happen at an early waterline while desired endpoint fail-closed isolation is reserved for a later waterline. What it still lacks is the larger operational hardening layer Cilium has around policy maps.

What is missing:

- richer policy-map operational hardening beyond endpoint map reset, live map entry inspection, dry-run planning, forced regenerate/reconcile, scoped quarantine, unquarantine, rollback-to-desired, endpoint policy freeze/unfreeze, success/failure action history, desired-state progressive dry-run rollout planning, desired-state progressive rollout, stop-on-failure staged rollout, failed-rollout automatic rollback, multi-window SLO-gated canary analysis, HTTP status/body, TCP, and TLS external traffic probes, pause/resume/cancel controls, auditable approval, acknowledgement, and finalize checkpoints, approval/ack/finalize expiry gates, HMAC signatures, external approval callbacks, external change-ticket status polling, weighted promotion rules, persisted rollout history, revision-isolated durable applied-endpoint rollout state, per-endpoint phase/reason reporting, and external change-system status synchronization, such as a fuller multi-step rollout state machine with richer operator workflows

Reference:

- `/tmp/cilium/pkg/endpointmanager/manager.go`
- `/tmp/cilium/pkg/endpointmanager/policymap_pressure.go`
- `/tmp/cilium/bpf/lib/policy.h`

This is the most important missing work on the eBPF side.

### 4. Rule-level observability is still shallow

Netloom has drop/trace style events, policy-rule packet/byte counters in the evaluator, policy explanation helpers and `netloom-agent policy-explain` for packet verdict/reason/matched-rule debugging without writing policy counters or creating conntrack state, `netloom-agent route-explain` for topology/policy-route/reroute/drop/NAT/LB/gateway decisions from desired state, long-running agent `/policy/explain` and `/route/explain` APIs backed by the latest successfully reconciled desired state, a long-running agent `/policy/rules` JSON API that merges latest rule counters with the compiled rule catalog for operator-friendly endpoint/rule inspection, a long-running agent `/policy/events` JSON API for recent endpoint policy-map update events with endpoint filtering and bounded history, an agent telemetry interface that can surface endpoint/rule counters in normal reconcile output, a pinned eBPF policy-map reader for counter fields, TCX L4 ACL maps that increment packet/byte counters in the fast path and merge those counters back into agent telemetry after reconcile, a long-running agent Prometheus text endpoint for reconcile, policy-map, policy-rule, TCX counters, cumulative policy add/update/delete/failure/rollback counters, and reconcile latency buckets, plus long-running controller Prometheus and `/status` JSON endpoints for desired object counts, LB health probes, OVN health latency, OVN health consecutive failure/success and recovery state, OVN operation counts, reconcile success/failure, OVN cluster leader/quorum endpoint detail, OVN desired-state cleanup/drift counters, live OVN NB managed-row audit counts, duplicate/incomplete managed-row gauges, missing/unexpected managed-row gauges, external-id field drift gauges, stale advisory and maintenance result state, and libovsdb-backed column drift checks for core OVN names, Logical Router stale options/LB-group references, Router/Router Port disabled state, Logical Switch config and stale ACL/QoS/forwarding/LB-group references, Logical Router/Switch Port attachments, endpoint Logical Switch Port `addresses`/`port_security` and stale `type`/`options`/`tag`/`enabled`/DHCP attachments, IPv6 router-port RA config, LSP DHCP option attachments, Router/Switch LoadBalancer attachments, Router NAT attachments, Router Policy/Static Route attachments, Gateway router options, Policy, Static Route, Static Route BFD, NAT, LoadBalancer rows including stale session-affinity options and health-check attachments, LoadBalancer HealthCheck rows, DHCP rows, and DNS rows. This now gives the product a stable place to report live datapath and control-plane counters, but it is not yet Cilium/Kube-OVN grade runtime observability.

What is missing:

- full OVN column-level value drift telemetry beyond the currently audited core names, Logical Router stale options/LB-group references, Router/Router Port disabled state, and Logical Switch stale ACL/QoS/forwarding/LB-group references, topology, endpoint Logical Switch Port addresses/port_security and stale type/options/tag/enabled/DHCP state, IPv6 router-port RA config, router/switch port attachments, LSP DHCP option attachments, router/switch load-balancer attachments, router NAT attachments, router policy/static route attachments, gateway router options, route, service, LoadBalancer stale session-affinity/health-check attachment state, NAT, DHCP, and DNS columns

This is product work, not just test work.

### 5. OVN control-plane health and recovery workflows are minimal

Kube-OVN has explicit leader/DB-health/recovery logic around OVN:

- `/tmp/kube-ovn/pkg/ovn_leader_checker/ovn.go`
- `/tmp/kube-ovn/pkg/ovnmonitor`

Netloom now has libovsdb `echo` health probing and echo-failure reconnect for direct OVSDB topology mode, a reconnecting libovsdb topology health checker that rebuilds and re-monitors the Northbound client with configurable backoff after disconnects or echo failures, comma/whitespace separated OVN Northbound libovsdb endpoint failover for initial connect and health reconnect, optional `NETLOOM_OVN_LEADER_STATUS_CMD` leader endpoint probing with leader-aware connection preference, built-in `ovn-appctl -t <target> cluster/status OVN_Northbound` leader probing through `NETLOOM_OVN_CLUSTER_STATUS_TARGETS`, per-endpoint OVN cluster/status parsing for target, role, server ID, leader ID, reachability, and error telemetry in controller status/metrics, cluster-wide quorum summaries for reachable endpoint count, quorum size, leader count, and `ok`/`degraded`/`lost`/`split-brain`/`unknown`/`disabled` quorum status in logs, metrics, `Open_vSwitch.external_ids:netloom_controller_status`, and the controller `/status` JSON API, bounded recent reconcile event history in local `Open_vSwitch.external_ids:netloom_controller_events` plus `netloom-controller controller-events` for offline health/audit/failure-phase review, opt-in per-database OVN DB compaction after successful reconcile through `NETLOOM_OVN_DB_COMPACT_TARGETS`, stale-state advisory through `NETLOOM_OVN_STALE_ADVISORY_THRESHOLD` that warns when live audit missing/unexpected/drifted/duplicate/incomplete managed rows exceed an operator-defined burden, an OVSDB-audit-driven `NETLOOM_OVN_STALE_MAINTENANCE_CMD` hook that receives structured stale burden environment variables and persists the result in local `Open_vSwitch.external_ids:netloom_controller_status`, and controller metrics/log/status fields for consecutive OVN health failures, consecutive successes, the first successful recovering reconcile after a failure, active OVN endpoint, leader OVN endpoint, leader preference status, configured endpoint count, reachable endpoint count, quorum size, leader count, quorum status, failover count, maintenance success/failure counts, and stale advisory status.

Netloom is still missing:

- typed in-database stale repair actions for every drift category, beyond desired-state orphan cleanup, steady-state unexpected/incomplete row cleanup, core OVN name repair, Logical Router stale-options/LB-group reference repair, Router/Router Port disabled-state repair, Logical Switch stale ACL/QoS/forwarding/LB-group reference repair, Subnet router/localnet parent attachment repair, IPv6 router port RA repair, LoadBalancer router/switch parent attachment and row-column repair, Endpoint Logical Switch Port address/port-security/type/options/tag/enabled repair, Endpoint DHCP attachment/family repair, DNS row/switch attachment repair, RouteTable static route row repair, RouteTable static route BFD row repair, PolicyRoute row repair, Gateway router options/external_ids repair, NAT row repair, LoadBalancer health-check attachment repair, opt-in DB compaction, and the operator-controlled stale maintenance hook

If this stays missing, the system will work in a lab but remain weak as a product.

## Lower-priority gaps

These are real but not the first outsourcing targets:

- BGP/EVPN or external route advertisement
- service-grade gateway features beyond current NAT/LB/gateway set
- richer L7 policy model
- traffic engineering / QoS / bandwidth control beyond provider-port shaping, OVSDB Queue row programming, subnet-CIDR queue selection, TCP/UDP queue selectors, and endpoint-label queue selectors
- deeper multi-tenant capacity planning beyond provider-network subnet/endpoint quota accounting

## Recommended outsourcing order

1. Typed OVN client layer based on `libovsdb`
2. Provider network management subsystem
3. eBPF policy-map hardening and observability
4. OVN health/recovery subsystem
5. Advanced gateway features such as BGP/EVPN

## Bottom line

Netloom already has the core SDN semantics implemented.

The biggest remaining gaps are not "missing VPC/subnet/gateway/security-group basics". They are:

- product-grade OVN client/runtime architecture
- provider network lifecycle management
- Cilium-grade eBPF operational hardening
- observability and recovery

Those are the parts I would hand to additional engineers first.
