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
`ManagedOVNReader` returns `ManagedOVNRow` objects for live state accounting, the current `ovn-nbctl` audit path adapts command output into that typed reader interface, and `LibOVSDBManagedReader` can read the same managed rows from a real libovsdb monitor/cache using Netloom-local OVN NB models under `internal/ovn/ovsdb/ovnnb`. Those models are pulled into this repository from Kube-OVN's generated OVSDB model package, so Netloom follows Kube-OVN's local model pattern without relying on a `go.mod` replace to the Kube-OVN fork. When `NETLOOM_OVN_LIBOVSDB_ENDPOINT` or `NETLOOM_OVN_NBCTL_DB` points at an OVN Northbound endpoint, the state-file controller now defaults both topology writes and live audit to libovsdb; `NETLOOM_OVN_TOPOLOGY_BACKEND=nbctl` and `NETLOOM_OVN_AUDIT_BACKEND=nbctl` are explicit debug overrides for the command path. Live audit compares managed-row identities against desired state to report missing and unexpected managed rows, and `LibOVSDBTopologyWriter` can directly create/update VPC logical routers, Subnet logical switches/IPAM `other_config`, router ports, router switch ports, provider localnet ports, Endpoint logical switch ports, DHCP_Options, RouteTable static routes, PolicyRoute rows, Gateway router metadata, NAT rows, Load_Balancer rows, and Load_Balancer_Health_Check rows in OVN Northbound DB transactions. It also implements lifecycle cleanup for direct OVSDB mode: desired-state removal deletes managed rows by UUID after detaching parent references, and first reconcile scans live managed rows to remove orphan objects not present in current desired state. It is still not a full typed OVN write client for every topology object.

What is missing:

- typed cache/monitor write support beyond VPC logical routers, Subnet/Endpoint logical switch topology, DHCP_Options, static routes, policy routes, Gateway router metadata, NAT rows, Load_Balancer rows, Load_Balancer_Health_Check rows, and live managed-row audit
- clustered OVN DB leader/failover behavior beyond reconnecting a single libovsdb topology client

Reference:

- `/tmp/kube-ovn/pkg/ovsdb/client/client.go`
- `/tmp/kube-ovn/pkg/ovs/ovn-nb-logical_router_policy.go`
- `/tmp/kube-ovn/pkg/ovs/ovn-nb-logical_router_route.go`

This is the single most important control-plane hardening area still missing.

### 2. Provider network management is still too thin for a product

Netloom can create provider VLAN links, discover provider interface inventory, select ready candidate parent interfaces, report per-provider readiness/issues, and optionally sync local OVS `Open_vSwitch` database bridge mappings with `NETLOOM_OVSDB_SYNC=1`. It now turns runtime parent/link drift into explicit provider issues and network-level reasons such as `parent-down`, `link-missing`, and `link-drift`, so underlay breakage remains visible after initial planning succeeds. When OVSDB sync is enabled, the agent creates deterministic OVS bridges, attaches managed provider VLAN links, repairs managed port-to-bridge drift, annotates Bridge/Interface rows with Netloom `external_ids`, writes `external_ids:ovn-bridge-mappings` for OVN localnet resolution, and removes stale Netloom-owned provider bridges when cleanup mode is enabled. Netloom also carries local Kube-OVN-derived `Open_vSwitch` DB models under `internal/ovn/ovsdb/vswitch` and builds typed desired rows for the provider `Open_vSwitch`, `Bridge`, `Port`, and `Interface` tables, so the local underlay state has a structured OVSDB representation rather than only command strings. When `NETLOOM_OVSDB_ENDPOINT` is set, both netlink and command state-file datapath backends use libovsdb transactions against those typed `Open_vSwitch` rows to create/update bridges, ports, interfaces, bridge mappings, wrong-bridge port drift, and cleanup of stale Netloom-owned provider rows instead of issuing `ovs-vsctl` writes. It also reads provider bridge mapping, bridge, port, and interface status from the same libovsdb monitor/cache and reports `ovsdb-bridge-missing`, `ovsdb-mapping-missing`, `ovsdb-port-drift`, and `ovsdb-interface-drift` provider issues; strict provider health fails on those OVSDB-backed network issues. Provider networks can now declare `isolation=exclusive`; the datapath rejects parent-interface sharing with any other provider network, reports `parent-isolation-conflict`, and writes the isolation intent into managed OVSDB `external_ids`.

What is missing:

- richer multi-provider isolation beyond exclusive parent-interface ownership, such as bandwidth/QoS separation and tenant quota accounting
- deeper clustered OVS/OVN controller connectivity reporting beyond per-bridge local OVSDB drift checks

Reference:

- `/tmp/kube-ovn/test/e2e/kube-ovn/underlay/underlay.go`
- `/tmp/kube-ovn/test/e2e/kube-ovn/underlay/vlan_subinterfaces.go`
- `/tmp/kube-ovn/pkg/apis/kubeovn/v1/provider-network.go`

For bare metal, this should become a native Netloom subsystem, not a CRD clone.

### 3. eBPF ACL datapath lacks Cilium-grade operational controls

Netloom already has compile/store/evaluate/TCX attach. It also has policy-map pressure metrics, overflow rejection before programming, configurable fail-closed overflow remediation that clears an endpoint policy map when an oversized desired map cannot be installed, pinned-map drift repair that ignores counter-only changes, explicit live-vs-desired policy-map drift telemetry, attach/update rollback signals, per-endpoint usage accounting, endpoint-scoped lifecycle status with revision, drift, pressure, last stats, and last event, conservative rule-level CIDR compaction for equivalent adjacent CIDR expansions, `netloom-agent policy-status` as a JSON CLI around that status view, a long-running `/policy/endpoints` HTTP API around the latest endpoint lifecycle status, `DELETE /policy/endpoints/{endpoint}` for operator-triggered endpoint policy map reset in long-running agents, `POST /policy/endpoints/{endpoint}/plan` for staged dry-run policy update planning without modifying live maps, `POST /policy/endpoints/{endpoint}/regenerate` for Cilium-style forced endpoint policy regeneration from the latest successful desired state, `POST /policy/endpoints/{endpoint}/quarantine` for scoped endpoint isolation with ingress and egress deny-all policy entries, `POST /policy/endpoints/{endpoint}/unquarantine` for restoring the endpoint policy from the latest successful desired state, and `POST /policy/endpoints/rollout` for staged multi-endpoint policy rollout with all-endpoint planning, configurable batch size, pressure-aware automatic batch shrinking, dry-run mode, per-endpoint phase reporting, stop-on-failure blast-radius control, automatic rollback of endpoints already modified in the failed rollout, and SLO-gated canary checks based on policy rule drop/reject telemetry. Desired-state `policy_rollouts` now lets the bare-metal agent defer normal policy writes for active rollout nodes, then progressively apply the declared endpoint subset with batch, pressure-aware, and SLO-gated controls while reporting rollout planned/applied/skipped/failed/rolled_back/rollback_failed/slo_failed in logs and Prometheus metrics. It also has configurable non-desired endpoint policy-map aging/GC for long-running bare-metal agents, configurable pressure-triggered mitigation that deletes non-desired managed endpoint maps before the pressured store reaches capacity, and opt-in pressure-triggered endpoint quarantine through `NETLOOM_POLICY_PRESSURE_QUARANTINE` when desired endpoint pressure remains above threshold. What it still lacks is the larger operational hardening layer Cilium has around policy maps.

What is missing:

- richer rollout automation beyond endpoint map reset, dry-run planning, forced regenerate/reconcile, scoped quarantine, unquarantine, desired-state progressive rollout, stop-on-failure staged rollout, failed-rollout automatic rollback, and SLO-gated canary analysis, such as multi-window SLO evaluation and external traffic probes

Reference:

- `/tmp/cilium/pkg/endpointmanager/manager.go`
- `/tmp/cilium/pkg/endpointmanager/policymap_pressure.go`
- `/tmp/cilium/bpf/lib/policy.h`

This is the most important missing work on the eBPF side.

### 4. Rule-level observability is still shallow

Netloom has drop/trace style events, policy-rule packet/byte counters in the evaluator, policy explanation helpers and `netloom-agent policy-explain` for packet verdict/reason/matched-rule debugging without writing policy counters or creating conntrack state, `netloom-agent route-explain` for topology/policy-route/reroute/drop/NAT/LB/gateway decisions from desired state, long-running agent `/policy/explain` and `/route/explain` APIs backed by the latest successfully reconciled desired state, an agent telemetry interface that can surface endpoint/rule counters in normal reconcile output, a pinned eBPF policy-map reader for counter fields, TCX L4 ACL maps that increment packet/byte counters in the fast path and merge those counters back into agent telemetry after reconcile, a long-running agent Prometheus text endpoint for reconcile, policy-map, policy-rule, TCX counters, cumulative policy add/update/delete/failure/rollback counters, and reconcile latency buckets, plus a long-running controller Prometheus text endpoint for desired object counts, LB health probes, OVN health latency, OVN health consecutive failure/success and recovery state, OVN operation counts, reconcile success/failure, OVN desired-state cleanup/drift counters, live OVN NB managed-row audit counts, duplicate/incomplete managed-row gauges, missing/unexpected managed-row gauges, external-id field drift gauges, and libovsdb-backed column drift checks for core OVN names, Logical Switch config, Logical/Router Port, Policy, Static Route, NAT, LoadBalancer, HealthCheck, and DHCP rows. This now gives the product a stable place to report live datapath and control-plane counters, but it is not yet Cilium/Kube-OVN grade runtime observability.

What is missing:

- full OVN column-level value drift telemetry beyond the currently audited core names, topology, route, service, NAT, and DHCP columns

This is product work, not just test work.

### 5. OVN control-plane health and recovery workflows are minimal

Kube-OVN has explicit leader/DB-health/recovery logic around OVN:

- `/tmp/kube-ovn/pkg/ovn_leader_checker/ovn.go`
- `/tmp/kube-ovn/pkg/ovnmonitor`

Netloom now has `ovn-nbctl show` health probing, libovsdb `echo` health probing for direct OVSDB topology mode, a reconnecting libovsdb topology health checker that rebuilds and re-monitors the Northbound client with configurable backoff after disconnects, comma/whitespace separated OVN Northbound libovsdb endpoint failover for initial connect and health reconnect, optional `NETLOOM_OVN_LEADER_STATUS_CMD` leader endpoint probing with leader-aware connection preference, built-in `ovn-appctl -t <target> cluster/status OVN_Northbound` leader probing through `NETLOOM_OVN_CLUSTER_STATUS_TARGETS`, opt-in OVN DB compaction after successful reconcile through `NETLOOM_OVN_DB_COMPACT_TARGETS`, command timeout/retry knobs, and controller metrics/log fields for consecutive OVN health failures, consecutive successes, the first successful recovering reconcile after a failure, active OVN endpoint, leader OVN endpoint, leader preference status, configured endpoint count, failover count, and maintenance success/failure counts.

Netloom is still missing:

- richer stale-state maintenance workflows beyond desired-state orphan cleanup and opt-in DB compaction

If this stays missing, the system will work in a lab but remain weak as a product.

## Lower-priority gaps

These are real but not the first outsourcing targets:

- BGP/EVPN or external route advertisement
- service-grade gateway features beyond current NAT/LB/gateway set
- richer L7 policy model
- traffic engineering / QoS / bandwidth control
- multi-tenant quota and capacity accounting

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
