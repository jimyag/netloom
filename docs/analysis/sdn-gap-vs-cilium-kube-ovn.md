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

### 1. Replace `ovn-nbctl` orchestration with a typed OVSDB client layer

Netloom still drives OVN primarily through command planning and `ovn-nbctl` execution in
[internal/ovn](/home/jimyag/src/github/jimyag/netloom/internal/ovn).

What is missing:

- object-level CRUD by UUID instead of shell-command synthesis
- typed cache/monitor support
- stronger transactional updates for policy routes, static routes, NAT, LB health checks
- better HA/reconnect behavior against clustered OVN DB

Reference:

- `/tmp/kube-ovn/pkg/ovsdb/client/client.go`
- `/tmp/kube-ovn/pkg/ovs/ovn-nb-logical_router_policy.go`
- `/tmp/kube-ovn/pkg/ovs/ovn-nb-logical_router_route.go`

This is the single most important control-plane refactor still missing.

### 2. Provider network management is still too thin for a product

Netloom can create provider VLAN links from static mappings and it has tests for create/cleanup. But it does not have a real provider-network management subsystem.

What is missing:

- provider network inventory object/model
- per-node readiness/status
- automatic parent-interface discovery/validation
- multi-provider isolation semantics beyond env-var mapping
- richer failure reporting when underlay state drifts

Reference:

- `/tmp/kube-ovn/test/e2e/kube-ovn/underlay/underlay.go`
- `/tmp/kube-ovn/test/e2e/kube-ovn/underlay/vlan_subinterfaces.go`
- `/tmp/kube-ovn/pkg/apis/kubeovn/v1/provider-network.go`

For bare metal, this should become a native Netloom subsystem, not a CRD clone.

### 3. eBPF ACL datapath lacks Cilium-grade operational controls

Netloom already has compile/store/evaluate/TCX attach. What it still lacks is the operational hardening layer Cilium has around policy maps.

What is missing:

- policy-map pressure metrics
- overflow handling strategy
- periodic full reconciliation of live map contents vs desired state
- stronger attach/update rollback semantics exposed as product signals
- per-endpoint policy-map usage accounting

Reference:

- `/tmp/cilium/pkg/endpointmanager/manager.go`
- `/tmp/cilium/pkg/endpointmanager/policymap_pressure.go`
- `/tmp/cilium/bpf/lib/policy.h`

This is the most important missing work on the eBPF side.

### 4. Rule-level observability is still shallow

Netloom has drop/trace style events, policy-rule packet/byte counters in the evaluator, an agent telemetry interface that can surface endpoint/rule counters in normal reconcile output, a pinned eBPF policy-map reader for counter fields, TCX L4 ACL maps that increment packet/byte counters in the fast path and merge those counters back into agent telemetry after reconcile, a long-running agent Prometheus text endpoint for reconcile, policy-map, policy-rule, and TCX counters, and a long-running controller Prometheus text endpoint for desired object counts, LB health probes, OVN health latency, OVN operation counts, reconcile success/failure, and OVN desired-state cleanup/drift counters. This now gives the product a stable place to report live datapath and control-plane counters, but it is not yet Cilium/Kube-OVN grade runtime observability.

What is missing:

- histogram-style policy install/update/delete metrics
- histogram-style reconcile latency and failure metrics with historical buckets
- live OVSDB object drift metrics from a typed monitor/cache
- "why was this packet dropped/rerouted" debug surface beyond tests/log scraping

This is product work, not just test work.

### 5. OVN control-plane health and recovery workflows are minimal

Kube-OVN has explicit leader/DB-health/recovery logic around OVN:

- `/tmp/kube-ovn/pkg/ovn_leader_checker/ovn.go`
- `/tmp/kube-ovn/pkg/ovnmonitor`

Netloom is missing:

- OVN DB health checks
- reconnect/backoff strategy at the product level
- leader/failover handling model
- DB compaction / stale-state maintenance workflow

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
