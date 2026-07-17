# Cilium-Inspired eBPF ACL Design

This note records the implementation choices netloom should borrow from Cilium
for the ACL datapath.

Analyzed Cilium checkout:

- Repository: `https://github.com/cilium/cilium`
- Commit: `46b1025f`
- Local path during analysis: `/tmp/netloom-cilium`

Relevant Cilium files:

- `bpf/lib/policy.h`
- `pkg/maps/policymap/policymap.go`
- `pkg/policy/mapstate.go`
- `pkg/endpoint/policy.go`
- `pkg/fqdn/doc.go`
- `pkg/policy/api/cidr.go`
- `pkg/policy/k8s/cilium_cidr_group.go`

## Decisions

netloom should use endpoint-scoped policy programs and maps, not a single global
ACL table. The control plane compiles `SecurityGroup` rules into a per-endpoint
program, and the node agent realizes that program into local BPF maps.

The map key should follow Cilium's shape:

- remote security identity
- traffic direction
- L4 protocol
- destination port
- LPM prefix length for protocol and port wildcarding

The value should carry:

- allow or deny verdict
- precedence
- stateful flag
- logging flag
- rule cookie or rule id for accounting

Deny entries must have higher precedence than allow entries. This mirrors
Cilium's policy lookup behavior and avoids rule order ambiguity when an allow
and a deny both match.
`action=log` is compiled as allow plus the logging flag, while `log: true`
adds verdict logging to any allow or deny action.

## Boundary With SDN Routing

Policy routes remain topology intent and are realized by the SDN backend.
Security groups remain ACL intent and are realized by the eBPF backend.

`PolicyRoute` may reroute or blackhole traffic at routing scope. It must not be
used as a business ACL mechanism. `SecurityGroupRule` must not support reroute.

## Current Implementation Scope

The Go compiler emits cilium-style map entries for endpoint policy programs.
Those entries are covered by userspace evaluator tests and can also be stored
in kernel eBPF maps through the optional privileged backend.

The TCX datapath currently supports:

- a map-backed verdict program for attach/detach verification
- IPv4 source ACLs for ingress checks
- IPv4 TCP/UDP CIDR peer + destination port-prefix ACLs, and IPv4 ICMP CIDR ACLs
  with protocol-only, type-only, or type+code keys, backed by an LPM trie.
  Ingress policy matches the packet source address; egress policy matches the
  packet destination address.
- IPv6 TCP/UDP CIDR peer + destination port-prefix ACL map/program primitives,
  and IPv6 ICMP CIDR ACL projection using ICMPv6 next-header 58 with the same
  protocol-only, type-only, or type+code key shape.
- policy-driven TCX L4 selftests where `SecurityGroupRule` is compiled into a
  `policy.Program` before being projected into the TCX map. The agent selftest
  accepts ICMP policy checks with `NETLOOM_TCX_PROTO=1` and no destination port,
  matching the ICMP zero-port key used by the runtime TCX map.

Port ranges are decomposed into CIDR-like port prefixes and projected into the
TCX LPM trie. The key is ordered as protocol, peer prefix, then destination
port prefix, so the fast path can match both remote CIDR and L4 range without
expanding every port into a hash entry. ICMP uses the same 16-bit L4 field for
type/code: protocol-only ICMP has no L4 prefix, type-only matches the first
8 bits, and type+code matches all 16 bits. Workload TCX attach projects ingress
rules to host-veth egress and egress rules to host-veth ingress, matching the
direction split used by endpoint policy datapaths.
Remote-group and remote-endpoint-selector rules keep their Cilium-style remote
identity in the userspace policy map. The TCX L4 projection does not accept
those rules, because the current TCX key can match CIDR, protocol, and port but
cannot validate the remote identity. Keeping identity rules out of TCX avoids
silently weakening a `remote_group` or endpoint-selector rule into a pure CIDR
match. Those rules remain enforced and testable through the canonical eBPF
policy map and evaluator until the fast path grows identity matching.
In dual-stack endpoint policies, IPv4 and IPv6 CIDR entries can both be
projected into LPM-backed TCX rule sets. The agent uses a unified L4 TCX attach
path: IPv4-only policies attach the IPv4 program, IPv6-only policies attach the
IPv6 program, and mixed policies attach both programs to the same interface and
direction using TCX multi-program anchors.

The controller can reconcile either the built-in bootstrap state, a JSON
desired-state file, or desired state imported into the local Open vSwitch
database at `Open_vSwitch.external_ids:netloom_desired_state`. Docker e2e tests
exercise the JSON path against a live OVN Northbound database and verify TCX ACL
behavior in privileged node containers.
Live OVN programming uses the local OVN Northbound OVSDB model and libovsdb
transactions with `external_ids:netloom_owner=netloom` metadata. The command
planner remains useful for dry-run and regression tests, but it is not the
controller runtime path when an OVN endpoint is configured.
In periodic reconcile mode the controller keeps a persistent topology backend,
compares the previous desired snapshot with the current one, and deletes
netloom-owned logical ports, NAT rules, routes, policies, switches, router
ports, and routers that are no longer desired. Docker e2e verifies endpoint and
SNAT deletion against the live OVN Northbound database.

Service VIP handling follows OVN load-balancer behavior closely enough for
control-plane validation. DNAT rules without port mapping are all-protocol
rules, matching the OVN operation netloom emits. DNAT rules with equal external
and target ports use OVN NAT `--portrange`; DNAT and Floating IP
(`dnat_and_snat`) rules that translate the port use a netloom-owned OVN `NAT`
row with `external_port_range` and `logical_port_range`, so port translation
does not introduce an extra Load_Balancer topology. Floating IP rules can also
carry OVN distributed NAT `logical_port` and `external_mac` fields, matching the
Kube-OVN/OVN requirement that distributed floating IP ARP replies and egress
packets use the logical switch port's MAC.
Endpoint desired state can also carry a static `mac`. The control plane rejects
duplicates inside the same subnet and rejects the Kube-OVN conflict case where a
static endpoint MAC equals the deterministic router-port gateway MAC. When a
MAC is present, the OVN planner writes `MAC IP` to the logical switch port
addresses and port-security fields; otherwise it keeps OVN dynamic addressing
for the endpoint IP.
Subnet desired state supports `exclude_cidrs` as the CIDR form of Kube-OVN's
`excludeIps` reservation model. Excluded prefixes must be contained by the
subnet CIDR and use the same address family. The control plane rejects endpoint
IPs that land in an excluded prefix, and the IPAM allocator can be constructed
with the same excluded prefixes so automatic allocation skips reserved ranges.
Route-table and policy-route ECMP both keep the full `next_hops` list in the
userspace resolver decision while selecting one next hop with a stable flow hash.
This mirrors the OVN/Linux datapath intent closely enough for unit and selftest
validation without losing the multi next-hop state needed for assertions.
Policy-route L4 matching includes both `src_ports` and `dst_ports`. The OVN
planner groups alternative source or destination port ranges with OR before
joining them with the rest of the logical-router-policy match, while the Linux
datapath expands the same intent into the source/destination port cross product
required by `ip rule`/netlink. Policy-route priority is constrained to OVN's
logical-router-policy range `0..32767`, so invalid priorities fail validation
before reaching a live Northbound transaction.
`LoadBalancer` frontends are declared with a required `ports` array. Each
frontend owns its protocol and backend target ports while sharing the same
Service VIP; those backends are rendered into the OVN VIP backend set and the
userspace topology resolver uses the same stable hashing inputs for flow
affinity.
The desired state can set OVN load-balancer `selection_fields`; when session
affinity is enabled without explicit fields, netloom uses `ip_src` for IPv4
VIPs and `ipv6_src` for IPv6 VIPs so the OVN Northbound row and local resolver
agree on ClientIP affinity. Backends default to healthy; when a backend is
marked `healthy=false`, the planner omits it from that OVN VIP backend list and
the resolver excludes it from local service resolution. Validation requires at
least one healthy backend per frontend so the OVN `lb-add` operation never
receives an empty backend set. Multi-port health checks converge one OVN
`Load_Balancer_Health_Check` row per frontend VIP by finding existing managed
rows, updating their options in place, and only creating missing rows. The
state-file controller can additionally enable active TCP backend probes with
`NETLOOM_LB_HEALTH_PROBE=1`; probe results are applied to TCP load balancers
with health checks before the OVN plan is generated. A per-controller tracker
honors the configured `success_count` and `failure_count` across reconcile
loops, so transient probe failures do not immediately remove a backend and
recovery requires the configured number of successful probes. Explicit
`healthy=false` still acts as a manual drain. This lets tests cover the same
fail-away behavior expected from OVN health-check state while keeping
health-derived backend selection visible in the desired-state model.

The eBPF policy store rejects oversized endpoint maps before programming by
default. Operators can set `NETLOOM_EBPF_MAP_OVERFLOW_ACTION=clear` to use a
fail-closed remediation path instead: when a desired endpoint policy exceeds the
configured map capacity, the store clears that endpoint map, advances the policy
revision, and records a remediated policy update event with the original
overflow reason. Since the userspace evaluator and TCX policy model both drop
traffic when no policy entry matches, this avoids preserving stale allows after
a failed oversized update. Long-running agents expose the latest endpoint policy
lifecycle view at `/policy/endpoints` on the existing metrics HTTP listener;
the response includes the same revision, drift, pressure, last stats, and last
event data as `netloom-agent policy-status`, and supports filtering with
`?endpoint=pod-a` or `?endpoint=prod/pod-a`. Operators can inspect compiled
endpoint policy-map keys, values, counters, and remote CIDRs through
`netloom-agent policy-entries` or the long-running `/policy/entries/{endpoint}`
API. Long-running agents also support endpoint policy freeze/unfreeze through
`POST /policy/endpoints/{endpoint}/freeze` and `/unfreeze`; frozen endpoints are
skipped by normal reconcile policy-map and TCX updates until explicitly
unfrozen or until their optional `ttl_seconds` / RFC3339 `expires_at` expires,
and the frozen endpoint list plus expiry metadata is persisted in local OVS
`Open_vSwitch.external_ids:netloom_policy_freeze_state` when
`NETLOOM_OVSDB_ENDPOINT` is configured. Successful and failed endpoint
lifecycle actions are exposed through `GET /policy/endpoints/actions/history`
and persisted in local OVS
`Open_vSwitch.external_ids:netloom_policy_endpoint_action_history` when OVSDB is
configured; operators can filter the action history by endpoint, action,
success, and recent-entry limit. Failed entries include `success:false` and an
`error` string. `netloom-agent policy-action-history` reads the same local OVSDB
history for offline node-local audits when the HTTP listener is not exposed. The
same endpoint API supports
operator lifecycle actions: `DELETE /policy/endpoints/{endpoint}` clears an
endpoint map, `POST /policy/endpoints/{endpoint}/plan` dry-runs the latest
desired policy and returns add/update/delete/unchanged counts without modifying
the live map or revision, `POST /policy/endpoints/{endpoint}/regenerate`
restores desired policy from the latest successful state,
`POST /policy/endpoints/{endpoint}/quarantine` installs ingress and egress
deny-all entries, and
`POST /policy/endpoints/{endpoint}/unquarantine` restores desired policy after
isolation.

The agent can also realize a minimal Linux L3 workload datapath from the same
desired-state file. It has two modes:

- `local`: install local endpoint `/32` addresses on a local device and remote
  endpoint `/32` routes through the remote node underlay address.
- `netns`: create a network namespace and veth pair for each local endpoint,
  assign the endpoint `/32` inside the namespace, install a default route via
  the host-side veth, and route remote endpoint `/32`s through the remote node
  underlay address.

Docker e2e uses `netns` mode to verify workload-to-workload traffic with
`ip netns exec`, so the test covers per-workload interfaces instead of only
node-local loopback addresses. The Linux datapath can run through the legacy
command planner or the `vishvananda/netlink` and `vishvananda/netns` backend;
Docker e2e uses the netlink backend for namespace, veth, address, and route
programming. This is still a small Linux bootstrap datapath; the command
planner is isolated so the same reconcile path can later target OVN-backed
ports without changing the policy compiler.

For workload policy enforcement, the agent can attach the TCX L4 ACL program to
each eligible local endpoint's host-side veth in egress direction.
Packets entering the workload namespace are filtered immediately before crossing
the veth peer, so Docker e2e now validates both datapath connectivity and
security-group drops at the workload boundary. Multiple local workloads can be
attached in one reconcile pass and are held for the same lifecycle window.

Remote security-group references follow the same shape as Cilium identity-based
policy. During reconcile, the compiler receives the current endpoint set,
expands `remote_group` members in the same VPC into stable endpoint identities,
and also records each member's exact `/32` or `/128` CIDR. The endpoint identity
drives policy-map evaluation, and the CIDR is treated as an additional match
constraint instead of a replacement for identity. TCX skips these rules until it
can enforce both identity and CIDR together. When membership changes, periodic
agent reconcile recompiles the endpoint program so the policy map receives the
updated endpoint identities and CIDRs.
Security groups also carry a Kube-OVN-style `tier` field constrained to 0 or 1.
The eBPF policy map encodes tier into rule precedence: tier 0 entries win over
tier 1 entries, and within the same tier drop/reject entries continue to win
over allow/log entries. Rule priorities follow Kube-OVN's 1..16384 API range
and lower numeric values win, matching Kube-OVN's
`SecurityGroupHighestPriority - rule.Priority` OVN ACL projection. Priority 0 is
invalid, so desired state must make rule ordering explicit. This keeps platform
guardrails deterministic without moving security-group enforcement back into
OVN ACLs.

Endpoint labels and named ports follow Cilium's late-binding policy behavior.
Endpoints can declare `labels` and `named_ports` with a name, TCP or UDP
protocol, and concrete port number. Rules can use `remote_endpoint_selector` to
match same-VPC endpoints by label equality and `remote_endpoint_expressions` to
add Kubernetes/Cilium match-expression semantics. Supported operators are `In`,
`NotIn`, `Exists`, and `DoesNotExist`; expressions are ANDed with
`remote_endpoint_selector` labels. Ingress rules resolve `named_ports` against
the protected endpoint before map encoding. Egress rules resolve named ports
with `remote_group`, `remote_endpoint_selector`, or
`remote_endpoint_expressions`, because the destination endpoint set is then
known; each remote member contributes its own resolved port and exact CIDR.
Validation rejects named ports on CIDR, CIDR-group, entity, service, and FQDN
egress rules instead of guessing a destination port source.

Service egress policy follows Cilium's `toServices` shape for VIP-based
dependencies. A `SecurityGroupRule` can use `remote_service` to reference a
same-VPC desired-state `LoadBalancer`; the compiler expands it to the service
VIP as `/32` or `/128`. If the rule does not pin a concrete protocol or port,
the expanded ACL inherits the LoadBalancer protocol and frontend port, so the
eBPF policy map enforces the service-facing tuple while topology resolution can
still translate the VIP to a healthy backend. If the rule provides an explicit
port range, that range is used only to select matching service frontends; each
compiled ACL is narrowed back to the exact frontend port, avoiding accidental
VIP exposure for nearby ports in the same range.

Remote entities follow the Cilium `toEntities` and `fromEntities` shape for
common destination classes that should not be repeated as hand-written CIDRs.
`remote_entities` currently supports `all`, `world`, `world-ipv4`,
`world-ipv6`, `cluster`, `private`, `host`, `remote-node`, and `none`. `all`
expands to IPv4 and IPv6 default CIDRs, `world` expands to those default CIDRs
after subtracting the current VPC's subnet CIDRs, `world-ipv4` and
`world-ipv6` apply the same subtraction to only their IP family, `cluster`
expands to the current VPC's subnet CIDRs from desired state, `private` expands
to RFC1918 plus ULA ranges, `host` expands to the current VPC gateway LAN IPs
as `/32` or `/128` CIDRs, `remote-node` expands to same-VPC gateway LAN IPs
whose gateway node differs from the protected endpoint's node, and `none`
intentionally expands to no rules. Because `none` is a no-match sentinel, it
must be used alone and validation rejects combinations with other entities. The
expanded entries use the same CIDR fallback and TCX projection path as direct
CIDR rules.

CIDR groups follow Cilium's `CIDRGroupRef` and `CIDRSet` idea for reusable
external CIDR sets. Netloom models those sets as desired-state `cidr_groups`; a
`SecurityGroupRule` can refer to one with `remote_cidr_group`, and the compiler
expands the group into one CIDR-backed policy entry per prefix. A group may use
the compact `cidrs` list or `entries` with per-CIDR `except_cidrs`; entry-level
exceptions are subtracted before policy map entries are generated. The expanded
entries share the same CIDR identity and CIDR fallback path as direct
`remote_cidr` rules, so the userspace evaluator and TCX projection do not need
a separate rule type. Before entries are materialized, equivalent adjacent CIDRs
from the same expanded rule are compacted into the shortest safe prefix. The
compiler does not merge across different actions, priorities, ports, endpoint
identities, services, FQDN names, or entities, so compaction reduces map pressure
without widening policy intent.

Direct `remote_cidr` rules also support Cilium `CIDRRule.ExceptCIDRs` style
exceptions through `except_cidrs`. Validation requires every exception prefix
to be contained by the parent CIDR and to use the same IP family. The compiler
subtracts exceptions from the parent prefix and emits the minimal remaining
CIDR set as independent policy entries, then applies the same equivalent-CIDR
compaction step where possible. Rule-level exceptions are intentionally limited
to direct CIDR rules and are rejected when combined with `remote_cidr_group`;
reusable group-level exceptions belong on CIDRGroup `entries`.

FQDN egress policy follows Cilium's `toFQDNs` split between DNS-derived state
and endpoint policy. A `SecurityGroupRule` can use `remote_fqdns` selectors with
`match_name` or `match_pattern`; during controller or agent reconcile, the
compiler matches those selectors against desired-state `dns_records` and emits
one CIDR-backed policy entry per resolved IP (`/32` for IPv4, `/128` for IPv6).
`match_pattern` follows Cilium's `matchpattern` wildcard semantics: ordinary
`*` matches characters within one DNS label and does not cross `.`, even when
the entire pattern is just `*`; a leading `**.` matches one or more subdomain
labels. DNS names, DHCP search domains, and FQDN selectors are validated
label-by-label before policy compilation; empty labels, overlong labels, and
wildcards in exact `match_name` selectors are rejected. Unresolved names compile
to no entries, so they do not accidentally allow broad egress. This gives the
eBPF ACL path the same CIDR fallback enforcement shape as `remote_cidr` while
preserving the higher-level FQDN intent in the model.
The desired-state DNS cache supports TTL expiry with `ttl_seconds` and
`observed_at`; expired records are skipped during policy compilation so stale
answers stop granting egress. For agent-driven nodes, `NETLOOM_OVSDB_ENDPOINT` enables a runtime DNS observation cache in local OVSDB `Open_vSwitch.external_ids:netloom_dns_observations` on each state-file reconcile. The external_id value can contain the same `dns_records` shape as desired state, allowing an external DNS observer or proxy to refresh FQDN-derived CIDR entries without rewriting the main topology document. This is the state update half of Cilium's DNS proxy model;
the `internal/dnsobserver` package parses DNS wire responses, including
compressed names and `A`/`AAAA`/`CNAME` records from answer, authority, and
additional sections, into that same observation record shape. CNAME aliases use
the shortest TTL across the CNAME chain and terminal address record, matching
the cache lifetime that should govern FQDN-derived policy entries. The
`netloom-dns-observer` command wraps that parser as a
sidecar-friendly bridge: it accepts newline-delimited base64 or hex DNS
responses, one raw DNS response, UDP proxy traffic, or DNS-over-TCP proxy
traffic, including multiple queries on one TCP client connection, and merges the derived records into local OVSDB
`Open_vSwitch.external_ids:netloom_dns_observations`. Packet interception can
therefore be layered on top of this command or parser without changing policy
compilation.

Stateful rules now have a userspace conntrack model that mirrors the Cilium
policy decision shape. `EvaluateStateful` first checks established reverse-flow
state, then evaluates the endpoint policy map. A stateful allow creates a
reverse key for the same endpoint and remote identity; deny rules never create
state. Reverse-flow hits refresh the entry's idle timestamp. The long-running
agent reconciler owns the conntrack store and runs an idle sweep on each
reconcile, defaulting to a five-minute maximum idle age and honoring
`NETLOOM_CONNTRACK_MAX_IDLE_MS` for shorter lab validation or longer production
grace periods. It also deletes entries when an endpoint disappears or its
compiled policy signature changes, so stale state cannot survive a policy
update.

Policy updates now compute a Cilium-style incremental diff before replacing an
endpoint map. The diff reports added, updated, deleted, and unchanged entries.
Successful replacement advances a per-endpoint policy revision and appends a
policy update event with previous/current revision and diff stats. Failed
replacement appends a failed audit event with the attempted revision and error,
but leaves the endpoint policy, last successful stats, and stored revision
intact. The agent reconcile result exposes the same counters, making policy
churn visible without scraping raw BPF maps. The in-memory store applies that
plan transactionally. The eBPF store still uses a create-populate-swap path for
kernel-map safety, but records the same revision and diff statistics so it can
move to in-place map mutation without changing the control plane contract.

The userspace policy evaluator also exposes Cilium-style observability hooks.
`PolicyRecorder` tracks per-endpoint allow, drop, conntrack, established, and
logged flow counters. Drop decisions emit a structured event with endpoint ID,
remote identity, remote IP, direction, protocol, destination port, reason, and
rule cookie when a policy-deny rule matched. No-match drops are recorded
separately, which makes it possible to distinguish default deny from explicit
security-group deny in tests and future agent output. Rules with `log` set, or
with `action=log`, also emit a policy verdict event for both allow and drop
decisions with the same remote identity and IP context, matching the Cilium
idea that policy verdict observability is not limited to denied traffic.
The evaluator also exposes `Explain` and `ExplainStateful` query helpers for
debugging a packet tuple without writing policy counters. The explanation
includes endpoint ID, verdict, reason, evaluated-entry count, matched rule
cookie, copied policy-map entry, original packet context, and conntrack or
stateful-rule markers. `netloom-agent policy-explain` exposes that result from
the same desired-state compilation path used by reconcile, so operators get a
stable answer for default-deny drops, explicit deny/reject drops, PMTU/NDP
control allows, and stateful return-flow allows without scraping log text.
The eBPF policy-map value also carries packet and byte counter fields. The
eBPF store implements the same policy telemetry interface by reading live pinned
map values, classifying counters by rule cookie and action, and preserving those
counters during drift checks so reconcile does not rewrite a healthy map merely
because datapath counters changed. The same live-vs-desired comparison is
available as policy-map drift telemetry with missing, extra, and changed entry
counts. The policy store also exposes endpoint-scoped lifecycle status that
combines revision, map usage, pressure, drift, last update stats, and the last
update event; `netloom-agent policy-status` and the long-running
`/policy/endpoints` HTTP API both report that Cilium-style endpoint policy view
without scraping reconcile logs. The endpoint API also exposes explicit reset,
dry-run plan, regenerate, quarantine, unquarantine, and multi-endpoint rollout
actions for scoped remediation and staged policy rollout. Rollout requests plan
all requested endpoints first, support dry-run and configurable batch size, apply
endpoint maps through the same policy backend path as reconcile, and stop on the
first failed endpoint while reporting later endpoints as skipped. Approval-gated
rollouts can carry `approval_ref` so an external change request or approval
ticket is preserved in the rollout response and history. A rollout can also
enable SLO gating; after each batch the agent reads policy rule telemetry
for already-applied endpoints, compares drop/reject percentage with the
configured threshold once enough packets have been observed, and rolls back the
current rollout if the canary violates the SLO. Long-running agents expose
rollout history through `/policy/endpoints/rollout/history` and persist it in
local OVS `Open_vSwitch.external_ids:netloom_policy_rollout_history`; operators
can read the same audit trail with `netloom-agent policy-rollout-history` and
filter by source, rollout name, and recent-entry limit. The TCX L4 ACL map value
similarly carries the projected rule cookie, log flag, and packet and byte
counters. IPv4 and IPv6
TCX programs atomically increment those counters after a successful LPM lookup
and before returning the rule action. After a successful TCX reconcile, the agent
reads the live attachment maps, aggregates counters by rule cookie, classifies
logged hits from the value metadata, and merges them into the normal
`policy_rule_stats` telemetry output. Single-workload TCX counters are labelled
with the endpoint ID; shared-interface counters are labelled with the TCX target
identity. This exposes Cilium-style rule hit accounting without changing match
semantics.
In long-running state-file agent mode, `NETLOOM_AGENT_METRICS_ADDR` enables a
Prometheus text endpoint with `/metrics` and `/healthz`. The scrape surface
exports the latest reconcile success and duration, policy-map
entries/capacity/pressure, policy-map drift, aggregate rule counters,
per-endpoint or per-TCX target rule counters, cumulative policy
add/update/delete/failure/rollback counters, a reconcile latency histogram, and
TCX failure/rollback signals. The same listener also serves `/policy/explain`
and `/route/explain`: policy explanation evaluates endpoint, peer, protocol,
port, ICMP, and stateful query parameters against the latest successfully
reconciled desired state, while route explanation evaluates topology,
policy-route, NAT, LB, and gateway decisions for packet query parameters. This
keeps the log output useful for humans while giving operators a stable runtime
surface for alerts, dashboards, and packet-path inspection.
`action=reject` is preserved separately from `drop` in the policy map and
userspace evaluator: matching packets return a `reject` verdict and generate a
`policy-reject` drop event. The current TCX fast path still maps reject to drop
because it does not synthesize TCP reset or ICMP unreachable packets.

The Linux datapath also has an explicit cleanup mode. When enabled, the agent
removes netloom-owned network namespaces with the configured prefix that are no
longer present as local endpoints in the desired state. Docker e2e validates
that a stale workload namespace is deleted while the remaining workload
namespace is preserved.

State-file mode can run once or periodically. With
`NETLOOM_RECONCILE_INTERVAL_MS`, the controller and agent re-read the desired
state on each interval. In periodic agent mode, TCX attachments are held by the
agent reconciler instead of being tied to a single reconcile call. The reconciler
keeps unchanged attachments, replaces them when policy content changes, and
closes stale attachments when a workload is no longer a local TCX target.

Docker e2e starts a long-running agent, rewrites the state file to turn a
workload ACL from allow to drop, verifies that the next reconcile updates the
TCX policy, then rewrites the state again to remove one workload and verifies
that stale namespace cleanup runs automatically.
