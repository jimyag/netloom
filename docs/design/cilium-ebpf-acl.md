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
In dual-stack endpoint policies, IPv4 and IPv6 CIDR entries can both be
projected into LPM-backed TCX rule sets. The agent uses a unified L4 TCX attach
path: IPv4-only policies attach the IPv4 program, IPv6-only policies attach the
IPv6 program, and mixed policies attach both programs to the same interface and
direction using TCX multi-program anchors.

The controller can reconcile either the built-in bootstrap state or a JSON
desired-state file. Docker e2e tests exercise the JSON path against a live OVN
Northbound database and verify TCX ACL behavior in privileged node containers.
OVN programming is emitted as idempotent `ovn-nbctl` operations with
`external_ids:netloom_owner=netloom` metadata, and the live executor batches a
reconcile step into one `ovn-nbctl` transaction.
In periodic state-file mode the controller keeps a persistent topology backend,
compares the previous desired snapshot with the current one, and emits
`--if-exists` delete operations for netloom-owned logical ports, NAT rules,
NAT-backed load balancers, routes, policies, switches, router ports, and routers
that are no longer desired. Docker e2e verifies endpoint and SNAT deletion
against the live OVN Northbound database.

Service VIP handling follows OVN load-balancer behavior closely enough for
control-plane validation. DNAT rules with equal external and target ports use OVN
NAT `--portrange`; DNAT rules that translate the port use a netloom-owned OVN
Load_Balancer bound to the logical router so the VIP port and backend port can
differ while the control-plane object remains a NAT rule. Floating IP
`dnat_and_snat` rules can also carry OVN distributed NAT `logical_port` and
`external_mac` fields, matching the Kube-OVN/OVN requirement that distributed
floating IP ARP replies and egress packets use the logical switch port's MAC.
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
`LoadBalancer` backends
are rendered into the OVN VIP backend set and the userspace topology resolver
uses the same stable hashing inputs for flow affinity. The desired state can
set OVN load-balancer `selection_fields`; when session affinity is enabled
without explicit fields, netloom uses `ip_src` for IPv4 VIPs and `ipv6_src` for
IPv6 VIPs so the OVN Northbound row and local resolver agree on ClientIP
affinity. Backends default to healthy; when a backend is marked
`healthy=false`, the planner omits it from the OVN VIP backend list and the
resolver excludes it from local service resolution. Validation requires at
least one healthy backend so the OVN `lb-add` operation never receives an empty
backend set. The state-file controller can additionally enable active TCP
backend probes with `NETLOOM_LB_HEALTH_PROBE=1`; probe results are applied to
TCP load balancers with health checks before the OVN plan is generated, while
explicit `healthy=false` still acts as a manual drain. This lets tests cover
the same fail-away behavior expected from OVN health-check state while keeping
health-derived backend selection visible in the desired-state model.

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
drives policy-map evaluation, while the exact CIDR lets the TCX L4 projection
enforce remote-group rules for workload traffic. When membership changes,
periodic agent reconcile recompiles the endpoint program and replaces the TCX
attachment signature.
Security groups also carry a Kube-OVN-style `tier` field constrained to 0 or 1.
The eBPF policy map encodes tier into rule precedence: tier 0 entries win over
tier 1 entries, and within the same tier drop/reject entries continue to win
over allow/log entries. Non-zero rule priorities follow Kube-OVN's 1..16384
API range and lower numeric values win, matching Kube-OVN's
`SecurityGroupHighestPriority - rule.Priority` OVN ACL projection. Priority 0
is retained as the desired-state compatibility default and sorts below explicit
priorities. This keeps platform guardrails deterministic without moving
security-group enforcement back into OVN ACLs.

Named ports follow Cilium's late-binding policy behavior. Endpoints can declare
`named_ports` with a name, TCP or UDP protocol, and concrete port number.
Ingress rules resolve `named_ports` against the protected endpoint before map
encoding. Egress rules resolve named ports only with `remote_group`, because the
destination endpoint set is then known; each remote member contributes its own
resolved port and exact CIDR. CIDR, CIDR-group, and FQDN egress rules reject
named ports instead of guessing a destination port source.

Remote entities follow the Cilium `toEntities` and `fromEntities` shape for
common destination classes that should not be repeated as hand-written CIDRs.
`remote_entities` currently supports `all`, `world`, `cluster`, `private`, and
`host`. `all` expands to IPv4 and IPv6 default CIDRs, `world` expands to those
default CIDRs after subtracting the current VPC's subnet CIDRs, `cluster`
expands to the current VPC's subnet CIDRs from desired state, `private` expands
to RFC1918 plus ULA ranges, and `host` expands to the current VPC gateway LAN
IPs as `/32` or `/128` CIDRs. The expanded entries use the same CIDR fallback
and TCX projection path as direct CIDR rules.

CIDR groups follow Cilium's `CIDRGroupRef` idea for reusable external CIDR
sets. Netloom models those sets as desired-state `cidr_groups`; a
`SecurityGroupRule` can refer to one with `remote_cidr_group`, and the compiler
expands the group into one CIDR-backed policy entry per prefix. The expanded
entries share the same CIDR identity and CIDR fallback path as direct
`remote_cidr` rules, so the userspace evaluator and TCX projection do not need
a separate rule type.

Direct `remote_cidr` rules also support Cilium `CIDRRule.ExceptCIDRs` style
exceptions through `except_cidrs`. Validation requires every exception prefix
to be contained by the parent CIDR and to use the same IP family. The compiler
subtracts exceptions from the parent prefix and emits the minimal remaining
CIDR set as independent policy entries. As in Cilium's current validation path,
exceptions are intentionally limited to direct CIDR rules and are rejected when
combined with `remote_cidr_group`.

FQDN egress policy follows Cilium's `toFQDNs` split between DNS-derived state
and endpoint policy. A `SecurityGroupRule` can use `remote_fqdns` selectors with
`match_name` or `match_pattern`; during controller or agent reconcile, the
compiler matches those selectors against desired-state `dns_records` and emits
one CIDR-backed policy entry per resolved IP (`/32` for IPv4, `/128` for IPv6).
`match_pattern` follows Cilium's `matchpattern` wildcard semantics: ordinary
`*` matches characters within one DNS label and does not cross `.`, while a
leading `**.` matches one or more subdomain labels. Unresolved names compile to
no entries, so they do not accidentally allow broad egress. This gives the eBPF
ACL path the same CIDR fallback enforcement shape as `remote_cidr` while
preserving the higher-level FQDN intent in the model.
The desired-state DNS cache supports TTL expiry with `ttl_seconds` and
`observed_at`; expired records are skipped during policy compilation so stale
answers stop granting egress. For agent-driven nodes, `NETLOOM_DNS_OBSERVATIONS_FILE`
adds a runtime DNS observation cache to each state-file reconcile. The file can
contain the same `dns_records` shape as desired state, allowing an external DNS
observer or proxy to refresh FQDN-derived CIDR entries without rewriting the main
topology document. This is the state update half of Cilium's DNS proxy model;
the `internal/dnsobserver` package parses DNS wire responses, including
compressed names, `A`, `AAAA`, and `CNAME` answers, into that same observation
record shape. The `netloom-dns-observer` command wraps that parser as a
sidecar-friendly bridge: it accepts newline-delimited base64 or hex DNS
responses, or one raw DNS response, and atomically merges the derived records
into `NETLOOM_DNS_OBSERVATIONS_FILE`. Packet interception can therefore be
layered on top of this command or parser without changing policy compilation.

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
policy update event with the diff stats. The agent reconcile result exposes the
same counters, making policy churn visible without scraping raw BPF maps. The
in-memory store applies that plan transactionally, so an injected failure leaves
the previous endpoint policy and revision intact. The eBPF store still uses a
create-populate-swap path for kernel-map safety, but records the same revision
and diff statistics so it can move to in-place map mutation without changing the
control plane contract.

The userspace policy evaluator also exposes Cilium-style observability hooks.
`PolicyRecorder` tracks per-endpoint allow, drop, conntrack, established, and
logged flow counters. Drop decisions emit a structured event with endpoint ID,
remote identity, direction, protocol, destination port, reason, and rule cookie
when a policy-deny rule matched. No-match drops are recorded separately, which
makes it possible to distinguish default deny from explicit security-group deny
in tests and future agent output. Rules with `log` set, or with `action=log`,
also emit a policy verdict event for both allow and drop decisions, matching
the Cilium idea that policy verdict observability is not limited to denied
traffic.
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
