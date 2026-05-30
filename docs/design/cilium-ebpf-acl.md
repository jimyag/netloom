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
- IPv4 TCP/UDP exact `/32 source + destination port` ACLs
- policy-driven TCX L4 selftests where `SecurityGroupRule` is compiled into a
  `policy.Program` before being projected into the TCX map

Port ranges are already decomposed in the cilium-style policy compiler, but the
TCX program intentionally starts with exact L4 matches. Wider CIDR and range
support should move to an LPM trie or identity-based policy lookup instead of
expanding large ranges into hash entries.

The controller can reconcile either the built-in bootstrap state or a JSON
desired-state file. Docker e2e tests exercise the JSON path against a live OVN
Northbound database and verify TCX ACL behavior in privileged node containers.
OVN programming is emitted as idempotent `ovn-nbctl` operations with
`external_ids:netloom_owner=netloom` metadata, and the live executor batches a
reconcile step into one `ovn-nbctl` transaction.

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

For workload policy enforcement, the agent can attach the TCX IPv4 L4 ACL
program to each eligible local endpoint's host-side veth in egress direction.
Packets entering the workload namespace are filtered immediately before crossing
the veth peer, so Docker e2e now validates both datapath connectivity and
security-group drops at the workload boundary. Multiple local workloads can be
attached in one reconcile pass and are held for the same lifecycle window.

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
