# netloom

`netloom` is a bare-metal SDN control plane.

It uses OVN/libovsdb for virtual network topology, Open vSwitch for local
provider networking, Linux datapath primitives for workload connectivity, and
eBPF/TCX for SecurityGroup and ACL enforcement.

This is not a Kubernetes integration. There are no CRDs, no CNI contract, and
no dependency on kube-apiserver.

## Current Status

The main SDN path is implemented:

- VPC, subnet, endpoint, IPAM, DHCP, DNS, gateway, NAT, load balancer, route
  table, and policy route reconciliation.
- OVN Northbound writes through libovsdb for routers, switches, ports, DHCP,
  DNS, static routes, BFD, policy routes, NAT, load balancers, and health
  checks.
- Local Open vSwitch writes for provider bridges, controllers, ports,
  interfaces, VLAN, QoS, queues, desired state, and runtime status.
- Linux datapath planning for netns/veth, addresses, routes, gateway routes,
  RPDB policy routing, and provider interfaces.
- SecurityGroup compilation into Cilium-style endpoint policy maps.
- eBPF/TCX ingress and egress ACLs for IPv4/IPv6 TCP, UDP, SCTP, and ICMP.
- Policy lifecycle, rollout, explain, status, metrics, freeze, quarantine,
  rollback, and OVSDB-backed audit state.

SecurityGroup and ACL rules are intentionally not implemented with OVN ACL.
OVN owns topology, routes, NAT, load balancing, DHCP, and DNS; eBPF/TCX owns
endpoint policy enforcement.

What is not finished is production packaging around that path: multi-node
deployment guides, certificate/systemd/container manifests, backup and restore,
upgrade and rollback runbooks, alert rules, and long-duration scale validation.

State is split deliberately:

- Desired network intent can come from a JSON file or from local
  `Open_vSwitch.external_ids:netloom_desired_state`.
- OVN Northbound DB stores the actual logical topology and service objects
  written by the controller.
- Local Open_vSwitch DB stores provider OVS objects plus agent/controller
  status, policy observations, and optional desired-state snapshots.

## Build

```bash
go test ./...
go build ./cmd/netloom-controller ./cmd/netloom-agent ./cmd/netloom-dns-observer
```

## Minimal Run

Controller reconciles desired state into OVN Northbound:

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
./netloom-controller
```

Agent reconciles node-local Open vSwitch, Linux datapath, and eBPF/TCX state:

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

Desired state can also be stored in local Open_vSwitch OVSDB:

```bash
./netloom-agent desired-state-import -ovsdb unix:/var/run/openvswitch/db.sock < /etc/netloom/state.json
./netloom-agent desired-state-export -ovsdb unix:/var/run/openvswitch/db.sock
```

## Documentation

- [Current implementation status](docs/current-status.md)
- [Quickstart](docs/quickstart.md)
- [Bare-metal usage guide](docs/usage.md)
- [Feature matrix](docs/features.md)
- [eBPF ACL design](docs/design/cilium-ebpf-acl.md)
- [Gap analysis vs Cilium and Kube-OVN](docs/analysis/sdn-gap-vs-cilium-kube-ovn.md)

## Validation

```bash
go test ./...
git diff --check
```

Docker e2e tests are opt-in and should be run by case group:

```bash
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Policy' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Provider' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerLinuxPolicyRouting' -count=1
```
