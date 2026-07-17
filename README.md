# netloom

`netloom` is a bare-metal SDN control plane. It uses OVN/OVSDB for virtual
network topology and local OVS state, and uses eBPF/TCX for security groups and
ACL enforcement.

It is not a Kubernetes integration. There are no CRDs, no CNI plugin contract,
and no dependency on kube-apiserver as the source of truth.

## What Works

The core SDN path is implemented and covered by unit, integration, and Docker
e2e tests:

- VPC, subnet, endpoint, IPAM, DHCP, DNS, gateway, NAT, load balancer, route
  table, and policy route reconciliation.
- OVN Northbound writes through libovsdb for logical routers, switches, ports,
  DHCP options, DNS, static routes, BFD, NAT, load balancers, and health checks.
- Local Open_vSwitch OVSDB writes for provider networks, bridges, controllers,
  ports, interfaces, QoS, queues, and netloom runtime status.
- Linux datapath planning for workload netns/veth, addresses, routes, gateway
  routes, RPDB policy routing, and provider interface selection.
- Security group compilation into Cilium-style endpoint policy maps.
- eBPF/TCX ACL datapath for ingress and egress IPv4/IPv6 TCP, UDP, SCTP, and ICMP.
- Policy rollout, status, explain, desired-state import/export, DNS observation,
  health, audit, and Prometheus metrics entry points.

See [docs/features.md](docs/features.md) for the detailed capability matrix and
known gaps.

## Quick Start

Build and test:

```bash
go test ./...
go build ./cmd/netloom-controller ./cmd/netloom-agent ./cmd/netloom-dns-observer
```

Run the controller from a desired-state file:

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock \
NETLOOM_RECONCILE_INTERVAL_MS=5000 \
./netloom-controller
```

Run the agent on a bare-metal node:

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

Desired state can also be stored in the local Open_vSwitch database:

```bash
./netloom-agent desired-state-import -ovsdb unix:/var/run/openvswitch/db.sock < /etc/netloom/state.json
./netloom-agent desired-state-export -ovsdb unix:/var/run/openvswitch/db.sock
```

## Documentation

- [Feature matrix](docs/features.md)
- [Usage guide](docs/usage.md)
- [eBPF ACL design](docs/design/cilium-ebpf-acl.md)
- [Gap analysis vs Cilium and Kube-OVN](docs/analysis/sdn-gap-vs-cilium-kube-ovn.md)

## E2E Tests

Docker e2e tests are opt-in and should be run by case group:

```bash
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Policy' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Provider' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerControllerReconcileIdempotent' -count=1
```

## Development

```bash
task deps
task lint
task test
task test:integration
task test:e2e
task build
```
