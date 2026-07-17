# netloom

`netloom` is a bare-metal SDN control plane.

It uses OVN/libovsdb for virtual network topology and local Open vSwitch state,
and uses eBPF/TCX for security groups and ACL enforcement. It is not a
Kubernetes integration: there are no CRDs, no CNI contract, and no dependency on
kube-apiserver.

## Status

The main SDN path is implemented.

Implemented:

- VPC, subnet, endpoint, IPAM, DHCP, DNS, gateway, NAT, load balancer, route
  table, and policy route reconciliation.
- OVN Northbound writes through libovsdb for logical routers, switches, ports,
  DHCP options, DNS, static routes, BFD, policy routes, NAT, load balancers, and
  health checks.
- Local Open_vSwitch OVSDB writes for provider bridges, controllers, ports,
  interfaces, QoS, queues, bridge mappings, desired state, and runtime status.
- Linux datapath planning for workload netns/veth, addresses, routes, gateway
  routes, RPDB policy routing, and provider interfaces.
- Security groups compiled into Cilium-style endpoint policy maps.
- eBPF/TCX ingress and egress ACLs for IPv4/IPv6 TCP, UDP, SCTP, and ICMP.
- Policy rollout, endpoint lifecycle controls, quarantine, freeze/unfreeze,
  rollback, explain APIs, status APIs, metrics, and OVSDB-backed audit state.

SecurityGroup/ACL is intentionally not implemented with OVN ACL. OVN owns
topology, routes, NAT, load balancing, DHCP, and DNS; eBPF/TCX owns endpoint
policy enforcement.

Still missing before production packaging:

- Multi-node deployment guide, certificates, systemd/container units, upgrade
  and rollback procedures.
- Backup and restore procedures for OVN NB/SB, Open_vSwitch DB, desired state,
  and policy rollout state.
- Long-running scale tests for many VPCs, subnets, endpoints, security groups,
  policy routes, load balancers, and provider queues.
- Operational runbooks for OVN failover, OVSDB reconnect, TCX attach failures,
  provider link changes, and BPF map pressure.

## Build

```bash
go test ./...
go build ./cmd/netloom-controller ./cmd/netloom-agent ./cmd/netloom-dns-observer
```

## Run

Controller reconciles desired state into OVN Northbound:

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
./netloom-controller
```

Agent reconciles node-local Linux, Open vSwitch, and eBPF/TCX state:

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

## Inspect

```bash
./netloom-controller controller-status -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-controller controller-events -ovsdb unix:/var/run/openvswitch/db.sock -limit 20
./netloom-agent agent-status -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-agent policy-status -state /etc/netloom/state.json -node node-a
./netloom-agent policy-explain -state /etc/netloom/state.json -vpc prod -endpoint vm-a -direction ingress -protocol tcp -remote-ip 10.10.0.20 -dest-port 80
./netloom-agent route-explain -state /etc/netloom/state.json -vpc prod -source 10.10.0.10 -dest 8.8.8.8 -protocol tcp -dest-port 443
curl -s http://127.0.0.1:9091/status
curl -s http://127.0.0.1:9092/metrics
```

## Documentation

- [Documentation index](docs/README.md)
- [Quickstart](docs/quickstart.md)
- [Current implementation status](docs/current-status.md)
- [Feature matrix](docs/features.md)
- [Bare-metal usage guide](docs/usage.md)
- [eBPF ACL design](docs/design/cilium-ebpf-acl.md)
- [Gap analysis vs Cilium and Kube-OVN](docs/analysis/sdn-gap-vs-cilium-kube-ovn.md)

## Test

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
