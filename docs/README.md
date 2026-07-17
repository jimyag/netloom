# Netloom Documentation

`netloom` is a bare-metal SDN product. Its main control-plane and datapath
features are implemented; the remaining work is mostly production packaging,
deployment guidance, scale validation, and operations runbooks.

## Implemented Main Path

- OVN/libovsdb control plane: VPC, subnet, endpoint, DHCP, DNS, gateway, route
  table, policy route, NAT, load balancer, health check, and audit state.
- Node datapath: Open vSwitch provider bridge/port/interface, VLAN, QoS/Queue,
  Linux netns/veth, addresses, routes, gateway routes, and RPDB policy routing.
- Security policy: SecurityGroup rules are compiled into Cilium-style endpoint
  policy maps and enforced by eBPF/TCX ingress/egress ACLs. OVN ACL is not used
  for SecurityGroup enforcement.
- Operations surface: desired state from JSON or Open_vSwitch OVSDB,
  controller/agent status, policy and route explain, policy entries/rules/events,
  rollout, freeze, quarantine, rollback, metrics, and audit history.

## Reading Order

1. [Current implementation status](current-status.md): what is implemented and
   what is still missing before production packaging.
2. [Quickstart](quickstart.md): the shortest path to run controller and agent in
   a bare-metal environment.
3. [Bare-metal usage guide](usage.md): desired state example, runtime flags,
   validation commands, rollout operations, and OVSDB-backed state.
4. [Feature matrix](features.md): feature-by-feature implementation and test
   entry points for VPC, subnet, gateway, SecurityGroup, policy route, provider
   network, NAT, load balancer, and observability.
5. [eBPF ACL design](design/cilium-ebpf-acl.md): why SecurityGroup/ACL
   enforcement lives in eBPF/TCX instead of OVN ACL.
6. [Gap analysis vs Cilium and Kube-OVN](analysis/sdn-gap-vs-cilium-kube-ovn.md):
   implementation choices and remaining production hardening work.

## Minimal Commands

```bash
go test ./...
go build ./cmd/netloom-controller ./cmd/netloom-agent ./cmd/netloom-dns-observer
```

Run controller:

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
./netloom-controller
```

Run agent:

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

Import desired state into local Open_vSwitch OVSDB:

```bash
./netloom-agent desired-state-import -ovsdb unix:/var/run/openvswitch/db.sock < /etc/netloom/state.json
./netloom-agent desired-state-export -ovsdb unix:/var/run/openvswitch/db.sock
```

Inspect runtime state:

```bash
./netloom-controller controller-status -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-agent agent-status -ovsdb unix:/var/run/openvswitch/db.sock
./netloom-agent policy-status -state /etc/netloom/state.json -node node-a
./netloom-agent policy-explain -state /etc/netloom/state.json -vpc prod -endpoint vm-a -direction ingress -protocol tcp -remote-ip 10.10.0.20 -dest-port 80
./netloom-agent route-explain -state /etc/netloom/state.json -vpc prod -source 10.10.0.10 -dest 8.8.8.8 -protocol tcp -dest-port 443
curl -s http://127.0.0.1:9091/status
curl -s http://127.0.0.1:9092/metrics
```
