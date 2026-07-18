# netloom

`netloom` is a bare-metal SDN control plane. It is based on OVN/libovsdb for
logical topology and service objects, Open vSwitch for local provider networking,
Linux datapath primitives for node-local connectivity, and eBPF/TCX for
SecurityGroup and ACL enforcement.

It is not a Kubernetes integration. There are no CRDs, no CNI contract, and no
dependency on kube-apiserver.

## Current Status

The main SDN path is implemented.

Implemented control-plane features:

- VPC, subnet, endpoint, IPAM, DHCP, DNS, gateway, route table, policy route,
  NAT, load balancer, and health check reconciliation.
- OVN Northbound writes through libovsdb for logical routers, logical switches,
  logical switch ports, DHCP options, DNS records, static routes, BFD sessions,
  logical router policies, NAT, load balancers, and health checks.
- OVN live audit and steady-state repair for managed topology drift, including
  stale endpoint port semantics, policy-route semantic columns and BFD refs,
  NAT stale columns, load-balancer parent refs, health-check refs, stale
  `ip_port_mappings`, and stale router/switch CoPP refs.
- Desired state from a JSON file or from local
  `Open_vSwitch.external_ids:netloom_desired_state`.

Implemented node datapath and policy features:

- Local Open vSwitch provider bridge, controller, port, interface, VLAN, QoS,
  queue, desired state, and runtime status management.
- Linux netns/veth, addresses, routes, gateway routes, RPDB policy routing, and
  provider interface planning.
- SecurityGroup compilation into Cilium-style endpoint policy maps.
- eBPF/TCX ingress and egress ACLs for IPv4/IPv6 TCP, UDP, SCTP, and ICMP.
- Policy status, explain, rule and entry inspection, metrics, rollout, freeze,
  quarantine, rollback, and audit history.

SecurityGroup and ACL rules intentionally do not use OVN ACL. OVN owns topology,
routes, NAT, load balancing, DHCP, and DNS; eBPF/TCX owns endpoint policy
enforcement.

Remaining work is mostly production packaging: multi-node deployment guides,
certificate/systemd/container manifests, backup and restore, upgrade and
rollback runbooks, alert rules, and long-duration scale validation.

## Build

```bash
go test ./...
go build ./cmd/netloom-controller ./cmd/netloom-agent ./cmd/netloom-dns-observer
```

## Minimal Usage

Prepare a desired state file such as `/etc/netloom/state.json`. See
[docs/usage.md](docs/usage.md) for a complete example.

Run the controller to reconcile desired state into OVN Northbound:

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
NETLOOM_RECONCILE_INTERVAL_MS=5000 \
NETLOOM_CONTROLLER_METRICS_ADDR=:9091 \
./netloom-controller
```

Run the agent on each bare-metal node to reconcile local OVS, Linux datapath,
and eBPF/TCX state:

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_NODE_NAME=node-a \
NETLOOM_OVSDB_ENDPOINT=unix:/var/run/openvswitch/db.sock \
NETLOOM_POLICY_STORE=ebpf \
NETLOOM_TCX_WORKLOAD=1 \
NETLOOM_LINUX_DATAPATH=1 \
NETLOOM_LINUX_DATAPATH_MODE=netns \
NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth1 \
NETLOOM_RUNTIME_PREFLIGHT_STRICT=1 \
NETLOOM_AGENT_METRICS_ADDR=:9092 \
./netloom-agent
```

Desired state can also be stored in local Open vSwitch OVSDB:

```bash
./netloom-agent desired-state-import -ovsdb unix:/var/run/openvswitch/db.sock < /etc/netloom/state.json
./netloom-agent desired-state-export -ovsdb unix:/var/run/openvswitch/db.sock
```

## Validation

Local validation:

```bash
go test ./...
git diff --check
```

Useful runtime checks:

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

Docker e2e tests are opt-in and should be run by case group:

```bash
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Policy' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDocker.*Provider' -count=1
NETLOOM_E2E=1 go test ./tests/e2e -run 'TestDockerLinuxPolicyRouting' -count=1
```

## Documentation

- [Current implementation status](docs/current-status.md)
- [Quickstart](docs/quickstart.md)
- [Bare-metal usage guide](docs/usage.md)
- [Feature matrix](docs/features.md)
- [eBPF ACL design](docs/design/cilium-ebpf-acl.md)
- [Gap analysis vs Cilium and Kube-OVN](docs/analysis/sdn-gap-vs-cilium-kube-ovn.md)
