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

Create a minimal desired-state file:

```json
{
  "vpcs": [{"name": "prod"}],
  "subnets": [
    {
      "name": "apps",
      "vpc": "prod",
      "cidr": "10.10.0.0/24",
      "gateway": "10.10.0.1",
      "dhcp": {"enabled": true}
    }
  ],
  "endpoints": [
    {
      "id": "vm-a",
      "vpc": "prod",
      "subnet": "apps",
      "ip": "10.10.0.10",
      "mac": "02:00:00:00:00:10",
      "node": "node-a",
      "security_groups": ["web"]
    }
  ],
  "security_groups": [
    {
      "name": "web",
      "vpc": "prod",
      "rules": [
        {
          "id": "allow-http",
          "direction": "ingress",
          "protocol": "tcp",
          "remote_entities": ["all"],
          "ports": [{"from": 80, "to": 80}],
          "action": "allow"
        }
      ]
    }
  ]
}
```

Run the controller to reconcile OVN Northbound topology:

```bash
NETLOOM_STATE_FILE=/etc/netloom/state.json \
NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock \
NETLOOM_RECONCILE_INTERVAL_MS=5000 \
./netloom-controller
```

Run the agent on a bare-metal node to reconcile Linux, OVS, and eBPF/TCX state:

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

Inspect policy and routing decisions without changing datapath state:

```bash
./netloom-agent policy-status -state /etc/netloom/state.json -node node-a
./netloom-agent policy-explain \
  -state /etc/netloom/state.json \
  -vpc prod \
  -endpoint vm-a \
  -direction ingress \
  -protocol tcp \
  -remote-ip 10.10.0.20 \
  -dest-port 80
./netloom-agent route-explain \
  -state /etc/netloom/state.json \
  -vpc prod \
  -source 10.10.0.10 \
  -dest 8.8.8.8 \
  -protocol tcp \
  -dest-port 443
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
