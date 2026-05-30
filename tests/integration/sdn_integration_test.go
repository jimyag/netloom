package integration

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/jimyag/netloom/internal/agent"
	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn"
	"github.com/jimyag/netloom/internal/topology"
)

func TestDesiredStateDrivesTopologyRoutesAndEBPFStyleACL(t *testing.T) {
	ctx := context.Background()
	state, err := control.LoadDesiredStateJSON(strings.NewReader(integrationStateJSON))
	if err != nil {
		t.Fatal(err)
	}

	memoryBackend := control.NewMemoryBackend()
	ovnRecorder := ovn.NewRecorderExecutor()
	ovnBackend := ovn.NewBackend(ovnRecorder)
	controller := control.NewController(control.MultiTopologyBackend{memoryBackend, ovnBackend}, memoryBackend)
	if err := controller.Reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}
	if _, ok := memoryBackend.VPCs["prod"]; !ok {
		t.Fatalf("vpc prod was not reconciled: %+v", memoryBackend.VPCs)
	}
	if subnet, ok := memoryBackend.Subnets["apps"]; !ok || subnet.Gateway.String() != "10.10.0.1" {
		t.Fatalf("subnet apps was not reconciled with gateway, got: %+v", memoryBackend.Subnets)
	} else if subnet.ProviderNetwork != "physnet-a" || subnet.VLAN != 100 {
		t.Fatalf("subnet provider network was not reconciled, got: %+v", subnet)
	} else if !subnet.DHCP.Enabled || subnet.DHCP.LeaseTime != 7200 {
		t.Fatalf("subnet dhcp was not reconciled, got: %+v", subnet.DHCP)
	}
	if gateway, ok := memoryBackend.Gateways["gw-a"]; !ok || gateway.Node != "node-a" || gateway.LANIP.String() != "10.10.0.254" {
		t.Fatalf("gateway gw-a was not reconciled, got: %+v", memoryBackend.Gateways)
	}
	if lb, ok := memoryBackend.LoadBalancers["web"]; !ok || lb.VIP.String() != "10.96.0.10" || len(lb.Backends) != 1 {
		t.Fatalf("load balancer web was not reconciled, got: %+v", memoryBackend.LoadBalancers)
	}
	if len(memoryBackend.PolicyRoutes) != 1 {
		t.Fatalf("policy routes = %d, want 1", len(memoryBackend.PolicyRoutes))
	}
	if program, ok := memoryBackend.PolicyProgram["pod-b"]; !ok || len(program.Rules) != 2 {
		t.Fatalf("security group rules for pod-b were not compiled, got: %+v", memoryBackend.PolicyProgram)
	}
	if !hasOVNCommand(ovnRecorder.Operations(), "lr-policy-add") {
		t.Fatalf("expected OVN policy route operation, got: %+v", ovnRecorder.Operations())
	}
	if !hasOVNCommand(ovnRecorder.Operations(), "lb-add") {
		t.Fatalf("expected OVN load balancer operation, got: %+v", ovnRecorder.Operations())
	}
	ovnOps := stringifyOVNOps(ovnRecorder.Operations())
	for _, expected := range []string{
		"external_ids:netloom_gateway_lan_ip=10.10.0.254",
		"external_ids:netloom_gateway_distributed=false",
		"options:chassis=node-a",
	} {
		if !strings.Contains(ovnOps, expected) {
			t.Fatalf("OVN gateway operations missing %q:\n%s", expected, ovnOps)
		}
	}

	routeDecision, err := topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
		VPC:      "prod",
		Source:   state.Endpoints[0].IP,
		Dest:     mustAddr(t, "172.16.10.20"),
		Protocol: model.ProtocolTCP,
		DestPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if routeDecision.MatchedBy != "policy-route/https-via-fw" || routeDecision.NextHop.String() != "10.10.0.253" {
		t.Fatalf("unexpected policy route decision: %+v", routeDecision)
	}
	if routeDecision.Translated.String() != "198.51.100.10" || routeDecision.Gateway != "gw-a" {
		t.Fatalf("expected gateway SNAT to be applied, got: %+v", routeDecision)
	}
	serviceDecision, err := topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
		VPC:      "prod",
		Source:   state.Endpoints[0].IP,
		Dest:     mustAddr(t, "10.96.0.10"),
		Protocol: model.ProtocolTCP,
		DestPort: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	if serviceDecision.MatchedBy != "load-balancer/web" || serviceDecision.Translated.String() != "10.10.0.11" || serviceDecision.TranslatedPort != 8080 {
		t.Fatalf("expected service VIP to resolve to backend, got: %+v", serviceDecision)
	}

	store := dataplane.NewInMemoryPolicyStore()
	result, err := agent.ReconcileNode(ctx, state, "node-b", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Endpoints != 1 || result.Entries == 0 || result.TCXEligible != 1 {
		t.Fatalf("unexpected agent result: %+v", result)
	}
	entries := store.Entries("pod-b")
	if len(entries) == 0 {
		t.Fatal("expected pod-b policy entries")
	}
	remoteIdentity := entries[0].Key.RemoteIdentity
	drop := dataplane.Evaluate(entries, dataplane.Packet{
		RemoteIdentity: remoteIdentity,
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		DestPort:       8080,
	})
	if drop.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected ingress tcp/8080 from pod-a identity to drop, got %+v", drop)
	}
	allow := dataplane.Evaluate(entries, dataplane.Packet{
		RemoteIdentity: remoteIdentity,
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		DestPort:       9090,
	})
	if allow.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected ingress tcp/9090 from pod-a identity to allow, got %+v", allow)
	}
}

func hasOVNCommand(ops []ovn.Operation, command string) bool {
	for _, op := range ops {
		if op.Command == command {
			return true
		}
	}
	return false
}

func stringifyOVNOps(ops []ovn.Operation) string {
	lines := make([]string, 0, len(ops))
	for _, op := range ops {
		lines = append(lines, op.String())
	}
	return strings.Join(lines, "\n")
}

func mustAddr(t *testing.T, raw string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

const integrationStateJSON = `{
  "vpcs": [{"name": "prod"}],
  "subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400}}],
  "endpoints": [
    {"id": "pod-a", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.10", "node": "node-a", "security_groups": ["client"]},
    {"id": "pod-b", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.11", "node": "node-b", "security_groups": ["server"]}
  ],
  "route_tables": [{"name": "main", "vpc": "prod", "routes": [{"destination": "0.0.0.0/0", "next_hop": "10.10.0.254"}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "prod", "priority": 100, "match": {"source": "10.10.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hop": "10.10.0.253"}}],
  "gateways": [{"name": "gw-a", "vpc": "prod", "node": "node-a", "external_if": "eth0", "lan_ip": "10.10.0.254"}],
  "nat_rules": [{"name": "egress", "vpc": "prod", "type": "snat", "match_cidr": "10.10.0.0/24", "external_ip": "198.51.100.10"}],
  "load_balancers": [{"name": "web", "vpc": "prod", "vip": "10.96.0.10", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.10.0.11", "port": 8080}], "subnets": ["apps"]}],
  "security_groups": [
    {"name": "client", "vpc": "prod", "rules": [{"id": "client-egress", "priority": 100, "direction": "egress", "protocol": "any", "remote_cidr": "0.0.0.0/0", "action": "allow"}]},
    {"name": "server", "vpc": "prod", "rules": [
      {"id": "drop-web", "priority": 200, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.10.0.10/32", "ports": [{"from": 8080, "to": 8080}], "action": "drop"},
      {"id": "allow-alt", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.10.0.10/32", "ports": [{"from": 9090, "to": 9090}], "action": "allow"}
    ]}
  ]
}`
