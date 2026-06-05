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
	"github.com/jimyag/netloom/internal/policy"
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
	if subnet, ok := memoryBackend.Subnets["prod\x00apps"]; !ok || subnet.Gateway.String() != "10.10.0.1" {
		t.Fatalf("subnet apps was not reconciled with gateway, got: %+v", memoryBackend.Subnets)
	} else if subnet.ProviderNetwork != "physnet-a" || subnet.VLAN != 100 {
		t.Fatalf("subnet provider network was not reconciled, got: %+v", subnet)
	} else if !subnet.DHCP.Enabled || subnet.DHCP.LeaseTime != 7200 {
		t.Fatalf("subnet dhcp was not reconciled, got: %+v", subnet.DHCP)
	} else if len(subnet.DHCP.DNSServers) != 1 || subnet.DHCP.DNSServers[0] != netip.MustParseAddr("10.96.0.10") || subnet.DHCP.DomainName != "svc.cluster.local" {
		t.Fatalf("subnet dhcp dns options were not reconciled, got: %+v", subnet.DHCP)
	} else if len(subnet.ExcludeCIDRs) != 1 || subnet.ExcludeCIDRs[0].String() != "10.10.0.16/28" {
		t.Fatalf("subnet exclude cidrs were not reconciled, got: %+v", subnet.ExcludeCIDRs)
	}
	if gateway, ok := memoryBackend.Gateways["gw-a"]; !ok || gateway.Node != "node-a" || gateway.LANIP.String() != "10.10.0.254" {
		t.Fatalf("gateway gw-a was not reconciled, got: %+v", memoryBackend.Gateways)
	}
	if lb, ok := memoryBackend.LoadBalancers["prod\x00web"]; !ok || lb.VIP.String() != "10.96.0.10" || len(lb.Frontends()) != 2 {
		t.Fatalf("load balancer web was not reconciled, got: %+v", memoryBackend.LoadBalancers)
	}
	if len(memoryBackend.PolicyRoutes) != 1 {
		t.Fatalf("policy routes = %d, want 1", len(memoryBackend.PolicyRoutes))
	}
	if program, ok := memoryBackend.PolicyProgram["pod-b"]; !ok || len(program.Rules) != 2 {
		t.Fatalf("security group rules for pod-b were not compiled, got: %+v", memoryBackend.PolicyProgram)
	}
	clientProgram, ok := memoryBackend.PolicyProgram["pod-a"]
	if !ok || len(clientProgram.Rules) != 13 {
		t.Fatalf("egress rules for pod-a were not compiled, got: %+v", memoryBackend.PolicyProgram)
	}
	if !hasOVNCommand(ovnRecorder.Operations(), "lr-policy-add") {
		t.Fatalf("expected OVN policy route operation, got: %+v", ovnRecorder.Operations())
	}
	ovnOps := stringifyOVNOps(ovnRecorder.Operations())
	for _, expected := range []string{
		"--ecmp lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.253",
		"--ecmp lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.254",
		"tcp.src == 32000",
	} {
		if !strings.Contains(ovnOps, expected) {
			t.Fatalf("expected OVN ECMP static route operation %q:\n%s", expected, ovnOps)
		}
	}
	if !hasOVNCommand(ovnRecorder.Operations(), "lb-add") {
		t.Fatalf("expected OVN load balancer operation, got: %+v", ovnRecorder.Operations())
	}
	for _, expected := range []string{
		"external_ids:netloom_gateway_lan_ip=10.10.0.254",
		"external_ids:netloom_gateway_distributed=false",
		"options:chassis=node-a",
		"lsp-set-addresses nl_lp_pod-a 0a:58:0a:0a:00:0a 10.10.0.10",
		"lsp-set-port-security nl_lp_pod-a 0a:58:0a:0a:00:0a 10.10.0.10",
	} {
		if !strings.Contains(ovnOps, expected) {
			t.Fatalf("OVN gateway operations missing %q:\n%s", expected, ovnOps)
		}
	}

	routeDecision, err := topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
		VPC:        "prod",
		Source:     state.Endpoints[0].IP,
		SourcePort: 32000,
		Dest:       mustAddr(t, "172.16.10.20"),
		Protocol:   model.ProtocolTCP,
		DestPort:   443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if routeDecision.MatchedBy != "policy-route/https-via-fw" || routeDecision.NextHop.String() != "10.10.0.253" {
		t.Fatalf("unexpected policy route decision: %+v", routeDecision)
	}
	if routeDecision.Translated.String() != "198.51.100.10" || routeDecision.Gateway != "gw-b" {
		t.Fatalf("expected gateway SNAT to be applied, got: %+v", routeDecision)
	}
	routeDecision, err = topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
		VPC:        "prod",
		Source:     state.Endpoints[0].IP,
		SourcePort: 31000,
		Dest:       mustAddr(t, "172.16.10.20"),
		Protocol:   model.ProtocolTCP,
		DestPort:   443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if routeDecision.MatchedBy != "route-table/main" {
		t.Fatalf("source-port mismatch should skip policy route, got: %+v", routeDecision)
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
	metricsDecision, err := topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
		VPC:      "prod",
		Source:   state.Endpoints[0].IP,
		Dest:     mustAddr(t, "10.96.0.10"),
		Protocol: model.ProtocolTCP,
		DestPort: 9090,
	})
	if err != nil {
		t.Fatal(err)
	}
	if metricsDecision.MatchedBy != "load-balancer/web" || metricsDecision.Translated.String() != "10.10.0.11" || metricsDecision.TranslatedPort != 9091 {
		t.Fatalf("expected metrics service VIP to resolve to backend, got: %+v", metricsDecision)
	}
	dnatDecision, err := topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
		VPC:    "prod",
		Source: mustAddr(t, "203.0.113.10"),
		Dest:   mustAddr(t, "198.51.100.20"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if dnatDecision.MatchedBy != "nat/web-dnat" || dnatDecision.Destination != "pod-b" || dnatDecision.Translated.String() != "10.10.0.11" {
		t.Fatalf("expected DNAT to resolve to pod-b, got: %+v", dnatDecision)
	}
	fipDecision, err := topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
		VPC:    "prod",
		Source: mustAddr(t, "203.0.113.10"),
		Dest:   mustAddr(t, "198.51.100.30"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if fipDecision.MatchedBy != "nat/web-fip" || fipDecision.Destination != "pod-b" || fipDecision.Translated.String() != "10.10.0.11" {
		t.Fatalf("expected floating IP to resolve to pod-b, got: %+v", fipDecision)
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
		RemoteIP:       mustAddr(t, "10.10.0.10"),
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		DestPort:       8080,
	})
	if drop.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected ingress tcp/8080 from pod-a identity to drop, got %+v", drop)
	}
	allow := dataplane.Evaluate(entries, dataplane.Packet{
		RemoteIdentity: remoteIdentity,
		RemoteIP:       mustAddr(t, "10.10.0.10"),
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		DestPort:       9090,
	})
	if allow.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected ingress tcp/9090 from pod-a identity to allow, got %+v", allow)
	}
	clientEntries, err := dataplane.EncodeProgram(clientProgram)
	if err != nil {
		t.Fatal(err)
	}
	fqdnAllow := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "203.0.113.10"),
		DestPort:  443,
	})
	if fqdnAllow.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected egress tcp/443 to fqdn-derived ip to allow, got %+v", fqdnAllow)
	}
	fqdnDrop := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "203.0.113.20"),
		DestPort:  443,
	})
	if fqdnDrop.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected egress tcp/443 to unresolved ip to drop, got %+v", fqdnDrop)
	}
	cidrGroupAllow := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "10.20.1.10"),
		DestPort:  8443,
	})
	if cidrGroupAllow.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected egress tcp/8443 to cidr-group-derived ip to allow, got %+v", cidrGroupAllow)
	}
	cidrGroupExceptDrop := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "10.20.200.10"),
		DestPort:  8443,
	})
	if cidrGroupExceptDrop.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected egress tcp/8443 inside cidr-group except range to drop, got %+v", cidrGroupExceptDrop)
	}
	selectorAllow := dataplane.Evaluate(clientEntries, dataplane.Packet{
		RemoteIdentity: policy.EndpointIdentity("pod-b"),
		Direction:      dataplane.DirectionEgress,
		Protocol:       6,
		RemoteIP:       mustAddr(t, "10.10.0.11"),
		DestPort:       9091,
	})
	if selectorAllow.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected egress tcp/9091 to selector-derived endpoint to allow, got %+v", selectorAllow)
	}
	servicePolicyAllow := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "10.96.0.10"),
		DestPort:  80,
	})
	if servicePolicyAllow.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected egress tcp/80 to remote service VIP to allow, got %+v", servicePolicyAllow)
	}
	metricsPolicyAllow := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "10.96.0.10"),
		DestPort:  9090,
	})
	if metricsPolicyAllow.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected egress tcp/9090 to remote service VIP to allow, got %+v", metricsPolicyAllow)
	}
	apiServicePolicyAllow := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "10.96.0.20"),
		DestPort:  8443,
	})
	if apiServicePolicyAllow.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected egress tcp/8443 to explicit remote service VIP port to allow, got %+v", apiServicePolicyAllow)
	}
	apiServicePolicyDrop := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "10.96.0.20"),
		DestPort:  9443,
	})
	if apiServicePolicyDrop.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected egress tcp/9443 to unmatched remote service VIP port to drop, got %+v", apiServicePolicyDrop)
	}
	multiServicePolicyAllow := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "10.96.0.30"),
		DestPort:  80,
	})
	if multiServicePolicyAllow.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected egress tcp/80 to any-protocol explicit remote service VIP port to allow, got %+v", multiServicePolicyAllow)
	}
	multiServiceProtocolDrop := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  17,
		RemoteIP:  mustAddr(t, "10.96.0.30"),
		DestPort:  80,
	})
	if multiServiceProtocolDrop.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected egress udp/80 to unmatched remote service protocol to drop, got %+v", multiServiceProtocolDrop)
	}
	multiServicePortDrop := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  17,
		RemoteIP:  mustAddr(t, "10.96.0.30"),
		DestPort:  53,
	})
	if multiServicePortDrop.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected egress udp/53 to unmatched explicit remote service port to drop, got %+v", multiServicePortDrop)
	}
	exceptAllow := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "192.0.2.10"),
		DestPort:  9443,
	})
	if exceptAllow.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected egress tcp/9443 outside except cidr to allow, got %+v", exceptAllow)
	}
	exceptDrop := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "192.0.2.200"),
		DestPort:  9443,
	})
	if exceptDrop.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected egress tcp/9443 inside except cidr to drop, got %+v", exceptDrop)
	}
	tierAllow := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "198.51.100.10"),
		DestPort:  9553,
	})
	if tierAllow.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected tier-0 platform rule to beat tier-1 tenant drop, got %+v", tierAllow)
	}
	hostAllow := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "10.10.0.254"),
		DestPort:  9444,
	})
	if hostAllow.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected egress tcp/9444 to host gateway entity to allow, got %+v", hostAllow)
	}
	remoteNodeAllow := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "10.10.0.253"),
		DestPort:  4240,
	})
	if remoteNodeAllow.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected egress tcp/4240 to remote-node gateway entity to allow, got %+v", remoteNodeAllow)
	}
	remoteNodeLocalDrop := dataplane.Evaluate(clientEntries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "10.10.0.254"),
		DestPort:  4240,
	})
	if remoteNodeLocalDrop.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected local gateway to stay outside remote-node entity, got %+v", remoteNodeLocalDrop)
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
  "subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1", "exclude_cidrs": ["10.10.0.16/28"], "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400, "dns_servers": ["10.96.0.10"], "domain_name": "svc.cluster.local", "search_domains": ["cluster.local", "svc.cluster.local"]}}],
  "endpoints": [
    {"id": "pod-a", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.10", "mac": "0A:58:0A:0A:00:0A", "node": "node-a", "security_groups": ["platform-client", "client"], "labels": {"app": "client", "env": "prod"}},
    {"id": "pod-b", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.11", "node": "node-b", "security_groups": ["server"], "labels": {"app": "server", "env": "prod"}}
  ],
  "route_tables": [{"name": "main", "vpc": "prod", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.10.0.253", "10.10.0.254"]}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "prod", "priority": 100, "match": {"source": "10.10.0.0/28", "destination": "172.16.0.0/16", "protocol": "tcp", "src_ports": [{"from": 32000, "to": 32000}], "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.10.0.253"]}}],
  "gateways": [
    {"name": "gw-a", "vpc": "prod", "node": "node-a", "external_if": "eth0", "lan_ip": "10.10.0.254"},
    {"name": "gw-b", "vpc": "prod", "node": "node-b", "external_if": "eth0", "lan_ip": "10.10.0.253"}
  ],
  "nat_rules": [
    {"name": "egress", "vpc": "prod", "type": "snat", "match_cidr": "10.10.0.0/28", "external_ip": "198.51.100.10"},
    {"name": "web-dnat", "vpc": "prod", "type": "dnat", "external_ip": "198.51.100.20", "target_ip": "10.10.0.11"},
    {"name": "web-fip", "vpc": "prod", "type": "dnat_and_snat", "external_ip": "198.51.100.30", "target_ip": "10.10.0.11"}
  ],
  "load_balancers": [
    {"name": "web", "vpc": "prod", "vip": "10.96.0.10", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.10.0.12", "port": 8080, "healthy": false}, {"ip": "10.10.0.11", "port": 8080}]}, {"name": "metrics", "port": 9090, "protocol": "tcp", "backends": [{"ip": "10.10.0.11", "port": 9091}]}], "subnets": ["apps"]},
    {"name": "api", "vpc": "prod", "vip": "10.96.0.20", "ports": [{"name": "https", "port": 8443, "protocol": "tcp", "backends": [{"ip": "10.10.0.11", "port": 8443}]}], "subnets": ["apps"]},
    {"name": "multi", "vpc": "prod", "vip": "10.96.0.30", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.10.0.11", "port": 8080}]}, {"name": "dns", "port": 53, "protocol": "udp", "backends": [{"ip": "10.10.0.11", "port": 5353}]}], "subnets": ["apps"]}
  ],
  "security_groups": [
    {"name": "platform-client", "vpc": "prod", "tier": 0, "rules": [
      {"id": "platform-egress-dns", "priority": 10, "direction": "egress", "protocol": "tcp", "remote_cidr": "198.51.100.0/24", "ports": [{"from": 9553, "to": 9553}], "action": "allow"}
    ]},
    {"name": "client", "vpc": "prod", "tier": 1, "rules": [
      {"id": "client-egress-api", "priority": 100, "direction": "egress", "protocol": "tcp", "remote_fqdns": [{"match_name": "api.example.com"}], "ports": [{"from": 443, "to": 443}], "action": "allow"},
      {"id": "client-egress-corp", "priority": 90, "direction": "egress", "protocol": "tcp", "remote_cidr_group": "corp", "ports": [{"from": 8443, "to": 8443}], "action": "allow"},
      {"id": "client-egress-docs", "priority": 80, "direction": "egress", "protocol": "tcp", "remote_cidr": "192.0.2.0/24", "except_cidrs": ["192.0.2.128/25"], "ports": [{"from": 9443, "to": 9443}], "action": "allow"},
      {"id": "client-egress-host", "priority": 70, "direction": "egress", "protocol": "tcp", "remote_entities": ["host"], "ports": [{"from": 9444, "to": 9444}], "action": "allow"},
      {"id": "client-egress-remote-node", "priority": 60, "direction": "egress", "protocol": "tcp", "remote_entities": ["remote-node"], "ports": [{"from": 4240, "to": 4240}], "action": "allow"},
      {"id": "client-egress-server-selector", "priority": 50, "direction": "egress", "protocol": "tcp", "remote_endpoint_selector": {"app": "server"}, "remote_endpoint_expressions": [{"key": "env", "operator": "In", "values": ["prod"]}, {"key": "deprecated", "operator": "DoesNotExist"}], "ports": [{"from": 9091, "to": 9091}], "action": "allow"},
      {"id": "client-egress-web-service", "priority": 40, "direction": "egress", "protocol": "any", "remote_service": "web", "action": "allow"},
      {"id": "client-egress-api-service", "priority": 35, "direction": "egress", "protocol": "tcp", "remote_service": "api", "ports": [{"from": 8443, "to": 8443}], "action": "allow"},
      {"id": "client-egress-multi-http-service", "priority": 34, "direction": "egress", "protocol": "any", "remote_service": "multi", "ports": [{"from": 80, "to": 80}], "action": "allow"},
      {"id": "client-drop-platform-dns", "priority": 1000, "direction": "egress", "protocol": "tcp", "remote_cidr": "198.51.100.0/24", "ports": [{"from": 9553, "to": 9553}], "action": "drop"}
    ]},
    {"name": "server", "vpc": "prod", "rules": [
      {"id": "drop-web", "priority": 200, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.10.0.10/32", "ports": [{"from": 8080, "to": 8080}], "action": "drop"},
      {"id": "allow-alt", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.10.0.10/32", "ports": [{"from": 9090, "to": 9090}], "action": "allow"}
    ]}
  ],
  "cidr_groups": [{"name": "corp", "vpc": "prod", "entries": [{"cidr": "10.20.0.0/16", "except_cidrs": ["10.20.128.0/17"]}]}],
  "dns_records": [
    {"name": "api.example.com", "ips": ["203.0.113.10"]},
    {"name": "api.example.com", "ips": ["203.0.113.20"], "ttl_seconds": 1, "observed_at": "2000-01-01T00:00:00Z"}
  ]
}`
