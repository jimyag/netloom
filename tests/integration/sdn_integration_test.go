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
	if gateway, ok := memoryBackend.Gateways["prod\x00gw-a"]; !ok || gateway.Node != "node-a" || gateway.LANIP.String() != "10.10.0.254" {
		t.Fatalf("gateway gw-a was not reconciled, got: %+v", memoryBackend.Gateways)
	}
	if lb, ok := memoryBackend.LoadBalancers["prod\x00web"]; !ok || lb.VIP.String() != "10.96.0.10" || len(lb.Frontends()) != 2 {
		t.Fatalf("load balancer web was not reconciled, got: %+v", memoryBackend.LoadBalancers)
	}
	if len(memoryBackend.PolicyRoutes) != 1 {
		t.Fatalf("policy routes = %d, want 1", len(memoryBackend.PolicyRoutes))
	}
	if program, ok := memoryBackend.PolicyProgram[model.EndpointKey("prod", "pod-b")]; !ok || len(program.Rules) != 2 {
		t.Fatalf("security group rules for pod-b were not compiled, got: %+v", memoryBackend.PolicyProgram)
	}
	clientProgram, ok := memoryBackend.PolicyProgram[model.EndpointKey("prod", "pod-a")]
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
		"set logical_switch nl_ls_prod_apps other_config:subnet=10.10.0.0/24",
		`set logical_switch nl_ls_prod_apps other_config:exclude_ips="10.10.0.1 10.10.0.16..10.10.0.31"`,
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
		"lsp-set-addresses nl_lp_prod_pod-a 0a:58:0a:0a:00:0a 10.10.0.10",
		"lsp-set-port-security nl_lp_prod_pod-a 0a:58:0a:0a:00:0a 10.10.0.10",
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
	if dnatDecision.MatchedBy != "nat/web-dnat" || dnatDecision.Destination != model.EndpointKey("prod", "pod-b") || dnatDecision.Translated.String() != "10.10.0.11" {
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
	if fipDecision.MatchedBy != "nat/web-fip" || fipDecision.Destination != model.EndpointKey("prod", "pod-b") || fipDecision.Translated.String() != "10.10.0.11" {
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
	entries := store.Entries(model.EndpointKey("prod", "pod-b"))
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
		RemoteIdentity: policy.EndpointIdentity(model.EndpointKey("prod", "pod-b")),
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

func TestDesiredStatePriorityConflictMatchesTCXEligibilityFromJSON(t *testing.T) {
	ctx := context.Background()
	denyState, err := control.LoadDesiredStateJSON(strings.NewReader(`{
  "vpcs": [{"name": "file"}],
  "provider_networks": [{"name": "physnet-a", "nodes": [{"node": "node-a", "interface": "eth1"}, {"node": "node-b", "interface": "eth1"}]}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400, "dns_servers": ["10.96.0.10"], "domain_name": "svc.cluster.local", "search_domains": ["cluster.local", "svc.cluster.local"]}}],
  "endpoints": [
    {"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["client"]},
    {"id": "file-pod-b", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.11", "node": "node-b", "security_groups": ["policy-conflict"]}
  ],
  "security_groups": [
    {"name": "client", "vpc": "file", "rules": []},
    {
      "name": "policy-conflict",
      "vpc": "file",
      "rules": [
        {"id": "allow-tcp", "priority": 200, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.10/32", "ports": [{"from": 8081, "to": 8081}], "action": "allow"},
        {"id": "deny-tcp", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.10/32", "ports": [{"from": 8081, "to": 8081}], "action": "drop"}
      ]
    }
  ]
}`))
	if err != nil {
		t.Fatal(err)
	}
	denyResult, err := agent.ReconcileNode(ctx, denyState, "node-b", dataplane.NewInMemoryPolicyStore())
	if err != nil {
		t.Fatal(err)
	}
	if denyResult.TCXEligible != 1 {
		t.Fatalf("deny-winning tcx eligible = %d, want 1", denyResult.TCXEligible)
	}

	allowState, err := control.LoadDesiredStateJSON(strings.NewReader(`{
  "vpcs": [{"name": "file"}],
  "provider_networks": [{"name": "physnet-a", "nodes": [{"node": "node-a", "interface": "eth1"}, {"node": "node-b", "interface": "eth1"}]}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400, "dns_servers": ["10.96.0.10"], "domain_name": "svc.cluster.local", "search_domains": ["cluster.local", "svc.cluster.local"]}}],
  "endpoints": [
    {"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["client"]},
    {"id": "file-pod-b", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.11", "node": "node-b", "security_groups": ["policy-conflict"]}
  ],
  "security_groups": [
    {"name": "client", "vpc": "file", "rules": []},
    {
      "name": "policy-conflict",
      "vpc": "file",
      "rules": [
        {"id": "allow-tcp", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.10/32", "ports": [{"from": 8081, "to": 8081}], "action": "allow"},
        {"id": "deny-tcp", "priority": 200, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.10/32", "ports": [{"from": 8081, "to": 8081}], "action": "drop"}
      ]
    }
  ]
}`))
	if err != nil {
		t.Fatal(err)
	}
	allowResult, err := agent.ReconcileNode(ctx, allowState, "node-b", dataplane.NewInMemoryPolicyStore())
	if err != nil {
		t.Fatal(err)
	}
	if allowResult.TCXEligible != 0 {
		t.Fatalf("allow-winning tcx eligible = %d, want 0", allowResult.TCXEligible)
	}
}

func TestDesiredStateExpandsFQDNPatternsAndPortMappedNATFromJSON(t *testing.T) {
	ctx := context.Background()
	state, err := control.LoadDesiredStateJSON(strings.NewReader(`{
  "vpcs": [{"name": "prod"}],
  "subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1"}],
  "endpoints": [
    {"id": "pod-a", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.10", "node": "node-a", "security_groups": ["client"]},
    {"id": "web", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.20", "node": "node-b"}
  ],
  "nat_rules": [
    {"name": "ssh", "vpc": "prod", "type": "dnat", "external_ip": "198.51.100.23", "target_ip": "10.10.0.10", "protocol": "tcp", "external_port": 2222, "target_port": 22},
    {"name": "https-fip", "vpc": "prod", "type": "dnat_and_snat", "external_ip": "198.51.100.30", "target_ip": "10.10.0.20", "protocol": "tcp", "external_port": 8443, "target_port": 443}
  ],
  "security_groups": [
    {"name": "client", "vpc": "prod", "rules": [
      {"id": "allow-patterns", "priority": 100, "direction": "egress", "protocol": "tcp", "remote_fqdns": [{"match_pattern": "*.svc.example.com"}, {"match_pattern": "**.deep.example.com"}], "ports": [{"from": 443, "to": 443}], "action": "allow"}
    ]}
  ],
  "dns_records": [
    {"name": "api.svc.example.com", "ips": ["203.0.113.10"]},
    {"name": "a.b.svc.example.com", "ips": ["203.0.113.20"]},
    {"name": "one.deep.example.com", "ips": ["203.0.113.30"]},
    {"name": "one.two.deep.example.com", "ips": ["203.0.113.40"]},
    {"name": "deep.example.com", "ips": ["203.0.113.50"]}
  ]
}`))
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

	sshDecision, err := topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
		VPC:      "prod",
		Source:   mustAddr(t, "203.0.113.200"),
		Dest:     mustAddr(t, "198.51.100.23"),
		Protocol: model.ProtocolTCP,
		DestPort: 2222,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sshDecision.MatchedBy != "nat/ssh" || sshDecision.Destination != model.EndpointKey("prod", "pod-a") || sshDecision.Translated != mustAddr(t, "10.10.0.10") || sshDecision.TranslatedPort != 22 {
		t.Fatalf("ssh decision = %+v, want port-mapped dnat to pod-a:22", sshDecision)
	}

	fipDecision, err := topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
		VPC:      "prod",
		Source:   mustAddr(t, "203.0.113.200"),
		Dest:     mustAddr(t, "198.51.100.30"),
		Protocol: model.ProtocolTCP,
		DestPort: 8443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fipDecision.MatchedBy != "nat/https-fip" || fipDecision.Destination != model.EndpointKey("prod", "web") || fipDecision.Translated != mustAddr(t, "10.10.0.20") || fipDecision.TranslatedPort != 443 {
		t.Fatalf("fip decision = %+v, want floating-ip target port translation", fipDecision)
	}

	program, ok := memoryBackend.PolicyProgram[model.EndpointKey("prod", "pod-a")]
	if !ok {
		t.Fatalf("missing compiled client policy program: %+v", memoryBackend.PolicyProgram)
	}
	entries, err := dataplane.EncodeProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	for _, packet := range []struct {
		name    string
		ip      string
		verdict dataplane.Verdict
	}{
		{name: "single-label wildcard", ip: "203.0.113.10", verdict: dataplane.VerdictAllow},
		{name: "double-star deep wildcard", ip: "203.0.113.30", verdict: dataplane.VerdictAllow},
		{name: "nested deep wildcard", ip: "203.0.113.40", verdict: dataplane.VerdictAllow},
		{name: "star does not span labels", ip: "203.0.113.20", verdict: dataplane.VerdictDrop},
		{name: "pattern does not match root", ip: "203.0.113.50", verdict: dataplane.VerdictDrop},
	} {
		decision := dataplane.Evaluate(entries, dataplane.Packet{
			Direction: dataplane.DirectionEgress,
			Protocol:  6,
			RemoteIP:  mustAddr(t, packet.ip),
			DestPort:  443,
		})
		if decision.Verdict != packet.verdict {
			t.Fatalf("%s decision = %+v, want verdict %s", packet.name, decision, packet.verdict)
		}
	}

	ovnOps := stringifyOVNOps(ovnRecorder.Operations())
	for _, expected := range []string{
		"external_port_range=2222",
		"logical_port_range=22",
		"external_port_range=8443",
		"logical_port_range=443",
	} {
		if !strings.Contains(ovnOps, expected) {
			t.Fatalf("ovn operations missing %q:\n%s", expected, ovnOps)
		}
	}
}

func TestDesiredStateRemovesLocalnetTagWhenProviderNetworkVLANIsCleared(t *testing.T) {
	ctx := context.Background()
	initial, err := control.LoadDesiredStateJSON(strings.NewReader(`{
  "vpcs": [{"name": "file"}],
  "provider_networks": [{"name": "physnet-a", "nodes": [{"node": "node-a", "interface": "eth1"}]}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a"}]
}`))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := control.LoadDesiredStateJSON(strings.NewReader(`{
  "vpcs": [{"name": "file"}],
  "provider_networks": [{"name": "physnet-a", "nodes": [{"node": "node-a", "interface": "eth1"}]}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a"}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a"}]
}`))
	if err != nil {
		t.Fatal(err)
	}

	memoryBackend := control.NewMemoryBackend()
	ovnRecorder := ovn.NewRecorderExecutor()
	ovnBackend := ovn.NewBackend(ovnRecorder)
	controller := control.NewController(control.MultiTopologyBackend{memoryBackend, ovnBackend}, memoryBackend)
	if err := controller.Reconcile(ctx, initial); err != nil {
		t.Fatal(err)
	}
	if err := controller.Reconcile(ctx, updated); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(ovnRecorder.Operations())
	if !strings.Contains(joined, "set logical_switch_port nl_ls_file_fileapps_to_fileapps_localnet tag=100") {
		t.Fatalf("initial provider vlan programming missing tag set:\n%s", joined)
	}
	if !strings.Contains(joined, "remove logical_switch_port nl_ls_file_fileapps_to_fileapps_localnet tag") {
		t.Fatalf("updated provider network should clear stale localnet tag:\n%s", joined)
	}
}

func TestDesiredStateProgramsDistributedGatewayWithoutChassisPin(t *testing.T) {
	ctx := context.Background()
	state, err := control.LoadDesiredStateJSON(strings.NewReader(`{
  "vpcs": [{"name": "prod"}],
  "subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1"}],
  "gateways": [{"name": "gw-dist", "vpc": "prod", "node": "node-a", "external_if": "eth0", "lan_ip": "10.10.0.254", "distributed": true}]
}`))
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

	gateway, ok := memoryBackend.Gateways["prod\x00gw-dist"]
	if !ok {
		t.Fatalf("distributed gateway was not reconciled: %+v", memoryBackend.Gateways)
	}
	if !gateway.Distributed || gateway.Node != "node-a" || gateway.ExternalIF != "eth0" || gateway.LANIP != netip.MustParseAddr("10.10.0.254") {
		t.Fatalf("distributed gateway state = %+v, want distributed node-a eth0 10.10.0.254", gateway)
	}

	ovnOps := stringifyOVNOps(ovnRecorder.Operations())
	for _, expected := range []string{
		"external_ids:netloom_gateway=gw-dist",
		"external_ids:netloom_external_if=eth0",
		"external_ids:netloom_gateway_lan_ip=10.10.0.254",
		"external_ids:netloom_gateway_distributed=true",
		"remove logical_router nl_lr_prod options chassis",
	} {
		if !strings.Contains(ovnOps, expected) {
			t.Fatalf("distributed gateway operations missing %q:\n%s", expected, ovnOps)
		}
	}
	if strings.Contains(ovnOps, "options:chassis=node-a") {
		t.Fatalf("distributed gateway must not pin chassis:\n%s", ovnOps)
	}
}

func TestDesiredStateRemoteEntityNoneProducesNoAgentEntries(t *testing.T) {
	ctx := context.Background()
	state, err := control.LoadDesiredStateJSON(strings.NewReader(`{
  "vpcs": [{"name": "prod"}],
  "subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1"}],
  "endpoints": [{"id": "pod-a", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.10", "node": "node-a", "security_groups": ["client"]}],
  "security_groups": [{
    "name": "client",
    "vpc": "prod",
    "rules": [{
      "id": "allow-none",
      "priority": 100,
      "direction": "egress",
      "protocol": "tcp",
      "remote_entities": ["none"],
      "ports": [{"from": 443, "to": 443}],
      "action": "allow"
    }]
  }]
}`))
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

	program, ok := memoryBackend.PolicyProgram[model.EndpointKey("prod", "pod-a")]
	if !ok {
		t.Fatalf("expected policy program for pod-a, got %+v", memoryBackend.PolicyProgram)
	}
	if len(program.Rules) != 0 || len(program.MapEntries) != 0 {
		t.Fatalf("remote entity none should not produce compiled rules, got rules=%d entries=%d", len(program.Rules), len(program.MapEntries))
	}

	store := dataplane.NewInMemoryPolicyStore()
	result, err := agent.ReconcileNode(ctx, state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Endpoints != 1 || result.Programs != 1 || result.Entries != 0 || result.TCXEligible != 0 {
		t.Fatalf("expected none entity to stay out of dataplane programming, got %+v", result)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("entries = %d, want 0", len(entries))
	}
	if joined := stringifyOVNOps(ovnRecorder.Operations()); strings.Contains(joined, "acl") {
		t.Fatalf("ovn planner must not grow ACL state for ebpf-only none entity rules:\n%s", joined)
	}
}

func TestDesiredStateLoggedPoliciesEmitRecorderEvents(t *testing.T) {
	ctx := context.Background()
	state, err := control.LoadDesiredStateJSON(strings.NewReader(`{
  "vpcs": [{"name": "prod"}],
  "subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1"}],
  "endpoints": [{"id": "pod-a", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.10", "node": "node-a", "security_groups": ["client"]}],
  "security_groups": [{
    "name": "client",
    "vpc": "prod",
    "rules": [
      {
        "id": "allow-logged",
        "priority": 100,
        "direction": "egress",
        "protocol": "tcp",
        "remote_cidr": "198.51.100.10/32",
        "ports": [{"from": 443, "to": 443}],
        "action": "allow",
        "log": true
      },
      {
        "id": "drop-logged",
        "priority": 90,
        "direction": "egress",
        "protocol": "tcp",
        "remote_cidr": "198.51.100.20/32",
        "ports": [{"from": 8443, "to": 8443}],
        "action": "drop",
        "log": true
      }
    ]
  }]
}`))
	if err != nil {
		t.Fatal(err)
	}

	memoryBackend := control.NewMemoryBackend()
	controller := control.NewController(memoryBackend, memoryBackend)
	if err := controller.Reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}

	program, ok := memoryBackend.PolicyProgram[model.EndpointKey("prod", "pod-a")]
	if !ok {
		t.Fatalf("expected policy program for pod-a, got %+v", memoryBackend.PolicyProgram)
	}
	entries, err := dataplane.EncodeProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("encoded entries = %d, want 2 logged rules", len(entries))
	}

	recorder := dataplane.NewPolicyRecorder()
	endpointID := model.EndpointKey("prod", "pod-a")
	allow := dataplane.EvaluateObserved(endpointID, entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "198.51.100.10"),
		DestPort:  443,
	}, recorder)
	drop := dataplane.EvaluateObserved(endpointID, entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "198.51.100.20"),
		DestPort:  8443,
	}, recorder)
	noMatch := dataplane.EvaluateObserved(endpointID, entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  mustAddr(t, "198.51.100.30"),
		DestPort:  443,
	}, recorder)
	if allow.Verdict != dataplane.VerdictAllow || drop.Verdict != dataplane.VerdictDrop || noMatch.Verdict != dataplane.VerdictDrop {
		t.Fatalf("unexpected verdicts allow=%+v drop=%+v noMatch=%+v", allow, drop, noMatch)
	}

	metrics := recorder.Metrics(endpointID)
	if metrics.Allowed != 1 || metrics.Dropped != 2 || metrics.DenyDrops != 1 || metrics.NoMatchDrops != 1 || metrics.Logged != 2 {
		t.Fatalf("unexpected logged policy metrics: %+v", metrics)
	}
	events := recorder.PolicyEvents()
	if len(events) != 2 {
		t.Fatalf("policy events = %d, want 2 logged events", len(events))
	}
	if events[0].Verdict != dataplane.VerdictAllow || events[0].DestPort != 443 || events[0].RemoteIP != mustAddr(t, "198.51.100.10") {
		t.Fatalf("first logged policy event = %+v, want logged allow", events[0])
	}
	if events[1].Verdict != dataplane.VerdictDrop || events[1].DestPort != 8443 || events[1].RemoteIP != mustAddr(t, "198.51.100.20") {
		t.Fatalf("second logged policy event = %+v, want logged drop", events[1])
	}
}

func TestDesiredStateLoadBalancerSelectionFieldsDriveStableBackendChoice(t *testing.T) {
	ctx := context.Background()
	state, err := control.LoadDesiredStateJSON(strings.NewReader(`{
  "vpcs": [{"name": "affinity"}],
  "subnets": [
    {"name": "apps-v4", "vpc": "affinity", "cidr": "10.247.0.0/24", "gateway": "10.247.0.1"},
    {"name": "apps-v6", "vpc": "affinity", "cidr": "fd00:47::/64", "gateway": "fd00:47::1"}
  ],
  "endpoints": [
    {"id": "client-v4", "vpc": "affinity", "subnet": "apps-v4", "ip": "10.247.0.50", "node": "node-a"},
    {"id": "client-v6", "vpc": "affinity", "subnet": "apps-v6", "ip": "fd00:47::50", "node": "node-a"}
  ],
  "load_balancers": [
    {"name": "web-v4", "vpc": "affinity", "vip": "10.96.0.60", "session_affinity": true, "affinity_timeout": 7200, "selection_fields": ["tp_src", "ip_src"], "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.247.0.10", "port": 8080}, {"ip": "10.247.0.11", "port": 8080}]}], "subnets": ["apps-v4"]},
    {"name": "web-v6", "vpc": "affinity", "vip": "fd00:96::60", "session_affinity": true, "selection_fields": ["ipv6_src"], "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "fd00:47::10", "port": 8080}, {"ip": "fd00:47::11", "port": 8080}]}], "subnets": ["apps-v6"]}
  ]
}`))
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

	firstV4, err := topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
		VPC:        "affinity",
		Source:     mustAddr(t, "10.247.0.50"),
		SourcePort: 31000,
		Dest:       mustAddr(t, "10.96.0.60"),
		Protocol:   model.ProtocolTCP,
		DestPort:   80,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondV4, err := topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
		VPC:        "affinity",
		Source:     mustAddr(t, "10.247.0.50"),
		SourcePort: 31000,
		Dest:       mustAddr(t, "10.96.0.60"),
		Protocol:   model.ProtocolTCP,
		DestPort:   80,
	})
	if err != nil {
		t.Fatal(err)
	}
	if firstV4.MatchedBy != "load-balancer/web-v4" || secondV4.Translated != firstV4.Translated || secondV4.TranslatedPort != firstV4.TranslatedPort {
		t.Fatalf("v4 affinity selection should stay stable for identical source tuple: first=%+v second=%+v", firstV4, secondV4)
	}

	seenV4 := map[string]struct{}{}
	for sourcePort := uint16(31000); sourcePort < 31100; sourcePort++ {
		decision, err := topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
			VPC:        "affinity",
			Source:     mustAddr(t, "10.247.0.50"),
			SourcePort: sourcePort,
			Dest:       mustAddr(t, "10.96.0.60"),
			Protocol:   model.ProtocolTCP,
			DestPort:   80,
		})
		if err != nil {
			t.Fatal(err)
		}
		seenV4[decision.Translated.String()] = struct{}{}
	}
	if len(seenV4) < 2 {
		t.Fatalf("tp_src selection should vary IPv4 backend choice across source ports, got backends %v", seenV4)
	}

	firstV6, err := topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
		VPC:        "affinity",
		Source:     mustAddr(t, "fd00:47::50"),
		SourcePort: 32000,
		Dest:       mustAddr(t, "fd00:96::60"),
		Protocol:   model.ProtocolTCP,
		DestPort:   80,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondV6, err := topology.Resolve(memoryBackend.TopologyState(), topology.Packet{
		VPC:        "affinity",
		Source:     mustAddr(t, "fd00:47::50"),
		SourcePort: 32099,
		Dest:       mustAddr(t, "fd00:96::60"),
		Protocol:   model.ProtocolTCP,
		DestPort:   80,
	})
	if err != nil {
		t.Fatal(err)
	}
	if firstV6.MatchedBy != "load-balancer/web-v6" || secondV6.Translated != firstV6.Translated || secondV6.TranslatedPort != firstV6.TranslatedPort {
		t.Fatalf("ipv6_src-only selection should ignore source port changes: first=%+v second=%+v", firstV6, secondV6)
	}

	ovnOps := stringifyOVNOps(ovnRecorder.Operations())
	for _, expected := range []string{
		`selection_fields=["ip_src","tp_src"]`,
		`selection_fields=["ipv6_src"]`,
		"options:affinity_timeout=7200",
		"options:affinity_timeout=10800",
	} {
		if !strings.Contains(ovnOps, expected) {
			t.Fatalf("ovn operations missing %q:\n%s", expected, ovnOps)
		}
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
  "provider_networks": [{"name": "physnet-a", "nodes": [{"node": "node-a", "interface": "eth1"}, {"node": "node-b", "interface": "eth1"}]}],
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
