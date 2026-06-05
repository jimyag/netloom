package control

import (
	"context"
	"net/netip"
	"testing"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
	"github.com/jimyag/netloom/internal/topology"
)

func TestMemoryBackendClonesInputsAndTopologyState(t *testing.T) {
	backend := NewMemoryBackend()
	subnet := model.Subnet{
		Name:         "apps",
		VPC:          "prod",
		CIDR:         netip.MustParsePrefix("10.10.0.0/24"),
		Gateway:      netip.MustParseAddr("10.10.0.1"),
		ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("10.10.0.128/25")},
		DHCP: model.DHCPOptions{
			Enabled:       true,
			DNSServers:    []netip.Addr{netip.MustParseAddr("10.96.0.10")},
			SearchDomains: []string{"svc.cluster.local"},
		},
	}
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"web"},
		NamedPorts:     []model.NamedPort{{Name: "http", Protocol: model.ProtocolTCP, Port: 8080}},
		Labels:         model.Labels{"app": "web"},
	}
	routeTable := model.RouteTable{
		Name: "default",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
		}},
	}
	policyRoute := model.PolicyRoute{
		Name:     "force-private",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("172.16.0.0/16"),
			DstPorts:    []model.PortRange{{From: 443, To: 443}},
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	}
	lb := model.LoadBalancer{
		Name:            "web",
		VPC:             "prod",
		VIP:             netip.MustParseAddr("10.96.0.10"),
		SelectionFields: []string{"ip_src"},
		Ports: []model.LoadBalancerPort{{
			Port:     80,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080}},
		}},
		Subnets: []string{"apps"},
	}

	if err := backend.CleanupTopology(context.Background(), topology.State{
		VPCs:          map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets:       map[string]model.Subnet{subnetKey("prod", "apps"): subnet},
		Endpoints:     map[string]model.Endpoint{"pod-a": endpoint},
		RouteTables:   map[string]model.RouteTable{routeTableKey("prod", "default"): routeTable},
		Gateways:      map[string]model.Gateway{"gw-a": {Name: "gw-a", VPC: "prod", Node: "node-a", ExternalIF: "eth0", LANIP: netip.MustParseAddr("10.10.0.254")}},
		NATRules:      map[string]model.NATRule{natRuleKey("prod", "egress"): {Name: "egress", VPC: "prod", Type: model.ActionSNAT, MatchCIDR: netip.MustParsePrefix("10.10.0.0/24"), ExternalIP: netip.MustParseAddr("198.51.100.10")}},
		LoadBalancers: map[string]model.LoadBalancer{loadBalancerKey("prod", "web"): lb},
	}); err != nil {
		t.Fatal(err)
	}
	if err := backend.EnsurePolicyRoute(context.Background(), policyRoute); err != nil {
		t.Fatal(err)
	}

	subnet.DHCP.DNSServers[0] = netip.MustParseAddr("10.96.0.11")
	endpoint.Labels["app"] = "mutated"
	routeTable.Routes[0].NextHops[0] = netip.MustParseAddr("10.10.0.252")
	policyRoute.Action.NextHops[0] = netip.MustParseAddr("10.10.0.252")
	lb.Ports[0].Backends[0].IP = netip.MustParseAddr("10.10.0.12")

	state := backend.TopologyState()
	if got := state.Subnets[subnetKey("prod", "apps")].DHCP.DNSServers[0]; got != netip.MustParseAddr("10.96.0.10") {
		t.Fatalf("stored subnet dns = %s, want original", got)
	}
	if got := state.Endpoints["pod-a"].Labels["app"]; got != "web" {
		t.Fatalf("stored endpoint label = %s, want original", got)
	}
	if got := state.RouteTables[routeTableKey("prod", "default")].Routes[0].NextHops[0]; got != netip.MustParseAddr("10.10.0.254") {
		t.Fatalf("stored route next hop = %s, want original", got)
	}
	if got := state.PolicyRoutes[0].Action.NextHops[0]; got != netip.MustParseAddr("10.10.0.253") {
		t.Fatalf("stored policy route next hop = %s, want original", got)
	}
	if got := state.LoadBalancers[loadBalancerKey("prod", "web")].Ports[0].Backends[0].IP; got != netip.MustParseAddr("10.10.0.10") {
		t.Fatalf("stored load balancer backend = %s, want original", got)
	}

	state.Subnets[subnetKey("prod", "apps")].DHCP.DNSServers[0] = netip.MustParseAddr("10.96.0.12")
	state.Endpoints["pod-a"].Labels["app"] = "returned"
	state.RouteTables[routeTableKey("prod", "default")].Routes[0].NextHops[0] = netip.MustParseAddr("10.10.0.251")
	state.PolicyRoutes[0].Action.NextHops[0] = netip.MustParseAddr("10.10.0.251")
	state.LoadBalancers[loadBalancerKey("prod", "web")].Ports[0].Backends[0].IP = netip.MustParseAddr("10.10.0.13")

	state = backend.TopologyState()
	if got := state.Subnets[subnetKey("prod", "apps")].DHCP.DNSServers[0]; got != netip.MustParseAddr("10.96.0.10") {
		t.Fatalf("returned subnet mutation leaked into backend: %s", got)
	}
	if got := state.Endpoints["pod-a"].Labels["app"]; got != "web" {
		t.Fatalf("returned endpoint mutation leaked into backend: %s", got)
	}
	if got := state.RouteTables[routeTableKey("prod", "default")].Routes[0].NextHops[0]; got != netip.MustParseAddr("10.10.0.254") {
		t.Fatalf("returned route mutation leaked into backend: %s", got)
	}
	if got := state.PolicyRoutes[0].Action.NextHops[0]; got != netip.MustParseAddr("10.10.0.253") {
		t.Fatalf("returned policy route mutation leaked into backend: %s", got)
	}
	if got := state.LoadBalancers[loadBalancerKey("prod", "web")].Ports[0].Backends[0].IP; got != netip.MustParseAddr("10.10.0.10") {
		t.Fatalf("returned load balancer mutation leaked into backend: %s", got)
	}
}

func TestMemoryBackendClonesPolicyPrograms(t *testing.T) {
	backend := NewMemoryBackend()
	icmpType := uint8(8)
	icmpCode := uint8(0)
	program := policy.Program{
		EndpointID: "pod-a",
		MapEntries: []policy.MapEntry{{
			RuleID:     "allow-web",
			RemoteCIDR: netip.MustParsePrefix("10.10.0.0/24"),
		}},
		Rules: []policy.Rule{{
			ID:         "allow-web",
			Ports:      []model.PortRange{{From: 80, To: 80}},
			NamedPorts: []string{"http"},
			ICMPType:   &icmpType,
			ICMPCode:   &icmpCode,
		}},
	}
	if err := backend.ApplyEndpointProgram(context.Background(), program); err != nil {
		t.Fatal(err)
	}
	program.Rules[0].Ports[0].From = 443
	program.Rules[0].NamedPorts[0] = "https"
	*program.Rules[0].ICMPType = 3
	program.MapEntries[0].RuleID = "mutated"

	stored := backend.PolicyProgram["pod-a"]
	if got := stored.Rules[0].Ports[0].From; got != 80 {
		t.Fatalf("stored policy port = %d, want original", got)
	}
	if got := stored.Rules[0].NamedPorts[0]; got != "http" {
		t.Fatalf("stored named port = %s, want original", got)
	}
	if got := *stored.Rules[0].ICMPType; got != 8 {
		t.Fatalf("stored icmp type = %d, want original", got)
	}
	if got := stored.MapEntries[0].RuleID; got != "allow-web" {
		t.Fatalf("stored map entry rule id = %s, want original", got)
	}
}
