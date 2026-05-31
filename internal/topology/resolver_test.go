package topology

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/jimyag/netloom/internal/model"
)

func testLoadBalancer(name string, vip string, port uint16, backends []model.LoadBalancerBackend) model.LoadBalancer {
	return model.LoadBalancer{
		Name: name,
		VPC:  "prod",
		VIP:  netip.MustParseAddr(vip),
		Ports: []model.LoadBalancerPort{{
			Port:     port,
			Protocol: model.ProtocolTCP,
			Backends: backends,
		}},
	}
}

func TestResolveDirectEndpoint(t *testing.T) {
	state := State{
		Endpoints: map[string]model.Endpoint{
			"pod-b": {ID: "pod-b", VPC: "prod", IP: netip.MustParseAddr("10.10.0.20")},
		},
	}
	decision, err := Resolve(state, Packet{
		VPC:    "prod",
		Source: netip.MustParseAddr("10.10.0.10"),
		Dest:   netip.MustParseAddr("10.10.0.20"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Destination != "pod-b" || decision.Action != model.ActionAllow {
		t.Fatalf("decision = %+v, want direct allow to pod-b", decision)
	}
}

func TestResolveLoadBalancerVIPToBackend(t *testing.T) {
	unhealthy := false
	state := State{
		Endpoints: map[string]model.Endpoint{
			"pod-a": {ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10")},
		},
		LoadBalancers: map[string]model.LoadBalancer{
			"web": func() model.LoadBalancer {
				lb := testLoadBalancer("web", "10.96.0.10", 80, []model.LoadBalancerBackend{
					{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080, Healthy: &unhealthy},
					{IP: netip.MustParseAddr("10.10.0.30"), Port: 8080},
					{IP: netip.MustParseAddr("10.10.0.20"), Port: 8080},
				})
				lb.Subnets = []string{"apps"}
				return lb
			}(),
		},
	}
	decision, err := Resolve(state, Packet{
		VPC:      "prod",
		Source:   netip.MustParseAddr("10.10.0.10"),
		Dest:     netip.MustParseAddr("10.96.0.10"),
		Protocol: model.ProtocolTCP,
		DestPort: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != model.ActionAllow || decision.MatchedBy != "load-balancer/web" {
		t.Fatalf("decision = %+v, want load balancer allow", decision)
	}
	if decision.Translated != netip.MustParseAddr("10.10.0.20") || decision.TranslatedPort != 8080 {
		t.Fatalf("backend = %s:%d, want 10.10.0.20:8080", decision.Translated, decision.TranslatedPort)
	}
}

func TestResolveLoadBalancerMultiPortVIPToBackend(t *testing.T) {
	state := State{
		LoadBalancers: map[string]model.LoadBalancer{
			"web": {
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Ports: []model.LoadBalancerPort{
					{
						Name:     "http",
						Port:     80,
						Protocol: model.ProtocolTCP,
						Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.20"), Port: 8080}},
					},
					{
						Name:     "metrics",
						Port:     9090,
						Protocol: model.ProtocolTCP,
						Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.20"), Port: 9091}},
					},
				},
			},
		},
	}
	decision, err := Resolve(state, Packet{
		VPC:      "prod",
		Source:   netip.MustParseAddr("10.10.1.10"),
		Dest:     netip.MustParseAddr("10.96.0.10"),
		Protocol: model.ProtocolTCP,
		DestPort: 9090,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.MatchedBy != "load-balancer/web" || decision.Translated != netip.MustParseAddr("10.10.0.20") || decision.TranslatedPort != 9091 {
		t.Fatalf("decision = %+v, want metrics frontend target 9091", decision)
	}
}

func TestResolveLoadBalancerSkipsUnhealthyBackends(t *testing.T) {
	healthy := true
	unhealthy := false
	state := State{
		LoadBalancers: map[string]model.LoadBalancer{
			"web": testLoadBalancer("web", "10.96.0.10", 80, []model.LoadBalancerBackend{
				{IP: netip.MustParseAddr("10.10.0.20"), Port: 8080, Healthy: &unhealthy},
				{IP: netip.MustParseAddr("10.10.0.30"), Port: 8080, Healthy: &healthy},
			}),
		},
	}
	packet := Packet{
		VPC:      "prod",
		Source:   netip.MustParseAddr("10.10.1.10"),
		Dest:     netip.MustParseAddr("10.96.0.10"),
		Protocol: model.ProtocolTCP,
		DestPort: 80,
	}
	decision, err := Resolve(state, packet)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Translated != netip.MustParseAddr("10.10.0.30") || decision.TranslatedPort != 8080 {
		t.Fatalf("backend = %s:%d, want only healthy backend", decision.Translated, decision.TranslatedPort)
	}

	state.LoadBalancers["web"] = testLoadBalancer("web", "10.96.0.10", 80, []model.LoadBalancerBackend{
		{IP: netip.MustParseAddr("10.10.0.20"), Port: 8080, Healthy: &unhealthy},
	})
	decision, err = Resolve(state, packet)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != model.ActionDrop || decision.MatchedBy != "no-route" {
		t.Fatalf("decision = %+v, want drop when all backends are unhealthy", decision)
	}
}

func TestResolveLoadBalancerBackendSelectionIsStablePerFlow(t *testing.T) {
	state := State{
		LoadBalancers: map[string]model.LoadBalancer{
			"web": testLoadBalancer("web", "10.96.0.10", 80, []model.LoadBalancerBackend{
				{IP: netip.MustParseAddr("10.10.0.20"), Port: 8080},
				{IP: netip.MustParseAddr("10.10.0.30"), Port: 8080},
				{IP: netip.MustParseAddr("10.10.0.40"), Port: 8080},
			}),
		},
	}

	packet := Packet{
		VPC:      "prod",
		Source:   netip.MustParseAddr("10.10.1.10"),
		Dest:     netip.MustParseAddr("10.96.0.10"),
		Protocol: model.ProtocolTCP,
		DestPort: 80,
	}
	first, err := Resolve(state, packet)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		decision, err := Resolve(state, packet)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Translated != first.Translated || decision.TranslatedPort != first.TranslatedPort {
			t.Fatalf("backend changed from %s:%d to %s:%d for same flow", first.Translated, first.TranslatedPort, decision.Translated, decision.TranslatedPort)
		}
	}

	seen := map[netip.Addr]bool{}
	for i := 1; i <= 32; i++ {
		packet.Source = netip.MustParseAddr(fmt.Sprintf("10.10.1.%d", i))
		decision, err := Resolve(state, packet)
		if err != nil {
			t.Fatal(err)
		}
		seen[decision.Translated] = true
	}
	if len(seen) < 2 {
		t.Fatalf("selected %d backend(s), want different flows to spread across backends", len(seen))
	}
}

func TestResolveLoadBalancerSessionAffinityIgnoresSourcePort(t *testing.T) {
	lb := model.LoadBalancer{
		Name:            "web",
		VPC:             "prod",
		VIP:             netip.MustParseAddr("10.96.0.10"),
		SessionAffinity: true,
		Ports: []model.LoadBalancerPort{{
			Port:     80,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{
				{IP: netip.MustParseAddr("10.10.0.20"), Port: 8080},
				{IP: netip.MustParseAddr("10.10.0.30"), Port: 8080},
				{IP: netip.MustParseAddr("10.10.0.40"), Port: 8080},
			},
		}},
	}
	affinityState := State{LoadBalancers: map[string]model.LoadBalancer{"web": lb}}
	packet := Packet{
		VPC:        "prod",
		Source:     netip.MustParseAddr("10.10.1.10"),
		SourcePort: 30000,
		Dest:       netip.MustParseAddr("10.96.0.10"),
		Protocol:   model.ProtocolTCP,
		DestPort:   80,
	}
	first, err := Resolve(affinityState, packet)
	if err != nil {
		t.Fatal(err)
	}
	for _, sourcePort := range []uint16{30001, 30002, 40000, 50000} {
		packet.SourcePort = sourcePort
		decision, err := Resolve(affinityState, packet)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Translated != first.Translated || decision.TranslatedPort != first.TranslatedPort {
			t.Fatalf("affinity backend changed from %s:%d to %s:%d", first.Translated, first.TranslatedPort, decision.Translated, decision.TranslatedPort)
		}
	}

	lb.SessionAffinity = false
	flowState := State{LoadBalancers: map[string]model.LoadBalancer{"web": lb}}
	seen := map[netip.Addr]bool{}
	for sourcePort := uint16(30000); sourcePort < 30100; sourcePort++ {
		packet.SourcePort = sourcePort
		decision, err := Resolve(flowState, packet)
		if err != nil {
			t.Fatal(err)
		}
		seen[decision.Translated] = true
	}
	if len(seen) < 2 {
		t.Fatalf("non-affinity load balancer selected %d backend(s), want source port to affect flow selection", len(seen))
	}
}

func TestResolveLoadBalancerSelectionFieldsDriveBackendChoice(t *testing.T) {
	lb := model.LoadBalancer{
		Name:            "web",
		VPC:             "prod",
		VIP:             netip.MustParseAddr("10.96.0.10"),
		SelectionFields: []string{"ip_src"},
		Ports: []model.LoadBalancerPort{{
			Port:     80,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{
				{IP: netip.MustParseAddr("10.10.0.20"), Port: 8080},
				{IP: netip.MustParseAddr("10.10.0.30"), Port: 8080},
				{IP: netip.MustParseAddr("10.10.0.40"), Port: 8080},
			},
		}},
	}
	state := State{LoadBalancers: map[string]model.LoadBalancer{"web": lb}}
	packet := Packet{
		VPC:        "prod",
		Source:     netip.MustParseAddr("10.10.1.10"),
		SourcePort: 30000,
		Dest:       netip.MustParseAddr("10.96.0.10"),
		Protocol:   model.ProtocolTCP,
		DestPort:   80,
	}
	first, err := Resolve(state, packet)
	if err != nil {
		t.Fatal(err)
	}
	for _, sourcePort := range []uint16{30001, 30002, 40000, 50000} {
		packet.SourcePort = sourcePort
		decision, err := Resolve(state, packet)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Translated != first.Translated || decision.TranslatedPort != first.TranslatedPort {
			t.Fatalf("ip_src selection changed backend from %s:%d to %s:%d", first.Translated, first.TranslatedPort, decision.Translated, decision.TranslatedPort)
		}
	}

	lb.SelectionFields = []string{"ip_src", "tp_src"}
	state.LoadBalancers["web"] = lb
	seen := map[netip.Addr]bool{}
	for sourcePort := uint16(30000); sourcePort < 30100; sourcePort++ {
		packet.SourcePort = sourcePort
		decision, err := Resolve(state, packet)
		if err != nil {
			t.Fatal(err)
		}
		seen[decision.Translated] = true
	}
	if len(seen) < 2 {
		t.Fatalf("ip_src+tp_src selection selected %d backend(s), want source port to affect selection", len(seen))
	}
}

func TestResolveLoadBalancerRequiresBoundSourceSubnet(t *testing.T) {
	state := State{
		Endpoints: map[string]model.Endpoint{
			"pod-a": {ID: "pod-a", VPC: "prod", Subnet: "clients", IP: netip.MustParseAddr("10.10.1.10")},
		},
		LoadBalancers: map[string]model.LoadBalancer{
			"web": func() model.LoadBalancer {
				lb := testLoadBalancer("web", "10.96.0.10", 80, []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.20"), Port: 8080}})
				lb.Subnets = []string{"apps"}
				return lb
			}(),
		},
	}
	decision, err := Resolve(state, Packet{
		VPC:      "prod",
		Source:   netip.MustParseAddr("10.10.1.10"),
		Dest:     netip.MustParseAddr("10.96.0.10"),
		Protocol: model.ProtocolTCP,
		DestPort: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != model.ActionDrop || decision.MatchedBy != "no-route" {
		t.Fatalf("decision = %+v, want no-route drop", decision)
	}
}

func TestResolveDNATToEndpoint(t *testing.T) {
	state := State{
		Endpoints: map[string]model.Endpoint{
			"pod-a": {ID: "pod-a", VPC: "prod", IP: netip.MustParseAddr("10.10.0.10")},
		},
		NATRules: map[string]model.NATRule{
			"web": {
				Name:       "web",
				VPC:        "prod",
				Type:       model.ActionDNAT,
				ExternalIP: netip.MustParseAddr("198.51.100.20"),
				TargetIP:   netip.MustParseAddr("10.10.0.10"),
			},
		},
	}
	decision, err := Resolve(state, Packet{
		VPC:    "prod",
		Source: netip.MustParseAddr("203.0.113.10"),
		Dest:   netip.MustParseAddr("198.51.100.20"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.MatchedBy != "nat/web" || decision.Destination != "pod-a" || decision.Translated != netip.MustParseAddr("10.10.0.10") {
		t.Fatalf("decision = %+v, want DNAT to pod-a", decision)
	}
}

func TestResolvePortDNATRequiresProtocolAndPort(t *testing.T) {
	state := State{
		NATRules: map[string]model.NATRule{
			"ssh": {
				Name:         "ssh",
				VPC:          "prod",
				Type:         model.ActionDNAT,
				ExternalIP:   netip.MustParseAddr("198.51.100.23"),
				TargetIP:     netip.MustParseAddr("10.10.0.10"),
				Protocol:     model.ProtocolTCP,
				ExternalPort: 2222,
				TargetPort:   2222,
			},
		},
	}
	decision, err := Resolve(state, Packet{
		VPC:      "prod",
		Source:   netip.MustParseAddr("203.0.113.10"),
		Dest:     netip.MustParseAddr("198.51.100.23"),
		Protocol: model.ProtocolTCP,
		DestPort: 2222,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.MatchedBy != "nat/ssh" || decision.Translated != netip.MustParseAddr("10.10.0.10") || decision.TranslatedPort != 2222 {
		t.Fatalf("decision = %+v, want port DNAT", decision)
	}

	dropped, err := Resolve(state, Packet{
		VPC:      "prod",
		Source:   netip.MustParseAddr("203.0.113.10"),
		Dest:     netip.MustParseAddr("198.51.100.23"),
		Protocol: model.ProtocolUDP,
		DestPort: 2222,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dropped.Action != model.ActionDrop || dropped.MatchedBy != "no-route" {
		t.Fatalf("decision = %+v, want no-route drop", dropped)
	}
}

func TestResolvePortDNATTranslatesTargetPort(t *testing.T) {
	state := State{
		Endpoints: map[string]model.Endpoint{
			"web": {
				ID:     "web",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.20"),
				Node:   "node-a",
			},
		},
		NATRules: map[string]model.NATRule{
			"web-https": {
				Name:         "web-https",
				VPC:          "prod",
				Type:         model.ActionDNAT,
				ExternalIP:   netip.MustParseAddr("198.51.100.80"),
				TargetIP:     netip.MustParseAddr("10.10.0.20"),
				Protocol:     model.ProtocolTCP,
				ExternalPort: 8443,
				TargetPort:   443,
			},
		},
	}
	decision, err := Resolve(state, Packet{
		VPC:      "prod",
		Source:   netip.MustParseAddr("203.0.113.10"),
		Dest:     netip.MustParseAddr("198.51.100.80"),
		Protocol: model.ProtocolTCP,
		DestPort: 8443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.MatchedBy != "nat/web-https" || decision.Destination != "web" || decision.Translated != netip.MustParseAddr("10.10.0.20") || decision.TranslatedPort != 443 {
		t.Fatalf("decision = %+v, want DNAT target port translation", decision)
	}
}

func TestResolveFloatingIPToEndpoint(t *testing.T) {
	state := State{
		Endpoints: map[string]model.Endpoint{
			"pod-a": {ID: "pod-a", VPC: "prod", IP: netip.MustParseAddr("10.10.0.10")},
		},
		NATRules: map[string]model.NATRule{
			"fip": {
				Name:       "fip",
				VPC:        "prod",
				Type:       model.ActionDNATSNAT,
				ExternalIP: netip.MustParseAddr("198.51.100.30"),
				TargetIP:   netip.MustParseAddr("10.10.0.10"),
			},
		},
	}
	decision, err := Resolve(state, Packet{
		VPC:    "prod",
		Source: netip.MustParseAddr("203.0.113.10"),
		Dest:   netip.MustParseAddr("198.51.100.30"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.MatchedBy != "nat/fip" || decision.Destination != "pod-a" || decision.Translated != netip.MustParseAddr("10.10.0.10") {
		t.Fatalf("decision = %+v, want floating IP to pod-a", decision)
	}
}

func TestResolveFloatingIPPortTranslation(t *testing.T) {
	state := State{
		Endpoints: map[string]model.Endpoint{
			"pod-a": {ID: "pod-a", VPC: "prod", IP: netip.MustParseAddr("10.10.0.10")},
		},
		NATRules: map[string]model.NATRule{
			"fip-https": {
				Name:         "fip-https",
				VPC:          "prod",
				Type:         model.ActionDNATSNAT,
				ExternalIP:   netip.MustParseAddr("198.51.100.30"),
				TargetIP:     netip.MustParseAddr("10.10.0.10"),
				Protocol:     model.ProtocolTCP,
				ExternalPort: 8443,
				TargetPort:   443,
			},
		},
	}
	decision, err := Resolve(state, Packet{
		VPC:      "prod",
		Source:   netip.MustParseAddr("203.0.113.10"),
		Dest:     netip.MustParseAddr("198.51.100.30"),
		Protocol: model.ProtocolTCP,
		DestPort: 8443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.MatchedBy != "nat/fip-https" || decision.Destination != "pod-a" || decision.Translated != netip.MustParseAddr("10.10.0.10") || decision.TranslatedPort != 443 {
		t.Fatalf("decision = %+v, want floating IP target port translation", decision)
	}
}

func TestResolvePolicyRouteBeatsStaticRoute(t *testing.T) {
	state := State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("172.16.0.0/16"),
					NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
				}},
			},
		},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "private-via-fw",
			VPC:      "prod",
			Priority: 100,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("172.16.0.0/16"),
				Protocol:    model.ProtocolTCP,
				DstPorts:    []model.PortRange{{From: 443, To: 443}},
			},
			Action: model.RouteAction{
				Type:     model.ActionReroute,
				NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")},
			},
		}},
	}
	decision, err := Resolve(state, Packet{
		VPC:      "prod",
		Source:   netip.MustParseAddr("10.10.0.10"),
		Dest:     netip.MustParseAddr("172.16.1.10"),
		Protocol: model.ProtocolTCP,
		DestPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.NextHop != netip.MustParseAddr("10.10.0.253") {
		t.Fatalf("next hop = %s, want policy route next hop", decision.NextHop)
	}
	if decision.MatchedBy != "policy-route/private-via-fw" {
		t.Fatalf("matched by = %s, want policy route", decision.MatchedBy)
	}
}

func TestResolveAllowPolicyRouteBeatsLowerPriorityDrop(t *testing.T) {
	state := State{
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "allow-api",
			VPC:      "prod",
			Priority: 300,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("198.51.100.10/32"),
				Protocol:    model.ProtocolTCP,
				DstPorts:    []model.PortRange{{From: 443, To: 443}},
			},
			Action: model.RouteAction{Type: model.ActionAllow},
		}, {
			Name:     "drop-lab",
			VPC:      "prod",
			Priority: 100,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("198.51.100.0/24"),
			},
			Action: model.RouteAction{Type: model.ActionDrop},
		}},
	}
	decision, err := Resolve(state, Packet{
		VPC:      "prod",
		Source:   netip.MustParseAddr("10.10.0.10"),
		Dest:     netip.MustParseAddr("198.51.100.10"),
		Protocol: model.ProtocolTCP,
		DestPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != model.ActionAllow || decision.MatchedBy != "policy-route/allow-api" {
		t.Fatalf("decision = %+v, want allow-api allow", decision)
	}

	decision, err = Resolve(state, Packet{
		VPC:    "prod",
		Source: netip.MustParseAddr("10.10.0.10"),
		Dest:   netip.MustParseAddr("198.51.100.20"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != model.ActionDrop || decision.MatchedBy != "policy-route/drop-lab" {
		t.Fatalf("decision = %+v, want lower priority drop", decision)
	}
}

func TestResolvePolicyRouteMatchesSourceAndDestinationPorts(t *testing.T) {
	state := State{
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "tenant-api",
			VPC:      "prod",
			Priority: 200,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("198.51.100.0/24"),
				Protocol:    model.ProtocolTCP,
				SrcPorts:    []model.PortRange{{From: 32000, To: 32010}},
				DstPorts:    []model.PortRange{{From: 443, To: 443}},
			},
			Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
		}, {
			Name:     "fallback",
			VPC:      "prod",
			Priority: 100,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("198.51.100.0/24"),
			},
			Action: model.RouteAction{Type: model.ActionDrop},
		}},
	}
	decision, err := Resolve(state, Packet{
		VPC:        "prod",
		Source:     netip.MustParseAddr("10.10.0.10"),
		SourcePort: 32001,
		Dest:       netip.MustParseAddr("198.51.100.10"),
		Protocol:   model.ProtocolTCP,
		DestPort:   443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.MatchedBy != "policy-route/tenant-api" || decision.NextHop != netip.MustParseAddr("10.10.0.253") {
		t.Fatalf("decision = %+v, want source-port policy route", decision)
	}

	decision, err = Resolve(state, Packet{
		VPC:        "prod",
		Source:     netip.MustParseAddr("10.10.0.10"),
		SourcePort: 31000,
		Dest:       netip.MustParseAddr("198.51.100.10"),
		Protocol:   model.ProtocolTCP,
		DestPort:   443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.MatchedBy != "policy-route/fallback" || decision.Action != model.ActionDrop {
		t.Fatalf("decision = %+v, want source-port mismatch to fall back", decision)
	}
}

func TestResolveAllowPolicyRouteContinuesToStaticRoute(t *testing.T) {
	state := State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("198.51.100.0/24"),
					NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
				}},
			},
		},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "allow-api",
			VPC:      "prod",
			Priority: 300,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("198.51.100.10/32"),
				Protocol:    model.ProtocolTCP,
				DstPorts:    []model.PortRange{{From: 443, To: 443}},
			},
			Action: model.RouteAction{Type: model.ActionAllow},
		}, {
			Name:     "drop-lab",
			VPC:      "prod",
			Priority: 100,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("198.51.100.0/24"),
			},
			Action: model.RouteAction{Type: model.ActionDrop},
		}},
		Gateways: map[string]model.Gateway{
			"gw-a": {Name: "gw-a", VPC: "prod", Node: "node-a", ExternalIF: "eth0", LANIP: netip.MustParseAddr("10.10.0.254")},
		},
		NATRules: map[string]model.NATRule{
			"snat": {
				Name:       "snat",
				VPC:        "prod",
				Type:       model.ActionSNAT,
				MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
				ExternalIP: netip.MustParseAddr("203.0.113.10"),
			},
		},
	}
	decision, err := Resolve(state, Packet{
		VPC:      "prod",
		Source:   netip.MustParseAddr("10.10.0.10"),
		Dest:     netip.MustParseAddr("198.51.100.10"),
		Protocol: model.ProtocolTCP,
		DestPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != model.ActionReroute || decision.MatchedBy != "policy-route/allow-api" {
		t.Fatalf("decision = %+v, want allow policy to continue into static route", decision)
	}
	if decision.NextHop != netip.MustParseAddr("10.10.0.254") || decision.Gateway != "gw-a" {
		t.Fatalf("route = next-hop %s gateway %s, want static route via gw-a", decision.NextHop, decision.Gateway)
	}
	if decision.Translated != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("translated = %s, want SNAT after allowed static route", decision.Translated)
	}
}

func TestResolvePolicyRouteSNATUsesNextHopGateway(t *testing.T) {
	state := State{
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "private-via-fw",
			VPC:      "prod",
			Priority: 100,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("172.16.0.0/16"),
			},
			Action: model.RouteAction{
				Type:     model.ActionReroute,
				NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")},
			},
		}},
		Gateways: map[string]model.Gateway{
			"gw-a": {Name: "gw-a", VPC: "prod", Node: "node-a", ExternalIF: "eth0", LANIP: netip.MustParseAddr("10.10.0.254")},
			"gw-b": {Name: "gw-b", VPC: "prod", Node: "node-b", ExternalIF: "eth0", LANIP: netip.MustParseAddr("10.10.0.253")},
		},
		NATRules: map[string]model.NATRule{
			"egress": {
				Name:       "egress",
				VPC:        "prod",
				Type:       model.ActionSNAT,
				MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
				ExternalIP: netip.MustParseAddr("198.51.100.10"),
			},
		},
	}
	for i := 0; i < 20; i++ {
		decision, err := Resolve(state, Packet{
			VPC:    "prod",
			Source: netip.MustParseAddr("10.10.0.10"),
			Dest:   netip.MustParseAddr("172.16.1.10"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Gateway != "gw-b" {
			t.Fatalf("gateway = %s, want next-hop gateway gw-b", decision.Gateway)
		}
		if decision.Translated != netip.MustParseAddr("198.51.100.10") {
			t.Fatalf("translated = %s, want SNAT external ip", decision.Translated)
		}
	}
}

func TestResolveECMPPolicyRouteReturnsNextHops(t *testing.T) {
	nextHops := []netip.Addr{
		netip.MustParseAddr("10.10.0.253"),
		netip.MustParseAddr("10.10.0.254"),
	}
	state := State{
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "centralized-egress",
			VPC:      "prod",
			Priority: 100,
			Match: model.RouteMatch{
				Source: netip.MustParsePrefix("10.10.0.0/24"),
			},
			Action: model.RouteAction{
				Type:     model.ActionReroute,
				NextHops: nextHops,
			},
		}},
	}
	decision, err := Resolve(state, Packet{
		VPC:    "prod",
		Source: netip.MustParseAddr("10.10.0.10"),
		Dest:   netip.MustParseAddr("203.0.113.10"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !containsAddr(nextHops, decision.NextHop) {
		t.Fatalf("next hop = %s, want one of ECMP next hops %v", decision.NextHop, nextHops)
	}
	if len(decision.NextHops) != 2 || decision.NextHops[1] != netip.MustParseAddr("10.10.0.254") {
		t.Fatalf("next hops = %v, want ECMP next hops", decision.NextHops)
	}
}

func TestResolveECMPPolicyRouteSelectsStableNextHopPerFlow(t *testing.T) {
	nextHops := []netip.Addr{
		netip.MustParseAddr("10.10.0.253"),
		netip.MustParseAddr("10.10.0.254"),
	}
	state := State{
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "centralized-egress",
			VPC:      "prod",
			Priority: 100,
			Match: model.RouteMatch{
				Source: netip.MustParsePrefix("10.10.0.0/24"),
			},
			Action: model.RouteAction{Type: model.ActionReroute, NextHops: nextHops},
		}},
	}
	packet := Packet{
		VPC:        "prod",
		Source:     netip.MustParseAddr("10.10.0.10"),
		SourcePort: 40000,
		Dest:       netip.MustParseAddr("203.0.113.10"),
		Protocol:   model.ProtocolTCP,
		DestPort:   443,
	}
	first, err := Resolve(state, packet)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		decision, err := Resolve(state, packet)
		if err != nil {
			t.Fatal(err)
		}
		if decision.NextHop != first.NextHop {
			t.Fatalf("next hop changed for same flow: first=%s now=%s", first.NextHop, decision.NextHop)
		}
	}

	selected := make(map[netip.Addr]struct{})
	for sourcePort := uint16(40000); sourcePort < 40100; sourcePort++ {
		packet.SourcePort = sourcePort
		decision, err := Resolve(state, packet)
		if err != nil {
			t.Fatal(err)
		}
		selected[decision.NextHop] = struct{}{}
	}
	if len(selected) < 2 {
		t.Fatalf("ECMP selection used %d next hop(s), want flow hash to spread across %v", len(selected), nextHops)
	}
}

func TestResolveECMPStaticRouteSelectsStableNextHopPerFlow(t *testing.T) {
	nextHops := []netip.Addr{
		netip.MustParseAddr("10.10.0.253"),
		netip.MustParseAddr("10.10.0.254"),
	}
	state := State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("203.0.113.0/24"),
					NextHops:    nextHops,
				}},
			},
		},
	}
	packet := Packet{
		VPC:        "prod",
		Source:     netip.MustParseAddr("10.10.0.10"),
		SourcePort: 50000,
		Dest:       netip.MustParseAddr("203.0.113.10"),
		Protocol:   model.ProtocolTCP,
		DestPort:   443,
	}
	first, err := Resolve(state, packet)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		decision, err := Resolve(state, packet)
		if err != nil {
			t.Fatal(err)
		}
		if decision.NextHop != first.NextHop {
			t.Fatalf("static route next hop changed for same flow: first=%s now=%s", first.NextHop, decision.NextHop)
		}
	}
	if !containsAddr(nextHops, first.NextHop) || len(first.NextHops) != 2 {
		t.Fatalf("decision = %+v, want selected member and all ECMP next hops", first)
	}
}

func containsAddr(values []netip.Addr, target netip.Addr) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestResolveECMPStaticRouteReturnsNextHops(t *testing.T) {
	state := State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("0.0.0.0/0"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("10.10.0.253"),
						netip.MustParseAddr("10.10.0.254"),
					},
				}},
			},
		},
	}
	decision, err := Resolve(state, Packet{
		VPC:    "prod",
		Source: netip.MustParseAddr("10.10.0.10"),
		Dest:   netip.MustParseAddr("203.0.113.10"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.MatchedBy != "route-table/main" || decision.NextHop != netip.MustParseAddr("10.10.0.253") {
		t.Fatalf("unexpected static ECMP decision: %+v", decision)
	}
	if len(decision.NextHops) != 2 || decision.NextHops[1] != netip.MustParseAddr("10.10.0.254") {
		t.Fatalf("next hops = %v, want static ECMP next hops", decision.NextHops)
	}
}

func TestResolveLongestPrefixStaticRouteAndSNATGateway(t *testing.T) {
	state := State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{
					{Destination: netip.MustParsePrefix("0.0.0.0/0"), NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.254")}},
					{Destination: netip.MustParsePrefix("203.0.113.0/24"), NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
				},
			},
		},
		Gateways: map[string]model.Gateway{
			"gw-a": {Name: "gw-a", VPC: "prod", Node: "node-a", ExternalIF: "eth0", LANIP: netip.MustParseAddr("10.10.0.254")},
		},
		NATRules: map[string]model.NATRule{
			"snat": {
				Name:       "snat",
				VPC:        "prod",
				Type:       model.ActionSNAT,
				MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
				ExternalIP: netip.MustParseAddr("198.51.100.10"),
			},
		},
	}
	decision, err := Resolve(state, Packet{
		VPC:    "prod",
		Source: netip.MustParseAddr("10.10.0.10"),
		Dest:   netip.MustParseAddr("203.0.113.99"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.NextHop != netip.MustParseAddr("10.10.0.253") {
		t.Fatalf("next hop = %s, want longest prefix route", decision.NextHop)
	}
	if decision.Translated != netip.MustParseAddr("198.51.100.10") {
		t.Fatalf("translated = %s, want SNAT external ip", decision.Translated)
	}
	if decision.Gateway != "gw-a" {
		t.Fatalf("gateway = %s, want gw-a", decision.Gateway)
	}
}

func TestResolveBlackhole(t *testing.T) {
	state := State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("192.0.2.0/24"),
					Blackhole:   true,
				}},
			},
		},
	}
	decision, err := Resolve(state, Packet{
		VPC:    "prod",
		Source: netip.MustParseAddr("10.10.0.10"),
		Dest:   netip.MustParseAddr("192.0.2.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != model.ActionDrop {
		t.Fatalf("action = %s, want drop", decision.Action)
	}
}
