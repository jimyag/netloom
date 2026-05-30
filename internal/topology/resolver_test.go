package topology

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/jimyag/netloom/internal/model"
)

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
	state := State{
		Endpoints: map[string]model.Endpoint{
			"pod-a": {ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10")},
		},
		LoadBalancers: map[string]model.LoadBalancer{
			"web": {
				Name:     "web",
				VPC:      "prod",
				VIP:      netip.MustParseAddr("10.96.0.10"),
				Port:     80,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{
					{IP: netip.MustParseAddr("10.10.0.30"), Port: 8080},
					{IP: netip.MustParseAddr("10.10.0.20"), Port: 8080},
				},
				Subnets: []string{"apps"},
			},
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

func TestResolveLoadBalancerBackendSelectionIsStablePerFlow(t *testing.T) {
	state := State{
		LoadBalancers: map[string]model.LoadBalancer{
			"web": {
				Name:     "web",
				VPC:      "prod",
				VIP:      netip.MustParseAddr("10.96.0.10"),
				Port:     80,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{
					{IP: netip.MustParseAddr("10.10.0.20"), Port: 8080},
					{IP: netip.MustParseAddr("10.10.0.30"), Port: 8080},
					{IP: netip.MustParseAddr("10.10.0.40"), Port: 8080},
				},
			},
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
		Port:            80,
		Protocol:        model.ProtocolTCP,
		SessionAffinity: true,
		Backends: []model.LoadBalancerBackend{
			{IP: netip.MustParseAddr("10.10.0.20"), Port: 8080},
			{IP: netip.MustParseAddr("10.10.0.30"), Port: 8080},
			{IP: netip.MustParseAddr("10.10.0.40"), Port: 8080},
		},
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

func TestResolveLoadBalancerRequiresBoundSourceSubnet(t *testing.T) {
	state := State{
		Endpoints: map[string]model.Endpoint{
			"pod-a": {ID: "pod-a", VPC: "prod", Subnet: "clients", IP: netip.MustParseAddr("10.10.1.10")},
		},
		LoadBalancers: map[string]model.LoadBalancer{
			"web": {
				Name:     "web",
				VPC:      "prod",
				VIP:      netip.MustParseAddr("10.96.0.10"),
				Port:     80,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.20"), Port: 8080}},
				Subnets:  []string{"apps"},
			},
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

func TestResolvePolicyRouteBeatsStaticRoute(t *testing.T) {
	state := State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("172.16.0.0/16"),
					NextHop:     netip.MustParseAddr("10.10.0.254"),
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
				Type:    model.ActionReroute,
				NextHop: netip.MustParseAddr("10.10.0.253"),
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

func TestResolveLongestPrefixStaticRouteAndSNATGateway(t *testing.T) {
	state := State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{
					{Destination: netip.MustParsePrefix("0.0.0.0/0"), NextHop: netip.MustParseAddr("10.10.0.254")},
					{Destination: netip.MustParsePrefix("203.0.113.0/24"), NextHop: netip.MustParseAddr("10.10.0.253")},
				},
			},
		},
		Gateways: map[string]model.Gateway{
			"gw-a": {Name: "gw-a", VPC: "prod", Node: "node-a", LANIP: netip.MustParseAddr("10.10.0.254")},
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
