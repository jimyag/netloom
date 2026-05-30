package topology

import (
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
