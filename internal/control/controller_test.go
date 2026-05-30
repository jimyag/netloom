package control

import (
	"context"
	"net/netip"
	"testing"

	"github.com/jimyag/netloom/internal/model"
)

func TestControllerReconcileSeparatesTopologyFromPolicy(t *testing.T) {
	backend := NewMemoryBackend()
	controller := NewController(backend, backend)

	state := DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
		RouteTables: []model.RouteTable{{
			Name: "main",
			VPC:  "prod",
			Routes: []model.Route{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				NextHop:     netip.MustParseAddr("10.10.0.254"),
			}},
		}},
		PolicyRoutes: []model.PolicyRoute{
			{
				Name:     "low",
				VPC:      "prod",
				Priority: 10,
				Match: model.RouteMatch{
					Protocol: model.ProtocolAny,
				},
				Action: model.RouteAction{Type: model.ActionAllow},
			},
			{
				Name:     "force-private",
				VPC:      "prod",
				Priority: 200,
				Match: model.RouteMatch{
					Source:      netip.MustParsePrefix("10.10.0.0/24"),
					Destination: netip.MustParsePrefix("172.16.0.0/16"),
					Protocol:    model.ProtocolTCP,
				},
				Action: model.RouteAction{
					Type:    model.ActionReroute,
					NextHop: netip.MustParseAddr("10.10.0.253"),
				},
			},
		},
		Gateways: []model.Gateway{{
			Name:       "gw-a",
			VPC:        "prod",
			Node:       "node-a",
			ExternalIF: "eth0",
			LANIP:      netip.MustParseAddr("10.10.0.254"),
		}},
		NATRules: []model.NATRule{{
			Name:       "egress",
			VPC:        "prod",
			Type:       model.ActionSNAT,
			MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
			ExternalIP: netip.MustParseAddr("192.0.2.10"),
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:        "allow-ingress",
				Priority:  100,
				Direction: model.DirectionIngress,
				Protocol:  model.ProtocolTCP,
				Ports:     []model.PortRange{{From: 443, To: 443}},
				Action:    model.ActionAllow,
				Stateful:  true,
			}},
		}},
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
	}

	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if len(backend.VPCs) != 1 || len(backend.Subnets) != 1 || len(backend.Endpoints) != 1 {
		t.Fatalf("topology objects were not reconciled: %+v", backend)
	}
	if got := len(backend.PolicyProgram["pod-a"].Rules); got != 1 {
		t.Fatalf("compiled policy rules = %d, want 1", got)
	}
	if got := backend.PolicyRoutes[0].Name; got != "force-private" {
		t.Fatalf("first policy route = %s, want force-private", got)
	}
}

func TestControllerReconcileRemovesStaleMemoryState(t *testing.T) {
	backend := NewMemoryBackend()
	controller := NewController(backend, backend)
	first := DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:        "allow-ingress",
				Priority:  100,
				Direction: model.DirectionIngress,
				Protocol:  model.ProtocolTCP,
				Ports:     []model.PortRange{{From: 443, To: 443}},
				Action:    model.ActionAllow,
			}},
		}},
	}
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if len(backend.Endpoints) != 1 || len(backend.PolicyProgram) != 1 {
		t.Fatalf("expected first reconcile to create endpoint and policy: %+v", backend)
	}

	second := first
	second.Endpoints = nil
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if len(backend.Endpoints) != 0 {
		t.Fatalf("stale endpoints were not removed: %+v", backend.Endpoints)
	}
	if len(backend.PolicyProgram) != 0 {
		t.Fatalf("stale policy programs were not removed: %+v", backend.PolicyProgram)
	}
	if len(backend.Subnets) != 1 {
		t.Fatalf("desired subnet should remain: %+v", backend.Subnets)
	}
}
