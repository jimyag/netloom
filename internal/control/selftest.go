package control

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn"
	"github.com/jimyag/netloom/internal/topology"
)

type SelfTestResult struct {
	PolicyRouteNextHop netip.Addr
	SNATAddress        netip.Addr
	Gateway            string
	ServiceBackend     netip.Addr
	ServiceBackendPort uint16
	DNATTarget         netip.Addr
	FloatingIPTarget   netip.Addr
	OVNOperations      int
	OVNExecuted        int
}

func RunSelfTest(ctx context.Context) (SelfTestResult, error) {
	return runSelfTest(ctx, ovn.NewRecorderExecutor())
}

func RunOVNSelfTest(ctx context.Context, executor ovn.Executor) (SelfTestResult, error) {
	return runSelfTest(ctx, executor)
}

func runSelfTest(ctx context.Context, executor ovn.Executor) (SelfTestResult, error) {
	backend := NewMemoryBackend()
	ovnBackend := ovn.NewBackend(executor)
	controller := NewController(MultiTopologyBackend{backend, ovnBackend}, backend)
	state := DesiredState{
		VPCs: []model.VPC{{Name: "default"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "default",
			CIDR:    netip.MustParsePrefix("10.244.0.0/24"),
			Gateway: netip.MustParseAddr("10.244.0.1"),
		}},
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "default",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.244.0.10"),
			Node:   "node-a",
		}},
		RouteTables: []model.RouteTable{{
			Name: "main",
			VPC:  "default",
			Routes: []model.Route{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				NextHops:    []netip.Addr{netip.MustParseAddr("10.244.0.254")},
			}},
		}},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "https-via-fw",
			VPC:      "default",
			Priority: 100,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.244.0.0/24"),
				Destination: netip.MustParsePrefix("172.16.0.0/16"),
				Protocol:    model.ProtocolTCP,
				DstPorts:    []model.PortRange{{From: 443, To: 443}},
			},
			Action: model.RouteAction{
				Type:     model.ActionReroute,
				NextHops: []netip.Addr{netip.MustParseAddr("10.244.0.253")},
			},
		}},
		Gateways: []model.Gateway{{
			Name:       "gw-a",
			VPC:        "default",
			Node:       "node-a",
			ExternalIF: "eth0",
			LANIP:      netip.MustParseAddr("10.244.0.254"),
		}},
		NATRules: []model.NATRule{{
			Name:       "egress-snat",
			VPC:        "default",
			Type:       model.ActionSNAT,
			MatchCIDR:  netip.MustParsePrefix("10.244.0.0/24"),
			ExternalIP: netip.MustParseAddr("198.51.100.10"),
		}, {
			Name:       "web-dnat",
			VPC:        "default",
			Type:       model.ActionDNAT,
			ExternalIP: netip.MustParseAddr("198.51.100.20"),
			TargetIP:   netip.MustParseAddr("10.244.0.10"),
		}, {
			Name:       "web-fip",
			VPC:        "default",
			Type:       model.ActionDNATSNAT,
			ExternalIP: netip.MustParseAddr("198.51.100.30"),
			TargetIP:   netip.MustParseAddr("10.244.0.10"),
		}},
		LoadBalancers: []model.LoadBalancer{{
			Name: "web",
			VPC:  "default",
			VIP:  netip.MustParseAddr("10.96.0.10"),
			Ports: []model.LoadBalancerPort{{
				Port:     80,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{{
					IP:   netip.MustParseAddr("10.244.0.10"),
					Port: 8080,
				}},
			}},
			Subnets: []string{"apps"},
		}},
	}
	if err := controller.Reconcile(ctx, state); err != nil {
		return SelfTestResult{}, err
	}
	routeDecision, err := topology.Resolve(backend.TopologyState(), topology.Packet{
		VPC:      "default",
		Source:   netip.MustParseAddr("10.244.0.10"),
		Dest:     netip.MustParseAddr("172.16.1.10"),
		Protocol: model.ProtocolTCP,
		DestPort: 443,
	})
	if err != nil {
		return SelfTestResult{}, err
	}
	if routeDecision.NextHop != netip.MustParseAddr("10.244.0.253") {
		return SelfTestResult{}, fmt.Errorf("expected policy route next hop 10.244.0.253, got %s", routeDecision.NextHop)
	}
	egressDecision, err := topology.Resolve(backend.TopologyState(), topology.Packet{
		VPC:    "default",
		Source: netip.MustParseAddr("10.244.0.10"),
		Dest:   netip.MustParseAddr("203.0.113.10"),
	})
	if err != nil {
		return SelfTestResult{}, err
	}
	if egressDecision.Translated != netip.MustParseAddr("198.51.100.10") {
		return SelfTestResult{}, fmt.Errorf("expected snat 198.51.100.10, got %s", egressDecision.Translated)
	}
	if egressDecision.Gateway != "gw-a" {
		return SelfTestResult{}, fmt.Errorf("expected gateway gw-a, got %s", egressDecision.Gateway)
	}
	serviceDecision, err := topology.Resolve(backend.TopologyState(), topology.Packet{
		VPC:      "default",
		Source:   netip.MustParseAddr("10.244.0.10"),
		Dest:     netip.MustParseAddr("10.96.0.10"),
		Protocol: model.ProtocolTCP,
		DestPort: 80,
	})
	if err != nil {
		return SelfTestResult{}, err
	}
	if serviceDecision.Translated != netip.MustParseAddr("10.244.0.10") || serviceDecision.TranslatedPort != 8080 {
		return SelfTestResult{}, fmt.Errorf("expected service backend 10.244.0.10:8080, got %s:%d", serviceDecision.Translated, serviceDecision.TranslatedPort)
	}
	dnatDecision, err := topology.Resolve(backend.TopologyState(), topology.Packet{
		VPC:    "default",
		Source: netip.MustParseAddr("203.0.113.10"),
		Dest:   netip.MustParseAddr("198.51.100.20"),
	})
	if err != nil {
		return SelfTestResult{}, err
	}
	if dnatDecision.Translated != netip.MustParseAddr("10.244.0.10") {
		return SelfTestResult{}, fmt.Errorf("expected dnat target 10.244.0.10, got %s", dnatDecision.Translated)
	}
	fipDecision, err := topology.Resolve(backend.TopologyState(), topology.Packet{
		VPC:    "default",
		Source: netip.MustParseAddr("203.0.113.10"),
		Dest:   netip.MustParseAddr("198.51.100.30"),
	})
	if err != nil {
		return SelfTestResult{}, err
	}
	if fipDecision.Translated != netip.MustParseAddr("10.244.0.10") {
		return SelfTestResult{}, fmt.Errorf("expected floating ip target 10.244.0.10, got %s", fipDecision.Translated)
	}
	if len(ovnBackend.Operations()) == 0 {
		return SelfTestResult{}, fmt.Errorf("expected OVN topology operations to be planned")
	}
	executed := len(ovnBackend.Operations())
	if recorder, ok := executor.(*ovn.RecorderExecutor); ok {
		executed = len(recorder.Operations())
		if executed != len(ovnBackend.Operations()) {
			return SelfTestResult{}, fmt.Errorf("expected all OVN operations to pass through executor")
		}
	}
	return SelfTestResult{
		PolicyRouteNextHop: routeDecision.NextHop,
		SNATAddress:        egressDecision.Translated,
		Gateway:            egressDecision.Gateway,
		ServiceBackend:     serviceDecision.Translated,
		ServiceBackendPort: serviceDecision.TranslatedPort,
		DNATTarget:         dnatDecision.Translated,
		FloatingIPTarget:   fipDecision.Translated,
		OVNOperations:      len(ovnBackend.Operations()),
		OVNExecuted:        executed,
	}, nil
}
