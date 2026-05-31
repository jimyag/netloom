package control

import (
	"context"
	"net/netip"
	"strings"
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
				NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
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
					Type:     model.ActionReroute,
					NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")},
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
		LoadBalancers: []model.LoadBalancer{{
			Name: "web-vip",
			VPC:  "prod",
			VIP:  netip.MustParseAddr("10.96.0.10"),
			Ports: []model.LoadBalancerPort{{
				Port: 80,
				Backends: []model.LoadBalancerBackend{{
					IP:   netip.MustParseAddr("10.10.0.10"),
					Port: 8080,
				}},
			}},
			Subnets: []string{"apps"},
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
	if _, ok := backend.LoadBalancers["web-vip"]; !ok {
		t.Fatalf("load balancer was not reconciled: %+v", backend.LoadBalancers)
	}
}

func TestControllerRejectsConflictingNATRules(t *testing.T) {
	baseState := DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
	}
	tests := []struct {
		name    string
		rules   []model.NATRule
		wantErr string
	}{
		{
			name: "duplicate snat cidr",
			rules: []model.NATRule{
				{Name: "egress-a", VPC: "prod", Type: model.ActionSNAT, MatchCIDR: netip.MustParsePrefix("10.10.0.0/24"), ExternalIP: netip.MustParseAddr("198.51.100.10")},
				{Name: "egress-b", VPC: "prod", Type: model.ActionSNAT, MatchCIDR: netip.MustParsePrefix("10.10.0.0/24"), ExternalIP: netip.MustParseAddr("198.51.100.11")},
			},
			wantErr: "conflicts",
		},
		{
			name: "overlapping snat cidr",
			rules: []model.NATRule{
				{Name: "egress-a", VPC: "prod", Type: model.ActionSNAT, MatchCIDR: netip.MustParsePrefix("10.10.0.0/24"), ExternalIP: netip.MustParseAddr("198.51.100.10")},
				{Name: "egress-b", VPC: "prod", Type: model.ActionSNAT, MatchCIDR: netip.MustParsePrefix("10.10.0.128/25"), ExternalIP: netip.MustParseAddr("198.51.100.11")},
			},
			wantErr: "overlapping cidr",
		},
		{
			name: "floating ip owns whole external ip",
			rules: []model.NATRule{
				{Name: "fip", VPC: "prod", Type: model.ActionDNATSNAT, ExternalIP: netip.MustParseAddr("198.51.100.20"), TargetIP: netip.MustParseAddr("10.10.0.10")},
				{Name: "ssh", VPC: "prod", Type: model.ActionDNAT, ExternalIP: netip.MustParseAddr("198.51.100.20"), TargetIP: netip.MustParseAddr("10.10.0.11"), Protocol: model.ProtocolTCP, ExternalPort: 2222, TargetPort: 2222},
			},
			wantErr: "external ip",
		},
		{
			name: "same external protocol port",
			rules: []model.NATRule{
				{Name: "ssh-a", VPC: "prod", Type: model.ActionDNAT, ExternalIP: netip.MustParseAddr("198.51.100.30"), TargetIP: netip.MustParseAddr("10.10.0.10"), Protocol: model.ProtocolTCP, ExternalPort: 2222, TargetPort: 2222},
				{Name: "ssh-b", VPC: "prod", Type: model.ActionDNAT, ExternalIP: netip.MustParseAddr("198.51.100.30"), TargetIP: netip.MustParseAddr("10.10.0.11"), Protocol: model.ProtocolTCP, ExternalPort: 2222, TargetPort: 2222},
			},
			wantErr: "conflicts",
		},
		{
			name: "same external port across protocol",
			rules: []model.NATRule{
				{Name: "tcp", VPC: "prod", Type: model.ActionDNAT, ExternalIP: netip.MustParseAddr("198.51.100.40"), TargetIP: netip.MustParseAddr("10.10.0.10"), Protocol: model.ProtocolTCP, ExternalPort: 8443, TargetPort: 8443},
				{Name: "udp", VPC: "prod", Type: model.ActionDNAT, ExternalIP: netip.MustParseAddr("198.51.100.40"), TargetIP: netip.MustParseAddr("10.10.0.11"), Protocol: model.ProtocolUDP, ExternalPort: 8443, TargetPort: 8443},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := baseState
			state.NATRules = tt.rules
			err := NewController(NewMemoryBackend(), NewMemoryBackend()).Reconcile(context.Background(), state)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected reconcile to fail")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestControllerAllowsOverlappingSNATCIDRsAcrossVPCs(t *testing.T) {
	state := DesiredState{
		VPCs: []model.VPC{{Name: "prod"}, {Name: "dev"}},
		Subnets: []model.Subnet{
			{Name: "prod-apps", VPC: "prod", CIDR: netip.MustParsePrefix("10.10.0.0/24"), Gateway: netip.MustParseAddr("10.10.0.1")},
			{Name: "dev-apps", VPC: "dev", CIDR: netip.MustParsePrefix("10.10.0.0/24"), Gateway: netip.MustParseAddr("10.10.0.1")},
		},
		NATRules: []model.NATRule{
			{Name: "prod-egress", VPC: "prod", Type: model.ActionSNAT, MatchCIDR: netip.MustParsePrefix("10.10.0.0/24"), ExternalIP: netip.MustParseAddr("198.51.100.10")},
			{Name: "dev-egress", VPC: "dev", Type: model.ActionSNAT, MatchCIDR: netip.MustParsePrefix("10.10.0.0/24"), ExternalIP: netip.MustParseAddr("198.51.100.11")},
		},
	}
	if err := NewController(NewMemoryBackend(), NewMemoryBackend()).Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
}

func TestControllerRejectsConflictingLoadBalancers(t *testing.T) {
	baseState := DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
	}
	tests := []struct {
		name          string
		loadBalancers []model.LoadBalancer
	}{
		{
			name: "single port",
			loadBalancers: []model.LoadBalancer{
				{
					Name: "web-a",
					VPC:  "prod",
					VIP:  netip.MustParseAddr("10.96.0.10"),
					Ports: []model.LoadBalancerPort{{
						Port: 80,
						Backends: []model.LoadBalancerBackend{{
							IP:   netip.MustParseAddr("10.10.0.10"),
							Port: 8080,
						}},
					}},
				},
				{
					Name: "web-b",
					VPC:  "prod",
					VIP:  netip.MustParseAddr("10.96.0.10"),
					Ports: []model.LoadBalancerPort{{
						Port: 80,
						Backends: []model.LoadBalancerBackend{{
							IP:   netip.MustParseAddr("10.10.0.11"),
							Port: 8080,
						}},
					}},
				},
			},
		},
		{
			name: "multi port frontend",
			loadBalancers: []model.LoadBalancer{
				{
					Name: "web-a",
					VPC:  "prod",
					VIP:  netip.MustParseAddr("10.96.0.10"),
					Ports: []model.LoadBalancerPort{{
						Port:     9090,
						Protocol: model.ProtocolTCP,
						Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 9091}},
					}},
				},
				{
					Name: "web-b",
					VPC:  "prod",
					VIP:  netip.MustParseAddr("10.96.0.10"),
					Ports: []model.LoadBalancerPort{{
						Port: 9090,
						Backends: []model.LoadBalancerBackend{{
							IP:   netip.MustParseAddr("10.10.0.11"),
							Port: 9091,
						}},
					}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := baseState
			state.LoadBalancers = tt.loadBalancers
			err := NewController(NewMemoryBackend(), NewMemoryBackend()).Reconcile(context.Background(), state)
			if err == nil {
				t.Fatal("expected conflicting load balancers to fail")
			}
			if !strings.Contains(err.Error(), "conflicts") {
				t.Fatalf("error %q does not contain conflicts", err)
			}
		})
	}
}

func TestControllerRejectsNATAndLoadBalancerVIPConflicts(t *testing.T) {
	baseState := DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
	}
	tests := []struct {
		name string
		nat  model.NATRule
		lb   model.LoadBalancer
	}{
		{
			name: "port dnat owns load balancer vip port",
			nat:  model.NATRule{Name: "web-nat", VPC: "prod", Type: model.ActionDNAT, ExternalIP: netip.MustParseAddr("198.51.100.80"), TargetIP: netip.MustParseAddr("10.10.0.10"), Protocol: model.ProtocolTCP, ExternalPort: 8443, TargetPort: 443},
			lb: model.LoadBalancer{Name: "web-lb", VPC: "prod", VIP: netip.MustParseAddr("198.51.100.80"), Ports: []model.LoadBalancerPort{{
				Port:     8443,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.11"), Port: 8080}},
			}}},
		},
		{
			name: "floating ip owns all load balancer ports",
			nat:  model.NATRule{Name: "web-fip", VPC: "prod", Type: model.ActionDNATSNAT, ExternalIP: netip.MustParseAddr("198.51.100.81"), TargetIP: netip.MustParseAddr("10.10.0.10")},
			lb: model.LoadBalancer{Name: "web-lb", VPC: "prod", VIP: netip.MustParseAddr("198.51.100.81"), Ports: []model.LoadBalancerPort{{
				Port:     8443,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.11"), Port: 8080}},
			}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := baseState
			state.NATRules = []model.NATRule{tt.nat}
			state.LoadBalancers = []model.LoadBalancer{tt.lb}
			err := NewController(NewMemoryBackend(), NewMemoryBackend()).Reconcile(context.Background(), state)
			if err == nil {
				t.Fatal("expected NAT/LB VIP conflict to fail")
			}
			if !strings.Contains(err.Error(), "conflicts") {
				t.Fatalf("error %q does not contain conflicts", err)
			}
		})
	}
}

func TestControllerAllowsNATAndLoadBalancerSamePortDifferentProtocol(t *testing.T) {
	state := DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
		NATRules: []model.NATRule{{
			Name:         "udp-nat",
			VPC:          "prod",
			Type:         model.ActionDNAT,
			ExternalIP:   netip.MustParseAddr("198.51.100.90"),
			TargetIP:     netip.MustParseAddr("10.10.0.10"),
			Protocol:     model.ProtocolUDP,
			ExternalPort: 8443,
			TargetPort:   8443,
		}},
		LoadBalancers: []model.LoadBalancer{{
			Name: "tcp-lb",
			VPC:  "prod",
			VIP:  netip.MustParseAddr("198.51.100.90"),
			Ports: []model.LoadBalancerPort{{
				Port:     8443,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.11"), Port: 8080}},
			}},
		}},
	}
	if err := NewController(NewMemoryBackend(), NewMemoryBackend()).Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
}

func TestControllerAllowsRemoteServiceAnyProtocolExplicitPort(t *testing.T) {
	state := validObjectGraphState()
	state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.Prefix{}
	state.SecurityGroups[0].Rules[0].Direction = model.DirectionEgress
	state.SecurityGroups[0].Rules[0].Protocol = model.ProtocolAny
	state.SecurityGroups[0].Rules[0].RemoteService = "web"
	state.SecurityGroups[0].Rules[0].Ports = []model.PortRange{{From: 80, To: 80}}

	if err := NewController(NewMemoryBackend(), NewMemoryBackend()).Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
}

func TestControllerRejectsInvalidObjectGraph(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*DesiredState)
		wantErr string
	}{
		{
			name: "duplicate vpc",
			mutate: func(state *DesiredState) {
				state.VPCs = append(state.VPCs, model.VPC{Name: "prod"})
			},
			wantErr: "duplicate vpc name",
		},
		{
			name: "duplicate subnet",
			mutate: func(state *DesiredState) {
				state.Subnets = append(state.Subnets, state.Subnets[0])
			},
			wantErr: "duplicate subnet name",
		},
		{
			name: "subnet unknown vpc",
			mutate: func(state *DesiredState) {
				state.Subnets[0].VPC = "missing"
			},
			wantErr: "subnet \"apps\" references unknown vpc",
		},
		{
			name: "duplicate security group",
			mutate: func(state *DesiredState) {
				state.SecurityGroups = append(state.SecurityGroups, state.SecurityGroups[0])
			},
			wantErr: "duplicate security group name",
		},
		{
			name: "duplicate security group rule",
			mutate: func(state *DesiredState) {
				state.SecurityGroups[0].Rules = append(state.SecurityGroups[0].Rules, state.SecurityGroups[0].Rules[0])
			},
			wantErr: "security group rule \"allow-client\" is duplicated",
		},
		{
			name: "duplicate cidr group",
			mutate: func(state *DesiredState) {
				state.CIDRGroups = append(state.CIDRGroups,
					model.CIDRGroup{Name: "corp", VPC: "prod", CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}},
					model.CIDRGroup{Name: "corp", VPC: "prod", CIDRs: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}},
				)
			},
			wantErr: "duplicate cidr group name",
		},
		{
			name: "remote group unknown",
			mutate: func(state *DesiredState) {
				state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.Prefix{}
				state.SecurityGroups[0].Rules[0].RemoteGroup = "missing"
			},
			wantErr: "references unknown remote group",
		},
		{
			name: "remote cidr group unknown",
			mutate: func(state *DesiredState) {
				state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.Prefix{}
				state.SecurityGroups[0].Rules[0].RemoteCIDRGroup = "missing"
			},
			wantErr: "references unknown remote cidr group",
		},
		{
			name: "remote cidr group vpc mismatch",
			mutate: func(state *DesiredState) {
				state.VPCs = append(state.VPCs, model.VPC{Name: "other"})
				state.CIDRGroups = append(state.CIDRGroups, model.CIDRGroup{
					Name:  "corp",
					VPC:   "other",
					CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
				})
				state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.Prefix{}
				state.SecurityGroups[0].Rules[0].RemoteCIDRGroup = "corp"
			},
			wantErr: "references remote cidr group",
		},
		{
			name: "remote service unknown",
			mutate: func(state *DesiredState) {
				state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.Prefix{}
				state.SecurityGroups[0].Rules[0].Direction = model.DirectionEgress
				state.SecurityGroups[0].Rules[0].RemoteService = "missing"
			},
			wantErr: "references unknown remote service",
		},
		{
			name: "remote service vpc mismatch",
			mutate: func(state *DesiredState) {
				state.VPCs = append(state.VPCs, model.VPC{Name: "other"})
				state.Subnets = append(state.Subnets, model.Subnet{
					Name:    "other-apps",
					VPC:     "other",
					CIDR:    netip.MustParsePrefix("10.20.0.0/24"),
					Gateway: netip.MustParseAddr("10.20.0.1"),
				})
				state.LoadBalancers[0].VPC = "other"
				state.LoadBalancers[0].Subnets = []string{"other-apps"}
				state.LoadBalancers[0].Ports[0].Backends[0].IP = netip.MustParseAddr("10.20.0.10")
				state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.Prefix{}
				state.SecurityGroups[0].Rules[0].Direction = model.DirectionEgress
				state.SecurityGroups[0].Rules[0].RemoteService = "web"
			},
			wantErr: "references remote service",
		},
		{
			name: "remote service protocol mismatch",
			mutate: func(state *DesiredState) {
				state.LoadBalancers[0].Ports[0].Protocol = model.ProtocolUDP
				state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.Prefix{}
				state.SecurityGroups[0].Rules[0].Direction = model.DirectionEgress
				state.SecurityGroups[0].Rules[0].RemoteService = "web"
				state.SecurityGroups[0].Rules[0].Protocol = model.ProtocolTCP
			},
			wantErr: "security group rule \"allow-client\" references remote service \"web\" without matching tcp frontend",
		},
		{
			name: "remote service explicit port mismatch",
			mutate: func(state *DesiredState) {
				state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.Prefix{}
				state.SecurityGroups[0].Rules[0].Direction = model.DirectionEgress
				state.SecurityGroups[0].Rules[0].RemoteService = "web"
				state.SecurityGroups[0].Rules[0].Protocol = model.ProtocolTCP
				state.SecurityGroups[0].Rules[0].Ports = []model.PortRange{{From: 443, To: 443}}
			},
			wantErr: "security group rule \"allow-client\" references remote service \"web\" without matching tcp frontend port 443-443",
		},
		{
			name: "duplicate endpoint",
			mutate: func(state *DesiredState) {
				state.Endpoints = append(state.Endpoints, state.Endpoints[0])
			},
			wantErr: "duplicate endpoint id",
		},
		{
			name: "endpoint unknown subnet",
			mutate: func(state *DesiredState) {
				state.Endpoints[0].Subnet = "missing"
			},
			wantErr: "references unknown subnet",
		},
		{
			name: "endpoint subnet vpc mismatch",
			mutate: func(state *DesiredState) {
				state.VPCs = append(state.VPCs, model.VPC{Name: "other"})
				state.Subnets = append(state.Subnets, model.Subnet{
					Name:    "other-apps",
					VPC:     "other",
					CIDR:    netip.MustParsePrefix("10.20.0.0/24"),
					Gateway: netip.MustParseAddr("10.20.0.1"),
				})
				state.Endpoints[0].Subnet = "other-apps"
			},
			wantErr: "references subnet \"other-apps\" in vpc \"other\"",
		},
		{
			name: "endpoint outside subnet",
			mutate: func(state *DesiredState) {
				state.Endpoints[0].IP = netip.MustParseAddr("10.20.0.10")
			},
			wantErr: "outside subnet",
		},
		{
			name: "endpoint excluded by subnet",
			mutate: func(state *DesiredState) {
				state.Subnets[0].ExcludeCIDRs = []netip.Prefix{netip.MustParsePrefix("10.10.0.8/29")}
			},
			wantErr: "excluded by subnet",
		},
		{
			name: "endpoint ip conflicts with subnet gateway",
			mutate: func(state *DesiredState) {
				state.Endpoints[0].IP = netip.MustParseAddr("10.10.0.1")
			},
			wantErr: "endpoint \"pod-a\" ip 10.10.0.1 conflicts with subnet \"apps\" gateway ip",
		},
		{
			name: "endpoint unknown security group",
			mutate: func(state *DesiredState) {
				state.Endpoints[0].SecurityGroups = []string{"missing"}
			},
			wantErr: "references unknown security group",
		},
		{
			name: "ingress named port missing on endpoint",
			mutate: func(state *DesiredState) {
				state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.Prefix{}
				state.SecurityGroups[0].Rules[0].NamedPorts = []string{"http"}
				state.SecurityGroups[0].Rules[0].Ports = nil
			},
			wantErr: "security group rule \"allow-client\" named port tcp/http is not defined on endpoint \"pod-a\"",
		},
		{
			name: "egress remote group named port missing on remote endpoint",
			mutate: func(state *DesiredState) {
				state.SecurityGroups = append(state.SecurityGroups, model.SecurityGroup{
					Name: "client",
					VPC:  "prod",
					Rules: []model.SecurityGroupRule{{
						ID:          "egress-web",
						Direction:   model.DirectionEgress,
						Protocol:    model.ProtocolTCP,
						RemoteGroup: "web",
						NamedPorts:  []string{"http"},
						Action:      model.ActionAllow,
					}},
				})
				state.Endpoints = append(state.Endpoints, model.Endpoint{
					ID:             "pod-client",
					VPC:            "prod",
					Subnet:         "apps",
					IP:             netip.MustParseAddr("10.10.0.11"),
					Node:           "node-a",
					SecurityGroups: []string{"client"},
				})
			},
			wantErr: "security group rule \"egress-web\" remote endpoint \"pod-a\": security group rule \"egress-web\" named port tcp/http is not defined on endpoint \"pod-a\"",
		},
		{
			name: "egress selector named port missing on remote endpoint",
			mutate: func(state *DesiredState) {
				state.Endpoints[0].Labels = model.Labels{"app": "api"}
				state.SecurityGroups = append(state.SecurityGroups, model.SecurityGroup{
					Name: "client",
					VPC:  "prod",
					Rules: []model.SecurityGroupRule{{
						ID:                     "egress-api",
						Direction:              model.DirectionEgress,
						Protocol:               model.ProtocolTCP,
						RemoteEndpointSelector: model.Labels{"app": "api"},
						NamedPorts:             []string{"http"},
						Action:                 model.ActionAllow,
					}},
				})
				state.Endpoints = append(state.Endpoints, model.Endpoint{
					ID:             "pod-client",
					VPC:            "prod",
					Subnet:         "apps",
					IP:             netip.MustParseAddr("10.10.0.11"),
					Node:           "node-a",
					SecurityGroups: []string{"client"},
				})
			},
			wantErr: "security group rule \"egress-api\" remote endpoint \"pod-a\": security group rule \"egress-api\" named port tcp/http is not defined on endpoint \"pod-a\"",
		},
		{
			name: "endpoint ip conflict",
			mutate: func(state *DesiredState) {
				state.Endpoints = append(state.Endpoints, model.Endpoint{
					ID:             "pod-b",
					VPC:            "prod",
					Subnet:         "apps",
					IP:             netip.MustParseAddr("10.10.0.10"),
					Node:           "node-b",
					SecurityGroups: []string{"web"},
				})
			},
			wantErr: "conflicts",
		},
		{
			name: "endpoint mac conflicts with subnet gateway",
			mutate: func(state *DesiredState) {
				state.Endpoints[0].MAC = model.SubnetGatewayMAC("prod", "apps", netip.MustParseAddr("10.10.0.1"))
			},
			wantErr: "conflicts with subnet \"apps\" gateway mac",
		},
		{
			name: "endpoint mac conflict",
			mutate: func(state *DesiredState) {
				state.Endpoints[0].MAC = "0a:58:0a:0a:00:0a"
				state.Endpoints = append(state.Endpoints, model.Endpoint{
					ID:             "pod-b",
					VPC:            "prod",
					Subnet:         "apps",
					IP:             netip.MustParseAddr("10.10.0.11"),
					MAC:            "0A:58:0A:0A:00:0A",
					Node:           "node-b",
					SecurityGroups: []string{"web"},
				})
			},
			wantErr: "conflicts with \"pod-a\" on mac",
		},
		{
			name: "duplicate gateway",
			mutate: func(state *DesiredState) {
				state.Gateways = append(state.Gateways, state.Gateways[0])
			},
			wantErr: "duplicate gateway name",
		},
		{
			name: "gateway outside vpc subnet",
			mutate: func(state *DesiredState) {
				state.Gateways[0].LANIP = netip.MustParseAddr("10.20.0.254")
			},
			wantErr: "gateway \"gw-a\" lan ip 10.20.0.254 is outside vpc \"prod\" subnets",
		},
		{
			name: "gateway excluded by subnet",
			mutate: func(state *DesiredState) {
				state.Subnets[0].ExcludeCIDRs = []netip.Prefix{netip.MustParsePrefix("10.10.0.248/29")}
			},
			wantErr: "gateway \"gw-a\" lan ip 10.10.0.254 is excluded by subnet \"apps\"",
		},
		{
			name: "gateway lan ip conflicts with endpoint",
			mutate: func(state *DesiredState) {
				state.Gateways[0].LANIP = netip.MustParseAddr("10.10.0.10")
			},
			wantErr: "gateway \"gw-a\" lan ip 10.10.0.10 conflicts with endpoint \"pod-a\" in vpc prod",
		},
		{
			name: "gateway lan ip conflicts with subnet gateway",
			mutate: func(state *DesiredState) {
				state.Gateways[0].LANIP = netip.MustParseAddr("10.10.0.1")
			},
			wantErr: "gateway \"gw-a\" lan ip 10.10.0.1 conflicts with subnet \"apps\" gateway ip",
		},
		{
			name: "gateway lan ip conflicts with another gateway",
			mutate: func(state *DesiredState) {
				state.Gateways = append(state.Gateways, model.Gateway{
					Name:  "gw-b",
					VPC:   "prod",
					Node:  "node-b",
					LANIP: netip.MustParseAddr("10.10.0.254"),
				})
			},
			wantErr: "gateway \"gw-b\" conflicts with \"gw-a\" on lan ip 10.10.0.254 in vpc prod",
		},
		{
			name: "remote entity host without gateway",
			mutate: func(state *DesiredState) {
				state.Gateways = nil
				state.SecurityGroups[0].Rules[0].Direction = model.DirectionEgress
				state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.Prefix{}
				state.SecurityGroups[0].Rules[0].RemoteEntities = []string{"host"}
			},
			wantErr: "security group rule \"allow-client\" remote entity host requires at least one gateway in vpc \"prod\"",
		},
		{
			name: "remote entity remote-node without different gateway node",
			mutate: func(state *DesiredState) {
				state.SecurityGroups[0].Rules[0].Direction = model.DirectionEgress
				state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.Prefix{}
				state.SecurityGroups[0].Rules[0].RemoteEntities = []string{"remote-node"}
			},
			wantErr: "security group rule \"allow-client\" remote entity remote-node requires at least one gateway on a different node in vpc \"prod\"",
		},
		{
			name: "load balancer unknown subnet",
			mutate: func(state *DesiredState) {
				state.LoadBalancers[0].Subnets = []string{"missing"}
			},
			wantErr: "load balancer \"web\" references unknown subnet",
		},
		{
			name: "load balancer subnet vpc mismatch",
			mutate: func(state *DesiredState) {
				state.VPCs = append(state.VPCs, model.VPC{Name: "other"})
				state.Subnets = append(state.Subnets, model.Subnet{
					Name:    "other-apps",
					VPC:     "other",
					CIDR:    netip.MustParsePrefix("10.20.0.0/24"),
					Gateway: netip.MustParseAddr("10.20.0.1"),
				})
				state.LoadBalancers[0].Subnets = []string{"other-apps"}
			},
			wantErr: "references subnet \"other-apps\" in vpc \"other\"",
		},
		{
			name: "load balancer backend outside subnet",
			mutate: func(state *DesiredState) {
				state.LoadBalancers[0].Ports[0].Backends[0].IP = netip.MustParseAddr("10.20.0.10")
			},
			wantErr: "load balancer \"web\" backend 10.20.0.10:8080 is outside vpc \"prod\" subnets",
		},
		{
			name: "load balancer backend excluded by subnet",
			mutate: func(state *DesiredState) {
				state.Subnets[0].ExcludeCIDRs = []netip.Prefix{netip.MustParsePrefix("10.10.0.8/29")}
			},
			wantErr: "load balancer \"web\" backend 10.10.0.10:8080 is excluded by subnet \"apps\"",
		},
		{
			name: "load balancer vip inside vpc subnet",
			mutate: func(state *DesiredState) {
				state.LoadBalancers[0].VIP = netip.MustParseAddr("10.10.0.20")
			},
			wantErr: "load balancer \"web\" vip 10.10.0.20 is inside subnet \"apps\" in vpc \"prod\"",
		},
		{
			name: "load balancer vip conflicts with subnet gateway",
			mutate: func(state *DesiredState) {
				state.LoadBalancers[0].VIP = netip.MustParseAddr("10.10.0.1")
			},
			wantErr: "load balancer \"web\" vip 10.10.0.1 is inside subnet \"apps\" in vpc \"prod\"",
		},
		{
			name: "load balancer vip conflicts with endpoint",
			mutate: func(state *DesiredState) {
				state.LoadBalancers[0].VIP = netip.MustParseAddr("10.10.0.10")
			},
			wantErr: "load balancer \"web\" vip 10.10.0.10 is inside subnet \"apps\" in vpc \"prod\"",
		},
		{
			name: "route table unknown vpc",
			mutate: func(state *DesiredState) {
				state.RouteTables = []model.RouteTable{{
					Name: "main",
					VPC:  "missing",
					Routes: []model.Route{{
						Destination: netip.MustParsePrefix("0.0.0.0/0"),
						NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
					}},
				}}
			},
			wantErr: "route table \"main\" references unknown vpc",
		},
		{
			name: "route table next hop outside subnet",
			mutate: func(state *DesiredState) {
				state.RouteTables = []model.RouteTable{{
					Name: "main",
					VPC:  "prod",
					Routes: []model.Route{{
						Destination: netip.MustParsePrefix("0.0.0.0/0"),
						NextHops:    []netip.Addr{netip.MustParseAddr("10.20.0.254")},
					}},
				}}
			},
			wantErr: "route table \"main\" next hop 10.20.0.254 is outside vpc \"prod\" subnets",
		},
		{
			name: "route table next hop excluded by subnet",
			mutate: func(state *DesiredState) {
				state.Subnets[0].ExcludeCIDRs = []netip.Prefix{netip.MustParsePrefix("10.10.0.254/32")}
				state.Gateways[0].LANIP = netip.MustParseAddr("10.10.0.253")
				state.RouteTables = []model.RouteTable{{
					Name: "main",
					VPC:  "prod",
					Routes: []model.Route{{
						Destination: netip.MustParsePrefix("0.0.0.0/0"),
						NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
					}},
				}}
			},
			wantErr: "route table \"main\" next hop 10.10.0.254 is excluded by subnet \"apps\"",
		},
		{
			name: "policy route unknown vpc",
			mutate: func(state *DesiredState) {
				state.PolicyRoutes = []model.PolicyRoute{{
					Name:     "drop-lab",
					VPC:      "missing",
					Priority: 100,
					Match:    model.RouteMatch{Destination: netip.MustParsePrefix("198.51.100.0/24")},
					Action:   model.RouteAction{Type: model.ActionDrop},
				}}
			},
			wantErr: "policy route \"drop-lab\" references unknown vpc",
		},
		{
			name: "policy route next hop outside subnet",
			mutate: func(state *DesiredState) {
				state.PolicyRoutes = []model.PolicyRoute{{
					Name:     "force-private",
					VPC:      "prod",
					Priority: 100,
					Match:    model.RouteMatch{Destination: netip.MustParsePrefix("172.16.0.0/16")},
					Action:   model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.20.0.253")}},
				}}
			},
			wantErr: "policy route \"force-private\" next hop 10.20.0.253 is outside vpc \"prod\" subnets",
		},
		{
			name: "policy route next hop excluded by subnet",
			mutate: func(state *DesiredState) {
				state.Subnets[0].ExcludeCIDRs = []netip.Prefix{netip.MustParsePrefix("10.10.0.253/32")}
				state.PolicyRoutes = []model.PolicyRoute{{
					Name:     "force-private",
					VPC:      "prod",
					Priority: 100,
					Match:    model.RouteMatch{Destination: netip.MustParsePrefix("172.16.0.0/16")},
					Action:   model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
				}}
			},
			wantErr: "policy route \"force-private\" next hop 10.10.0.253 is excluded by subnet \"apps\"",
		},
		{
			name: "policy route source outside subnet",
			mutate: func(state *DesiredState) {
				state.PolicyRoutes = []model.PolicyRoute{{
					Name:     "drop-other-source",
					VPC:      "prod",
					Priority: 100,
					Match:    model.RouteMatch{Source: netip.MustParsePrefix("10.20.0.0/24")},
					Action:   model.RouteAction{Type: model.ActionDrop},
				}}
			},
			wantErr: "policy route \"drop-other-source\" source 10.20.0.0/24 is outside vpc \"prod\" subnets",
		},
		{
			name: "policy route source excluded by subnet",
			mutate: func(state *DesiredState) {
				state.Subnets[0].ExcludeCIDRs = []netip.Prefix{netip.MustParsePrefix("10.10.0.20/32")}
				state.PolicyRoutes = []model.PolicyRoute{{
					Name:     "drop-excluded-source",
					VPC:      "prod",
					Priority: 100,
					Match:    model.RouteMatch{Source: netip.MustParsePrefix("10.10.0.20/32")},
					Action:   model.RouteAction{Type: model.ActionDrop},
				}}
			},
			wantErr: "policy route \"drop-excluded-source\" source 10.10.0.20/32 is excluded by subnet \"apps\"",
		},
		{
			name: "nat unknown vpc",
			mutate: func(state *DesiredState) {
				state.NATRules = []model.NATRule{{
					Name:       "egress",
					VPC:        "missing",
					Type:       model.ActionSNAT,
					MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
					ExternalIP: netip.MustParseAddr("198.51.100.10"),
				}}
			},
			wantErr: "nat rule \"egress\" references unknown vpc",
		},
		{
			name: "snat match cidr outside subnet",
			mutate: func(state *DesiredState) {
				state.NATRules = []model.NATRule{{
					Name:       "egress",
					VPC:        "prod",
					Type:       model.ActionSNAT,
					MatchCIDR:  netip.MustParsePrefix("10.20.0.0/24"),
					ExternalIP: netip.MustParseAddr("198.51.100.10"),
				}}
			},
			wantErr: "nat rule \"egress\" match cidr 10.20.0.0/24 is outside vpc \"prod\" subnets",
		},
		{
			name: "snat match cidr excluded by subnet",
			mutate: func(state *DesiredState) {
				state.Subnets[0].ExcludeCIDRs = []netip.Prefix{netip.MustParsePrefix("10.10.0.20/32")}
				state.NATRules = []model.NATRule{{
					Name:       "host-egress",
					VPC:        "prod",
					Type:       model.ActionSNAT,
					MatchCIDR:  netip.MustParsePrefix("10.10.0.20/32"),
					ExternalIP: netip.MustParseAddr("198.51.100.10"),
				}}
			},
			wantErr: "nat rule \"host-egress\" match cidr 10.10.0.20/32 is excluded by subnet \"apps\"",
		},
		{
			name: "snat external ip inside vpc subnet",
			mutate: func(state *DesiredState) {
				state.NATRules = []model.NATRule{{
					Name:       "egress",
					VPC:        "prod",
					Type:       model.ActionSNAT,
					MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
					ExternalIP: netip.MustParseAddr("10.10.0.254"),
				}}
			},
			wantErr: "nat rule \"egress\" external ip 10.10.0.254 is inside subnet \"apps\" in vpc \"prod\"",
		},
		{
			name: "dnat target outside subnet",
			mutate: func(state *DesiredState) {
				state.NATRules = []model.NATRule{{
					Name:       "web-dnat",
					VPC:        "prod",
					Type:       model.ActionDNAT,
					ExternalIP: netip.MustParseAddr("198.51.100.20"),
					TargetIP:   netip.MustParseAddr("10.20.0.10"),
				}}
			},
			wantErr: "nat rule \"web-dnat\" target ip 10.20.0.10 is outside vpc \"prod\" subnets",
		},
		{
			name: "dnat external ip inside vpc subnet",
			mutate: func(state *DesiredState) {
				state.NATRules = []model.NATRule{{
					Name:       "web-dnat",
					VPC:        "prod",
					Type:       model.ActionDNAT,
					ExternalIP: netip.MustParseAddr("10.10.0.20"),
					TargetIP:   netip.MustParseAddr("10.10.0.10"),
				}}
			},
			wantErr: "nat rule \"web-dnat\" external ip 10.10.0.20 is inside subnet \"apps\" in vpc \"prod\"",
		},
		{
			name: "floating ip target excluded by subnet",
			mutate: func(state *DesiredState) {
				state.Subnets[0].ExcludeCIDRs = []netip.Prefix{netip.MustParsePrefix("10.10.0.12/32")}
				state.LoadBalancers[0].Ports[0].Backends[0].IP = netip.MustParseAddr("10.10.0.20")
				state.NATRules = []model.NATRule{{
					Name:       "web-fip",
					VPC:        "prod",
					Type:       model.ActionDNATSNAT,
					ExternalIP: netip.MustParseAddr("198.51.100.30"),
					TargetIP:   netip.MustParseAddr("10.10.0.12"),
				}}
			},
			wantErr: "nat rule \"web-fip\" target ip 10.10.0.12 is excluded by subnet \"apps\"",
		},
		{
			name: "load balancer unknown vpc",
			mutate: func(state *DesiredState) {
				state.LoadBalancers[0].VPC = "missing"
				state.LoadBalancers[0].Subnets = nil
			},
			wantErr: "load balancer \"web\" references unknown vpc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := validObjectGraphState()
			tt.mutate(&state)
			err := NewController(NewMemoryBackend(), NewMemoryBackend()).Reconcile(context.Background(), state)
			if err == nil {
				t.Fatal("expected invalid object graph to fail")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestControllerRejectsConflictingStaticRoutes(t *testing.T) {
	state := DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
		RouteTables: []model.RouteTable{
			{
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("0.0.0.0/0"),
					NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
				}},
			},
			{
				Name: "egress",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("0.0.0.0/0"),
					NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.253")},
				}},
			},
		},
	}
	err := NewController(NewMemoryBackend(), NewMemoryBackend()).Reconcile(context.Background(), state)
	if err == nil {
		t.Fatal("expected conflicting static routes to fail")
	}
	if !strings.Contains(err.Error(), "conflicts") || !strings.Contains(err.Error(), "0.0.0.0/0") {
		t.Fatalf("error %q does not describe static route conflict", err)
	}
}

func TestControllerRejectsDuplicateRouteTableNames(t *testing.T) {
	state := DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		RouteTables: []model.RouteTable{
			{Name: "main", VPC: "prod"},
			{Name: "main", VPC: "prod"},
		},
	}
	err := NewController(NewMemoryBackend(), NewMemoryBackend()).Reconcile(context.Background(), state)
	if err == nil {
		t.Fatal("expected duplicate route table names to fail")
	}
	if !strings.Contains(err.Error(), "duplicate route table name") {
		t.Fatalf("error %q does not mention duplicate route table name", err)
	}
}

func TestControllerRejectsOverlappingSubnetsInSameVPC(t *testing.T) {
	state := DesiredState{
		VPCs: []model.VPC{{Name: "prod"}, {Name: "dev"}},
		Subnets: []model.Subnet{
			{
				Name:    "apps",
				VPC:     "prod",
				CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
				Gateway: netip.MustParseAddr("10.10.0.1"),
			},
			{
				Name:    "apps-overlap",
				VPC:     "prod",
				CIDR:    netip.MustParsePrefix("10.10.0.128/25"),
				Gateway: netip.MustParseAddr("10.10.0.129"),
			},
			{
				Name:    "dev-apps",
				VPC:     "dev",
				CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
				Gateway: netip.MustParseAddr("10.10.0.1"),
			},
		},
	}
	err := NewController(NewMemoryBackend(), NewMemoryBackend()).Reconcile(context.Background(), state)
	if err == nil {
		t.Fatal("expected overlapping subnets in the same vpc to fail")
	}
	if !strings.Contains(err.Error(), "overlaps") || !strings.Contains(err.Error(), "prod") {
		t.Fatalf("error %q does not describe same-vpc subnet overlap", err)
	}
}

func TestControllerRejectsConflictingPolicyRoutes(t *testing.T) {
	state := DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
		PolicyRoutes: []model.PolicyRoute{
			{
				Name:     "private-a",
				VPC:      "prod",
				Priority: 100,
				Match: model.RouteMatch{
					Source:      netip.MustParsePrefix("10.10.0.0/24"),
					Destination: netip.MustParsePrefix("172.16.0.0/16"),
					Protocol:    model.ProtocolTCP,
					DstPorts:    []model.PortRange{{From: 443, To: 443}},
				},
				Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
			},
			{
				Name:     "private-b",
				VPC:      "prod",
				Priority: 100,
				Match: model.RouteMatch{
					Source:      netip.MustParsePrefix("10.10.0.0/24"),
					Destination: netip.MustParsePrefix("172.16.0.0/16"),
					Protocol:    model.ProtocolTCP,
					DstPorts:    []model.PortRange{{From: 443, To: 443}},
				},
				Action: model.RouteAction{Type: model.ActionDrop},
			},
		},
	}
	err := NewController(NewMemoryBackend(), NewMemoryBackend()).Reconcile(context.Background(), state)
	if err == nil {
		t.Fatal("expected conflicting policy routes to fail")
	}
	if !strings.Contains(err.Error(), "conflicts") || !strings.Contains(err.Error(), "priority 100") {
		t.Fatalf("error %q does not describe policy route conflict", err)
	}
}

func TestControllerRejectsDuplicatePolicyRouteNames(t *testing.T) {
	state := DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		PolicyRoutes: []model.PolicyRoute{
			{
				Name:     "private",
				VPC:      "prod",
				Priority: 100,
				Match:    model.RouteMatch{Destination: netip.MustParsePrefix("172.16.0.0/16")},
				Action:   model.RouteAction{Type: model.ActionDrop},
			},
			{
				Name:     "private",
				VPC:      "prod",
				Priority: 90,
				Match:    model.RouteMatch{Destination: netip.MustParsePrefix("198.51.100.0/24")},
				Action:   model.RouteAction{Type: model.ActionDrop},
			},
		},
	}
	err := NewController(NewMemoryBackend(), NewMemoryBackend()).Reconcile(context.Background(), state)
	if err == nil {
		t.Fatal("expected duplicate policy route names to fail")
	}
	if !strings.Contains(err.Error(), "duplicate policy route name") {
		t.Fatalf("error %q does not mention duplicate policy route name", err)
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

func validObjectGraphState() DesiredState {
	return DesiredState{
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
		Gateways: []model.Gateway{{
			Name:  "gw-a",
			VPC:   "prod",
			Node:  "node-a",
			LANIP: netip.MustParseAddr("10.10.0.254"),
		}},
		LoadBalancers: []model.LoadBalancer{{
			Name: "web",
			VPC:  "prod",
			VIP:  netip.MustParseAddr("10.96.0.10"),
			Ports: []model.LoadBalancerPort{{
				Port:     80,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080}},
			}},
			Subnets: []string{"apps"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-client",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("10.10.0.0/24"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionAllow,
			}},
		}},
	}
}
