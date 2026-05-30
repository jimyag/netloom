package model

import (
	"net/netip"
	"strings"
	"testing"
)

func TestCoreNetworkResourcesValidateRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		valid   func() error
		invalid func() error
		wantErr string
	}{
		{
			name: "vpc",
			valid: func() error {
				return VPC{Name: "prod"}.Validate()
			},
			invalid: func() error {
				return VPC{}.Validate()
			},
			wantErr: "vpc name is required",
		},
		{
			name: "subnet",
			valid: func() error {
				return Subnet{
					Name:            "apps",
					VPC:             "prod",
					CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
					Gateway:         netip.MustParseAddr("10.10.0.1"),
					ProviderNetwork: "physnet-a",
					VLAN:            100,
				}.Validate()
			},
			invalid: func() error {
				return Subnet{
					Name:    "apps",
					VPC:     "prod",
					CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
					Gateway: netip.MustParseAddr("10.11.0.1"),
				}.Validate()
			},
			wantErr: "outside cidr",
		},
		{
			name: "gateway",
			valid: func() error {
				return Gateway{
					Name:  "gw-a",
					VPC:   "prod",
					Node:  "node-a",
					LANIP: netip.MustParseAddr("10.10.0.254"),
				}.Validate()
			},
			invalid: func() error {
				return Gateway{
					Name: "gw-a",
					VPC:  "prod",
				}.Validate()
			},
			wantErr: "gateway node is required",
		},
		{
			name: "security group",
			valid: func() error {
				return SecurityGroup{
					Name: "web",
					VPC:  "prod",
					Rules: []SecurityGroupRule{{
						ID:        "allow-web",
						Direction: DirectionIngress,
						Protocol:  ProtocolTCP,
						Ports:     []PortRange{{From: 443, To: 443}},
						Action:    ActionAllow,
					}},
				}.Validate()
			},
			invalid: func() error {
				return SecurityGroup{
					Name: "web",
					Rules: []SecurityGroupRule{{
						ID:        "allow-web",
						Direction: DirectionIngress,
						Action:    ActionAllow,
					}},
				}.Validate()
			},
			wantErr: "security group vpc is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.valid(); err != nil {
				t.Fatalf("valid resource failed: %v", err)
			}
			err := tt.invalid()
			if err == nil {
				t.Fatal("expected invalid resource to fail")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestSubnetProviderNetworkVLANValidation(t *testing.T) {
	subnet := Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
		VLAN:    100,
	}
	err := subnet.Validate()
	if err == nil {
		t.Fatal("expected vlan without provider network to fail")
	}
	if !strings.Contains(err.Error(), "requires provider network") {
		t.Fatalf("error %q does not mention provider network", err)
	}

	subnet.ProviderNetwork = "physnet-a"
	subnet.VLAN = 4095
	err = subnet.Validate()
	if err == nil {
		t.Fatal("expected out-of-range vlan to fail")
	}
	if !strings.Contains(err.Error(), "between 1 and 4094") {
		t.Fatalf("error %q does not mention vlan range", err)
	}
}

func TestPolicyRouteRequiresNextHopForReroute(t *testing.T) {
	route := PolicyRoute{
		Name:     "force-egress",
		VPC:      "prod",
		Priority: 100,
		Match: RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("172.16.0.0/16"),
			Protocol:    ProtocolTCP,
			DstPorts:    []PortRange{{From: 443, To: 443}},
		},
		Action: RouteAction{Type: ActionReroute},
	}
	if err := route.Validate(); err == nil {
		t.Fatal("expected reroute without next hop to fail")
	}

	route.Action.NextHop = netip.MustParseAddr("10.10.0.254")
	if err := route.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityGroupRuleDoesNotAcceptRouteActions(t *testing.T) {
	rule := SecurityGroupRule{
		ID:        "route-action",
		Direction: DirectionEgress,
		Protocol:  ProtocolTCP,
		Ports:     []PortRange{{From: 443, To: 443}},
		Action:    ActionReroute,
	}
	if err := rule.Validate(); err == nil {
		t.Fatal("expected security group rule to reject reroute action")
	}
}

func TestNATRuleValidateKubeOVNStyleNAT(t *testing.T) {
	tests := []struct {
		name    string
		rule    NATRule
		wantErr string
	}{
		{
			name: "snat",
			rule: NATRule{
				Name:       "egress",
				VPC:        "prod",
				Type:       ActionSNAT,
				MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
				ExternalIP: netip.MustParseAddr("198.51.100.10"),
			},
		},
		{
			name: "dnat",
			rule: NATRule{
				Name:       "web",
				VPC:        "prod",
				Type:       ActionDNAT,
				ExternalIP: netip.MustParseAddr("198.51.100.20"),
				TargetIP:   netip.MustParseAddr("10.10.0.10"),
			},
		},
		{
			name: "floating ip",
			rule: NATRule{
				Name:       "fip",
				VPC:        "prod",
				Type:       ActionDNATSNAT,
				ExternalIP: netip.MustParseAddr("198.51.100.30"),
				TargetIP:   netip.MustParseAddr("10.10.0.11"),
			},
		},
		{
			name: "port dnat",
			rule: NATRule{
				Name:         "ssh",
				VPC:          "prod",
				Type:         ActionDNAT,
				ExternalIP:   netip.MustParseAddr("198.51.100.40"),
				TargetIP:     netip.MustParseAddr("10.10.0.12"),
				Protocol:     ProtocolTCP,
				ExternalPort: 2222,
				TargetPort:   2222,
			},
		},
		{
			name: "dnat target required",
			rule: NATRule{
				Name:       "broken",
				VPC:        "prod",
				Type:       ActionDNAT,
				ExternalIP: netip.MustParseAddr("198.51.100.50"),
			},
			wantErr: "dnat target ip is required",
		},
		{
			name: "port dnat protocol required",
			rule: NATRule{
				Name:         "broken-port",
				VPC:          "prod",
				Type:         ActionDNAT,
				ExternalIP:   netip.MustParseAddr("198.51.100.60"),
				TargetIP:     netip.MustParseAddr("10.10.0.13"),
				ExternalPort: 8443,
				TargetPort:   8443,
			},
			wantErr: "requires tcp or udp protocol",
		},
		{
			name: "port translation unsupported",
			rule: NATRule{
				Name:         "broken-translation",
				VPC:          "prod",
				Type:         ActionDNAT,
				ExternalIP:   netip.MustParseAddr("198.51.100.70"),
				TargetIP:     netip.MustParseAddr("10.10.0.14"),
				Protocol:     ProtocolTCP,
				ExternalPort: 8443,
				TargetPort:   443,
			},
			wantErr: "port translation is not supported",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected validation to fail")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadBalancerValidateServiceVIP(t *testing.T) {
	valid := LoadBalancer{
		Name:     "web",
		VPC:      "prod",
		VIP:      netip.MustParseAddr("10.96.0.10"),
		Port:     80,
		Protocol: ProtocolTCP,
		Backends: []LoadBalancerBackend{{
			IP:   netip.MustParseAddr("10.10.0.10"),
			Port: 8080,
		}},
		Subnets: []string{"apps"},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		lb      LoadBalancer
		wantErr string
	}{
		{
			name: "vip required",
			lb: LoadBalancer{
				Name:     "web",
				VPC:      "prod",
				Port:     80,
				Backends: valid.Backends,
			},
			wantErr: "vip is required",
		},
		{
			name: "backend required",
			lb: LoadBalancer{
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Port: 80,
			},
			wantErr: "backends are required",
		},
		{
			name: "unsupported protocol",
			lb: LoadBalancer{
				Name:     "web",
				VPC:      "prod",
				VIP:      netip.MustParseAddr("10.96.0.10"),
				Port:     80,
				Protocol: ProtocolICMP,
				Backends: valid.Backends,
			},
			wantErr: "unsupported load balancer protocol",
		},
		{
			name: "backend port required",
			lb: LoadBalancer{
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Port: 80,
				Backends: []LoadBalancerBackend{{
					IP: netip.MustParseAddr("10.10.0.10"),
				}},
			},
			wantErr: "backend port is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.lb.Validate()
			if err == nil {
				t.Fatal("expected validation to fail")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}
