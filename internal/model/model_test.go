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
					DHCP:            DHCPOptions{Enabled: true, LeaseTime: 3600, MTU: 1450},
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

func TestSubnetDHCPValidation(t *testing.T) {
	subnet := Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
		DHCP:    DHCPOptions{LeaseTime: 3600},
	}
	err := subnet.Validate()
	if err == nil {
		t.Fatal("expected disabled dhcp with lease time to fail")
	}
	if !strings.Contains(err.Error(), "disabled dhcp") {
		t.Fatalf("error %q does not mention disabled dhcp", err)
	}

	subnet.DHCP = DHCPOptions{Enabled: true, LeaseTime: 30}
	err = subnet.Validate()
	if err == nil {
		t.Fatal("expected short lease time to fail")
	}
	if !strings.Contains(err.Error(), "at least 60") {
		t.Fatalf("error %q does not mention lease time", err)
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

	route.Match.Protocol = ProtocolAny
	if err := route.Validate(); err == nil {
		t.Fatal("expected dst ports without transport protocol to fail")
	}
}

func TestRouteRejectsMixedIPFamilies(t *testing.T) {
	route := Route{
		Destination: netip.MustParsePrefix("fd00:10::/64"),
		NextHop:     netip.MustParseAddr("10.10.0.254"),
	}
	err := route.Validate()
	if err == nil {
		t.Fatal("expected mixed route families to fail")
	}
	if !strings.Contains(err.Error(), "next hop family") {
		t.Fatalf("error %q does not mention next hop family", err)
	}
}

func TestPolicyRouteRejectsMixedIPFamilies(t *testing.T) {
	route := PolicyRoute{
		Name:     "mixed",
		VPC:      "prod",
		Priority: 100,
		Match: RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("fd00:20::/64"),
		},
		Action: RouteAction{Type: ActionDrop},
	}
	err := route.Validate()
	if err == nil {
		t.Fatal("expected mixed source and destination families to fail")
	}
	if !strings.Contains(err.Error(), "same IP family") {
		t.Fatalf("error %q does not mention IP family", err)
	}

	route.Match.Source = netip.Prefix{}
	route.Action = RouteAction{Type: ActionReroute, NextHop: netip.MustParseAddr("10.10.0.254")}
	err = route.Validate()
	if err == nil {
		t.Fatal("expected IPv4 next hop for IPv6 destination to fail")
	}
	if !strings.Contains(err.Error(), "next hop family") {
		t.Fatalf("error %q does not mention next hop family", err)
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

func TestSecurityGroupRulePortsRequireTransportProtocol(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolAny, ProtocolICMP} {
		rule := SecurityGroupRule{
			ID:        "invalid-ports",
			Direction: DirectionIngress,
			Protocol:  protocol,
			Ports:     []PortRange{{From: 443, To: 443}},
			Action:    ActionDrop,
		}
		err := rule.Validate()
		if err == nil {
			t.Fatalf("expected %s security group ports to fail", protocol)
		}
		if !strings.Contains(err.Error(), "ports require tcp or udp protocol") {
			t.Fatalf("error %q does not mention transport protocol", err)
		}
	}

	rule := SecurityGroupRule{
		ID:        "valid-ports",
		Direction: DirectionIngress,
		Protocol:  ProtocolUDP,
		Ports:     []PortRange{{From: 53, To: 53}},
		Action:    ActionAllow,
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
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
		{
			name: "snat family mismatch",
			rule: NATRule{
				Name:       "broken-snat-family",
				VPC:        "prod",
				Type:       ActionSNAT,
				MatchCIDR:  netip.MustParsePrefix("fd00:10::/64"),
				ExternalIP: netip.MustParseAddr("198.51.100.80"),
			},
			wantErr: "external ip family",
		},
		{
			name: "dnat family mismatch",
			rule: NATRule{
				Name:       "broken-dnat-family",
				VPC:        "prod",
				Type:       ActionDNAT,
				ExternalIP: netip.MustParseAddr("198.51.100.90"),
				TargetIP:   netip.MustParseAddr("fd00:10::10"),
			},
			wantErr: "external ip family",
		},
		{
			name: "floating ip family mismatch",
			rule: NATRule{
				Name:       "broken-fip-family",
				VPC:        "prod",
				Type:       ActionDNATSNAT,
				ExternalIP: netip.MustParseAddr("2001:db8::10"),
				TargetIP:   netip.MustParseAddr("10.10.0.11"),
			},
			wantErr: "external ip family",
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
		{
			name: "affinity timeout requires session affinity",
			lb: LoadBalancer{
				Name:            "web",
				VPC:             "prod",
				VIP:             netip.MustParseAddr("10.96.0.10"),
				Port:            80,
				Backends:        valid.Backends,
				AffinityTimeout: 10800,
			},
			wantErr: "affinity timeout requires session affinity",
		},
		{
			name: "affinity timeout too large",
			lb: LoadBalancer{
				Name:            "web",
				VPC:             "prod",
				VIP:             netip.MustParseAddr("10.96.0.10"),
				Port:            80,
				Backends:        valid.Backends,
				SessionAffinity: true,
				AffinityTimeout: 86401,
			},
			wantErr: "at most 86400",
		},
		{
			name: "backend family mismatch",
			lb: LoadBalancer{
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Port: 80,
				Backends: []LoadBalancerBackend{{
					IP:   netip.MustParseAddr("fd00:10::10"),
					Port: 8080,
				}},
			},
			wantErr: "ip family must match vip",
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
