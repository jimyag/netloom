package model

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
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

func TestSubnetExcludeCIDRValidation(t *testing.T) {
	subnet := Subnet{
		Name:         "apps",
		VPC:          "prod",
		CIDR:         netip.MustParsePrefix("10.10.0.0/24"),
		Gateway:      netip.MustParseAddr("10.10.0.1"),
		ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("10.10.0.128/25")},
	}
	if err := subnet.Validate(); err != nil {
		t.Fatal(err)
	}
	if !subnet.Excludes(netip.MustParseAddr("10.10.0.200")) {
		t.Fatal("expected exclude cidr to contain 10.10.0.200")
	}
	if subnet.Excludes(netip.MustParseAddr("10.10.0.20")) {
		t.Fatal("did not expect exclude cidr to contain 10.10.0.20")
	}

	subnet.ExcludeCIDRs = []netip.Prefix{netip.MustParsePrefix("10.10.1.0/24")}
	if err := subnet.Validate(); err == nil || !strings.Contains(err.Error(), "outside cidr") {
		t.Fatalf("error = %v, want outside cidr validation", err)
	}

	subnet.ExcludeCIDRs = []netip.Prefix{netip.MustParsePrefix("fd00:10::/64")}
	if err := subnet.Validate(); err == nil || !strings.Contains(err.Error(), "family must match") {
		t.Fatalf("error = %v, want family validation", err)
	}
}

func TestSecurityGroupTierValidation(t *testing.T) {
	valid := SecurityGroup{
		Name: "web",
		VPC:  "prod",
		Tier: 1,
		Rules: []SecurityGroupRule{{
			ID:        "allow-web",
			Direction: DirectionIngress,
			Protocol:  ProtocolTCP,
			Ports:     []PortRange{{From: 443, To: 443}},
			Action:    ActionAllow,
		}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid security group tier failed: %v", err)
	}
	invalid := valid
	invalid.Tier = 2
	if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), "tier") {
		t.Fatalf("error = %v, want tier validation", err)
	}
}

func TestSecurityGroupRulePriorityValidation(t *testing.T) {
	valid := SecurityGroupRule{
		ID:        "allow-web",
		Priority:  SecurityGroupPriorityMax,
		Direction: DirectionIngress,
		Protocol:  ProtocolTCP,
		Ports:     []PortRange{{From: 443, To: 443}},
		Action:    ActionAllow,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid rule priority failed: %v", err)
	}
	unspecified := valid
	unspecified.Priority = 0
	if err := unspecified.Validate(); err != nil {
		t.Fatalf("unspecified rule priority failed: %v", err)
	}
	for _, priority := range []int{-1, SecurityGroupPriorityMax + 1} {
		invalid := valid
		invalid.Priority = priority
		if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), "priority") {
			t.Fatalf("priority %d error = %v, want priority validation", priority, err)
		}
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

	route.Action.NextHop = netip.Addr{}
	route.Action.NextHops = []netip.Addr{
		netip.MustParseAddr("10.10.0.253"),
		netip.MustParseAddr("10.10.0.254"),
	}
	if err := route.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := route.Action.RerouteNextHops(); len(got) != 2 || got[0].String() != "10.10.0.253" || got[1].String() != "10.10.0.254" {
		t.Fatalf("reroute next hops = %v", got)
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

func TestRouteSupportsECMPNextHops(t *testing.T) {
	route := Route{
		Destination: netip.MustParsePrefix("0.0.0.0/0"),
		NextHops: []netip.Addr{
			netip.MustParseAddr("10.10.0.253"),
			netip.MustParseAddr("10.10.0.254"),
		},
	}
	if err := route.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := route.RouteNextHops(); len(got) != 2 || got[0] != netip.MustParseAddr("10.10.0.253") || got[1] != netip.MustParseAddr("10.10.0.254") {
		t.Fatalf("route next hops = %v, want ECMP next hops", got)
	}

	route.NextHop = netip.MustParseAddr("10.10.0.253")
	err := route.Validate()
	if err == nil {
		t.Fatal("expected duplicate next hop to fail")
	}
	if !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("error %q does not mention duplicate next hop", err)
	}

	blackhole := Route{
		Destination: netip.MustParsePrefix("0.0.0.0/0"),
		NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.253")},
		Blackhole:   true,
	}
	err = blackhole.Validate()
	if err == nil {
		t.Fatal("expected blackhole route with next hop to fail")
	}
	if !strings.Contains(err.Error(), "must not set next hop") {
		t.Fatalf("error %q does not mention blackhole next hop", err)
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

	route.Action = RouteAction{
		Type: ActionReroute,
		NextHops: []netip.Addr{
			netip.MustParseAddr("fd00:10::fe"),
			netip.MustParseAddr("10.10.0.254"),
		},
	}
	err = route.Validate()
	if err == nil {
		t.Fatal("expected mixed ECMP next hop family to fail")
	}
	if !strings.Contains(err.Error(), "same IP family") {
		t.Fatalf("error %q does not mention next hop IP family", err)
	}

	route.Match.Destination = netip.MustParsePrefix("10.20.0.0/16")
	route.Action = RouteAction{
		Type: ActionReroute,
		NextHops: []netip.Addr{
			netip.MustParseAddr("10.10.0.254"),
			netip.MustParseAddr("10.10.0.254"),
		},
	}
	err = route.Validate()
	if err == nil {
		t.Fatal("expected duplicate ECMP next hop to fail")
	}
	if !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("error %q does not mention duplicate next hop", err)
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

func TestEndpointValidatesNamedPorts(t *testing.T) {
	endpoint := Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		IP:     netip.MustParseAddr("10.10.0.10"),
		MAC:    "0A:58:0A:0A:00:0A",
		Node:   "node-a",
		NamedPorts: []NamedPort{
			{Name: "http", Protocol: ProtocolTCP, Port: 8080},
			{Name: "dns", Protocol: ProtocolUDP, Port: 53},
		},
	}
	if err := endpoint.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := endpoint.NormalizedMAC(); got != "0a:58:0a:0a:00:0a" {
		t.Fatalf("normalized mac = %q, want lowercase canonical mac", got)
	}

	endpoint.NamedPorts = append(endpoint.NamedPorts, NamedPort{Name: "http", Protocol: ProtocolTCP, Port: 9090})
	if err := endpoint.Validate(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("error = %v, want duplicate named port validation", err)
	}

	endpoint.NamedPorts = []NamedPort{{Name: "bad.name", Protocol: ProtocolTCP, Port: 8080}}
	if err := endpoint.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported character") {
		t.Fatalf("error = %v, want invalid named port name validation", err)
	}

	endpoint.NamedPorts = nil
	endpoint.MAC = "not-a-mac"
	if err := endpoint.Validate(); err == nil || !strings.Contains(err.Error(), "endpoint mac is invalid") {
		t.Fatalf("error = %v, want invalid mac validation", err)
	}
}

func TestGatewayMACMatchesOVNRouterPortMAC(t *testing.T) {
	if got := GatewayMAC(netip.MustParseAddr("10.10.0.1")); got != "0a:58:0a:0a:00:01" {
		t.Fatalf("gateway mac = %s", got)
	}
	if got := GatewayMAC(netip.MustParseAddr("fd00:10::1")); got != "0a:58:00:00:00:01" {
		t.Fatalf("gateway mac = %s", got)
	}
}

func TestSecurityGroupRuleValidatesNamedPorts(t *testing.T) {
	rule := SecurityGroupRule{
		ID:         "allow-http",
		Direction:  DirectionIngress,
		Protocol:   ProtocolTCP,
		NamedPorts: []string{"http"},
		Action:     ActionAllow,
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}

	rule.Protocol = ProtocolICMP
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "named ports require tcp or udp protocol") {
		t.Fatalf("error = %v, want protocol validation", err)
	}

	rule.Protocol = ProtocolTCP
	rule.NamedPorts = []string{"http", "http"}
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("error = %v, want duplicate named port validation", err)
	}
}

func TestSecurityGroupRuleValidatesICMPTypeAndCode(t *testing.T) {
	icmpType := uint8(8)
	icmpCode := uint8(0)
	rule := SecurityGroupRule{
		ID:        "icmp-echo",
		Direction: DirectionEgress,
		Protocol:  ProtocolICMP,
		ICMPType:  &icmpType,
		ICMPCode:  &icmpCode,
		Action:    ActionAllow,
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}

	rule.Protocol = ProtocolTCP
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "icmp_type requires icmp protocol") {
		t.Fatalf("error = %v, want icmp_type protocol validation", err)
	}

	rule.Protocol = ProtocolICMP
	rule.ICMPType = nil
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "icmp_code requires icmp_type") {
		t.Fatalf("error = %v, want icmp_code requires icmp_type", err)
	}
}

func TestSecurityGroupRuleValidatesRemoteFQDNSelectors(t *testing.T) {
	valid := SecurityGroupRule{
		ID:        "allow-api",
		Direction: DirectionEgress,
		Protocol:  ProtocolTCP,
		RemoteFQDNs: []FQDNSelector{
			{MatchName: "api.example.com"},
			{MatchPattern: "*.svc.example.com"},
		},
		Ports:  []PortRange{{From: 443, To: 443}},
		Action: ActionAllow,
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		rule    SecurityGroupRule
		wantErr string
	}{
		{
			name: "ingress fqdn",
			rule: SecurityGroupRule{
				ID:          "bad-ingress",
				Direction:   DirectionIngress,
				Protocol:    ProtocolTCP,
				RemoteFQDNs: []FQDNSelector{{MatchName: "api.example.com"}},
				Action:      ActionAllow,
			},
			wantErr: "only supported for egress",
		},
		{
			name: "mutually exclusive",
			rule: SecurityGroupRule{
				ID:          "bad-remote",
				Direction:   DirectionEgress,
				Protocol:    ProtocolTCP,
				RemoteCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
				RemoteFQDNs: []FQDNSelector{{MatchName: "api.example.com"}},
				Action:      ActionAllow,
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "empty selector",
			rule: SecurityGroupRule{
				ID:          "bad-empty",
				Direction:   DirectionEgress,
				Protocol:    ProtocolTCP,
				RemoteFQDNs: []FQDNSelector{{}},
				Action:      ActionAllow,
			},
			wantErr: "match name or match pattern is required",
		},
		{
			name: "invalid character",
			rule: SecurityGroupRule{
				ID:          "bad-name",
				Direction:   DirectionEgress,
				Protocol:    ProtocolTCP,
				RemoteFQDNs: []FQDNSelector{{MatchName: "api example.com"}},
				Action:      ActionAllow,
			},
			wantErr: "unsupported character",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if err == nil {
				t.Fatal("expected validation to fail")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestSecurityGroupRuleValidatesRemoteEntities(t *testing.T) {
	rule := SecurityGroupRule{
		ID:             "allow-world",
		Direction:      DirectionEgress,
		Protocol:       ProtocolTCP,
		RemoteEntities: []string{"world", "host", "remote-node"},
		Ports:          []PortRange{{From: 443, To: 443}},
		Action:         ActionAllow,
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}

	rule.RemoteEntities = []string{"world", "world"}
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("error = %v, want duplicate remote entity validation", err)
	}

	rule.RemoteEntities = []string{"internet"}
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported remote entity") {
		t.Fatalf("error = %v, want unsupported remote entity validation", err)
	}

	rule.RemoteEntities = []string{"world"}
	rule.RemoteCIDR = netip.MustParsePrefix("0.0.0.0/0")
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v, want remote selector exclusivity validation", err)
	}
}

func TestDNSRecordValidation(t *testing.T) {
	record := DNSRecord{Name: "api.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.10")}}
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	underscoreRecord := DNSRecord{Name: "_api.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.11")}}
	if err := underscoreRecord.Validate(); err != nil {
		t.Fatal(err)
	}
	ttlRecord := DNSRecord{
		Name:       "api.example.com",
		IPs:        []netip.Addr{netip.MustParseAddr("203.0.113.10")},
		TTLSeconds: 30,
		ObservedAt: time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
	}
	if err := ttlRecord.Validate(); err != nil {
		t.Fatal(err)
	}
	if ttlRecord.IsExpired(time.Date(2026, 5, 30, 12, 0, 29, 0, time.UTC)) {
		t.Fatal("record should still be active before ttl expires")
	}
	if !ttlRecord.IsExpired(time.Date(2026, 5, 30, 12, 0, 30, 0, time.UTC)) {
		t.Fatal("record should expire when ttl boundary is reached")
	}
	if err := (DNSRecord{Name: "api.example.com"}).Validate(); err == nil {
		t.Fatal("expected dns record without ips to fail")
	}
	if err := (DNSRecord{
		Name:       "api.example.com",
		IPs:        []netip.Addr{netip.MustParseAddr("203.0.113.10")},
		TTLSeconds: 30,
	}).Validate(); err == nil {
		t.Fatal("expected ttl record without observed_at to fail")
	}
	if err := (DNSRecord{
		Name:       "api.example.com",
		IPs:        []netip.Addr{netip.MustParseAddr("203.0.113.10")},
		ObservedAt: time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
	}).Validate(); err == nil {
		t.Fatal("expected observed_at without ttl to fail")
	}
}

func TestCIDRGroupValidation(t *testing.T) {
	group := CIDRGroup{
		Name:  "corp",
		VPC:   "prod",
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("2001:db8::/64")},
		Entries: []CIDRGroupEntry{{
			CIDR:        netip.MustParsePrefix("198.51.100.0/24"),
			ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.128/25")},
		}},
	}
	if err := group.Validate(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		group   CIDRGroup
		wantErr string
	}{
		{name: "name required", group: CIDRGroup{VPC: "prod", CIDRs: group.CIDRs}, wantErr: "name is required"},
		{name: "vpc required", group: CIDRGroup{Name: "corp", CIDRs: group.CIDRs}, wantErr: "vpc is required"},
		{name: "cidrs or entries required", group: CIDRGroup{Name: "corp", VPC: "prod"}, wantErr: "cidrs or entries are required"},
		{name: "duplicate cidr", group: CIDRGroup{Name: "corp", VPC: "prod", CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.1/16"), netip.MustParsePrefix("10.20.0.0/16")}}, wantErr: "duplicated"},
		{name: "duplicate entry cidr", group: CIDRGroup{Name: "corp", VPC: "prod", CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, Entries: []CIDRGroupEntry{{CIDR: netip.MustParsePrefix("10.20.0.1/16")}}}, wantErr: "duplicated"},
		{name: "entry except family mismatch", group: CIDRGroup{Name: "corp", VPC: "prod", Entries: []CIDRGroupEntry{{CIDR: netip.MustParsePrefix("10.20.0.0/16"), ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}}}}, wantErr: "family must match"},
		{name: "entry except outside cidr", group: CIDRGroup{Name: "corp", VPC: "prod", Entries: []CIDRGroupEntry{{CIDR: netip.MustParsePrefix("10.20.0.0/16"), ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}}}}, wantErr: "must be contained"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.group.Validate()
			if err == nil {
				t.Fatal("expected validation to fail")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestSecurityGroupRuleValidatesRemoteCIDRGroupExclusivity(t *testing.T) {
	rule := SecurityGroupRule{
		ID:              "allow-corp",
		Direction:       DirectionEgress,
		Protocol:        ProtocolTCP,
		RemoteCIDRGroup: "corp",
		Ports:           []PortRange{{From: 443, To: 443}},
		Action:          ActionAllow,
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}

	rule.RemoteCIDR = netip.MustParsePrefix("10.20.0.0/16")
	err := rule.Validate()
	if err == nil {
		t.Fatal("expected remote cidr and cidr group to be mutually exclusive")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error %q does not mention mutual exclusion", err)
	}
}

func TestEndpointValidatesLabels(t *testing.T) {
	endpoint := Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		IP:     netip.MustParseAddr("10.10.0.10"),
		Node:   "node-a",
		Labels: Labels{
			"app": "web",
			"env": "prod",
		},
	}
	if err := endpoint.Validate(); err != nil {
		t.Fatal(err)
	}
	endpoint.Labels = Labels{"": "web"}
	if err := endpoint.Validate(); err == nil || !strings.Contains(err.Error(), "label key is required") {
		t.Fatalf("error = %v, want missing label key validation", err)
	}
	endpoint.Labels = Labels{"app": ""}
	if err := endpoint.Validate(); err == nil || !strings.Contains(err.Error(), "value is required") {
		t.Fatalf("error = %v, want missing label value validation", err)
	}
}

func TestSecurityGroupRuleValidatesRemoteEndpointSelector(t *testing.T) {
	rule := SecurityGroupRule{
		ID:                     "allow-web",
		Direction:              DirectionIngress,
		Protocol:               ProtocolTCP,
		RemoteEndpointSelector: Labels{"app": "client"},
		Ports:                  []PortRange{{From: 8080, To: 8080}},
		Action:                 ActionAllow,
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}

	rule.RemoteCIDR = netip.MustParsePrefix("10.20.0.0/16")
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v, want remote selector exclusivity validation", err)
	}

	rule.RemoteCIDR = netip.Prefix{}
	rule.RemoteEndpointSelector = Labels{"bad key": "client"}
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "must not contain whitespace") {
		t.Fatalf("error = %v, want selector label validation", err)
	}
}

func TestSecurityGroupRuleValidatesRemoteService(t *testing.T) {
	rule := SecurityGroupRule{
		ID:            "allow-web-service",
		Direction:     DirectionEgress,
		Protocol:      ProtocolAny,
		RemoteService: "web",
		Action:        ActionAllow,
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}

	rule.RemoteCIDR = netip.MustParsePrefix("10.20.0.0/16")
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v, want remote service exclusivity validation", err)
	}

	rule.RemoteCIDR = netip.Prefix{}
	rule.Direction = DirectionIngress
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "only supported for egress") {
		t.Fatalf("error = %v, want remote service direction validation", err)
	}
}

func TestSecurityGroupRuleValidatesExceptCIDRs(t *testing.T) {
	rule := SecurityGroupRule{
		ID:          "allow-corp",
		Direction:   DirectionEgress,
		Protocol:    ProtocolTCP,
		RemoteCIDR:  netip.MustParsePrefix("10.20.0.0/16"),
		ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.10.0/24")},
		Ports:       []PortRange{{From: 443, To: 443}},
		Action:      ActionAllow,
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		rule    SecurityGroupRule
		wantErr string
	}{
		{
			name: "requires remote cidr",
			rule: SecurityGroupRule{
				ID:              "bad-cidr-group-except",
				Direction:       DirectionEgress,
				Protocol:        ProtocolTCP,
				RemoteCIDRGroup: "corp",
				ExceptCIDRs:     []netip.Prefix{netip.MustParsePrefix("10.20.10.0/24")},
				Action:          ActionAllow,
			},
			wantErr: "require remote cidr",
		},
		{
			name: "family mismatch",
			rule: SecurityGroupRule{
				ID:          "bad-family",
				Direction:   DirectionEgress,
				Protocol:    ProtocolTCP,
				RemoteCIDR:  netip.MustParsePrefix("10.20.0.0/16"),
				ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")},
				Action:      ActionAllow,
			},
			wantErr: "family must match",
		},
		{
			name: "outside remote cidr",
			rule: SecurityGroupRule{
				ID:          "bad-outside",
				Direction:   DirectionEgress,
				Protocol:    ProtocolTCP,
				RemoteCIDR:  netip.MustParsePrefix("10.20.0.0/16"),
				ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")},
				Action:      ActionAllow,
			},
			wantErr: "must be contained",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if err == nil {
				t.Fatal("expected validation to fail")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
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
			name: "distributed floating ip",
			rule: NATRule{
				Name:        "distributed-fip",
				VPC:         "prod",
				Type:        ActionDNATSNAT,
				ExternalIP:  netip.MustParseAddr("198.51.100.31"),
				TargetIP:    netip.MustParseAddr("10.10.0.14"),
				LogicalPort: "nl_lp_pod-a",
				ExternalMAC: "0a:58:0a:0a:00:0e",
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
			name: "port translation",
			rule: NATRule{
				Name:         "web-translation",
				VPC:          "prod",
				Type:         ActionDNAT,
				ExternalIP:   netip.MustParseAddr("198.51.100.70"),
				TargetIP:     netip.MustParseAddr("10.10.0.14"),
				Protocol:     ProtocolTCP,
				ExternalPort: 8443,
				TargetPort:   443,
			},
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
		{
			name: "distributed fields require floating ip",
			rule: NATRule{
				Name:        "broken-distributed-dnat",
				VPC:         "prod",
				Type:        ActionDNAT,
				ExternalIP:  netip.MustParseAddr("198.51.100.91"),
				TargetIP:    netip.MustParseAddr("10.10.0.15"),
				LogicalPort: "nl_lp_pod-a",
				ExternalMAC: "0a:58:0a:0a:00:0f",
			},
			wantErr: "only supported for dnat_and_snat",
		},
		{
			name: "distributed fields must be paired",
			rule: NATRule{
				Name:        "broken-distributed-pair",
				VPC:         "prod",
				Type:        ActionDNATSNAT,
				ExternalIP:  netip.MustParseAddr("198.51.100.92"),
				TargetIP:    netip.MustParseAddr("10.10.0.16"),
				LogicalPort: "nl_lp_pod-a",
			},
			wantErr: "must be set together",
		},
		{
			name: "distributed external mac must parse",
			rule: NATRule{
				Name:        "broken-distributed-mac",
				VPC:         "prod",
				Type:        ActionDNATSNAT,
				ExternalIP:  netip.MustParseAddr("198.51.100.93"),
				TargetIP:    netip.MustParseAddr("10.10.0.17"),
				LogicalPort: "nl_lp_pod-a",
				ExternalMAC: "not-a-mac",
			},
			wantErr: "external_mac is invalid",
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
		HealthCheck: LoadBalancerHealthCheck{
			Enabled:      true,
			Interval:     5,
			Timeout:      20,
			SuccessCount: 3,
			FailureCount: 3,
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	unhealthy := false
	if valid.Backends[0].Healthy != nil || !valid.Backends[0].IsHealthy() {
		t.Fatal("backend without explicit health should default to healthy")
	}
	if (LoadBalancerBackend{IP: valid.Backends[0].IP, Port: valid.Backends[0].Port, Healthy: &unhealthy}).IsHealthy() {
		t.Fatal("backend with healthy=false should be unhealthy")
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
			name: "selection field duplicate",
			lb: LoadBalancer{
				Name:            "web",
				VPC:             "prod",
				VIP:             netip.MustParseAddr("10.96.0.10"),
				Port:            80,
				Backends:        valid.Backends,
				SelectionFields: []string{"ip_src", "ip_src"},
			},
			wantErr: "selection field \"ip_src\" is duplicated",
		},
		{
			name: "selection field family mismatch",
			lb: LoadBalancer{
				Name:            "web",
				VPC:             "prod",
				VIP:             netip.MustParseAddr("10.96.0.10"),
				Port:            80,
				Backends:        valid.Backends,
				SelectionFields: []string{"ipv6_src"},
			},
			wantErr: "requires IPv6 VIP",
		},
		{
			name: "selection field unsupported",
			lb: LoadBalancer{
				Name:            "web",
				VPC:             "prod",
				VIP:             netip.MustParseAddr("10.96.0.10"),
				Port:            80,
				Backends:        valid.Backends,
				SelectionFields: []string{"eth_src"},
			},
			wantErr: "unsupported load balancer selection field",
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
		{
			name: "all backends unhealthy",
			lb: LoadBalancer{
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Port: 80,
				Backends: []LoadBalancerBackend{{
					IP:      netip.MustParseAddr("10.10.0.10"),
					Port:    8080,
					Healthy: &unhealthy,
				}},
			},
			wantErr: "at least one healthy backend",
		},
		{
			name: "disabled health check with options",
			lb: LoadBalancer{
				Name:        "web",
				VPC:         "prod",
				VIP:         netip.MustParseAddr("10.96.0.10"),
				Port:        80,
				Backends:    valid.Backends,
				HealthCheck: LoadBalancerHealthCheck{Interval: 5},
			},
			wantErr: "disabled health check",
		},
		{
			name: "health check interval too large",
			lb: LoadBalancer{
				Name:     "web",
				VPC:      "prod",
				VIP:      netip.MustParseAddr("10.96.0.10"),
				Port:     80,
				Backends: valid.Backends,
				HealthCheck: LoadBalancerHealthCheck{
					Enabled:  true,
					Interval: 86401,
				},
			},
			wantErr: "interval must be at most",
		},
		{
			name: "health check success count too large",
			lb: LoadBalancer{
				Name:     "web",
				VPC:      "prod",
				VIP:      netip.MustParseAddr("10.96.0.10"),
				Port:     80,
				Backends: valid.Backends,
				HealthCheck: LoadBalancerHealthCheck{
					Enabled:      true,
					SuccessCount: 256,
				},
			},
			wantErr: "success count must be at most",
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

func TestLoadBalancerEffectiveSelectionFields(t *testing.T) {
	tests := []struct {
		name string
		lb   LoadBalancer
		want []string
	}{
		{
			name: "explicit fields are normalized",
			lb: LoadBalancer{
				VIP:             netip.MustParseAddr("10.96.0.10"),
				SessionAffinity: true,
				SelectionFields: []string{" tp_src ", "ip_src"},
			},
			want: []string{"ip_src", "tp_src"},
		},
		{
			name: "ipv4 session affinity defaults to source ip",
			lb: LoadBalancer{
				VIP:             netip.MustParseAddr("10.96.0.10"),
				SessionAffinity: true,
			},
			want: []string{"ip_src"},
		},
		{
			name: "ipv6 session affinity defaults to source ip",
			lb: LoadBalancer{
				VIP:             netip.MustParseAddr("fd00:96::10"),
				SessionAffinity: true,
			},
			want: []string{"ipv6_src"},
		},
		{
			name: "no affinity has no default fields",
			lb: LoadBalancer{
				VIP: netip.MustParseAddr("10.96.0.10"),
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.lb.EffectiveSelectionFields()
			if !slices.Equal(got, tt.want) {
				t.Fatalf("fields = %v, want %v", got, tt.want)
			}
		})
	}
}
