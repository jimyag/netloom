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
					DHCP: DHCPOptions{
						Enabled:       true,
						LeaseTime:     3600,
						MTU:           1450,
						DNSServers:    []netip.Addr{netip.MustParseAddr("10.96.0.10")},
						DomainName:    "svc.cluster.local",
						SearchDomains: []string{"cluster.local"},
					},
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
			name: "provider network",
			valid: func() error {
				return ProviderNetwork{
					Name:      "physnet-a",
					Isolation: "exclusive",
					QoS: ProviderNetworkQoS{
						EgressRateBPS:  1000000000,
						EgressBurstBPS: 64000,
					},
					TenantQueues: []ProviderNetworkTenantQueuePolicy{{
						Tenant:     "prod",
						QueueID:    10,
						Protocol:   ProtocolTCP,
						Ports:      []PortRange{{From: 443, To: 443}},
						MinRateBPS: 100000000,
						MaxRateBPS: 500000000,
						BurstBPS:   64000,
					}},
					Nodes: []ProviderNetworkNode{
						{Node: "node-a", Interface: "bond0.100"},
					},
				}.Validate()
			},
			invalid: func() error {
				return ProviderNetwork{
					Name: "physnet-a",
					Nodes: []ProviderNetworkNode{
						{Node: "node-a"},
					},
				}.Validate()
			},
			wantErr: "provider network interface or interfaces are required",
		},
		{
			name: "provider network isolation",
			valid: func() error {
				return ProviderNetwork{
					Name:      "physnet-a",
					Isolation: "shared",
					Nodes: []ProviderNetworkNode{
						{Node: "node-a", Interface: "bond0.100"},
					},
				}.Validate()
			},
			invalid: func() error {
				return ProviderNetwork{
					Name:      "physnet-a",
					Isolation: "tenant",
					Nodes: []ProviderNetworkNode{
						{Node: "node-a", Interface: "bond0.100"},
					},
				}.Validate()
			},
			wantErr: "provider network isolation",
		},
		{
			name: "provider network qos",
			valid: func() error {
				return ProviderNetwork{
					Name: "physnet-a",
					QoS: ProviderNetworkQoS{
						EgressRateBPS: 1000000000,
					},
					Nodes: []ProviderNetworkNode{
						{Node: "node-a", Interface: "bond0.100"},
					},
				}.Validate()
			},
			invalid: func() error {
				return ProviderNetwork{
					Name: "physnet-a",
					QoS: ProviderNetworkQoS{
						EgressBurstBPS: 64000,
					},
					Nodes: []ProviderNetworkNode{
						{Node: "node-a", Interface: "bond0.100"},
					},
				}.Validate()
			},
			wantErr: "provider network qos",
		},
		{
			name: "gateway",
			valid: func() error {
				return Gateway{
					Name:       "gw-a",
					VPC:        "prod",
					Node:       "node-a",
					ExternalIF: "eth0",
					LANIP:      netip.MustParseAddr("10.10.0.254"),
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
						Priority:  100,
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
						Priority:  100,
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

func TestProviderNetworkRejectsInvalidTenantQueues(t *testing.T) {
	tests := []struct {
		name    string
		queues  []ProviderNetworkTenantQueuePolicy
		wantErr string
	}{
		{
			name: "missing rate",
			queues: []ProviderNetworkTenantQueuePolicy{{
				Tenant:  "prod",
				QueueID: 10,
			}},
			wantErr: "min_rate_bps or max_rate_bps is required",
		},
		{
			name: "duplicate selector",
			queues: []ProviderNetworkTenantQueuePolicy{{
				Tenant:     "prod",
				QueueID:    10,
				MaxRateBPS: 500000000,
			}, {
				Tenant:     "prod",
				QueueID:    11,
				MaxRateBPS: 500000000,
			}},
			wantErr: `provider network tenant queue selector "prod|" is duplicated`,
		},
		{
			name: "duplicate queue id",
			queues: []ProviderNetworkTenantQueuePolicy{{
				Tenant:     "prod",
				QueueID:    10,
				MaxRateBPS: 500000000,
			}, {
				Tenant:     "dev",
				QueueID:    10,
				MaxRateBPS: 100000000,
			}},
			wantErr: "provider network tenant queue id 10 is duplicated",
		},
		{
			name: "ports require protocol",
			queues: []ProviderNetworkTenantQueuePolicy{{
				Tenant:     "prod",
				QueueID:    10,
				Ports:      []PortRange{{From: 443, To: 443}},
				MaxRateBPS: 500000000,
			}},
			wantErr: "ports require protocol",
		},
		{
			name: "invalid endpoint selector",
			queues: []ProviderNetworkTenantQueuePolicy{{
				Tenant:           "prod",
				QueueID:          10,
				EndpointSelector: Labels{"": "web"},
				MaxRateBPS:       500000000,
			}},
			wantErr: "endpoint_selector: label key is required",
		},
		{
			name: "invalid identity selector",
			queues: []ProviderNetworkTenantQueuePolicy{{
				Tenant:           "prod",
				QueueID:          10,
				IdentitySelector: Labels{"bad key": "frontend"},
				MaxRateBPS:       500000000,
			}},
			wantErr: "identity_selector",
		},
		{
			name: "duplicate identity group",
			queues: []ProviderNetworkTenantQueuePolicy{{
				Tenant:         "prod",
				QueueID:        10,
				IdentityGroups: []string{"frontend", "frontend"},
				MaxRateBPS:     500000000,
			}},
			wantErr: `identity group "frontend" is duplicated`,
		},
		{
			name: "invalid identity group",
			queues: []ProviderNetworkTenantQueuePolicy{{
				Tenant:         "prod",
				QueueID:        10,
				IdentityGroups: []string{"bad group"},
				MaxRateBPS:     500000000,
			}},
			wantErr: "must not contain whitespace",
		},
		{
			name: "large port range",
			queues: []ProviderNetworkTenantQueuePolicy{{
				Tenant:     "prod",
				QueueID:    10,
				Protocol:   ProtocolTCP,
				Ports:      []PortRange{{From: 1, To: 2000}},
				MaxRateBPS: 500000000,
			}},
			wantErr: "range must not exceed 1024 ports",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ProviderNetwork{
				Name:         "physnet-a",
				TenantQueues: tt.queues,
				Nodes: []ProviderNetworkNode{
					{Node: "node-a", Interface: "bond0.100"},
				},
			}.Validate()
			if err == nil {
				t.Fatal("expected invalid tenant queues to fail")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestProviderNetworkAcceptsMultipleTenantQueueSelectors(t *testing.T) {
	err := ProviderNetwork{
		Name: "physnet-a",
		TenantQueues: []ProviderNetworkTenantQueuePolicy{{
			Tenant:     "prod",
			QueueID:    10,
			MaxRateBPS: 500000000,
		}, {
			Tenant:   "prod",
			QueueID:  11,
			Protocol: ProtocolTCP,
			Ports:    []PortRange{{From: 443, To: 443}},
			EndpointSelector: Labels{
				"app": "web",
			},
			EndpointExpressions: []LabelExpr{{
				Key:      "env",
				Operator: "In",
				Values:   []string{"prod"},
			}},
			IdentitySelector: Labels{
				"tier": "frontend",
			},
			IdentityExpressions: []LabelExpr{{
				Key:      "role",
				Operator: "In",
				Values:   []string{"api"},
			}},
			IdentityGroups: []string{"frontend-api"},
			MaxRateBPS:     100000000,
		}},
		Nodes: []ProviderNetworkNode{
			{Node: "node-a", Interface: "bond0.100"},
		},
	}.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestIdentityGroupValidation(t *testing.T) {
	group := IdentityGroup{
		Name:        "frontend-api",
		VPC:         "prod",
		Source:      "cmdb/team-a",
		ObservedAt:  time.Date(2026, 7, 10, 1, 2, 3, 0, time.UTC),
		TTLSeconds:  300,
		EndpointIDs: []string{"pod-a"},
		EndpointSelector: Labels{
			"tier": "frontend",
		},
		EndpointExpressions: []LabelExpr{{
			Key:      "role",
			Operator: "In",
			Values:   []string{"api"},
		}},
	}
	if err := group.Validate(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		group   IdentityGroup
		wantErr string
	}{
		{name: "name required", group: IdentityGroup{VPC: "prod", EndpointIDs: []string{"pod-a"}}, wantErr: "name is required"},
		{name: "vpc required", group: IdentityGroup{Name: "frontend", EndpointIDs: []string{"pod-a"}}, wantErr: "vpc is required"},
		{name: "membership required", group: IdentityGroup{Name: "frontend", VPC: "prod"}, wantErr: "requires endpoint_ids or endpoint selector"},
		{name: "duplicate endpoint", group: IdentityGroup{Name: "frontend", VPC: "prod", EndpointIDs: []string{"pod-a", "pod-a"}}, wantErr: "duplicated"},
		{name: "source whitespace", group: IdentityGroup{Name: "frontend", VPC: "prod", Source: " cmdb", EndpointIDs: []string{"pod-a"}}, wantErr: "source"},
		{name: "ttl requires observed_at", group: IdentityGroup{Name: "frontend", VPC: "prod", TTLSeconds: 60, EndpointIDs: []string{"pod-a"}}, wantErr: "ttl_seconds requires observed_at"},
		{name: "invalid selector", group: IdentityGroup{Name: "frontend", VPC: "prod", EndpointSelector: Labels{"": "frontend"}}, wantErr: "endpoint_selector"},
		{name: "invalid expression", group: IdentityGroup{Name: "frontend", VPC: "prod", EndpointExpressions: []LabelExpr{{Key: "role", Operator: "In"}}}, wantErr: "requires values"},
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

func TestIdentityGroupExpiry(t *testing.T) {
	group := IdentityGroup{
		Name:        "frontend",
		VPC:         "prod",
		ObservedAt:  time.Date(2026, 7, 10, 1, 0, 0, 0, time.UTC),
		TTLSeconds:  60,
		EndpointIDs: []string{"pod-a"},
	}
	if got := group.ExpiresAt(); !got.Equal(time.Date(2026, 7, 10, 1, 1, 0, 0, time.UTC)) {
		t.Fatalf("ExpiresAt() = %s, want 2026-07-10T01:01:00Z", got)
	}
	if group.Expired(time.Date(2026, 7, 10, 1, 0, 59, 0, time.UTC)) {
		t.Fatal("group expired before expires_at")
	}
	if !group.Expired(time.Date(2026, 7, 10, 1, 1, 0, 0, time.UTC)) {
		t.Fatal("group should expire at expires_at")
	}
}

func TestProviderNetworkRejectsDuplicateNodes(t *testing.T) {
	err := ProviderNetwork{
		Name: "physnet-a",
		Nodes: []ProviderNetworkNode{
			{Node: "node-a", Interface: "eth1"},
			{Node: "node-a", Interface: "eth2"},
		},
	}.Validate()
	if err == nil {
		t.Fatal("expected duplicate provider network node to fail")
	}
	if !strings.Contains(err.Error(), `provider network node "node-a" is duplicated`) {
		t.Fatalf("error %q does not mention duplicate provider network node", err)
	}
}

func TestProviderNetworkAcceptsCandidateInterfaces(t *testing.T) {
	err := ProviderNetwork{
		Name: "physnet-a",
		Nodes: []ProviderNetworkNode{
			{Node: "node-a", Interfaces: []string{"ens5", "eth1"}},
		},
	}.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestProviderNetworkRejectsDuplicateCandidateInterfaces(t *testing.T) {
	err := ProviderNetwork{
		Name: "physnet-a",
		Nodes: []ProviderNetworkNode{
			{Node: "node-a", Interfaces: []string{"eth1", "eth1"}},
		},
	}.Validate()
	if err == nil {
		t.Fatal("expected duplicate candidate interfaces to fail")
	}
	if !strings.Contains(err.Error(), `provider network candidate interface "eth1" is duplicated`) {
		t.Fatalf("error %q does not mention duplicate candidate interface", err)
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

func TestModelRejectsUnspecifiedConcreteAddresses(t *testing.T) {
	tests := []struct {
		name    string
		valid   func() error
		wantErr string
	}{
		{
			name: "subnet gateway",
			valid: func() error {
				return Subnet{
					Name:    "apps",
					VPC:     "prod",
					CIDR:    netip.MustParsePrefix("0.0.0.0/24"),
					Gateway: netip.MustParseAddr("0.0.0.0"),
				}.Validate()
			},
			wantErr: "subnet gateway must not be unspecified",
		},
		{
			name: "dhcp dns server",
			valid: func() error {
				return DHCPOptions{
					Enabled:    true,
					DNSServers: []netip.Addr{netip.MustParseAddr("0.0.0.0")},
				}.Validate()
			},
			wantErr: "dhcp dns server 0 must not be unspecified",
		},
		{
			name: "endpoint ip",
			valid: func() error {
				return Endpoint{
					ID:     "pod-a",
					VPC:    "prod",
					Subnet: "apps",
					IP:     netip.MustParseAddr("0.0.0.0"),
					Node:   "node-a",
				}.Validate()
			},
			wantErr: "endpoint ip must not be unspecified",
		},
		{
			name: "route next hop",
			valid: func() error {
				return Route{
					Destination: netip.MustParsePrefix("198.51.100.0/24"),
					NextHops:    []netip.Addr{netip.MustParseAddr("0.0.0.0")},
				}.Validate()
			},
			wantErr: "route next hop must not be unspecified",
		},
		{
			name: "policy route next hop",
			valid: func() error {
				return PolicyRoute{
					Name:     "egress",
					VPC:      "prod",
					Priority: 100,
					Match:    RouteMatch{Destination: netip.MustParsePrefix("198.51.100.0/24")},
					Action:   RouteAction{Type: ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("0.0.0.0")}},
				}.Validate()
			},
			wantErr: "policy route reroute next hop 0 must not be unspecified",
		},
		{
			name: "gateway lan ip",
			valid: func() error {
				return Gateway{
					Name:       "gw-a",
					VPC:        "prod",
					Node:       "node-a",
					ExternalIF: "eth0",
					LANIP:      netip.MustParseAddr("0.0.0.0"),
				}.Validate()
			},
			wantErr: "gateway lan ip must not be unspecified",
		},
		{
			name: "nat external ip",
			valid: func() error {
				return NATRule{
					Name:       "egress",
					VPC:        "prod",
					Type:       ActionSNAT,
					MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
					ExternalIP: netip.MustParseAddr("0.0.0.0"),
				}.Validate()
			},
			wantErr: "nat external ip must not be unspecified",
		},
		{
			name: "dnat target ip",
			valid: func() error {
				return NATRule{
					Name:       "web",
					VPC:        "prod",
					Type:       ActionDNAT,
					ExternalIP: netip.MustParseAddr("198.51.100.10"),
					TargetIP:   netip.MustParseAddr("0.0.0.0"),
				}.Validate()
			},
			wantErr: "dnat target ip must not be unspecified",
		},
		{
			name: "load balancer vip",
			valid: func() error {
				return LoadBalancer{
					Name: "web",
					VPC:  "prod",
					VIP:  netip.MustParseAddr("0.0.0.0"),
					Ports: []LoadBalancerPort{{
						Port:     80,
						Protocol: ProtocolTCP,
						Backends: []LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080}},
					}},
				}.Validate()
			},
			wantErr: "load balancer vip must not be unspecified",
		},
		{
			name: "load balancer backend",
			valid: func() error {
				return LoadBalancerBackend{IP: netip.MustParseAddr("0.0.0.0"), Port: 8080}.Validate()
			},
			wantErr: "backend ip must not be unspecified",
		},
		{
			name: "dns record ip",
			valid: func() error {
				return DNSRecord{
					Name: "api.example.com",
					IPs:  []netip.Addr{netip.MustParseAddr("0.0.0.0")},
				}.Validate()
			},
			wantErr: "dns record ip 0 must not be unspecified",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.valid()
			if err == nil {
				t.Fatal("expected validation to fail")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestModelRejectsUnmaskedPrefixes(t *testing.T) {
	tests := []struct {
		name    string
		valid   func() error
		wantErr string
	}{
		{
			name: "subnet cidr",
			valid: func() error {
				return Subnet{
					Name:    "apps",
					VPC:     "prod",
					CIDR:    netip.MustParsePrefix("10.10.0.10/24"),
					Gateway: netip.MustParseAddr("10.10.0.1"),
				}.Validate()
			},
			wantErr: "subnet cidr must be masked",
		},
		{
			name: "subnet exclude cidr",
			valid: func() error {
				return Subnet{
					Name:         "apps",
					VPC:          "prod",
					CIDR:         netip.MustParsePrefix("10.10.0.0/24"),
					Gateway:      netip.MustParseAddr("10.10.0.1"),
					ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("10.10.0.20/28")},
				}.Validate()
			},
			wantErr: "subnet exclude cidr 0 must be masked",
		},
		{
			name: "route destination",
			valid: func() error {
				return Route{
					Destination: netip.MustParsePrefix("198.51.100.10/24"),
					NextHops:    []netip.Addr{netip.MustParseAddr("198.51.100.1")},
				}.Validate()
			},
			wantErr: "route destination must be masked",
		},
		{
			name: "policy route source",
			valid: func() error {
				return PolicyRoute{
					Name:     "egress",
					VPC:      "prod",
					Priority: 100,
					Match:    RouteMatch{Source: netip.MustParsePrefix("10.10.0.10/24")},
					Action:   RouteAction{Type: ActionDrop},
				}.Validate()
			},
			wantErr: "source prefix must be masked",
		},
		{
			name: "policy route destination",
			valid: func() error {
				return PolicyRoute{
					Name:     "egress",
					VPC:      "prod",
					Priority: 100,
					Match:    RouteMatch{Destination: netip.MustParsePrefix("198.51.100.10/24")},
					Action:   RouteAction{Type: ActionDrop},
				}.Validate()
			},
			wantErr: "destination prefix must be masked",
		},
		{
			name: "snat match cidr",
			valid: func() error {
				return NATRule{
					Name:       "egress",
					VPC:        "prod",
					Type:       ActionSNAT,
					MatchCIDR:  netip.MustParsePrefix("10.10.0.10/24"),
					ExternalIP: netip.MustParseAddr("198.51.100.10"),
				}.Validate()
			},
			wantErr: "snat match cidr must be masked",
		},
		{
			name: "remote cidr",
			valid: func() error {
				return SecurityGroupRule{
					ID:         "allow-corp",
					Priority:   100,
					Direction:  DirectionEgress,
					Protocol:   ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("198.51.100.10/24"),
					Ports:      []PortRange{{From: 443, To: 443}},
					Action:     ActionAllow,
				}.Validate()
			},
			wantErr: "remote cidr must be masked",
		},
		{
			name: "remote cidr except",
			valid: func() error {
				return SecurityGroupRule{
					ID:          "allow-corp",
					Priority:    100,
					Direction:   DirectionEgress,
					Protocol:    ProtocolTCP,
					RemoteCIDR:  netip.MustParsePrefix("198.51.100.0/24"),
					ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/28")},
					Ports:       []PortRange{{From: 443, To: 443}},
					Action:      ActionAllow,
				}.Validate()
			},
			wantErr: "except cidr 0 must be masked",
		},
		{
			name: "cidr group cidr",
			valid: func() error {
				return CIDRGroup{
					Name:  "corp",
					VPC:   "prod",
					CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/24")},
				}.Validate()
			},
			wantErr: "cidr group cidr 0 must be masked",
		},
		{
			name: "cidr group entry",
			valid: func() error {
				return CIDRGroupEntry{
					CIDR: netip.MustParsePrefix("198.51.100.10/24"),
				}.Validate()
			},
			wantErr: "cidr must be masked",
		},
		{
			name: "cidr group entry except",
			valid: func() error {
				return CIDRGroupEntry{
					CIDR:        netip.MustParsePrefix("198.51.100.0/24"),
					ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/28")},
				}.Validate()
			},
			wantErr: "except cidr 0 must be masked",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.valid()
			if err == nil {
				t.Fatal("expected validation to fail")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
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

	subnet.DHCP = DHCPOptions{DNSServers: []netip.Addr{netip.MustParseAddr("10.96.0.10")}}
	err = subnet.Validate()
	if err == nil || !strings.Contains(err.Error(), "disabled dhcp") {
		t.Fatalf("error = %v, want disabled dhcp dns validation", err)
	}

	subnet.DHCP = DHCPOptions{Enabled: true, DNSServers: []netip.Addr{netip.Addr{}}}
	err = subnet.Validate()
	if err == nil || !strings.Contains(err.Error(), "dns server 0 is invalid") {
		t.Fatalf("error = %v, want invalid dns server validation", err)
	}

	subnet.DHCP = DHCPOptions{Enabled: true, DNSServers: []netip.Addr{netip.MustParseAddr("fd00:96::10")}}
	err = subnet.Validate()
	if err == nil || !strings.Contains(err.Error(), "family must match subnet cidr") {
		t.Fatalf("error = %v, want subnet/dns family validation", err)
	}

	subnet.DHCP = DHCPOptions{Enabled: true, DomainName: "bad domain"}
	err = subnet.Validate()
	if err == nil || !strings.Contains(err.Error(), "dhcp domain name") {
		t.Fatalf("error = %v, want invalid domain validation", err)
	}

	subnet.DHCP = DHCPOptions{Enabled: true, DomainName: "svc..cluster.local"}
	err = subnet.Validate()
	if err == nil || !strings.Contains(err.Error(), "empty label") {
		t.Fatalf("error = %v, want empty dhcp domain label validation", err)
	}

	subnet.DHCP = DHCPOptions{Enabled: true, SearchDomains: []string{"cluster..local"}}
	err = subnet.Validate()
	if err == nil || !strings.Contains(err.Error(), "empty label") {
		t.Fatalf("error = %v, want empty dhcp search domain label validation", err)
	}

	subnet.DHCP = DHCPOptions{
		Enabled:       true,
		DNSServers:    []netip.Addr{netip.MustParseAddr("10.96.0.10")},
		DomainName:    "svc.cluster.local.",
		SearchDomains: []string{"cluster.local", "svc.cluster.local."},
	}
	if err := subnet.Validate(); err != nil {
		t.Fatalf("valid dhcp dns options failed: %v", err)
	}

	ipv6Subnet := Subnet{
		Name:    "appsv6",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("fd00:10::/64"),
		Gateway: netip.MustParseAddr("fd00:10::1"),
		DHCP: DHCPOptions{
			Enabled:       true,
			DNSServers:    []netip.Addr{netip.MustParseAddr("fd00:96::10")},
			DomainName:    "svc.cluster.local",
			SearchDomains: []string{"cluster.local"},
		},
	}
	if err := ipv6Subnet.Validate(); err != nil {
		t.Fatalf("valid ipv6 dhcp dns options failed: %v", err)
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
			Priority:  100,
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

func TestSecurityGroupRejectsDuplicateRuleIDs(t *testing.T) {
	group := SecurityGroup{
		Name: "web",
		VPC:  "prod",
		Rules: []SecurityGroupRule{
			{
				ID:        "allow-api",
				Priority:  100,
				Direction: DirectionIngress,
				Protocol:  ProtocolTCP,
				Ports:     []PortRange{{From: 443, To: 443}},
				Action:    ActionAllow,
			},
			{
				ID:        "allow-api",
				Priority:  100,
				Direction: DirectionEgress,
				Protocol:  ProtocolTCP,
				Ports:     []PortRange{{From: 443, To: 443}},
				Action:    ActionDrop,
			},
		},
	}

	err := group.Validate()
	if err == nil || !strings.Contains(err.Error(), "security group rule \"allow-api\" is duplicated") {
		t.Fatalf("error = %v, want duplicate security group rule id validation", err)
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
	for _, priority := range []int{-1, 0, SecurityGroupPriorityMax + 1} {
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

	route.Action.NextHops = []netip.Addr{netip.MustParseAddr("10.10.0.254")}
	if err := route.Validate(); err != nil {
		t.Fatal(err)
	}

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

func TestPolicyRoutePriorityValidation(t *testing.T) {
	valid := PolicyRoute{
		Name:     "allow-web",
		VPC:      "prod",
		Priority: PolicyRoutePriorityMax,
		Match:    RouteMatch{Destination: netip.MustParsePrefix("198.51.100.0/24")},
		Action:   RouteAction{Type: ActionAllow},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid policy route priority failed: %v", err)
	}
	for _, priority := range []int{PolicyRoutePriorityMin - 1, PolicyRoutePriorityMax + 1} {
		invalid := valid
		invalid.Priority = priority
		if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), "priority") {
			t.Fatalf("priority %d error = %v, want priority validation", priority, err)
		}
	}
}

func TestPolicyRouteSupportsRejectAction(t *testing.T) {
	route := PolicyRoute{
		Name:     "reject-lab",
		VPC:      "prod",
		Priority: 100,
		Match: RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("198.51.100.0/24"),
			Protocol:    ProtocolTCP,
			DstPorts:    []PortRange{{From: 443, To: 443}},
		},
		Action: RouteAction{Type: ActionReject},
	}
	if err := route.Validate(); err != nil {
		t.Fatalf("reject policy route should validate: %v", err)
	}
}

func TestPolicyRouteMatchValidatesSourcePorts(t *testing.T) {
	match := RouteMatch{
		Source:      netip.MustParsePrefix("10.10.0.0/24"),
		Destination: netip.MustParsePrefix("198.51.100.0/24"),
		Protocol:    ProtocolTCP,
		SrcPorts:    []PortRange{{From: 1024, To: 65535}},
		DstPorts:    []PortRange{{From: 443, To: 443}},
	}
	if err := match.Validate(); err != nil {
		t.Fatal(err)
	}

	match.Protocol = ProtocolICMP
	if err := match.Validate(); err == nil || !strings.Contains(err.Error(), "src ports require tcp or udp protocol") {
		t.Fatalf("error = %v, want src port protocol validation", err)
	}

	match.Protocol = ProtocolTCP
	match.SrcPorts = []PortRange{{From: 9000, To: 8000}}
	if err := match.Validate(); err == nil || !strings.Contains(err.Error(), "src port range 0") {
		t.Fatalf("error = %v, want src port range validation", err)
	}
}

func TestPolicyRouteRejectsNextHopsForNonRerouteActions(t *testing.T) {
	for _, action := range []Action{ActionAllow, ActionDrop, ActionReject} {
		route := PolicyRoute{
			Name:     "non-reroute",
			VPC:      "prod",
			Priority: 100,
			Match: RouteMatch{
				Destination: netip.MustParsePrefix("172.16.0.0/16"),
			},
			Action: RouteAction{
				Type:     action,
				NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.254")},
			},
		}
		err := route.Validate()
		if err == nil {
			t.Fatalf("expected %s policy route with next hops to fail", action)
		}
		if !strings.Contains(err.Error(), "only supported for reroute") {
			t.Fatalf("error %q does not mention reroute-only next hops", err)
		}
	}
}

func TestRouteRejectsMixedIPFamilies(t *testing.T) {
	route := Route{
		Destination: netip.MustParsePrefix("fd00:10::/64"),
		NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
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

	route.NextHops = append(route.NextHops, netip.MustParseAddr("10.10.0.253"))
	err := route.Validate()
	if err == nil {
		t.Fatal("expected duplicate ECMP next hop to fail")
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
	route.Action = RouteAction{Type: ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.254")}}
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
		Priority:  100,
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
			Priority:  100,
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
		Priority:  100,
		Direction: DirectionIngress,
		Protocol:  ProtocolUDP,
		Ports:     []PortRange{{From: 53, To: 53}},
		Action:    ActionAllow,
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}

	rule.Ports = []PortRange{{From: 53, To: 53}, {From: 53, To: 53}}
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("error = %v, want duplicate port range validation", err)
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

func TestEndpointRejectsDuplicateSecurityGroups(t *testing.T) {
	endpoint := Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"web", "web"},
	}
	if err := endpoint.Validate(); err == nil || !strings.Contains(err.Error(), "security group \"web\" is duplicated") {
		t.Fatalf("error = %v, want duplicate security group validation", err)
	}

	endpoint.SecurityGroups = []string{""}
	if err := endpoint.Validate(); err == nil || !strings.Contains(err.Error(), "security group is empty") {
		t.Fatalf("error = %v, want empty security group validation", err)
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

func TestSubnetGatewayMACIncludesNetworkContext(t *testing.T) {
	ip := netip.MustParseAddr("10.10.0.1")
	first := SubnetGatewayMAC("prod", "apps", ip)
	if first != "0a:58:3e:f3:95:f0" {
		t.Fatalf("subnet gateway mac = %s", first)
	}
	if first == GatewayMAC(ip) {
		t.Fatalf("subnet gateway mac should not use only gateway ip: %s", first)
	}
	if first != SubnetGatewayMAC("prod", "apps", ip) {
		t.Fatal("subnet gateway mac must be deterministic")
	}
	for _, got := range []string{
		SubnetGatewayMAC("stage", "apps", ip),
		SubnetGatewayMAC("prod", "dmz", ip),
	} {
		if got == first {
			t.Fatalf("subnet gateway mac collision: %s", got)
		}
	}
}

func TestGatewayRequiresExternalInterface(t *testing.T) {
	gateway := Gateway{
		Name:  "gw-a",
		VPC:   "prod",
		Node:  "node-a",
		LANIP: netip.MustParseAddr("10.10.0.254"),
	}
	if err := gateway.Validate(); err == nil || !strings.Contains(err.Error(), "gateway external_if is required") {
		t.Fatalf("error = %v, want missing external_if validation", err)
	}
}

func TestSecurityGroupRuleValidatesNamedPorts(t *testing.T) {
	rule := SecurityGroupRule{
		ID:         "allow-http",
		Priority:   100,
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

	rule.NamedPorts = []string{"http"}
	rule.Direction = DirectionEgress
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "egress named ports require remote_group or remote_endpoint_selector") {
		t.Fatalf("error = %v, want egress remote endpoint source validation", err)
	}

	rule.RemoteGroup = "web"
	if err := rule.Validate(); err != nil {
		t.Fatalf("egress remote group named port should validate: %v", err)
	}

	rule.RemoteGroup = ""
	rule.RemoteEndpointSelector = Labels{"app": "web"}
	if err := rule.Validate(); err != nil {
		t.Fatalf("egress remote endpoint selector named port should validate: %v", err)
	}

	rule.RemoteEndpointSelector = nil
	rule.RemoteEndpointExprs = []LabelExpr{{Key: "app", Operator: "Exists"}}
	if err := rule.Validate(); err != nil {
		t.Fatalf("egress remote endpoint expression named port should validate: %v", err)
	}
}

func TestSecurityGroupRuleValidatesICMPTypeAndCode(t *testing.T) {
	icmpType := uint8(8)
	icmpCode := uint8(0)
	rule := SecurityGroupRule{
		ID:        "icmp-echo",
		Priority:  100,
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
		Priority:  100,
		Direction: DirectionEgress,
		Protocol:  ProtocolTCP,
		RemoteFQDNs: []FQDNSelector{
			{MatchName: "api.example.com."},
			{MatchPattern: "*.svc.example.com"},
			{MatchPattern: "**.deep.example.com"},
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
				Priority:    100,
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
				Priority:    100,
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
				Priority:    100,
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
				Priority:    100,
				Direction:   DirectionEgress,
				Protocol:    ProtocolTCP,
				RemoteFQDNs: []FQDNSelector{{MatchName: "api example.com"}},
				Action:      ActionAllow,
			},
			wantErr: "unsupported character",
		},
		{
			name: "empty match name label",
			rule: SecurityGroupRule{
				ID:          "bad-empty-label",
				Priority:    100,
				Direction:   DirectionEgress,
				Protocol:    ProtocolTCP,
				RemoteFQDNs: []FQDNSelector{{MatchName: "api..example.com"}},
				Action:      ActionAllow,
			},
			wantErr: "empty label",
		},
		{
			name: "empty match pattern label",
			rule: SecurityGroupRule{
				ID:          "bad-pattern-empty-label",
				Priority:    100,
				Direction:   DirectionEgress,
				Protocol:    ProtocolTCP,
				RemoteFQDNs: []FQDNSelector{{MatchPattern: "*.bad..example.com"}},
				Action:      ActionAllow,
			},
			wantErr: "empty label",
		},
		{
			name: "match name wildcard",
			rule: SecurityGroupRule{
				ID:          "bad-name-wildcard",
				Priority:    100,
				Direction:   DirectionEgress,
				Protocol:    ProtocolTCP,
				RemoteFQDNs: []FQDNSelector{{MatchName: "*.example.com"}},
				Action:      ActionAllow,
			},
			wantErr: "unsupported character",
		},
		{
			name: "label starts with hyphen",
			rule: SecurityGroupRule{
				ID:          "bad-label-hyphen",
				Priority:    100,
				Direction:   DirectionEgress,
				Protocol:    ProtocolTCP,
				RemoteFQDNs: []FQDNSelector{{MatchName: "-api.example.com"}},
				Action:      ActionAllow,
			},
			wantErr: "must not start or end",
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
		Priority:       100,
		Direction:      DirectionEgress,
		Protocol:       ProtocolTCP,
		RemoteEntities: []string{"all", "world", "world-ipv4", "world-ipv6", "host", "remote-node"},
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

	rule.RemoteEntities = []string{"none", "world"}
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "none must not be combined") {
		t.Fatalf("error = %v, want none exclusivity validation", err)
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
	rootedRecord := DNSRecord{Name: "api.example.com.", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.12")}}
	if err := rootedRecord.Validate(); err != nil {
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
		Name: "api..example.com",
		IPs:  []netip.Addr{netip.MustParseAddr("203.0.113.10")},
	}).Validate(); err == nil || !strings.Contains(err.Error(), "empty label") {
		t.Fatalf("error = %v, want empty label validation", err)
	}
	if err := (DNSRecord{
		Name: "-api.example.com",
		IPs:  []netip.Addr{netip.MustParseAddr("203.0.113.10")},
	}).Validate(); err == nil || !strings.Contains(err.Error(), "must not start or end") {
		t.Fatalf("error = %v, want hyphen boundary validation", err)
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
	if err := (DNSRecord{
		Name: "api.example.com",
		IPs: []netip.Addr{
			netip.MustParseAddr("203.0.113.10"),
			netip.MustParseAddr("203.0.113.10"),
		},
	}).Validate(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("error = %v, want duplicate dns record ip validation", err)
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
		{name: "duplicate cidr", group: CIDRGroup{Name: "corp", VPC: "prod", CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.20.0.0/16")}}, wantErr: "duplicated"},
		{name: "duplicate entry cidr", group: CIDRGroup{Name: "corp", VPC: "prod", CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, Entries: []CIDRGroupEntry{{CIDR: netip.MustParsePrefix("10.20.0.0/16")}}}, wantErr: "duplicated"},
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
		Priority:        100,
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
		Priority:               100,
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

func TestSecurityGroupRuleValidatesRemoteEndpointExpressions(t *testing.T) {
	rule := SecurityGroupRule{
		ID:        "allow-web",
		Priority:  100,
		Direction: DirectionIngress,
		Protocol:  ProtocolTCP,
		RemoteEndpointExprs: []LabelExpr{
			{Key: "env", Operator: "In", Values: []string{"prod", "staging"}},
			{Key: "deprecated", Operator: "DoesNotExist"},
		},
		Ports:  []PortRange{{From: 8080, To: 8080}},
		Action: ActionAllow,
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}

	if !(Labels{"env": "prod", "app": "client"}).MatchesSelector(nil, rule.RemoteEndpointExprs) {
		t.Fatal("expected label expressions to match prod endpoint without deprecated label")
	}
	if (Labels{"env": "dev", "app": "client"}).MatchesSelector(nil, rule.RemoteEndpointExprs) {
		t.Fatal("expected label expressions to reject dev endpoint")
	}

	rule.RemoteEndpointExprs = []LabelExpr{{Key: "env", Operator: "In"}}
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "requires values") {
		t.Fatalf("error = %v, want missing expression values validation", err)
	}

	rule.RemoteEndpointExprs = []LabelExpr{{Key: "env", Operator: "Exists", Values: []string{"prod"}}}
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "must not set values") {
		t.Fatalf("error = %v, want exists expression values validation", err)
	}

	rule.RemoteEndpointExprs = []LabelExpr{{Key: "env", Operator: "GreaterThan", Values: []string{"prod"}}}
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported label expression operator") {
		t.Fatalf("error = %v, want unsupported operator validation", err)
	}
}

func TestSecurityGroupRuleValidatesRemoteService(t *testing.T) {
	rule := SecurityGroupRule{
		ID:            "allow-web-service",
		Priority:      100,
		Direction:     DirectionEgress,
		Protocol:      ProtocolAny,
		RemoteService: "web",
		Action:        ActionAllow,
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}

	rule.Ports = []PortRange{{From: 80, To: 80}}
	if err := rule.Validate(); err != nil {
		t.Fatalf("remote service with any protocol and explicit port should validate: %v", err)
	}

	rule.Ports = nil
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
		Priority:    100,
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
				Priority:        100,
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
				Priority:    100,
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
				Priority:    100,
				Direction:   DirectionEgress,
				Protocol:    ProtocolTCP,
				RemoteCIDR:  netip.MustParsePrefix("10.20.0.0/16"),
				ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")},
				Action:      ActionAllow,
			},
			wantErr: "must be contained",
		},
		{
			name: "duplicate except cidr",
			rule: SecurityGroupRule{
				ID:          "bad-duplicate",
				Priority:    100,
				Direction:   DirectionEgress,
				Protocol:    ProtocolTCP,
				RemoteCIDR:  netip.MustParsePrefix("10.20.0.0/16"),
				ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.10.0/24"), netip.MustParsePrefix("10.20.10.0/24")},
				Action:      ActionAllow,
			},
			wantErr: "duplicated",
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
			name: "dnat protocol requires port mapping",
			rule: NATRule{
				Name:       "broken-dnat-protocol",
				VPC:        "prod",
				Type:       ActionDNAT,
				ExternalIP: netip.MustParseAddr("198.51.100.61"),
				TargetIP:   netip.MustParseAddr("10.10.0.13"),
				Protocol:   ProtocolTCP,
			},
			wantErr: "dnat protocol must be any",
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
			name: "floating ip port translation",
			rule: NATRule{
				Name:         "fip-translation",
				VPC:          "prod",
				Type:         ActionDNATSNAT,
				ExternalIP:   netip.MustParseAddr("198.51.100.71"),
				TargetIP:     netip.MustParseAddr("10.10.0.15"),
				Protocol:     ProtocolTCP,
				ExternalPort: 8443,
				TargetPort:   443,
			},
		},
		{
			name: "floating ip port translation protocol required",
			rule: NATRule{
				Name:         "broken-fip-port",
				VPC:          "prod",
				Type:         ActionDNATSNAT,
				ExternalIP:   netip.MustParseAddr("198.51.100.72"),
				TargetIP:     netip.MustParseAddr("10.10.0.16"),
				ExternalPort: 8443,
				TargetPort:   443,
			},
			wantErr: "requires tcp or udp protocol",
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
	backends := []LoadBalancerBackend{{
		IP:   netip.MustParseAddr("10.10.0.10"),
		Port: 8080,
	}}
	valid := LoadBalancer{
		Name: "web",
		VPC:  "prod",
		VIP:  netip.MustParseAddr("10.96.0.10"),
		Ports: []LoadBalancerPort{{
			Port:     80,
			Protocol: ProtocolTCP,
			Backends: backends,
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
	if backends[0].Healthy != nil || !backends[0].IsHealthy() {
		t.Fatal("backend without explicit health should default to healthy")
	}
	if (LoadBalancerBackend{IP: backends[0].IP, Port: backends[0].Port, Healthy: &unhealthy}).IsHealthy() {
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
				Name: "web",
				VPC:  "prod",
				Ports: []LoadBalancerPort{{
					Port:     80,
					Backends: backends,
				}},
			},
			wantErr: "vip is required",
		},
		{
			name: "backend required",
			lb: LoadBalancer{
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Ports: []LoadBalancerPort{{
					Port: 80,
				}},
			},
			wantErr: "backends are required",
		},
		{
			name: "unsupported protocol",
			lb: LoadBalancer{
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Ports: []LoadBalancerPort{{
					Port:     80,
					Protocol: ProtocolICMP,
					Backends: backends,
				}},
			},
			wantErr: "unsupported load balancer protocol",
		},
		{
			name: "backend port required",
			lb: LoadBalancer{
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Ports: []LoadBalancerPort{{
					Port: 80,
					Backends: []LoadBalancerBackend{{
						IP: netip.MustParseAddr("10.10.0.10"),
					}},
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
				AffinityTimeout: 10800,
				Ports: []LoadBalancerPort{{
					Port:     80,
					Backends: backends,
				}},
			},
			wantErr: "affinity timeout requires session affinity",
		},
		{
			name: "affinity timeout too large",
			lb: LoadBalancer{
				Name:            "web",
				VPC:             "prod",
				VIP:             netip.MustParseAddr("10.96.0.10"),
				SessionAffinity: true,
				AffinityTimeout: 86401,
				Ports: []LoadBalancerPort{{
					Port:     80,
					Backends: backends,
				}},
			},
			wantErr: "at most 86400",
		},
		{
			name: "selection field duplicate",
			lb: LoadBalancer{
				Name:            "web",
				VPC:             "prod",
				VIP:             netip.MustParseAddr("10.96.0.10"),
				SelectionFields: []string{"ip_src", "ip_src"},
				Ports: []LoadBalancerPort{{
					Port:     80,
					Backends: backends,
				}},
			},
			wantErr: "selection field \"ip_src\" is duplicated",
		},
		{
			name: "selection field family mismatch",
			lb: LoadBalancer{
				Name:            "web",
				VPC:             "prod",
				VIP:             netip.MustParseAddr("10.96.0.10"),
				SelectionFields: []string{"ipv6_src"},
				Ports: []LoadBalancerPort{{
					Port:     80,
					Backends: backends,
				}},
			},
			wantErr: "requires IPv6 VIP",
		},
		{
			name: "selection field unsupported",
			lb: LoadBalancer{
				Name:            "web",
				VPC:             "prod",
				VIP:             netip.MustParseAddr("10.96.0.10"),
				SelectionFields: []string{"eth_src"},
				Ports: []LoadBalancerPort{{
					Port:     80,
					Backends: backends,
				}},
			},
			wantErr: "unsupported load balancer selection field",
		},
		{
			name: "backend family mismatch",
			lb: LoadBalancer{
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Ports: []LoadBalancerPort{{
					Port: 80,
					Backends: []LoadBalancerBackend{{
						IP:   netip.MustParseAddr("fd00:10::10"),
						Port: 8080,
					}},
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
				Ports: []LoadBalancerPort{{
					Port: 80,
					Backends: []LoadBalancerBackend{{
						IP:      netip.MustParseAddr("10.10.0.10"),
						Port:    8080,
						Healthy: &unhealthy,
					}},
				}},
			},
			wantErr: "at least one healthy backend",
		},
		{
			name: "duplicate backend",
			lb: LoadBalancer{
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Ports: []LoadBalancerPort{{
					Port: 80,
					Backends: []LoadBalancerBackend{
						{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080},
						{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080},
					},
				}},
			},
			wantErr: "backend 10.10.0.10:8080 is duplicated",
		},
		{
			name: "duplicate subnet",
			lb: LoadBalancer{
				Name:    "web",
				VPC:     "prod",
				VIP:     netip.MustParseAddr("10.96.0.10"),
				Subnets: []string{"apps", "apps"},
				Ports: []LoadBalancerPort{{
					Port:     80,
					Backends: backends,
				}},
			},
			wantErr: "subnet \"apps\" is duplicated",
		},
		{
			name: "disabled health check with options",
			lb: LoadBalancer{
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Ports: []LoadBalancerPort{{
					Port:     80,
					Backends: backends,
				}},
				HealthCheck: LoadBalancerHealthCheck{Interval: 5},
			},
			wantErr: "disabled health check",
		},
		{
			name: "health check interval too large",
			lb: LoadBalancer{
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Ports: []LoadBalancerPort{{
					Port:     80,
					Backends: backends,
				}},
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
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Ports: []LoadBalancerPort{{
					Port:     80,
					Backends: backends,
				}},
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

func TestLoadBalancerValidateMultiPortServiceVIP(t *testing.T) {
	lb := LoadBalancer{
		Name: "web",
		VPC:  "prod",
		VIP:  netip.MustParseAddr("10.96.0.10"),
		Ports: []LoadBalancerPort{
			{
				Name:     "http",
				Port:     80,
				Protocol: ProtocolTCP,
				Backends: []LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080}},
			},
			{
				Name:     "metrics",
				Port:     9090,
				Protocol: ProtocolTCP,
				Backends: []LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 9091}},
			},
		},
	}
	if err := lb.Validate(); err != nil {
		t.Fatal(err)
	}
	frontends := lb.Frontends()
	if len(frontends) != 2 {
		t.Fatalf("frontends = %d, want 2", len(frontends))
	}
	if frontends[0].Port != 80 || frontends[0].Backends[0].Port != 8080 {
		t.Fatalf("http frontend = %+v, want service 80 to target 8080", frontends[0])
	}
	if frontends[1].Port != 9090 || frontends[1].Backends[0].Port != 9091 {
		t.Fatalf("metrics frontend = %+v, want service 9090 to target 9091", frontends[1])
	}

	lb.Ports[1].Port = 80
	if err := lb.Validate(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("error = %v, want duplicate frontend validation", err)
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
