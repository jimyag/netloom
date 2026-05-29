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
					Name:    "apps",
					VPC:     "prod",
					CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
					Gateway: netip.MustParseAddr("10.10.0.1"),
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
