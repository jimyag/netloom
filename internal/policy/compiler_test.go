package policy

import (
	"net/netip"
	"testing"

	"github.com/jimyag/netloom/internal/model"
)

func TestCompileForEndpointSortsRulesAndPreservesACLShape(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"web"},
	}
	groups := map[string]model.SecurityGroup{
		"web": {
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{
				{
					ID:        "default-deny",
					Priority:  1,
					Direction: model.DirectionIngress,
					Protocol:  model.ProtocolAny,
					Action:    model.ActionDrop,
				},
				{
					ID:         "allow-https",
					Priority:   100,
					Direction:  model.DirectionIngress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("10.20.0.0/16"),
					Ports:      []model.PortRange{{From: 443, To: 443}},
					Action:     model.ActionAllow,
					Stateful:   true,
				},
			},
		},
	}

	program, err := CompileForEndpoint(endpoint, groups)
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Rules) != 2 {
		t.Fatalf("compiled rules = %d, want 2", len(program.Rules))
	}
	if program.Rules[0].ID != "allow-https" {
		t.Fatalf("first rule = %s, want allow-https", program.Rules[0].ID)
	}
	if program.Rules[0].Action != model.ActionAllow {
		t.Fatalf("first rule action = %s, want allow", program.Rules[0].Action)
	}
	if len(program.MapEntries) != 2 {
		t.Fatalf("compiled map entries = %d, want 2", len(program.MapEntries))
	}
	if program.MapEntries[0].RuleID != "default-deny" {
		t.Fatalf("highest precedence map entry = %s, want default-deny", program.MapEntries[0].RuleID)
	}
	if !program.MapEntries[0].Value.Deny {
		t.Fatal("default deny map entry should be marked deny")
	}
	if program.MapEntries[1].Key.L4PrefixBits != 24 {
		t.Fatalf("https l4 prefix bits = %d, want 24", program.MapEntries[1].Key.L4PrefixBits)
	}
}

func TestCompileForEndpointRejectsCrossVPCSecurityGroup(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"web"},
	}
	_, err := CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"web": {Name: "web", VPC: "dev"},
	})
	if err == nil {
		t.Fatal("expected cross-vpc security group to fail")
	}
}

func TestCompileForEndpointDecomposesPortRangesIntoLPMEntries(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"web"},
	}
	program, err := CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"web": {
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:        "range",
				Priority:  100,
				Direction: model.DirectionIngress,
				Protocol:  model.ProtocolTCP,
				Ports:     []model.PortRange{{From: 30000, To: 32767}},
				Action:    model.ActionAllow,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(program.MapEntries) == 0 {
		t.Fatal("expected port range to compile to one or more LPM entries")
	}
	for _, entry := range program.MapEntries {
		if entry.Key.L4PrefixBits <= 8 || entry.Key.L4PrefixBits > 24 {
			t.Fatalf("l4 prefix bits = %d, want port-aware prefix", entry.Key.L4PrefixBits)
		}
	}
}
