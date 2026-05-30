package policy

import (
	"net/netip"
	"sort"
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
	if program.MapEntries[1].RemoteCIDR != netip.MustParsePrefix("10.20.0.0/16") {
		t.Fatalf("https remote cidr = %s, want 10.20.0.0/16", program.MapEntries[1].RemoteCIDR)
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

func TestCompileForEndpointRejectsPortsWithoutTransportProtocol(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"web"},
	}
	_, err := CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"web": {
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:        "invalid-icmp-port",
				Direction: model.DirectionIngress,
				Protocol:  model.ProtocolICMP,
				Ports:     []model.PortRange{{From: 8, To: 8}},
				Action:    model.ActionDrop,
			}},
		},
	})
	if err == nil {
		t.Fatal("expected ICMP security group port match to fail")
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

func TestCompileForEndpointTreatsLogActionAsAllowWithLog(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"audit"},
	}
	program, err := CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"audit": {
			Name: "audit",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "log-web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("10.20.0.0/24"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionLog,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(program.MapEntries) != 1 {
		t.Fatalf("map entries = %d, want 1", len(program.MapEntries))
	}
	entry := program.MapEntries[0]
	if entry.Value.Deny {
		t.Fatal("log action should allow traffic")
	}
	if !entry.Value.Log {
		t.Fatal("log action should set log flag")
	}
}

func TestCompileForEndpointWithStateExpandsRemoteGroupMembers(t *testing.T) {
	target := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"web"},
	}
	peer := model.Endpoint{
		ID:             "pod-b",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.11"),
		Node:           "node-b",
		SecurityGroups: []string{"clients"},
	}
	other := model.Endpoint{
		ID:             "pod-c",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.12"),
		Node:           "node-b",
		SecurityGroups: []string{"other"},
	}
	program, err := CompileForEndpointWithState(target, map[string]model.SecurityGroup{
		"web": {
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:          "allow-clients",
				Priority:    100,
				Direction:   model.DirectionIngress,
				Protocol:    model.ProtocolTCP,
				RemoteGroup: "clients",
				Ports:       []model.PortRange{{From: 8080, To: 8080}},
				Action:      model.ActionAllow,
			}},
		},
		"clients": {Name: "clients", VPC: "prod"},
		"other":   {Name: "other", VPC: "prod"},
	}, []model.Endpoint{target, peer, other})
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Rules) != 1 {
		t.Fatalf("rules = %d, want one expanded remote-group member", len(program.Rules))
	}
	rule := program.Rules[0]
	if rule.RemoteEndpoint != "pod-b" {
		t.Fatalf("remote endpoint = %s, want pod-b", rule.RemoteEndpoint)
	}
	if rule.RemoteCIDR != netip.MustParsePrefix("10.10.0.11/32") {
		t.Fatalf("remote cidr = %s, want 10.10.0.11/32", rule.RemoteCIDR)
	}
	if len(program.MapEntries) != 1 {
		t.Fatalf("map entries = %d, want 1", len(program.MapEntries))
	}
	if program.MapEntries[0].Key.RemoteIdentity != EndpointIdentity("pod-b") {
		t.Fatalf("remote identity = %d, want endpoint identity", program.MapEntries[0].Key.RemoteIdentity)
	}
	if program.MapEntries[0].RemoteCIDR != netip.MustParsePrefix("10.10.0.11/32") {
		t.Fatalf("map entry remote cidr = %s, want pod-b /32", program.MapEntries[0].RemoteCIDR)
	}
}

func TestCompileForEndpointWithStateRejectsUnknownRemoteGroup(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"web"},
	}
	_, err := CompileForEndpointWithState(endpoint, map[string]model.SecurityGroup{
		"web": {
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:          "allow-missing",
				Direction:   model.DirectionIngress,
				Protocol:    model.ProtocolTCP,
				RemoteGroup: "missing",
				Ports:       []model.PortRange{{From: 8080, To: 8080}},
				Action:      model.ActionAllow,
			}},
		},
	}, []model.Endpoint{endpoint})
	if err == nil {
		t.Fatal("expected unknown remote group to fail")
	}
}

func TestCompileForEndpointWithContextExpandsRemoteFQDNsToCIDRs(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"client"},
	}
	program, err := CompileForEndpointWithContext(endpoint, map[string]model.SecurityGroup{
		"client": {
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:        "allow-api",
				Priority:  100,
				Direction: model.DirectionEgress,
				Protocol:  model.ProtocolTCP,
				RemoteFQDNs: []model.FQDNSelector{
					{MatchName: "API.EXAMPLE.COM."},
					{MatchPattern: "*.svc.example.com"},
				},
				Ports:  []model.PortRange{{From: 443, To: 443}},
				Action: model.ActionAllow,
			}},
		},
	}, CompileContext{
		DNSRecords: []model.DNSRecord{
			{Name: "api.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.10")}},
			{Name: "payments.svc.example.com", IPs: []netip.Addr{netip.MustParseAddr("2001:db8::10")}},
			{Name: "other.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.20")}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Rules) != 2 {
		t.Fatalf("rules = %d, want 2 fqdn-derived cidrs", len(program.Rules))
	}
	gotCIDRs := []string{program.Rules[0].RemoteCIDR.String(), program.Rules[1].RemoteCIDR.String()}
	sort.Strings(gotCIDRs)
	wantCIDRs := []string{"2001:db8::10/128", "203.0.113.10/32"}
	for i := range wantCIDRs {
		if gotCIDRs[i] != wantCIDRs[i] {
			t.Fatalf("fqdn cidrs = %v, want %v", gotCIDRs, wantCIDRs)
		}
	}
	if len(program.MapEntries) != 2 {
		t.Fatalf("map entries = %d, want 2", len(program.MapEntries))
	}
	for _, entry := range program.MapEntries {
		if !entry.RemoteCIDR.IsValid() {
			t.Fatalf("fqdn-derived map entry missing remote cidr: %+v", entry)
		}
		if entry.Key.RemoteIdentity == 0 {
			t.Fatalf("fqdn-derived map entry should use cidr identity: %+v", entry)
		}
	}
}

func TestCompileForEndpointWithContextUnresolvedRemoteFQDNProducesNoEntries(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"client"},
	}
	program, err := CompileForEndpointWithContext(endpoint, map[string]model.SecurityGroup{
		"client": {
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:          "allow-api",
				Priority:    100,
				Direction:   model.DirectionEgress,
				Protocol:    model.ProtocolTCP,
				RemoteFQDNs: []model.FQDNSelector{{MatchName: "api.example.com"}},
				Ports:       []model.PortRange{{From: 443, To: 443}},
				Action:      model.ActionAllow,
			}},
		},
	}, CompileContext{
		DNSRecords: []model.DNSRecord{
			{Name: "other.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.20")}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Rules) != 0 || len(program.MapEntries) != 0 {
		t.Fatalf("unresolved fqdn compiled to rules=%d entries=%d, want none", len(program.Rules), len(program.MapEntries))
	}
}

func TestCompileForEndpointWithContextExpandsRemoteCIDRGroup(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"client"},
	}
	program, err := CompileForEndpointWithContext(endpoint, map[string]model.SecurityGroup{
		"client": {
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:              "allow-corp",
				Priority:        100,
				Direction:       model.DirectionEgress,
				Protocol:        model.ProtocolTCP,
				RemoteCIDRGroup: "corp",
				Ports:           []model.PortRange{{From: 443, To: 443}},
				Action:          model.ActionAllow,
			}},
		},
	}, CompileContext{
		CIDRGroups: []model.CIDRGroup{
			{Name: "corp", VPC: "prod", CIDRs: []netip.Prefix{
				netip.MustParsePrefix("10.20.1.1/16"),
				netip.MustParsePrefix("2001:db8::/64"),
			}},
			{Name: "corp", VPC: "other", CIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Rules) != 2 {
		t.Fatalf("rules = %d, want 2 cidr-group-derived rules", len(program.Rules))
	}
	gotCIDRs := []string{program.Rules[0].RemoteCIDR.String(), program.Rules[1].RemoteCIDR.String()}
	sort.Strings(gotCIDRs)
	wantCIDRs := []string{"10.20.0.0/16", "2001:db8::/64"}
	for i := range wantCIDRs {
		if gotCIDRs[i] != wantCIDRs[i] {
			t.Fatalf("cidr group cidrs = %v, want %v", gotCIDRs, wantCIDRs)
		}
	}
	if len(program.MapEntries) != 2 {
		t.Fatalf("map entries = %d, want 2", len(program.MapEntries))
	}
}

func TestCompileForEndpointWithContextRejectsUnknownRemoteCIDRGroup(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"client"},
	}
	_, err := CompileForEndpointWithContext(endpoint, map[string]model.SecurityGroup{
		"client": {
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:              "allow-corp",
				Direction:       model.DirectionEgress,
				Protocol:        model.ProtocolTCP,
				RemoteCIDRGroup: "missing",
				Ports:           []model.PortRange{{From: 443, To: 443}},
				Action:          model.ActionAllow,
			}},
		},
	}, CompileContext{})
	if err == nil {
		t.Fatal("expected unknown remote cidr group to fail")
	}
}

func TestCompileForEndpointExpandsRemoteCIDRExceptCIDRs(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"client"},
	}
	program, err := CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"client": {
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:          "allow-corp-minus-db",
				Priority:    100,
				Direction:   model.DirectionEgress,
				Protocol:    model.ProtocolTCP,
				RemoteCIDR:  netip.MustParsePrefix("10.20.0.0/24"),
				ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.128/25")},
				Ports:       []model.PortRange{{From: 443, To: 443}},
				Action:      model.ActionAllow,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Rules) != 1 {
		t.Fatalf("rules = %d, want 1 remaining CIDR", len(program.Rules))
	}
	if program.Rules[0].RemoteCIDR != netip.MustParsePrefix("10.20.0.0/25") {
		t.Fatalf("remote cidr = %s, want 10.20.0.0/25", program.Rules[0].RemoteCIDR)
	}
	if len(program.MapEntries) != 1 || program.MapEntries[0].RemoteCIDR != netip.MustParsePrefix("10.20.0.0/25") {
		t.Fatalf("map entries = %+v, want one /25 entry", program.MapEntries)
	}
}

func TestCompileForEndpointExpandsRemoteCIDRMultipleExceptCIDRs(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"client"},
	}
	program, err := CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"client": {
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:          "allow-corp-minus-two-hosts",
				Priority:    100,
				Direction:   model.DirectionEgress,
				Protocol:    model.ProtocolTCP,
				RemoteCIDR:  netip.MustParsePrefix("192.0.2.0/30"),
				ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("192.0.2.2/32")},
				Ports:       []model.PortRange{{From: 443, To: 443}},
				Action:      model.ActionAllow,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	gotCIDRs := make([]string, 0, len(program.Rules))
	for _, rule := range program.Rules {
		gotCIDRs = append(gotCIDRs, rule.RemoteCIDR.String())
	}
	sort.Strings(gotCIDRs)
	wantCIDRs := []string{"192.0.2.0/32", "192.0.2.3/32"}
	if len(gotCIDRs) != len(wantCIDRs) {
		t.Fatalf("cidrs = %v, want %v", gotCIDRs, wantCIDRs)
	}
	for i := range wantCIDRs {
		if gotCIDRs[i] != wantCIDRs[i] {
			t.Fatalf("cidrs = %v, want %v", gotCIDRs, wantCIDRs)
		}
	}
}

func TestCompileForEndpointExpandsIPv6RemoteCIDRExceptCIDRs(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("fd00:10::10"),
		Node:           "node-a",
		SecurityGroups: []string{"client"},
	}
	program, err := CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"client": {
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:          "allow-v6-minus-half",
				Priority:    100,
				Direction:   model.DirectionEgress,
				Protocol:    model.ProtocolTCP,
				RemoteCIDR:  netip.MustParsePrefix("2001:db8:10::/64"),
				ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("2001:db8:10::8000:0:0:0/65")},
				Ports:       []model.PortRange{{From: 443, To: 443}},
				Action:      model.ActionAllow,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Rules) != 1 {
		t.Fatalf("rules = %d, want 1 remaining CIDR", len(program.Rules))
	}
	if program.Rules[0].RemoteCIDR != netip.MustParsePrefix("2001:db8:10::/65") {
		t.Fatalf("remote cidr = %s, want 2001:db8:10::/65", program.Rules[0].RemoteCIDR)
	}
	if len(program.MapEntries) != 1 || program.MapEntries[0].RemoteCIDR != netip.MustParsePrefix("2001:db8:10::/65") {
		t.Fatalf("map entries = %+v, want one IPv6 /65 entry", program.MapEntries)
	}
}
