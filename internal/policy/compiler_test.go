package policy

import (
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

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
	if program.Rules[0].ID != "default-deny" {
		t.Fatalf("first rule = %s, want default-deny", program.Rules[0].ID)
	}
	if program.Rules[0].Action != model.ActionDrop {
		t.Fatalf("first rule action = %s, want drop", program.Rules[0].Action)
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

func TestCompileForEndpointUsesKubeOVNStyleLowerRulePriorityFirst(t *testing.T) {
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
					ID:         "allow-fallback",
					Priority:   100,
					Direction:  model.DirectionEgress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("192.0.2.0/24"),
					Ports:      []model.PortRange{{From: 443, To: 443}},
					Action:     model.ActionAllow,
				},
				{
					ID:         "allow-primary",
					Priority:   1,
					Direction:  model.DirectionEgress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("192.0.2.0/24"),
					Ports:      []model.PortRange{{From: 443, To: 443}},
					Action:     model.ActionAllow,
				},
			},
		},
	}
	program, err := CompileForEndpoint(endpoint, groups)
	if err != nil {
		t.Fatal(err)
	}
	if program.Rules[0].ID != "allow-primary" {
		t.Fatalf("first rule = %s, want lower numeric priority allow-primary", program.Rules[0].ID)
	}
	if program.MapEntries[0].RuleID != "allow-primary" {
		t.Fatalf("highest precedence entry = %s, want allow-primary", program.MapEntries[0].RuleID)
	}
}

func TestCompileForEndpointSortsSecurityGroupTierBeforeRulePriority(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"platform", "tenant"},
	}
	groups := map[string]model.SecurityGroup{
		"platform": {
			Name: "platform",
			VPC:  "prod",
			Tier: 0,
			Rules: []model.SecurityGroupRule{{
				ID:        "platform-allow",
				Priority:  10,
				Direction: model.DirectionEgress,
				Protocol:  model.ProtocolTCP,
				Ports:     []model.PortRange{{From: 443, To: 443}},
				Action:    model.ActionAllow,
			}},
		},
		"tenant": {
			Name: "tenant",
			VPC:  "prod",
			Tier: 1,
			Rules: []model.SecurityGroupRule{{
				ID:        "tenant-drop",
				Priority:  1000,
				Direction: model.DirectionEgress,
				Protocol:  model.ProtocolTCP,
				Ports:     []model.PortRange{{From: 443, To: 443}},
				Action:    model.ActionDrop,
			}},
		},
	}
	program, err := CompileForEndpoint(endpoint, groups)
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(program.Rules))
	}
	if program.Rules[0].ID != "platform-allow" || program.Rules[0].Tier != 0 {
		t.Fatalf("first rule = %+v, want tier-0 platform allow", program.Rules[0])
	}
	if program.MapEntries[0].RuleID != "platform-allow" {
		t.Fatalf("highest precedence entry = %s, want platform-allow", program.MapEntries[0].RuleID)
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

func TestCompileForEndpointEncodesICMPTypeAndCode(t *testing.T) {
	icmpType := uint8(8)
	icmpCode := uint8(0)
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"icmp"},
	}
	groups := map[string]model.SecurityGroup{
		"icmp": {
			Name: "icmp",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-echo",
				Priority:   100,
				Direction:  model.DirectionEgress,
				Protocol:   model.ProtocolICMP,
				RemoteCIDR: netip.MustParsePrefix("198.51.100.0/24"),
				ICMPType:   &icmpType,
				ICMPCode:   &icmpCode,
				Action:     model.ActionAllow,
			}},
		},
	}

	program, err := CompileForEndpoint(endpoint, groups)
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Rules) != 1 || program.Rules[0].ICMPType == nil || *program.Rules[0].ICMPType != 8 {
		t.Fatalf("compiled rule = %+v, want ICMP type preserved", program.Rules)
	}
	if len(program.MapEntries) != 1 {
		t.Fatalf("map entries = %d, want 1", len(program.MapEntries))
	}
	entry := program.MapEntries[0]
	if entry.Key.Protocol != model.ProtocolICMP || entry.Key.DestPort != 0x0800 || entry.Key.L4PrefixBits != 24 {
		t.Fatalf("icmp map key = %+v, want protocol/type/code exact", entry.Key)
	}
}

func TestCompileForEndpointResolvesIngressNamedPort(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"web"},
		NamedPorts: []model.NamedPort{
			{Name: "http", Protocol: model.ProtocolTCP, Port: 8080},
		},
	}
	program, err := CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"web": {
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("10.20.0.0/16"),
				NamedPorts: []string{"http"},
				Action:     model.ActionAllow,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(program.MapEntries) != 1 {
		t.Fatalf("entries = %d, want 1", len(program.MapEntries))
	}
	if program.MapEntries[0].Key.DestPort != 8080 || program.MapEntries[0].Key.L4PrefixBits != 24 {
		t.Fatalf("named port map key = %+v, want tcp/8080 exact", program.MapEntries[0].Key)
	}
}

func TestCompileForEndpointResolvesEgressNamedPortFromRemoteGroup(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "client",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"client"},
	}
	remote := model.Endpoint{
		ID:             "api",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.20"),
		Node:           "node-b",
		SecurityGroups: []string{"api"},
		NamedPorts: []model.NamedPort{
			{Name: "http", Protocol: model.ProtocolTCP, Port: 8080},
		},
	}
	groups := map[string]model.SecurityGroup{
		"client": {
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:          "egress-api",
				Priority:    100,
				Direction:   model.DirectionEgress,
				Protocol:    model.ProtocolTCP,
				RemoteGroup: "api",
				NamedPorts:  []string{"http"},
				Action:      model.ActionAllow,
			}},
		},
		"api": {Name: "api", VPC: "prod"},
	}
	program, err := CompileForEndpointWithContext(endpoint, groups, CompileContext{Endpoints: []model.Endpoint{endpoint, remote}})
	if err != nil {
		t.Fatal(err)
	}
	if len(program.MapEntries) != 1 {
		t.Fatalf("entries = %d, want 1", len(program.MapEntries))
	}
	entry := program.MapEntries[0]
	if entry.Key.DestPort != 8080 || entry.RemoteCIDR != netip.MustParsePrefix("10.10.0.20/32") {
		t.Fatalf("egress named port entry = %+v, want remote api tcp/8080", entry)
	}
}

func TestCompileForEndpointRejectsUnresolvableNamedPort(t *testing.T) {
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
				ID:         "allow-http",
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				NamedPorts: []string{"http"},
				Action:     model.ActionAllow,
			}},
		},
	})
	if err == nil {
		t.Fatal("expected missing named port to fail")
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
			{Name: "deep.payments.svc.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.30")}},
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

func TestCompileForEndpointWithContextFQDNPatternUsesCiliumLabelWildcards(t *testing.T) {
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
				ID:        "allow-svc",
				Priority:  100,
				Direction: model.DirectionEgress,
				Protocol:  model.ProtocolTCP,
				RemoteFQDNs: []model.FQDNSelector{
					{MatchPattern: "*.svc.example.com"},
					{MatchPattern: "**.deep.example.com"},
				},
				Ports:  []model.PortRange{{From: 443, To: 443}},
				Action: model.ActionAllow,
			}},
		},
	}, CompileContext{
		DNSRecords: []model.DNSRecord{
			{Name: "api.svc.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.10")}},
			{Name: "a.b.svc.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.20")}},
			{Name: "one.deep.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.30")}},
			{Name: "one.two.deep.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.40")}},
			{Name: "deep.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.50")}},
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
	wantCIDRs := []string{"203.0.113.10/32", "203.0.113.30/32", "203.0.113.40/32"}
	if len(gotCIDRs) != len(wantCIDRs) {
		t.Fatalf("fqdn cidrs = %v, want %v", gotCIDRs, wantCIDRs)
	}
	for i := range wantCIDRs {
		if gotCIDRs[i] != wantCIDRs[i] {
			t.Fatalf("fqdn cidrs = %v, want %v", gotCIDRs, wantCIDRs)
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

func TestCompileForEndpointWithContextSkipsExpiredDNSRecords(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"client"},
	}
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
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
		Now: now,
		DNSRecords: []model.DNSRecord{
			{
				Name:       "api.example.com",
				IPs:        []netip.Addr{netip.MustParseAddr("203.0.113.10")},
				TTLSeconds: 60,
				ObservedAt: now.Add(-59 * time.Second),
			},
			{
				Name:       "api.example.com",
				IPs:        []netip.Addr{netip.MustParseAddr("203.0.113.20")},
				TTLSeconds: 60,
				ObservedAt: now.Add(-60 * time.Second),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Rules) != 1 {
		t.Fatalf("rules = %d, want only non-expired dns record", len(program.Rules))
	}
	if program.Rules[0].RemoteCIDR != netip.MustParsePrefix("203.0.113.10/32") {
		t.Fatalf("remote cidr = %s, want active dns record only", program.Rules[0].RemoteCIDR)
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

func TestCompileForEndpointWithContextExpandsRemoteEntities(t *testing.T) {
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
				ID:             "allow-entities",
				Priority:       100,
				Direction:      model.DirectionEgress,
				Protocol:       model.ProtocolTCP,
				RemoteEntities: []string{"cluster", "host", "private"},
				Ports:          []model.PortRange{{From: 443, To: 443}},
				Action:         model.ActionAllow,
			}},
		},
	}, CompileContext{
		Subnets: []model.Subnet{
			{Name: "apps", VPC: "prod", CIDR: netip.MustParsePrefix("10.10.0.0/24"), Gateway: netip.MustParseAddr("10.10.0.1")},
			{Name: "db", VPC: "prod", CIDR: netip.MustParsePrefix("fd00:10::/64"), Gateway: netip.MustParseAddr("fd00:10::1")},
			{Name: "other", VPC: "dev", CIDR: netip.MustParsePrefix("192.0.2.0/24"), Gateway: netip.MustParseAddr("192.0.2.1")},
		},
		Gateways: []model.Gateway{
			{Name: "gw-a", VPC: "prod", Node: "node-a", LANIP: netip.MustParseAddr("10.10.0.254")},
			{Name: "gw-v6", VPC: "prod", Node: "node-b", LANIP: netip.MustParseAddr("fd00:10::fe")},
			{Name: "gw-dev", VPC: "dev", Node: "node-c", LANIP: netip.MustParseAddr("192.0.2.254")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	gotCIDRs := make([]string, 0, len(program.Rules))
	gotEntities := make(map[string]struct{})
	for _, rule := range program.Rules {
		gotCIDRs = append(gotCIDRs, rule.RemoteCIDR.String())
		gotEntities[rule.RemoteEntity] = struct{}{}
	}
	sort.Strings(gotCIDRs)
	wantCIDRs := []string{"10.0.0.0/8", "10.10.0.0/24", "10.10.0.254/32", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fd00:10::/64", "fd00:10::fe/128"}
	if len(gotCIDRs) != len(wantCIDRs) {
		t.Fatalf("entity cidrs = %v, want %v", gotCIDRs, wantCIDRs)
	}
	for i := range wantCIDRs {
		if gotCIDRs[i] != wantCIDRs[i] {
			t.Fatalf("entity cidrs = %v, want %v", gotCIDRs, wantCIDRs)
		}
	}
	if _, ok := gotEntities["cluster"]; !ok {
		t.Fatalf("entities = %v, want cluster", gotEntities)
	}
	if _, ok := gotEntities["host"]; !ok {
		t.Fatalf("entities = %v, want host", gotEntities)
	}
	if _, ok := gotEntities["private"]; !ok {
		t.Fatalf("entities = %v, want private", gotEntities)
	}
	if len(program.MapEntries) != len(wantCIDRs) {
		t.Fatalf("map entries = %d, want %d", len(program.MapEntries), len(wantCIDRs))
	}
}

func TestCompileForEndpointWithContextRejectsHostEntityWithoutGateway(t *testing.T) {
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
				ID:             "allow-host",
				Priority:       100,
				Direction:      model.DirectionEgress,
				Protocol:       model.ProtocolTCP,
				RemoteEntities: []string{"host"},
				Ports:          []model.PortRange{{From: 443, To: 443}},
				Action:         model.ActionAllow,
			}},
		},
	}, CompileContext{})
	if err == nil || !strings.Contains(err.Error(), "host requires at least one gateway") {
		t.Fatalf("error = %v, want missing host gateway validation", err)
	}
}

func TestCompileForEndpointWithContextExpandsRemoteNodeEntity(t *testing.T) {
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
				ID:             "allow-remote-node",
				Priority:       100,
				Direction:      model.DirectionEgress,
				Protocol:       model.ProtocolTCP,
				RemoteEntities: []string{"remote-node"},
				Ports:          []model.PortRange{{From: 4240, To: 4240}},
				Action:         model.ActionAllow,
			}},
		},
	}, CompileContext{
		Gateways: []model.Gateway{
			{Name: "gw-local", VPC: "prod", Node: "node-a", LANIP: netip.MustParseAddr("10.10.0.254")},
			{Name: "gw-remote", VPC: "prod", Node: "node-b", LANIP: netip.MustParseAddr("10.10.0.253")},
			{Name: "gw-remote-v6", VPC: "prod", Node: "node-c", LANIP: netip.MustParseAddr("fd00:10::fe")},
			{Name: "gw-other", VPC: "dev", Node: "node-d", LANIP: netip.MustParseAddr("192.0.2.254")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	gotCIDRs := make([]string, 0, len(program.Rules))
	for _, rule := range program.Rules {
		gotCIDRs = append(gotCIDRs, rule.RemoteCIDR.String())
		if rule.RemoteEntity != "remote-node" {
			t.Fatalf("remote entity = %q, want remote-node", rule.RemoteEntity)
		}
	}
	sort.Strings(gotCIDRs)
	wantCIDRs := []string{"10.10.0.253/32", "fd00:10::fe/128"}
	if len(gotCIDRs) != len(wantCIDRs) {
		t.Fatalf("remote-node cidrs = %v, want %v", gotCIDRs, wantCIDRs)
	}
	for i := range wantCIDRs {
		if gotCIDRs[i] != wantCIDRs[i] {
			t.Fatalf("remote-node cidrs = %v, want %v", gotCIDRs, wantCIDRs)
		}
	}
	if len(program.MapEntries) != len(wantCIDRs) {
		t.Fatalf("map entries = %d, want %d", len(program.MapEntries), len(wantCIDRs))
	}
}

func TestCompileForEndpointWithContextRejectsRemoteNodeEntityWithoutRemoteGateway(t *testing.T) {
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
				ID:             "allow-remote-node",
				Priority:       100,
				Direction:      model.DirectionEgress,
				Protocol:       model.ProtocolTCP,
				RemoteEntities: []string{"remote-node"},
				Ports:          []model.PortRange{{From: 4240, To: 4240}},
				Action:         model.ActionAllow,
			}},
		},
	}, CompileContext{
		Gateways: []model.Gateway{
			{Name: "gw-local", VPC: "prod", Node: "node-a", LANIP: netip.MustParseAddr("10.10.0.254")},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "remote-node requires at least one gateway on a different node") {
		t.Fatalf("error = %v, want missing remote-node gateway validation", err)
	}
}

func TestCompileForEndpointWithContextExpandsWorldEntityOutsideCluster(t *testing.T) {
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
				ID:             "allow-world",
				Priority:       100,
				Direction:      model.DirectionEgress,
				Protocol:       model.ProtocolTCP,
				RemoteEntities: []string{"world"},
				Ports:          []model.PortRange{{From: 443, To: 443}},
				Action:         model.ActionAllow,
			}},
		},
	}, CompileContext{
		Subnets: []model.Subnet{
			{Name: "apps", VPC: "prod", CIDR: netip.MustParsePrefix("10.10.0.0/24"), Gateway: netip.MustParseAddr("10.10.0.1")},
			{Name: "v6", VPC: "prod", CIDR: netip.MustParsePrefix("fd00:10::/64"), Gateway: netip.MustParseAddr("fd00:10::1")},
			{Name: "other", VPC: "dev", CIDR: netip.MustParsePrefix("192.0.2.0/24"), Gateway: netip.MustParseAddr("192.0.2.1")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Rules) == 0 {
		t.Fatal("expected world entity to produce CIDR rules")
	}
	if len(program.MapEntries) != len(program.Rules) {
		t.Fatalf("map entries = %d, want %d", len(program.MapEntries), len(program.Rules))
	}
	assertEntityCIDRsMatchIP(t, program.Rules, "world", netip.MustParseAddr("203.0.113.10"), true)
	assertEntityCIDRsMatchIP(t, program.Rules, "world", netip.MustParseAddr("2001:db8::10"), true)
	assertEntityCIDRsMatchIP(t, program.Rules, "world", netip.MustParseAddr("10.10.0.42"), false)
	assertEntityCIDRsMatchIP(t, program.Rules, "world", netip.MustParseAddr("fd00:10::42"), false)
	for _, rule := range program.Rules {
		if rule.RemoteCIDR == netip.MustParsePrefix("0.0.0.0/0") || rule.RemoteCIDR == netip.MustParsePrefix("::/0") {
			t.Fatalf("world entity kept unsplit all-cidr %s", rule.RemoteCIDR)
		}
	}
}

func assertEntityCIDRsMatchIP(t *testing.T, rules []Rule, entity string, ip netip.Addr, want bool) {
	t.Helper()
	for _, rule := range rules {
		if rule.RemoteEntity == entity && rule.RemoteCIDR.Contains(ip) {
			if !want {
				t.Fatalf("entity %s unexpectedly matches ip %s with cidr %s", entity, ip, rule.RemoteCIDR)
			}
			return
		}
	}
	if want {
		t.Fatalf("entity %s does not match ip %s", entity, ip)
	}
}

func TestCompileForEndpointWithContextRejectsClusterEntityWithoutSubnets(t *testing.T) {
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
				ID:             "allow-cluster",
				Direction:      model.DirectionEgress,
				Protocol:       model.ProtocolTCP,
				RemoteEntities: []string{"cluster"},
				Ports:          []model.PortRange{{From: 443, To: 443}},
				Action:         model.ActionAllow,
			}},
		},
	}, CompileContext{})
	if err == nil {
		t.Fatal("expected cluster entity without subnets to fail")
	}
}

func TestCompileForEndpointWithContextRejectsWorldEntityWithoutSubnets(t *testing.T) {
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
				ID:             "allow-world",
				Direction:      model.DirectionEgress,
				Protocol:       model.ProtocolTCP,
				RemoteEntities: []string{"world"},
				Ports:          []model.PortRange{{From: 443, To: 443}},
				Action:         model.ActionAllow,
			}},
		},
	}, CompileContext{})
	if err == nil {
		t.Fatal("expected world entity without subnets to fail")
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
