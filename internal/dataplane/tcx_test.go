package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
)

var (
	testEndpointA = model.EndpointKey("prod", "pod-a")
	testEndpointB = model.EndpointKey("prod", "pod-b")
)

func TestNewConstantTCXProgramRejectsUnknownAction(t *testing.T) {
	program, err := NewConstantTCXProgram(99)
	if err == nil {
		program.Close()
		t.Fatal("expected unsupported action to fail")
	}
}

func TestNewIPv4SourceACLMapRejectsIPv6(t *testing.T) {
	aclMap, err := NewIPv4SourceACLMap(netip.MustParseAddr("2001:db8::1"), TCXDrop)
	if err == nil {
		aclMap.Close()
		t.Fatal("expected IPv6 source to fail")
	}
}

func TestNewIPv4L4ACLMapRejectsMissingFields(t *testing.T) {
	aclMap, err := NewIPv4L4ACLMap(netip.MustParseAddr("172.30.0.11"), 0, 8080, TCXDrop)
	if err == nil {
		aclMap.Close()
		t.Fatal("expected missing protocol to fail")
	}
	aclMap, err = NewIPv4L4ACLMap(netip.MustParseAddr("172.30.0.11"), 6, 0, TCXDrop)
	if err == nil {
		aclMap.Close()
		t.Fatal("expected missing port to fail")
	}
}

func TestIPv4L4ACLRulesFromProgramProjectsExactIngressPolicy(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{
			{
				ID:         "drop-web",
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			},
			{
				ID:         "drop-wide-cidr",
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			},
			{
				ID:         "skip-egress",
				Direction:  model.DirectionEgress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.12/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			},
		},
	}
	rules, err := IPv4L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(rules))
	}
	if rules[0].Source != netip.MustParseAddr("172.30.0.11") || rules[0].Protocol != 6 || rules[0].DestPort != 8080 || rules[0].Action != TCXDrop {
		t.Fatalf("unexpected rule: %+v", rules[0])
	}
	if rules[0].SourceCIDR != netip.MustParsePrefix("172.30.0.11/32") {
		t.Fatalf("exact source cidr = %s, want 172.30.0.11/32", rules[0].SourceCIDR)
	}
	if rules[1].SourceCIDR != netip.MustParsePrefix("172.30.0.0/24") || rules[1].Protocol != 6 || rules[1].DestPort != 8080 || rules[1].Action != TCXDrop {
		t.Fatalf("unexpected wide cidr rule: %+v", rules[1])
	}
}

func TestIPv4L4ACLRulesFromProgramProjectsRemoteEndpointIdentityCIDR(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:             "drop-client",
			Direction:      model.DirectionIngress,
			Protocol:       model.ProtocolTCP,
			RemoteCIDR:     netip.MustParsePrefix("172.30.0.11/32"),
			RemoteEndpoint: testEndpointB,
			Ports:          []model.PortRange{{From: 8080, To: 8080}},
			Action:         model.ActionDrop,
		}},
	}

	rules, err := IPv4L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateL4ACLProgramSupport(program); err != nil {
		t.Fatalf("support error = %v, want remote endpoint exact CIDR projection", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want one projected remote endpoint CIDR rule", len(rules))
	}
	if rules[0].SourceCIDR != netip.MustParsePrefix("172.30.0.11/32") || rules[0].Protocol != 6 || rules[0].DestPort != 8080 || rules[0].Action != TCXDrop {
		t.Fatalf("remote endpoint TCX rule = %+v, want exact CIDR tcp/8080 drop", rules[0])
	}
}

func TestIPv4L4ACLRulesFromProgramRejectsAllowOnlyPolicy(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "allow-web",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
			Ports:      []model.PortRange{{From: 8080, To: 8080}},
			Action:     model.ActionAllow,
		}},
	}

	_, err := IPv4L4ACLRulesFromProgram(program)
	if err == nil || !strings.Contains(err.Error(), "no enforcing IPv4 L4 ingress ACL rules") {
		t.Fatalf("error = %v, want allow-only TCX policy to be non-enforcing", err)
	}
}

func TestIPv4L4ACLRulesFromProgramProjectsExactEgressPolicy(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{
			{
				ID:         "skip-ingress",
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			},
			{
				ID:         "drop-egress-api",
				Direction:  model.DirectionEgress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("198.51.100.10/32"),
				Ports:      []model.PortRange{{From: 443, To: 443}},
				Action:     model.ActionDrop,
			},
		},
	}
	rules, err := IPv4L4ACLRulesFromProgramForDirection(program, model.DirectionEgress)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].Source != netip.MustParseAddr("198.51.100.10") || rules[0].Protocol != 6 || rules[0].DestPort != 443 || rules[0].Action != TCXDrop {
		t.Fatalf("unexpected rule: %+v", rules[0])
	}
	if rules[0].DestPortPrefixBits != 16 {
		t.Fatalf("dest port prefix bits = %d, want exact port", rules[0].DestPortPrefixBits)
	}
}

func TestIPv4L4ACLRulesFromProgramProjectsRejectActionToDrop(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "reject-web",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("172.30.0.20/32"),
			Ports:      []model.PortRange{{From: 8080, To: 8080}},
			Action:     model.ActionReject,
		}},
	}

	rules, err := IPv4L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatalf("IPv4L4ACLRulesFromProgram returned error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].Source != netip.MustParseAddr("172.30.0.20") || rules[0].Protocol != 6 || rules[0].DestPort != 8080 || rules[0].Action != TCXDrop {
		t.Fatalf("unexpected IPv4 reject projection: %+v", rules[0])
	}
}

func TestIPv4L4ACLRulesFromProgramPrunesLowerPrecedenceNarrowRule(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{
			{
				ID:         "deny-nodeports",
				Tier:       1,
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 30000, To: 32767}},
				Action:     model.ActionDrop,
			},
			{
				ID:         "allow-one-nodeport",
				Tier:       1,
				Priority:   200,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 30080, To: 30080}},
				Action:     model.ActionAllow,
			},
		},
	}
	rules, err := IPv4L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Action != TCXDrop {
			t.Fatalf("rules = %+v, lower-precedence narrow allow would shadow broad deny in LPM", rules)
		}
	}
}

func TestIPv4L4ACLRulesFromProgramKeepsHigherPrecedenceNarrowRule(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{
			{
				ID:         "allow-nodeports",
				Tier:       1,
				Priority:   300,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 30000, To: 32767}},
				Action:     model.ActionAllow,
			},
			{
				ID:         "deny-one-nodeport",
				Tier:       1,
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 30080, To: 30080}},
				Action:     model.ActionDrop,
			},
		},
	}
	rules, err := IPv4L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	var hasNarrowDrop bool
	for _, rule := range rules {
		if rule.SourceCIDR == netip.MustParsePrefix("172.30.0.11/32") && rule.DestPort == 30080 && rule.Action == TCXDrop {
			hasNarrowDrop = true
		}
	}
	if !hasNarrowDrop {
		t.Fatalf("rules = %+v, want higher-precedence narrow drop preserved", rules)
	}
}

func TestIPv4L4ACLRulesFromProgramProjectsPortRangePolicy(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "drop-nodeports",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
			Ports:      []model.PortRange{{From: 30000, To: 32767}},
			Action:     model.ActionDrop,
		}},
	}
	rules, err := IPv4L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 5 {
		t.Fatalf("rules = %d, want 5 CIDR+port-prefix TCX rules: %+v", len(rules), rules)
	}
	for _, rule := range rules {
		if rule.SourceCIDR != netip.MustParsePrefix("172.30.0.0/24") || rule.Protocol != 6 || rule.Action != TCXDrop {
			t.Fatalf("unexpected range rule: %+v", rule)
		}
		if rule.DestPortPrefixBits >= 16 {
			t.Fatalf("range rule prefix bits = %d, want compressed port prefix", rule.DestPortPrefixBits)
		}
	}
	if rules[0].DestPort != 30000 || rules[0].DestPortPrefixBits != 12 {
		t.Fatalf("first range block = %d/%d, want 30000/12", rules[0].DestPort, rules[0].DestPortPrefixBits)
	}
}

func TestIPv4L4ACLRulesFromProgramProjectsProtocolOnlyPolicy(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "drop-all-tcp",
			Direction:  model.DirectionEgress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("198.51.100.0/24"),
			Action:     model.ActionDrop,
		}},
	}
	rules, err := IPv4L4ACLRulesFromProgramForDirection(program, model.DirectionEgress)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want one protocol-only TCX rule", len(rules))
	}
	if rules[0].DestPort != 0 || rules[0].DestPortPrefixBits != 0 {
		t.Fatalf("dest port = %d/%d, want wildcard port", rules[0].DestPort, rules[0].DestPortPrefixBits)
	}
}

func TestIPv4L4ACLRulesFromProgramProjectsICMPCIDRPolicy(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "drop-icmp",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolICMP,
			RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
			Action:     model.ActionDrop,
		}},
	}
	rules, err := IPv4L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].SourceCIDR != netip.MustParsePrefix("172.30.0.0/24") || rules[0].Protocol != 1 || rules[0].DestPort != 0 || rules[0].Action != TCXDrop {
		t.Fatalf("unexpected ICMP rule: %+v", rules[0])
	}
	if rules[0].DestPortPrefixBits != 0 {
		t.Fatalf("icmp prefix bits = %d, want protocol-only wildcard", rules[0].DestPortPrefixBits)
	}
}

func TestIPv4L4ACLRulesFromProgramProjectsICMPDropTypeAndCode(t *testing.T) {
	icmpType := uint8(8)
	icmpCode := uint8(0)
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "drop-echo",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolICMP,
			RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
			ICMPType:   &icmpType,
			ICMPCode:   &icmpCode,
			Action:     model.ActionDrop,
		}},
	}
	rules, err := IPv4L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].Protocol != 1 || rules[0].DestPort != 0x0800 || rules[0].DestPortPrefixBits != 16 || rules[0].Action != TCXDrop {
		t.Fatalf("unexpected ICMP type/code rule: %+v", rules[0])
	}
}

func TestIPv4L4ACLTCXProgramBypassesICMPFragmentationNeeded(t *testing.T) {
	instructions := ipv4L4ACLTCXInstructions(1, 26)
	seenICMPLoad := false
	for _, ins := range instructions {
		if ins.Symbol() == "load_icmp" {
			seenICMPLoad = true
			continue
		}
		if seenICMPLoad && ins.Constant == 0x0304 && ins.Reference() == "pass" {
			return
		}
	}
	t.Fatalf("TCX instructions do not bypass ICMP fragmentation-needed before policy lookup:\n%s", instructions)
}

func TestIPv4L4ACLRulesFromProgramRejectsICMPPorts(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "invalid-icmp-port",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolICMP,
			RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
			Ports:      []model.PortRange{{From: 8, To: 8}},
			Action:     model.ActionDrop,
		}},
	}
	_, err := IPv4L4ACLRulesFromProgram(program)
	if err == nil {
		t.Fatal("expected ICMP port TCX projection to fail")
	}
	if !strings.Contains(err.Error(), "ICMP TCX ACL does not support destination ports") {
		t.Fatalf("error %q does not mention ICMP ports", err)
	}
}

func TestIPv4L4ACLRulesFromProgramSkipsIPv6CIDR(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{
			{
				ID:         "drop-v6",
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("fd00:10::/64"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			},
			{
				ID:         "drop-v4",
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			},
		},
	}
	rules, err := IPv4L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].SourceCIDR != netip.MustParsePrefix("172.30.0.0/24") {
		t.Fatalf("rules = %+v, want only IPv4 rule", rules)
	}
	if err := ValidateIPv4L4ACLProgramSupport(program); err != nil {
		t.Fatalf("IPv6 rules should remain in policy map without blocking IPv4 TCX projection: %v", err)
	}
}

func TestIPv6L4ACLRulesFromProgramProjectsExactIngressPolicy(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{
			{
				ID:         "drop-v6-web",
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("fd00:10::20/128"),
				Ports:      []model.PortRange{{From: 8443, To: 8443}},
				Action:     model.ActionDrop,
			},
			{
				ID:         "skip-v4",
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 8443, To: 8443}},
				Action:     model.ActionDrop,
			},
		},
	}
	rules, err := IPv6L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1 IPv6 rule", len(rules))
	}
	if rules[0].Source != netip.MustParseAddr("fd00:10::20") || rules[0].SourceCIDR != netip.MustParsePrefix("fd00:10::20/128") || rules[0].Protocol != 6 || rules[0].DestPort != 8443 || rules[0].DestPortPrefixBits != 16 || rules[0].Action != TCXDrop {
		t.Fatalf("unexpected IPv6 rule: %+v", rules[0])
	}
}

func TestIPv6L4ACLRulesFromProgramProjectsRejectActionToDrop(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "reject-v6-web",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("fd00:10::20/128"),
			Ports:      []model.PortRange{{From: 8443, To: 8443}},
			Action:     model.ActionReject,
		}},
	}

	rules, err := IPv6L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatalf("IPv6L4ACLRulesFromProgram returned error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].Source != netip.MustParseAddr("fd00:10::20") || rules[0].SourceCIDR != netip.MustParsePrefix("fd00:10::20/128") || rules[0].Protocol != 6 || rules[0].DestPort != 8443 || rules[0].DestPortPrefixBits != 16 || rules[0].Action != TCXDrop {
		t.Fatalf("unexpected IPv6 reject projection: %+v", rules[0])
	}
}

func TestIPv6L4ACLRulesFromProgramProjectsPortRangePolicy(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "drop-v6-range",
			Direction:  model.DirectionEgress,
			Protocol:   model.ProtocolUDP,
			RemoteCIDR: netip.MustParsePrefix("2001:db8:10::/64"),
			Ports:      []model.PortRange{{From: 30000, To: 32767}},
			Action:     model.ActionDrop,
		}},
	}
	rules, err := IPv6L4ACLRulesFromProgramForDirection(program, model.DirectionEgress)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 5 {
		t.Fatalf("rules = %d, want 5 IPv6 CIDR+port-prefix TCX rules: %+v", len(rules), rules)
	}
	for _, rule := range rules {
		if rule.SourceCIDR != netip.MustParsePrefix("2001:db8:10::/64") || rule.Protocol != 17 || rule.Action != TCXDrop {
			t.Fatalf("unexpected IPv6 range rule: %+v", rule)
		}
		if rule.DestPortPrefixBits >= 16 {
			t.Fatalf("range rule prefix bits = %d, want compressed port prefix", rule.DestPortPrefixBits)
		}
	}
}

func TestIPv6L4ACLRulesFromProgramProjectsICMPv6DropTypeAndCode(t *testing.T) {
	icmpType := uint8(128)
	icmpCode := uint8(0)
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "drop-v6-echo",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolICMP,
			RemoteCIDR: netip.MustParsePrefix("fd00:10::/64"),
			ICMPType:   &icmpType,
			ICMPCode:   &icmpCode,
			Action:     model.ActionDrop,
		}},
	}
	rules, err := IPv6L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].Protocol != 58 || rules[0].DestPort != 0x8000 || rules[0].DestPortPrefixBits != 16 || rules[0].Action != TCXDrop {
		t.Fatalf("unexpected ICMPv6 type/code rule: %+v", rules[0])
	}
}

func TestIPv6L4ACLTCXProgramBypassesICMPv6PacketTooBig(t *testing.T) {
	instructions := ipv6L4ACLTCXInstructions(1, 22)
	seenICMPv6Load := false
	for _, ins := range instructions {
		if ins.Symbol() == "load_icmpv6" {
			seenICMPv6Load = true
			continue
		}
		if seenICMPv6Load && ins.Constant == 0x0200 && ins.Reference() == "pass" {
			return
		}
	}
	t.Fatalf("TCX instructions do not bypass ICMPv6 packet-too-big before policy lookup:\n%s", instructions)
}

func TestIPv6L4ACLTCXProgramBypassesICMPv6NeighborDiscovery(t *testing.T) {
	instructions := ipv6L4ACLTCXInstructions(1, 22)
	expected := map[int64]bool{
		0x8500: false,
		0x8600: false,
		0x8700: false,
		0x8800: false,
	}
	seenICMPv6Load := false
	for _, ins := range instructions {
		if ins.Symbol() == "load_icmpv6" {
			seenICMPv6Load = true
			continue
		}
		if seenICMPv6Load && ins.Reference() == "pass" {
			if _, ok := expected[ins.Constant]; ok {
				expected[ins.Constant] = true
			}
		}
	}
	for icmpValue, found := range expected {
		if !found {
			t.Fatalf("TCX instructions do not bypass ICMPv6 %#04x before policy lookup:\n%s", icmpValue, instructions)
		}
	}
}

func TestIPv6L4ACLRulesFromProgramRejectsICMPv6Ports(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "invalid-v6-icmp-port",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolICMP,
			RemoteCIDR: netip.MustParsePrefix("fd00:10::/64"),
			Ports:      []model.PortRange{{From: 8, To: 8}},
			Action:     model.ActionDrop,
		}},
	}
	_, err := IPv6L4ACLRulesFromProgram(program)
	if err == nil {
		t.Fatal("expected ICMPv6 port TCX projection to fail")
	}
	if !strings.Contains(err.Error(), "ICMPv6 TCX ACL does not support destination ports") {
		t.Fatalf("error %q does not mention ICMPv6 ports", err)
	}
}

func TestIPv4L4ACLRulesFromProgramRejectsNoExactRules(t *testing.T) {
	_, err := IPv4L4ACLRulesFromProgram(policy.Program{EndpointID: testEndpointA})
	if err == nil {
		t.Fatal("expected empty TCX projection to fail")
	}
}

func TestAttachTCXL4RulesForDirectionUsesTailAnchorForIPv6(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot adjust memlock for TCX attach test: %v", err)
	}
	var anchors []bool
	originalAttach := attachTCX
	attachTCX = func(opts link.TCXOptions) (link.Link, error) {
		anchors = append(anchors, opts.Anchor != nil)
		return nil, nil
	}
	t.Cleanup(func() {
		attachTCX = originalAttach
	})
	attachment, err := AttachTCXL4RulesForDirection(context.Background(), "lo",
		[]IPv4L4ACLRule{{Action: TCXDrop, Protocol: 6, SourceCIDR: netip.MustParsePrefix("172.30.0.11/32"), DestPort: 8080}},
		[]IPv6L4ACLRule{{Action: TCXDrop, Protocol: 6, SourceCIDR: netip.MustParsePrefix("fd00:10::11/128"), DestPort: 8080}},
		ebpf.AttachTCXIngress, model.DirectionIngress)
	if err != nil {
		t.Fatal(err)
	}
	defer attachment.Close()

	if len(anchors) != 2 {
		t.Fatalf("attach calls = %d, want 2", len(anchors))
	}
	if anchors[0] {
		t.Fatalf("first ipv4 attach should not use an anchor")
	}
	if !anchors[1] {
		t.Fatalf("second ipv6 attach should use tail anchor")
	}
}

func TestAttachTCXL4RulesForDirectionReturnsErrorWhenSecondAttachFails(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot adjust memlock for TCX attach test: %v", err)
	}
	callCount := 0
	originalAttach := attachTCX
	attachTCX = func(opts link.TCXOptions) (link.Link, error) {
		callCount++
		if callCount == 1 {
			return nil, nil
		}
		return nil, errors.New("mocked tail attach failure")
	}
	t.Cleanup(func() {
		attachTCX = originalAttach
	})

	_, err := AttachTCXL4RulesForDirection(context.Background(), "lo",
		[]IPv4L4ACLRule{{Action: TCXDrop, Protocol: 6, SourceCIDR: netip.MustParsePrefix("172.30.0.11/32"), DestPort: 8080}},
		[]IPv6L4ACLRule{{Action: TCXDrop, Protocol: 6, SourceCIDR: netip.MustParsePrefix("fd00:10::11/128"), DestPort: 8080}},
		ebpf.AttachTCXIngress, model.DirectionIngress)
	if err == nil {
		t.Fatal("expected dual-stack attach failure")
	}
	if callCount != 2 {
		t.Fatalf("attach calls = %d, want 2", callCount)
	}
}

func TestAttachTCXL4RulesForDirectionReturnsAttachFailure(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot adjust memlock for TCX attach test: %v", err)
	}
	originalAttach := attachTCX
	attachTCX = func(opts link.TCXOptions) (link.Link, error) {
		return nil, errors.New("mocked attach failure")
	}
	t.Cleanup(func() {
		attachTCX = originalAttach
	})

	_, err := AttachTCXIPv4L4RulesForDirection(context.Background(), "lo",
		[]IPv4L4ACLRule{{Action: TCXDrop, Protocol: 6, SourceCIDR: netip.MustParsePrefix("172.30.0.11/32"), DestPort: 8080}},
		ebpf.AttachTCXIngress, model.DirectionIngress)
	if err == nil {
		t.Fatal("expected dual-stack attach failure")
	}
	if !strings.Contains(err.Error(), "mocked attach failure") {
		t.Fatalf("error = %v, want mocked attach failure", err)
	}
}

func TestNewConstantTCXProgramReturnsVerifierError(t *testing.T) {
	originalProgram := newTCXProgram
	newTCXProgram = func(*ebpf.ProgramSpec) (*ebpf.Program, error) {
		return nil, errors.New("mocked verifier rejection")
	}
	t.Cleanup(func() {
		newTCXProgram = originalProgram
	})

	_, err := NewConstantTCXProgram(TCXPass)
	if err == nil {
		t.Fatal("expected verifier failure")
	}
	if !strings.Contains(err.Error(), "mocked verifier rejection") {
		t.Fatalf("error = %v, want mocked verifier rejection", err)
	}
}

func TestRunTCXVerdictReturnsVerifierError(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot adjust memlock for TCX verify test: %v", err)
	}
	originalProgram := newTCXProgram
	newTCXProgram = func(*ebpf.ProgramSpec) (*ebpf.Program, error) {
		return nil, errors.New("mocked verifier rejection")
	}
	t.Cleanup(func() {
		newTCXProgram = originalProgram
	})

	_, err := RunTCXVerdict(context.Background(), "lo", TCXPass, 0)
	if err == nil {
		t.Fatal("expected verifier failure")
	}
	if !strings.Contains(err.Error(), "mocked verifier rejection") {
		t.Fatalf("error = %v, want mocked verifier rejection", err)
	}
}

func TestRunTCXVerdictReturnsAttachError(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot adjust memlock for TCX attach test: %v", err)
	}
	originalAttach := attachTCX
	attachTCX = func(opts link.TCXOptions) (link.Link, error) {
		return nil, errors.New("mocked attach failure")
	}
	t.Cleanup(func() {
		attachTCX = originalAttach
	})

	_, err := RunTCXVerdict(context.Background(), "lo", TCXPass, 0)
	if err == nil {
		t.Fatal("expected attach failure")
	}
	if !strings.Contains(err.Error(), "mocked attach failure") {
		t.Fatalf("error = %v, want mocked attach failure", err)
	}
}

func TestNewMapBackedTCXProgramReturnsVerifierError(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot adjust memlock for map-backed tcx verify test: %v", err)
	}
	verdictMap, err := NewVerdictMap(TCXPass)
	if err != nil {
		t.Fatalf("prepare verdict map: %v", err)
	}
	defer verdictMap.Close()

	originalProgram := newTCXProgram
	newTCXProgram = func(*ebpf.ProgramSpec) (*ebpf.Program, error) {
		return nil, errors.New("mocked verifier rejection")
	}
	t.Cleanup(func() {
		newTCXProgram = originalProgram
	})
	_, err = NewMapBackedTCXProgram(verdictMap)
	if err == nil {
		t.Fatal("expected map-backed tcx verifier failure")
	}
	if !strings.Contains(err.Error(), "mocked verifier rejection") {
		t.Fatalf("error = %v, want mocked verifier rejection", err)
	}
}

func TestNewIPv4L4ACLMapReturnsCreationError(t *testing.T) {
	originalMap := newTCXMap
	newTCXMap = func(*ebpf.MapSpec) (*ebpf.Map, error) {
		return nil, errors.New("mocked map creation failure")
	}
	t.Cleanup(func() {
		newTCXMap = originalMap
	})
	aclMap, err := NewIPv4L4ACLMap(netip.MustParseAddr("172.30.0.11"), 6, 8080, TCXDrop)
	if err == nil {
		aclMap.Close()
		t.Fatal("expected IPv4 L4 ACL map creation failure")
	}
	if !strings.Contains(err.Error(), "mocked map creation failure") {
		t.Fatalf("error = %v, want mocked map creation failure", err)
	}
}

func TestNewIPv6L4ACLMapFromRulesReturnsCreationError(t *testing.T) {
	originalMap := newTCXMap
	newTCXMap = func(*ebpf.MapSpec) (*ebpf.Map, error) {
		return nil, errors.New("mocked map creation failure")
	}
	t.Cleanup(func() {
		newTCXMap = originalMap
	})
	aclMap, err := NewIPv6L4ACLMapFromRules([]IPv6L4ACLRule{{
		SourceCIDR: netip.MustParsePrefix("fd00:10::20/128"),
		Protocol:   6,
		DestPort:   8080,
		Action:     TCXDrop,
	}})
	if err == nil {
		aclMap.Close()
		t.Fatal("expected IPv6 L4 ACL map creation failure")
	}
	if !strings.Contains(err.Error(), "mocked map creation failure") {
		t.Fatalf("error = %v, want mocked map creation failure", err)
	}
}

func TestNewIPv4SourceACLMapReturnsCreationError(t *testing.T) {
	originalMap := newTCXMap
	newTCXMap = func(*ebpf.MapSpec) (*ebpf.Map, error) {
		return nil, errors.New("mocked map creation failure")
	}
	t.Cleanup(func() {
		newTCXMap = originalMap
	})
	aclMap, err := NewIPv4SourceACLMap(netip.MustParseAddr("172.30.0.11"), TCXDrop)
	if err == nil {
		aclMap.Close()
		t.Fatal("expected IPv4 source ACL map creation failure")
	}
	if !strings.Contains(err.Error(), "mocked map creation failure") {
		t.Fatalf("error = %v, want mocked map creation failure", err)
	}
}

func TestIPv4L4ACLUsesLPMTrieMapSpec(t *testing.T) {
	spec := ipv4L4ACLMapSpec(1)
	if spec.Type != ebpf.LPMTrie {
		t.Fatalf("map type = %s, want LPMTrie", spec.Type)
	}
	if spec.KeySize != 20 {
		t.Fatalf("key size = %d, want 20 with local+peer IPv4 key", spec.KeySize)
	}
	if spec.Flags == 0 {
		t.Fatal("LPM trie map should set no-prealloc flag")
	}
}

func TestIPv6L4ACLUsesLPMTrieMapSpec(t *testing.T) {
	spec := ipv6L4ACLMapSpec(1)
	if spec.Type != ebpf.LPMTrie {
		t.Fatalf("map type = %s, want LPMTrie", spec.Type)
	}
	if spec.KeySize != 44 {
		t.Fatalf("key size = %d, want 44 with local+peer IPv6 key", spec.KeySize)
	}
	if spec.Flags == 0 {
		t.Fatal("LPM trie map should set no-prealloc flag")
	}
}

func TestIPv4L4ACLRuleSourceCIDR(t *testing.T) {
	cidr, err := ruleSourceCIDR(IPv4L4ACLRule{SourceCIDR: netip.MustParsePrefix("172.30.0.55/24")})
	if err != nil {
		t.Fatal(err)
	}
	if cidr != netip.MustParsePrefix("172.30.0.0/24") {
		t.Fatalf("cidr = %s, want masked 172.30.0.0/24", cidr)
	}
	cidr, err = ruleSourceCIDR(IPv4L4ACLRule{Source: netip.MustParseAddr("172.30.0.11")})
	if err != nil {
		t.Fatal(err)
	}
	if cidr != netip.MustParsePrefix("172.30.0.11/32") {
		t.Fatalf("exact cidr = %s, want 172.30.0.11/32", cidr)
	}
}

func TestIPv6L4ACLRuleSourceCIDR(t *testing.T) {
	cidr, err := ipv6RuleSourceCIDR(IPv6L4ACLRule{SourceCIDR: netip.MustParsePrefix("fd00:10::55/64")})
	if err != nil {
		t.Fatal(err)
	}
	if cidr != netip.MustParsePrefix("fd00:10::/64") {
		t.Fatalf("cidr = %s, want masked fd00:10::/64", cidr)
	}
	cidr, err = ipv6RuleSourceCIDR(IPv6L4ACLRule{Source: netip.MustParseAddr("fd00:10::11")})
	if err != nil {
		t.Fatal(err)
	}
	if cidr != netip.MustParsePrefix("fd00:10::11/128") {
		t.Fatalf("exact cidr = %s, want fd00:10::11/128", cidr)
	}
	if _, err := ipv6RuleSourceCIDR(IPv6L4ACLRule{SourceCIDR: netip.MustParsePrefix("172.30.0.0/24")}); err == nil {
		t.Fatal("expected IPv4 CIDR to fail IPv6 rule validation")
	}
}

func TestIPv4L4ACLKeyPrefixLenIncludesProtocolAndPort(t *testing.T) {
	local := netip.MustParsePrefix("10.10.0.10/32")
	if got := ipv4L4PrefixLen(local, netip.MustParsePrefix("172.30.0.0/24"), 16); got != 104 {
		t.Fatalf("/32-local+/24-peer exact-port prefix len = %d, want 104", got)
	}
	if got := ipv4L4PrefixLen(local, netip.MustParsePrefix("172.30.0.11/32"), 16); got != 112 {
		t.Fatalf("/32-local+/32-peer exact-port prefix len = %d, want full key length 112", got)
	}
	if got := ipv4L4PrefixLen(local, netip.MustParsePrefix("172.30.0.0/24"), 12); got != 100 {
		t.Fatalf("/32-local+/24-peer port-prefix len = %d, want 100", got)
	}
	if ipv4L4LookupPrefixLen != 112 {
		t.Fatalf("lookup prefix len = %d, want full key length 112", ipv4L4LookupPrefixLen)
	}
}

func TestIPv6L4ACLKeyPrefixLenIncludesProtocolAndPort(t *testing.T) {
	local := netip.MustParsePrefix("fd00:10::10/128")
	if got := ipv6L4PrefixLen(local, netip.MustParsePrefix("fd00:10::/64"), 16); got != 240 {
		t.Fatalf("/128-local+/64-peer exact-port prefix len = %d, want 240", got)
	}
	if got := ipv6L4PrefixLen(local, netip.MustParsePrefix("fd00:10::11/128"), 16); got != 304 {
		t.Fatalf("/128-local+/128-peer exact-port prefix len = %d, want full key length 304", got)
	}
	if got := ipv6L4PrefixLen(local, netip.MustParsePrefix("fd00:10::/64"), 12); got != 236 {
		t.Fatalf("/128-local+/64-peer port-prefix len = %d, want 236", got)
	}
	if ipv6L4LookupPrefixLen != 304 {
		t.Fatalf("lookup prefix len = %d, want full IPv6 key length 304", ipv6L4LookupPrefixLen)
	}
}

func TestIPv4L4ACLKeyPeerIPUsesNetworkByteOrder(t *testing.T) {
	got := ipv4L4PeerKey(netip.MustParseAddr("10.245.0.0"))
	want := [4]byte{10, 245, 0, 0}
	if got != want {
		t.Fatalf("peer ip key bytes = %#v, want network-order %#v", got, want)
	}
}

func TestIPv6L4ACLKeyPeerIPUsesNetworkByteOrder(t *testing.T) {
	got := ipv6L4PeerKey(netip.MustParseAddr("fd00:10::1"))
	want := [16]byte{0xfd, 0x00, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if got != want {
		t.Fatalf("peer ip key bytes = %#v, want network-order %#v", got, want)
	}
}

func TestIPv4L4ACLRulesFromProgramsDeduplicatesRules(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{
			{
				ID:         "drop-web-a",
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			},
		},
	}
	rules, err := IPv4L4ACLRulesFromPrograms([]policy.Program{program, program})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
}

func TestIPv4L4ACLRulesFromProgramsKeepsHigherPrecedenceDuplicateKey(t *testing.T) {
	drop := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "drop-web",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
			Ports:      []model.PortRange{{From: 8080, To: 8080}},
			Action:     model.ActionDrop,
		}},
	}
	allow := policy.Program{
		EndpointID: testEndpointB,
		Rules: []policy.Rule{{
			ID:         "allow-web",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
			Ports:      []model.PortRange{{From: 8080, To: 8080}},
			Action:     model.ActionAllow,
		}},
	}
	rules, err := IPv4L4ACLRulesFromPrograms([]policy.Program{drop, allow})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Action != TCXDrop {
		t.Fatalf("rules = %+v, want higher-precedence drop only", rules)
	}
}

func TestIPv4L4ACLRulesFromProgramTreatsLowerNumericPriorityAllowAsNonEnforcingWhenItBeatsDrop(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{
			{
				ID:         "drop-fallback",
				Priority:   200,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8081, To: 8081}},
				Action:     model.ActionDrop,
			},
			{
				ID:         "allow-primary",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8081, To: 8081}},
				Action:     model.ActionAllow,
			},
		},
	}
	_, err := IPv4L4ACLRulesFromProgram(program)
	if err == nil || !strings.Contains(err.Error(), "no enforcing IPv4 L4 ingress ACL rules") {
		t.Fatalf("error = %v, want allow-winning TCX policy to be treated as non-enforcing", err)
	}
}

func TestIPv4L4ACLRulesFromProgramsKeepDistinctLocalEndpointKeys(t *testing.T) {
	programA := policy.Program{
		EndpointID: testEndpointA,
		EndpointIP: netip.MustParseAddr("10.10.0.10"),
		Rules: []policy.Rule{{
			ID:         "drop-web-a",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
			Ports:      []model.PortRange{{From: 8080, To: 8080}},
			Action:     model.ActionDrop,
		}},
	}
	programB := policy.Program{
		EndpointID: testEndpointB,
		EndpointIP: netip.MustParseAddr("10.10.0.11"),
		Rules: []policy.Rule{{
			ID:         "drop-web-b",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
			Ports:      []model.PortRange{{From: 8080, To: 8080}},
			Action:     model.ActionDrop,
		}},
	}
	rules, err := IPv4L4ACLRulesFromPrograms([]policy.Program{programA, programB})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules = %+v, want one rule per local endpoint", rules)
	}
	locals := []netip.Prefix{rules[0].LocalCIDR, rules[1].LocalCIDR}
	if !slices.Contains(locals, netip.MustParsePrefix("10.10.0.10/32")) || !slices.Contains(locals, netip.MustParsePrefix("10.10.0.11/32")) {
		t.Fatalf("locals = %+v, want both endpoint /32s", locals)
	}
}

func TestIPv6L4ACLRulesFromProgramsDeduplicatesRules(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{
			{
				ID:         "drop-v6-web-a",
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("fd00:10::11/128"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			},
		},
	}
	rules, err := IPv6L4ACLRulesFromPrograms([]policy.Program{program, program})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
}

func TestIPv6L4ACLRulesFromProgramsKeepsHigherPrecedenceDuplicateKey(t *testing.T) {
	drop := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "drop-v6-web",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("fd00:10::11/128"),
			Ports:      []model.PortRange{{From: 8080, To: 8080}},
			Action:     model.ActionDrop,
		}},
	}
	allow := policy.Program{
		EndpointID: testEndpointB,
		Rules: []policy.Rule{{
			ID:         "allow-v6-web",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("fd00:10::11/128"),
			Ports:      []model.PortRange{{From: 8080, To: 8080}},
			Action:     model.ActionAllow,
		}},
	}
	rules, err := IPv6L4ACLRulesFromPrograms([]policy.Program{drop, allow})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Action != TCXDrop {
		t.Fatalf("rules = %+v, want higher-precedence drop only", rules)
	}
}

func TestIPv6L4ACLRulesFromProgramsKeepDistinctLocalEndpointKeys(t *testing.T) {
	programA := policy.Program{
		EndpointID: testEndpointA,
		EndpointIP: netip.MustParseAddr("fd00:10::10"),
		Rules: []policy.Rule{{
			ID:         "drop-v6-web-a",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("fd00:20::11/128"),
			Ports:      []model.PortRange{{From: 8443, To: 8443}},
			Action:     model.ActionDrop,
		}},
	}
	programB := policy.Program{
		EndpointID: testEndpointB,
		EndpointIP: netip.MustParseAddr("fd00:10::11"),
		Rules: []policy.Rule{{
			ID:         "drop-v6-web-b",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("fd00:20::11/128"),
			Ports:      []model.PortRange{{From: 8443, To: 8443}},
			Action:     model.ActionDrop,
		}},
	}
	rules, err := IPv6L4ACLRulesFromPrograms([]policy.Program{programA, programB})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules = %+v, want one rule per local endpoint", rules)
	}
	locals := []netip.Prefix{rules[0].LocalCIDR, rules[1].LocalCIDR}
	if !slices.Contains(locals, netip.MustParsePrefix("fd00:10::10/128")) || !slices.Contains(locals, netip.MustParsePrefix("fd00:10::11/128")) {
		t.Fatalf("locals = %+v, want both endpoint /128s", locals)
	}
}

func TestIPv4L4ACLRulesFromProgramTreatsLogOnlyPolicyAsNotEnforcing(t *testing.T) {
	program := policy.Program{
		EndpointID: testEndpointA,
		Rules: []policy.Rule{{
			ID:         "log-web",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
			Ports:      []model.PortRange{{From: 8080, To: 8080}},
			Action:     model.ActionLog,
		}},
	}
	_, err := IPv4L4ACLRulesFromProgram(program)
	if err == nil || !strings.Contains(err.Error(), "no enforcing IPv4 L4 ingress ACL rules") {
		t.Fatalf("error = %v, want log-only TCX policy to be non-enforcing", err)
	}
}

func TestTCXSelfTestPrivileged(t *testing.T) {
	if os.Getenv("NETLOOM_TCX_TEST") != "1" {
		t.Skip("set NETLOOM_TCX_TEST=1 to load and attach a TCX program")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot adjust memlock rlimit for TCX test: %v", err)
	}
	result, err := RunTCXSelfTest(context.Background(), "lo")
	if err != nil {
		if isPermissionOrKernelLimit(err) {
			t.Skipf("TCX attach is not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	if result.Interface != "lo" || result.Direction != "ingress" || result.Action != TCXPass {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRunTCXVerdictHonorsAction(t *testing.T) {
	if os.Getenv("NETLOOM_TCX_TEST") != "1" {
		t.Skip("set NETLOOM_TCX_TEST=1 to load and attach a TCX program")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot adjust memlock rlimit for TCX test: %v", err)
	}
	result, err := RunTCXVerdict(context.Background(), "lo", TCXDrop, 0)
	if err != nil {
		if isPermissionOrKernelLimit(err) {
			t.Skipf("TCX attach is not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	if result.Interface != "lo" || result.Direction != "ingress" || result.Action != TCXDrop || result.Mode != "verdict" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestAttachTCXRejectsMissingInterface(t *testing.T) {
	program := &ebpf.Program{}
	_, err := AttachTCX(context.Background(), "netloom-missing0", program, ebpf.AttachTCXIngress)
	if err == nil {
		t.Fatal("expected missing interface to fail")
	}
}

func isPermissionOrKernelLimit(err error) bool {
	text := err.Error()
	return strings.Contains(text, "operation not permitted") ||
		strings.Contains(text, "not supported") ||
		strings.Contains(text, "permission denied")
}
