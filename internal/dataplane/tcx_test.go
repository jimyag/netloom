package dataplane

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
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
		EndpointID: "pod-a",
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

func TestIPv4L4ACLRulesFromProgramProjectsExactEgressPolicy(t *testing.T) {
	program := policy.Program{
		EndpointID: "pod-a",
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
}

func TestIPv4L4ACLRulesFromProgramRejectsNoExactRules(t *testing.T) {
	_, err := IPv4L4ACLRulesFromProgram(policy.Program{EndpointID: "pod-a"})
	if err == nil {
		t.Fatal("expected empty TCX projection to fail")
	}
}

func TestIPv4L4ACLUsesLPMTrieMapSpec(t *testing.T) {
	spec := ipv4L4ACLMapSpec(1)
	if spec.Type != ebpf.LPMTrie {
		t.Fatalf("map type = %s, want LPMTrie", spec.Type)
	}
	if spec.KeySize != 12 {
		t.Fatalf("key size = %d, want 12", spec.KeySize)
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

func TestIPv4L4ACLKeyPrefixLenIncludesProtocolAndPort(t *testing.T) {
	if got := ipv4L4PrefixLen(netip.MustParsePrefix("172.30.0.0/24")); got != 56 {
		t.Fatalf("/24 prefix len = %d, want protocol+pad+port+cidr bits 56", got)
	}
	if got := ipv4L4PrefixLen(netip.MustParsePrefix("172.30.0.11/32")); got != 64 {
		t.Fatalf("/32 prefix len = %d, want protocol+pad+port+cidr bits 64", got)
	}
	if ipv4L4LookupPrefixLen != 64 {
		t.Fatalf("lookup prefix len = %d, want full key length 64", ipv4L4LookupPrefixLen)
	}
}

func TestIPv4L4ACLRulesFromProgramsDeduplicatesRules(t *testing.T) {
	program := policy.Program{
		EndpointID: "pod-a",
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

func TestIPv4L4ACLRulesFromProgramTreatsLogActionAsPass(t *testing.T) {
	program := policy.Program{
		EndpointID: "pod-a",
		Rules: []policy.Rule{{
			ID:         "log-web",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
			Ports:      []model.PortRange{{From: 8080, To: 8080}},
			Action:     model.ActionLog,
		}},
	}
	rules, err := IPv4L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].Action != TCXPass {
		t.Fatalf("tcx action = %d, want pass", rules[0].Action)
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
