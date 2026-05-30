package agent

import (
	"context"
	"net/netip"
	"testing"

	"github.com/jimyag/netloom/internal/dataplane"
)

func TestRunSelfTestCompilesAndEvaluatesPolicy(t *testing.T) {
	result, err := RunSelfTest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.EndpointID != "selftest-pod" {
		t.Fatalf("endpoint id = %s, want selftest-pod", result.EndpointID)
	}
	if result.Entries < 2 {
		t.Fatalf("entries = %d, want at least 2", result.Entries)
	}
	if result.Allowed != dataplane.VerdictAllow {
		t.Fatalf("allowed verdict = %s, want allow", result.Allowed)
	}
	if result.Denied != dataplane.VerdictDrop {
		t.Fatalf("denied verdict = %s, want drop", result.Denied)
	}
	if result.PolicyStats.Allowed != 1 || result.PolicyStats.Dropped != 1 || result.PolicyStats.DenyDrops != 1 || result.PolicyStats.Logged != 2 {
		t.Fatalf("policy stats = %+v, want one allow and one deny drop", result.PolicyStats)
	}
	if result.DropEvents != 1 {
		t.Fatalf("drop events = %d, want 1", result.DropEvents)
	}
	if result.PolicyEvents != 2 {
		t.Fatalf("policy events = %d, want 2", result.PolicyEvents)
	}
	if result.TCX != "not-requested" {
		t.Fatalf("tcx status = %s, want not-requested", result.TCX)
	}
}

func TestCompileTCXPolicySelfTestUsesPolicyCompiler(t *testing.T) {
	port := uint16(8080)
	program, err := compileTCXPolicySelfTest(netip.MustParseAddr("172.30.0.11"), 6, &port, dataplane.TCXDrop)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := dataplane.IPv4L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].Source != netip.MustParseAddr("172.30.0.11") || rules[0].Protocol != 6 || rules[0].DestPort != 8080 || rules[0].Action != dataplane.TCXDrop {
		t.Fatalf("unexpected TCX rule: %+v", rules[0])
	}
}

func TestCompileTCXPolicySelfTestSupportsICMPWithoutPort(t *testing.T) {
	program, err := compileTCXPolicySelfTest(netip.MustParseAddr("172.30.0.11"), 1, nil, dataplane.TCXDrop)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := dataplane.IPv4L4ACLRulesFromProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].Source != netip.MustParseAddr("172.30.0.11") || rules[0].Protocol != 1 || rules[0].DestPort != 0 || rules[0].Action != dataplane.TCXDrop {
		t.Fatalf("unexpected TCX ICMP rule: %+v", rules[0])
	}
}

func TestTCXSelfTestPortRequiresDportForTCP(t *testing.T) {
	_, err := tcxSelfTestPort(6, "")
	if err == nil {
		t.Fatal("expected missing TCP destination port to fail")
	}
}

func TestTCXSelfTestPortAllowsICMPWithoutDport(t *testing.T) {
	port, err := tcxSelfTestPort(1, "")
	if err != nil {
		t.Fatal(err)
	}
	if port != nil {
		t.Fatalf("port = %d, want nil", *port)
	}
}
