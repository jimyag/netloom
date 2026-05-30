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
	program, err := compileTCXPolicySelfTest(netip.MustParseAddr("172.30.0.11"), 6, 8080, dataplane.TCXDrop)
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
