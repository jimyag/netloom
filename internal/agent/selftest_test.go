package agent

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/model"
)

func TestRunSelfTestCompilesAndEvaluatesPolicy(t *testing.T) {
	result, err := RunSelfTest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.EndpointID != model.EndpointKey("default", "selftest-pod") {
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
	if result.PolicyStats.Allowed != 3 || result.PolicyStats.Dropped != 1 || result.PolicyStats.Conntrack != 1 || result.PolicyStats.Established != 1 || result.PolicyStats.DenyDrops != 1 || result.PolicyStats.Logged != 3 {
		t.Fatalf("policy stats = %+v, want allowed=3 dropped=1 conntrack=1 established=1 deny_drops=1 logged=3", result.PolicyStats)
	}
	if len(result.RuleStats) != 3 {
		t.Fatalf("rule stats = %+v, want allow, deny, and conntrack buckets", result.RuleStats)
	}
	var conntrackRule, allowRule, denyRule *dataplane.RuleMetrics
	for i := range result.RuleStats {
		switch {
		case result.RuleStats[i].RuleCookie == 0:
			conntrackRule = &result.RuleStats[i]
		case result.RuleStats[i].Allowed > 0:
			allowRule = &result.RuleStats[i]
		case result.RuleStats[i].Dropped > 0:
			denyRule = &result.RuleStats[i]
		}
	}
	if conntrackRule == nil || conntrackRule.Allowed != 1 || conntrackRule.Conntrack != 1 || conntrackRule.RuleCookie != 0 {
		t.Fatalf("conntrack rule stats = %+v, want one conntrack-only allow bucket", conntrackRule)
	}
	if allowRule == nil || allowRule.RuleCookie == 0 || allowRule.Allowed != 2 || allowRule.Conntrack != 0 || allowRule.Established != 1 || allowRule.Logged != 2 {
		t.Fatalf("allow rule stats = %+v, want stateful allow aggregation", allowRule)
	}
	if denyRule == nil || denyRule.RuleCookie == 0 || denyRule.Dropped != 1 || denyRule.DenyDrops != 1 || denyRule.Logged != 1 {
		t.Fatalf("deny rule stats = %+v, want deny aggregation", denyRule)
	}
	if result.DropEvents != 1 {
		t.Fatalf("drop events = %d, want 1", result.DropEvents)
	}
	if result.PolicyEvents != 3 {
		t.Fatalf("policy events = %d, want 3", result.PolicyEvents)
	}
	if result.TraceEvents != 4 {
		t.Fatalf("trace events = %d, want 4", result.TraceEvents)
	}
	if result.TCX != "not-requested" {
		t.Fatalf("tcx status = %s, want not-requested", result.TCX)
	}
}

func TestRunSelfTestAcceptsCustomVpcScope(t *testing.T) {
	t.Setenv("NETLOOM_SELFTEST_VPC", "blue")
	result, err := RunSelfTest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.EndpointID != model.EndpointKey("blue", "selftest-pod") {
		t.Fatalf("endpoint id = %s, want blue-scoped selftest-pod", result.EndpointID)
	}
	if !strings.Contains(result.TCX, "not-requested") {
		t.Fatalf("tcx status = %s, want not-requested", result.TCX)
	}
}

func TestRunSelfTestTcxAttachFailureIsSurfaceable(t *testing.T) {
	t.Setenv("NETLOOM_TCX_SELFTEST_IFACE", "not-a-real-interface")
	_, err := RunSelfTest(context.Background())
	if err == nil {
		t.Fatal("expected tcx selftest to fail for missing interface")
	}
	if !strings.Contains(err.Error(), "tcx selftest:") {
		t.Fatalf("selftest attach error should be wrapped as tcx selftest: %v", err)
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
