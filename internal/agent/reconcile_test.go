package agent

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
)

func tcxProgram(endpointID string, direction model.Direction, cidr string, port uint16) policy.Program {
	return policy.Program{
		EndpointID: endpointID,
		Rules: []policy.Rule{{
			ID:         endpointID + "-tcx",
			Direction:  direction,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix(cidr),
			Ports:      []model.PortRange{{From: port, To: port}},
			Action:     model.ActionDrop,
		}},
	}
}

func TestReconcileNodeAppliesOnlyLocalEndpointPolicies(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "pod-a",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.10"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
			{
				ID:             "pod-b",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.11"),
				Node:           "node-b",
				SecurityGroups: []string{"web"},
			},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Endpoints != 1 || result.Programs != 1 || result.Entries != 1 || result.TCXEligible != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.PolicyAdded != 1 || result.PolicyUpdated != 0 || result.PolicyDeleted != 0 || result.PolicyUnchanged != 0 || result.PolicyEvents != 1 || result.PolicyRevisionMax != 1 {
		t.Fatalf("policy update summary = %+v, want one add at revision 1", result)
	}
	if result.TCX != "not-requested" {
		t.Fatalf("tcx = %s, want not-requested", result.TCX)
	}
	if entries := store.Entries("pod-a"); len(entries) != 1 {
		t.Fatalf("pod-a entries = %d, want 1", len(entries))
	}
	if entries := store.Entries("pod-b"); len(entries) != 0 {
		t.Fatalf("pod-b entries = %d, want 0", len(entries))
	}
}

func TestReconcileNodeReportsPolicyDiffStatsAcrossRevisions(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	if _, err := ReconcileNode(context.Background(), state, "node-a", store); err != nil {
		t.Fatal(err)
	}

	state.SecurityGroups[0].Rules[0].Action = model.ActionAllow
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyAdded != 0 || result.PolicyUpdated != 1 || result.PolicyDeleted != 0 || result.PolicyUnchanged != 0 || result.PolicyEvents != 1 || result.PolicyRevisionMax != 2 {
		t.Fatalf("policy update summary = %+v, want one update at revision 2", result)
	}
	events := store.Events()
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[1].EndpointID != "pod-a" || events[1].Stats.Updated != 1 || events[1].Stats.Revision != 2 {
		t.Fatalf("second event = %+v, want pod-a update revision 2", events[1])
	}
}

func TestReconcileNodeReportsUnchangedPolicyStats(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	if _, err := ReconcileNode(context.Background(), state, "node-a", store); err != nil {
		t.Fatal(err)
	}
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyAdded != 0 || result.PolicyUpdated != 0 || result.PolicyDeleted != 0 || result.PolicyUnchanged != 1 || result.PolicyEvents != 1 || result.PolicyRevisionMax != 2 {
		t.Fatalf("policy update summary = %+v, want one unchanged entry at revision 2", result)
	}
}

func TestPrepareReconcileWithTCXInterfaceAcceptsPortRangePolicy(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"range-web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "range-web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-range",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 8080, To: 8088}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	result, targets, _, err := prepareReconcile(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "lo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TCXEligible != 1 || len(targets) != 1 {
		t.Fatalf("tcx eligible/targets = %d/%d, want range policy target", result.TCXEligible, len(targets))
	}
	rules, err := dataplane.IPv4L4ACLRulesFromProgramsForDirection(targets[0].programs, model.DirectionIngress)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("tcx range rules = %+v, want two port-prefix blocks", rules)
	}
}

func TestReconcileNodeWithTCXInterfaceAcceptsCIDRPolicy(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"wide-web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "wide-web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-wide",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: dataplane.NewInMemoryPolicyStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TCXEligible != 1 {
		t.Fatalf("tcx eligible = %d, want 1 for CIDR policy", result.TCXEligible)
	}
}

func TestPrepareReconcileWithTCXInterfaceBuildsDualStackTarget(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"dual-web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "dual-web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{
				{
					ID:         "drop-v6",
					Priority:   200,
					Direction:  model.DirectionIngress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("fd00:20::/64"),
					Ports:      []model.PortRange{{From: 8080, To: 8080}},
					Action:     model.ActionDrop,
				},
				{
					ID:         "drop-v4",
					Priority:   100,
					Direction:  model.DirectionIngress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
					Ports:      []model.PortRange{{From: 8080, To: 8080}},
					Action:     model.ActionDrop,
				},
			},
		}},
	}
	result, targets, _, err := prepareReconcile(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "lo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 2 || result.TCXEligible != 1 {
		t.Fatalf("result = %+v, want both policy entries and one TCX-eligible program", result)
	}
	if len(targets) != 1 || targets[0].policyDirection != model.DirectionIngress {
		t.Fatalf("targets = %+v, want ingress TCX target for dual-stack policy", targets)
	}
	v4Rules, err := dataplane.IPv4L4ACLRulesFromProgramsForDirection(targets[0].programs, model.DirectionIngress)
	if err != nil {
		t.Fatalf("IPv4 TCX rules: %v", err)
	}
	if len(v4Rules) != 1 || v4Rules[0].SourceCIDR != netip.MustParsePrefix("172.30.0.0/24") {
		t.Fatalf("IPv4 TCX rules = %+v, want IPv4 CIDR rule", v4Rules)
	}
	v6Rules, err := dataplane.IPv6L4ACLRulesFromProgramsForDirection(targets[0].programs, model.DirectionIngress)
	if err != nil {
		t.Fatalf("IPv6 TCX rules: %v", err)
	}
	if len(v6Rules) != 1 || v6Rules[0].SourceCIDR != netip.MustParsePrefix("fd00:20::/64") {
		t.Fatalf("IPv6 TCX rules = %+v, want IPv6 CIDR rule", v6Rules)
	}
}

func TestPrepareReconcileWithTCXInterfaceAcceptsIPv6OnlyPolicy(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("fd00:10::10"),
			Node:           "node-a",
			SecurityGroups: []string{"v6-web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "v6-web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-v6",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("fd00:20::/64"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	result, targets, _, err := prepareReconcile(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "lo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 1 {
		t.Fatalf("result = %+v, want IPv6 policy entry and one TCX-eligible program", result)
	}
	if len(targets) != 1 || targets[0].policyDirection != model.DirectionIngress {
		t.Fatalf("targets = %+v, want ingress TCX target for IPv6 policy", targets)
	}
	v6Rules, err := dataplane.IPv6L4ACLRulesFromProgramsForDirection(targets[0].programs, model.DirectionIngress)
	if err != nil {
		t.Fatalf("IPv6 TCX rules: %v", err)
	}
	if len(v6Rules) != 1 || v6Rules[0].SourceCIDR != netip.MustParsePrefix("fd00:20::/64") {
		t.Fatalf("IPv6 TCX rules = %+v, want IPv6 CIDR rule", v6Rules)
	}
}

func TestTCXTargetsBuildsOneEgressTargetPerWorkload(t *testing.T) {
	targets := tcxTargets(ReconcileOptions{TCXWorkload: true}, []policy.Program{
		tcxProgram("pod-a", model.DirectionIngress, "172.30.0.11/32", 8080),
		tcxProgram("pod-b", model.DirectionIngress, "172.30.0.12/32", 8080),
	})
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	for i, target := range targets {
		if target.attach != ebpf.AttachTCXEgress {
			t.Fatalf("target %d attach = %v, want egress", i, target.attach)
		}
		if target.policyDirection != model.DirectionIngress {
			t.Fatalf("target %d policy direction = %s, want ingress", i, target.policyDirection)
		}
		if len(target.programs) != 1 {
			t.Fatalf("target %d programs = %d, want 1", i, len(target.programs))
		}
	}
	if targets[0].ifName == targets[1].ifName {
		t.Fatalf("expected distinct host veth names, got %s", targets[0].ifName)
	}
}

func TestTCXTargetsBuildsIngressTargetForWorkloadEgressPolicy(t *testing.T) {
	targets := tcxTargets(ReconcileOptions{TCXWorkload: true}, []policy.Program{
		tcxProgram("pod-a", model.DirectionEgress, "198.51.100.10/32", 443),
	})
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(targets))
	}
	target := targets[0]
	if target.attach != ebpf.AttachTCXIngress || target.policyDirection != model.DirectionEgress {
		t.Fatalf("unexpected target attach=%v policy_direction=%s", target.attach, target.policyDirection)
	}
	if target.ifName == "" || len(target.programs) != 1 {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestTCXTargetsBuildsOneIngressTargetForNodeInterface(t *testing.T) {
	programs := []policy.Program{
		tcxProgram("pod-a", model.DirectionIngress, "172.30.0.11/32", 8080),
		tcxProgram("pod-b", model.DirectionIngress, "172.30.0.12/32", 8080),
	}
	targets := tcxTargets(ReconcileOptions{TCXInterface: "eth0"}, programs)
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(targets))
	}
	target := targets[0]
	if target.ifName != "eth0" || target.attach != ebpf.AttachTCXIngress || target.policyDirection != model.DirectionIngress || len(target.programs) != 2 {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestAttachTCXTargetsRejectsEmptyTargets(t *testing.T) {
	_, err := attachTCXTargets(context.Background(), nil, 0)
	if err == nil {
		t.Fatal("expected empty targets to fail")
	}
}

func TestReconcilerKeepsAndReplacesTCXAttachments(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "pod-a",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.10"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
			{
				ID:             "pod-b",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.11"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	var attaches int
	var closes int
	reconciler.attach = func(_ context.Context, target tcxTarget) (tcxAttachmentHandle, error) {
		attaches++
		return tcxAttachmentHandle{
			result: dataplane.TCXSelfTestResult{Interface: target.ifName, Direction: "egress", Mode: "policy-l4"},
			close: func() error {
				closes++
				return nil
			},
		}, nil
	}
	options := ReconcileOptions{Node: "node-a", TCXWorkload: true}
	result, err := reconciler.Reconcile(context.Background(), state, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.TCX != "attached-workloads:2:egress:policy-l4" || attaches != 2 || closes != 0 {
		t.Fatalf("unexpected first reconcile result=%+v attaches=%d closes=%d", result, attaches, closes)
	}
	if _, err := reconciler.Reconcile(context.Background(), state, options); err != nil {
		t.Fatal(err)
	}
	if attaches != 2 || closes != 0 {
		t.Fatalf("expected unchanged reconcile to keep attachments, attaches=%d closes=%d", attaches, closes)
	}
	state.SecurityGroups[0].Rules[0].Action = model.ActionAllow
	if _, err := reconciler.Reconcile(context.Background(), state, options); err != nil {
		t.Fatal(err)
	}
	if attaches != 4 || closes != 2 {
		t.Fatalf("expected policy change to replace both attachments, attaches=%d closes=%d", attaches, closes)
	}
	state.Endpoints = state.Endpoints[:1]
	if _, err := reconciler.Reconcile(context.Background(), state, options); err != nil {
		t.Fatal(err)
	}
	if attaches != 4 || closes != 3 {
		t.Fatalf("expected stale attachment to close and remaining attachment to stay, attaches=%d closes=%d", attaches, closes)
	}
	if err := reconciler.Close(); err != nil {
		t.Fatal(err)
	}
	if closes != 4 {
		t.Fatalf("final closes = %d, want 4", closes)
	}
}

func TestReconcilerClearsConntrackWhenPolicyChangesOrEndpointIsRemoved(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("10.10.0.11/32"),
				Ports:      []model.PortRange{{From: 443, To: 443}},
				Action:     model.ActionAllow,
				Stateful:   true,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	reconciler.ConntrackStore().Add(dataplane.ConntrackKey{
		EndpointID:     "pod-a",
		RemoteIdentity: 100,
		Direction:      dataplane.DirectionEgress,
		Protocol:       6,
		DestPort:       55000,
	})
	if reconciler.ConntrackStore().Len() != 1 {
		t.Fatalf("conntrack entries = %d, want 1", reconciler.ConntrackStore().Len())
	}

	state.SecurityGroups[0].Rules[0].Action = model.ActionDrop
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if reconciler.ConntrackStore().Len() != 0 {
		t.Fatalf("conntrack entries after policy change = %d, want 0", reconciler.ConntrackStore().Len())
	}

	reconciler.ConntrackStore().Add(dataplane.ConntrackKey{
		EndpointID:     "pod-a",
		RemoteIdentity: 100,
		Direction:      dataplane.DirectionEgress,
		Protocol:       6,
		DestPort:       55000,
	})
	state.Endpoints = nil
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if reconciler.ConntrackStore().Len() != 0 {
		t.Fatalf("conntrack entries after endpoint removal = %d, want 0", reconciler.ConntrackStore().Len())
	}
}

func TestReconcilerClearsConntrackForNonTCXPolicyChange(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-any-cidr",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolAny,
				RemoteCIDR: netip.MustParsePrefix("10.10.0.11/32"),
				Action:     model.ActionAllow,
				Stateful:   true,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if tcxEligibleProgramForDirection(policy.Program{
		EndpointID: "pod-a",
		Rules: []policy.Rule{{
			ID:         "allow-any-cidr",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolAny,
			RemoteCIDR: netip.MustParsePrefix("10.10.0.11/32"),
			Action:     model.ActionAllow,
			Stateful:   true,
		}},
	}, model.DirectionIngress) {
		t.Fatal("test policy should not be TCX eligible")
	}

	reconciler.ConntrackStore().Add(dataplane.ConntrackKey{
		EndpointID:     "pod-a",
		RemoteIdentity: 100,
		Direction:      dataplane.DirectionEgress,
		Protocol:       6,
		DestPort:       55000,
	})
	state.SecurityGroups[0].Rules[0].Action = model.ActionDrop
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if reconciler.ConntrackStore().Len() != 0 {
		t.Fatalf("conntrack entries after non-TCX policy change = %d, want 0", reconciler.ConntrackStore().Len())
	}
}

func TestReconcilerExpiresIdleConntrack(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("10.10.0.11/32"),
				Ports:      []model.PortRange{{From: 443, To: 443}},
				Action:     model.ActionAllow,
				Stateful:   true,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	reconciler.ConntrackStore().Add(dataplane.ConntrackKey{
		EndpointID:     "pod-a",
		RemoteIdentity: 100,
		Direction:      dataplane.DirectionEgress,
		Protocol:       6,
		DestPort:       55000,
	})
	time.Sleep(time.Millisecond)

	result, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{
		Node:          "node-a",
		ConntrackIdle: time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ConntrackExpired != 1 || reconciler.ConntrackStore().Len() != 0 {
		t.Fatalf("conntrack expired=%d remaining=%d, want one idle entry expired", result.ConntrackExpired, reconciler.ConntrackStore().Len())
	}
}

func TestReconcileNodeAllowsMultipleEligibleWorkloadsWithoutTCXAttach(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "pod-a",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.10"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
			{
				ID:             "pod-b",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.11"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	result, err := ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err != nil {
		t.Fatal(err)
	}
	if result.TCXEligible != 2 {
		t.Fatalf("tcx eligible = %d, want 2", result.TCXEligible)
	}
}

func TestReconcileNodeRejectsMissingNodeName(t *testing.T) {
	_, err := ReconcileNode(context.Background(), control.DesiredState{}, "", dataplane.NewInMemoryPolicyStore())
	if err == nil {
		t.Fatal("expected empty node name to fail")
	}
}

func TestReconcileNodeRejectsUnknownSecurityGroup(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"missing"},
		}},
	}
	_, err := ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err == nil {
		t.Fatal("expected unknown security group to fail")
	}
}

func TestReconcileNodeExpandsRemoteGroupMembership(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "pod-a",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.10"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
			{
				ID:             "pod-b",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.11"),
				Node:           "node-b",
				SecurityGroups: []string{"clients"},
			},
		},
		SecurityGroups: []model.SecurityGroup{
			{
				Name: "web",
				VPC:  "prod",
				Rules: []model.SecurityGroupRule{{
					ID:          "drop-client-web",
					Priority:    100,
					Direction:   model.DirectionIngress,
					Protocol:    model.ProtocolTCP,
					RemoteGroup: "clients",
					Ports:       []model.PortRange{{From: 8080, To: 8080}},
					Action:      model.ActionDrop,
				}},
			},
			{Name: "clients", VPC: "prod"},
		},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	entries := store.Entries("pod-a")
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Key.RemoteIdentity != policy.EndpointIdentity("pod-b") {
		t.Fatalf("remote identity = %d, want pod-b identity", entries[0].Key.RemoteIdentity)
	}

	state.Endpoints = state.Endpoints[:1]
	result, err = ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 0 || result.TCXEligible != 0 {
		t.Fatalf("expected empty remote group to remove entries, got %+v", result)
	}
	if entries := store.Entries("pod-a"); len(entries) != 0 {
		t.Fatalf("entries after member removal = %d, want 0", len(entries))
	}
}

func TestReconcileNodeCompilesFQDNRulesFromDNSRecords(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"client"},
		}},
		SecurityGroups: []model.SecurityGroup{{
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
		}},
		DNSRecords: []model.DNSRecord{{
			Name: "api.example.com",
			IPs:  []netip.Addr{netip.MustParseAddr("203.0.113.10")},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	entries := store.Entries("pod-a")
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].RemoteCIDR.String() != "203.0.113.10/32" {
		t.Fatalf("remote cidr = %s, want fqdn-derived /32", entries[0].RemoteCIDR)
	}
	decision := dataplane.Evaluate(entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("203.0.113.10"),
		DestPort:  443,
	})
	if decision.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected fqdn-derived egress allow, got %+v", decision)
	}
}

func TestReconcileNodeCompilesCIDRGroupRules(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"client"},
		}},
		SecurityGroups: []model.SecurityGroup{{
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
		}},
		CIDRGroups: []model.CIDRGroup{{
			Name:  "corp",
			VPC:   "prod",
			CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.30.0.0/16")},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 2 || result.TCXEligible != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	entries := store.Entries("pod-a")
	decision := dataplane.Evaluate(entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("10.20.1.10"),
		DestPort:  443,
	})
	if decision.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected cidr-group-derived egress allow, got %+v", decision)
	}
}
