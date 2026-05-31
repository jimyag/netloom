package agent

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/linuxdatapath"
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

func TestReconcilerDeletesStaleEndpointPolicy(t *testing.T) {
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
	reconciler := NewReconciler(store)
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if entries := store.Entries("pod-a"); len(entries) != 1 {
		t.Fatalf("pod-a entries = %d, want 1", len(entries))
	}

	state.Endpoints = nil
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if entries := store.Entries("pod-a"); len(entries) != 0 {
		t.Fatalf("stale pod-a entries = %+v, want deleted", entries)
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

func TestAttachTCXTargetsReportsNotAttachedForEmptyTargets(t *testing.T) {
	status, err := attachTCXTargets(context.Background(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if status != "not-attached" {
		t.Fatalf("status = %q, want not-attached", status)
	}
}

func TestReconcileNodeWithTCXInterfaceAllowsNoEligiblePolicy(t *testing.T) {
	result, err := ReconcileNodeWithOptions(context.Background(), control.DesiredState{}, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "lo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TCX != "not-attached" || result.TCXEligible != 0 {
		t.Fatalf("result = %+v, want no eligible TCX policy and not-attached", result)
	}
}

func TestReconcileNodeWithTCXInterfaceTreatsAllowOnlyPolicyAsNotEligible(t *testing.T) {
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
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionAllow,
			}},
		}},
	}

	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "lo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 0 || result.TCX != "not-attached" {
		t.Fatalf("result = %+v, want policy stored but allow-only TCX not attached", result)
	}
}

func TestReconcileNodeWithTCXRejectsRemoteEndpointPolicy(t *testing.T) {
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
				SecurityGroups: []string{"client"},
			},
		},
		SecurityGroups: []model.SecurityGroup{
			{
				Name: "web",
				VPC:  "prod",
				Rules: []model.SecurityGroupRule{{
					ID:          "drop-client",
					Priority:    100,
					Direction:   model.DirectionIngress,
					Protocol:    model.ProtocolTCP,
					RemoteGroup: "client",
					Ports:       []model.PortRange{{From: 8080, To: 8080}},
					Action:      model.ActionDrop,
				}},
			},
			{Name: "client", VPC: "prod"},
		},
	}

	_, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "lo",
	})
	if err == nil || !strings.Contains(err.Error(), "remote endpoint identity match") {
		t.Fatalf("error = %v, want explicit remote endpoint identity TCX rejection", err)
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
	result, err = reconciler.Reconcile(context.Background(), state, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.TCX != "not-attached" || attaches != 2 || closes != 2 {
		t.Fatalf("expected allow-only policy change to close attachments, result=%+v attaches=%d closes=%d", result, attaches, closes)
	}
	state.Endpoints = state.Endpoints[:1]
	if _, err := reconciler.Reconcile(context.Background(), state, options); err != nil {
		t.Fatal(err)
	}
	if attaches != 2 || closes != 2 {
		t.Fatalf("expected no stale attachment left to close, attaches=%d closes=%d", attaches, closes)
	}
	if err := reconciler.Close(); err != nil {
		t.Fatal(err)
	}
	if closes != 2 {
		t.Fatalf("final closes = %d, want 2", closes)
	}
}

func TestReconcilerClosesTCXAttachmentsWhenPolicyNoLongerEligible(t *testing.T) {
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
	if result.TCX != "attached:"+linuxdatapath.HostVethName("pod-a")+":egress:policy-l4" || attaches != 1 || closes != 0 {
		t.Fatalf("unexpected first reconcile result=%+v attaches=%d closes=%d", result, attaches, closes)
	}

	state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.Prefix{}
	state.SecurityGroups[0].Rules[0].RemoteGroup = "client"
	state.SecurityGroups = append(state.SecurityGroups, model.SecurityGroup{Name: "client", VPC: "prod"})
	result, err = reconciler.Reconcile(context.Background(), state, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.TCX != "not-attached" {
		t.Fatalf("tcx = %q, want not-attached", result.TCX)
	}
	if attaches != 1 || closes != 1 {
		t.Fatalf("expected stale attachment to close without reattach, attaches=%d closes=%d", attaches, closes)
	}
	if err := reconciler.Close(); err != nil {
		t.Fatal(err)
	}
	if closes != 1 {
		t.Fatalf("close should not close already removed attachments again, closes=%d", closes)
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

func TestReconcileNodeRejectsDuplicateSecurityGroups(t *testing.T) {
	state := control.DesiredState{
		SecurityGroups: []model.SecurityGroup{
			{Name: "web", VPC: "prod"},
			{Name: "web", VPC: "prod"},
		},
	}
	_, err := ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err == nil {
		t.Fatal("expected duplicate security groups to fail")
	}
	if !strings.Contains(err.Error(), "duplicate security group name") {
		t.Fatalf("error %q does not mention duplicate security group name", err)
	}
}

func TestReconcileNodeRejectsDuplicateEndpoints(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:     "pod-a",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.10"),
				Node:   "node-a",
			},
			{
				ID:     "pod-a",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.11"),
				Node:   "node-a",
			},
		},
	}
	_, err := ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err == nil {
		t.Fatal("expected duplicate endpoints to fail")
	}
	if !strings.Contains(err.Error(), "duplicate endpoint id") {
		t.Fatalf("error %q does not mention duplicate endpoint id", err)
	}
}

func TestReconcileNodeRejectsDuplicateLoadBalancers(t *testing.T) {
	state := control.DesiredState{
		LoadBalancers: []model.LoadBalancer{
			{
				Name: "api",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Ports: []model.LoadBalancerPort{{
					Port:     443,
					Protocol: model.ProtocolTCP,
					Backends: []model.LoadBalancerBackend{{
						IP:   netip.MustParseAddr("10.10.0.10"),
						Port: 8443,
					}},
				}},
			},
			{
				Name: "api",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.11"),
				Ports: []model.LoadBalancerPort{{
					Port:     443,
					Protocol: model.ProtocolTCP,
					Backends: []model.LoadBalancerBackend{{
						IP:   netip.MustParseAddr("10.10.0.11"),
						Port: 8443,
					}},
				}},
			},
		},
	}
	_, err := ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err == nil {
		t.Fatal("expected duplicate load balancers to fail")
	}
	if !strings.Contains(err.Error(), "duplicate load balancer") {
		t.Fatalf("error %q does not mention duplicate load balancer", err)
	}
}

func TestReconcileNodeRejectsDuplicateCIDRGroups(t *testing.T) {
	state := control.DesiredState{
		CIDRGroups: []model.CIDRGroup{
			{Name: "corp", VPC: "prod", CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}},
			{Name: "corp", VPC: "prod", CIDRs: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}},
		},
	}
	_, err := ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err == nil {
		t.Fatal("expected duplicate cidr groups to fail")
	}
	if !strings.Contains(err.Error(), "duplicate cidr group") {
		t.Fatalf("error %q does not mention duplicate cidr group", err)
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
	if result.Entries != 1 || result.TCXEligible != 0 {
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

func TestReconcileNodeExpandsRemoteEndpointSelector(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "pod-web",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.20"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
			{
				ID:     "pod-client",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.10"),
				Node:   "node-b",
				Labels: model.Labels{"app": "client", "env": "prod"},
			},
			{
				ID:     "pod-dev-client",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.11"),
				Node:   "node-c",
				Labels: model.Labels{"app": "client", "env": "dev"},
			},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:                     "allow-client",
				Priority:               100,
				Direction:              model.DirectionIngress,
				Protocol:               model.ProtocolTCP,
				RemoteEndpointSelector: model.Labels{"app": "client"},
				RemoteEndpointExprs: []model.LabelExpr{
					{Key: "env", Operator: "In", Values: []string{"prod"}},
				},
				Ports:  []model.PortRange{{From: 8080, To: 8080}},
				Action: model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	entries := store.Entries("pod-web")
	decision := dataplane.Evaluate(entries, dataplane.Packet{
		RemoteIdentity: policy.EndpointIdentity("pod-client"),
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		RemoteIP:       netip.MustParseAddr("10.10.0.10"),
		DestPort:       8080,
	})
	if decision.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected selector-derived ingress allow, got %+v", decision)
	}
	devDecision := dataplane.Evaluate(entries, dataplane.Packet{
		RemoteIdentity: policy.EndpointIdentity("pod-dev-client"),
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		RemoteIP:       netip.MustParseAddr("10.10.0.11"),
		DestPort:       8080,
	})
	if devDecision.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected selector expression to reject dev client, got %+v", devDecision)
	}
}

func TestReconcileNodeCompilesRemoteServiceRule(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-client",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"client"},
		}},
		LoadBalancers: []model.LoadBalancer{{
			Name: "web",
			VPC:  "prod",
			VIP:  netip.MustParseAddr("10.96.0.10"),
			Ports: []model.LoadBalancerPort{{
				Port:     80,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{{
					IP:   netip.MustParseAddr("10.10.0.20"),
					Port: 8080,
				}},
			}},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:            "allow-web-service",
				Priority:      100,
				Direction:     model.DirectionEgress,
				Protocol:      model.ProtocolAny,
				RemoteService: "web",
				Action:        model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	decision := dataplane.Evaluate(store.Entries("pod-client"), dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("10.96.0.10"),
		DestPort:  80,
	})
	if decision.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected egress tcp/80 to service VIP to allow, got %+v", decision)
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
	if result.Entries != 1 || result.TCXEligible != 0 {
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
			CIDRs: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")},
			Entries: []model.CIDRGroupEntry{{
				CIDR:        netip.MustParsePrefix("10.20.0.0/16"),
				ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.128.0/17")},
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 2 || result.TCXEligible != 0 {
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
	excluded := dataplane.Evaluate(entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("10.20.200.10"),
		DestPort:  443,
	})
	if excluded.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected cidr-group except range to drop, got %+v", excluded)
	}
}

func TestReconcileNodeCompilesHostEntityFromGateways(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"client"},
		}},
		Gateways: []model.Gateway{{
			Name:  "gw-a",
			VPC:   "prod",
			Node:  "node-a",
			LANIP: netip.MustParseAddr("10.10.0.254"),
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:             "allow-host",
				Priority:       100,
				Direction:      model.DirectionEgress,
				Protocol:       model.ProtocolTCP,
				RemoteEntities: []string{"host"},
				Ports:          []model.PortRange{{From: 9444, To: 9444}},
				Action:         model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	entries := store.Entries("pod-a")
	if len(entries) != 1 || entries[0].RemoteCIDR.String() != "10.10.0.254/32" {
		t.Fatalf("entries = %+v, want host gateway /32", entries)
	}
	decision := dataplane.Evaluate(entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("10.10.0.254"),
		DestPort:  9444,
	})
	if decision.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected host entity egress allow, got %+v", decision)
	}
}

func TestReconcileNodeCompilesRemoteNodeEntityFromGateways(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"client"},
		}},
		Gateways: []model.Gateway{
			{
				Name:  "gw-local",
				VPC:   "prod",
				Node:  "node-a",
				LANIP: netip.MustParseAddr("10.10.0.254"),
			},
			{
				Name:  "gw-remote",
				VPC:   "prod",
				Node:  "node-b",
				LANIP: netip.MustParseAddr("10.10.0.253"),
			},
		},
		SecurityGroups: []model.SecurityGroup{{
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
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	entries := store.Entries("pod-a")
	if len(entries) != 1 || entries[0].RemoteCIDR.String() != "10.10.0.253/32" {
		t.Fatalf("entries = %+v, want remote node gateway /32", entries)
	}
	remoteDecision := dataplane.Evaluate(entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("10.10.0.253"),
		DestPort:  4240,
	})
	if remoteDecision.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected remote-node entity egress allow, got %+v", remoteDecision)
	}
	localDecision := dataplane.Evaluate(entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("10.10.0.254"),
		DestPort:  4240,
	})
	if localDecision.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected local gateway to stay outside remote-node entity, got %+v", localDecision)
	}
}
