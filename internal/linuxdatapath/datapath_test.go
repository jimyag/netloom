package linuxdatapath

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/model"
)

func TestPlanProgramsLocalAddressesAndRemoteRoutes(t *testing.T) {
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
				ID:     "pod-b",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.11"),
				Node:   "node-b",
			},
		},
	}
	ops, result, err := Plan(context.Background(), state, Options{
		Node:           "node-a",
		LocalDevice:    "nl0",
		UnderlayDevice: "eth9",
		NodeUnderlays: map[string]netip.Addr{
			"node-b": netip.MustParseAddr("172.30.0.12"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.LocalAddresses != 1 || result.RemoteRoutes != 1 || result.Device != "nl0" {
		t.Fatalf("unexpected result: %+v", result)
	}
	want := []Operation{
		{Command: "ip", Args: []string{"link", "set", "nl0", "up"}},
		{Command: "ip", Args: []string{"addr", "replace", "10.10.0.10/32", "dev", "nl0"}},
		{Command: "ip", Args: []string{"route", "replace", "10.10.0.11/32", "via", "172.30.0.12", "dev", "eth9"}},
	}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("ops = %#v, want %#v", ops, want)
	}
}

func TestPlanRequiresRemoteUnderlay(t *testing.T) {
	_, _, err := Plan(context.Background(), control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-b",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.11"),
			Node:   "missing-node",
		}},
	}, Options{Node: "node-a"})
	if err == nil {
		t.Fatal("expected missing remote underlay to fail")
	}
}

func TestPlanNetNSProgramsVethAndNamespace(t *testing.T) {
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
				ID:     "pod-b",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.11"),
				Node:   "node-b",
			},
		},
	}
	ops, result, err := Plan(context.Background(), state, Options{
		Node:          "node-a",
		Mode:          "netns",
		WorkloadIF:    "eth0",
		NodeUnderlays: map[string]netip.Addr{"node-b": netip.MustParseAddr("172.30.0.12")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != "netns" || result.Device != "netns" || result.LocalAddresses != 1 || result.RemoteRoutes != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"ip_forward=1",
		"ip netns add nl-pod-a",
		"ip netns exec nl-pod-a ip addr replace 10.10.0.10/32 dev eth0",
		"ip netns exec nl-pod-a ip route replace default via 169.254.1.1 dev eth0 onlink",
		"ip route replace 10.10.0.11/32 via 172.30.0.12 dev eth0",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanProgramsLinuxPolicyRoutes(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "https-via-fw",
			VPC:      "prod",
			Priority: 200,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("172.16.0.0/16"),
				Protocol:    model.ProtocolTCP,
				DstPorts:    []model.PortRange{{From: 443, To: 443}},
			},
			Action: model.RouteAction{
				Type:    model.ActionReroute,
				NextHop: netip.MustParseAddr("10.10.0.253"),
			},
		}, {
			Name:     "drop-lab",
			VPC:      "prod",
			Priority: 100,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("198.51.100.0/24"),
			},
			Action: model.RouteAction{Type: model.ActionDrop},
		}},
	}

	ops, result, err := Plan(context.Background(), state, Options{
		Node:            "node-a",
		LocalDevice:     "nl0",
		UnderlayDevice:  "eth9",
		PolicyTableBase: 20000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyRoutes != 2 {
		t.Fatalf("policy routes = %d, want 2", result.PolicyRoutes)
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"ip route replace 172.16.0.0/16 via 10.10.0.253 dev eth9 table 20000",
		"ip rule add priority 9800 from 10.10.0.0/24 to 172.16.0.0/16 ipproto tcp dport 443 table 20000",
		"ip route replace blackhole 198.51.100.0/24 table 20001",
		"ip rule add priority 9900 from 10.10.0.0/24 to 198.51.100.0/24 table 20001",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("policy route ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanCleansManagedPolicyRouteRulesWhenRequested(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
	}
	ops, result, err := Plan(context.Background(), state, Options{
		Node:            "node-a",
		PolicyTableBase: 22000,
		PolicyTableSize: 64,
		CleanupStale:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyRoutes != 0 {
		t.Fatalf("policy routes = %d, want 0", result.PolicyRoutes)
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{"ip rule show", "start=22000", "end=22064", "ip rule del priority"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("cleanup ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanSkipsPolicyRoutesWithoutLocalVPC(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "other-vpc",
			VPC:      "other",
			Priority: 100,
			Match:    model.RouteMatch{Destination: netip.MustParsePrefix("172.16.0.0/16")},
			Action:   model.RouteAction{Type: model.ActionReroute, NextHop: netip.MustParseAddr("10.10.0.253")},
		}},
	}
	ops, result, err := Plan(context.Background(), state, Options{Node: "node-a", UnderlayDevice: "eth9"})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyRoutes != 0 {
		t.Fatalf("policy routes = %d, want 0", result.PolicyRoutes)
	}
	if strings.Contains(stringifyOps(ops), "ip rule") {
		t.Fatalf("unexpected policy route ops:\n%s", stringifyOps(ops))
	}
}

func TestApplicablePolicyRoutesValidatesAndSkipsNonLocalRoutes(t *testing.T) {
	routes := []model.PolicyRoute{{
		Name:   "invalid-any-port",
		VPC:    "prod",
		Match:  model.RouteMatch{Protocol: model.ProtocolAny, DstPorts: []model.PortRange{{From: 53, To: 53}}},
		Action: model.RouteAction{Type: model.ActionDrop},
	}, {
		Name:   "other-vpc",
		VPC:    "other",
		Match:  model.RouteMatch{Destination: netip.MustParsePrefix("192.0.2.0/24")},
		Action: model.RouteAction{Type: model.ActionDrop},
	}}
	_, err := applicablePolicyRoutes(routes, map[string]struct{}{"prod": struct{}{}})
	if err == nil {
		t.Fatal("expected local invalid policy route to fail")
	}
	applicable, err := applicablePolicyRoutes(routes, map[string]struct{}{"other": struct{}{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(applicable) != 1 || applicable[0].Name != "other-vpc" {
		t.Fatalf("applicable routes = %+v, want only other-vpc", applicable)
	}
}

func TestManagedPolicyTableRange(t *testing.T) {
	options := Options{PolicyTableBase: 22000, PolicyTableSize: 64}
	for _, table := range []int{22000, 22063} {
		if !managedPolicyTable(table, options) {
			t.Fatalf("table %d should be managed", table)
		}
	}
	for _, table := range []int{21999, 22064} {
		if managedPolicyTable(table, options) {
			t.Fatalf("table %d should not be managed", table)
		}
	}
}

func TestNetlinkPolicyRuleEncodesL4Match(t *testing.T) {
	route := model.PolicyRoute{
		Name:     "https-via-fw",
		VPC:      "prod",
		Priority: 200,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("172.16.0.0/16"),
			Protocol:    model.ProtocolTCP,
			DstPorts:    []model.PortRange{{From: 443, To: 443}},
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHop: netip.MustParseAddr("10.10.0.253")},
	}
	rules := netlinkPolicyRules(route, linuxPolicyRulePriority(route.Priority), 20000)
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	rule := rules[0]
	if rule.Priority != 9800 || rule.Table != 20000 || rule.Src.String() != "10.10.0.0/24" || rule.Dst.String() != "172.16.0.0/16" {
		t.Fatalf("unexpected rule: %+v", rule)
	}
	if rule.IPProto != 6 || rule.Dport == nil || rule.Dport.Start != 443 || rule.Dport.End != 443 {
		t.Fatalf("unexpected L4 match: proto=%d dport=%+v", rule.IPProto, rule.Dport)
	}
}

func TestPlanNetNSCleanupDeletesStaleNamespaces(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
	}
	ops, result, err := Plan(context.Background(), state, Options{
		Node:         "node-a",
		Mode:         "netns",
		CleanupStale: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.CleanupPlanned {
		t.Fatal("cleanup was not marked as planned")
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{"ip netns list", "grep '^nl-'", " nl-pod-a ", "ip netns del"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("cleanup ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestHostVethNameIsStableAndShort(t *testing.T) {
	first := HostVethName("file-pod-a")
	second := HostVethName("file-pod-a")
	if first != second {
		t.Fatalf("host veth name is not stable: %s != %s", first, second)
	}
	if len(first) > 15 {
		t.Fatalf("host veth name %q is longer than Linux ifname limit", first)
	}
}

func TestListManagedNetNSFiltersByPrefix(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"nl-pod-a", "nl-pod-b", "other-pod", "nlx-pod"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	names, err := listManagedNetNSAt(dir, "nl")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"nl-pod-a", "nl-pod-b"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %#v, want %#v", names, want)
	}
}

func TestNormalizeOptionsDefaultsNetlinkSettings(t *testing.T) {
	options, result, err := normalizeOptions(Options{Node: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	if options.Mode != "local" || options.LocalDevice != "lo" || options.UnderlayDevice != "eth0" || options.WorkloadIF != "eth0" {
		t.Fatalf("unexpected defaults: %+v", options)
	}
	if options.HostGateway != netip.MustParseAddr("169.254.1.1") {
		t.Fatalf("host gateway = %s", options.HostGateway)
	}
	if options.PolicyTableBase != 10000 {
		t.Fatalf("policy table base = %d, want 10000", options.PolicyTableBase)
	}
	if result.Device != "lo" || result.Mode != "local" {
		t.Fatalf("unexpected result defaults: %+v", result)
	}
}

func stringifyOps(ops []Operation) string {
	lines := make([]string, 0, len(ops))
	for _, op := range ops {
		lines = append(lines, op.Command+" "+strings.Join(op.Args, " "))
	}
	return strings.Join(lines, "\n")
}
