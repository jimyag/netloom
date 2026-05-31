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
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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
		{Command: "ip", Args: []string{"route", "replace", "10.10.0.11/32", "via", "172.30.0.12", "dev", "eth9", "proto", "187"}},
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
		"ip route replace 10.10.0.11/32 via 172.30.0.12 dev eth0 proto 187",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanRemoteRouteCleanupDeletesOnlyManagedStaleRoutes(t *testing.T) {
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
		CleanupStale: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.CleanupPlanned {
		t.Fatal("cleanup was not marked as planned")
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"ip route replace 10.10.0.11/32 via 172.30.0.12 dev eth9 proto 187",
		"ip $family -o route show proto 187 dev eth9",
		" 10.10.0.11/32 ",
		"ip $family route del \"$dst\" dev eth9 proto 187",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("managed remote route cleanup missing %q:\n%s", expected, joined)
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
				Type:     model.ActionReroute,
				NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")},
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
		"ip rule add priority 9800 from 10.10.0.0/24 to 172.16.0.0/16 ipproto tcp dport 443 table 20000 protocol 186",
		"ip route replace blackhole 198.51.100.0/24 table 20001",
		"ip rule add priority 9900 from 10.10.0.0/24 to 198.51.100.0/24 table 20001 protocol 186",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("policy route ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanProgramsAllowPolicyRouteToMainTable(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "allow-https",
			VPC:      "prod",
			Priority: 300,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("198.51.100.10/32"),
				Protocol:    model.ProtocolTCP,
				DstPorts:    []model.PortRange{{From: 443, To: 443}},
			},
			Action: model.RouteAction{Type: model.ActionAllow},
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
		"ip rule add priority 9700 from 10.10.0.0/24 to 198.51.100.10/32 ipproto tcp dport 443 table 254 protocol 186",
		"ip route replace blackhole 198.51.100.0/24 table 20000",
		"ip rule add priority 9900 from 10.10.0.0/24 to 198.51.100.0/24 table 20000 protocol 186",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("allow policy route ops missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "ip route replace 198.51.100.10/32") {
		t.Fatalf("allow policy route must not program a managed route table:\n%s", joined)
	}
}

func TestPlanProgramsIPv6LinuxPolicyRoute(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps-v6",
			IP:     netip.MustParseAddr("fd00:10::10"),
			Node:   "node-a",
		}},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "v6-via-fw",
			VPC:      "prod",
			Priority: 200,
			Match: model.RouteMatch{
				Source:   netip.MustParsePrefix("fd00:10::/64"),
				Protocol: model.ProtocolICMP,
			},
			Action: model.RouteAction{
				Type:     model.ActionReroute,
				NextHops: []netip.Addr{netip.MustParseAddr("fd00:10::fe")},
			},
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
	if result.PolicyRoutes != 1 {
		t.Fatalf("policy routes = %d, want 1", result.PolicyRoutes)
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"ip addr replace fd00:10::10/128 dev nl0",
		"ip route replace ::/0 via fd00:10::fe dev eth9 table 20000",
		"ip rule add priority 9800 from fd00:10::/64 ipproto ipv6-icmp table 20000 protocol 186",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("IPv6 policy route ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanProgramsECMPPolicyRoute(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "centralized-egress",
			VPC:      "prod",
			Priority: 200,
			Match: model.RouteMatch{
				Source: netip.MustParsePrefix("10.10.0.0/24"),
			},
			Action: model.RouteAction{
				Type: model.ActionReroute,
				NextHops: []netip.Addr{
					netip.MustParseAddr("10.10.0.253"),
					netip.MustParseAddr("10.10.0.254"),
				},
			},
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
	if result.PolicyRoutes != 1 {
		t.Fatalf("policy routes = %d, want 1", result.PolicyRoutes)
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"ip route replace 0.0.0.0/0 nexthop via 10.10.0.253 dev eth9 nexthop via 10.10.0.254 dev eth9 table 20000",
		"ip rule add priority 9800 from 10.10.0.0/24 table 20000 protocol 186",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("ECMP policy route ops missing %q:\n%s", expected, joined)
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
	for _, expected := range []string{"ip rule show", "start=22000", "end=22064", "proto=186", "ip rule del priority"} {
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
			Action:   model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
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
	}, {
		Name:   "local-allow",
		VPC:    "prod",
		Match:  model.RouteMatch{Destination: netip.MustParsePrefix("203.0.113.10/32")},
		Action: model.RouteAction{Type: model.ActionAllow},
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
	applicable, err = applicablePolicyRoutes(routes[1:], map[string]struct{}{"prod": struct{}{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(applicable) != 1 || applicable[0].Name != "local-allow" {
		t.Fatalf("applicable routes = %+v, want local allow route", applicable)
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

func TestNetlinkPolicyRuleCleanupCoversIPv4AndIPv6(t *testing.T) {
	families := netlinkPolicyRuleFamilies()
	if !reflect.DeepEqual(families, []int{unix.AF_INET, unix.AF_INET6}) {
		t.Fatalf("cleanup families = %#v, want IPv4 and IPv6", families)
	}
}

func TestManagedPolicyRuleIncludesProtocolMarker(t *testing.T) {
	options := Options{PolicyTableBase: 22000, PolicyTableSize: 64}
	if !managedPolicyRule(netlink.Rule{Table: linuxMainRouteTable, Protocol: linuxPolicyRuleProtocolID}, options) {
		t.Fatal("rule with netloom protocol marker should be managed")
	}
	if managedPolicyRule(netlink.Rule{Table: linuxMainRouteTable}, options) {
		t.Fatal("main table rule without netloom protocol marker should not be managed")
	}
}

func TestAllocatePolicyRouteTablesKeepsExistingNamesStable(t *testing.T) {
	options := Options{PolicyTableBase: 22000, PolicyTableSize: 1024}
	routes := []model.PolicyRoute{
		testReroutePolicyRoute("web", 200),
		testReroutePolicyRoute("db", 100),
	}
	before, err := allocatePolicyRouteTables(routes, options)
	if err != nil {
		t.Fatal(err)
	}
	after, err := allocatePolicyRouteTables(append([]model.PolicyRoute{testReroutePolicyRoute("api", 300)}, routes...), options)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"web", "db"} {
		if before[name] != after[name] {
			t.Fatalf("table for %s changed from %d to %d after inserting another policy route", name, before[name], after[name])
		}
	}
	if before["web"] == before["db"] || after["api"] == after["web"] || after["api"] == after["db"] {
		t.Fatalf("allocated duplicate tables: before=%v after=%v", before, after)
	}
}

func TestAllocatePolicyRouteTablesRejectsExhaustedRange(t *testing.T) {
	_, err := allocatePolicyRouteTables([]model.PolicyRoute{
		testReroutePolicyRoute("web", 200),
		testReroutePolicyRoute("db", 100),
	}, Options{PolicyTableBase: 22000, PolicyTableSize: 1})
	if err == nil {
		t.Fatal("expected exhausted policy table range to fail")
	}
}

func TestAllocatePolicyRouteTablesRejectsDuplicateNames(t *testing.T) {
	_, err := allocatePolicyRouteTables([]model.PolicyRoute{
		testReroutePolicyRoute("web", 200),
		testReroutePolicyRoute("web", 100),
	}, Options{PolicyTableBase: 22000, PolicyTableSize: 64})
	if err == nil {
		t.Fatal("expected duplicate policy route names to fail")
	}
}

func TestPolicyRuleKeySeparatesPortsAndProtocolMarker(t *testing.T) {
	route := model.PolicyRoute{
		Name:     "https-via-fw",
		VPC:      "prod",
		Priority: 200,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("172.16.0.0/16"),
			Protocol:    model.ProtocolTCP,
			DstPorts:    []model.PortRange{{From: 443, To: 443}, {From: 8443, To: 8443}},
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	}
	rules := netlinkPolicyRules(route, linuxPolicyRulePriority(route.Priority), 20000)
	if policyRuleKey(*rules[0]) == policyRuleKey(*rules[1]) {
		t.Fatalf("policy rule keys should include destination port: %q", policyRuleKey(*rules[0]))
	}
	unmarked := *rules[0]
	unmarked.Protocol = 0
	if policyRuleKey(*rules[0]) == policyRuleKey(unmarked) {
		t.Fatalf("policy rule keys should include protocol marker: %q", policyRuleKey(*rules[0]))
	}
}

func TestRouteEquivalentDetectsNextHopChanges(t *testing.T) {
	route := testReroutePolicyRoute("web", 200)
	first, err := policyRouteNetlinkRoute(route, 22000, 10)
	if err != nil {
		t.Fatal(err)
	}
	route.Action.NextHops = []netip.Addr{netip.MustParseAddr("10.10.0.254")}
	second, err := policyRouteNetlinkRoute(route, 22000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if routeEquivalent(*first, *second) {
		t.Fatalf("routes with different next hops should not be equivalent: %#v %#v", first, second)
	}
	clone, err := policyRouteNetlinkRoute(testReroutePolicyRoute("web", 200), 22000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !routeEquivalent(*first, *clone) {
		t.Fatalf("identical routes should be equivalent: %#v %#v", first, clone)
	}
}

func TestRemoteEndpointNetlinkRouteCarriesProtocolMarker(t *testing.T) {
	route, err := remoteEndpointNetlinkRoute(netip.MustParseAddr("10.10.0.11"), netip.MustParseAddr("172.30.0.12"), 9)
	if err != nil {
		t.Fatal(err)
	}
	if route.Table != linuxMainRouteTable || route.LinkIndex != 9 || route.Dst.String() != "10.10.0.11/32" || route.Gw.String() != "172.30.0.12" {
		t.Fatalf("unexpected remote route: %+v", route)
	}
	if int(route.Protocol) != linuxRemoteRouteProtocolID {
		t.Fatalf("remote route protocol = %d, want %d", route.Protocol, linuxRemoteRouteProtocolID)
	}
}

func TestRemoteEndpointPrefixesExcludeLocalEndpoints(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a"},
			{ID: "pod-b", IP: netip.MustParseAddr("10.10.0.11"), Node: "node-b"},
			{ID: "pod-v6", IP: netip.MustParseAddr("fd00:10::11"), Node: "node-b"},
		},
	}
	want := []string{"10.10.0.11/32", "fd00:10::11/128"}
	if got := remoteEndpointPrefixes(state, "node-a"); !reflect.DeepEqual(got, want) {
		t.Fatalf("remote endpoint prefixes = %#v, want %#v", got, want)
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
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	}
	rules := netlinkPolicyRules(route, linuxPolicyRulePriority(route.Priority), 20000)
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	rule := rules[0]
	if rule.Priority != 9800 || rule.Table != 20000 || rule.Src.String() != "10.10.0.0/24" || rule.Dst.String() != "172.16.0.0/16" {
		t.Fatalf("unexpected rule: %+v", rule)
	}
	if int(rule.Protocol) != linuxPolicyRuleProtocolID {
		t.Fatalf("rule protocol = %d, want %d", rule.Protocol, linuxPolicyRuleProtocolID)
	}
	if rule.IPProto != 6 || rule.Dport == nil || rule.Dport.Start != 443 || rule.Dport.End != 443 {
		t.Fatalf("unexpected L4 match: proto=%d dport=%+v", rule.IPProto, rule.Dport)
	}
}

func testReroutePolicyRoute(name string, priority int) model.PolicyRoute {
	return model.PolicyRoute{
		Name:     name,
		VPC:      "prod",
		Priority: priority,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("172.16.0.0/16"),
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	}
}

func TestNetlinkPolicyRuleEncodesIPv6Family(t *testing.T) {
	route := model.PolicyRoute{
		Name:     "v6-via-fw",
		VPC:      "prod",
		Priority: 200,
		Match: model.RouteMatch{
			Source:   netip.MustParsePrefix("fd00:10::/64"),
			Protocol: model.ProtocolICMP,
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("fd00:10::fe")}},
	}
	rules := netlinkPolicyRules(route, linuxPolicyRulePriority(route.Priority), 20000)
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	rule := rules[0]
	if rule.Family != unix.AF_INET6 || rule.Src.String() != "fd00:10::/64" {
		t.Fatalf("unexpected IPv6 rule: %+v", rule)
	}
	if rule.IPProto != unix.IPPROTO_ICMPV6 {
		t.Fatalf("ipproto = %d, want ICMPv6", rule.IPProto)
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

func TestDatapathBackendDefaultsToNetlink(t *testing.T) {
	if got := datapathBackend(""); got != "netlink" {
		t.Fatalf("default backend = %s, want netlink", got)
	}
	if got := datapathBackend("command"); got != "command" {
		t.Fatalf("explicit backend = %s, want command", got)
	}
}

func stringifyOps(ops []Operation) string {
	lines := make([]string, 0, len(ops))
	for _, op := range ops {
		lines = append(lines, op.Command+" "+strings.Join(op.Args, " "))
	}
	return strings.Join(lines, "\n")
}
