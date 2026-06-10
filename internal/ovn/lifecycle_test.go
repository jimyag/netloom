package ovn

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/topology"
)

func TestSnapshotDesiredKeepsPolicyRoutesWithSameOVNMatch(t *testing.T) {
	state := topology.State{
		PolicyRoutes: []model.PolicyRoute{
			{
				Name:     "allow-api",
				VPC:      "prod",
				Priority: 100,
				Match:    model.RouteMatch{Source: netip.MustParsePrefix("10.10.0.0/24")},
				Action:   model.RouteAction{Type: model.ActionAllow},
			},
			{
				Name:     "drop-api",
				VPC:      "prod",
				Priority: 100,
				Match:    model.RouteMatch{Source: netip.MustParsePrefix("10.10.0.0/24")},
				Action:   model.RouteAction{Type: model.ActionDrop},
			},
		},
	}

	snapshot := snapshotDesired(state)
	if got := len(snapshot.PolicyRoutes); got != 2 {
		t.Fatalf("policy route snapshot length = %d, want 2", got)
	}
	if _, ok := snapshot.PolicyRoutes[policyRouteKey(state.PolicyRoutes[0])]; !ok {
		t.Fatalf("allow-api policy route missing from snapshot: %#v", snapshot.PolicyRoutes)
	}
	if _, ok := snapshot.PolicyRoutes[policyRouteKey(state.PolicyRoutes[1])]; !ok {
		t.Fatalf("drop-api policy route missing from snapshot: %#v", snapshot.PolicyRoutes)
	}
}

func TestRouteCleanupFromSingleToECMPPreservesExistingHop(t *testing.T) {
	oldState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
				}},
			},
		},
	}
	nextState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("10.10.0.254"),
						netip.MustParseAddr("10.10.0.253"),
					},
				}},
			},
		},
	}

	old := snapshotDesired(oldState).Routes[routeKey("prod", oldState.RouteTables["main"].Routes[0])]
	next := snapshotDesired(nextState).Routes[routeKey("prod", nextState.RouteTables["main"].Routes[0])]
	ops := routeUpdateCleanupOperations(old, next)
	if len(ops) != 0 {
		t.Fatalf("route cleanup ops = %v, want 0", ops)
	}
}

func TestRouteCleanupFromSingleToECMPPreservesExistingIPv6Hop(t *testing.T) {
	oldState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("2001:db8::/32"),
					NextHops:    []netip.Addr{netip.MustParseAddr("2001:db8::254")},
				}},
			},
		},
	}
	nextState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("2001:db8::/32"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("2001:db8::254"),
						netip.MustParseAddr("2001:db8::253"),
					},
				}},
			},
		},
	}

	old := snapshotDesired(oldState).Routes[routeKey("prod", oldState.RouteTables["main"].Routes[0])]
	next := snapshotDesired(nextState).Routes[routeKey("prod", nextState.RouteTables["main"].Routes[0])]
	ops := routeUpdateCleanupOperations(old, next)
	if len(ops) != 0 {
		t.Fatalf("route cleanup ops = %v, want 0", ops)
	}
}

func TestRouteCleanupFromECMPReorderedNextHops(t *testing.T) {
	oldState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("10.10.0.254"),
						netip.MustParseAddr("10.10.0.253"),
					},
				}},
			},
		},
	}
	nextState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("10.10.0.253"),
						netip.MustParseAddr("10.10.0.254"),
					},
				}},
			},
		},
	}

	old := snapshotDesired(oldState).Routes[routeKey("prod", oldState.RouteTables["main"].Routes[0])]
	next := snapshotDesired(nextState).Routes[routeKey("prod", nextState.RouteTables["main"].Routes[0])]
	ops := routeUpdateCleanupOperations(old, next)
	if len(ops) != 0 {
		t.Fatalf("route cleanup ops = %v, want 0 for reordered next hops", ops)
	}
}

func TestRouteCleanupFromECMPIPv6ReorderedNextHops(t *testing.T) {
	oldState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("2001:db8::/32"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("2001:db8::254"),
						netip.MustParseAddr("2001:db8::253"),
					},
				}},
			},
		},
	}
	nextState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("2001:db8::/32"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("2001:db8::253"),
						netip.MustParseAddr("2001:db8::254"),
					},
				}},
			},
		},
	}

	old := snapshotDesired(oldState).Routes[routeKey("prod", oldState.RouteTables["main"].Routes[0])]
	next := snapshotDesired(nextState).Routes[routeKey("prod", nextState.RouteTables["main"].Routes[0])]
	ops := routeUpdateCleanupOperations(old, next)
	if len(ops) != 0 {
		t.Fatalf("ipv6 route cleanup ops = %v, want 0 for reordered next hops", ops)
	}
}

func TestRouteCleanupFromECMPToSinglePreservesExistingHop(t *testing.T) {
	oldState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("10.10.0.252"),
						netip.MustParseAddr("10.10.0.253"),
					},
				}},
			},
		},
	}
	nextState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.253")},
				}},
			},
		},
	}

	old := snapshotDesired(oldState).Routes[routeKey("prod", oldState.RouteTables["main"].Routes[0])]
	next := snapshotDesired(nextState).Routes[routeKey("prod", nextState.RouteTables["main"].Routes[0])]
	ops := routeUpdateCleanupOperations(old, next)
	if len(ops) != 1 {
		t.Fatalf("route cleanup ops = %v, want one stale nexthop cleanup", ops)
	}
	got := stringifyOperations([]Operation{ops[0]})
	if !strings.Contains(got, "--if-exists lr-route-del nl_lr_prod 10.10.0.0/16 10.10.0.252") {
		t.Fatalf("route cleanup operation = %q, want stale nexthop delete", got)
	}
}

func TestRouteCleanupFromECMPToSinglePreservesExistingIPv6Hop(t *testing.T) {
	oldState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("2001:db8::/32"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("2001:db8::252"),
						netip.MustParseAddr("2001:db8::253"),
					},
				}},
			},
		},
	}
	nextState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("2001:db8::/32"),
					NextHops:    []netip.Addr{netip.MustParseAddr("2001:db8::253")},
				}},
			},
		},
	}

	old := snapshotDesired(oldState).Routes[routeKey("prod", oldState.RouteTables["main"].Routes[0])]
	next := snapshotDesired(nextState).Routes[routeKey("prod", nextState.RouteTables["main"].Routes[0])]
	ops := routeUpdateCleanupOperations(old, next)
	if len(ops) != 1 {
		t.Fatalf("route cleanup ops = %v, want one stale nexthop cleanup", ops)
	}
	got := stringifyOperations([]Operation{ops[0]})
	if !strings.Contains(got, "--if-exists lr-route-del nl_lr_prod 2001:db8::/32 2001:db8::252") {
		t.Fatalf("route cleanup operation = %q, want stale nexthop delete", got)
	}
}

func TestRouteCleanupFromECMPToSingleWithoutIntersectionDeletesRoute(t *testing.T) {
	oldState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("10.10.0.252"),
						netip.MustParseAddr("10.10.0.253"),
					},
				}},
			},
		},
	}
	nextState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
				}},
			},
		},
	}

	old := snapshotDesired(oldState).Routes[routeKey("prod", oldState.RouteTables["main"].Routes[0])]
	next := snapshotDesired(nextState).Routes[routeKey("prod", nextState.RouteTables["main"].Routes[0])]
	ops := routeUpdateCleanupOperations(old, next)
	if len(ops) != 1 {
		t.Fatalf("route cleanup ops = %v, want one destination cleanup", ops)
	}
	got := stringifyOperations(ops)
	if !strings.Contains(got, "--if-exists lr-route-del nl_lr_prod 10.10.0.0/16") {
		t.Fatalf("route cleanup operation = %q, want destination cleanup", got)
	}
}

func TestRouteCleanupFromBlackholeToNexthopDeletesDestination(t *testing.T) {
	oldState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					Blackhole:   true,
				}},
			},
		},
	}
	nextState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
				}},
			},
		},
	}

	old := snapshotDesired(oldState).Routes[routeKey("prod", oldState.RouteTables["main"].Routes[0])]
	next := snapshotDesired(nextState).Routes[routeKey("prod", nextState.RouteTables["main"].Routes[0])]
	ops := routeUpdateCleanupOperations(old, next)
	if len(ops) != 1 {
		t.Fatalf("route cleanup ops = %v, want one destination cleanup", ops)
	}
	got := stringifyOperations([]Operation{ops[0]})
	if !strings.Contains(got, "--if-exists lr-route-del nl_lr_prod 10.10.0.0/16") {
		t.Fatalf("route cleanup operation = %q, want blackhole destination cleanup", got)
	}
}

func TestRouteCleanupFromSingleToSingleUsesMayExistUpdate(t *testing.T) {
	oldState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
				}},
			},
		},
	}
	nextState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.253")},
				}},
			},
		},
	}

	old := snapshotDesired(oldState).Routes[routeKey("prod", oldState.RouteTables["main"].Routes[0])]
	next := snapshotDesired(nextState).Routes[routeKey("prod", nextState.RouteTables["main"].Routes[0])]
	ops := routeUpdateCleanupOperations(old, next)
	if len(ops) != 0 {
		t.Fatalf("route cleanup ops = %v, want no cleanup because lr-route-add --may-exist updates nexthop", ops)
	}
}

func TestRouteCleanupFromECMPToECMPDeletesOnlyStaleNexthops(t *testing.T) {
	oldState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("10.10.0.252"),
						netip.MustParseAddr("10.10.0.253"),
						netip.MustParseAddr("10.10.0.254"),
					},
				}},
			},
		},
	}
	nextState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("10.10.0.252"),
						netip.MustParseAddr("10.10.0.254"),
						netip.MustParseAddr("10.10.0.255"),
					},
				}},
			},
		},
	}

	old := snapshotDesired(oldState).Routes[routeKey("prod", oldState.RouteTables["main"].Routes[0])]
	next := snapshotDesired(nextState).Routes[routeKey("prod", nextState.RouteTables["main"].Routes[0])]
	ops := routeUpdateCleanupOperations(old, next)
	if len(ops) != 1 {
		t.Fatalf("route cleanup ops = %v, want one stale nexthop delete", ops)
	}
	got := stringifyOperations([]Operation{ops[0]})
	if !strings.Contains(got, "--if-exists lr-route-del nl_lr_prod 10.10.0.0/16 10.10.0.253") {
		t.Fatalf("route cleanup operation = %q, want stale nexthop delete", got)
	}
}

func TestRouteCleanupFromECMPToECMPWithNoIntersectionDeletesWholeSet(t *testing.T) {
	oldState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("10.10.0.252"),
						netip.MustParseAddr("10.10.0.253"),
					},
				}},
			},
		},
	}
	nextState := topology.State{
		RouteTables: map[string]model.RouteTable{
			"main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.10.0.0/16"),
					NextHops: []netip.Addr{
						netip.MustParseAddr("10.10.0.254"),
						netip.MustParseAddr("10.10.0.255"),
					},
				}},
			},
		},
	}

	old := snapshotDesired(oldState).Routes[routeKey("prod", oldState.RouteTables["main"].Routes[0])]
	next := snapshotDesired(nextState).Routes[routeKey("prod", nextState.RouteTables["main"].Routes[0])]
	ops := routeUpdateCleanupOperations(old, next)
	if len(ops) != 2 {
		t.Fatalf("route cleanup ops = %v, want two stale nexthop deletes", ops)
	}
	joined := stringifyOperations(ops)
	if !strings.Contains(joined, "--if-exists lr-route-del nl_lr_prod 10.10.0.0/16 10.10.0.252") {
		t.Fatalf("route cleanup operation = %q, want stale nexthop delete for 10.10.0.252", joined)
	}
	if !strings.Contains(joined, "--if-exists lr-route-del nl_lr_prod 10.10.0.0/16 10.10.0.253") {
		t.Fatalf("route cleanup operation = %q, want stale nexthop delete for 10.10.0.253", joined)
	}
}

func TestCleanupPolicyRoutePrefersNexthopsSyncForECMP(t *testing.T) {
	oldState := topology.State{
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "egress-ecmp",
			VPC:      "prod",
			Priority: 100,
			Match:    model.RouteMatch{Source: netip.MustParsePrefix("10.10.0.0/24")},
			Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{
				netip.MustParseAddr("10.10.0.253"),
				netip.MustParseAddr("10.10.0.254"),
			}},
		}},
	}
	nextState := topology.State{
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "egress-ecmp",
			VPC:      "prod",
			Priority: 100,
			Match:    model.RouteMatch{Source: netip.MustParsePrefix("10.10.0.0/24")},
			Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{
				netip.MustParseAddr("10.10.0.252"),
				netip.MustParseAddr("10.10.0.254"),
			}},
		}},
	}

	ops := cleanupOperations(snapshotDesired(oldState), snapshotDesired(nextState))
	joined := stringifyOperations(ops)
	if strings.Contains(joined, "lr-policy-del nl_lr_prod 100") {
		t.Fatalf("cleanup should not delete ECMP policy route, should sync nexthops instead: %s", joined)
	}
	expected := "sync-policy-route-nexthops prod egress-ecmp 100 ip4.src == 10.10.0.0/24 [\"10.10.0.252\",\"10.10.0.254\"]"
	if !strings.Contains(joined, expected) {
		t.Fatalf("cleanup policy route convergence should emit nexthops sync op: %s", joined)
	}
}

func TestCleanupPolicyRouteUsesNameIdentityAndOldMatch(t *testing.T) {
	oldState := topology.State{
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "egress",
			VPC:      "prod",
			Priority: 100,
			Match:    model.RouteMatch{Source: netip.MustParsePrefix("10.10.0.0/24")},
			Action:   model.RouteAction{Type: model.ActionAllow},
		}},
	}
	nextState := topology.State{
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "egress",
			VPC:      "prod",
			Priority: 100,
			Match:    model.RouteMatch{Source: netip.MustParsePrefix("10.20.0.0/24")},
			Action:   model.RouteAction{Type: model.ActionAllow},
		}},
	}

	ops := cleanupOperations(snapshotDesired(oldState), snapshotDesired(nextState))
	joined := stringifyOperations(ops)
	if !strings.Contains(joined, "lr-policy-del nl_lr_prod 100 ip4.src == 10.10.0.0/24") {
		t.Fatalf("cleanup should delete policy route by old match:\n%s", joined)
	}
}

func TestCleanupSingleHopPolicyRouteSyncsNexthop(t *testing.T) {
	oldState := topology.State{
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "egress",
			VPC:      "prod",
			Priority: 100,
			Match:    model.RouteMatch{Source: netip.MustParsePrefix("10.10.0.0/24")},
			Action:   model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
		}},
	}
	nextState := topology.State{
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "egress",
			VPC:      "prod",
			Priority: 100,
			Match:    model.RouteMatch{Source: netip.MustParsePrefix("10.10.0.0/24")},
			Action:   model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.252")}},
		}},
	}

	ops := cleanupOperations(snapshotDesired(oldState), snapshotDesired(nextState))
	joined := stringifyOperations(ops)
	if strings.Contains(joined, "lr-policy-del nl_lr_prod 100 ip4.src == 10.10.0.0/24") {
		t.Fatalf("single-hop policy route should sync nexthop in place, not delete:\n%s", joined)
	}
	expected := "sync-policy-route-nexthop prod egress 100 ip4.src == 10.10.0.0/24 10.10.0.252"
	if !strings.Contains(joined, expected) {
		t.Fatalf("cleanup should emit single-hop nexthop sync op:\n%s", joined)
	}
}

func TestSnapshotDesiredClonesLoadBalancerBackendHealthPointers(t *testing.T) {
	healthy := true
	state := topology.State{
		LoadBalancers: map[string]model.LoadBalancer{
			"web": {
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Ports: []model.LoadBalancerPort{{
					Port: 80,
					Backends: []model.LoadBalancerBackend{{
						IP:      netip.MustParseAddr("10.10.0.10"),
						Port:    8080,
						Healthy: &healthy,
					}},
				}},
			},
		},
	}

	snapshot := snapshotDesired(state)
	healthy = false

	got := snapshot.LoadBalancers[loadBalancerStateKey(state.LoadBalancers["web"])].Ports[0].Backends[0].Healthy
	if got == nil || !*got {
		t.Fatalf("snapshot backend health = %v, want cloned true value after source mutation", got)
	}
}

func stringifyOperations(ops []Operation) string {
	var lines []string
	for _, op := range ops {
		fields := append([]string{}, op.Flags...)
		fields = append(fields, op.Command)
		fields = append(fields, op.Args...)
		lines = append(lines, strings.Join(fields, " "))
	}
	return strings.Join(lines, "\n")
}
