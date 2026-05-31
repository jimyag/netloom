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
