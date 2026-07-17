package agent

import (
	"context"
	"net/netip"
	"reflect"
	"testing"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/model"
)

type policyMapUsageStore struct {
	*dataplane.InMemoryPolicyStore
	usages []dataplane.PolicyMapUsage
	err    error
}

func (s *policyMapUsageStore) PolicyMapUsage(_ context.Context) ([]dataplane.PolicyMapUsage, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]dataplane.PolicyMapUsage(nil), s.usages...), nil
}

func TestReconcileNodeAggregatesPolicyMapPressureSummary(t *testing.T) {
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
	store := &policyMapUsageStore{
		InMemoryPolicyStore: dataplane.NewInMemoryPolicyStore(),
		usages: []dataplane.PolicyMapUsage{
			{EndpointID: model.EndpointKey("prod", "pod-a"), Entries: 12, Capacity: 16},
			{EndpointID: model.EndpointKey("prod", "pod-b"), Entries: 8, Capacity: 16},
		},
	}

	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyMapEntries != 20 || result.PolicyMapCapacity != 32 {
		t.Fatalf("policy map totals = %+v, want entries 20 capacity 32", result)
	}
	if result.PolicyMapPressureMax != 75 {
		t.Fatalf("policy map pressure max = %d, want 75", result.PolicyMapPressureMax)
	}
	if result.PolicyMapPressureEndpoint != model.EndpointKey("prod", "pod-a") {
		t.Fatalf("policy map pressure endpoint = %q, want pod-a", result.PolicyMapPressureEndpoint)
	}
	if result.PolicyMapPressureEndpoints != 0 {
		t.Fatalf("policy map pressure endpoints = %d, want 0", result.PolicyMapPressureEndpoints)
	}
	wantHotspots := []dataplane.PolicyMapPressureHotspot{
		{EndpointID: model.EndpointKey("prod", "pod-a"), Entries: 12, Capacity: 16, PressurePercent: 75, Severity: dataplane.PolicyMapPressureNormal},
		{EndpointID: model.EndpointKey("prod", "pod-b"), Entries: 8, Capacity: 16, PressurePercent: 50, Severity: dataplane.PolicyMapPressureNormal},
	}
	if !reflect.DeepEqual(result.PolicyMapPressureHotspots, wantHotspots) {
		t.Fatalf("policy map pressure hotspots = %+v, want %+v", result.PolicyMapPressureHotspots, wantHotspots)
	}

	store.usages = []dataplane.PolicyMapUsage{
		{EndpointID: model.EndpointKey("prod", "pod-a"), Entries: 13, Capacity: 16},
	}
	result, err = ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyMapPressureMax != 81 || result.PolicyMapPressureEndpoint != model.EndpointKey("prod", "pod-a") || result.PolicyMapPressureEndpoints != 1 {
		t.Fatalf("pressure summary = %+v, want one pressured endpoint at 81%%", result)
	}
}
