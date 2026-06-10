package dataplane

import (
	"context"
	"testing"

	"github.com/jimyag/netloom/internal/model"
)

func TestInMemoryPolicyStoreExposesPolicyMapUsageSummary(t *testing.T) {
	store := NewInMemoryPolicyStore()
	endpointA := model.EndpointKey("prod", "pod-a")
	endpointB := model.EndpointKey("prod", "pod-b")
	for endpointID, entries := range map[string][]PolicyMapEntry{
		endpointA: {{
			Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 1, Direction: DirectionIngress},
			Value: PolicyEntry{Precedence: 10},
		}},
		endpointB: {{
			Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 2, Direction: DirectionIngress},
			Value: PolicyEntry{Precedence: 20},
		}, {
			Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 3, Direction: DirectionIngress},
			Value: PolicyEntry{Precedence: 30},
		}},
	} {
		if err := store.ReplaceEndpoint(context.Background(), endpointID, entries); err != nil {
			t.Fatal(err)
		}
	}

	usages, err := store.PolicyMapUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(usages) != 2 {
		t.Fatalf("usages = %d, want 2", len(usages))
	}
	if usages[0].EndpointID != endpointA || usages[0].Entries != 1 || usages[0].Capacity != 0 {
		t.Fatalf("first usage = %+v, want pod-a with one entry and unknown capacity", usages[0])
	}
	if usages[1].EndpointID != endpointB || usages[1].Entries != 2 || usages[1].Capacity != 0 {
		t.Fatalf("second usage = %+v, want pod-b with two entries and unknown capacity", usages[1])
	}
}

func TestSummarizePolicyMapUsageCalculatesPressureBands(t *testing.T) {
	summary := SummarizePolicyMapUsage([]PolicyMapUsage{
		{EndpointID: "a", Entries: 12, Capacity: 16},
		{EndpointID: "b", Entries: 13, Capacity: 16},
		{EndpointID: "c", Entries: 4, Capacity: 0},
	})
	if summary.Entries != 29 || summary.Capacity != 32 {
		t.Fatalf("summary totals = %+v, want entries 29 and capacity 32", summary)
	}
	if summary.MaxPressurePercent != 81 {
		t.Fatalf("max pressure = %d, want 81", summary.MaxPressurePercent)
	}
	if summary.PressureEndpoints != 1 {
		t.Fatalf("pressure endpoints = %d, want 1", summary.PressureEndpoints)
	}
}
