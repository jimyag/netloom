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

func TestInMemoryPolicyStoreReportsEndpointStatuses(t *testing.T) {
	store := NewInMemoryPolicyStore()
	endpointA := model.EndpointKey("prod", "pod-a")
	entry := PolicyMapEntry{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 1, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 10, RuleCookie: 7},
	}
	if err := store.ReplaceEndpoint(context.Background(), endpointA, []PolicyMapEntry{entry}); err != nil {
		t.Fatal(err)
	}

	statuses, err := store.PolicyEndpointStatuses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 {
		t.Fatalf("statuses = %d, want one endpoint status", len(statuses))
	}
	status := statuses[0]
	if status.EndpointID != endpointA || status.Revision != 1 || status.Entries != 1 || status.Capacity != 0 || status.PressurePercent != 0 {
		t.Fatalf("status = %+v, want endpoint revision and usage", status)
	}
	if status.Drift.Drifted || status.Drift.Missing != 0 || status.Drift.Extra != 0 || status.Drift.Changed != 0 {
		t.Fatalf("drift = %+v, want clean in-memory status", status.Drift)
	}
	if status.LastStats.Revision != 1 || status.LastStats.Added != 1 {
		t.Fatalf("last stats = %+v, want revision 1 add", status.LastStats)
	}
	if !status.HasLastEvent || !status.LastEvent.Success || status.LastEvent.EndpointID != endpointA || status.LastEvent.Revision != 1 {
		t.Fatalf("last event = %+v has=%t, want successful endpoint event", status.LastEvent, status.HasLastEvent)
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
	if summary.MaxPressureEndpoint != "b" {
		t.Fatalf("max pressure endpoint = %q, want b", summary.MaxPressureEndpoint)
	}
	if summary.PressureEndpoints != 1 {
		t.Fatalf("pressure endpoints = %d, want 1", summary.PressureEndpoints)
	}
}

func TestDiffPolicyMapEntriesClassifiesDrift(t *testing.T) {
	desiredKeep := PolicyMapEntry{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 1, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 10, RuleCookie: 1},
	}
	desiredChanged := PolicyMapEntry{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 2, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 20, RuleCookie: 2, Deny: 1},
	}
	desiredMissing := PolicyMapEntry{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 3, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 30, RuleCookie: 3},
	}
	liveKeepWithCounters := desiredKeep
	liveKeepWithCounters.Value.Packets = 99
	liveKeepWithCounters.Value.Bytes = 4096
	liveChanged := desiredChanged
	liveChanged.Value.Deny = 0
	liveExtra := PolicyMapEntry{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 4, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 40, RuleCookie: 4},
	}

	report := DiffPolicyMapEntries("prod/pod-a", []PolicyMapEntry{desiredKeep, desiredChanged, desiredMissing}, []PolicyMapEntry{liveKeepWithCounters, liveChanged, liveExtra})
	if !report.Drifted || report.Missing != 1 || report.Extra != 1 || report.Changed != 1 {
		t.Fatalf("drift report = %+v, want one missing, one extra and one changed entry", report)
	}
}

func TestSummarizePolicyMapDriftAggregatesReports(t *testing.T) {
	summary := SummarizePolicyMapDrift([]PolicyMapDrift{
		{EndpointID: "a", Missing: 1, Drifted: true},
		{EndpointID: "b"},
		{EndpointID: "c", Extra: 2, Changed: 3, Drifted: true},
	})
	if summary.Endpoints != 3 || summary.DriftedEndpoints != 2 || summary.MissingEntries != 1 || summary.ExtraEntries != 2 || summary.ChangedEntries != 3 {
		t.Fatalf("drift summary = %+v", summary)
	}
}
