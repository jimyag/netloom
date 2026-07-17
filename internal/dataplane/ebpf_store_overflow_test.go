package dataplane

import (
	"context"
	"strings"
	"testing"

	"github.com/jimyag/netloom/internal/model"
)

func TestEBPFPolicyStoreRejectsPolicyMapOverflowBeforeProgramming(t *testing.T) {
	store := NewEBPFPolicyStore(1)
	endpointID := model.EndpointKey("prod", "pod-a")
	oldEntries := []PolicyMapEntry{{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 1, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 10},
	}}
	store.entries[endpointID] = canonicalPolicyEntries(oldEntries)
	store.revisions[endpointID] = 1
	store.lastStats[endpointID] = PolicyUpdateStats{Revision: 1, Added: 1}
	store.events = append(store.events, PolicyUpdateEvent{
		EndpointID: endpointID,
		Revision:   1,
		Stats:      PolicyUpdateStats{Revision: 1, Added: 1},
		Success:    true,
	})

	overflow := []PolicyMapEntry{
		{
			Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 2, Direction: DirectionIngress},
			Value: PolicyEntry{Precedence: 20},
		},
		{
			Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 3, Direction: DirectionIngress},
			Value: PolicyEntry{Precedence: 30},
		},
	}
	err := store.ReplaceEndpoint(context.Background(), endpointID, overflow)
	if err == nil || !strings.Contains(err.Error(), "policy map capacity exceeded") {
		t.Fatalf("error = %v, want capacity exceeded", err)
	}
	if revision := store.Revision(endpointID); revision != 1 {
		t.Fatalf("revision after overflow = %d, want 1", revision)
	}
	entries, err := store.PolicyMapUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Entries != 1 || entries[0].Capacity != 1 {
		t.Fatalf("usage after overflow = %+v, want one preserved entry with capacity 1", entries)
	}
	if got := store.Events(); len(got) != 2 || got[1].Success || !strings.Contains(got[1].Error, "policy map capacity exceeded") {
		t.Fatalf("events after overflow = %+v, want failed overflow event", got)
	}
}

func TestEBPFPolicyStoreClearsPolicyMapOverflowWhenConfigured(t *testing.T) {
	store := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		MaxEntries:     1,
		OverflowAction: PolicyMapOverflowClear,
	})
	endpointID := model.EndpointKey("prod", "pod-a")
	oldEntries := []PolicyMapEntry{{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 1, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 10},
	}}
	store.entries[endpointID] = canonicalPolicyEntries(oldEntries)
	store.revisions[endpointID] = 1
	store.lastStats[endpointID] = PolicyUpdateStats{Revision: 1, Added: 1}

	overflow := []PolicyMapEntry{
		{
			Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 2, Direction: DirectionIngress},
			Value: PolicyEntry{Precedence: 20},
		},
		{
			Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 3, Direction: DirectionIngress},
			Value: PolicyEntry{Precedence: 30},
		},
	}
	if err := store.ReplaceEndpoint(context.Background(), endpointID, overflow); err != nil {
		t.Fatalf("ReplaceEndpoint() error = %v, want clear remediation success", err)
	}
	if revision := store.Revision(endpointID); revision != 2 {
		t.Fatalf("revision after overflow remediation = %d, want 2", revision)
	}
	if got := store.LastStats(endpointID); got.Revision != 2 || got.Deleted != 1 || got.Added != 0 || got.Updated != 0 {
		t.Fatalf("last stats after overflow remediation = %+v, want one deleted entry", got)
	}
	usages, err := store.PolicyMapUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(usages) != 1 || usages[0].Entries != 0 || usages[0].Capacity != 1 {
		t.Fatalf("usage after overflow remediation = %+v, want empty fail-closed endpoint", usages)
	}
	decision := Evaluate(store.entries[endpointID], Packet{
		RemoteIdentity: 2,
		Direction:      DirectionIngress,
	})
	if decision.Verdict != VerdictDrop || decision.Match != nil {
		t.Fatalf("decision after overflow remediation = %+v, want no-match drop", decision)
	}
	events := store.Events()
	if len(events) != 1 || !events[0].Success || !events[0].Remediated || events[0].Remediation != string(PolicyMapOverflowClear) {
		t.Fatalf("events after overflow remediation = %+v, want successful clear remediation event", events)
	}
	if events[0].OccurredAt == nil || events[0].OccurredAt.IsZero() {
		t.Fatalf("overflow remediation event occurred_at is zero in %+v, want timestamped remediation event", events[0])
	}
	if !strings.Contains(events[0].Error, "policy map capacity exceeded") {
		t.Fatalf("overflow remediation event error = %q, want original overflow reason", events[0].Error)
	}
}

func TestEBPFPolicyStoreCapacityCheckCountsUniqueKeys(t *testing.T) {
	store := NewEBPFPolicyStore(1)
	endpointID := model.EndpointKey("prod", "pod-a")
	entries := []PolicyMapEntry{
		{
			Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 1, Direction: DirectionIngress},
			Value: PolicyEntry{Precedence: 10},
		},
		{
			Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 1, Direction: DirectionIngress},
			Value: PolicyEntry{Precedence: 20},
		},
	}
	if err := store.validatePolicyMapCapacity(endpointID, entries); err != nil {
		t.Fatalf("validatePolicyMapCapacity() with duplicate keys error = %v, want success", err)
	}

	overflow := append(entries, PolicyMapEntry{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 2, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 30},
	})
	if err := store.validatePolicyMapCapacity(endpointID, overflow); err == nil || !strings.Contains(err.Error(), "policy map capacity exceeded") {
		t.Fatalf("validatePolicyMapCapacity() error = %v, want overflow", err)
	}
}
