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
