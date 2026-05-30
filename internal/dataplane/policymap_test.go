package dataplane

import (
	"context"
	"math"
	"net/netip"
	"testing"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
)

func TestEncodeEntryUsesCiliumStylePolicyKeyShape(t *testing.T) {
	entry := policy.MapEntry{
		Key: policy.MapKey{
			RemoteIdentity: 12345,
			Direction:      model.DirectionIngress,
			Protocol:       model.ProtocolTCP,
			DestPort:       443,
			L4PrefixBits:   24,
		},
		Value: policy.MapValue{
			Deny:       false,
			Precedence: 100,
			Stateful:   true,
			Log:        true,
		},
		RemoteCIDR: netip.MustParsePrefix("10.20.0.0/16"),
		RuleID:     "allow-https",
	}

	encoded, err := EncodeEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	if encoded.Key.PrefixLen != StaticPrefixBits+24 {
		t.Fatalf("prefix len = %d, want %d", encoded.Key.PrefixLen, StaticPrefixBits+24)
	}
	if encoded.Key.Protocol != 6 {
		t.Fatalf("protocol = %d, want tcp/6", encoded.Key.Protocol)
	}
	if encoded.Key.Direction != DirectionIngress {
		t.Fatalf("direction = %d, want ingress/%d", encoded.Key.Direction, DirectionIngress)
	}
	if encoded.Value.Stateful != 1 || encoded.Value.Log != 1 {
		t.Fatalf("stateful/log flags = %d/%d, want 1/1", encoded.Value.Stateful, encoded.Value.Log)
	}
	if encoded.RemoteCIDR != netip.MustParsePrefix("10.20.0.0/16") {
		t.Fatalf("remote cidr = %s, want 10.20.0.0/16", encoded.RemoteCIDR)
	}
	if encoded.Value.RuleCookie == 0 {
		t.Fatal("rule cookie should be stable and non-zero")
	}
}

func TestPolicyBackendReplacesEndpointEntries(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"web"},
	}
	program, err := policy.CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"web": {
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "deny-cidr",
				Priority:   10,
				Direction:  model.DirectionEgress,
				Protocol:   model.ProtocolAny,
				RemoteCIDR: netip.MustParsePrefix("192.0.2.0/24"),
				Action:     model.ActionDrop,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	store := NewInMemoryPolicyStore()
	backend := NewPolicyBackend(store)
	if err := backend.ApplyEndpointProgram(context.Background(), program); err != nil {
		t.Fatal(err)
	}

	entries := store.Entries("pod-a")
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Key.RemoteIdentity == 0 {
		t.Fatal("cidr rule should compile to a non-wildcard remote identity")
	}
	if entries[0].RemoteCIDR != netip.MustParsePrefix("192.0.2.0/24") {
		t.Fatalf("remote cidr = %s, want 192.0.2.0/24", entries[0].RemoteCIDR)
	}
	if entries[0].Value.Precedence != math.MaxUint32 {
		t.Fatalf("deny precedence = %d, want max uint32", entries[0].Value.Precedence)
	}
	if entries[0].Value.Deny != 1 {
		t.Fatal("deny rule should encode deny flag")
	}
}

func TestPlanPolicyUpdateComputesIncrementalDiff(t *testing.T) {
	keep := PolicyMapEntry{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 1, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 10},
	}
	updateOld := PolicyMapEntry{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits + 24, RemoteIdentity: 2, Direction: DirectionIngress, Protocol: 6, DestPortBE: hostToNetwork16(80)},
		Value: PolicyEntry{Precedence: 20},
	}
	updateNew := updateOld
	updateNew.Value.Deny = 1
	deleted := PolicyMapEntry{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 3, Direction: DirectionEgress},
		Value: PolicyEntry{Precedence: 30},
	}
	added := PolicyMapEntry{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 4, Direction: DirectionEgress},
		Value: PolicyEntry{Precedence: 40},
	}

	plan := PlanPolicyUpdate([]PolicyMapEntry{keep, updateOld, deleted}, []PolicyMapEntry{keep, updateNew, added})
	stats := plan.Stats()
	if stats.Revision != 0 || stats.Added != 1 || stats.Updated != 1 || stats.Deleted != 1 || stats.Unchanged != 1 {
		t.Fatalf("stats = %+v, want one add/update/delete/unchanged", stats)
	}
	if plan.Add[0] != added || plan.Update[0] != updateNew || plan.Delete[0] != deleted.Key || plan.Unchanged[0] != keep {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestPlanPolicyUpdateDetectsRemoteCIDRMetadataChange(t *testing.T) {
	oldEntry := PolicyMapEntry{
		Key:        PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: policy.EndpointIdentity("pod-b"), Direction: DirectionIngress},
		Value:      PolicyEntry{Precedence: 10},
		RemoteCIDR: netip.MustParsePrefix("10.10.0.11/32"),
	}
	newEntry := oldEntry
	newEntry.RemoteCIDR = netip.MustParsePrefix("10.10.0.12/32")

	plan := PlanPolicyUpdate([]PolicyMapEntry{oldEntry}, []PolicyMapEntry{newEntry})
	if len(plan.Update) != 1 || plan.Update[0] != newEntry || len(plan.Unchanged) != 0 {
		t.Fatalf("plan = %+v, want remote CIDR metadata update", plan)
	}
}

func TestInMemoryPolicyStoreAppliesIncrementalStats(t *testing.T) {
	store := NewInMemoryPolicyStore()
	first := []PolicyMapEntry{{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 1, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 10},
	}}
	if err := store.ReplaceEndpoint(context.Background(), "pod-a", first); err != nil {
		t.Fatal(err)
	}
	stats := store.LastStats("pod-a")
	if stats.Revision != 1 || stats.Added != 1 || stats.Updated != 0 || stats.Deleted != 0 {
		t.Fatalf("first stats = %+v, want one add", stats)
	}
	if revision := store.Revision("pod-a"); revision != 1 {
		t.Fatalf("first revision = %d, want 1", revision)
	}

	second := []PolicyMapEntry{{
		Key:   first[0].Key,
		Value: PolicyEntry{Precedence: 20},
	}}
	if err := store.ReplaceEndpoint(context.Background(), "pod-a", second); err != nil {
		t.Fatal(err)
	}
	stats = store.LastStats("pod-a")
	if stats.Revision != 2 || stats.Added != 0 || stats.Updated != 1 || stats.Deleted != 0 {
		t.Fatalf("second stats = %+v, want one update", stats)
	}
	entries := store.Entries("pod-a")
	if len(entries) != 1 || entries[0].Value.Precedence != 20 {
		t.Fatalf("entries = %+v, want updated precedence", entries)
	}
	events := store.Events()
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[0].EndpointID != "pod-a" || events[0].Revision != 1 || events[1].Revision != 2 {
		t.Fatalf("events = %+v, want pod-a revisions 1 and 2", events)
	}
}

func TestInMemoryPolicyStoreRollsBackOnFailure(t *testing.T) {
	store := NewInMemoryPolicyStore()
	oldEntries := []PolicyMapEntry{{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 1, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 10},
	}}
	if err := store.ReplaceEndpoint(context.Background(), "pod-a", oldEntries); err != nil {
		t.Fatal(err)
	}
	store.SetFailAfter(0)
	store.SetFailAfter(1)
	newEntries := []PolicyMapEntry{{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 2, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 20},
	}}
	err := store.ReplaceEndpoint(context.Background(), "pod-a", newEntries)
	if err == nil {
		t.Fatal("expected injected update failure")
	}
	if revision := store.Revision("pod-a"); revision != 1 {
		t.Fatalf("revision after failure = %d, want 1", revision)
	}
	entries := store.Entries("pod-a")
	if len(entries) != 1 || entries[0] != oldEntries[0] {
		t.Fatalf("entries after failure = %+v, want old entries", entries)
	}
}
