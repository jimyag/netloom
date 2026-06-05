package dataplane

import (
	"context"
	"math"
	"net/netip"
	"strings"
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
			Deny:            false,
			Precedence:      100,
			Stateful:        true,
			Log:             true,
			RequireIdentity: true,
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
	if encoded.Value.Stateful != 1 || encoded.Value.Log != 1 || encoded.Value.RequireIdentity != 1 {
		t.Fatalf("stateful/log/require-identity flags = %d/%d/%d, want 1/1/1", encoded.Value.Stateful, encoded.Value.Log, encoded.Value.RequireIdentity)
	}
	if encoded.RemoteCIDR != netip.MustParsePrefix("10.20.0.0/16") {
		t.Fatalf("remote cidr = %s, want 10.20.0.0/16", encoded.RemoteCIDR)
	}
	if encoded.Value.RuleCookie == 0 {
		t.Fatal("rule cookie should be stable and non-zero")
	}
}

func TestEncodeEntryUsesICMPv6ProtocolForIPv6CIDR(t *testing.T) {
	icmpType := uint16(128) << 8
	entry := policy.MapEntry{
		Key: policy.MapKey{
			Direction:    model.DirectionIngress,
			Protocol:     model.ProtocolICMP,
			DestPort:     icmpType,
			L4PrefixBits: 16,
		},
		Value: policy.MapValue{
			Precedence: 100,
		},
		RemoteCIDR: netip.MustParsePrefix("fd00:20::/64"),
		RuleID:     "allow-icmpv6",
	}

	encoded, err := EncodeEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	if encoded.Key.Protocol != 58 {
		t.Fatalf("protocol = %d, want icmpv6/58 for IPv6 CIDR", encoded.Key.Protocol)
	}
	if encoded.Key.DestPortBE != hostToNetwork16(icmpType) {
		t.Fatalf("icmp type key = %#x, want %#x", networkToHost16(encoded.Key.DestPortBE), icmpType)
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

	entries := store.Entries(model.EndpointKey("prod", "pod-a"))
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

func TestCiliumStyleDefaultAllowModeLeavesExplicitDenyEnforced(t *testing.T) {
	defaultAllow := false
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
			Name:               "web",
			VPC:                "prod",
			DefaultDenyEgress:  &defaultAllow,
			DefaultDenyIngress: &defaultAllow,
			Rules: []model.SecurityGroupRule{{
				ID:         "deny-admin",
				Priority:   100,
				Direction:  model.DirectionEgress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("203.0.113.0/24"),
				Ports:      []model.PortRange{{From: 8443, To: 8443}},
				Action:     model.ActionDrop,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := EncodeProgram(program)
	if err != nil {
		t.Fatal(err)
	}

	allow := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("198.51.100.10"),
		Direction: DirectionEgress,
		Protocol:  6,
		DestPort:  443,
	})
	if allow.Verdict != VerdictAllow {
		t.Fatalf("default-allow unmatched verdict = %s, want allow", allow.Verdict)
	}
	deny := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("203.0.113.20"),
		Direction: DirectionEgress,
		Protocol:  6,
		DestPort:  8443,
	})
	if deny.Verdict != VerdictDrop || deny.Match == nil || deny.Match.Value.Deny == 0 {
		t.Fatalf("explicit deny decision = %+v, want policy drop", deny)
	}
	ingress := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("198.51.100.20"),
		Direction: DirectionIngress,
		Protocol:  17,
		DestPort:  53,
	})
	if ingress.Verdict != VerdictAllow {
		t.Fatalf("ingress default-allow verdict = %s, want allow", ingress.Verdict)
	}
}

func TestPolicyBackendHonorsSecurityGroupTierPrecedence(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"platform", "tenant"},
	}
	program, err := policy.CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"platform": {
			Name: "platform",
			VPC:  "prod",
			Tier: 0,
			Rules: []model.SecurityGroupRule{{
				ID:         "platform-allow-api",
				Priority:   10,
				Direction:  model.DirectionEgress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("192.0.2.0/24"),
				Ports:      []model.PortRange{{From: 443, To: 443}},
				Action:     model.ActionAllow,
			}},
		},
		"tenant": {
			Name: "tenant",
			VPC:  "prod",
			Tier: 1,
			Rules: []model.SecurityGroupRule{{
				ID:         "tenant-drop-api",
				Priority:   1000,
				Direction:  model.DirectionEgress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("192.0.2.0/24"),
				Ports:      []model.PortRange{{From: 443, To: 443}},
				Action:     model.ActionDrop,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := EncodeProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	decision := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("192.0.2.10"),
		Direction: DirectionEgress,
		Protocol:  6,
		DestPort:  443,
	})
	if decision.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want tier-0 allow to beat tier-1 drop", decision.Verdict)
	}
}

func TestPolicyBackendHonorsLowerSecurityGroupRulePriority(t *testing.T) {
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
			Rules: []model.SecurityGroupRule{
				{
					ID:         "allow-fallback",
					Priority:   1000,
					Direction:  model.DirectionEgress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("192.0.2.0/24"),
					Ports:      []model.PortRange{{From: 443, To: 443}},
					Action:     model.ActionAllow,
				},
				{
					ID:         "allow-primary",
					Priority:   1,
					Direction:  model.DirectionEgress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("192.0.2.0/24"),
					Ports:      []model.PortRange{{From: 443, To: 443}},
					Action:     model.ActionAllow,
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := EncodeProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("encoded entries = %d, want highest-priority entry for duplicate key", len(entries))
	}
	decision := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("192.0.2.10"),
		Direction: DirectionEgress,
		Protocol:  6,
		DestPort:  443,
	})
	if decision.Match == nil || decision.Match.Value.RuleCookie != stableCookie("allow-primary") {
		t.Fatalf("decision = %+v, want lower numeric priority allow-primary", decision)
	}

	store := NewInMemoryPolicyStore()
	backend := NewPolicyBackend(store)
	if err := backend.ApplyEndpointProgram(context.Background(), program); err != nil {
		t.Fatal(err)
	}
	stored := store.Entries(model.EndpointKey("prod", "pod-a"))
	if len(stored) != 1 || stored[0].Value.RuleCookie != stableCookie("allow-primary") {
		t.Fatalf("stored entries = %+v, want only highest-priority allow-primary", stored)
	}
}

func TestEncodeProgramRejectsSamePriorityDuplicateKeyConflict(t *testing.T) {
	program := policy.Program{
		EndpointID: "pod-a",
		MapEntries: []policy.MapEntry{
			{
				Key: policy.MapKey{
					RemoteIdentity: 100,
					Direction:      model.DirectionIngress,
					Protocol:       model.ProtocolTCP,
					DestPort:       443,
					L4PrefixBits:   24,
				},
				Value:  policy.MapValue{Precedence: 100},
				RuleID: "allow-api",
			},
			{
				Key: policy.MapKey{
					RemoteIdentity: 100,
					Direction:      model.DirectionIngress,
					Protocol:       model.ProtocolTCP,
					DestPort:       443,
					L4PrefixBits:   24,
				},
				Value:  policy.MapValue{Deny: true, Precedence: 100},
				RuleID: "drop-api",
			},
		},
	}

	_, err := EncodeProgram(program)
	if err == nil {
		t.Fatal("expected duplicate key conflict to fail")
	}
	if got := err.Error(); !strings.Contains(got, "conflicting policy map entries") {
		t.Fatalf("error = %q, want conflicting policy map entries", got)
	}
}

func TestPolicyBackendPreservesRejectAction(t *testing.T) {
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
				ID:         "reject-cidr",
				Priority:   10,
				Direction:  model.DirectionEgress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("192.0.2.0/24"),
				Ports:      []model.PortRange{{From: 443, To: 443}},
				Action:     model.ActionReject,
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

	entries := store.Entries(model.EndpointKey("prod", "pod-a"))
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Value.Deny != 1 || entries[0].Value.Reject != 1 {
		t.Fatalf("deny/reject flags = %d/%d, want 1/1", entries[0].Value.Deny, entries[0].Value.Reject)
	}
	decision := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("192.0.2.10"),
		Direction: DirectionEgress,
		Protocol:  6,
		DestPort:  443,
	})
	if decision.Verdict != VerdictReject {
		t.Fatalf("verdict = %s, want reject", decision.Verdict)
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

func TestCanonicalPolicyMapEntriesRejectsRemoteCIDRIdentityCollision(t *testing.T) {
	key := PolicyKey{
		PrefixLen:      StaticPrefixBits + 24,
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPortBE:     hostToNetwork16(443),
	}
	entries := []PolicyMapEntry{
		{
			Key:        key,
			Value:      PolicyEntry{L4PrefixLen: 24, Precedence: 100},
			RemoteCIDR: netip.MustParsePrefix("10.20.0.0/24"),
		},
		{
			Key:        key,
			Value:      PolicyEntry{L4PrefixLen: 24, Precedence: 100},
			RemoteCIDR: netip.MustParsePrefix("10.30.0.0/24"),
		},
	}

	_, err := canonicalPolicyMapEntries(entries)
	if err == nil || !strings.Contains(err.Error(), "remote cidr metadata") {
		t.Fatalf("error = %v, want remote cidr metadata collision", err)
	}
}

func TestCanonicalPolicyMapEntriesRejectsHigherPrecedenceRemoteCIDRCollision(t *testing.T) {
	key := PolicyKey{
		PrefixLen:      StaticPrefixBits + 24,
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPortBE:     hostToNetwork16(443),
	}
	entries := []PolicyMapEntry{
		{
			Key:        key,
			Value:      PolicyEntry{L4PrefixLen: 24, Precedence: 100},
			RemoteCIDR: netip.MustParsePrefix("10.20.0.0/24"),
		},
		{
			Key:        key,
			Value:      PolicyEntry{L4PrefixLen: 24, Precedence: 200},
			RemoteCIDR: netip.MustParsePrefix("10.30.0.0/24"),
		},
	}

	_, err := canonicalPolicyMapEntries(entries)
	if err == nil || !strings.Contains(err.Error(), "remote cidr metadata") {
		t.Fatalf("error = %v, want higher precedence remote cidr collision", err)
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
	if events[0].EndpointID != "pod-a" || !events[0].Success || events[0].PreviousRevision != 0 || events[0].Revision != 1 {
		t.Fatalf("first event = %+v, want pod-a success from revision 0 to 1", events[0])
	}
	if events[1].EndpointID != "pod-a" || !events[1].Success || events[1].PreviousRevision != 1 || events[1].Revision != 2 {
		t.Fatalf("events = %+v, want pod-a revisions 1 and 2", events)
	}
}

func TestInMemoryPolicyStoreDeletesEndpoint(t *testing.T) {
	store := NewInMemoryPolicyStore()
	entries := []PolicyMapEntry{{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 1, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 10},
	}}
	if err := store.ReplaceEndpoint(context.Background(), "pod-a", entries); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteEndpoint(context.Background(), "pod-a"); err != nil {
		t.Fatal(err)
	}
	if got := store.Entries("pod-a"); len(got) != 0 {
		t.Fatalf("entries after delete = %+v, want empty", got)
	}
	if revision := store.Revision("pod-a"); revision != 0 {
		t.Fatalf("revision after delete = %d, want 0", revision)
	}
	if stats := store.LastStats("pod-a"); stats != (PolicyUpdateStats{}) {
		t.Fatalf("stats after delete = %+v, want zero", stats)
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
	events := store.Events()
	if len(events) != 2 {
		t.Fatalf("events = %d, want success and failed update event", len(events))
	}
	failed := events[1]
	if failed.Success || failed.EndpointID != "pod-a" || failed.PreviousRevision != 1 || failed.Revision != 2 || failed.Error == "" {
		t.Fatalf("failed event = %+v, want failed attempted revision 2 without advancing store revision", failed)
	}
	if failed.Stats.Revision != 2 || failed.Stats.Added != 1 || failed.Stats.Deleted != 1 {
		t.Fatalf("failed stats = %+v, want attempted add/delete diff at revision 2", failed.Stats)
	}
}
