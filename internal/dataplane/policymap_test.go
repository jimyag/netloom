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
		RuleID: "allow-https",
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
	if entries[0].Value.Precedence != math.MaxUint32 {
		t.Fatalf("deny precedence = %d, want max uint32", entries[0].Value.Precedence)
	}
	if entries[0].Value.Deny != 1 {
		t.Fatal("deny rule should encode deny flag")
	}
}
