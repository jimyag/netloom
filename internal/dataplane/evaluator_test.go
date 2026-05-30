package dataplane

import (
	"math"
	"testing"
)

func TestEvaluateDefaultsToDrop(t *testing.T) {
	decision := Evaluate(nil, Packet{
		Direction: DirectionIngress,
		Protocol:  6,
		DestPort:  443,
	})
	if decision.Verdict != VerdictDrop {
		t.Fatalf("verdict = %s, want drop", decision.Verdict)
	}
}

func TestEvaluateChoosesDenyPrecedenceOverAllow(t *testing.T) {
	entries := []PolicyMapEntry{
		{
			Key: PolicyKey{
				PrefixLen:      StaticPrefixBits + 24,
				RemoteIdentity: 100,
				Direction:      DirectionIngress,
				Protocol:       6,
				DestPortBE:     hostToNetwork16(443),
			},
			Value: PolicyEntry{
				L4PrefixLen: 24,
				Precedence:  100,
			},
		},
		{
			Key: PolicyKey{
				PrefixLen:      StaticPrefixBits,
				RemoteIdentity: 100,
				Direction:      DirectionIngress,
			},
			Value: PolicyEntry{
				Deny:        1,
				Precedence:  math.MaxUint32,
				L4PrefixLen: 0,
			},
		},
	}

	decision := Evaluate(entries, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	})
	if decision.Verdict != VerdictDrop {
		t.Fatalf("verdict = %s, want drop", decision.Verdict)
	}
}

func TestEvaluateMatchesPortPrefix(t *testing.T) {
	entries := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + 20,
			RemoteIdentity: 0,
			Direction:      DirectionEgress,
			Protocol:       6,
			DestPortBE:     hostToNetwork16(0x3000),
		},
		Value: PolicyEntry{
			L4PrefixLen: 20,
			Precedence:  10,
		},
	}}

	allowed := Evaluate(entries, Packet{Direction: DirectionEgress, Protocol: 6, DestPort: 0x300f})
	if allowed.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow", allowed.Verdict)
	}
	dropped := Evaluate(entries, Packet{Direction: DirectionEgress, Protocol: 6, DestPort: 0x3010})
	if dropped.Verdict != VerdictDrop {
		t.Fatalf("verdict = %s, want drop", dropped.Verdict)
	}
}

func TestEvaluateStatefulAllowsReverseFlowFromConntrack(t *testing.T) {
	entries := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + 24,
			RemoteIdentity: 100,
			Direction:      DirectionIngress,
			Protocol:       6,
			DestPortBE:     hostToNetwork16(443),
		},
		Value: PolicyEntry{
			L4PrefixLen: 24,
			Precedence:  100,
			Stateful:    1,
		},
	}}
	conntrack := NewInMemoryConntrackStore()

	ingress := EvaluateStateful("pod-a", entries, Packet{
		SourcePort:     55000,
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	}, conntrack)
	if ingress.Verdict != VerdictAllow || !ingress.Established {
		t.Fatalf("ingress decision = %+v, want allow and established", ingress)
	}
	if conntrack.Len() != 1 {
		t.Fatalf("conntrack entries = %d, want 1", conntrack.Len())
	}

	reverse := EvaluateStateful("pod-a", nil, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		DestPort:       55000,
	}, conntrack)
	if reverse.Verdict != VerdictAllow || !reverse.Conntrack {
		t.Fatalf("reverse decision = %+v, want conntrack allow", reverse)
	}
}

func TestEvaluateStatefulDenyDoesNotCreateConntrack(t *testing.T) {
	entries := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + 24,
			RemoteIdentity: 100,
			Direction:      DirectionIngress,
			Protocol:       6,
			DestPortBE:     hostToNetwork16(443),
		},
		Value: PolicyEntry{
			Deny:        1,
			L4PrefixLen: 24,
			Precedence:  100,
			Stateful:    1,
		},
	}}
	conntrack := NewInMemoryConntrackStore()
	decision := EvaluateStateful("pod-a", entries, Packet{
		SourcePort:     55000,
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	}, conntrack)
	if decision.Verdict != VerdictDrop {
		t.Fatalf("decision = %+v, want drop", decision)
	}
	if conntrack.Len() != 0 {
		t.Fatalf("conntrack entries = %d, want 0", conntrack.Len())
	}
}

func TestConntrackDeleteEndpointRemovesState(t *testing.T) {
	conntrack := NewInMemoryConntrackStore()
	conntrack.Add(ConntrackKey{EndpointID: "pod-a", RemoteIdentity: 100, Direction: DirectionEgress, Protocol: 6, DestPort: 55000})
	conntrack.Add(ConntrackKey{EndpointID: "pod-b", RemoteIdentity: 100, Direction: DirectionEgress, Protocol: 6, DestPort: 55000})
	conntrack.DeleteEndpoint("pod-a")
	if conntrack.Len() != 1 {
		t.Fatalf("conntrack entries = %d, want 1", conntrack.Len())
	}
	if conntrack.Has(ConntrackKey{EndpointID: "pod-a", RemoteIdentity: 100, Direction: DirectionEgress, Protocol: 6, DestPort: 55000}) {
		t.Fatal("pod-a state should be deleted")
	}
}
