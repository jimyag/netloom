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
