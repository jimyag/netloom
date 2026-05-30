package dataplane

import (
	"math"
	"net/netip"
	"testing"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
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

func TestEvaluateMatchesRemoteCIDRFromPacketIP(t *testing.T) {
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
				ID:         "allow-cidr",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("10.20.0.0/24"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionAllow,
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

	allowed := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("10.20.0.55"),
		Direction: DirectionIngress,
		Protocol:  6,
		DestPort:  8080,
	})
	if allowed.Verdict != VerdictAllow {
		t.Fatalf("cidr decision = %+v, want allow", allowed)
	}
	dropped := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("10.20.1.55"),
		Direction: DirectionIngress,
		Protocol:  6,
		DestPort:  8080,
	})
	if dropped.Verdict != VerdictDrop {
		t.Fatalf("outside cidr decision = %+v, want drop", dropped)
	}
}

func TestEvaluateRemoteCIDRKeepsIdentityPrecedence(t *testing.T) {
	entries := []PolicyMapEntry{
		{
			Key:        PolicyKey{PrefixLen: StaticPrefixBits + 24, RemoteIdentity: 100, Direction: DirectionIngress, Protocol: 6, DestPortBE: hostToNetwork16(443)},
			RemoteCIDR: netip.MustParsePrefix("10.20.0.0/24"),
			Value:      PolicyEntry{L4PrefixLen: 24, Precedence: 100},
		},
		{
			Key:        PolicyKey{PrefixLen: StaticPrefixBits + 24, RemoteIdentity: 200, Direction: DirectionIngress, Protocol: 6, DestPortBE: hostToNetwork16(443)},
			RemoteCIDR: netip.MustParsePrefix("10.20.0.55/32"),
			Value:      PolicyEntry{Deny: 1, L4PrefixLen: 24, Precedence: 200},
		},
	}
	decision := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("10.20.0.55"),
		Direction: DirectionIngress,
		Protocol:  6,
		DestPort:  443,
	})
	if decision.Verdict != VerdictDrop {
		t.Fatalf("decision = %+v, want higher-precedence cidr deny", decision)
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

func TestPolicyRecorderTracksMetricsAndDropEvents(t *testing.T) {
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
				RuleCookie:  42,
			},
		},
		{
			Key: PolicyKey{
				PrefixLen:      StaticPrefixBits + 24,
				RemoteIdentity: 200,
				Direction:      DirectionIngress,
				Protocol:       6,
				DestPortBE:     hostToNetwork16(443),
			},
			Value: PolicyEntry{
				Deny:        1,
				L4PrefixLen: 24,
				Precedence:  100,
				RuleCookie:  99,
			},
		},
	}
	recorder := NewPolicyRecorder()
	allow := EvaluateObserved("pod-a", entries, Packet{RemoteIdentity: 100, Direction: DirectionIngress, Protocol: 6, DestPort: 443}, recorder)
	deny := EvaluateObserved("pod-a", entries, Packet{RemoteIdentity: 200, Direction: DirectionIngress, Protocol: 6, DestPort: 443}, recorder)
	noMatch := EvaluateObserved("pod-a", entries, Packet{RemoteIdentity: 300, Direction: DirectionIngress, Protocol: 6, DestPort: 443}, recorder)
	if allow.Verdict != VerdictAllow || deny.Verdict != VerdictDrop || noMatch.Verdict != VerdictDrop {
		t.Fatalf("unexpected decisions: allow=%+v deny=%+v noMatch=%+v", allow, deny, noMatch)
	}
	metrics := recorder.Metrics("pod-a")
	if metrics.Allowed != 1 || metrics.Dropped != 2 || metrics.DenyDrops != 1 || metrics.NoMatchDrops != 1 {
		t.Fatalf("metrics = %+v, want allow=1 drop=2 deny=1 no-match=1", metrics)
	}
	events := recorder.DropEvents()
	if len(events) != 2 {
		t.Fatalf("drop events = %d, want 2", len(events))
	}
	if events[0].Reason != DropReasonPolicyDeny || events[0].RuleCookie != 99 {
		t.Fatalf("first event = %+v, want policy deny with cookie 99", events[0])
	}
	if events[1].Reason != DropReasonNoMatch || events[1].RuleCookie != 0 {
		t.Fatalf("second event = %+v, want no-match", events[1])
	}
}

func TestPolicyRecorderTracksLoggedPolicyEvents(t *testing.T) {
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
				Log:         1,
				Precedence:  100,
				RuleCookie:  42,
			},
		},
		{
			Key: PolicyKey{
				PrefixLen:      StaticPrefixBits + 24,
				RemoteIdentity: 200,
				Direction:      DirectionIngress,
				Protocol:       6,
				DestPortBE:     hostToNetwork16(8443),
			},
			Value: PolicyEntry{
				Deny:        1,
				L4PrefixLen: 24,
				Log:         1,
				Precedence:  100,
				RuleCookie:  99,
			},
		},
	}
	recorder := NewPolicyRecorder()
	allow := EvaluateObserved("pod-a", entries, Packet{RemoteIdentity: 100, Direction: DirectionIngress, Protocol: 6, DestPort: 443}, recorder)
	drop := EvaluateObserved("pod-a", entries, Packet{RemoteIdentity: 200, Direction: DirectionIngress, Protocol: 6, DestPort: 8443}, recorder)
	noMatch := EvaluateObserved("pod-a", entries, Packet{RemoteIdentity: 300, Direction: DirectionIngress, Protocol: 6, DestPort: 443}, recorder)
	if allow.Verdict != VerdictAllow || drop.Verdict != VerdictDrop || noMatch.Verdict != VerdictDrop {
		t.Fatalf("unexpected decisions: allow=%+v drop=%+v noMatch=%+v", allow, drop, noMatch)
	}
	metrics := recorder.Metrics("pod-a")
	if metrics.Logged != 2 {
		t.Fatalf("logged metrics = %d, want 2", metrics.Logged)
	}
	events := recorder.PolicyEvents()
	if len(events) != 2 {
		t.Fatalf("policy events = %d, want 2", len(events))
	}
	if events[0].Verdict != VerdictAllow || events[0].RuleCookie != 42 || events[0].DestPort != 443 {
		t.Fatalf("first event = %+v, want logged allow", events[0])
	}
	if events[1].Verdict != VerdictDrop || events[1].RuleCookie != 99 || events[1].DestPort != 8443 {
		t.Fatalf("second event = %+v, want logged drop", events[1])
	}
}

func TestActionLogCompilesToAllowPolicyEvent(t *testing.T) {
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"audit"},
	}
	program, err := policy.CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"audit": {
			Name: "audit",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "log-web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("10.20.0.0/24"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionLog,
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
	recorder := NewPolicyRecorder()
	decision := EvaluateObserved("pod-a", entries, Packet{
		RemoteIdentity: program.MapEntries[0].Key.RemoteIdentity,
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       8080,
	}, recorder)
	if decision.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow", decision.Verdict)
	}
	metrics := recorder.Metrics("pod-a")
	if metrics.Allowed != 1 || metrics.Logged != 1 || metrics.Dropped != 0 {
		t.Fatalf("metrics = %+v, want one logged allow", metrics)
	}
	events := recorder.PolicyEvents()
	if len(events) != 1 || events[0].Verdict != VerdictAllow || events[0].RuleCookie == 0 {
		t.Fatalf("policy events = %+v, want one logged allow with cookie", events)
	}
}

func TestPolicyRecorderTracksConntrackDecisions(t *testing.T) {
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
	recorder := NewPolicyRecorder()
	conntrack := NewInMemoryConntrackStore()
	EvaluateStatefulObserved("pod-a", entries, Packet{
		SourcePort:     55000,
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	}, conntrack, recorder)
	EvaluateStatefulObserved("pod-a", nil, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		DestPort:       55000,
	}, conntrack, recorder)
	metrics := recorder.Metrics("pod-a")
	if metrics.Allowed != 2 || metrics.Established != 1 || metrics.Conntrack != 1 {
		t.Fatalf("metrics = %+v, want allowed=2 established=1 conntrack=1", metrics)
	}
}
