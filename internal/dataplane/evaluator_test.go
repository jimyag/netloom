package dataplane

import (
	"math"
	"net/netip"
	"testing"
	"time"

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

func TestEvaluateRequiresRemoteCIDRMatchEvenWhenIdentityMatches(t *testing.T) {
	entries := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + 24,
			RemoteIdentity: policy.EndpointIdentity(model.EndpointKey("prod", "pod-b")),
			Direction:      DirectionIngress,
			Protocol:       6,
			DestPortBE:     hostToNetwork16(443),
		},
		RemoteCIDR: netip.MustParsePrefix("10.20.0.0/16"),
		Value: PolicyEntry{
			L4PrefixLen:     24,
			Precedence:      100,
			RequireIdentity: 1,
		},
	}}

	spoofed := Evaluate(entries, Packet{
		RemoteIdentity: policy.EndpointIdentity(model.EndpointKey("prod", "pod-b")),
		RemoteIP:       netip.MustParseAddr("10.30.0.10"),
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	})
	if spoofed.Verdict != VerdictDrop {
		t.Fatalf("verdict = %s, want drop when identity matches but CIDR does not", spoofed.Verdict)
	}

	allowed := Evaluate(entries, Packet{
		RemoteIdentity: policy.EndpointIdentity(model.EndpointKey("prod", "pod-b")),
		RemoteIP:       netip.MustParseAddr("10.20.0.10"),
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	})
	if allowed.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow when both identity and CIDR match", allowed.Verdict)
	}
}

func TestEvaluatePreservesRejectVerdict(t *testing.T) {
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
			Reject:      1,
			L4PrefixLen: 24,
			Precedence:  100,
			RuleCookie:  77,
		},
	}}
	recorder := NewPolicyRecorder()
	decision := EvaluateObserved(model.EndpointKey("prod", "pod-a"), entries, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	}, recorder)
	if decision.Verdict != VerdictReject {
		t.Fatalf("verdict = %s, want reject", decision.Verdict)
	}
	metrics := recorder.Metrics(model.EndpointKey("prod", "pod-a"))
	if metrics.Dropped != 1 || metrics.RejectDrops != 1 || metrics.DenyDrops != 0 || metrics.NoMatchDrops != 0 {
		t.Fatalf("metrics = %+v, want one policy reject drop", metrics)
	}
	events := recorder.DropEvents()
	if len(events) != 1 || events[0].Reason != DropReasonPolicyReject || events[0].RuleCookie != 77 {
		t.Fatalf("drop events = %+v, want policy reject with cookie", events)
	}
}

func TestEvaluateAllowsIPv4FragmentationNeededForPMTU(t *testing.T) {
	entries := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + 24,
			RemoteIdentity: 0,
			Direction:      DirectionIngress,
			Protocol:       1,
			DestPortBE:     hostToNetwork16(0x0304),
		},
		Value: PolicyEntry{
			Deny:        1,
			L4PrefixLen: 24,
			Precedence:  math.MaxUint32,
		},
	}}

	decision := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("192.0.2.10"),
		Direction: DirectionIngress,
		Protocol:  1,
		ICMPType:  3,
		ICMPCode:  4,
	})
	if decision.Verdict != VerdictAllow || decision.Match != nil {
		t.Fatalf("fragmentation-needed decision = %+v, want unconditional PMTU allow", decision)
	}

	otherUnreachable := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("192.0.2.10"),
		Direction: DirectionIngress,
		Protocol:  1,
		ICMPType:  3,
		ICMPCode:  1,
	})
	if otherUnreachable.Verdict != VerdictDrop {
		t.Fatalf("other ICMP unreachable decision = %+v, want policy drop", otherUnreachable)
	}
}

func TestEvaluateAllowsIPv6PacketTooBigForPMTU(t *testing.T) {
	entries := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + 24,
			RemoteIdentity: 0,
			Direction:      DirectionEgress,
			Protocol:       58,
			DestPortBE:     hostToNetwork16(0x0200),
		},
		Value: PolicyEntry{
			Deny:        1,
			L4PrefixLen: 24,
			Precedence:  math.MaxUint32,
		},
	}}

	decision := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("2001:db8::10"),
		Direction: DirectionEgress,
		Protocol:  58,
		ICMPType:  2,
		ICMPCode:  0,
	})
	if decision.Verdict != VerdictAllow || decision.Match != nil {
		t.Fatalf("packet-too-big decision = %+v, want unconditional PMTU allow", decision)
	}

	otherUnreachable := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("2001:db8::10"),
		Direction: DirectionEgress,
		Protocol:  58,
		ICMPType:  1,
		ICMPCode:  0,
	})
	if otherUnreachable.Verdict != VerdictDrop {
		t.Fatalf("other ICMPv6 unreachable decision = %+v, want policy drop", otherUnreachable)
	}
}

func TestEvaluateAllowsIPv6NeighborDiscovery(t *testing.T) {
	entries := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + 24,
			RemoteIdentity: 0,
			Direction:      DirectionIngress,
			Protocol:       58,
			DestPortBE:     hostToNetwork16(0x8700),
		},
		Value: PolicyEntry{
			Deny:        1,
			L4PrefixLen: 24,
			Precedence:  math.MaxUint32,
		},
	}}

	for _, icmpType := range []uint8{133, 134, 135, 136} {
		decision := Evaluate(entries, Packet{
			RemoteIP:  netip.MustParseAddr("fe80::1"),
			Direction: DirectionIngress,
			Protocol:  58,
			ICMPType:  icmpType,
			ICMPCode:  0,
		})
		if decision.Verdict != VerdictAllow || decision.Match != nil {
			t.Fatalf("ICMPv6 type %d decision = %+v, want unconditional NDP allow", icmpType, decision)
		}
	}

	malformed := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("fe80::1"),
		Direction: DirectionIngress,
		Protocol:  58,
		ICMPType:  135,
		ICMPCode:  1,
	})
	if malformed.Verdict != VerdictDrop {
		t.Fatalf("malformed NDP decision = %+v, want policy drop", malformed)
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

func TestEvaluateMatchesICMPTypeAndCode(t *testing.T) {
	entries := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + 24,
			RemoteIdentity: 0,
			Direction:      DirectionEgress,
			Protocol:       1,
			DestPortBE:     hostToNetwork16(0x0800),
		},
		Value: PolicyEntry{
			L4PrefixLen: 24,
			Precedence:  10,
		},
	}}

	allowed := Evaluate(entries, Packet{Direction: DirectionEgress, Protocol: 1, ICMPType: 8, ICMPCode: 0})
	if allowed.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow", allowed.Verdict)
	}
	dropped := Evaluate(entries, Packet{Direction: DirectionEgress, Protocol: 1, ICMPType: 8, ICMPCode: 1})
	if dropped.Verdict != VerdictDrop {
		t.Fatalf("verdict = %s, want drop", dropped.Verdict)
	}
}

func TestEvaluateMatchesICMPTypeOnly(t *testing.T) {
	entries := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + 16,
			RemoteIdentity: 0,
			Direction:      DirectionIngress,
			Protocol:       1,
			DestPortBE:     hostToNetwork16(0x0300),
		},
		Value: PolicyEntry{
			L4PrefixLen: 16,
			Precedence:  10,
		},
	}}

	allowed := Evaluate(entries, Packet{Direction: DirectionIngress, Protocol: 1, ICMPType: 3, ICMPCode: 1})
	if allowed.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow", allowed.Verdict)
	}
	dropped := Evaluate(entries, Packet{Direction: DirectionIngress, Protocol: 1, ICMPType: 8, ICMPCode: 0})
	if dropped.Verdict != VerdictDrop {
		t.Fatalf("verdict = %s, want drop", dropped.Verdict)
	}
}

func TestEvaluateMatchesICMPv6TypeAndCode(t *testing.T) {
	icmpType := uint8(128)
	icmpCode := uint8(0)
	endpoint := model.Endpoint{
		ID:             "pod-a",
		VPC:            "prod",
		Subnet:         "apps-v6",
		IP:             netip.MustParseAddr("fd00:10::10"),
		Node:           "node-a",
		SecurityGroups: []string{"icmpv6"},
	}
	program, err := policy.CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"icmpv6": {
			Name: "icmpv6",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-icmpv6-echo",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolICMP,
				RemoteCIDR: netip.MustParsePrefix("fd00:20::/64"),
				ICMPType:   &icmpType,
				ICMPCode:   &icmpCode,
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
	if len(entries) != 1 || entries[0].Key.Protocol != 58 {
		t.Fatalf("encoded entries = %+v, want ICMPv6 protocol 58", entries)
	}

	allowed := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("fd00:20::11"),
		Direction: DirectionIngress,
		Protocol:  58,
		ICMPType:  128,
		ICMPCode:  0,
	})
	if allowed.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow", allowed.Verdict)
	}
	dropped := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("fd00:20::11"),
		Direction: DirectionIngress,
		Protocol:  58,
		ICMPType:  128,
		ICMPCode:  1,
	})
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

func TestEvaluateRemoteCIDRChoosesLongestPrefix(t *testing.T) {
	specificCookie := stableCookie("allow-specific-host")
	entries := []PolicyMapEntry{
		{
			Key:        PolicyKey{PrefixLen: StaticPrefixBits + 24, RemoteIdentity: 200, Direction: DirectionIngress, Protocol: 6, DestPortBE: hostToNetwork16(443)},
			RemoteCIDR: netip.MustParsePrefix("10.20.0.55/32"),
			Value:      PolicyEntry{L4PrefixLen: 24, Precedence: 100, RuleCookie: specificCookie},
		},
		{
			Key:        PolicyKey{PrefixLen: StaticPrefixBits + 24, RemoteIdentity: 100, Direction: DirectionIngress, Protocol: 6, DestPortBE: hostToNetwork16(443)},
			RemoteCIDR: netip.MustParsePrefix("10.20.0.0/24"),
			Value:      PolicyEntry{L4PrefixLen: 24, Precedence: 100, RuleCookie: stableCookie("allow-subnet")},
		},
	}
	decision := Evaluate(entries, Packet{
		RemoteIP:  netip.MustParseAddr("10.20.0.55"),
		Direction: DirectionIngress,
		Protocol:  6,
		DestPort:  443,
	})
	if decision.Verdict != VerdictAllow || decision.Match == nil {
		t.Fatalf("decision = %+v, want allow with matched rule", decision)
	}
	if decision.Match.Value.RuleCookie != specificCookie {
		t.Fatalf("rule cookie = %d, want longest-prefix cookie %d", decision.Match.Value.RuleCookie, specificCookie)
	}
}

func TestEvaluateRemoteCIDRDoesNotOverrideExactIdentity(t *testing.T) {
	exactCookie := stableCookie("allow-identity")
	entries := []PolicyMapEntry{
		{
			Key:        PolicyKey{PrefixLen: StaticPrefixBits + 24, RemoteIdentity: 100, Direction: DirectionIngress, Protocol: 6, DestPortBE: hostToNetwork16(443)},
			Value:      PolicyEntry{L4PrefixLen: 24, Precedence: 100, RuleCookie: exactCookie},
			RemoteCIDR: netip.MustParsePrefix("10.20.0.0/24"),
		},
		{
			Key:        PolicyKey{PrefixLen: StaticPrefixBits + 24, RemoteIdentity: 200, Direction: DirectionIngress, Protocol: 6, DestPortBE: hostToNetwork16(443)},
			RemoteCIDR: netip.MustParsePrefix("10.20.0.55/32"),
			Value:      PolicyEntry{L4PrefixLen: 24, Precedence: 100, RuleCookie: stableCookie("allow-cidr-host")},
		},
	}
	decision := Evaluate(entries, Packet{
		RemoteIdentity: 100,
		RemoteIP:       netip.MustParseAddr("10.20.0.55"),
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	})
	if decision.Verdict != VerdictAllow || decision.Match == nil {
		t.Fatalf("decision = %+v, want allow with matched rule", decision)
	}
	if decision.Match.Value.RuleCookie != exactCookie {
		t.Fatalf("rule cookie = %d, want exact identity cookie %d", decision.Match.Value.RuleCookie, exactCookie)
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

	ingress := EvaluateStateful(model.EndpointKey("prod", "pod-a"), entries, Packet{
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

	reverse := EvaluateStateful(model.EndpointKey("prod", "pod-a"), nil, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		SourcePort:     443,
		DestPort:       55000,
	}, conntrack)
	if reverse.Verdict != VerdictAllow || !reverse.Conntrack {
		t.Fatalf("reverse decision = %+v, want conntrack allow", reverse)
	}
}

func TestEvaluateStatefulKeepsConntrackSourcePortsSeparate(t *testing.T) {
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

	allowed := EvaluateStateful(model.EndpointKey("prod", "pod-a"), entries, Packet{
		SourcePort:     55000,
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	}, conntrack)
	if allowed.Verdict != VerdictAllow || !allowed.Established {
		t.Fatalf("allowed decision = %+v, want stateful allow", allowed)
	}

	reverseDifferentLocalPort := EvaluateStateful(model.EndpointKey("prod", "pod-a"), nil, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		SourcePort:     8443,
		DestPort:       55000,
	}, conntrack)
	if reverseDifferentLocalPort.Verdict != VerdictDrop || reverseDifferentLocalPort.Conntrack {
		t.Fatalf("reverse different local port decision = %+v, want no conntrack match", reverseDifferentLocalPort)
	}

	reverseSameLocalPort := EvaluateStateful(model.EndpointKey("prod", "pod-a"), nil, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		SourcePort:     443,
		DestPort:       55000,
	}, conntrack)
	if reverseSameLocalPort.Verdict != VerdictAllow || !reverseSameLocalPort.Conntrack {
		t.Fatalf("reverse same local port decision = %+v, want conntrack allow", reverseSameLocalPort)
	}
}

func TestEvaluateStatefulKeepsICMPTypesSeparate(t *testing.T) {
	entries := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + 24,
			RemoteIdentity: 100,
			Direction:      DirectionEgress,
			Protocol:       1,
			DestPortBE:     hostToNetwork16(0x0800),
		},
		Value: PolicyEntry{
			L4PrefixLen: 24,
			Precedence:  100,
			Stateful:    1,
		},
	}}
	conntrack := NewInMemoryConntrackStore()

	request := EvaluateStateful(model.EndpointKey("prod", "pod-a"), entries, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       1,
		ICMPType:       8,
		ICMPCode:       0,
	}, conntrack)
	if request.Verdict != VerdictAllow || !request.Established {
		t.Fatalf("request decision = %+v, want stateful allow", request)
	}

	wrongReply := EvaluateStateful(model.EndpointKey("prod", "pod-a"), nil, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       1,
		ICMPType:       3,
		ICMPCode:       0,
	}, conntrack)
	if wrongReply.Verdict != VerdictDrop || wrongReply.Conntrack {
		t.Fatalf("wrong reply decision = %+v, want no conntrack match", wrongReply)
	}

	echoReply := EvaluateStateful(model.EndpointKey("prod", "pod-a"), nil, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       1,
		ICMPType:       0,
		ICMPCode:       0,
	}, conntrack)
	if echoReply.Verdict != VerdictAllow || !echoReply.Conntrack {
		t.Fatalf("echo reply decision = %+v, want conntrack allow", echoReply)
	}
}

func TestEvaluateStatefulKeepsICMPv6TypesSeparate(t *testing.T) {
	entries := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + 24,
			RemoteIdentity: 100,
			Direction:      DirectionEgress,
			Protocol:       58,
			DestPortBE:     hostToNetwork16(0x8000),
		},
		Value: PolicyEntry{
			L4PrefixLen: 24,
			Precedence:  100,
			Stateful:    1,
		},
	}}
	conntrack := NewInMemoryConntrackStore()

	request := EvaluateStateful(model.EndpointKey("prod", "pod-a"), entries, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       58,
		ICMPType:       128,
		ICMPCode:       0,
	}, conntrack)
	if request.Verdict != VerdictAllow || !request.Established {
		t.Fatalf("request decision = %+v, want stateful allow", request)
	}

	wrongReply := EvaluateStateful(model.EndpointKey("prod", "pod-a"), nil, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       58,
		ICMPType:       1,
		ICMPCode:       0,
	}, conntrack)
	if wrongReply.Verdict != VerdictDrop || wrongReply.Conntrack {
		t.Fatalf("wrong reply decision = %+v, want no conntrack match", wrongReply)
	}

	echoReply := EvaluateStateful(model.EndpointKey("prod", "pod-a"), nil, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       58,
		ICMPType:       129,
		ICMPCode:       0,
	}, conntrack)
	if echoReply.Verdict != VerdictAllow || !echoReply.Conntrack {
		t.Fatalf("echo reply decision = %+v, want conntrack allow", echoReply)
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
	decision := EvaluateStateful(model.EndpointKey("prod", "pod-a"), entries, Packet{
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

func TestEvaluateStatefulDenyOverridesConntrack(t *testing.T) {
	entries := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + 24,
			RemoteIdentity: 100,
			Direction:      DirectionEgress,
			Protocol:       6,
			DestPortBE:     hostToNetwork16(55000),
		},
		Value: PolicyEntry{
			Deny:        1,
			L4PrefixLen: 24,
			Precedence:  math.MaxUint32,
			RuleCookie:  99,
		},
	}}
	conntrack := NewInMemoryConntrackStore()
	conntrack.Add(ConntrackKey{
		EndpointID:     model.EndpointKey("prod", "pod-a"),
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		SourcePort:     443,
		DestPort:       55000,
	})

	recorder := NewPolicyRecorder()
	decision := EvaluateStatefulObserved(model.EndpointKey("prod", "pod-a"), entries, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		SourcePort:     443,
		DestPort:       55000,
	}, conntrack, recorder)
	if decision.Verdict != VerdictDrop || decision.Conntrack {
		t.Fatalf("decision = %+v, want explicit deny to override conntrack", decision)
	}
	metrics := recorder.Metrics(model.EndpointKey("prod", "pod-a"))
	if metrics.Dropped != 1 || metrics.DenyDrops != 1 || metrics.Allowed != 0 || metrics.Conntrack != 0 {
		t.Fatalf("metrics = %+v, want one policy deny without conntrack allow", metrics)
	}
	events := recorder.DropEvents()
	if len(events) != 1 || events[0].Reason != DropReasonPolicyDeny || events[0].RuleCookie != 99 {
		t.Fatalf("drop events = %+v, want explicit deny event", events)
	}
}

func TestEvaluateStatefulRejectOverridesConntrack(t *testing.T) {
	entries := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + 24,
			RemoteIdentity: 100,
			Direction:      DirectionEgress,
			Protocol:       6,
			DestPortBE:     hostToNetwork16(55000),
		},
		Value: PolicyEntry{
			Deny:        1,
			Reject:      1,
			L4PrefixLen: 24,
			Precedence:  math.MaxUint32,
			RuleCookie:  101,
		},
	}}
	conntrack := NewInMemoryConntrackStore()
	conntrack.Add(ConntrackKey{
		EndpointID:     model.EndpointKey("prod", "pod-a"),
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		SourcePort:     443,
		DestPort:       55000,
	})

	decision := EvaluateStateful(model.EndpointKey("prod", "pod-a"), entries, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		SourcePort:     443,
		DestPort:       55000,
	}, conntrack)
	if decision.Verdict != VerdictReject || decision.Conntrack {
		t.Fatalf("decision = %+v, want explicit reject to override conntrack", decision)
	}
}

func TestConntrackDeleteEndpointRemovesState(t *testing.T) {
	conntrack := NewInMemoryConntrackStore()
	conntrack.Add(ConntrackKey{EndpointID: model.EndpointKey("prod", "pod-a"), RemoteIdentity: 100, Direction: DirectionEgress, Protocol: 6, DestPort: 55000})
	conntrack.Add(ConntrackKey{EndpointID: model.EndpointKey("prod", "pod-b"), RemoteIdentity: 100, Direction: DirectionEgress, Protocol: 6, DestPort: 55000})
	conntrack.DeleteEndpoint(model.EndpointKey("prod", "pod-a"))
	if conntrack.Len() != 1 {
		t.Fatalf("conntrack entries = %d, want 1", conntrack.Len())
	}
	if conntrack.Has(ConntrackKey{EndpointID: model.EndpointKey("prod", "pod-a"), RemoteIdentity: 100, Direction: DirectionEgress, Protocol: 6, DestPort: 55000}) {
		t.Fatal("pod-a state should be deleted")
	}
}

func TestConntrackKeysAreVPCAware(t *testing.T) {
	conntrack := NewInMemoryConntrackStore()
	prodEndpoint := model.EndpointKey("prod", "pod-a")
	devEndpoint := model.EndpointKey("dev", "pod-a")
	conntrack.Add(ConntrackKey{
		EndpointID:     devEndpoint,
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		SourcePort:     443,
		DestPort:       55000,
	})

	prodReply := EvaluateStateful(prodEndpoint, nil, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		SourcePort:     443,
		DestPort:       55000,
	}, conntrack)
	if prodReply.Verdict != VerdictDrop {
		t.Fatalf("prod reply = %+v, want conntrack mismatch due to VPC mismatch", prodReply)
	}

	devReply := EvaluateStateful(devEndpoint, nil, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		SourcePort:     443,
		DestPort:       55000,
	}, conntrack)
	if devReply.Verdict != VerdictAllow || !devReply.Conntrack {
		t.Fatalf("dev reply = %+v, want conntrack allow", devReply)
	}
}

func TestConntrackExpiresIdleEntries(t *testing.T) {
	now := time.Unix(100, 0)
	conntrack := newInMemoryConntrackStoreWithClock(time.Second, func() time.Time { return now })
	key := ConntrackKey{EndpointID: model.EndpointKey("prod", "pod-a"), RemoteIdentity: 100, Direction: DirectionEgress, Protocol: 6, DestPort: 55000}
	conntrack.Add(key)

	now = now.Add(time.Second)
	if !conntrack.Has(key) {
		t.Fatal("conntrack entry should still be alive at max idle boundary")
	}
	now = now.Add(1500 * time.Millisecond)
	if conntrack.Has(key) {
		t.Fatal("conntrack entry should expire after idle timeout")
	}
	if conntrack.Len() != 0 {
		t.Fatalf("conntrack entries = %d, want expired entry removed", conntrack.Len())
	}
}

func TestConntrackSweepIdleEntries(t *testing.T) {
	now := time.Unix(100, 0)
	conntrack := newInMemoryConntrackStoreWithClock(0, func() time.Time { return now })
	conntrack.Add(ConntrackKey{EndpointID: model.EndpointKey("prod", "pod-a"), RemoteIdentity: 100, Direction: DirectionEgress, Protocol: 6, DestPort: 55000})
	conntrack.Add(ConntrackKey{EndpointID: model.EndpointKey("prod", "pod-b"), RemoteIdentity: 100, Direction: DirectionEgress, Protocol: 6, DestPort: 55000})

	now = now.Add(2 * time.Second)
	deleted := conntrack.SweepIdle(time.Second)
	if deleted != 2 || conntrack.Len() != 0 {
		t.Fatalf("deleted=%d remaining=%d, want both conntrack entries expired", deleted, conntrack.Len())
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
	allow := EvaluateObserved(model.EndpointKey("prod", "pod-a"), entries, Packet{RemoteIdentity: 100, RemoteIP: netip.MustParseAddr("10.20.0.10"), Direction: DirectionIngress, Protocol: 6, DestPort: 443}, recorder)
	deny := EvaluateObserved(model.EndpointKey("prod", "pod-a"), entries, Packet{RemoteIdentity: 200, RemoteIP: netip.MustParseAddr("10.20.0.20"), Direction: DirectionIngress, Protocol: 6, DestPort: 443}, recorder)
	noMatch := EvaluateObserved(model.EndpointKey("prod", "pod-a"), entries, Packet{RemoteIdentity: 300, RemoteIP: netip.MustParseAddr("10.20.0.30"), Direction: DirectionIngress, Protocol: 6, DestPort: 443}, recorder)
	if allow.Verdict != VerdictAllow || deny.Verdict != VerdictDrop || noMatch.Verdict != VerdictDrop {
		t.Fatalf("unexpected decisions: allow=%+v deny=%+v noMatch=%+v", allow, deny, noMatch)
	}
	metrics := recorder.Metrics(model.EndpointKey("prod", "pod-a"))
	if metrics.Allowed != 1 || metrics.Dropped != 2 || metrics.DenyDrops != 1 || metrics.NoMatchDrops != 1 {
		t.Fatalf("metrics = %+v, want allow=1 drop=2 deny=1 no-match=1", metrics)
	}
	events := recorder.DropEvents()
	if len(events) != 2 {
		t.Fatalf("drop events = %d, want 2", len(events))
	}
	if events[0].Reason != DropReasonPolicyDeny || events[0].RuleCookie != 99 || events[0].RemoteIP != netip.MustParseAddr("10.20.0.20") {
		t.Fatalf("first event = %+v, want policy deny with cookie 99", events[0])
	}
	if events[1].Reason != DropReasonNoMatch || events[1].RuleCookie != 0 || events[1].RemoteIP != netip.MustParseAddr("10.20.0.30") {
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
	allow := EvaluateObserved(model.EndpointKey("prod", "pod-a"), entries, Packet{RemoteIdentity: 100, RemoteIP: netip.MustParseAddr("10.30.0.10"), Direction: DirectionIngress, Protocol: 6, DestPort: 443}, recorder)
	drop := EvaluateObserved(model.EndpointKey("prod", "pod-a"), entries, Packet{RemoteIdentity: 200, RemoteIP: netip.MustParseAddr("10.30.0.20"), Direction: DirectionIngress, Protocol: 6, DestPort: 8443}, recorder)
	noMatch := EvaluateObserved(model.EndpointKey("prod", "pod-a"), entries, Packet{RemoteIdentity: 300, RemoteIP: netip.MustParseAddr("10.30.0.30"), Direction: DirectionIngress, Protocol: 6, DestPort: 443}, recorder)
	if allow.Verdict != VerdictAllow || drop.Verdict != VerdictDrop || noMatch.Verdict != VerdictDrop {
		t.Fatalf("unexpected decisions: allow=%+v drop=%+v noMatch=%+v", allow, drop, noMatch)
	}
	metrics := recorder.Metrics(model.EndpointKey("prod", "pod-a"))
	if metrics.Logged != 2 {
		t.Fatalf("logged metrics = %d, want 2", metrics.Logged)
	}
	events := recorder.PolicyEvents()
	if len(events) != 2 {
		t.Fatalf("policy events = %d, want 2", len(events))
	}
	if events[0].Verdict != VerdictAllow || events[0].RuleCookie != 42 || events[0].DestPort != 443 || events[0].RemoteIP != netip.MustParseAddr("10.30.0.10") {
		t.Fatalf("first event = %+v, want logged allow", events[0])
	}
	if events[1].Verdict != VerdictDrop || events[1].RuleCookie != 99 || events[1].DestPort != 8443 || events[1].RemoteIP != netip.MustParseAddr("10.30.0.20") {
		t.Fatalf("second event = %+v, want logged drop", events[1])
	}
}

func TestPolicyRecorderAggregatesRuleMetrics(t *testing.T) {
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
				Log:         1,
				L4PrefixLen: 24,
				Precedence:  100,
				RuleCookie:  99,
			},
		},
	}
	recorder := NewPolicyRecorder()
	endpointID := model.EndpointKey("prod", "pod-a")

	EvaluateObserved(endpointID, entries, Packet{
		RemoteIdentity: 100,
		RemoteIP:       netip.MustParseAddr("10.30.0.10"),
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       443,
		Bytes:          128,
	}, recorder)
	EvaluateObserved(endpointID, entries, Packet{
		RemoteIdentity: 200,
		RemoteIP:       netip.MustParseAddr("10.30.0.20"),
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       8443,
		Bytes:          256,
	}, recorder)
	EvaluateObserved(endpointID, entries, Packet{
		RemoteIdentity: 300,
		RemoteIP:       netip.MustParseAddr("10.30.0.30"),
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       9443,
		Bytes:          512,
	}, recorder)

	stats := recorder.RuleMetrics(endpointID)
	if len(stats) != 3 {
		t.Fatalf("rule metrics = %+v, want 3 buckets including no-match", stats)
	}
	if stats[0].RuleCookie != 0 || stats[0].Packets != 1 || stats[0].Bytes != 512 || stats[0].Dropped != 1 || stats[0].NoMatchDrops != 1 {
		t.Fatalf("no-match rule metrics = %+v, want one 512-byte no-match drop", stats[0])
	}
	if stats[1].RuleCookie != 42 || stats[1].Allowed != 1 || stats[1].Dropped != 0 || stats[1].Bytes != 128 || stats[1].Logged != 1 {
		t.Fatalf("allow rule metrics = %+v, want one logged allow", stats[1])
	}
	if stats[2].RuleCookie != 99 || stats[2].Allowed != 0 || stats[2].Dropped != 1 || stats[2].Bytes != 256 || stats[2].DenyDrops != 1 || stats[2].Logged != 1 {
		t.Fatalf("deny rule metrics = %+v, want one logged deny drop", stats[2])
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
	decision := EvaluateObserved(model.EndpointKey("prod", "pod-a"), entries, Packet{
		RemoteIdentity: program.MapEntries[0].Key.RemoteIdentity,
		RemoteIP:       netip.MustParseAddr("10.20.0.10"),
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       8080,
	}, recorder)
	if decision.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow", decision.Verdict)
	}
	metrics := recorder.Metrics(model.EndpointKey("prod", "pod-a"))
	if metrics.Allowed != 1 || metrics.Logged != 1 || metrics.Dropped != 0 {
		t.Fatalf("metrics = %+v, want one logged allow", metrics)
	}
	events := recorder.PolicyEvents()
	if len(events) != 1 || events[0].Verdict != VerdictAllow || events[0].RuleCookie == 0 || events[0].RemoteIP != netip.MustParseAddr("10.20.0.10") {
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
	EvaluateStatefulObserved(model.EndpointKey("prod", "pod-a"), entries, Packet{
		SourcePort:     55000,
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	}, conntrack, recorder)
	EvaluateStatefulObserved(model.EndpointKey("prod", "pod-a"), nil, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		SourcePort:     443,
		DestPort:       55000,
	}, conntrack, recorder)
	metrics := recorder.Metrics(model.EndpointKey("prod", "pod-a"))
	if metrics.Allowed != 2 || metrics.Established != 1 || metrics.Conntrack != 1 {
		t.Fatalf("metrics = %+v, want allowed=2 established=1 conntrack=1", metrics)
	}
}

func TestPolicyRecorderTracksTraceEvents(t *testing.T) {
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
	}, {
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
			Precedence:  100,
			RuleCookie:  88,
		},
	}}
	recorder := NewPolicyRecorder()
	conntrack := NewInMemoryConntrackStore()

	EvaluateStatefulObserved(model.EndpointKey("prod", "pod-a"), entries, Packet{
		SourcePort:     50000,
		RemoteIdentity: 100,
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	}, conntrack, recorder)
	EvaluateStatefulObserved(model.EndpointKey("prod", "pod-a"), entries, Packet{
		RemoteIdentity: 200,
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       8443,
		RemoteIP:       netip.MustParseAddr("10.10.0.99"),
	}, conntrack, recorder)
	EvaluateStatefulObserved(model.EndpointKey("prod", "pod-a"), entries, Packet{
		RemoteIdentity: 300,
		Direction:      DirectionIngress,
		Protocol:       6,
		DestPort:       443,
		RemoteIP:       netip.MustParseAddr("10.10.0.88"),
	}, conntrack, recorder)
	EvaluateStatefulObserved(model.EndpointKey("prod", "pod-a"), nil, Packet{
		RemoteIdentity: 100,
		Direction:      DirectionEgress,
		Protocol:       6,
		SourcePort:     443,
		DestPort:       50000,
	}, conntrack, recorder)

	events := recorder.TraceEvents()
	if len(events) != 4 {
		t.Fatalf("trace events = %d, want 4", len(events))
	}
	if events[0].Verdict != VerdictAllow || events[0].Established != true || events[0].Conntrack {
		t.Fatalf("first trace event = %+v, want stateful allow establishing conntrack", events[0])
	}
	if events[1].Verdict != VerdictDrop || !events[1].DenyDrop || events[1].RuleCookie != 88 {
		t.Fatalf("second trace event = %+v, want policy deny with cookie", events[1])
	}
	if !events[2].NoMatchDrop || events[2].Verdict != VerdictDrop {
		t.Fatalf("third trace event = %+v, want no-match drop marker", events[2])
	}
	if events[3].Verdict != VerdictAllow || !events[3].Conntrack {
		t.Fatalf("fourth trace event = %+v, want conntrack allow", events[3])
	}
}
