package dataplane

import (
	"encoding/binary"
	"sync"
)

type Packet struct {
	SourcePort     uint16
	RemoteIdentity uint32
	Direction      uint8
	Protocol       uint8
	DestPort       uint16
}

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDrop  Verdict = "drop"
)

type Decision struct {
	Verdict     Verdict
	Match       *PolicyMapEntry
	Conntrack   bool
	Established bool
}

func Evaluate(entries []PolicyMapEntry, packet Packet) Decision {
	var selected *PolicyMapEntry
	for i := range entries {
		entry := &entries[i]
		if !matches(entry.Key, packet) {
			continue
		}
		if selected == nil || betterMatch(*entry, *selected) {
			selected = entry
		}
	}
	if selected == nil {
		return Decision{Verdict: VerdictDrop}
	}
	if selected.Value.Deny != 0 {
		return Decision{Verdict: VerdictDrop, Match: selected}
	}
	return Decision{Verdict: VerdictAllow, Match: selected}
}

type ConntrackKey struct {
	EndpointID     string
	RemoteIdentity uint32
	Direction      uint8
	Protocol       uint8
	DestPort       uint16
}

type ConntrackStore interface {
	Has(ConntrackKey) bool
	Add(ConntrackKey)
	DeleteEndpoint(endpointID string)
	Len() int
}

type InMemoryConntrackStore struct {
	mu      sync.Mutex
	entries map[ConntrackKey]struct{}
}

func NewInMemoryConntrackStore() *InMemoryConntrackStore {
	return &InMemoryConntrackStore{entries: make(map[ConntrackKey]struct{})}
}

func (s *InMemoryConntrackStore) Has(key ConntrackKey) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.entries[key]
	return ok
}

func (s *InMemoryConntrackStore) Add(key ConntrackKey) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = struct{}{}
}

func (s *InMemoryConntrackStore) DeleteEndpoint(endpointID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.entries {
		if key.EndpointID == endpointID {
			delete(s.entries, key)
		}
	}
}

func (s *InMemoryConntrackStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func EvaluateStateful(endpointID string, entries []PolicyMapEntry, packet Packet, conntrack ConntrackStore) Decision {
	if endpointID != "" && conntrack != nil && conntrack.Has(conntrackKey(endpointID, packet)) {
		return Decision{Verdict: VerdictAllow, Conntrack: true}
	}
	decision := Evaluate(entries, packet)
	if decision.Verdict != VerdictAllow || decision.Match == nil || decision.Match.Value.Stateful == 0 || conntrack == nil {
		return decision
	}
	reverse := reverseConntrackKey(endpointID, packet)
	if reverse.EndpointID != "" {
		conntrack.Add(reverse)
		decision.Established = true
	}
	return decision
}

func matches(key PolicyKey, packet Packet) bool {
	if key.Direction != packet.Direction {
		return false
	}
	if key.RemoteIdentity != 0 && key.RemoteIdentity != packet.RemoteIdentity {
		return false
	}

	l4PrefixLen := uint8(key.PrefixLen - StaticPrefixBits)
	if l4PrefixLen == 0 {
		return true
	}
	if key.Protocol != packet.Protocol {
		return false
	}
	if l4PrefixLen <= 8 {
		return true
	}

	portPrefixLen := l4PrefixLen - 8
	mask := uint16(0xffff << (16 - portPrefixLen))
	return networkToHost16(key.DestPortBE)&mask == packet.DestPort&mask
}

func betterMatch(candidate, selected PolicyMapEntry) bool {
	if candidate.Value.Precedence != selected.Value.Precedence {
		return candidate.Value.Precedence > selected.Value.Precedence
	}
	if candidate.Value.L4PrefixLen != selected.Value.L4PrefixLen {
		return candidate.Value.L4PrefixLen > selected.Value.L4PrefixLen
	}
	if candidate.Key.RemoteIdentity != selected.Key.RemoteIdentity {
		return candidate.Key.RemoteIdentity != 0
	}
	return false
}

func networkToHost16(value uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], value)
	return binary.BigEndian.Uint16(b[:])
}

func conntrackKey(endpointID string, packet Packet) ConntrackKey {
	return ConntrackKey{
		EndpointID:     endpointID,
		RemoteIdentity: packet.RemoteIdentity,
		Direction:      packet.Direction,
		Protocol:       packet.Protocol,
		DestPort:       packet.DestPort,
	}
}

func reverseConntrackKey(endpointID string, packet Packet) ConntrackKey {
	port := packet.SourcePort
	if port == 0 {
		port = packet.DestPort
	}
	return ConntrackKey{
		EndpointID:     endpointID,
		RemoteIdentity: packet.RemoteIdentity,
		Direction:      reverseDirection(packet.Direction),
		Protocol:       packet.Protocol,
		DestPort:       port,
	}
}

func reverseDirection(direction uint8) uint8 {
	switch direction {
	case DirectionIngress:
		return DirectionEgress
	case DirectionEgress:
		return DirectionIngress
	default:
		return direction
	}
}
