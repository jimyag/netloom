package dataplane

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
)

const (
	DirectionIngress = uint8(1)
	DirectionEgress  = uint8(2)

	StaticPrefixBits = uint32(40)
)

type PolicyKey struct {
	PrefixLen      uint32
	RemoteIdentity uint32
	Direction      uint8
	Protocol       uint8
	DestPortBE     uint16
}

type PolicyEntry struct {
	Deny        uint8
	L4PrefixLen uint8
	Stateful    uint8
	Log         uint8
	Precedence  uint32
	RuleCookie  uint32
}

type PolicyMapEntry struct {
	Key   PolicyKey
	Value PolicyEntry
}

type PolicyStore interface {
	ReplaceEndpoint(ctx context.Context, endpointID string, entries []PolicyMapEntry) error
}

type InMemoryPolicyStore struct {
	mu        sync.Mutex
	endpoints map[string][]PolicyMapEntry
}

func NewInMemoryPolicyStore() *InMemoryPolicyStore {
	return &InMemoryPolicyStore{endpoints: make(map[string][]PolicyMapEntry)}
}

func (s *InMemoryPolicyStore) ReplaceEndpoint(_ context.Context, endpointID string, entries []PolicyMapEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	copied := append([]PolicyMapEntry(nil), entries...)
	s.endpoints[endpointID] = copied
	return nil
}

func (s *InMemoryPolicyStore) Entries(endpointID string) []PolicyMapEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]PolicyMapEntry(nil), s.endpoints[endpointID]...)
}

type PolicyBackend struct {
	store PolicyStore
}

func NewPolicyBackend(store PolicyStore) *PolicyBackend {
	return &PolicyBackend{store: store}
}

func (b *PolicyBackend) ApplyEndpointProgram(ctx context.Context, program policy.Program) error {
	entries, err := EncodeProgram(program)
	if err != nil {
		return err
	}
	return b.store.ReplaceEndpoint(ctx, program.EndpointID, entries)
}

func EncodeProgram(program policy.Program) ([]PolicyMapEntry, error) {
	entries := make([]PolicyMapEntry, 0, len(program.MapEntries))
	for _, entry := range program.MapEntries {
		encoded, err := EncodeEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", entry.RuleID, err)
		}
		entries = append(entries, encoded)
	}
	return entries, nil
}

func EncodeEntry(entry policy.MapEntry) (PolicyMapEntry, error) {
	proto, err := protocolNumber(entry.Key.Protocol)
	if err != nil {
		return PolicyMapEntry{}, err
	}
	direction, err := directionNumber(entry.Key.Direction)
	if err != nil {
		return PolicyMapEntry{}, err
	}

	return PolicyMapEntry{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits + uint32(entry.Key.L4PrefixBits),
			RemoteIdentity: entry.Key.RemoteIdentity,
			Direction:      direction,
			Protocol:       proto,
			DestPortBE:     hostToNetwork16(entry.Key.DestPort),
		},
		Value: PolicyEntry{
			Deny:        boolByte(entry.Value.Deny),
			L4PrefixLen: entry.Key.L4PrefixBits,
			Stateful:    boolByte(entry.Value.Stateful),
			Log:         boolByte(entry.Value.Log),
			Precedence:  entry.Value.Precedence,
			RuleCookie:  stableCookie(entry.RuleID),
		},
	}, nil
}

func protocolNumber(protocol model.Protocol) (uint8, error) {
	switch protocol {
	case "", model.ProtocolAny:
		return 0, nil
	case model.ProtocolTCP:
		return 6, nil
	case model.ProtocolUDP:
		return 17, nil
	case model.ProtocolICMP:
		return 1, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q", protocol)
	}
}

func directionNumber(direction model.Direction) (uint8, error) {
	switch direction {
	case model.DirectionIngress:
		return DirectionIngress, nil
	case model.DirectionEgress:
		return DirectionEgress, nil
	default:
		return 0, fmt.Errorf("unsupported direction %q", direction)
	}
}

func hostToNetwork16(value uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], value)
	return binary.NativeEndian.Uint16(b[:])
}

func boolByte(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

func stableCookie(value string) uint32 {
	var out uint32 = 2166136261
	for _, b := range []byte(value) {
		out ^= uint32(b)
		out *= 16777619
	}
	return out
}
