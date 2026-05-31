package dataplane

import (
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
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
	Deny            uint8
	L4PrefixLen     uint8
	Stateful        uint8
	Log             uint8
	Precedence      uint32
	RuleCookie      uint32
	Reject          uint8
	RequireIdentity uint8
}

type PolicyMapEntry struct {
	Key        PolicyKey
	Value      PolicyEntry
	RemoteCIDR netip.Prefix
}

type PolicyUpdateStats struct {
	Revision  uint64
	Added     int
	Updated   int
	Deleted   int
	Unchanged int
}

type PolicyUpdateEvent struct {
	EndpointID string
	Revision   uint64
	Stats      PolicyUpdateStats
}

type PolicyUpdatePlan struct {
	Add       []PolicyMapEntry
	Update    []PolicyMapEntry
	Delete    []PolicyKey
	Unchanged []PolicyMapEntry
}

type PolicyStore interface {
	ReplaceEndpoint(ctx context.Context, endpointID string, entries []PolicyMapEntry) error
	DeleteEndpoint(ctx context.Context, endpointID string) error
}

type InMemoryPolicyStore struct {
	mu        sync.Mutex
	endpoints map[string][]PolicyMapEntry
	lastStats map[string]PolicyUpdateStats
	revisions map[string]uint64
	events    []PolicyUpdateEvent
	failAfter int
}

func NewInMemoryPolicyStore() *InMemoryPolicyStore {
	return &InMemoryPolicyStore{
		endpoints: make(map[string][]PolicyMapEntry),
		lastStats: make(map[string]PolicyUpdateStats),
		revisions: make(map[string]uint64),
	}
}

func (s *InMemoryPolicyStore) ReplaceEndpoint(_ context.Context, endpointID string, entries []PolicyMapEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	plan := PlanPolicyUpdate(s.endpoints[endpointID], entries)
	next := append([]PolicyMapEntry(nil), s.endpoints[endpointID]...)
	applied := 0
	for _, key := range plan.Delete {
		if s.failAfter > 0 && applied >= s.failAfter {
			return fmt.Errorf("in-memory policy update failed after %d operations", applied)
		}
		next = deleteEntry(next, key)
		applied++
	}
	for _, entry := range append(append([]PolicyMapEntry(nil), plan.Add...), plan.Update...) {
		if s.failAfter > 0 && applied >= s.failAfter {
			return fmt.Errorf("in-memory policy update failed after %d operations", applied)
		}
		next = upsertEntry(next, entry)
		applied++
	}
	revision := s.revisions[endpointID] + 1
	stats := plan.Stats()
	stats.Revision = revision
	s.endpoints[endpointID] = canonicalPolicyEntries(next)
	s.revisions[endpointID] = revision
	s.lastStats[endpointID] = stats
	s.events = append(s.events, PolicyUpdateEvent{
		EndpointID: endpointID,
		Revision:   revision,
		Stats:      stats,
	})
	return nil
}

func (s *InMemoryPolicyStore) DeleteEndpoint(_ context.Context, endpointID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.endpoints, endpointID)
	delete(s.lastStats, endpointID)
	delete(s.revisions, endpointID)
	return nil
}

func (s *InMemoryPolicyStore) Entries(endpointID string) []PolicyMapEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]PolicyMapEntry(nil), s.endpoints[endpointID]...)
}

func (s *InMemoryPolicyStore) LastStats(endpointID string) PolicyUpdateStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastStats[endpointID]
}

func (s *InMemoryPolicyStore) Revision(endpointID string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revisions[endpointID]
}

func (s *InMemoryPolicyStore) Events() []PolicyUpdateEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]PolicyUpdateEvent(nil), s.events...)
}

func (s *InMemoryPolicyStore) SetFailAfter(operations int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failAfter = operations
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
	return canonicalPolicyMapEntries(entries)
}

func EncodeEntry(entry policy.MapEntry) (PolicyMapEntry, error) {
	proto, err := protocolNumberForEntry(entry)
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
		RemoteCIDR: entry.RemoteCIDR,
		Value: PolicyEntry{
			Deny:            boolByte(entry.Value.Deny),
			L4PrefixLen:     entry.Key.L4PrefixBits,
			Stateful:        boolByte(entry.Value.Stateful),
			Log:             boolByte(entry.Value.Log),
			Precedence:      entry.Value.Precedence,
			RuleCookie:      stableCookie(entry.RuleID),
			Reject:          boolByte(entry.Value.Reject),
			RequireIdentity: boolByte(entry.Value.RequireIdentity),
		},
	}, nil
}

func protocolNumberForEntry(entry policy.MapEntry) (uint8, error) {
	if entry.Key.Protocol == model.ProtocolICMP && entry.RemoteCIDR.IsValid() && entry.RemoteCIDR.Addr().Is6() && !entry.RemoteCIDR.Addr().Is4() {
		return 58, nil
	}
	return protocolNumber(entry.Key.Protocol)
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

func canonicalPolicyMapEntries(entries []PolicyMapEntry) ([]PolicyMapEntry, error) {
	byKey := make(map[PolicyKey]PolicyMapEntry, len(entries))
	for _, entry := range entries {
		existing, ok := byKey[entry.Key]
		if !ok || betterPolicyMapEntry(entry, existing) {
			if ok && entry.RemoteCIDR != existing.RemoteCIDR {
				return nil, fmt.Errorf("conflicting policy map entries for identical key and remote cidr metadata")
			}
			byKey[entry.Key] = entry
			continue
		}
		if entry.RemoteCIDR != existing.RemoteCIDR {
			return nil, fmt.Errorf("conflicting policy map entries for identical key and remote cidr metadata")
		}
		if samePolicyMapPriority(entry, existing) && entry.Value != existing.Value {
			return nil, fmt.Errorf("conflicting policy map entries for identical key")
		}
	}
	out := make([]PolicyMapEntry, 0, len(byKey))
	for _, entry := range byKey {
		out = append(out, entry)
	}
	sortEntries(out)
	return out, nil
}

func betterPolicyMapEntry(candidate, selected PolicyMapEntry) bool {
	if candidate.Value.Precedence != selected.Value.Precedence {
		return candidate.Value.Precedence > selected.Value.Precedence
	}
	if candidate.Value.L4PrefixLen != selected.Value.L4PrefixLen {
		return candidate.Value.L4PrefixLen > selected.Value.L4PrefixLen
	}
	return false
}

func samePolicyMapPriority(left, right PolicyMapEntry) bool {
	return left.Value.Precedence == right.Value.Precedence &&
		left.Value.L4PrefixLen == right.Value.L4PrefixLen
}

func PlanPolicyUpdate(oldEntries, newEntries []PolicyMapEntry) PolicyUpdatePlan {
	oldByKey := entryMap(oldEntries)
	newByKey := entryMap(newEntries)
	var plan PolicyUpdatePlan
	for key, oldEntry := range oldByKey {
		newEntry, ok := newByKey[key]
		if !ok {
			plan.Delete = append(plan.Delete, key)
			continue
		}
		if oldEntry.Value == newEntry.Value && oldEntry.RemoteCIDR == newEntry.RemoteCIDR {
			plan.Unchanged = append(plan.Unchanged, newEntry)
		} else {
			plan.Update = append(plan.Update, newEntry)
		}
	}
	for key, newEntry := range newByKey {
		if _, ok := oldByKey[key]; !ok {
			plan.Add = append(plan.Add, newEntry)
		}
	}
	sortPlan(&plan)
	return plan
}

func (p PolicyUpdatePlan) Stats() PolicyUpdateStats {
	return PolicyUpdateStats{
		Added:     len(p.Add),
		Updated:   len(p.Update),
		Deleted:   len(p.Delete),
		Unchanged: len(p.Unchanged),
	}
}

func entryMap(entries []PolicyMapEntry) map[PolicyKey]PolicyMapEntry {
	out := make(map[PolicyKey]PolicyMapEntry, len(entries))
	for _, entry := range entries {
		out[entry.Key] = entry
	}
	return out
}

func sortPlan(plan *PolicyUpdatePlan) {
	sortEntries(plan.Add)
	sortEntries(plan.Update)
	sortEntries(plan.Unchanged)
	sortKeys(plan.Delete)
}

func canonicalPolicyEntries(entries []PolicyMapEntry) []PolicyMapEntry {
	out := append([]PolicyMapEntry(nil), entries...)
	sortEntries(out)
	return out
}

func sortEntries(entries []PolicyMapEntry) {
	slices.SortFunc(entries, func(a, b PolicyMapEntry) int {
		return comparePolicyKey(a.Key, b.Key)
	})
}

func sortKeys(keys []PolicyKey) {
	slices.SortFunc(keys, comparePolicyKey)
}

func comparePolicyKey(a, b PolicyKey) int {
	switch {
	case a.PrefixLen != b.PrefixLen:
		return cmp.Compare(a.PrefixLen, b.PrefixLen)
	case a.RemoteIdentity != b.RemoteIdentity:
		return cmp.Compare(a.RemoteIdentity, b.RemoteIdentity)
	case a.Direction != b.Direction:
		return cmp.Compare(a.Direction, b.Direction)
	case a.Protocol != b.Protocol:
		return cmp.Compare(a.Protocol, b.Protocol)
	default:
		return cmp.Compare(a.DestPortBE, b.DestPortBE)
	}
}

func deleteEntry(entries []PolicyMapEntry, key PolicyKey) []PolicyMapEntry {
	out := entries[:0]
	for _, entry := range entries {
		if entry.Key != key {
			out = append(out, entry)
		}
	}
	return out
}

func upsertEntry(entries []PolicyMapEntry, entry PolicyMapEntry) []PolicyMapEntry {
	for i := range entries {
		if entries[i].Key == entry.Key {
			entries[i] = entry
			return entries
		}
	}
	return append(entries, entry)
}
