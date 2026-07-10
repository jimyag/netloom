package dataplane

import (
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

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
	Packets         uint64
	Bytes           uint64
}

type PolicyMapEntry struct {
	Key        PolicyKey
	Value      PolicyEntry
	RemoteCIDR netip.Prefix
}

type PolicyUpdateStats struct {
	Revision  uint64 `json:"revision"`
	Added     int    `json:"added"`
	Updated   int    `json:"updated"`
	Deleted   int    `json:"deleted"`
	Unchanged int    `json:"unchanged"`
}

type PolicyMapUsage struct {
	EndpointID string `json:"endpoint_id"`
	Entries    uint32 `json:"entries"`
	Capacity   uint32 `json:"capacity"`
}

type PolicyMapUsageSummary struct {
	Entries             uint32 `json:"entries"`
	Capacity            uint32 `json:"capacity"`
	MaxPressurePercent  uint32 `json:"max_pressure_percent"`
	MaxPressureEndpoint string `json:"max_pressure_endpoint,omitempty"`
	PressureEndpoints   int    `json:"pressure_endpoints"`
}

const DefaultPolicyMapPressureThresholdPercent = 80

type PolicyMapDrift struct {
	EndpointID string `json:"endpoint_id"`
	Missing    int    `json:"missing"`
	Extra      int    `json:"extra"`
	Changed    int    `json:"changed"`
	Drifted    bool   `json:"drifted"`
}

type PolicyMapDriftSummary struct {
	Endpoints        int `json:"endpoints"`
	DriftedEndpoints int `json:"drifted_endpoints"`
	MissingEntries   int `json:"missing_entries"`
	ExtraEntries     int `json:"extra_entries"`
	ChangedEntries   int `json:"changed_entries"`
}

type PolicyMapOverflowAction string

const (
	PolicyMapOverflowReject PolicyMapOverflowAction = "reject"
	PolicyMapOverflowClear  PolicyMapOverflowAction = "clear"
)

func ParsePolicyMapOverflowAction(value string) (PolicyMapOverflowAction, error) {
	switch action := PolicyMapOverflowAction(strings.TrimSpace(value)); action {
	case "", PolicyMapOverflowReject:
		return PolicyMapOverflowReject, nil
	case PolicyMapOverflowClear:
		return PolicyMapOverflowClear, nil
	default:
		return "", fmt.Errorf("unsupported policy map overflow action %q", value)
	}
}

type PolicyUpdateEvent struct {
	EndpointID       string            `json:"endpoint_id"`
	PreviousRevision uint64            `json:"previous_revision"`
	Revision         uint64            `json:"revision"`
	Stats            PolicyUpdateStats `json:"stats"`
	Success          bool              `json:"success"`
	Error            string            `json:"error,omitempty"`
	Remediated       bool              `json:"remediated,omitempty"`
	Remediation      string            `json:"remediation,omitempty"`
}

type PolicyEndpointStatus struct {
	EndpointID      string            `json:"endpoint_id"`
	Revision        uint64            `json:"revision"`
	Entries         uint32            `json:"entries"`
	Capacity        uint32            `json:"capacity"`
	PressurePercent uint32            `json:"pressure_percent"`
	Drift           PolicyMapDrift    `json:"drift"`
	LastStats       PolicyUpdateStats `json:"last_stats"`
	LastEvent       PolicyUpdateEvent `json:"last_event"`
	HasLastEvent    bool              `json:"has_last_event"`
}

type PolicyUpdatePlan struct {
	Add       []PolicyMapEntry
	Update    []PolicyMapEntry
	Delete    []PolicyKey
	Unchanged []PolicyMapEntry
}

type policyUpdateStep int

const (
	policyUpdateStepAddUpdate policyUpdateStep = iota + 1
	policyUpdateStepDelete
)

type PolicyStore interface {
	ReplaceEndpoint(ctx context.Context, endpointID string, entries []PolicyMapEntry) error
	DeleteEndpoint(ctx context.Context, endpointID string) error
}

type InMemoryPolicyStore struct {
	mu        sync.Mutex
	endpoints map[string][]PolicyMapEntry
	lastStats map[string]PolicyUpdateStats
	lastSeen  map[string]time.Time
	revisions map[string]uint64
	events    []PolicyUpdateEvent
	failAfter int
}

func NewInMemoryPolicyStore() *InMemoryPolicyStore {
	return &InMemoryPolicyStore{
		endpoints: make(map[string][]PolicyMapEntry),
		lastStats: make(map[string]PolicyUpdateStats),
		lastSeen:  make(map[string]time.Time),
		revisions: make(map[string]uint64),
	}
}

func (s *InMemoryPolicyStore) ReplaceEndpoint(_ context.Context, endpointID string, entries []PolicyMapEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	plan := PlanPolicyUpdate(s.endpoints[endpointID], entries)
	next := append([]PolicyMapEntry(nil), s.endpoints[endpointID]...)
	previousRevision := s.revisions[endpointID]
	revision := previousRevision + 1
	applied := 0
	for _, step := range policyUpdateSequence(len(s.endpoints[endpointID]), plan, 0, false) {
		switch step {
		case policyUpdateStepAddUpdate:
			for _, entry := range append(append([]PolicyMapEntry(nil), plan.Add...), plan.Update...) {
				if s.failAfter > 0 && applied >= s.failAfter {
					err := fmt.Errorf("in-memory policy update failed after %d operations", applied)
					s.recordPolicyUpdateFailure(endpointID, previousRevision, revision, plan.Stats(), err)
					return err
				}
				next = upsertEntry(next, entry)
				applied++
			}
		case policyUpdateStepDelete:
			for _, key := range plan.Delete {
				if s.failAfter > 0 && applied >= s.failAfter {
					err := fmt.Errorf("in-memory policy update failed after %d operations", applied)
					s.recordPolicyUpdateFailure(endpointID, previousRevision, revision, plan.Stats(), err)
					return err
				}
				next = deleteEntry(next, key)
				applied++
			}
		}
	}
	stats := plan.Stats()
	stats.Revision = revision
	s.endpoints[endpointID] = canonicalPolicyEntries(next)
	s.revisions[endpointID] = revision
	s.lastStats[endpointID] = stats
	s.lastSeen[endpointID] = time.Now()
	s.events = append(s.events, PolicyUpdateEvent{
		EndpointID:       endpointID,
		PreviousRevision: previousRevision,
		Revision:         revision,
		Stats:            stats,
		Success:          true,
	})
	return nil
}

func (s *InMemoryPolicyStore) recordPolicyUpdateFailure(endpointID string, previousRevision, revision uint64, stats PolicyUpdateStats, err error) {
	stats.Revision = revision
	s.events = append(s.events, PolicyUpdateEvent{
		EndpointID:       endpointID,
		PreviousRevision: previousRevision,
		Revision:         revision,
		Stats:            stats,
		Success:          false,
		Error:            err.Error(),
	})
}

func (s *InMemoryPolicyStore) DeleteEndpoint(_ context.Context, endpointID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deleteEndpointLocked(endpointID)
	return nil
}

func (s *InMemoryPolicyStore) EndpointIDs(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	endpoints := s.policyEndpointIDsLocked()
	ids := make([]string, 0, len(endpoints))
	for endpointID := range endpoints {
		ids = append(ids, endpointID)
	}
	slices.Sort(ids)
	return ids, nil
}

func (s *InMemoryPolicyStore) deleteEndpointLocked(endpointID string) {
	delete(s.endpoints, endpointID)
	delete(s.lastStats, endpointID)
	delete(s.lastSeen, endpointID)
	delete(s.revisions, endpointID)
}

func (s *InMemoryPolicyStore) SweepPolicyEndpoints(ctx context.Context, keep []string, maxIdle time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if maxIdle <= 0 {
		return 0, nil
	}
	keepSet := make(map[string]struct{}, len(keep))
	for _, endpointID := range keep {
		keepSet[endpointID] = struct{}{}
	}
	now := time.Now()
	swept := 0
	for endpointID := range s.policyEndpointIDsLocked() {
		if _, ok := keepSet[endpointID]; ok {
			continue
		}
		lastSeen := s.lastSeen[endpointID]
		if lastSeen.IsZero() {
			lastSeen = now
			s.lastSeen[endpointID] = lastSeen
		}
		if now.Sub(lastSeen) < maxIdle {
			continue
		}
		s.deleteEndpointLocked(endpointID)
		swept++
	}
	return swept, nil
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

func (s *InMemoryPolicyStore) PolicyMapUsage(_ context.Context) ([]PolicyMapUsage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	usages := make([]PolicyMapUsage, 0, len(s.endpoints))
	for endpointID, entries := range s.endpoints {
		usages = append(usages, PolicyMapUsage{
			EndpointID: endpointID,
			Entries:    uint32(len(entries)),
		})
	}
	slices.SortFunc(usages, func(a, b PolicyMapUsage) int {
		return cmp.Compare(a.EndpointID, b.EndpointID)
	})
	return usages, nil
}

func (s *InMemoryPolicyStore) PolicyMapDrift(_ context.Context) ([]PolicyMapDrift, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	endpointIDs := make([]string, 0, len(s.endpoints))
	for endpointID := range s.endpoints {
		endpointIDs = append(endpointIDs, endpointID)
	}
	slices.Sort(endpointIDs)
	reports := make([]PolicyMapDrift, 0, len(endpointIDs))
	for _, endpointID := range endpointIDs {
		entries := s.endpoints[endpointID]
		reports = append(reports, DiffPolicyMapEntries(endpointID, entries, entries))
	}
	return reports, nil
}

func (s *InMemoryPolicyStore) PolicyEndpointStatuses(_ context.Context) ([]PolicyEndpointStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	endpoints := s.policyEndpointIDsLocked()
	endpointIDs := make([]string, 0, len(endpoints))
	for endpointID := range endpoints {
		endpointIDs = append(endpointIDs, endpointID)
	}
	slices.Sort(endpointIDs)
	statuses := make([]PolicyEndpointStatus, 0, len(endpointIDs))
	for _, endpointID := range endpointIDs {
		entries := s.endpoints[endpointID]
		status := PolicyEndpointStatus{
			EndpointID:      endpointID,
			Revision:        s.revisions[endpointID],
			Entries:         uint32(len(entries)),
			Drift:           DiffPolicyMapEntries(endpointID, entries, entries),
			LastStats:       s.lastStats[endpointID],
			PressurePercent: policyMapPressurePercent(PolicyMapUsage{EndpointID: endpointID, Entries: uint32(len(entries))}),
		}
		if event, ok := lastPolicyUpdateEvent(s.events, endpointID); ok {
			status.LastEvent = event
			status.HasLastEvent = true
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func (s *InMemoryPolicyStore) policyEndpointIDsLocked() map[string]struct{} {
	endpoints := make(map[string]struct{}, len(s.endpoints)+len(s.revisions)+len(s.lastStats)+len(s.lastSeen))
	for endpointID := range s.endpoints {
		endpoints[endpointID] = struct{}{}
	}
	for endpointID := range s.revisions {
		endpoints[endpointID] = struct{}{}
	}
	for endpointID := range s.lastStats {
		endpoints[endpointID] = struct{}{}
	}
	for endpointID := range s.lastSeen {
		endpoints[endpointID] = struct{}{}
	}
	return endpoints
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
			RuleCookie:      stableCookie(policyRuleCookieKey(entry)),
			Reject:          boolByte(entry.Value.Reject),
			RequireIdentity: boolByte(entry.Value.RequireIdentity),
		},
	}, nil
}

func policyRuleCookieKey(entry policy.MapEntry) string {
	if entry.RuleRef != "" {
		return entry.RuleRef
	}
	return entry.RuleID
}

func PolicyRuleCookie(value string) uint32 {
	return stableCookie(value)
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

func SummarizePolicyMapUsage(usages []PolicyMapUsage) PolicyMapUsageSummary {
	var summary PolicyMapUsageSummary
	for _, usage := range usages {
		summary.Entries += usage.Entries
		summary.Capacity += usage.Capacity
		pressure := policyMapPressurePercent(usage)
		if pressure > summary.MaxPressurePercent || pressure == summary.MaxPressurePercent && pressure > 0 && (summary.MaxPressureEndpoint == "" || usage.EndpointID < summary.MaxPressureEndpoint) {
			summary.MaxPressurePercent = pressure
			summary.MaxPressureEndpoint = usage.EndpointID
		}
		if pressure >= DefaultPolicyMapPressureThresholdPercent {
			summary.PressureEndpoints++
		}
	}
	return summary
}

func DiffPolicyMapEntries(endpointID string, desired, live []PolicyMapEntry) PolicyMapDrift {
	desiredByKey := entryMap(desired)
	liveByKey := entryMap(live)
	report := PolicyMapDrift{
		EndpointID: endpointID,
	}
	for key, desiredEntry := range desiredByKey {
		liveEntry, ok := liveByKey[key]
		if !ok {
			report.Missing++
			continue
		}
		if !policyEntrySemanticsEqual(liveEntry.Value, desiredEntry.Value) {
			report.Changed++
		}
	}
	for key := range liveByKey {
		if _, ok := desiredByKey[key]; !ok {
			report.Extra++
		}
	}
	report.Drifted = report.Missing != 0 || report.Extra != 0 || report.Changed != 0
	return report
}

func SummarizePolicyMapDrift(reports []PolicyMapDrift) PolicyMapDriftSummary {
	var summary PolicyMapDriftSummary
	for _, report := range reports {
		summary.Endpoints++
		if report.Drifted {
			summary.DriftedEndpoints++
		}
		summary.MissingEntries += report.Missing
		summary.ExtraEntries += report.Extra
		summary.ChangedEntries += report.Changed
	}
	return summary
}

func lastPolicyUpdateEvent(events []PolicyUpdateEvent, endpointID string) (PolicyUpdateEvent, bool) {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].EndpointID == endpointID {
			return events[i], true
		}
	}
	return PolicyUpdateEvent{}, false
}

func policyMapPressurePercent(usage PolicyMapUsage) uint32 {
	if usage.Capacity == 0 {
		return 0
	}
	if usage.Entries >= usage.Capacity {
		return 100
	}
	return uint32((uint64(usage.Entries) * 100) / uint64(usage.Capacity))
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

func policyUpdateSequence(oldEntryCount int, plan PolicyUpdatePlan, maxEntries uint32, fullRewrite bool) []policyUpdateStep {
	if fullRewrite {
		return []policyUpdateStep{policyUpdateStepAddUpdate}
	}
	if maxEntries == 0 || oldEntryCount+len(plan.Add) <= int(maxEntries) {
		return []policyUpdateStep{policyUpdateStepAddUpdate, policyUpdateStepDelete}
	}
	return []policyUpdateStep{policyUpdateStepDelete, policyUpdateStepAddUpdate}
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
