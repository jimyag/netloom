package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const defaultPolicyMapMaxEntries = 16 * 1024
const defaultPolicyMapSchemaVersion = 2
const policyMapMetaFileSuffix = ".meta"

type EBPFPolicyStoreConfig struct {
	MaxEntries    uint32
	PinRoot       string
	MetadataRoot  string
	SchemaVersion uint32
}

type policyMapMetadata struct {
	EndpointID    string `json:"endpoint_id,omitempty"`
	SchemaVersion uint32 `json:"schema_version"`
	MaxEntries    uint32 `json:"max_entries"`
}

type EBPFPolicyStore struct {
	mu           sync.Mutex
	maxEntries   uint32
	pinRoot      string
	metadataRoot string
	schema       uint32
	maps         map[string]*ebpf.Map
	entries      map[string][]PolicyMapEntry
	lastStats    map[string]PolicyUpdateStats
	revisions    map[string]uint64
	events       []PolicyUpdateEvent
}

func NewEBPFPolicyStore(maxEntries uint32) *EBPFPolicyStore {
	return NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{MaxEntries: maxEntries})
}

func NewEBPFPolicyStoreWithConfig(cfg EBPFPolicyStoreConfig) *EBPFPolicyStore {
	maxEntries := cfg.MaxEntries
	if maxEntries == 0 {
		maxEntries = defaultPolicyMapMaxEntries
	}
	schema := cfg.SchemaVersion
	if schema == 0 {
		schema = defaultPolicyMapSchemaVersion
	}
	pinRoot := strings.TrimSpace(cfg.PinRoot)
	if pinRoot != "" {
		pinRoot = filepath.Clean(pinRoot)
	}
	metadataRoot := strings.TrimSpace(cfg.MetadataRoot)
	if metadataRoot != "" {
		metadataRoot = filepath.Clean(metadataRoot)
	}
	return &EBPFPolicyStore{
		maxEntries:   maxEntries,
		pinRoot:      pinRoot,
		metadataRoot: metadataRoot,
		schema:       schema,
		maps:         make(map[string]*ebpf.Map),
		entries:      make(map[string][]PolicyMapEntry),
		lastStats:    make(map[string]PolicyUpdateStats),
		revisions:    make(map[string]uint64),
	}
}

func (s *EBPFPolicyStore) ReplaceEndpoint(ctx context.Context, endpointID string, entries []PolicyMapEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if endpointID == "" {
		return fmt.Errorf("endpoint id is required")
	}
	plan := PlanPolicyUpdate(s.entries[endpointID], entries)
	previousRevision := s.revisions[endpointID]
	revision := previousRevision + 1
	if err := s.validatePolicyMapCapacity(endpointID, entries); err != nil {
		s.recordPolicyUpdateFailure(endpointID, previousRevision, revision, plan.Stats(), err)
		return err
	}

	next, err := s.preparePolicyMapLocked(ctx, endpointID, entries, s.entries[endpointID], plan)
	if err != nil {
		err = fmt.Errorf("prepare eBPF policy map for endpoint %s: %w", endpointID, err)
		s.recordPolicyUpdateFailure(endpointID, previousRevision, revision, plan.Stats(), err)
		return err
	}

	old := s.maps[endpointID]
	stats := plan.Stats()
	stats.Revision = revision
	s.maps[endpointID] = next
	s.entries[endpointID] = canonicalPolicyEntries(entries)
	s.revisions[endpointID] = revision
	s.lastStats[endpointID] = stats
	s.events = append(s.events, PolicyUpdateEvent{
		EndpointID:       endpointID,
		PreviousRevision: previousRevision,
		Revision:         revision,
		Stats:            stats,
		Success:          true,
	})
	if old != nil && old != next {
		old.Close()
	}
	return nil
}

func (s *EBPFPolicyStore) preparePolicyMapLocked(ctx context.Context, endpointID string, nextEntries, oldEntries []PolicyMapEntry, plan PolicyUpdatePlan) (*ebpf.Map, error) {
	if s.pinRoot == "" {
		return s.createTransientPolicyMap(ctx, endpointID, nextEntries)
	}
	if err := s.ensurePinRoot(); err != nil {
		return nil, err
	}
	path := s.pinnedPolicyMapPath(endpointID)
	metadataPath := s.pinnedPolicyMapMetadataPath(endpointID)
	m := s.maps[endpointID]
	expected := s.policyMapSpec()
	reloaded := false

	if m == nil {
		loaded, err := s.loadPinnedPolicyMap(endpointID, path, metadataPath, expected)
		if err != nil {
			if err := s.migratePinnedMap(endpointID, path, metadataPath); err != nil {
				return nil, err
			}
			loaded = nil
		}
		if loaded == nil {
			newMap, err := s.createPinnedPolicyMap(ctx, endpointID, path, metadataPath, expected)
			if err != nil {
				return nil, err
			}
			if err := s.populatePolicyMap(ctx, newMap, nextEntries); err != nil {
				_ = s.removePinnedMap(newMap, path, metadataPath)
				newMap.Close()
				return nil, err
			}
			return newMap, nil
		}
		m = loaded
		reloaded = true
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !reloaded && len(oldEntries) > 0 {
		drifted, err := s.policyMapDrifted(m, nextEntries)
		if err != nil {
			return nil, fmt.Errorf("inspect eBPF policy map for endpoint %s: %w", endpointID, err)
		}
		if drifted {
			if err := s.clearMap(m); err != nil {
				return nil, fmt.Errorf("clear drifted eBPF policy map for endpoint %s: %w", endpointID, err)
			}
			if err := s.populatePolicyMap(ctx, m, nextEntries); err != nil {
				return nil, fmt.Errorf("rewrite drifted eBPF policy map for endpoint %s: %w", endpointID, err)
			}
			return m, nil
		}
	}
	if reloaded || len(oldEntries) == 0 {
		if err := s.clearMap(m); err != nil {
			return nil, fmt.Errorf("clear stale eBPF policy map for endpoint %s: %w", endpointID, err)
		}
	}
	for _, step := range policyUpdateSequence(len(oldEntries), plan, s.maxEntries, reloaded || len(oldEntries) == 0) {
		switch step {
		case policyUpdateStepAddUpdate:
			for _, entry := range append([]PolicyMapEntry(nil), append(plan.Add, plan.Update...)...) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if err := m.Put(&entry.Key, &entry.Value); err != nil {
					return nil, fmt.Errorf("write eBPF policy map for endpoint %s: %w", endpointID, err)
				}
			}
		case policyUpdateStepDelete:
			for _, key := range plan.Delete {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if err := m.Delete(key); err != nil {
					return nil, fmt.Errorf("delete eBPF policy map key for endpoint %s: %w", endpointID, err)
				}
			}
		}
	}
	return m, nil
}

func (s *EBPFPolicyStore) createTransientPolicyMap(ctx context.Context, endpointID string, entries []PolicyMapEntry) (*ebpf.Map, error) {
	next, err := ebpf.NewMap(s.policyMapSpec())
	if err != nil {
		return nil, fmt.Errorf("create eBPF policy map for endpoint %s: %w", endpointID, err)
	}
	if err := s.populatePolicyMap(ctx, next, entries); err != nil {
		next.Close()
		return nil, fmt.Errorf("write eBPF policy map for endpoint %s: %w", endpointID, err)
	}
	return next, nil
}

func (s *EBPFPolicyStore) createPinnedPolicyMap(ctx context.Context, endpointID, mapPath, metadataPath string, spec *ebpf.MapSpec) (*ebpf.Map, error) {
	if err := os.Remove(mapPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale pinned map for endpoint %s: %w", endpointID, err)
	}
	if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale pinned policy metadata for endpoint %s: %w", endpointID, err)
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, fmt.Errorf("create eBPF policy map for endpoint %s: %w", endpointID, err)
	}
	if err := m.Pin(mapPath); err != nil {
		m.Close()
		return nil, fmt.Errorf("pin eBPF policy map for endpoint %s to %s: %w", endpointID, mapPath, err)
	}
	if err := s.writeMapMetadata(metadataPath, endpointID); err != nil {
		_ = s.removePinnedMap(m, mapPath, metadataPath)
		m.Close()
		return nil, err
	}
	return m, nil
}

func (s *EBPFPolicyStore) loadPinnedPolicyMap(endpointID, mapPath, metadataPath string, expectedSpec *ebpf.MapSpec) (*ebpf.Map, error) {
	if _, err := os.Stat(mapPath); os.IsNotExist(err) {
		return nil, nil
	}
	m, err := ebpf.LoadPinnedMap(mapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return nil, fmt.Errorf("load pinned eBPF policy map from %s: %w", mapPath, err)
	}
	if err := s.validatePinnedMap(m, endpointID, expectedSpec, metadataPath); err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}

func (s *EBPFPolicyStore) migratePinnedMap(endpointID, mapPath, metadataPath string) error {
	if err := s.removePinnedMap(nil, mapPath, metadataPath); err != nil {
		return fmt.Errorf("migrate pinned policy map for endpoint %s: %w", endpointID, err)
	}
	return nil
}

func (s *EBPFPolicyStore) validatePinnedMap(m *ebpf.Map, endpointID string, expectedSpec *ebpf.MapSpec, metadataPath string) error {
	info, err := m.Info()
	if err != nil {
		return fmt.Errorf("read eBPF policy map metadata: %w", err)
	}
	if info.Type != expectedSpec.Type || info.KeySize != expectedSpec.KeySize || info.ValueSize != expectedSpec.ValueSize || info.MaxEntries != expectedSpec.MaxEntries || info.Flags != expectedSpec.Flags {
		return fmt.Errorf("pinned eBPF map schema mismatch")
	}
	metadata, err := s.loadMapMetadata(metadataPath)
	if err != nil {
		return fmt.Errorf("load pinned policy map metadata from %s: %w", metadataPath, err)
	}
	if metadata.SchemaVersion != s.schema || metadata.MaxEntries != expectedSpec.MaxEntries {
		return fmt.Errorf("pinned eBPF map schema migration required")
	}
	if metadata.EndpointID != "" && metadata.EndpointID != endpointID {
		return fmt.Errorf("pinned eBPF map endpoint identity mismatch")
	}
	return nil
}

func (s *EBPFPolicyStore) writeMapMetadata(path, endpointID string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create policy map metadata root for %s: %w", path, err)
	}
	metadata := policyMapMetadata{
		EndpointID:    endpointID,
		SchemaVersion: s.schema,
		MaxEntries:    s.maxEntries,
	}
	payload, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("encode policy map metadata for %s: %w", path, err)
	}
	if err := os.WriteFile(path, payload, 0600); err != nil {
		return fmt.Errorf("write policy map metadata to %s: %w", path, err)
	}
	return nil
}

func (s *EBPFPolicyStore) loadMapMetadata(path string) (*policyMapMetadata, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("missing metadata: %w", err)
		}
		return nil, err
	}
	var metadata policyMapMetadata
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return nil, fmt.Errorf("decode policy map metadata from %s: %w", path, err)
	}
	return &metadata, nil
}

func (s *EBPFPolicyStore) removePinnedMap(m *ebpf.Map, mapPath, metadataPath string) error {
	var firstErr error
	if m != nil {
		if err := m.Unpin(); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = fmt.Errorf("unpin eBPF policy map %s: %w", mapPath, err)
		}
	}
	if m != nil {
		if err := m.Close(); err != nil {
			firstErr = fmt.Errorf("close eBPF policy map %s: %w", mapPath, err)
		}
	}
	if err := os.Remove(mapPath); err != nil && !os.IsNotExist(err) && firstErr == nil {
		firstErr = fmt.Errorf("unpin eBPF policy map %s: %w", mapPath, err)
	}
	if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) && firstErr == nil {
		firstErr = fmt.Errorf("remove policy map metadata %s: %w", metadataPath, err)
	}
	return firstErr
}

func (s *EBPFPolicyStore) populatePolicyMap(ctx context.Context, m *ebpf.Map, entries []PolicyMapEntry) error {
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := m.Put(&entry.Key, &entry.Value); err != nil {
			return err
		}
	}
	return nil
}

func (s *EBPFPolicyStore) clearMap(m *ebpf.Map) error {
	iter := m.Iterate()
	var key PolicyKey
	var value PolicyEntry
	for iter.Next(&key, &value) {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	return nil
}

func (s *EBPFPolicyStore) policyMapDrifted(m *ebpf.Map, desired []PolicyMapEntry) (bool, error) {
	actual, err := s.readPolicyMapEntries(m)
	if err != nil {
		return false, err
	}
	actualByKey := make(map[PolicyKey]PolicyEntry, len(actual))
	for _, entry := range actual {
		actualByKey[entry.Key] = entry.Value
	}
	desiredByKey := make(map[PolicyKey]PolicyEntry, len(desired))
	for _, entry := range desired {
		desiredByKey[entry.Key] = entry.Value
	}
	if len(actualByKey) != len(desiredByKey) {
		return true, nil
	}
	for key, desiredValue := range desiredByKey {
		actualValue, ok := actualByKey[key]
		if !ok || !policyEntrySemanticsEqual(actualValue, desiredValue) {
			return true, nil
		}
	}
	return false, nil
}

func policyEntrySemanticsEqual(left, right PolicyEntry) bool {
	left.Packets = 0
	left.Bytes = 0
	right.Packets = 0
	right.Bytes = 0
	return left == right
}

func (s *EBPFPolicyStore) readPolicyMapEntries(m *ebpf.Map) ([]PolicyMapEntry, error) {
	iter := m.Iterate()
	var (
		key   PolicyKey
		value PolicyEntry
	)
	entries := make([]PolicyMapEntry, 0)
	for iter.Next(&key, &value) {
		entries = append(entries, PolicyMapEntry{Key: key, Value: value})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *EBPFPolicyStore) policyMapSpec() *ebpf.MapSpec {
	valueSize := uint32(binary.Size(PolicyEntry{}))
	if valueSize <= 0 {
		return nil
	}
	return &ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		KeySize:    uint32(unsafe.Sizeof(PolicyKey{})),
		ValueSize:  valueSize,
		MaxEntries: s.maxEntries,
		Flags:      unix.BPF_F_NO_PREALLOC,
	}
}

func (s *EBPFPolicyStore) pinnedPolicyMapPath(endpointID string) string {
	return filepath.Join(s.pinRoot, mapName(endpointID))
}

func (s *EBPFPolicyStore) pinnedPolicyMapMetadataPath(endpointID string) string {
	if s.metadataRoot != "" {
		return filepath.Join(s.metadataRoot, mapName(endpointID)+policyMapMetaFileSuffix)
	}
	return s.pinnedPolicyMapPath(endpointID) + policyMapMetaFileSuffix
}

func (s *EBPFPolicyStore) ensurePinRoot() error {
	if s.pinRoot == "" {
		return nil
	}
	if err := os.MkdirAll(s.pinRoot, 0o755); err != nil {
		return fmt.Errorf("create eBPF map pin root %s: %w", s.pinRoot, err)
	}
	return nil
}

func (s *EBPFPolicyStore) recordPolicyUpdateFailure(endpointID string, previousRevision, revision uint64, stats PolicyUpdateStats, err error) {
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

func (s *EBPFPolicyStore) DeleteEndpoint(ctx context.Context, endpointID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if endpointID == "" {
		return fmt.Errorf("endpoint id is required")
	}
	if s.pinRoot != "" {
		if err := s.removePinnedMap(nil, s.pinnedPolicyMapPath(endpointID), s.pinnedPolicyMapMetadataPath(endpointID)); err != nil {
			return fmt.Errorf("remove pinned eBPF map for endpoint %s: %w", endpointID, err)
		}
	}
	if m := s.maps[endpointID]; m != nil {
		if err := m.Close(); err != nil {
			return fmt.Errorf("close eBPF policy map for endpoint %s: %w", endpointID, err)
		}
	}
	delete(s.maps, endpointID)
	delete(s.entries, endpointID)
	delete(s.lastStats, endpointID)
	delete(s.revisions, endpointID)
	return nil
}

func (s *EBPFPolicyStore) LastStats(endpointID string) PolicyUpdateStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastStats[endpointID]
}

func (s *EBPFPolicyStore) EndpointIDs(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.managedEndpointIDsLocked()
}

func (s *EBPFPolicyStore) Revision(endpointID string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revisions[endpointID]
}

func (s *EBPFPolicyStore) Events() []PolicyUpdateEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]PolicyUpdateEvent(nil), s.events...)
}

func (s *EBPFPolicyStore) PolicyMapUsage(_ context.Context) ([]PolicyMapUsage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	endpointIDs, err := s.managedEndpointIDsLocked()
	if err != nil {
		return nil, err
	}
	usages := make([]PolicyMapUsage, 0, len(endpointIDs))
	for _, endpointID := range endpointIDs {
		count, err := s.policyMapEntryCountLocked(endpointID)
		if err != nil {
			return nil, fmt.Errorf("read policy map usage for endpoint %s: %w", endpointID, err)
		}
		usages = append(usages, PolicyMapUsage{
			EndpointID: endpointID,
			Entries:    count,
			Capacity:   s.maxEntries,
		})
	}
	sort.Slice(usages, func(i, j int) bool {
		return usages[i].EndpointID < usages[j].EndpointID
	})
	return usages, nil
}

func (s *EBPFPolicyStore) PolicyMapDrift(ctx context.Context) ([]PolicyMapDrift, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	endpointIDs, err := s.managedEndpointIDsLocked()
	if err != nil {
		return nil, err
	}
	reports := make([]PolicyMapDrift, 0, len(endpointIDs))
	for _, endpointID := range endpointIDs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		live, err := s.policyMapEntriesLocked(endpointID)
		if err != nil {
			return nil, fmt.Errorf("read policy map drift for endpoint %s: %w", endpointID, err)
		}
		reports = append(reports, DiffPolicyMapEntries(endpointID, s.entries[endpointID], live))
	}
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].EndpointID < reports[j].EndpointID
	})
	return reports, nil
}

func (s *EBPFPolicyStore) PolicyRuleMetrics(ctx context.Context) ([]RuleMetrics, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	endpointIDs, err := s.managedEndpointIDsLocked()
	if err != nil {
		return nil, err
	}
	out := make([]RuleMetrics, 0)
	for _, endpointID := range endpointIDs {
		entries, err := s.policyMapEntriesLocked(endpointID)
		if err != nil {
			return nil, fmt.Errorf("read policy rule metrics for endpoint %s: %w", endpointID, err)
		}
		for _, entry := range entries {
			out = append(out, policyRuleMetricsFromEntry(endpointID, entry))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EndpointID != out[j].EndpointID {
			return out[i].EndpointID < out[j].EndpointID
		}
		return out[i].RuleCookie < out[j].RuleCookie
	})
	return out, nil
}

func (s *EBPFPolicyStore) managedEndpointIDsLocked() ([]string, error) {
	endpoints := make(map[string]struct{}, len(s.maps)+len(s.entries))
	for endpointID := range s.maps {
		endpoints[endpointID] = struct{}{}
	}
	for endpointID := range s.entries {
		endpoints[endpointID] = struct{}{}
	}
	metadataRoot := s.policyMapMetadataRoot()
	if metadataRoot != "" {
		entries, err := os.ReadDir(metadataRoot)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("list eBPF policy metadata root %s: %w", metadataRoot, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), policyMapMetaFileSuffix) {
				continue
			}
			metadata, err := s.loadMapMetadata(filepath.Join(metadataRoot, entry.Name()))
			if err != nil || metadata.EndpointID == "" {
				continue
			}
			endpoints[metadata.EndpointID] = struct{}{}
		}
	}
	ids := make([]string, 0, len(endpoints))
	for endpointID := range endpoints {
		ids = append(ids, endpointID)
	}
	sort.Strings(ids)
	return ids, nil
}

func (s *EBPFPolicyStore) policyMapEntryCountLocked(endpointID string) (uint32, error) {
	entries, err := s.policyMapEntriesLocked(endpointID)
	if err != nil {
		return 0, err
	}
	return uint32(len(entries)), nil
}

func (s *EBPFPolicyStore) policyMapEntriesLocked(endpointID string) ([]PolicyMapEntry, error) {
	if m := s.maps[endpointID]; m != nil {
		return s.readPolicyMapEntries(m)
	}
	if s.pinRoot != "" {
		loaded, err := s.loadPinnedPolicyMap(endpointID, s.pinnedPolicyMapPath(endpointID), s.pinnedPolicyMapMetadataPath(endpointID), s.policyMapSpec())
		if err != nil {
			return nil, err
		}
		if loaded != nil {
			defer loaded.Close()
			return s.readPolicyMapEntries(loaded)
		}
	}
	return append([]PolicyMapEntry(nil), s.entries[endpointID]...), nil
}

func policyRuleMetricsFromEntry(endpointID string, entry PolicyMapEntry) RuleMetrics {
	metrics := RuleMetrics{
		EndpointID: endpointID,
		RuleCookie: entry.Value.RuleCookie,
		Packets:    entry.Value.Packets,
		Bytes:      entry.Value.Bytes,
	}
	switch {
	case entry.Value.Reject != 0:
		metrics.Dropped = entry.Value.Packets
		metrics.Rejected = entry.Value.Packets
		metrics.RejectDrops = entry.Value.Packets
	case entry.Value.Deny != 0:
		metrics.Dropped = entry.Value.Packets
		metrics.DenyDrops = entry.Value.Packets
	default:
		metrics.Allowed = entry.Value.Packets
	}
	if entry.Value.Log != 0 {
		metrics.Logged = entry.Value.Packets
	}
	return metrics
}

func (s *EBPFPolicyStore) policyMapMetadataRoot() string {
	if s.metadataRoot != "" {
		return s.metadataRoot
	}
	return s.pinRoot
}

func (s *EBPFPolicyStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error
	for endpointID, m := range s.maps {
		if err := m.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close eBPF policy map for endpoint %s: %w", endpointID, err)
		}
		delete(s.maps, endpointID)
		delete(s.entries, endpointID)
		delete(s.lastStats, endpointID)
		delete(s.revisions, endpointID)
	}
	return firstErr
}

func mapName(endpointID string) string {
	const prefix = "nlp"
	sum := sha256.Sum256([]byte(endpointID))
	return prefix + hex.EncodeToString(sum[:])[:12]
}
