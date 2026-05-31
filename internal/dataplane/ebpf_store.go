package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const defaultPolicyMapMaxEntries = 16 * 1024

type EBPFPolicyStore struct {
	mu         sync.Mutex
	maxEntries uint32
	maps       map[string]*ebpf.Map
	entries    map[string][]PolicyMapEntry
	lastStats  map[string]PolicyUpdateStats
	revisions  map[string]uint64
	events     []PolicyUpdateEvent
}

func NewEBPFPolicyStore(maxEntries uint32) *EBPFPolicyStore {
	if maxEntries == 0 {
		maxEntries = defaultPolicyMapMaxEntries
	}
	return &EBPFPolicyStore{
		maxEntries: maxEntries,
		maps:       make(map[string]*ebpf.Map),
		entries:    make(map[string][]PolicyMapEntry),
		lastStats:  make(map[string]PolicyUpdateStats),
		revisions:  make(map[string]uint64),
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

	next, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       mapName(endpointID),
		Type:       ebpf.LPMTrie,
		KeySize:    uint32(unsafe.Sizeof(PolicyKey{})),
		ValueSize:  uint32(unsafe.Sizeof(PolicyEntry{})),
		MaxEntries: s.maxEntries,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		return fmt.Errorf("create eBPF policy map for endpoint %s: %w", endpointID, err)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			next.Close()
			return err
		}
		if err := next.Put(entry.Key, entry.Value); err != nil {
			next.Close()
			return fmt.Errorf("write eBPF policy map for endpoint %s: %w", endpointID, err)
		}
	}

	old := s.maps[endpointID]
	revision := s.revisions[endpointID] + 1
	stats := plan.Stats()
	stats.Revision = revision
	s.maps[endpointID] = next
	s.entries[endpointID] = canonicalPolicyEntries(entries)
	s.revisions[endpointID] = revision
	s.lastStats[endpointID] = stats
	s.events = append(s.events, PolicyUpdateEvent{
		EndpointID: endpointID,
		Revision:   revision,
		Stats:      stats,
	})
	if old != nil {
		old.Close()
	}
	return nil
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
