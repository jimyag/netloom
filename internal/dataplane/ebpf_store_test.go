package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/jimyag/netloom/internal/model"
)

func requireEBPFTest(t *testing.T) {
	t.Helper()
	if os.Getenv("NETLOOM_EBPF_TEST") != "1" {
		t.Skip("set NETLOOM_EBPF_TEST=1 to create kernel eBPF maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot adjust memlock rlimit for eBPF test: %v", err)
	}
}

func replaceOrSkipIfUnprivileged(t *testing.T, store PolicyStore, endpointID string, entries []PolicyMapEntry) {
	t.Helper()
	if err := store.ReplaceEndpoint(context.Background(), endpointID, entries); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("kernel eBPF map creation is not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
}

func TestMapNameSanitizesEndpointID(t *testing.T) {
	got := mapName("pod/a:b")
	if len(got) != 15 {
		t.Fatalf("map name length = %d, want 15", len(got))
	}
	if !strings.HasPrefix(got, "nlp") {
		t.Fatalf("map name = %q, want nlp prefix", got)
	}
}

func TestMapNameAvoidsSanitizeAndTruncationCollisions(t *testing.T) {
	cases := []struct {
		left  string
		right string
	}{
		{left: "pod/a:b", right: "pod_a_b"},
		{left: "very-long-endpoint-name-a", right: "very-long-endpoint-name-b"},
	}
	for _, tc := range cases {
		left := mapName(tc.left)
		right := mapName(tc.right)
		if left == right {
			t.Fatalf("map names collide for %q and %q: %q", tc.left, tc.right, left)
		}
		if len(left) > 15 || len(right) > 15 {
			t.Fatalf("map names exceed eBPF limit: %q/%d %q/%d", left, len(left), right, len(right))
		}
	}
}

func TestEBPFPolicyStoreDeleteEndpointRejectsEmptyID(t *testing.T) {
	store := NewEBPFPolicyStore(16)
	err := store.DeleteEndpoint(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "endpoint id is required") {
		t.Fatalf("error = %v, want endpoint id validation", err)
	}
}

func TestEBPFPolicyStorePrivileged(t *testing.T) {
	requireEBPFTest(t)
	endpointID := model.EndpointKey("prod", "pod-a")

	store := NewEBPFPolicyStore(16)
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	})

	replaceOrSkipIfUnprivileged(t, store, endpointID, []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits,
			RemoteIdentity: 0,
			Direction:      DirectionIngress,
		},
		Value: PolicyEntry{
			Deny:       1,
			Precedence: ^uint32(0),
		},
	}})
}

func TestNewEBPFPolicyStoreWithConfigDefaults(t *testing.T) {
	store := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot: "  /var/run/netloom-ebpf  ",
	})
	if store.maxEntries != defaultPolicyMapMaxEntries {
		t.Fatalf("maxEntries = %d, want %d", store.maxEntries, defaultPolicyMapMaxEntries)
	}
	if store.schema != defaultPolicyMapSchemaVersion {
		t.Fatalf("schema = %d, want %d", store.schema, defaultPolicyMapSchemaVersion)
	}
	expectedPinRoot := filepath.Clean("/var/run/netloom-ebpf")
	if store.pinRoot != expectedPinRoot {
		t.Fatalf("pinRoot = %q, want %q", store.pinRoot, expectedPinRoot)
	}
}

func TestEBPFPolicyStorePinnedMapMetadataRoundTrip(t *testing.T) {
	requireEBPFTest(t)
	endpointID := model.EndpointKey("prod", "endpoint-a")
	tmp := t.TempDir()
	store := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 2,
	})
	metadataPath := store.pinnedPolicyMapMetadataPath(endpointID)
	if err := store.writeMapMetadata(metadataPath, endpointID); err != nil {
		t.Fatalf("writeMapMetadata() error = %v", err)
	}
	raw, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", metadataPath, err)
	}
	var decoded policyMapMetadata
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode metadata error = %v", err)
	}
	if decoded.EndpointID != endpointID {
		t.Fatalf("metadata endpoint id = %q, want %q", decoded.EndpointID, endpointID)
	}
	if decoded.SchemaVersion != 2 {
		t.Fatalf("metadata schema = %d, want %d", decoded.SchemaVersion, 2)
	}
	if decoded.MaxEntries != 16 {
		t.Fatalf("metadata max entries = %d, want %d", decoded.MaxEntries, 16)
	}
}

func TestEBPFPolicyStorePinnedMapMigration(t *testing.T) {
	requireEBPFTest(t)
	endpointID := model.EndpointKey("prod", "endpoint-a")
	tmp := t.TempDir()
	legacy := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() {
		_ = legacy.Close()
	})
	replaceOrSkipIfUnprivileged(t, legacy, endpointID, []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits,
			RemoteIdentity: 0,
			Direction:      DirectionIngress,
		},
		Value: PolicyEntry{
			Deny:       1,
			Precedence: ^uint32(0),
		},
	}})

	recovered := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    64,
		SchemaVersion: 1,
	})
	t.Cleanup(func() {
		_ = recovered.Close()
	})
	replaceOrSkipIfUnprivileged(t, recovered, endpointID, []PolicyMapEntry{})
	mapPath := recovered.pinnedPolicyMapPath(endpointID)
	_, err := os.Stat(mapPath)
	if err != nil {
		t.Fatalf("Map pin should exist after migration: %v", err)
	}
	metadata, err := recovered.loadMapMetadata(recovered.pinnedPolicyMapMetadataPath(endpointID))
	if err != nil {
		t.Fatalf("loadMapMetadata() error = %v", err)
	}
	if metadata.MaxEntries != 64 {
		t.Fatalf("metadata max entries = %d, want 64", metadata.MaxEntries)
	}
}

func TestEBPFPolicyStorePinnedMapClearOnReload(t *testing.T) {
	requireEBPFTest(t)
	endpointID := model.EndpointKey("prod", "endpoint-a")
	tmp := t.TempDir()
	store := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{PinRoot: tmp})
	t.Cleanup(func() {
		_ = store.Close()
	})
	replaceOrSkipIfUnprivileged(t, store, endpointID, []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits,
			RemoteIdentity: 0,
			Direction:      DirectionIngress,
		},
		Value: PolicyEntry{
			Deny:       1,
			Precedence: ^uint32(0),
		},
	}})
	reloaded := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{PinRoot: tmp})
	t.Cleanup(func() {
		_ = reloaded.Close()
	})
	replaceOrSkipIfUnprivileged(t, reloaded, endpointID, []PolicyMapEntry{})
	iter := reloaded.maps[endpointID].Iterate()
	var (
		key PolicyKey
		val PolicyEntry
	)
	count := 0
	for iter.Next(&key, &val) {
		count++
	}
	if iter.Err() != nil {
		t.Fatalf("iterate map error = %v", iter.Err())
	}
	if count != 0 {
		t.Fatalf("map entries = %d, want 0", count)
	}
}

func TestEBPFPolicyStorePinnedMapMigrationSkipsStaleMetadata(t *testing.T) {
	requireEBPFTest(t)
	endpointID := model.EndpointKey("prod", "endpoint-a")
	tmp := t.TempDir()
	legacy := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = legacy.Close() })

	replaceOrSkipIfUnprivileged(t, legacy, endpointID, []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits,
			RemoteIdentity: 0,
			Direction:      DirectionIngress,
		},
		Value: PolicyEntry{Deny: 1, Precedence: ^uint32(0)},
	}})

	metadataPath := legacy.pinnedPolicyMapMetadataPath(endpointID)
	staleMetadata := policyMapMetadata{SchemaVersion: 999, MaxEntries: 16}
	stalePayload, _ := json.Marshal(staleMetadata)
	if err := os.WriteFile(metadataPath, stalePayload, 0600); err != nil {
		t.Fatalf("write stale metadata error = %v", err)
	}

	recovered := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = recovered.Close() })

	replaceOrSkipIfUnprivileged(t, recovered, endpointID, []PolicyMapEntry{})
	metadata, err := recovered.loadMapMetadata(recovered.pinnedPolicyMapMetadataPath(endpointID))
	if err != nil {
		t.Fatalf("loadMapMetadata() error = %v", err)
	}
	if metadata.SchemaVersion != 1 {
		t.Fatalf("metadata schema = %d, want 1", metadata.SchemaVersion)
	}
	if metadata.MaxEntries != 16 {
		t.Fatalf("metadata max entries = %d, want 16", metadata.MaxEntries)
	}
}

func TestEBPFPolicyStorePinnedMapMigrationRecoverFromCorruptMetadata(t *testing.T) {
	requireEBPFTest(t)
	endpointID := model.EndpointKey("prod", "endpoint-a")
	tmp := t.TempDir()
	legacy := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = legacy.Close() })

	replaceOrSkipIfUnprivileged(t, legacy, endpointID, []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits,
			RemoteIdentity: 0,
			Direction:      DirectionIngress,
		},
		Value: PolicyEntry{
			Deny:       1,
			Precedence: ^uint32(0),
		},
	}})

	metadataPath := legacy.pinnedPolicyMapMetadataPath(endpointID)
	if err := os.WriteFile(metadataPath, []byte("not-json"), 0600); err != nil {
		t.Fatalf("corrupt metadata file error = %v", err)
	}

	recovered := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    32,
		SchemaVersion: 2,
	})
	t.Cleanup(func() { _ = recovered.Close() })
	replacement := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits,
			RemoteIdentity: 0,
			Direction:      DirectionIngress,
			Protocol:       6,
			DestPortBE:     hostToNetwork16(443),
		},
		Value: PolicyEntry{
			Deny:        1,
			Precedence:  100,
			L4PrefixLen: 24,
		},
	}}
	replaceOrSkipIfUnprivileged(t, recovered, endpointID, replacement)

	metadata, err := recovered.loadMapMetadata(recovered.pinnedPolicyMapMetadataPath(endpointID))
	if err != nil {
		t.Fatalf("loadMapMetadata() error = %v", err)
	}
	if metadata.SchemaVersion != 2 || metadata.MaxEntries != 32 {
		t.Fatalf("metadata = %+v, want schema=2 max_entries=32", metadata)
	}
	entries := recovered.maps[endpointID]
	if entries == nil {
		t.Fatal("recovered store entry map should be loaded")
	}
	iter := entries.Iterate()
	var key PolicyKey
	var value PolicyEntry
	count := 0
	for iter.Next(&key, &value) {
		count++
	}
	if iter.Err() != nil {
		t.Fatalf("iterate map error = %v", iter.Err())
	}
	if count != 1 {
		t.Fatalf("map entries = %d, want 1", count)
	}
}

func TestEBPFPolicyStorePinnedMapMigrationPreservesEntriesAfterSchemaBump(t *testing.T) {
	requireEBPFTest(t)
	endpointID := model.EndpointKey("prod", "endpoint-a")
	tmp := t.TempDir()
	legacy := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = legacy.Close() })

	rule := PolicyMapEntry{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits,
			RemoteIdentity: 0,
			Direction:      DirectionIngress,
		},
		Value: PolicyEntry{Deny: 1, Precedence: ^uint32(0)},
	}
	replaceOrSkipIfUnprivileged(t, legacy, endpointID, []PolicyMapEntry{rule})

	recovered := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    32,
		SchemaVersion: 2,
	})
	t.Cleanup(func() { _ = recovered.Close() })

	replaceOrSkipIfUnprivileged(t, recovered, endpointID, []PolicyMapEntry{rule})
	mapPath := recovered.pinnedPolicyMapPath(endpointID)
	metadata, err := recovered.loadMapMetadata(recovered.pinnedPolicyMapMetadataPath(endpointID))
	if err != nil {
		t.Fatalf("loadMapMetadata() error = %v", err)
	}
	if metadata.SchemaVersion != 2 {
		t.Fatalf("metadata schema = %d, want 2", metadata.SchemaVersion)
	}
	if metadata.MaxEntries != 32 {
		t.Fatalf("metadata max entries = %d, want 32", metadata.MaxEntries)
	}
	if _, err := os.Stat(mapPath); err != nil {
		t.Fatalf("pinned map should exist: %v", err)
	}
	iter := recovered.maps[endpointID].Iterate()
	var (
		key   PolicyKey
		value PolicyEntry
	)
	count := 0
	for iter.Next(&key, &value) {
		count++
	}
	if iter.Err() != nil {
		t.Fatalf("iterate map error = %v", iter.Err())
	}
	if count != 1 {
		t.Fatalf("map entries = %d, want 1", count)
	}
}

func TestEBPFPolicyStoreDeleteEndpointRemovesPinnedMapWithoutLoadedState(t *testing.T) {
	requireEBPFTest(t)
	endpointID := model.EndpointKey("prod", "endpoint-a")
	tmp := t.TempDir()
	store := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = store.Close() })

	replaceOrSkipIfUnprivileged(t, store, endpointID, []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits,
			RemoteIdentity: 0,
			Direction:      DirectionIngress,
		},
		Value: PolicyEntry{
			Deny:       1,
			Precedence: ^uint32(0),
		},
	}})

	mapPath := store.pinnedPolicyMapPath(endpointID)
	metadataPath := store.pinnedPolicyMapMetadataPath(endpointID)
	if _, err := os.Stat(mapPath); err != nil {
		t.Fatalf("pinned policy map missing after replace: %v", err)
	}
	if _, err := os.Stat(metadataPath); err != nil {
		t.Fatalf("pinned policy map metadata missing after replace: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store error = %v", err)
	}
	if _, err := os.Stat(mapPath); err != nil {
		t.Fatalf("pinned policy map should survive store close for restart recovery: %v", err)
	}
	if _, err := os.Stat(metadataPath); err != nil {
		t.Fatalf("pinned policy map metadata should survive store close for restart recovery: %v", err)
	}

	restored := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = restored.Close() })
	if err := restored.DeleteEndpoint(context.Background(), endpointID); err != nil {
		t.Fatalf("DeleteEndpoint() error = %v", err)
	}
	if _, err := os.Stat(mapPath); !os.IsNotExist(err) {
		t.Fatalf("pinned policy map was not removed, stat error = %v", err)
	}
	if _, err := os.Stat(metadataPath); !os.IsNotExist(err) {
		t.Fatalf("pinned policy metadata was not removed, stat error = %v", err)
	}
}

func TestEBPFPolicyStoreClosePreservesPinnedMapsForRestart(t *testing.T) {
	requireEBPFTest(t)
	endpointID := model.EndpointKey("prod", "endpoint-a")
	tmp := t.TempDir()
	store := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})

	rule := []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits,
			RemoteIdentity: 42,
			Direction:      DirectionIngress,
		},
		Value: PolicyEntry{
			Deny:       1,
			Precedence: 42,
		},
	}}
	replaceOrSkipIfUnprivileged(t, store, endpointID, rule)
	mapPath := store.pinnedPolicyMapPath(endpointID)
	metadataPath := store.pinnedPolicyMapMetadataPath(endpointID)

	if err := store.Close(); err != nil {
		t.Fatalf("close store error = %v", err)
	}
	if _, err := os.Stat(mapPath); err != nil {
		t.Fatalf("pinned policy map should remain after close: %v", err)
	}
	if _, err := os.Stat(metadataPath); err != nil {
		t.Fatalf("pinned policy metadata should remain after close: %v", err)
	}

	recovered := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = recovered.Close() })

	replaceOrSkipIfUnprivileged(t, recovered, endpointID, rule)
	if recovered.maps[endpointID] == nil {
		t.Fatal("recovered store should load pinned map after restart")
	}
	iter := recovered.maps[endpointID].Iterate()
	var (
		key PolicyKey
		val PolicyEntry
	)
	count := 0
	for iter.Next(&key, &val) {
		count++
	}
	if iter.Err() != nil {
		t.Fatalf("iterate recovered map error = %v", iter.Err())
	}
	if count != 1 {
		t.Fatalf("recovered map entries = %d, want 1", count)
	}
}

func TestEBPFPolicyStoreEndpointIDsIncludesPinnedEndpointsAfterRestart(t *testing.T) {
	requireEBPFTest(t)
	endpointID := model.EndpointKey("prod", "endpoint-a")
	tmp := t.TempDir()
	store := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	replaceOrSkipIfUnprivileged(t, store, endpointID, []PolicyMapEntry{{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 7, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 7, Deny: 1},
	}})
	if err := store.Close(); err != nil {
		t.Fatalf("close store error = %v", err)
	}

	recovered := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = recovered.Close() })
	endpoints, err := recovered.EndpointIDs(context.Background())
	if err != nil {
		t.Fatalf("EndpointIDs() error = %v", err)
	}
	if len(endpoints) != 1 || endpoints[0] != endpointID {
		t.Fatalf("EndpointIDs() = %v, want [%q]", endpoints, endpointID)
	}
}

func TestEBPFPolicyStoreEndpointIDsIncludesPinnedEndpointsFromSeparateMetadataRoot(t *testing.T) {
	requireEBPFTest(t)
	endpointID := model.EndpointKey("prod", "endpoint-a")
	tmp := t.TempDir()
	metadataRoot := filepath.Join(tmp, "meta")
	store := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MetadataRoot:  metadataRoot,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	replaceOrSkipIfUnprivileged(t, store, endpointID, []PolicyMapEntry{{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 7, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 7, Deny: 1},
	}})
	if err := store.Close(); err != nil {
		t.Fatalf("close store error = %v", err)
	}

	recovered := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MetadataRoot:  metadataRoot,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = recovered.Close() })
	endpoints, err := recovered.EndpointIDs(context.Background())
	if err != nil {
		t.Fatalf("EndpointIDs() error = %v", err)
	}
	if len(endpoints) != 1 || endpoints[0] != endpointID {
		t.Fatalf("EndpointIDs() = %v, want [%q]", endpoints, endpointID)
	}
}

func TestEBPFPolicyStorePinnedMapCanBeUpdatedAcrossReconciles(t *testing.T) {
	requireEBPFTest(t)
	endpointID := model.EndpointKey("prod", "endpoint-a")
	tmp := t.TempDir()
	store := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MetadataRoot:  filepath.Join(tmp, "meta"),
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = store.Close() })

	first := []PolicyMapEntry{{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 10, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 10, Deny: 1},
	}}
	second := []PolicyMapEntry{{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 20, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 20, Deny: 1},
	}}
	replaceOrSkipIfUnprivileged(t, store, endpointID, first)
	replaceOrSkipIfUnprivileged(t, store, endpointID, second)

	iter := store.maps[endpointID].Iterate()
	var (
		key PolicyKey
		val PolicyEntry
	)
	count := 0
	for iter.Next(&key, &val) {
		if key.RemoteIdentity != 20 {
			t.Fatalf("remote identity = %d, want 20 after update", key.RemoteIdentity)
		}
		if val.Precedence != 20 {
			t.Fatalf("precedence = %d, want 20 after update", val.Precedence)
		}
		count++
	}
	if iter.Err() != nil {
		t.Fatalf("iterate map error = %v", iter.Err())
	}
	if count != 1 {
		t.Fatalf("map entries = %d, want 1", count)
	}
}

func TestEBPFPolicyStoreMaintainsDistinctPinnedMapsForVPCEndpoints(t *testing.T) {
	requireEBPFTest(t)
	vpcOne := model.EndpointKey("prod", "endpoint-a")
	vpcTwo := model.EndpointKey("stg", "endpoint-a")
	tmp := t.TempDir()
	store := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = store.Close() })

	replaceOrSkipIfUnprivileged(t, store, vpcOne, []PolicyMapEntry{{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 10, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 10, Deny: 1},
	}})
	replaceOrSkipIfUnprivileged(t, store, vpcTwo, []PolicyMapEntry{{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 20, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 20, Deny: 1},
	}})

	mapPathOne := store.pinnedPolicyMapPath(vpcOne)
	mapPathTwo := store.pinnedPolicyMapPath(vpcTwo)
	if mapPathOne == mapPathTwo {
		t.Fatalf("pinned map paths must not collide for different VPC-scoped endpoint IDs: %s", mapPathOne)
	}
	if _, err := os.Stat(mapPathOne); err != nil {
		t.Fatalf("expected pinned map for first VPC endpoint: %v", err)
	}
	if _, err := os.Stat(mapPathTwo); err != nil {
		t.Fatalf("expected pinned map for second VPC endpoint: %v", err)
	}

	reloaded := NewEBPFPolicyStoreWithConfig(EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = reloaded.Close() })
	replaceOrSkipIfUnprivileged(t, reloaded, vpcTwo, []PolicyMapEntry{{
		Key:   PolicyKey{PrefixLen: StaticPrefixBits, RemoteIdentity: 20, Direction: DirectionIngress},
		Value: PolicyEntry{Precedence: 20, Deny: 1},
	}})
	if err := reloaded.DeleteEndpoint(context.Background(), vpcOne); err != nil {
		t.Fatalf("DeleteEndpoint(%q) error = %v", vpcOne, err)
	}

	iter := reloaded.maps[vpcTwo].Iterate()
	var (
		key PolicyKey
		val PolicyEntry
	)
	count := 0
	for iter.Next(&key, &val) {
		if key.RemoteIdentity == 0 {
			t.Fatalf("unexpected stale entry for removed endpoint %q", vpcOne)
		}
		if key.RemoteIdentity != 20 {
			t.Fatalf("expected remote identity 20 on remaining endpoint, got %d", key.RemoteIdentity)
		}
		if val.Precedence != 20 {
			t.Fatalf("expected precedence 20 on remaining endpoint, got %d", val.Precedence)
		}
		count++
	}
	if iter.Err() != nil {
		t.Fatalf("iterate remaining endpoint map error = %v", iter.Err())
	}
	if count != 1 {
		t.Fatalf("expected one policy entry for remaining endpoint, got %d", count)
	}
	metadata, err := reloaded.loadMapMetadata(reloaded.pinnedPolicyMapMetadataPath(vpcTwo))
	if err != nil {
		t.Fatalf("load metadata for remaining endpoint = %v", err)
	}
	if metadata.MaxEntries != 16 {
		t.Fatalf("metadata max entries mismatch: %d", metadata.MaxEntries)
	}
}

func TestMapNameAvoidsVPCTrailingCollisions(t *testing.T) {
	left := model.EndpointKey("prod", "pod/a:b")
	right := model.EndpointKey("stg", "pod/a:b")
	leftName := mapName(left)
	rightName := mapName(right)
	if leftName == rightName {
		t.Fatalf("map names collide for %q and %q: %s", left, right, leftName)
	}
	if !strings.HasPrefix(leftName, "nlp") || !strings.HasPrefix(rightName, "nlp") {
		t.Fatalf("map names should start with nlp: %q, %q", leftName, rightName)
	}
	if len(leftName) != len(rightName) {
		t.Fatalf("map names should both be 15 chars, got %d and %d", len(leftName), len(rightName))
	}
	if len(leftName) != 15 {
		t.Fatalf("map name length must be 15: %d", len(leftName))
	}
}
