package agent

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/linuxdatapath"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
)

func requireEBPFReconcilerTest(t *testing.T) {
	t.Helper()
	if os.Getenv("NETLOOM_EBPF_TEST") != "1" {
		t.Skip("set NETLOOM_EBPF_TEST=1 to create kernel eBPF maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot adjust memlock rlimit for eBPF test: %v", err)
	}
}

type countingIdentityResolver struct {
	mu     sync.Mutex
	inner  policy.IdentityResolver
	misses map[string]int
}

func newCountingIdentityResolver() *countingIdentityResolver {
	return &countingIdentityResolver{
		inner:  policy.NewIdentityCache(),
		misses: make(map[string]int),
	}
}

func (c *countingIdentityResolver) Identity(value string) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.misses[value]; !ok {
		c.misses[value] = 1
	}
	if c.inner == nil {
		return policy.EndpointIdentity(value)
	}
	return c.inner.Identity(value)
}

func (c *countingIdentityResolver) missesFor(value string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.misses[value]
}

type scopedPolicyStore struct {
	replaces []string
	deletes  []string
}

func (s *scopedPolicyStore) ReplaceEndpoint(_ context.Context, endpointID string, _ []dataplane.PolicyMapEntry) error {
	s.replaces = append(s.replaces, endpointID)
	return nil
}

func (s *scopedPolicyStore) DeleteEndpoint(_ context.Context, endpointID string) error {
	s.deletes = append(s.deletes, endpointID)
	return nil
}

type inventoryPolicyStore struct {
	scopedPolicyStore
	endpoints []string
}

func (s *inventoryPolicyStore) EndpointIDs(_ context.Context) ([]string, error) {
	return append([]string(nil), s.endpoints...), nil
}

type usagePolicyStore struct {
	*dataplane.InMemoryPolicyStore
	usages   []dataplane.PolicyMapUsage
	drift    []dataplane.PolicyMapDrift
	statuses []dataplane.PolicyEndpointStatus
	err      error
}

func (s *usagePolicyStore) PolicyMapUsage(_ context.Context) ([]dataplane.PolicyMapUsage, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]dataplane.PolicyMapUsage(nil), s.usages...), nil
}

func (s *usagePolicyStore) PolicyMapDrift(_ context.Context) ([]dataplane.PolicyMapDrift, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]dataplane.PolicyMapDrift(nil), s.drift...), nil
}

func (s *usagePolicyStore) PolicyEndpointStatuses(_ context.Context) ([]dataplane.PolicyEndpointStatus, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]dataplane.PolicyEndpointStatus(nil), s.statuses...), nil
}

type concurrentPolicyStore struct {
	delay               time.Duration
	delegate            *dataplane.InMemoryPolicyStore
	mu                  sync.Mutex
	active              int
	maxActive           int
	firstReplaceStarted chan struct{}
	startedOnce         sync.Once
}

func newConcurrentPolicyStore(delay time.Duration) *concurrentPolicyStore {
	return &concurrentPolicyStore{
		delay:               delay,
		delegate:            dataplane.NewInMemoryPolicyStore(),
		firstReplaceStarted: make(chan struct{}, 1),
	}
}

func (s *concurrentPolicyStore) ReplaceEndpoint(ctx context.Context, endpointID string, entries []dataplane.PolicyMapEntry) error {
	s.startWrite()
	time.Sleep(s.delay)
	defer s.finishWrite()
	return s.delegate.ReplaceEndpoint(ctx, endpointID, entries)
}

func (s *concurrentPolicyStore) DeleteEndpoint(ctx context.Context, endpointID string) error {
	s.startWrite()
	time.Sleep(s.delay)
	defer s.finishWrite()
	return s.delegate.DeleteEndpoint(ctx, endpointID)
}

func (s *concurrentPolicyStore) startWrite() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active++
	if s.active > s.maxActive {
		s.maxActive = s.active
	}
	if s.active == 1 {
		s.startedOnce.Do(func() {
			s.firstReplaceStarted <- struct{}{}
		})
	}
}

func (s *concurrentPolicyStore) finishWrite() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
}

func (s *concurrentPolicyStore) MaxConcurrentWrites() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxActive
}

func tcxProgram(endpointID string, direction model.Direction, cidr string, port uint16) policy.Program {
	return policy.Program{
		EndpointID: endpointID,
		EndpointIP: tcxProgramEndpointIP(endpointID),
		Rules: []policy.Rule{{
			ID:         endpointID + "-tcx",
			Direction:  direction,
			Protocol:   model.ProtocolTCP,
			RemoteCIDR: netip.MustParsePrefix(cidr),
			Ports:      []model.PortRange{{From: port, To: port}},
			Action:     model.ActionDrop,
		}},
	}
}

func tcxProgramEndpointIP(endpointID string) netip.Addr {
	switch {
	case strings.Contains(endpointID, "pod-a"):
		return netip.MustParseAddr("10.10.0.10")
	case strings.Contains(endpointID, "pod-b"):
		return netip.MustParseAddr("10.10.0.11")
	default:
		return netip.MustParseAddr("10.10.0.254")
	}
}

func TestReconcileNodeAppliesOnlyLocalEndpointPolicies(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "pod-a",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.10"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
			{
				ID:             "pod-b",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.11"),
				Node:           "node-b",
				SecurityGroups: []string{"web"},
			},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Endpoints != 1 || result.Programs != 1 || result.Entries != 1 || result.TCXEligible != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.PolicyAdded != 1 || result.PolicyUpdated != 0 || result.PolicyDeleted != 0 || result.PolicyUnchanged != 0 || result.PolicyEvents != 1 || result.PolicyRevisionMax != 1 {
		t.Fatalf("policy update summary = %+v, want one add at revision 1", result)
	}
	if result.TCX != "not-requested" {
		t.Fatalf("tcx = %s, want not-requested", result.TCX)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %d, want 1", len(entries))
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-b")); len(entries) != 0 {
		t.Fatalf("pod-b entries = %d, want 0", len(entries))
	}
}

func TestReconcileNodeKeepsSameEndpointIDScopedByVPCInPolicyLifecycle(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "shared",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.10"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
			{
				ID:             "shared",
				VPC:            "dev",
				Subnet:         "apps-dev",
				IP:             netip.MustParseAddr("10.20.0.10"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
		},
		SecurityGroups: []model.SecurityGroup{
			{
				Name: "web",
				VPC:  "prod",
				Rules: []model.SecurityGroupRule{{
					ID:        "prod-web",
					Priority:  100,
					Direction: model.DirectionIngress,
					Protocol:  model.ProtocolAny,
					Action:    model.ActionAllow,
				}},
			},
			{
				Name: "web",
				VPC:  "dev",
				Rules: []model.SecurityGroupRule{{
					ID:        "dev-web",
					Priority:  100,
					Direction: model.DirectionIngress,
					Protocol:  model.ProtocolAny,
					Action:    model.ActionAllow,
				}},
			},
		},
	}

	store := &scopedPolicyStore{}
	reconciler := NewReconciler(store)
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a", Store: store}); err != nil {
		t.Fatalf("first reconcile failed: %v", err)
	}
	prodKey := model.EndpointKey("prod", "shared")
	devKey := model.EndpointKey("dev", "shared")
	if !slices.Contains(store.replaces, prodKey) || !slices.Contains(store.replaces, devKey) {
		t.Fatalf("first reconcile replace endpoints = %v, want %v and %v", store.replaces, prodKey, devKey)
	}

	state.Endpoints = []model.Endpoint{{
		ID:             "shared",
		VPC:            "dev",
		Subnet:         "apps-dev",
		IP:             netip.MustParseAddr("10.20.0.10"),
		Node:           "node-a",
		SecurityGroups: []string{"web"},
	}}
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a", Store: store}); err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}
	if !slices.Contains(store.deletes, prodKey) || slices.Contains(store.deletes, devKey) {
		t.Fatalf("delete endpoints = %v, want stale %v only", store.deletes, prodKey)
	}
}

func TestReconcilerDeletesInventoryEndpointsMissingAfterRestart(t *testing.T) {
	store := &inventoryPolicyStore{
		endpoints: []string{
			model.EndpointKey("prod", "stale"),
			model.EndpointKey("prod", "live"),
		},
	}
	reconciler := NewReconciler(store)
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "live",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:        "allow-all",
				Priority:  100,
				Direction: model.DirectionIngress,
				Protocol:  model.ProtocolAny,
				Action:    model.ActionAllow,
			}},
		}},
	}

	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a", Store: store}); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if !slices.Contains(store.deletes, model.EndpointKey("prod", "stale")) {
		t.Fatalf("stale endpoint delete list = %v, want %q", store.deletes, model.EndpointKey("prod", "stale"))
	}
	if slices.Contains(store.deletes, model.EndpointKey("prod", "live")) {
		t.Fatalf("live endpoint must not be deleted: %v", store.deletes)
	}
	if !slices.Contains(store.replaces, model.EndpointKey("prod", "live")) {
		t.Fatalf("live endpoint replace list = %v, want %q", store.replaces, model.EndpointKey("prod", "live"))
	}
}

func TestReconcilerRestartCleansStalePinnedEBPFEndpoints(t *testing.T) {
	requireEBPFReconcilerTest(t)
	tmp := t.TempDir()
	staleEndpoint := model.EndpointKey("prod", "stale")
	liveEndpoint := model.EndpointKey("prod", "live")

	initialStore := dataplane.NewEBPFPolicyStoreWithConfig(dataplane.EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	staleEntries := []dataplane.PolicyMapEntry{{
		Key:   dataplane.PolicyKey{PrefixLen: dataplane.StaticPrefixBits, RemoteIdentity: 10, Direction: dataplane.DirectionIngress},
		Value: dataplane.PolicyEntry{Precedence: 10, Deny: 1},
	}}
	liveEntries := []dataplane.PolicyMapEntry{{
		Key:   dataplane.PolicyKey{PrefixLen: dataplane.StaticPrefixBits, RemoteIdentity: 20, Direction: dataplane.DirectionIngress},
		Value: dataplane.PolicyEntry{Precedence: 20, Deny: 1},
	}}
	if err := initialStore.ReplaceEndpoint(context.Background(), staleEndpoint, staleEntries); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("kernel eBPF map creation is not permitted in this environment: %v", err)
		}
		t.Fatalf("seed stale endpoint map: %v", err)
	}
	if err := initialStore.ReplaceEndpoint(context.Background(), liveEndpoint, liveEntries); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("kernel eBPF map creation is not permitted in this environment: %v", err)
		}
		t.Fatalf("seed live endpoint map: %v", err)
	}
	if err := initialStore.Close(); err != nil {
		t.Fatalf("close seeded store: %v", err)
	}
	if entries, err := os.ReadDir(tmp); err != nil {
		t.Fatalf("list pin root after seed: %v", err)
	} else if len(entries) != 4 {
		t.Fatalf("pin root entries after seed = %d, want 4", len(entries))
	}

	restartedStore := dataplane.NewEBPFPolicyStoreWithConfig(dataplane.EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = restartedStore.Close() })
	reconciler := NewReconciler(restartedStore)
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "live",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("10.10.0.11/32"),
				Ports:      []model.PortRange{{From: 443, To: 443}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a", Store: restartedStore}); err != nil {
		t.Fatalf("reconcile after restart: %v", err)
	}

	endpointIDs, err := restartedStore.EndpointIDs(context.Background())
	if err != nil {
		t.Fatalf("EndpointIDs() after restart reconcile: %v", err)
	}
	if !slices.Equal(endpointIDs, []string{liveEndpoint}) {
		t.Fatalf("managed endpoints after restart reconcile = %v, want [%q]", endpointIDs, liveEndpoint)
	}
	if entries, err := os.ReadDir(tmp); err != nil {
		t.Fatalf("list pin root after restart reconcile: %v", err)
	} else if len(entries) != 2 {
		t.Fatalf("pin root entries after stale cleanup = %d, want 2", len(entries))
	}
}

func TestReconcilerRestartCleansStalePinnedEBPFEndpointsWithSeparateMetadataRoot(t *testing.T) {
	requireEBPFReconcilerTest(t)
	tmp := t.TempDir()
	metadataRoot := filepath.Join(tmp, "meta")
	staleEndpoint := model.EndpointKey("prod", "stale")
	liveEndpoint := model.EndpointKey("prod", "live")

	initialStore := dataplane.NewEBPFPolicyStoreWithConfig(dataplane.EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MetadataRoot:  metadataRoot,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	staleEntries := []dataplane.PolicyMapEntry{{
		Key:   dataplane.PolicyKey{PrefixLen: dataplane.StaticPrefixBits, RemoteIdentity: 10, Direction: dataplane.DirectionIngress},
		Value: dataplane.PolicyEntry{Precedence: 10, Deny: 1},
	}}
	liveEntries := []dataplane.PolicyMapEntry{{
		Key:   dataplane.PolicyKey{PrefixLen: dataplane.StaticPrefixBits, RemoteIdentity: 20, Direction: dataplane.DirectionIngress},
		Value: dataplane.PolicyEntry{Precedence: 20, Deny: 1},
	}}
	if err := initialStore.ReplaceEndpoint(context.Background(), staleEndpoint, staleEntries); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("kernel eBPF map creation is not permitted in this environment: %v", err)
		}
		t.Fatalf("seed stale endpoint map: %v", err)
	}
	if err := initialStore.ReplaceEndpoint(context.Background(), liveEndpoint, liveEntries); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("kernel eBPF map creation is not permitted in this environment: %v", err)
		}
		t.Fatalf("seed live endpoint map: %v", err)
	}
	if err := initialStore.Close(); err != nil {
		t.Fatalf("close seeded store: %v", err)
	}
	if entries, err := os.ReadDir(tmp); err != nil {
		t.Fatalf("list pin root after seed: %v", err)
	} else if len(entries) != 3 {
		t.Fatalf("pin root entries after seed = %d, want 3 including metadata dir", len(entries))
	}
	if entries, err := os.ReadDir(metadataRoot); err != nil {
		t.Fatalf("list metadata root after seed: %v", err)
	} else if len(entries) != 2 {
		t.Fatalf("metadata root entries after seed = %d, want 2", len(entries))
	}

	restartedStore := dataplane.NewEBPFPolicyStoreWithConfig(dataplane.EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MetadataRoot:  metadataRoot,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = restartedStore.Close() })
	reconciler := NewReconciler(restartedStore)
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "live",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("10.10.0.11/32"),
				Ports:      []model.PortRange{{From: 443, To: 443}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a", Store: restartedStore}); err != nil {
		t.Fatalf("reconcile after restart: %v", err)
	}

	endpointIDs, err := restartedStore.EndpointIDs(context.Background())
	if err != nil {
		t.Fatalf("EndpointIDs() after restart reconcile: %v", err)
	}
	if !slices.Equal(endpointIDs, []string{liveEndpoint}) {
		t.Fatalf("managed endpoints after restart reconcile = %v, want [%q]", endpointIDs, liveEndpoint)
	}
	if entries, err := os.ReadDir(tmp); err != nil {
		t.Fatalf("list pin root after restart reconcile: %v", err)
	} else if len(entries) != 2 {
		t.Fatalf("pin root entries after stale cleanup = %d, want 2 including metadata dir", len(entries))
	}
	if entries, err := os.ReadDir(metadataRoot); err != nil {
		t.Fatalf("list metadata root after restart reconcile: %v", err)
	} else if len(entries) != 1 {
		t.Fatalf("metadata root entries after stale cleanup = %d, want 1", len(entries))
	}
}

func TestReconcilerRepairsDriftedPinnedEBPFPolicyMap(t *testing.T) {
	requireEBPFReconcilerTest(t)
	tmp := t.TempDir()
	store := dataplane.NewEBPFPolicyStoreWithConfig(dataplane.EBPFPolicyStoreConfig{
		PinRoot:       tmp,
		MaxEntries:    16,
		SchemaVersion: 1,
	})
	t.Cleanup(func() { _ = store.Close() })
	reconciler := NewReconciler(store)
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "live",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("10.10.0.11/32"),
				Ports:      []model.PortRange{{From: 443, To: 443}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a", Store: store}); err != nil {
		t.Fatalf("first reconcile failed: %v", err)
	}

	mapPath, err := singlePinnedPolicyMapPath(tmp)
	if err != nil {
		t.Fatalf("singlePinnedPolicyMapPath() error = %v", err)
	}
	pinnedMap, err := ebpf.LoadPinnedMap(mapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		t.Fatalf("LoadPinnedMap(%q) error = %v", mapPath, err)
	}
	defer pinnedMap.Close()

	expectedKey := dataplane.PolicyKey{
		PrefixLen:      dataplane.StaticPrefixBits + 24,
		RemoteIdentity: policy.EndpointIdentity("10.10.0.11/32"),
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		DestPortBE:     hostToNetwork16(443),
	}
	var expectedValue dataplane.PolicyEntry
	if err := pinnedMap.Lookup(expectedKey, &expectedValue); err != nil {
		t.Fatalf("Lookup(expectedKey) error = %v", err)
	}
	if err := pinnedMap.Delete(expectedKey); err != nil {
		t.Fatalf("Delete(expectedKey) error = %v", err)
	}
	rogueKey := dataplane.PolicyKey{
		PrefixLen:      dataplane.StaticPrefixBits + 24,
		RemoteIdentity: policy.EndpointIdentity("10.10.0.99/32"),
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		DestPortBE:     hostToNetwork16(443),
	}
	rogueValue := dataplane.PolicyEntry{Precedence: 999, L4PrefixLen: 24}
	if err := pinnedMap.Put(&rogueKey, &rogueValue); err != nil {
		t.Fatalf("Put(rogueKey) error = %v", err)
	}

	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a", Store: store}); err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}

	repairedMap, err := ebpf.LoadPinnedMap(mapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		t.Fatalf("LoadPinnedMap repaired map error = %v", err)
	}
	defer repairedMap.Close()
	var repairedValue dataplane.PolicyEntry
	if err := repairedMap.Lookup(expectedKey, &repairedValue); err != nil {
		t.Fatalf("Lookup(expectedKey) after repair error = %v", err)
	}
	if repairedValue != expectedValue {
		t.Fatalf("expected value after repair = %+v, want %+v", repairedValue, expectedValue)
	}
	var discarded dataplane.PolicyEntry
	if err := repairedMap.Lookup(rogueKey, &discarded); err == nil {
		t.Fatalf("rogue key still present after repair: %+v", discarded)
	}
}

func singlePinnedPolicyMapPath(pinRoot string) (string, error) {
	entries, err := os.ReadDir(pinRoot)
	if err != nil {
		return "", err
	}
	var matches []string
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".meta") {
			continue
		}
		matches = append(matches, filepath.Join(pinRoot, entry.Name()))
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("expected one pinned policy map, got %d", len(matches))
	}
	return matches[0], nil
}

func hostToNetwork16(value uint16) uint16 {
	return value<<8 | value>>8
}

func TestReconcileSharesIdentityResolverAcrossLocalEndpoints(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "pod-a",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.10"),
				Node:           "node-a",
				SecurityGroups: []string{"clients"},
			},
			{
				ID:             "pod-b",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.11"),
				Node:           "node-a",
				SecurityGroups: []string{"clients"},
			},
			{
				ID:             "pod-c",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.12"),
				Node:           "node-a",
				SecurityGroups: []string{"clients"},
			},
		},
		SecurityGroups: []model.SecurityGroup{
			{
				Name: "clients",
				VPC:  "prod",
				Rules: []model.SecurityGroupRule{{
					ID:          "allow-clients",
					Priority:    100,
					Direction:   model.DirectionIngress,
					Protocol:    model.ProtocolTCP,
					RemoteGroup: "clients",
					Ports:       []model.PortRange{{From: 8080, To: 8081}},
					Action:      model.ActionAllow,
				}},
			},
		},
	}
	store := dataplane.NewInMemoryPolicyStore()
	resolver := newCountingIdentityResolver()
	reconciler := NewReconciler(store)
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{
		Node:             "node-a",
		Store:            store,
		IdentityResolver: resolver,
	}); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	for _, endpoint := range []string{"pod-a", "pod-b", "pod-c"} {
		endpointKey := model.EndpointKey("prod", endpoint)
		if got := resolver.missesFor("endpoint:" + endpointKey); got != 1 {
			t.Fatalf("identity(%q) misses = %d, want 1 with shared resolver", endpointKey, got)
		}
	}
}

func TestReconcileNodeReportsPolicyDiffStatsAcrossRevisions(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	if _, err := ReconcileNode(context.Background(), state, "node-a", store); err != nil {
		t.Fatal(err)
	}

	state.SecurityGroups[0].Rules[0].Action = model.ActionAllow
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyAdded != 0 || result.PolicyUpdated != 1 || result.PolicyDeleted != 0 || result.PolicyUnchanged != 0 || result.PolicyEvents != 1 || result.PolicyRevisionMax != 2 {
		t.Fatalf("policy update summary = %+v, want one update at revision 2", result)
	}
	events := store.Events()
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[1].EndpointID != model.EndpointKey("prod", "pod-a") || !events[1].Success || events[1].PreviousRevision != 1 || events[1].Revision != 2 || events[1].Stats.Updated != 1 || events[1].Stats.Revision != 2 {
		t.Fatalf("second event = %+v, want pod-a update revision 2", events[1])
	}
}

func TestReconcileNodeReportsPolicyFailureAndRollbackSignals(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	if _, err := ReconcileNode(context.Background(), state, "node-a", store); err != nil {
		t.Fatal(err)
	}

	state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.MustParsePrefix("172.30.0.21/32")
	state.SecurityGroups[0].Rules = append(state.SecurityGroups[0].Rules, model.SecurityGroupRule{
		ID:         "web-alt",
		Priority:   110,
		Direction:  model.DirectionIngress,
		Protocol:   model.ProtocolTCP,
		RemoteCIDR: netip.MustParsePrefix("172.30.0.12/32"),
		Ports:      []model.PortRange{{From: 8443, To: 8443}},
		Action:     model.ActionAllow,
	})
	store.SetFailAfter(1)

	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err == nil {
		t.Fatal("expected reconcile to fail after partial policy update")
	}
	if result.Endpoints != 1 || result.Programs != 1 || result.Entries != 2 {
		t.Fatalf("partial result scope = %+v, want one endpoint/program and two desired entries", result)
	}
	if result.PolicyEvents != 1 || result.PolicyFailed != 1 || result.PolicyRollbacks != 1 || result.PolicyRevisionMax != 2 {
		t.Fatalf("policy failure summary = %+v, want one failed rollback event at revision 2", result)
	}
	if result.PolicyFailedEndpoint != model.EndpointKey("prod", "pod-a") || result.PolicyFailedRevision != 2 {
		t.Fatalf("policy failed endpoint/revision = %q/%d, want pod-a revision 2", result.PolicyFailedEndpoint, result.PolicyFailedRevision)
	}
	if !strings.Contains(result.PolicyLastError, "in-memory policy update failed after 1 operations") {
		t.Fatalf("policy last error = %q, want in-memory update failure", result.PolicyLastError)
	}
	events := store.Events()
	if len(events) != 2 || events[1].Success {
		t.Fatalf("events = %+v, want failed second event", events)
	}
}

func TestReconcilerDeletesStaleEndpointPolicy(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	reconciler := NewReconciler(store)
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %d, want 1", len(entries))
	}

	state.Endpoints = nil
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("stale pod-a entries = %+v, want deleted", entries)
	}
}

func TestReconcileNodeReportsUnchangedPolicyStats(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	if _, err := ReconcileNode(context.Background(), state, "node-a", store); err != nil {
		t.Fatal(err)
	}
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyAdded != 0 || result.PolicyUpdated != 0 || result.PolicyDeleted != 0 || result.PolicyUnchanged != 1 || result.PolicyEvents != 1 || result.PolicyRevisionMax != 2 {
		t.Fatalf("policy update summary = %+v, want one unchanged entry at revision 2", result)
	}
}

func TestReconcileNodeReportsPolicyRuleMetricsTelemetry(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	endpointID := model.EndpointKey("prod", "pod-a")
	allowEntry := dataplane.PolicyMapEntry{Value: dataplane.PolicyEntry{RuleCookie: 42, Log: 1}}
	dropEntry := dataplane.PolicyMapEntry{Value: dataplane.PolicyEntry{RuleCookie: 7, Deny: 1}}
	recorder := dataplane.NewPolicyRecorder()
	recorder.Observe(endpointID, dataplane.Packet{Bytes: 128}, dataplane.Decision{Verdict: dataplane.VerdictAllow, Match: &allowEntry})
	recorder.Observe(endpointID, dataplane.Packet{Bytes: 256}, dataplane.Decision{Verdict: dataplane.VerdictDrop, Match: &dropEntry})

	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:            "node-a",
		Store:           store,
		PolicyTelemetry: recorder,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyRulePackets != 2 || result.PolicyRuleBytes != 384 || result.PolicyRuleAllowed != 1 || result.PolicyRuleDropped != 1 || result.PolicyRuleRejected != 0 || result.PolicyRuleLogged != 1 {
		t.Fatalf("policy rule metric summary = %+v", result)
	}
	if len(result.PolicyRuleStats) != 2 {
		t.Fatalf("policy rule stats = %+v, want two rule buckets", result.PolicyRuleStats)
	}
	if result.PolicyRuleStats[0].EndpointID != endpointID || result.PolicyRuleStats[0].RuleCookie != 7 || result.PolicyRuleStats[0].Dropped != 1 {
		t.Fatalf("first rule stats = %+v, want drop cookie 7", result.PolicyRuleStats[0])
	}
	if result.PolicyRuleStats[1].EndpointID != endpointID || result.PolicyRuleStats[1].RuleCookie != 42 || result.PolicyRuleStats[1].Allowed != 1 || result.PolicyRuleStats[1].Logged != 1 {
		t.Fatalf("second rule stats = %+v, want logged allow cookie 42", result.PolicyRuleStats[1])
	}
}

func TestReconcilerReportsTCXRuleMetricsTelemetry(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	reconciler.attach = func(_ context.Context, target tcxTarget) (tcxAttachmentHandle, error) {
		return tcxAttachmentHandle{
			result: dataplane.TCXSelfTestResult{Interface: target.ifName, Direction: "egress", Mode: "policy-l4"},
			close:  func() error { return nil },
			metrics: func(context.Context) ([]dataplane.RuleMetrics, error) {
				return []dataplane.RuleMetrics{{
					RuleCookie: 42,
					Packets:    2,
					Bytes:      128,
					Dropped:    2,
					DenyDrops:  2,
				}}, nil
			},
		}, nil
	}

	result, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{
		Node:        "node-a",
		TCXWorkload: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	endpointID := model.EndpointKey("prod", "pod-a")
	if result.PolicyRulePackets != 2 || result.PolicyRuleBytes != 128 || result.PolicyRuleDropped != 2 || result.PolicyRuleAllowed != 0 {
		t.Fatalf("policy rule metric summary = %+v", result)
	}
	if len(result.PolicyRuleStats) != 1 {
		t.Fatalf("policy rule stats = %+v, want one tcx rule bucket", result.PolicyRuleStats)
	}
	if result.PolicyRuleStats[0].EndpointID != endpointID || result.PolicyRuleStats[0].RuleCookie != 42 || result.PolicyRuleStats[0].DenyDrops != 2 {
		t.Fatalf("tcx rule stats = %+v, want endpoint-labelled drop counters", result.PolicyRuleStats[0])
	}
}

func TestReconcileNodeReportsPolicyMapPressureSummary(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	store := &usagePolicyStore{
		InMemoryPolicyStore: dataplane.NewInMemoryPolicyStore(),
		usages: []dataplane.PolicyMapUsage{
			{EndpointID: model.EndpointKey("prod", "pod-a"), Entries: 12, Capacity: 16},
			{EndpointID: model.EndpointKey("prod", "pod-b"), Entries: 8, Capacity: 16},
		},
		drift: []dataplane.PolicyMapDrift{
			{EndpointID: model.EndpointKey("prod", "pod-a"), Missing: 1, Extra: 2, Changed: 3, Drifted: true},
			{EndpointID: model.EndpointKey("prod", "pod-b")},
		},
		statuses: []dataplane.PolicyEndpointStatus{
			{
				EndpointID:      model.EndpointKey("prod", "pod-a"),
				Revision:        7,
				Entries:         12,
				Capacity:        16,
				PressurePercent: 75,
				Drift:           dataplane.PolicyMapDrift{EndpointID: model.EndpointKey("prod", "pod-a"), Missing: 1, Extra: 2, Changed: 3, Drifted: true},
				LastStats:       dataplane.PolicyUpdateStats{Revision: 7, Updated: 1},
				LastEvent:       dataplane.PolicyUpdateEvent{EndpointID: model.EndpointKey("prod", "pod-a"), Revision: 7, Success: true},
				HasLastEvent:    true,
			},
		},
	}
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyMapEntries != 20 || result.PolicyMapCapacity != 32 {
		t.Fatalf("policy map totals = %+v, want entries 20 capacity 32", result)
	}
	if result.PolicyMapPressureMax != 75 {
		t.Fatalf("policy map pressure max = %d, want 75", result.PolicyMapPressureMax)
	}
	if result.PolicyMapPressureEndpoint != model.EndpointKey("prod", "pod-a") {
		t.Fatalf("policy map pressure endpoint = %q, want pod-a", result.PolicyMapPressureEndpoint)
	}
	if result.PolicyMapPressureEndpoints != 0 {
		t.Fatalf("policy map pressure endpoints = %d, want 0", result.PolicyMapPressureEndpoints)
	}
	if result.PolicyMapDriftEndpoints != 1 || result.PolicyMapDriftMissing != 1 || result.PolicyMapDriftExtra != 2 || result.PolicyMapDriftChanged != 3 {
		t.Fatalf("policy map drift summary = %+v, want one drifted endpoint", result)
	}
	if len(result.PolicyEndpointStatus) != 1 || result.PolicyEndpointStatus[0].EndpointID != model.EndpointKey("prod", "pod-a") || result.PolicyEndpointStatus[0].Revision != 7 || !result.PolicyEndpointStatus[0].Drift.Drifted || !result.PolicyEndpointStatus[0].HasLastEvent {
		t.Fatalf("policy endpoint status = %+v, want endpoint lifecycle status", result.PolicyEndpointStatus)
	}

	store.usages = []dataplane.PolicyMapUsage{
		{EndpointID: model.EndpointKey("prod", "pod-a"), Entries: 13, Capacity: 16},
	}
	result, err = ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyMapPressureMax != 81 || result.PolicyMapPressureEndpoint != model.EndpointKey("prod", "pod-a") || result.PolicyMapPressureEndpoints != 1 {
		t.Fatalf("pressure summary = %+v, want one pressured endpoint at 81%%", result)
	}
}

func TestPrepareReconcileWithTCXInterfaceAcceptsPortRangePolicy(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"range-web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "range-web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-range",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 8080, To: 8088}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	result, targets, _, err := prepareReconcile(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "lo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TCXEligible != 1 || len(targets) != 1 {
		t.Fatalf("tcx eligible/targets = %d/%d, want range policy target", result.TCXEligible, len(targets))
	}
	rules, err := dataplane.IPv4L4ACLRulesFromProgramsForDirection(targets[0].programs, model.DirectionIngress)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("tcx range rules = %+v, want two port-prefix blocks", rules)
	}
}

func TestReconcileNodeWithTCXInterfaceAcceptsCIDRPolicy(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"wide-web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "wide-web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-wide",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: dataplane.NewInMemoryPolicyStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TCXEligible != 1 {
		t.Fatalf("tcx eligible = %d, want 1 for CIDR policy", result.TCXEligible)
	}
}

func TestPrepareReconcileWithTCXInterfaceBuildsDualStackTarget(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"dual-web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "dual-web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{
				{
					ID:         "drop-v6",
					Priority:   200,
					Direction:  model.DirectionIngress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("fd00:20::/64"),
					Ports:      []model.PortRange{{From: 8080, To: 8080}},
					Action:     model.ActionDrop,
				},
				{
					ID:         "drop-v4",
					Priority:   100,
					Direction:  model.DirectionIngress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
					Ports:      []model.PortRange{{From: 8080, To: 8080}},
					Action:     model.ActionDrop,
				},
			},
		}},
	}
	result, targets, _, err := prepareReconcile(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "lo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 2 || result.TCXEligible != 1 {
		t.Fatalf("result = %+v, want both policy entries and one TCX-eligible program", result)
	}
	if len(targets) != 1 || targets[0].policyDirection != model.DirectionIngress {
		t.Fatalf("targets = %+v, want ingress TCX target for dual-stack policy", targets)
	}
	v4Rules, err := dataplane.IPv4L4ACLRulesFromProgramsForDirection(targets[0].programs, model.DirectionIngress)
	if err != nil {
		t.Fatalf("IPv4 TCX rules: %v", err)
	}
	if len(v4Rules) != 1 || v4Rules[0].SourceCIDR != netip.MustParsePrefix("172.30.0.0/24") {
		t.Fatalf("IPv4 TCX rules = %+v, want IPv4 CIDR rule", v4Rules)
	}
	v6Rules, err := dataplane.IPv6L4ACLRulesFromProgramsForDirection(targets[0].programs, model.DirectionIngress)
	if err != nil {
		t.Fatalf("IPv6 TCX rules: %v", err)
	}
	if len(v6Rules) != 1 || v6Rules[0].SourceCIDR != netip.MustParsePrefix("fd00:20::/64") {
		t.Fatalf("IPv6 TCX rules = %+v, want IPv6 CIDR rule", v6Rules)
	}
}

func TestPrepareReconcileWithTCXInterfaceAcceptsIPv6OnlyPolicy(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("fd00:10::10"),
			Node:           "node-a",
			SecurityGroups: []string{"v6-web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "v6-web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-v6",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("fd00:20::/64"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	result, targets, _, err := prepareReconcile(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "lo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 1 {
		t.Fatalf("result = %+v, want IPv6 policy entry and one TCX-eligible program", result)
	}
	if len(targets) != 1 || targets[0].policyDirection != model.DirectionIngress {
		t.Fatalf("targets = %+v, want ingress TCX target for IPv6 policy", targets)
	}
	v6Rules, err := dataplane.IPv6L4ACLRulesFromProgramsForDirection(targets[0].programs, model.DirectionIngress)
	if err != nil {
		t.Fatalf("IPv6 TCX rules: %v", err)
	}
	if len(v6Rules) != 1 || v6Rules[0].SourceCIDR != netip.MustParsePrefix("fd00:20::/64") {
		t.Fatalf("IPv6 TCX rules = %+v, want IPv6 CIDR rule", v6Rules)
	}
}

func TestTCXTargetsBuildsOneEgressTargetPerWorkload(t *testing.T) {
	targets, err := tcxTargets(ReconcileOptions{TCXWorkload: true}, []policy.Program{
		tcxProgram("pod-a", model.DirectionIngress, "172.30.0.11/32", 8080),
		tcxProgram("pod-b", model.DirectionIngress, "172.30.0.12/32", 8080),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	for i, target := range targets {
		if target.attach != ebpf.AttachTCXEgress {
			t.Fatalf("target %d attach = %v, want egress", i, target.attach)
		}
		if target.policyDirection != model.DirectionIngress {
			t.Fatalf("target %d policy direction = %s, want ingress", i, target.policyDirection)
		}
		if len(target.programs) != 1 {
			t.Fatalf("target %d programs = %d, want 1", i, len(target.programs))
		}
	}
	if targets[0].ifName == targets[1].ifName {
		t.Fatalf("expected distinct host veth names, got %s", targets[0].ifName)
	}
}

func TestTCXTargetsBuildsIngressTargetForWorkloadEgressPolicy(t *testing.T) {
	targets, err := tcxTargets(ReconcileOptions{TCXWorkload: true}, []policy.Program{
		tcxProgram("pod-a", model.DirectionEgress, "198.51.100.10/32", 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(targets))
	}
	target := targets[0]
	if target.attach != ebpf.AttachTCXIngress || target.policyDirection != model.DirectionEgress {
		t.Fatalf("unexpected target attach=%v policy_direction=%s", target.attach, target.policyDirection)
	}
	if target.ifName == "" || len(target.programs) != 1 {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestTCXTargetsBuildsSingleIngressTargetForNodeInterface(t *testing.T) {
	programs := []policy.Program{
		tcxProgram("pod-a", model.DirectionIngress, "172.30.0.11/32", 8080),
	}
	targets, err := tcxTargets(ReconcileOptions{TCXInterface: "eth0"}, programs)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(targets))
	}
	target := targets[0]
	if target.ifName != "eth0" || target.attach != ebpf.AttachTCXIngress || target.policyDirection != model.DirectionIngress || len(target.programs) != 1 {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestTCXTargetsBuildsSingleEgressTargetForNodeInterface(t *testing.T) {
	programs := []policy.Program{
		tcxProgram("pod-a", model.DirectionEgress, "198.51.100.10/32", 443),
	}
	targets, err := tcxTargets(ReconcileOptions{TCXInterface: "eth0"}, programs)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(targets))
	}
	target := targets[0]
	if target.ifName != "eth0" || target.attach != ebpf.AttachTCXEgress || target.policyDirection != model.DirectionEgress || len(target.programs) != 1 {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestTCXTargetsBuildsIngressAndEgressTargetsForSingleNodeInterfaceEndpoint(t *testing.T) {
	programs := []policy.Program{
		tcxProgram("pod-a", model.DirectionIngress, "172.30.0.11/32", 8080),
		tcxProgram("pod-a", model.DirectionEgress, "198.51.100.10/32", 443),
	}
	targets, err := tcxTargets(ReconcileOptions{TCXInterface: "eth0"}, programs)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	if targets[0].attach != ebpf.AttachTCXIngress || targets[0].policyDirection != model.DirectionIngress {
		t.Fatalf("first target = %+v, want ingress attach for ingress policy", targets[0])
	}
	if targets[1].attach != ebpf.AttachTCXEgress || targets[1].policyDirection != model.DirectionEgress {
		t.Fatalf("second target = %+v, want egress attach for egress policy", targets[1])
	}
}

func TestTCXTargetsBuildsSingleIngressTargetForMultipleNodeInterfaceEndpoints(t *testing.T) {
	programs := []policy.Program{
		tcxProgram("pod-a", model.DirectionIngress, "172.30.0.11/32", 8080),
		tcxProgram("pod-b", model.DirectionIngress, "172.30.0.12/32", 8080),
	}
	targets, err := tcxTargets(ReconcileOptions{TCXInterface: "eth0"}, programs)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want one aggregated ingress target", len(targets))
	}
	target := targets[0]
	if target.attach != ebpf.AttachTCXIngress || target.policyDirection != model.DirectionIngress || len(target.programs) != 2 {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestTCXTargetsBuildsSingleEgressTargetForMultipleNodeInterfaceEndpoints(t *testing.T) {
	programs := []policy.Program{
		tcxProgram("pod-a", model.DirectionEgress, "198.51.100.10/32", 443),
		tcxProgram("pod-b", model.DirectionEgress, "198.51.100.11/32", 443),
	}
	targets, err := tcxTargets(ReconcileOptions{TCXInterface: "eth0"}, programs)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want one aggregated egress target", len(targets))
	}
	target := targets[0]
	if target.attach != ebpf.AttachTCXEgress || target.policyDirection != model.DirectionEgress || len(target.programs) != 2 {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestAttachTCXTargetsReportsNotAttachedForEmptyTargets(t *testing.T) {
	status, stats, metrics, err := attachTCXTargets(context.Background(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if stats != (tcxUpdateStats{}) {
		t.Fatalf("stats = %+v, want zero-value", stats)
	}
	if status != "not-attached" {
		t.Fatalf("status = %q, want not-attached", status)
	}
	if len(metrics) != 0 {
		t.Fatalf("metrics = %+v, want none", metrics)
	}
}

func TestReconcilerTCXAttachmentErrorIncludesTargetContext(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	reconciler.attach = func(context.Context, tcxTarget) (tcxAttachmentHandle, error) {
		return tcxAttachmentHandle{}, fmt.Errorf("kernel attach failed")
	}
	_, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		TCXInterface: "lo",
	})
	if err == nil {
		t.Fatal("expected tcx attachment error")
	}
	if !strings.Contains(err.Error(), "attach tcx target") || !strings.Contains(err.Error(), "iface=lo") || !strings.Contains(err.Error(), "direction=ingress") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReconcilerSyncTCXTargetsRollsBackOnFailure(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	options := ReconcileOptions{Node: "node-a", TCXWorkload: true}
	var attachCalls int
	var closeCalls int
	reconciler.attach = func(_ context.Context, target tcxTarget) (tcxAttachmentHandle, error) {
		attachCalls++
		if attachCalls == 3 {
			return tcxAttachmentHandle{}, fmt.Errorf("simulated attach failure")
		}
		return tcxAttachmentHandle{
			result: dataplane.TCXSelfTestResult{Interface: target.ifName, Direction: "egress", Mode: "policy-l4"},
			close: func() error {
				closeCalls++
				return nil
			},
		}, nil
	}
	if _, err := reconciler.Reconcile(context.Background(), state, options); err != nil {
		t.Fatal(err)
	}
	podA := model.EndpointKey("prod", "pod-a")
	podB := model.EndpointKey("prod", "pod-b")
	firstKey := tcxTargetKey(tcxTarget{ifName: linuxdatapath.HostVethName(podA), attach: ebpf.AttachTCXEgress, policyDirection: model.DirectionIngress})
	firstAttachment, ok := reconciler.attachments[firstKey]
	if !ok {
		t.Fatalf("expected first attachment %s to exist", firstKey)
	}
	firstSignature := firstAttachment.signature

	state.Endpoints = append(state.Endpoints, model.Endpoint{
		ID:             "pod-b",
		VPC:            "prod",
		Subnet:         "apps",
		IP:             netip.MustParseAddr("10.10.0.11"),
		Node:           "node-a",
		SecurityGroups: []string{"web"},
	})
	state.Endpoints[0].IP = netip.MustParseAddr("10.10.0.20")
	state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.MustParsePrefix("172.30.0.12/32")

	result, err := reconciler.Reconcile(context.Background(), state, options)
	if err == nil {
		t.Fatal("expected reconcile failure during partial attachment update")
	}
	if result.TCXFailed != 1 || result.TCXRollbacks != 1 {
		t.Fatalf("tcx failure summary = %+v, want one failure and one rollback", result)
	}
	if result.TCXFailedTarget == "" || !strings.Contains(result.TCXFailedTarget, "direction=ingress") {
		t.Fatalf("tcx failed target = %q, want ingress target label", result.TCXFailedTarget)
	}
	if !strings.Contains(result.TCXLastError, "simulated attach failure") {
		t.Fatalf("tcx last error = %q, want attach failure", result.TCXLastError)
	}
	if attachCalls != 3 || closeCalls != 1 {
		t.Fatalf("unexpected attach/close counters after partial failure: attaches=%d closes=%d", attachCalls, closeCalls)
	}
	rolledBack, ok := reconciler.attachments[firstKey]
	if !ok {
		t.Fatalf("first attachment key %s was removed after failure", firstKey)
	}
	if rolledBack.signature != firstSignature {
		t.Fatalf("expected attachment %s signature to be rolled back, before=%q after=%q", firstKey, firstSignature, rolledBack.signature)
	}
	if len(reconciler.attachments) != 1 {
		t.Fatalf("expected only first attachment to remain after rollback, got=%d", len(reconciler.attachments))
	}

	_, err = reconciler.Reconcile(context.Background(), state, options)
	if err != nil {
		t.Fatal(err)
	}
	secondKey := tcxTargetKey(tcxTarget{ifName: linuxdatapath.HostVethName(podB), attach: ebpf.AttachTCXEgress, policyDirection: model.DirectionIngress})
	if _, ok := reconciler.attachments[secondKey]; !ok {
		t.Fatalf("expected second attachment %s to be attached after successful reconcile", secondKey)
	}
	if attachCalls != 5 {
		t.Fatalf("unexpected attach counter after successful reconcile: %d", attachCalls)
	}
}

func TestReconcileNodeWithTCXInterfaceReportsAttachFailureSignals(t *testing.T) {
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	reconciler.attach = func(context.Context, tcxTarget) (tcxAttachmentHandle, error) {
		return tcxAttachmentHandle{}, fmt.Errorf("kernel attach failed")
	}
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	result, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a", TCXInterface: "eth0"})
	if err == nil {
		t.Fatal("expected tcx attach failure")
	}
	if result.TCXEligible != 1 || result.TCXFailed != 1 || result.TCXRollbacks != 0 {
		t.Fatalf("result = %+v, want one tcx-eligible failure without rollback", result)
	}
	if !strings.Contains(result.TCXFailedTarget, "iface=eth0") || !strings.Contains(result.TCXFailedTarget, "direction=ingress") {
		t.Fatalf("tcx failed target = %q, want eth0 ingress target", result.TCXFailedTarget)
	}
	if !strings.Contains(result.TCXLastError, "kernel attach failed") {
		t.Fatalf("tcx last error = %q, want kernel attach failure", result.TCXLastError)
	}
}

func TestReconcileNodeWithTCXInterfaceAllowsNoEligiblePolicy(t *testing.T) {
	result, err := ReconcileNodeWithOptions(context.Background(), control.DesiredState{}, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "lo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TCX != "not-attached" || result.TCXEligible != 0 {
		t.Fatalf("result = %+v, want no eligible TCX policy and not-attached", result)
	}
}

func TestReconcileNodeWithTCXInterfaceTreatsAllowOnlyPolicyAsNotEligible(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionAllow,
			}},
		}},
	}

	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "lo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 0 || result.TCX != "not-attached" {
		t.Fatalf("result = %+v, want policy stored but allow-only TCX not attached", result)
	}
}

func TestPrepareReconcileProjectsRejectActionToTCXDrop(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "reject-web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionReject,
			}},
		}},
	}

	result, targets, _, err := prepareReconcile(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "lo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 1 {
		t.Fatalf("result = %+v, want reject policy to be TCX eligible", result)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want one ingress tcx target", len(targets))
	}
	if targets[0].attach != ebpf.AttachTCXIngress || targets[0].policyDirection != model.DirectionIngress {
		t.Fatalf("target = %+v, want ingress tcx attach for reject rule", targets[0])
	}
	rules, err := dataplane.IPv4L4ACLRulesFromProgramsForDirection(targets[0].programs, model.DirectionIngress)
	if err != nil {
		t.Fatalf("ingress tcx rules: %v", err)
	}
	if len(rules) != 1 || rules[0].SourceCIDR != netip.MustParsePrefix("172.30.0.11/32") || rules[0].DestPort != 8080 || rules[0].Action != dataplane.TCXDrop {
		t.Fatalf("ingress tcx rules = %+v, want reject projected as exact tcp/8080 drop", rules)
	}
}

func TestPrepareReconcileKeepsBothDirectionsEligibleWhenOneUsesReject(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"mixed"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "mixed",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{
				{
					ID:         "reject-web",
					Priority:   100,
					Direction:  model.DirectionIngress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
					Ports:      []model.PortRange{{From: 8080, To: 8080}},
					Action:     model.ActionReject,
				},
				{
					ID:         "drop-egress-https",
					Priority:   100,
					Direction:  model.DirectionEgress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("198.51.100.10/32"),
					Ports:      []model.PortRange{{From: 443, To: 443}},
					Action:     model.ActionDrop,
				},
			},
		}},
	}

	result, targets, _, err := prepareReconcile(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "eth0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 2 || result.TCXEligible != 1 {
		t.Fatalf("result = %+v, want one tcx-eligible program with both rules stored", result)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want ingress and egress tcx targets", len(targets))
	}
	if targets[0].attach != ebpf.AttachTCXIngress || targets[0].policyDirection != model.DirectionIngress {
		t.Fatalf("first target = %+v, want interface ingress attach for ingress reject direction", targets[0])
	}
	ingressRules, err := dataplane.IPv4L4ACLRulesFromProgramsForDirection(targets[0].programs, model.DirectionIngress)
	if err != nil {
		t.Fatalf("ingress tcx rules: %v", err)
	}
	if len(ingressRules) != 1 || ingressRules[0].SourceCIDR != netip.MustParsePrefix("172.30.0.11/32") || ingressRules[0].DestPort != 8080 || ingressRules[0].Action != dataplane.TCXDrop {
		t.Fatalf("ingress tcx rules = %+v, want reject projected as exact web drop rule", ingressRules)
	}
	if targets[1].attach != ebpf.AttachTCXEgress || targets[1].policyDirection != model.DirectionEgress {
		t.Fatalf("second target = %+v, want interface egress attach for egress drop direction", targets[1])
	}
	egressRules, err := dataplane.IPv4L4ACLRulesFromProgramsForDirection(targets[1].programs, model.DirectionEgress)
	if err != nil {
		t.Fatalf("egress tcx rules: %v", err)
	}
	if len(egressRules) != 1 || egressRules[0].SourceCIDR != netip.MustParsePrefix("198.51.100.10/32") || egressRules[0].DestPort != 443 || egressRules[0].Action != dataplane.TCXDrop {
		t.Fatalf("egress tcx rules = %+v, want exact https drop rule", egressRules)
	}
}

func TestReconcileNodeWithTCXInterfaceAttachesEgressPolicy(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"client"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-egress-https",
				Priority:   100,
				Direction:  model.DirectionEgress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("198.51.100.10/32"),
				Ports:      []model.PortRange{{From: 443, To: 443}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	var attaches int
	reconciler.attach = func(_ context.Context, target tcxTarget) (tcxAttachmentHandle, error) {
		attaches++
		if target.ifName != "eth0" || target.attach != ebpf.AttachTCXEgress || target.policyDirection != model.DirectionEgress {
			t.Fatalf("unexpected target: %+v", target)
		}
		return tcxAttachmentHandle{
			result: dataplane.TCXSelfTestResult{Interface: target.ifName, Direction: "egress", Mode: "policy-l4"},
			close:  func() error { return nil },
		}, nil
	}
	result, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "eth0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if attaches != 1 || result.TCXEligible != 1 || result.TCX != "attached:eth0:egress:policy-l4" {
		t.Fatalf("result/attaches = %+v/%d, want one egress attachment on eth0", result, attaches)
	}
}

func TestReconcileNodeWithTCXInterfaceAttachesBothDirectionsForSingleEndpoint(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{
				{
					ID:         "drop-http-ingress",
					Priority:   100,
					Direction:  model.DirectionIngress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
					Ports:      []model.PortRange{{From: 8080, To: 8080}},
					Action:     model.ActionDrop,
				},
				{
					ID:         "drop-https-egress",
					Priority:   100,
					Direction:  model.DirectionEgress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("198.51.100.10/32"),
					Ports:      []model.PortRange{{From: 443, To: 443}},
					Action:     model.ActionDrop,
				},
			},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	var gotTargets []tcxTarget
	reconciler.attach = func(_ context.Context, target tcxTarget) (tcxAttachmentHandle, error) {
		gotTargets = append(gotTargets, target)
		return tcxAttachmentHandle{
			result: dataplane.TCXSelfTestResult{
				Interface: target.ifName,
				Direction: map[model.Direction]string{
					model.DirectionIngress: "ingress",
					model.DirectionEgress:  "egress",
				}[target.policyDirection],
				Mode: "policy-l4",
			},
			close: func() error { return nil },
		}, nil
	}
	result, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "eth0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotTargets) != 2 {
		t.Fatalf("targets = %d, want 2", len(gotTargets))
	}
	if result.TCXEligible != 1 || result.TCX != "attached:eth0:mixed:policy-l4" {
		t.Fatalf("result = %+v, want mixed-direction attachment on shared interface", result)
	}
}

func TestReconcileNodeWithTCXProjectsRemoteEndpointPolicyByCIDR(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "pod-a",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.10"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
			{
				ID:             "pod-b",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.11"),
				Node:           "node-b",
				SecurityGroups: []string{"client"},
			},
		},
		SecurityGroups: []model.SecurityGroup{
			{
				Name: "web",
				VPC:  "prod",
				Rules: []model.SecurityGroupRule{{
					ID:          "drop-client",
					Priority:    100,
					Direction:   model.DirectionIngress,
					Protocol:    model.ProtocolTCP,
					RemoteGroup: "client",
					Ports:       []model.PortRange{{From: 8080, To: 8080}},
					Action:      model.ActionDrop,
				}},
			},
			{Name: "client", VPC: "prod"},
		},
	}

	store := dataplane.NewInMemoryPolicyStore()
	result, targets, programs, err := prepareReconcile(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        store,
		TCXInterface: "lo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 1 {
		t.Fatalf("result = %+v, want remote-group drop to be TCX eligible", result)
	}
	if len(targets) != 1 || len(programs) != 1 {
		t.Fatalf("targets/programs = %d/%d, want one TCX target and program", len(targets), len(programs))
	}
	rules, err := dataplane.IPv4L4ACLRulesFromProgram(programs[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].SourceCIDR != netip.MustParsePrefix("10.10.0.11/32") || rules[0].DestPort != 8080 || rules[0].Action != dataplane.TCXDrop {
		t.Fatalf("remote endpoint TCX rules = %+v, want exact remote endpoint /32 tcp/8080 drop", rules)
	}
}

func TestReconcilerKeepsAndReplacesTCXAttachments(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "pod-a",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.10"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
			{
				ID:             "pod-b",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.11"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	var attaches int
	var closes int
	reconciler.attach = func(_ context.Context, target tcxTarget) (tcxAttachmentHandle, error) {
		attaches++
		return tcxAttachmentHandle{
			result: dataplane.TCXSelfTestResult{Interface: target.ifName, Direction: "egress", Mode: "policy-l4"},
			close: func() error {
				closes++
				return nil
			},
		}, nil
	}
	options := ReconcileOptions{Node: "node-a", TCXWorkload: true}
	result, err := reconciler.Reconcile(context.Background(), state, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.TCX != "attached-workloads:2:egress:policy-l4" || attaches != 2 || closes != 0 {
		t.Fatalf("unexpected first reconcile result=%+v attaches=%d closes=%d", result, attaches, closes)
	}
	if _, err := reconciler.Reconcile(context.Background(), state, options); err != nil {
		t.Fatal(err)
	}
	if attaches != 2 || closes != 0 {
		t.Fatalf("expected unchanged reconcile to keep attachments, attaches=%d closes=%d", attaches, closes)
	}
	state.SecurityGroups[0].Rules[0].Action = model.ActionAllow
	result, err = reconciler.Reconcile(context.Background(), state, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.TCX != "not-attached" || attaches != 2 || closes != 2 {
		t.Fatalf("expected allow-only policy change to close attachments, result=%+v attaches=%d closes=%d", result, attaches, closes)
	}
	state.Endpoints = state.Endpoints[:1]
	if _, err := reconciler.Reconcile(context.Background(), state, options); err != nil {
		t.Fatal(err)
	}
	if attaches != 2 || closes != 2 {
		t.Fatalf("expected no stale attachment left to close, attaches=%d closes=%d", attaches, closes)
	}
	if err := reconciler.Close(); err != nil {
		t.Fatal(err)
	}
	if closes != 2 {
		t.Fatalf("final closes = %d, want 2", closes)
	}
}

func TestReconcilerClosesTCXAttachmentsWhenPolicyNoLongerEligible(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	var attaches int
	var closes int
	reconciler.attach = func(_ context.Context, target tcxTarget) (tcxAttachmentHandle, error) {
		attaches++
		return tcxAttachmentHandle{
			result: dataplane.TCXSelfTestResult{Interface: target.ifName, Direction: "egress", Mode: "policy-l4"},
			close: func() error {
				closes++
				return nil
			},
		}, nil
	}
	options := ReconcileOptions{Node: "node-a", TCXWorkload: true}
	result, err := reconciler.Reconcile(context.Background(), state, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.TCX != "attached:"+linuxdatapath.HostVethName(model.EndpointKey("prod", "pod-a"))+":egress:policy-l4" || attaches != 1 || closes != 0 {
		t.Fatalf("unexpected first reconcile result=%+v attaches=%d closes=%d", result, attaches, closes)
	}

	state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.Prefix{}
	state.SecurityGroups[0].Rules[0].RemoteGroup = "client"
	state.SecurityGroups = append(state.SecurityGroups, model.SecurityGroup{Name: "client", VPC: "prod"})
	result, err = reconciler.Reconcile(context.Background(), state, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.TCX != "not-attached" {
		t.Fatalf("tcx = %q, want not-attached", result.TCX)
	}
	if attaches != 1 || closes != 1 {
		t.Fatalf("expected stale attachment to close without reattach, attaches=%d closes=%d", attaches, closes)
	}
	if err := reconciler.Close(); err != nil {
		t.Fatal(err)
	}
	if closes != 1 {
		t.Fatalf("close should not close already removed attachments again, closes=%d", closes)
	}
}

func TestReconcilerTCXEligibilityFollowsPriorityConflictOutcome(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{
				{
					ID:         "allow-http",
					Priority:   200,
					Direction:  model.DirectionIngress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
					Ports:      []model.PortRange{{From: 8080, To: 8080}},
					Action:     model.ActionAllow,
				},
				{
					ID:         "drop-http",
					Priority:   100,
					Direction:  model.DirectionIngress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
					Ports:      []model.PortRange{{From: 8080, To: 8080}},
					Action:     model.ActionDrop,
				},
			},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	result, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	if result.TCXEligible != 1 {
		t.Fatalf("deny-winning policy tcx eligible = %d, want 1", result.TCXEligible)
	}

	state.SecurityGroups[0].Rules[0].Priority = 100
	state.SecurityGroups[0].Rules[1].Priority = 200
	result, err = reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	if result.TCXEligible != 0 {
		t.Fatalf("allow-winning policy tcx eligible = %d, want 0", result.TCXEligible)
	}
}

func TestReconcilerClearsConntrackWhenPolicyChangesOrEndpointIsRemoved(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("10.10.0.11/32"),
				Ports:      []model.PortRange{{From: 443, To: 443}},
				Action:     model.ActionAllow,
				Stateful:   true,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	reconciler.ConntrackStore().Add(dataplane.ConntrackKey{
		EndpointID:     model.EndpointKey("prod", "pod-a"),
		RemoteIdentity: 100,
		Direction:      dataplane.DirectionEgress,
		Protocol:       6,
		DestPort:       55000,
	})
	if reconciler.ConntrackStore().Len() != 1 {
		t.Fatalf("conntrack entries = %d, want 1", reconciler.ConntrackStore().Len())
	}

	state.SecurityGroups[0].Rules[0].Action = model.ActionDrop
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if reconciler.ConntrackStore().Len() != 0 {
		t.Fatalf("conntrack entries after policy change = %d, want 0", reconciler.ConntrackStore().Len())
	}

	reconciler.ConntrackStore().Add(dataplane.ConntrackKey{
		EndpointID:     model.EndpointKey("prod", "pod-a"),
		RemoteIdentity: 100,
		Direction:      dataplane.DirectionEgress,
		Protocol:       6,
		DestPort:       55000,
	})
	state.Endpoints = nil
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if reconciler.ConntrackStore().Len() != 0 {
		t.Fatalf("conntrack entries after endpoint removal = %d, want 0", reconciler.ConntrackStore().Len())
	}
}

func TestReconcilerClearsConntrackForNonTCXPolicyChange(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-any-cidr",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolAny,
				RemoteCIDR: netip.MustParsePrefix("10.10.0.11/32"),
				Action:     model.ActionAllow,
				Stateful:   true,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if tcxEligibleProgramForDirection(policy.Program{
		EndpointID: model.EndpointKey("prod", "pod-a"),
		Rules: []policy.Rule{{
			ID:         "allow-any-cidr",
			Direction:  model.DirectionIngress,
			Protocol:   model.ProtocolAny,
			RemoteCIDR: netip.MustParsePrefix("10.10.0.11/32"),
			Action:     model.ActionAllow,
			Stateful:   true,
		}},
	}, model.DirectionIngress) {
		t.Fatal("test policy should not be TCX eligible")
	}

	reconciler.ConntrackStore().Add(dataplane.ConntrackKey{
		EndpointID:     model.EndpointKey("prod", "pod-a"),
		RemoteIdentity: 100,
		Direction:      dataplane.DirectionEgress,
		Protocol:       6,
		DestPort:       55000,
	})
	state.SecurityGroups[0].Rules[0].Action = model.ActionDrop
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	if reconciler.ConntrackStore().Len() != 0 {
		t.Fatalf("conntrack entries after non-TCX policy change = %d, want 0", reconciler.ConntrackStore().Len())
	}
}

func TestReconcilerExpiresIdleConntrack(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-web",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("10.10.0.11/32"),
				Ports:      []model.PortRange{{From: 443, To: 443}},
				Action:     model.ActionAllow,
				Stateful:   true,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{Node: "node-a"}); err != nil {
		t.Fatal(err)
	}
	reconciler.ConntrackStore().Add(dataplane.ConntrackKey{
		EndpointID:     model.EndpointKey("prod", "pod-a"),
		RemoteIdentity: 100,
		Direction:      dataplane.DirectionEgress,
		Protocol:       6,
		DestPort:       55000,
	})
	time.Sleep(time.Millisecond)

	result, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{
		Node:          "node-a",
		ConntrackIdle: time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ConntrackExpired != 1 || reconciler.ConntrackStore().Len() != 0 {
		t.Fatalf("conntrack expired=%d remaining=%d, want one idle entry expired", result.ConntrackExpired, reconciler.ConntrackStore().Len())
	}
}

func TestReconcileNodeAllowsMultipleEligibleWorkloadsWithoutTCXAttach(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "pod-a",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.10"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
			{
				ID:             "pod-b",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.11"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	result, err := ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err != nil {
		t.Fatal(err)
	}
	if result.TCXEligible != 2 {
		t.Fatalf("tcx eligible = %d, want 2", result.TCXEligible)
	}
}

func TestReconcileNodeWithTCXInterfaceAggregatesMultipleEligibleIngressEndpoints(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "pod-a",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.10"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
			{
				ID:             "pod-b",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.11"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	reconciler := NewReconciler(dataplane.NewInMemoryPolicyStore())
	var gotTarget tcxTarget
	var attaches int
	reconciler.attach = func(_ context.Context, target tcxTarget) (tcxAttachmentHandle, error) {
		attaches++
		gotTarget = target
		return tcxAttachmentHandle{
			result: dataplane.TCXSelfTestResult{Interface: target.ifName, Direction: "ingress", Mode: "policy-l4"},
			close:  func() error { return nil },
		}, nil
	}
	result, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{
		Node:         "node-a",
		Store:        dataplane.NewInMemoryPolicyStore(),
		TCXInterface: "eth0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if attaches != 1 || gotTarget.attach != ebpf.AttachTCXIngress || gotTarget.policyDirection != model.DirectionIngress || len(gotTarget.programs) != 2 {
		t.Fatalf("unexpected attach target/result: target=%+v attaches=%d result=%+v", gotTarget, attaches, result)
	}
}

func TestReconcileNodeRejectsMissingNodeName(t *testing.T) {
	_, err := ReconcileNode(context.Background(), control.DesiredState{}, "", dataplane.NewInMemoryPolicyStore())
	if err == nil {
		t.Fatal("expected empty node name to fail")
	}
}

func TestReconcileNodeRejectsUnknownSecurityGroup(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"missing"},
		}},
	}
	_, err := ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err == nil {
		t.Fatal("expected unknown security group to fail")
	}
}

func TestReconcileNodeRejectsDuplicateSecurityGroups(t *testing.T) {
	state := control.DesiredState{
		SecurityGroups: []model.SecurityGroup{
			{Name: "web", VPC: "prod"},
			{Name: "web", VPC: "prod"},
		},
	}
	_, err := ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err == nil {
		t.Fatal("expected duplicate security groups to fail")
	}
	if !strings.Contains(err.Error(), "duplicate security group name") {
		t.Fatalf("error %q does not mention duplicate security group name", err)
	}
}

func TestReconcileNodeAllowsSameSecurityGroupNameAcrossVPCs(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
			{ID: "pod-b", VPC: "dev", Subnet: "apps-dev", IP: netip.MustParseAddr("10.20.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
		},
		SecurityGroups: []model.SecurityGroup{
			{
				Name: "web",
				VPC:  "prod",
				Rules: []model.SecurityGroupRule{{
					ID:         "prod-web",
					Priority:   100,
					Direction:  model.DirectionIngress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("198.51.100.10/32"),
					Ports:      []model.PortRange{{From: 443, To: 443}},
					Action:     model.ActionAllow,
				}},
			},
			{
				Name: "web",
				VPC:  "dev",
				Rules: []model.SecurityGroupRule{{
					ID:         "dev-web",
					Priority:   100,
					Direction:  model.DirectionIngress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("203.0.113.10/32"),
					Ports:      []model.PortRange{{From: 8443, To: 8443}},
					Action:     model.ActionAllow,
				}},
			},
		},
	}
	store := dataplane.NewInMemoryPolicyStore()
	if _, err := ReconcileNode(context.Background(), state, "node-a", store); err != nil {
		t.Fatalf("same security group name in different vpcs should validate: %v", err)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 || entries[0].RemoteCIDR != netip.MustParsePrefix("198.51.100.10/32") {
		t.Fatalf("pod-a entries = %+v, want prod security group entry", entries)
	}
	if entries := store.Entries(model.EndpointKey("dev", "pod-b")); len(entries) != 1 || entries[0].RemoteCIDR != netip.MustParsePrefix("203.0.113.10/32") {
		t.Fatalf("pod-b entries = %+v, want dev security group entry", entries)
	}
}

func TestReconcileNodeRejectsDuplicateEndpoints(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:     "pod-a",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.10"),
				Node:   "node-a",
			},
			{
				ID:     "pod-a",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.11"),
				Node:   "node-a",
			},
		},
	}
	_, err := ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err == nil {
		t.Fatal("expected duplicate endpoints to fail")
	}
	if !strings.Contains(err.Error(), "duplicate endpoint id") {
		t.Fatalf("error %q does not mention duplicate endpoint id", err)
	}
}

func TestReconcileNodeRejectsDuplicateLoadBalancers(t *testing.T) {
	state := control.DesiredState{
		LoadBalancers: []model.LoadBalancer{
			{
				Name: "api",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
				Ports: []model.LoadBalancerPort{{
					Port:     443,
					Protocol: model.ProtocolTCP,
					Backends: []model.LoadBalancerBackend{{
						IP:   netip.MustParseAddr("10.10.0.10"),
						Port: 8443,
					}},
				}},
			},
			{
				Name: "api",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.11"),
				Ports: []model.LoadBalancerPort{{
					Port:     443,
					Protocol: model.ProtocolTCP,
					Backends: []model.LoadBalancerBackend{{
						IP:   netip.MustParseAddr("10.10.0.11"),
						Port: 8443,
					}},
				}},
			},
		},
	}
	_, err := ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err == nil {
		t.Fatal("expected duplicate load balancers to fail")
	}
	if !strings.Contains(err.Error(), "duplicate load balancer") {
		t.Fatalf("error %q does not mention duplicate load balancer", err)
	}
}

func TestReconcileNodeRejectsDuplicateCIDRGroups(t *testing.T) {
	state := control.DesiredState{
		CIDRGroups: []model.CIDRGroup{
			{Name: "corp", VPC: "prod", CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}},
			{Name: "corp", VPC: "prod", CIDRs: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}},
		},
	}
	_, err := ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err == nil {
		t.Fatal("expected duplicate cidr groups to fail")
	}
	if !strings.Contains(err.Error(), "duplicate cidr group") {
		t.Fatalf("error %q does not mention duplicate cidr group", err)
	}
}

func TestReconcileNodeAllowsSameCIDRGroupNameAcrossVPCs(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"client"}},
			{ID: "pod-b", VPC: "dev", Subnet: "apps-dev", IP: netip.MustParseAddr("10.20.0.10"), Node: "node-a", SecurityGroups: []string{"client"}},
		},
		SecurityGroups: []model.SecurityGroup{
			{
				Name: "client",
				VPC:  "prod",
				Rules: []model.SecurityGroupRule{{
					ID:              "prod-corp",
					Priority:        100,
					Direction:       model.DirectionEgress,
					Protocol:        model.ProtocolTCP,
					RemoteCIDRGroup: "corp",
					Ports:           []model.PortRange{{From: 443, To: 443}},
					Action:          model.ActionAllow,
				}},
			},
			{
				Name: "client",
				VPC:  "dev",
				Rules: []model.SecurityGroupRule{{
					ID:              "dev-corp",
					Priority:        100,
					Direction:       model.DirectionEgress,
					Protocol:        model.ProtocolTCP,
					RemoteCIDRGroup: "corp",
					Ports:           []model.PortRange{{From: 443, To: 443}},
					Action:          model.ActionAllow,
				}},
			},
		},
		CIDRGroups: []model.CIDRGroup{
			{Name: "corp", VPC: "prod", CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}},
			{Name: "corp", VPC: "dev", CIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		},
	}
	store := dataplane.NewInMemoryPolicyStore()
	if _, err := ReconcileNode(context.Background(), state, "node-a", store); err != nil {
		t.Fatalf("same cidr group name in different vpcs should validate: %v", err)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 || entries[0].RemoteCIDR != netip.MustParsePrefix("198.51.100.0/24") {
		t.Fatalf("pod-a entries = %+v, want prod cidr group entry", entries)
	}
	if entries := store.Entries(model.EndpointKey("dev", "pod-b")); len(entries) != 1 || entries[0].RemoteCIDR != netip.MustParsePrefix("203.0.113.0/24") {
		t.Fatalf("pod-b entries = %+v, want dev cidr group entry", entries)
	}
}

func TestReconcileNodeExpandsRemoteGroupMembership(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "pod-a",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.10"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
			{
				ID:             "pod-b",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.11"),
				Node:           "node-b",
				SecurityGroups: []string{"clients"},
			},
		},
		SecurityGroups: []model.SecurityGroup{
			{
				Name: "web",
				VPC:  "prod",
				Rules: []model.SecurityGroupRule{{
					ID:          "drop-client-web",
					Priority:    100,
					Direction:   model.DirectionIngress,
					Protocol:    model.ProtocolTCP,
					RemoteGroup: "clients",
					Ports:       []model.PortRange{{From: 8080, To: 8080}},
					Action:      model.ActionDrop,
				}},
			},
			{Name: "clients", VPC: "prod"},
		},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	entries := store.Entries(model.EndpointKey("prod", "pod-a"))
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Key.RemoteIdentity != policy.EndpointIdentity(model.EndpointKey("prod", "pod-b")) {
		t.Fatalf("remote identity = %d, want pod-b identity", entries[0].Key.RemoteIdentity)
	}

	state.Endpoints = state.Endpoints[:1]
	result, err = ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 0 || result.TCXEligible != 0 {
		t.Fatalf("expected empty remote group to remove entries, got %+v", result)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("entries after member removal = %d, want 0", len(entries))
	}
}

func TestReconcileNodeReportsProviderNetworkCountsFromLinuxDatapath(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "eth1",
			}},
		}},
		Subnets: []model.Subnet{{
			Name:            "apps",
			VPC:             "prod",
			CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
			Gateway:         netip.MustParseAddr("10.10.0.1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
		}},
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
	}
	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: dataplane.NewInMemoryPolicyStore(),
		LinuxDatapath: &linuxdatapath.Options{
			LocalDevice:       "nl0",
			Mode:              "local",
			Backend:           "command",
			Executor:          noopExecutor{},
			ProviderInventory: []linuxdatapath.ProviderInterface{{Name: "eth1", Ready: true}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderNetworks != 1 || result.ProviderLinks != 1 {
		t.Fatalf("provider counts = %+v, want provider_networks=1 provider_links=1", result)
	}
	if result.ProviderReady != 0 || result.ProviderDegraded != 1 {
		t.Fatalf("provider health summary = %+v, want provider_ready=0 provider_degraded=1", result)
	}
	if len(result.ProviderStatus) != 1 {
		t.Fatalf("provider status = %+v, want 1 entry", result.ProviderStatus)
	}
	if got := result.ProviderStatus[0]; got.ProviderNetwork != "physnet-a" || got.ParentDevice != "eth1" || got.VLAN != 100 || got.LinkName == "" || got.Ready || got.ParentState != "up" || got.LinkState != "missing" {
		t.Fatalf("provider status[0] = %+v", got)
	}
	if result.Datapath != "linux:nl0" {
		t.Fatalf("datapath = %s, want linux:nl0", result.Datapath)
	}
}

func TestReconcileNodeSkipsRemoteEntityNoneRules(t *testing.T) {
	state := control.DesiredState{
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"client"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:             "allow-none",
				Priority:       100,
				Direction:      model.DirectionEgress,
				Protocol:       model.ProtocolTCP,
				RemoteEntities: []string{"none"},
				Ports:          []model.PortRange{{From: 443, To: 443}},
				Action:         model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Endpoints != 1 || result.Programs != 1 || result.Entries != 0 || result.TCXEligible != 0 {
		t.Fatalf("expected none entity to compile to no dataplane entries, got %+v", result)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("entries = %d, want 0 for remote entity none", len(entries))
	}
}

func TestReconcileNodeFailsWhenStrictProviderHealthIsEnabled(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "eth1",
			}},
		}},
		Subnets: []model.Subnet{{
			Name:            "apps",
			VPC:             "prod",
			CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
			Gateway:         netip.MustParseAddr("10.10.0.1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
		}},
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
	}
	_, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: dataplane.NewInMemoryPolicyStore(),
		LinuxDatapath: &linuxdatapath.Options{
			LocalDevice:          "nl0",
			Mode:                 "local",
			Backend:              "command",
			Executor:             noopExecutor{},
			ProviderInventory:    []linuxdatapath.ProviderInterface{{Name: "eth1", Ready: true}},
			StrictProviderHealth: true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "provider health degraded") {
		t.Fatalf("err = %v, want strict provider health failure", err)
	}
}

func TestReconcileNodeFailureKeepsProviderInventoryOnCandidateResolutionError(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:       "node-a",
				Interfaces: []string{"ens5", "bond0"},
			}},
		}},
		Subnets: []model.Subnet{{
			Name:            "apps",
			VPC:             "prod",
			CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
			Gateway:         netip.MustParseAddr("10.10.0.1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
		}},
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
	}
	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: dataplane.NewInMemoryPolicyStore(),
		LinuxDatapath: &linuxdatapath.Options{
			LocalDevice: "nl0",
			Mode:        "local",
			Backend:     "command",
			Executor:    noopExecutor{},
			ProviderInventory: []linuxdatapath.ProviderInterface{
				{Name: "eth1", Ready: true, State: "up"},
				{Name: "eth2", Ready: false, State: "down"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), `provider network "physnet-a" on node "node-a" could not resolve candidate interfaces ens5,bond0`) {
		t.Fatalf("err = %v, want candidate resolution failure", err)
	}
	if result.ProviderInventoryTotal != 2 || result.ProviderInventoryReady != 1 || result.ProviderInventoryDegraded != 1 {
		t.Fatalf("provider inventory summary = %+v, want total=2 ready=1 degraded=1", result)
	}
	if len(result.ProviderIssues) != 1 || result.ProviderIssues[0].Reason != "candidate-unresolved" || result.ProviderIssues[0].Detail != "ens5,bond0" {
		t.Fatalf("provider issues = %+v, want candidate-unresolved ens5,bond0", result.ProviderIssues)
	}
	if got := result.ProviderInventoryStatus[0].Name; got != "eth1" {
		t.Fatalf("provider inventory status[0] = %+v, want eth1 first", result.ProviderInventoryStatus[0])
	}
}

func TestReconcileNodeFailureKeepsProviderInventoryOnMissingProviderMapping(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-b",
				Interface: "eth1",
			}},
		}},
		Subnets: []model.Subnet{{
			Name:            "apps",
			VPC:             "prod",
			CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
			Gateway:         netip.MustParseAddr("10.10.0.1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
		}},
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
	}
	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: dataplane.NewInMemoryPolicyStore(),
		LinuxDatapath: &linuxdatapath.Options{
			LocalDevice: "nl0",
			Mode:        "local",
			Backend:     "command",
			Executor:    noopExecutor{},
			ProviderInventory: []linuxdatapath.ProviderInterface{
				{Name: "eth1", Ready: true, State: "up"},
				{Name: "eth2", Ready: false, State: "down"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), `provider network "physnet-a" requires parent device mapping on node "node-a"`) {
		t.Fatalf("err = %v, want missing provider mapping failure", err)
	}
	if result.ProviderInventoryTotal != 2 || result.ProviderInventoryReady != 1 || result.ProviderInventoryDegraded != 1 {
		t.Fatalf("provider inventory summary = %+v, want total=2 ready=1 degraded=1", result)
	}
	if len(result.ProviderIssues) != 1 || result.ProviderIssues[0].Reason != "missing-parent-mapping" || result.ProviderIssues[0].Node != "node-a" || result.ProviderIssues[0].VLAN != 100 {
		t.Fatalf("provider issues = %+v, want missing-parent-mapping on node-a/100", result.ProviderIssues)
	}
	if len(result.ProviderNetworkStatus) != 1 || result.ProviderNetworkStatus[0].ProviderNetwork != "physnet-a" || result.ProviderNetworkStatus[0].Ready || result.ProviderNetworkStatus[0].IssueCount != 1 {
		t.Fatalf("provider network status = %+v, want degraded physnet-a with one issue", result.ProviderNetworkStatus)
	}
}

func TestReconcileNodeFailureKeepsProviderInventoryOnProviderConflict(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{
			{
				Name: "physnet-a",
				Nodes: []model.ProviderNetworkNode{{
					Node:      "node-a",
					Interface: "eth1",
				}},
			},
			{
				Name: "physnet-b",
				Nodes: []model.ProviderNetworkNode{{
					Node:      "node-a",
					Interface: "eth1",
				}},
			},
		},
		Subnets: []model.Subnet{
			{
				Name:            "apps-a",
				VPC:             "prod",
				CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
				Gateway:         netip.MustParseAddr("10.10.0.1"),
				ProviderNetwork: "physnet-a",
				VLAN:            100,
			},
			{
				Name:            "apps-b",
				VPC:             "prod",
				CIDR:            netip.MustParsePrefix("10.20.0.0/24"),
				Gateway:         netip.MustParseAddr("10.20.0.1"),
				ProviderNetwork: "physnet-b",
				VLAN:            100,
			},
		},
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps-a", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a"},
			{ID: "pod-b", VPC: "prod", Subnet: "apps-b", IP: netip.MustParseAddr("10.20.0.10"), Node: "node-a"},
		},
	}
	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: dataplane.NewInMemoryPolicyStore(),
		LinuxDatapath: &linuxdatapath.Options{
			LocalDevice: "nl0",
			Mode:        "local",
			Backend:     "command",
			Executor:    noopExecutor{},
			ProviderInventory: []linuxdatapath.ProviderInterface{
				{Name: "eth1", Ready: true, State: "up"},
				{Name: "eth2", Ready: false, State: "down"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), `provider networks "physnet-a" and "physnet-b" both require parent eth1 vlan 100`) {
		t.Fatalf("err = %v, want provider conflict failure", err)
	}
	if result.ProviderInventoryTotal != 2 || result.ProviderInventoryReady != 1 || result.ProviderInventoryDegraded != 1 {
		t.Fatalf("provider inventory summary = %+v, want total=2 ready=1 degraded=1", result)
	}
	if len(result.ProviderIssues) != 1 || result.ProviderIssues[0].Reason != "parent-vlan-conflict" || result.ProviderIssues[0].ParentDevice != "eth1" || result.ProviderIssues[0].VLAN != 100 {
		t.Fatalf("provider issues = %+v, want parent-vlan-conflict on eth1/100", result.ProviderIssues)
	}
}

type noopExecutor struct{}

func (noopExecutor) Execute(context.Context, linuxdatapath.Operation) error {
	return nil
}

func TestReconcileNodeExpandsRemoteEndpointSelector(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:             "pod-web",
				VPC:            "prod",
				Subnet:         "apps",
				IP:             netip.MustParseAddr("10.10.0.20"),
				Node:           "node-a",
				SecurityGroups: []string{"web"},
			},
			{
				ID:     "pod-client",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.10"),
				Node:   "node-b",
				Labels: model.Labels{"app": "client", "env": "prod"},
			},
			{
				ID:     "pod-dev-client",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.11"),
				Node:   "node-c",
				Labels: model.Labels{"app": "client", "env": "dev"},
			},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:                     "allow-client",
				Priority:               100,
				Direction:              model.DirectionIngress,
				Protocol:               model.ProtocolTCP,
				RemoteEndpointSelector: model.Labels{"app": "client"},
				RemoteEndpointExprs: []model.LabelExpr{
					{Key: "env", Operator: "In", Values: []string{"prod"}},
				},
				Ports:  []model.PortRange{{From: 8080, To: 8080}},
				Action: model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	entries := store.Entries(model.EndpointKey("prod", "pod-web"))
	decision := dataplane.Evaluate(entries, dataplane.Packet{
		RemoteIdentity: policy.EndpointIdentity(model.EndpointKey("prod", "pod-client")),
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		RemoteIP:       netip.MustParseAddr("10.10.0.10"),
		DestPort:       8080,
	})
	if decision.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected selector-derived ingress allow, got %+v", decision)
	}
	devDecision := dataplane.Evaluate(entries, dataplane.Packet{
		RemoteIdentity: policy.EndpointIdentity(model.EndpointKey("prod", "pod-dev-client")),
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		RemoteIP:       netip.MustParseAddr("10.10.0.11"),
		DestPort:       8080,
	})
	if devDecision.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected selector expression to reject dev client, got %+v", devDecision)
	}
}

func TestReconcileNodeCompilesRemoteServiceRule(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-client",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"client"},
		}},
		LoadBalancers: []model.LoadBalancer{{
			Name: "web",
			VPC:  "prod",
			VIP:  netip.MustParseAddr("10.96.0.10"),
			Ports: []model.LoadBalancerPort{{
				Port:     80,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{{
					IP:   netip.MustParseAddr("10.10.0.20"),
					Port: 8080,
				}},
			}},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:            "allow-web-service",
				Priority:      100,
				Direction:     model.DirectionEgress,
				Protocol:      model.ProtocolAny,
				RemoteService: "web",
				Action:        model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	decision := dataplane.Evaluate(store.Entries(model.EndpointKey("prod", "pod-client")), dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("10.96.0.10"),
		DestPort:  80,
	})
	if decision.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected egress tcp/80 to service VIP to allow, got %+v", decision)
	}
}

func TestReconcileNodeCompilesFQDNRulesFromDNSRecords(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"client"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:          "allow-api",
				Priority:    100,
				Direction:   model.DirectionEgress,
				Protocol:    model.ProtocolTCP,
				RemoteFQDNs: []model.FQDNSelector{{MatchName: "api.example.com"}},
				Ports:       []model.PortRange{{From: 443, To: 443}},
				Action:      model.ActionAllow,
			}},
		}},
		DNSRecords: []model.DNSRecord{{
			Name: "api.example.com",
			IPs:  []netip.Addr{netip.MustParseAddr("203.0.113.10")},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	entries := store.Entries(model.EndpointKey("prod", "pod-a"))
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].RemoteCIDR.String() != "203.0.113.10/32" {
		t.Fatalf("remote cidr = %s, want fqdn-derived /32", entries[0].RemoteCIDR)
	}
	decision := dataplane.Evaluate(entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("203.0.113.10"),
		DestPort:  443,
	})
	if decision.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected fqdn-derived egress allow, got %+v", decision)
	}
}

func TestReconcileNodeCompilesCIDRGroupRules(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"client"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:              "allow-corp",
				Priority:        100,
				Direction:       model.DirectionEgress,
				Protocol:        model.ProtocolTCP,
				RemoteCIDRGroup: "corp",
				Ports:           []model.PortRange{{From: 443, To: 443}},
				Action:          model.ActionAllow,
			}},
		}},
		CIDRGroups: []model.CIDRGroup{{
			Name:  "corp",
			VPC:   "prod",
			CIDRs: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")},
			Entries: []model.CIDRGroupEntry{{
				CIDR:        netip.MustParsePrefix("10.20.0.0/16"),
				ExceptCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.128.0/17")},
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 2 || result.TCXEligible != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	entries := store.Entries(model.EndpointKey("prod", "pod-a"))
	decision := dataplane.Evaluate(entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("10.20.1.10"),
		DestPort:  443,
	})
	if decision.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected cidr-group-derived egress allow, got %+v", decision)
	}
	excluded := dataplane.Evaluate(entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("10.20.200.10"),
		DestPort:  443,
	})
	if excluded.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected cidr-group except range to drop, got %+v", excluded)
	}
}

func TestReconcileNodeCompilesHostEntityFromGateways(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"client"},
		}},
		Gateways: []model.Gateway{{
			Name:       "gw-a",
			VPC:        "prod",
			Node:       "node-a",
			ExternalIF: "eth0",
			LANIP:      netip.MustParseAddr("10.10.0.254"),
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:             "allow-host",
				Priority:       100,
				Direction:      model.DirectionEgress,
				Protocol:       model.ProtocolTCP,
				RemoteEntities: []string{"host"},
				Ports:          []model.PortRange{{From: 9444, To: 9444}},
				Action:         model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	entries := store.Entries(model.EndpointKey("prod", "pod-a"))
	if len(entries) != 1 || entries[0].RemoteCIDR.String() != "10.10.0.254/32" {
		t.Fatalf("entries = %+v, want host gateway /32", entries)
	}
	decision := dataplane.Evaluate(entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("10.10.0.254"),
		DestPort:  9444,
	})
	if decision.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected host entity egress allow, got %+v", decision)
	}
}

func TestReconcileNodeCompilesRemoteNodeEntityFromGateways(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"client"},
		}},
		Gateways: []model.Gateway{
			{
				Name:       "gw-local",
				VPC:        "prod",
				Node:       "node-a",
				ExternalIF: "eth0",
				LANIP:      netip.MustParseAddr("10.10.0.254"),
			},
			{
				Name:       "gw-remote",
				VPC:        "prod",
				Node:       "node-b",
				ExternalIF: "eth0",
				LANIP:      netip.MustParseAddr("10.10.0.253"),
			},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "client",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:             "allow-remote-node",
				Priority:       100,
				Direction:      model.DirectionEgress,
				Protocol:       model.ProtocolTCP,
				RemoteEntities: []string{"remote-node"},
				Ports:          []model.PortRange{{From: 4240, To: 4240}},
				Action:         model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 || result.TCXEligible != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	entries := store.Entries(model.EndpointKey("prod", "pod-a"))
	if len(entries) != 1 || entries[0].RemoteCIDR.String() != "10.10.0.253/32" {
		t.Fatalf("entries = %+v, want remote node gateway /32", entries)
	}
	remoteDecision := dataplane.Evaluate(entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("10.10.0.253"),
		DestPort:  4240,
	})
	if remoteDecision.Verdict != dataplane.VerdictAllow {
		t.Fatalf("expected remote-node entity egress allow, got %+v", remoteDecision)
	}
	localDecision := dataplane.Evaluate(entries, dataplane.Packet{
		Direction: dataplane.DirectionEgress,
		Protocol:  6,
		RemoteIP:  netip.MustParseAddr("10.10.0.254"),
		DestPort:  4240,
	})
	if localDecision.Verdict != dataplane.VerdictDrop {
		t.Fatalf("expected local gateway to stay outside remote-node entity, got %+v", localDecision)
	}
}

func TestReconcilerConcurrentReconcileSerializesStoreWrites(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:             "pod-a",
			VPC:            "prod",
			Subnet:         "apps",
			IP:             netip.MustParseAddr("10.10.0.10"),
			Node:           "node-a",
			SecurityGroups: []string{"web"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "drop-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.11/32"),
				Ports:      []model.PortRange{{From: 8080, To: 8080}},
				Action:     model.ActionDrop,
			}},
		}},
	}
	store := newConcurrentPolicyStore(50 * time.Millisecond)
	reconciler := NewReconciler(store)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() {
		_, err := reconciler.Reconcile(ctx, state, ReconcileOptions{Node: "node-a", Store: store})
		first <- err
	}()

	select {
	case <-store.firstReplaceStarted:
	case <-ctx.Done():
		t.Fatal("first reconcile did not reach policy store")
	}

	go func() {
		_, err := reconciler.Reconcile(ctx, state, ReconcileOptions{Node: "node-a", Store: store})
		second <- err
	}()

	firstErr := <-first
	secondErr := <-second
	if firstErr != nil {
		t.Fatalf("first reconcile failed: %v", firstErr)
	}
	if secondErr != nil {
		t.Fatalf("second reconcile failed: %v", secondErr)
	}
	if got := store.MaxConcurrentWrites(); got != 1 {
		t.Fatalf("concurrent policy store writes = %d, want 1", got)
	}
}
