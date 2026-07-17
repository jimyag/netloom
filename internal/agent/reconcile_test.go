package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
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

type sweepingPolicyStore struct {
	scopedPolicyStore
	keep    []string
	maxIdle time.Duration
	swept   int
}

func (s *sweepingPolicyStore) SweepPolicyEndpoints(_ context.Context, keep []string, maxIdle time.Duration) (int, error) {
	s.keep = append([]string(nil), keep...)
	s.maxIdle = maxIdle
	return s.swept, nil
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

type capacityPolicyStore struct {
	*dataplane.InMemoryPolicyStore
	capacity uint32
}

func (s *capacityPolicyStore) PolicyMapUsage(ctx context.Context) ([]dataplane.PolicyMapUsage, error) {
	endpointIDs, err := s.EndpointIDs(ctx)
	if err != nil {
		return nil, err
	}
	usages := make([]dataplane.PolicyMapUsage, 0, len(endpointIDs))
	for _, endpointID := range endpointIDs {
		usages = append(usages, dataplane.PolicyMapUsage{
			EndpointID: endpointID,
			Entries:    uint32(len(s.Entries(endpointID))),
			Capacity:   s.capacity,
		})
	}
	return usages, nil
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

func TestRegeneratePolicyEndpointReplacesDesiredEndpointPolicy(t *testing.T) {
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
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")
	if _, err := ReconcileNode(context.Background(), state, "node-a", store); err != nil {
		t.Fatal(err)
	}
	before := store.Revision(endpointID)

	status, err := RegeneratePolicyEndpoint(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	if status.EndpointID != endpointID || status.Revision != before+1 || status.Entries != 1 {
		t.Fatalf("regenerated status = %+v, want endpoint revision advanced", status)
	}
	if !status.HasLastEvent || !status.LastEvent.Success || status.LastEvent.Revision != before+1 {
		t.Fatalf("regenerated event = %+v has=%t, want successful forced update event", status.LastEvent, status.HasLastEvent)
	}
	if entries := store.Entries(endpointID); len(entries) != 1 || entries[0].RemoteCIDR != netip.MustParsePrefix("172.30.0.0/24") {
		t.Fatalf("entries = %+v, want regenerated desired policy", entries)
	}
}

func TestRegeneratePolicyEndpointRejectsRemoteNodeEndpoint(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-b",
		}},
	}
	_, err := RegeneratePolicyEndpoint(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: dataplane.NewInMemoryPolicyStore(),
	}, model.EndpointKey("prod", "pod-a"))
	if err == nil || !strings.Contains(err.Error(), "assigned to node") {
		t.Fatalf("error = %v, want remote node rejection", err)
	}
}

func TestPlanPolicyEndpointReportsDiffWithoutApplying(t *testing.T) {
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
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")
	oldEntries := []dataplane.PolicyMapEntry{{
		Key: dataplane.PolicyKey{
			PrefixLen:      dataplane.StaticPrefixBits + 8,
			RemoteIdentity: 42,
			Direction:      dataplane.DirectionIngress,
			Protocol:       6,
		},
		RemoteCIDR: netip.MustParsePrefix("198.51.100.0/24"),
		Value: dataplane.PolicyEntry{
			Deny:        1,
			L4PrefixLen: 8,
			Precedence:  100,
		},
	}}
	if err := store.ReplaceEndpoint(context.Background(), endpointID, oldEntries); err != nil {
		t.Fatal(err)
	}
	beforeRevision := store.Revision(endpointID)

	plan, err := PlanPolicyEndpoint(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.EndpointID != endpointID || !plan.Changed || plan.CurrentEntries != 1 || plan.DesiredEntries != 1 {
		t.Fatalf("plan = %+v, want one changed endpoint policy entry", plan)
	}
	if plan.Stats.Added != 1 || plan.Stats.Deleted != 1 || plan.Stats.Updated != 0 || plan.Stats.Unchanged != 0 {
		t.Fatalf("plan stats = %+v, want add/delete dry-run", plan.Stats)
	}
	if revision := store.Revision(endpointID); revision != beforeRevision {
		t.Fatalf("revision = %d, want unchanged %d", revision, beforeRevision)
	}
	if entries := store.Entries(endpointID); len(entries) != 1 || entries[0].RemoteCIDR != oldEntries[0].RemoteCIDR || entries[0].Value.Deny != 1 {
		t.Fatalf("entries = %+v, want old entries preserved", entries)
	}
}

func TestPlanPolicyEndpointReportsBlockingChangeRisk(t *testing.T) {
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
				ID:         "reject-api",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 443, To: 443}},
				Action:     model.ActionReject,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")
	plan, err := PlanPolicyEndpoint(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Risk.BlockingChange || plan.Risk.AddedDenyEntries != 1 || plan.Risk.AddedRejectEntries != 1 {
		t.Fatalf("plan risk = %+v, want one added reject blocking change", plan.Risk)
	}
}

func TestQuarantinePolicyEndpointReplacesPolicyWithIngressAndEgressDrops(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")

	status, err := QuarantinePolicyEndpoint(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	if status.EndpointID != endpointID || status.Revision != 1 || status.Entries != 2 {
		t.Fatalf("quarantine status = %+v, want two-entry revision", status)
	}
	if !status.HasLastEvent || !status.LastEvent.Success {
		t.Fatalf("quarantine event = %+v has=%t, want successful event", status.LastEvent, status.HasLastEvent)
	}
	entries := store.Entries(endpointID)
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want ingress and egress quarantine entries", entries)
	}
	ingress := dataplane.Evaluate(entries, dataplane.Packet{
		RemoteIdentity: 100,
		RemoteIP:       netip.MustParseAddr("203.0.113.10"),
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	})
	egress := dataplane.Evaluate(entries, dataplane.Packet{
		RemoteIdentity: 200,
		RemoteIP:       netip.MustParseAddr("198.51.100.10"),
		Direction:      dataplane.DirectionEgress,
		Protocol:       17,
		DestPort:       53,
	})
	if ingress.Verdict != dataplane.VerdictDrop || ingress.Match == nil || ingress.Match.Value.Deny == 0 {
		t.Fatalf("ingress decision = %+v, want quarantine policy deny", ingress)
	}
	if egress.Verdict != dataplane.VerdictDrop || egress.Match == nil || egress.Match.Value.Deny == 0 {
		t.Fatalf("egress decision = %+v, want quarantine policy deny", egress)
	}
}

func TestUnquarantinePolicyEndpointRestoresDesiredPolicy(t *testing.T) {
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
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")
	if _, err := QuarantinePolicyEndpoint(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, endpointID); err != nil {
		t.Fatal(err)
	}
	quarantineRevision := store.Revision(endpointID)

	status, err := UnquarantinePolicyEndpoint(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	if status.EndpointID != endpointID || status.Revision != quarantineRevision+1 || status.Entries != 1 {
		t.Fatalf("unquarantine status = %+v, want restored desired policy revision", status)
	}
	entries := store.Entries(endpointID)
	if len(entries) != 1 || entries[0].RemoteCIDR != netip.MustParsePrefix("172.30.0.0/24") || entries[0].Value.Deny != 0 {
		t.Fatalf("entries = %+v, want restored allow-http policy", entries)
	}
	decision := dataplane.Evaluate(entries, dataplane.Packet{
		RemoteIP:  netip.MustParseAddr("172.30.0.10"),
		Direction: dataplane.DirectionIngress,
		Protocol:  6,
		DestPort:  80,
	})
	if decision.Verdict != dataplane.VerdictAllow {
		t.Fatalf("decision = %+v, want restored allow", decision)
	}
}

func TestRollbackPolicyEndpointRestoresDesiredPolicy(t *testing.T) {
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
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")
	if _, err := QuarantinePolicyEndpoint(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, endpointID); err != nil {
		t.Fatal(err)
	}
	quarantineRevision := store.Revision(endpointID)

	status, err := RollbackPolicyEndpoint(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	if status.EndpointID != endpointID || status.Revision != quarantineRevision+1 || status.Entries != 1 {
		t.Fatalf("rollback status = %+v, want restored desired policy revision", status)
	}
	entries := store.Entries(endpointID)
	if len(entries) != 1 || entries[0].RemoteCIDR != netip.MustParsePrefix("172.30.0.0/24") || entries[0].Value.Deny != 0 {
		t.Fatalf("entries = %+v, want rolled back desired allow-http policy", entries)
	}
}

func TestReconcileNodeSweepsIdlePolicyEndpoints(t *testing.T) {
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
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("0.0.0.0/0"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	store := &sweepingPolicyStore{swept: 2}
	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:            "node-a",
		Store:           store,
		PolicyGCMaxIdle: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyGCEndpoints != 2 {
		t.Fatalf("policy gc endpoints = %d, want 2", result.PolicyGCEndpoints)
	}
	if store.maxIdle != time.Minute {
		t.Fatalf("max idle = %s, want 1m", store.maxIdle)
	}
	if len(store.keep) != 1 || store.keep[0] != model.EndpointKey("prod", "pod-a") {
		t.Fatalf("keep set = %v, want pod-a endpoint key", store.keep)
	}
}

func TestReconcileNodeKeepsFrozenPolicyEndpointDuringIdleSweep(t *testing.T) {
	frozenEndpoint := model.EndpointKey("prod", "pod-z")
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
				ID:        "allow-all",
				Priority:  100,
				Direction: model.DirectionIngress,
				Protocol:  model.ProtocolAny,
				Action:    model.ActionAllow,
			}},
		}},
	}
	store := &sweepingPolicyStore{}
	if _, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:            "node-a",
		Store:           store,
		PolicyGCMaxIdle: time.Minute,
		FrozenPolicyEndpoints: map[string]struct{}{
			frozenEndpoint: {},
		},
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{model.EndpointKey("prod", "pod-a"), frozenEndpoint}
	if !slices.Equal(store.keep, want) {
		t.Fatalf("keep set = %v, want %v", store.keep, want)
	}
}

func TestReconcileNodeSkipsFrozenPolicyEndpointApply(t *testing.T) {
	endpointID := model.EndpointKey("prod", "pod-a")
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
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	if _, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{Node: "node-a", Store: store}); err != nil {
		t.Fatal(err)
	}
	initial := store.Entries(endpointID)
	if len(initial) == 0 {
		t.Fatal("initial policy entries were not programmed")
	}

	state.SecurityGroups[0].Rules[0].RemoteCIDR = netip.MustParsePrefix("198.51.100.0/24")
	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
		FrozenPolicyEndpoints: map[string]struct{}{
			endpointID: {},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyFrozen != 1 {
		t.Fatalf("policy frozen = %d, want 1", result.PolicyFrozen)
	}
	frozen := store.Entries(endpointID)
	if !slices.EqualFunc(initial, frozen, func(a, b dataplane.PolicyMapEntry) bool {
		return a.Key == b.Key && a.Value == b.Value && a.RemoteCIDR == b.RemoteCIDR
	}) {
		t.Fatalf("frozen entries changed: before=%+v after=%+v", initial, frozen)
	}

	if _, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{Node: "node-a", Store: store}); err != nil {
		t.Fatal(err)
	}
	updated := store.Entries(endpointID)
	foundUpdatedCIDR := false
	for _, entry := range updated {
		if entry.RemoteCIDR == netip.MustParsePrefix("198.51.100.0/24") {
			foundUpdatedCIDR = true
			break
		}
	}
	if !foundUpdatedCIDR {
		t.Fatalf("updated entries = %+v, want new CIDR after unfreezing", updated)
	}
}

func TestPolicyEndpointActionsRejectFrozenEndpoint(t *testing.T) {
	endpointID := model.EndpointKey("prod", "pod-a")
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
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	options := ReconcileOptions{
		Node:  "node-a",
		Store: dataplane.NewInMemoryPolicyStore(),
		FrozenPolicyEndpoints: map[string]struct{}{
			endpointID: {},
		},
	}
	if _, err := RegeneratePolicyEndpoint(context.Background(), state, options, endpointID); err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("regenerate error = %v, want frozen", err)
	}
	if _, err := QuarantinePolicyEndpoint(context.Background(), state, options, endpointID); err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("quarantine error = %v, want frozen", err)
	}
}

func TestReconcileNodeMitigatesPolicyMapPressureByDeletingNonDesiredEndpoints(t *testing.T) {
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
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("0.0.0.0/0"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	staleEndpoint := model.EndpointKey("prod", "stale")
	store := &usagePolicyStore{
		InMemoryPolicyStore: dataplane.NewInMemoryPolicyStore(),
		usages: []dataplane.PolicyMapUsage{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Entries:    1,
			Capacity:   10,
		}, {
			EndpointID: staleEndpoint,
			Entries:    8,
			Capacity:   10,
		}},
	}
	if err := store.ReplaceEndpoint(context.Background(), staleEndpoint, []dataplane.PolicyMapEntry{{
		Key:   dataplane.PolicyKey{PrefixLen: dataplane.StaticPrefixBits, Direction: dataplane.DirectionIngress, RemoteIdentity: 42},
		Value: dataplane.PolicyEntry{},
	}}); err != nil {
		t.Fatal(err)
	}

	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:                              "node-a",
		Store:                             store,
		PolicyPressureMitigationThreshold: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyPressureMitigated != 1 {
		t.Fatalf("policy pressure mitigated = %d, want 1", result.PolicyPressureMitigated)
	}
	if entries := store.Entries(staleEndpoint); len(entries) != 0 {
		t.Fatalf("stale endpoint entries = %d, want deleted", len(entries))
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) == 0 {
		t.Fatal("desired endpoint policy was removed")
	}
}

func TestReconcileNodeMitigatesPolicyMapPressureKeepsFrozenEndpoint(t *testing.T) {
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
				ID:        "allow-all",
				Priority:  100,
				Direction: model.DirectionIngress,
				Protocol:  model.ProtocolAny,
				Action:    model.ActionAllow,
			}},
		}},
	}
	staleEndpoint := model.EndpointKey("prod", "stale")
	frozenEndpoint := model.EndpointKey("prod", "frozen")
	store := &usagePolicyStore{
		InMemoryPolicyStore: dataplane.NewInMemoryPolicyStore(),
		usages: []dataplane.PolicyMapUsage{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Entries:    1,
			Capacity:   10,
		}, {
			EndpointID: staleEndpoint,
			Entries:    8,
			Capacity:   10,
		}, {
			EndpointID: frozenEndpoint,
			Entries:    8,
			Capacity:   10,
		}},
	}
	for _, endpointID := range []string{staleEndpoint, frozenEndpoint} {
		if err := store.ReplaceEndpoint(context.Background(), endpointID, []dataplane.PolicyMapEntry{{
			Key:   dataplane.PolicyKey{PrefixLen: dataplane.StaticPrefixBits, Direction: dataplane.DirectionIngress, RemoteIdentity: 42},
			Value: dataplane.PolicyEntry{},
		}}); err != nil {
			t.Fatal(err)
		}
	}

	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:                              "node-a",
		Store:                             store,
		PolicyPressureMitigationThreshold: 80,
		FrozenPolicyEndpoints: map[string]struct{}{
			frozenEndpoint: {},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyPressureMitigated != 1 {
		t.Fatalf("policy pressure mitigated = %d, want 1", result.PolicyPressureMitigated)
	}
	if entries := store.Entries(staleEndpoint); len(entries) != 0 {
		t.Fatalf("stale endpoint entries = %d, want deleted", len(entries))
	}
	if entries := store.Entries(frozenEndpoint); len(entries) == 0 {
		t.Fatal("frozen endpoint policy was removed")
	}
}

func TestReconcileNodeQuarantinesDesiredEndpointWhenPolicyMapPressureRemainsHigh(t *testing.T) {
	endpointID := model.EndpointKey("prod", "pod-a")
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
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("0.0.0.0/0"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	store := &capacityPolicyStore{
		InMemoryPolicyStore: dataplane.NewInMemoryPolicyStore(),
		capacity:            1,
	}

	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:                              "node-a",
		Store:                             store,
		PolicyPressureMitigationThreshold: 80,
		PolicyPressureQuarantine:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyPressureQuarantined != 1 {
		t.Fatalf("policy pressure quarantined = %d, want 1", result.PolicyPressureQuarantined)
	}
	if result.PolicyPressureQuarantineEndpoint != endpointID {
		t.Fatalf("policy pressure quarantine endpoint = %q, want %q", result.PolicyPressureQuarantineEndpoint, endpointID)
	}
	entries := store.Entries(endpointID)
	if len(entries) != 2 {
		t.Fatalf("quarantine entries = %d, want ingress and egress drops", len(entries))
	}
	directions := map[uint8]bool{}
	for _, entry := range entries {
		if entry.Value.Deny != 1 || entry.Value.Precedence != ^uint32(0) {
			t.Fatalf("quarantine entry = %+v, want deny-all", entry)
		}
		directions[entry.Key.Direction] = true
	}
	if !directions[dataplane.DirectionIngress] || !directions[dataplane.DirectionEgress] {
		t.Fatalf("quarantine directions = %v, want ingress and egress", directions)
	}
}

func TestReconcileNodeSkipsPressureQuarantineForFrozenEndpoint(t *testing.T) {
	endpointID := model.EndpointKey("prod", "pod-a")
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
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("0.0.0.0/0"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	store := &capacityPolicyStore{
		InMemoryPolicyStore: dataplane.NewInMemoryPolicyStore(),
		capacity:            1,
	}
	original := dataplane.PolicyMapEntry{
		Key:   dataplane.PolicyKey{PrefixLen: dataplane.StaticPrefixBits, Direction: dataplane.DirectionIngress, RemoteIdentity: 42},
		Value: dataplane.PolicyEntry{Precedence: 100},
	}
	if err := store.ReplaceEndpoint(context.Background(), endpointID, []dataplane.PolicyMapEntry{original}); err != nil {
		t.Fatal(err)
	}

	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:                              "node-a",
		Store:                             store,
		PolicyPressureMitigationThreshold: 80,
		PolicyPressureQuarantine:          true,
		FrozenPolicyEndpoints: map[string]struct{}{
			endpointID: {},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyFrozen != 1 {
		t.Fatalf("policy frozen = %d, want 1", result.PolicyFrozen)
	}
	if result.PolicyPressureQuarantined != 0 || result.PolicyPressureQuarantineEndpoint != "" {
		t.Fatalf("pressure quarantine result = %+v, want no quarantine for frozen endpoint", result)
	}
	entries := store.Entries(endpointID)
	if len(entries) != 1 || entries[0].Key != original.Key || entries[0].Value != original.Value {
		t.Fatalf("frozen endpoint entries = %+v, want original entry preserved", entries)
	}
}

func TestReconcileNodeDoesNotQuarantineBelowQuarantineThreshold(t *testing.T) {
	endpointID := model.EndpointKey("prod", "pod-a")
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
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("0.0.0.0/0"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	}
	store := &capacityPolicyStore{
		InMemoryPolicyStore: dataplane.NewInMemoryPolicyStore(),
		capacity:            2,
	}

	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:                              "node-a",
		Store:                             store,
		PolicyPressureMitigationThreshold: 40,
		PolicyPressureQuarantineThreshold: 90,
		PolicyPressureQuarantine:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyMapPressureMax != 50 {
		t.Fatalf("policy pressure max = %d, want 50", result.PolicyMapPressureMax)
	}
	if result.PolicyPressureQuarantined != 0 || result.PolicyPressureQuarantineEndpoint != "" {
		t.Fatalf("policy quarantine result = %d/%q, want none", result.PolicyPressureQuarantined, result.PolicyPressureQuarantineEndpoint)
	}
	entries := store.Entries(endpointID)
	if len(entries) != 1 || entries[0].Value.Deny != 0 {
		t.Fatalf("entries = %+v, want original allow policy", entries)
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

func TestReconcilerKeepsFrozenInventoryEndpointMissingAfterRestart(t *testing.T) {
	frozenEndpoint := model.EndpointKey("prod", "frozen")
	store := &inventoryPolicyStore{
		endpoints: []string{
			model.EndpointKey("prod", "stale"),
			frozenEndpoint,
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

	if _, err := reconciler.Reconcile(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
		FrozenPolicyEndpoints: map[string]struct{}{
			frozenEndpoint: {},
		},
	}); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if !slices.Contains(store.deletes, model.EndpointKey("prod", "stale")) {
		t.Fatalf("delete endpoints = %v, want stale endpoint deleted", store.deletes)
	}
	if slices.Contains(store.deletes, frozenEndpoint) {
		t.Fatalf("frozen endpoint must not be deleted: %v", store.deletes)
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

func TestRolloutPolicyEndpointsDryRunPlansWithoutApplying(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		BatchSize: 2,
		DryRun:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollout.DryRun || rollout.BatchSize != 2 || rollout.Planned != 3 || rollout.Applied != 0 || rollout.Failed != 0 || rollout.Skipped != 0 {
		t.Fatalf("rollout = %+v, want three planned dry-run items", rollout)
	}
	if len(rollout.Items) != 3 || rollout.Items[0].Batch != 1 || rollout.Items[1].Batch != 1 || rollout.Items[2].Batch != 2 {
		t.Fatalf("rollout items = %+v, want two staged dry-run batches", rollout.Items)
	}
	if rollout.Items[0].Phase != "planned" || !rollout.Items[0].Plan.Changed || rollout.Items[0].Plan.DesiredEntries != 1 {
		t.Fatalf("first rollout item = %+v, want planned changed endpoint", rollout.Items[0])
	}
	if rollout.Risk.BlockingChange {
		t.Fatalf("rollout risk = %+v, want non-blocking allow dry-run", rollout.Risk)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("dry-run entries = %+v, want no live mutation", entries)
	}
}

func TestRolloutPolicyEndpointsAggregatesPlanRisk(t *testing.T) {
	state := rolloutPolicyState()
	state.SecurityGroups[0].Rules[0].Action = model.ActionReject
	state.SecurityGroups[0].Rules[0].ID = "reject-http"
	store := dataplane.NewInMemoryPolicyStore()

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollout.Risk.BlockingChange || rollout.Risk.AddedDenyEntries != 3 || rollout.Risk.AddedRejectEntries != 3 {
		t.Fatalf("rollout risk = %+v, want three added reject entries", rollout.Risk)
	}
	if len(rollout.Items) != 3 || !rollout.Items[0].Plan.Risk.BlockingChange {
		t.Fatalf("rollout items = %+v, want per-endpoint blocking risk", rollout.Items)
	}
}

func TestRolloutPolicyEndpointsPausesBlockingRiskUntilRiskAcknowledged(t *testing.T) {
	state := rolloutPolicyState()
	state.SecurityGroups[0].Rules[0].Action = model.ActionReject
	state.SecurityGroups[0].Rules[0].ID = "reject-http"
	store := dataplane.NewInMemoryPolicyStore()

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs:     []string{model.EndpointKey("prod", "pod-a")},
		BatchSize:       1,
		RiskAckRequired: true,
		RiskAckRef:      "risk-1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollout.Paused || !rollout.RiskAckPending || !rollout.Risk.BlockingChange || rollout.Applied != 0 || rollout.Skipped != 1 {
		t.Fatalf("rollout = %+v, want risk ack pause before mutation", rollout)
	}
	if rollout.Items[0].Phase != "paused" || rollout.Items[0].Reason != "risk_ack_pending" {
		t.Fatalf("rollout items = %+v, want risk_ack_pending pause", rollout.Items)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation before risk ack", entries)
	}
}

func TestRolloutPolicyEndpointsAppliesBlockingRiskAfterRiskAcknowledgement(t *testing.T) {
	state := rolloutPolicyState()
	state.SecurityGroups[0].Rules[0].Action = model.ActionReject
	state.SecurityGroups[0].Rules[0].ID = "reject-http"
	store := dataplane.NewInMemoryPolicyStore()

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs:      []string{model.EndpointKey("prod", "pod-a")},
		BatchSize:        1,
		RiskAckRequired:  true,
		RiskAcknowledged: true,
		RiskAckRef:       "risk-1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rollout.Paused || rollout.RiskAckPending || !rollout.Risk.BlockingChange || !rollout.RiskAcknowledged || rollout.Applied != 1 || rollout.Skipped != 0 {
		t.Fatalf("rollout = %+v, want risk-acknowledged blocking rollout applied", rollout)
	}
	entries := store.Entries(model.EndpointKey("prod", "pod-a"))
	if len(entries) != 1 || entries[0].Value.Reject == 0 {
		t.Fatalf("pod-a entries = %+v, want reject policy applied after risk ack", entries)
	}
}

func TestRolloutPolicyEndpointsDryRunFailsFrozenEndpointWithoutApplying(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
		FrozenPolicyEndpoints: map[string]struct{}{
			endpointID: {},
		},
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{endpointID},
		BatchSize:   1,
		DryRun:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollout.DryRun || rollout.Applied != 0 || rollout.Failed != 1 || len(rollout.Items) != 1 {
		t.Fatalf("rollout = %+v, want one failed frozen dry-run item", rollout)
	}
	if rollout.Items[0].Phase != "failed" || rollout.Items[0].Reason != "policy_frozen" || !strings.Contains(rollout.Items[0].Error, "frozen") {
		t.Fatalf("rollout item = %+v, want policy_frozen failure", rollout.Items[0])
	}
	if entries := store.Entries(endpointID); len(entries) != 0 {
		t.Fatalf("frozen dry-run entries = %+v, want no live mutation", entries)
	}
}

func TestRolloutPolicyEndpointsFailsFrozenEndpointWithoutApplying(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
		FrozenPolicyEndpoints: map[string]struct{}{
			endpointID: {},
		},
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{endpointID},
		BatchSize:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rollout.Applied != 0 || rollout.Failed != 1 || len(rollout.Items) != 1 {
		t.Fatalf("rollout = %+v, want one failed frozen item", rollout)
	}
	if rollout.Items[0].Phase != "failed" || rollout.Items[0].Reason != "policy_frozen" {
		t.Fatalf("rollout item = %+v, want policy_frozen failure", rollout.Items[0])
	}
	if entries := store.Entries(endpointID); len(entries) != 0 {
		t.Fatalf("frozen rollout entries = %+v, want no live mutation", entries)
	}
}

func TestReconcileDefersPolicyApplyForDesiredStateRollout(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:      "web-canary",
		Node:      "node-a",
		Endpoints: []string{"prod/pod-a", "prod/pod-b"},
		BatchSize: 1,
	}}
	store := dataplane.NewInMemoryPolicyStore()

	result, err := ReconcileNodeWithOptions(context.Background(), state, ReconcileOptions{
		Node:             "node-a",
		Store:            store,
		DeferPolicyApply: HasActivePolicyRollouts(state, "node-a"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Programs != 3 || result.PolicyEvents != 0 {
		t.Fatalf("deferred reconcile result = %+v, want programs compiled without policy events", result)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("deferred pod-a entries = %+v, want no live mutation", entries)
	}

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	ApplyPolicyRolloutResults(&result, rollouts)
	if result.PolicyRollouts != 1 || result.PolicyRolloutPlanned != 2 || result.PolicyRolloutApplied != 2 || result.PolicyRolloutFailed != 0 {
		t.Fatalf("rollout summary = %+v, want two applied endpoints", result)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want applied policy", entries)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-b")); len(entries) != 1 {
		t.Fatalf("pod-b entries = %+v, want applied policy", entries)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-c")); len(entries) != 0 {
		t.Fatalf("pod-c entries = %+v, want rollout endpoint filter", entries)
	}
}

func TestApplyPolicyRolloutsDryRunPlansWithoutApplying(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:      "web-canary-plan",
		Node:      "node-a",
		Endpoints: []string{"prod/pod-a", "prod/pod-b"},
		BatchSize: 2,
		DryRun:    true,
	}}
	store := dataplane.NewInMemoryPolicyStore()

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	var result ReconcileResult
	ApplyPolicyRolloutResults(&result, rollouts)
	if result.PolicyRollouts != 1 || result.PolicyRolloutPlanned != 2 || result.PolicyRolloutApplied != 0 || result.PolicyRolloutFailed != 0 {
		t.Fatalf("rollout summary = %+v rollouts=%+v, want planned dry-run rollout", result, rollouts)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.DryRun || rollouts[0].Rollout.BatchSize != 2 {
		t.Fatalf("rollouts = %+v, want dry-run rollout with batch size 2", rollouts)
	}
	if phases := []string{rollouts[0].Rollout.Items[0].Phase, rollouts[0].Rollout.Items[1].Phase}; !slices.Equal(phases, []string{"planned", "planned"}) {
		t.Fatalf("dry-run rollout phases = %+v, want planned items", phases)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no live mutation for desired-state dry-run", entries)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-b")); len(entries) != 0 {
		t.Fatalf("pod-b entries = %+v, want no live mutation for desired-state dry-run", entries)
	}
}

func TestApplyPolicyRolloutsDryRunFailsFrozenEndpointWithoutApplying(t *testing.T) {
	state := rolloutPolicyState()
	endpointID := model.EndpointKey("prod", "pod-a")
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:      "web-canary-plan",
		Node:      "node-a",
		Endpoints: []string{"prod/pod-a"},
		BatchSize: 1,
		DryRun:    true,
	}}
	store := dataplane.NewInMemoryPolicyStore()

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
		FrozenPolicyEndpoints: map[string]struct{}{
			endpointID: {},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var result ReconcileResult
	ApplyPolicyRolloutResults(&result, rollouts)
	if result.PolicyRollouts != 1 || result.PolicyRolloutPlanned != 1 || result.PolicyRolloutApplied != 0 || result.PolicyRolloutFailed != 1 {
		t.Fatalf("rollout summary = %+v rollouts=%+v, want frozen dry-run failure", result, rollouts)
	}
	if len(rollouts) != 1 || len(rollouts[0].Rollout.Items) != 1 {
		t.Fatalf("rollouts = %+v, want one rollout item", rollouts)
	}
	item := rollouts[0].Rollout.Items[0]
	if item.Phase != "failed" || item.Reason != "policy_frozen" {
		t.Fatalf("dry-run rollout item = %+v, want policy_frozen failure", item)
	}
	if entries := store.Entries(endpointID); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no live mutation for frozen dry-run", entries)
	}
}

func TestApplyPolicyRolloutsCancelsWithoutApplying(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:      "web-canary-cancel",
		Node:      "node-a",
		Endpoints: []string{"prod/pod-a", "prod/pod-b"},
		BatchSize: 1,
		Cancelled: true,
	}}
	store := dataplane.NewInMemoryPolicyStore()

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	var result ReconcileResult
	ApplyPolicyRolloutResults(&result, rollouts)
	if result.PolicyRollouts != 1 || result.PolicyRolloutPlanned != 2 || result.PolicyRolloutApplied != 0 || result.PolicyRolloutSkipped != 2 || result.PolicyRolloutPaused != 0 {
		t.Fatalf("rollout summary = %+v rollouts=%+v, want cancelled planned rollout without pause", result, rollouts)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.Cancelled || rollouts[0].Rollout.Paused {
		t.Fatalf("rollouts = %+v, want cancelled rollout that is not paused", rollouts)
	}
	if phases := []string{rollouts[0].Rollout.Items[0].Phase, rollouts[0].Rollout.Items[1].Phase}; !slices.Equal(phases, []string{"cancelled", "cancelled"}) {
		t.Fatalf("cancelled rollout phases = %+v, want cancelled items", phases)
	}
	if reasons := []string{rollouts[0].Rollout.Items[0].Reason, rollouts[0].Rollout.Items[1].Reason}; !slices.Equal(reasons, []string{"operator_cancelled", "operator_cancelled"}) {
		t.Fatalf("cancelled rollout reasons = %+v, want operator_cancelled", reasons)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no live mutation for cancelled rollout", entries)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-b")); len(entries) != 0 {
		t.Fatalf("pod-b entries = %+v, want no live mutation for cancelled rollout", entries)
	}
}

func TestApplyPolicyRolloutsResumesAppliedEndpoints(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:      "web-canary",
		Node:      "node-a",
		Endpoints: []string{"prod/pod-a", "prod/pod-b"},
		BatchSize: 1,
	}}
	store := dataplane.NewInMemoryPolicyStore()
	podA := model.EndpointKey("prod", "pod-a")
	podADesired := desiredPolicyEntriesForTest(t, state, "node-a", store, podA)
	if err := store.ReplaceEndpoint(context.Background(), podA, podADesired); err != nil {
		t.Fatal(err)
	}
	seedEvents := len(store.Events())

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
		PolicyRolloutResume: map[string][]string{
			"web-canary": {podA},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rollouts) != 1 {
		t.Fatalf("rollouts = %+v, want one resumed rollout", rollouts)
	}
	rollout := rollouts[0].Rollout
	if rollout.Applied != 2 || rollout.ResumedApplied != 1 {
		t.Fatalf("rollout = %+v, want one resumed endpoint and one newly applied endpoint", rollout)
	}
	if rollout.Items[0].EndpointID != podA || rollout.Items[0].Phase != "resumed_applied" {
		t.Fatalf("first rollout item = %+v, want resumed pod-a", rollout.Items[0])
	}
	if rollout.Items[0].Reason != "resumed_applied" {
		t.Fatalf("first rollout item reason = %q, want resumed_applied", rollout.Items[0].Reason)
	}
	if rollout.Items[1].Phase != "applied" {
		t.Fatalf("second rollout item = %+v, want newly applied pod-b", rollout.Items[1])
	}
	if got := len(store.Events()) - seedEvents; got != 1 {
		t.Fatalf("new policy events = %d, want only pod-b written", got)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-b")); len(entries) != 1 {
		t.Fatalf("pod-b entries = %+v, want rollout applied policy", entries)
	}
}

func TestApplyPolicyRolloutsReappliesResumedEndpointWhenPolicyDrifts(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:      "web-canary",
		Node:      "node-a",
		Endpoints: []string{"prod/pod-a"},
		BatchSize: 1,
	}}
	store := dataplane.NewInMemoryPolicyStore()
	podA := model.EndpointKey("prod", "pod-a")
	staleEntries := []dataplane.PolicyMapEntry{{
		Key:   dataplane.PolicyKey{PrefixLen: dataplane.StaticPrefixBits, Direction: dataplane.DirectionIngress},
		Value: dataplane.PolicyEntry{Precedence: 1, RuleCookie: 99, Deny: 1},
	}}
	if err := store.ReplaceEndpoint(context.Background(), podA, staleEntries); err != nil {
		t.Fatal(err)
	}
	seedEvents := len(store.Events())

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
		PolicyRolloutResume: map[string][]string{
			"web-canary": {podA},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rollouts) != 1 {
		t.Fatalf("rollouts = %+v, want one rollout", rollouts)
	}
	rollout := rollouts[0].Rollout
	if rollout.Applied != 1 || rollout.ResumedApplied != 0 || rollout.Skipped != 0 || rollout.Failed != 0 {
		t.Fatalf("rollout = %+v, want drifted resumed endpoint reapplied", rollout)
	}
	if rollout.Items[0].EndpointID != podA || rollout.Items[0].Phase != "applied" || rollout.Items[0].Reason != "resume_drift_reapplied" {
		t.Fatalf("rollout item = %+v, want applied resume_drift_reapplied", rollout.Items[0])
	}
	if got := len(store.Events()) - seedEvents; got != 1 {
		t.Fatalf("new policy events = %d, want one reapply", got)
	}
	desired := desiredPolicyEntriesForTest(t, state, "node-a", store, podA)
	if entries := store.Entries(podA); !slices.Equal(entries, desired) {
		t.Fatalf("pod-a entries = %+v, want desired entries %+v", entries, desired)
	}
}

func TestApplyPolicyRolloutsSkipsDisabledAndOtherNode(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{
		{Name: "disabled", Node: "node-a", Endpoints: []string{"prod/pod-a"}, BatchSize: 1, Disabled: true},
		{Name: "other-node", Node: "node-b", Endpoints: []string{"prod/pod-b"}, BatchSize: 1},
		{Name: "active", Node: "node-a", Endpoints: []string{"prod/pod-c"}, BatchSize: 1},
	}
	store := dataplane.NewInMemoryPolicyStore()

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rollouts) != 1 || rollouts[0].Name != "active" || rollouts[0].Rollout.Applied != 1 {
		t.Fatalf("rollouts = %+v, want only active node rollout", rollouts)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-c")); len(entries) != 1 {
		t.Fatalf("pod-c entries = %+v, want applied policy", entries)
	}
}

func TestApplyPolicyRolloutsPassesSLOGateSettings(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:                    "web-canary",
		Node:                    "node-a",
		Endpoints:               []string{"prod/pod-a", "prod/pod-b"},
		BatchSize:               1,
		SLOGated:                true,
		SLOWindowCount:          2,
		SLOWindowIntervalMS:     1,
		SLODropThresholdPercent: 20,
		SLOMinPackets:           10,
	}}
	store := dataplane.NewInMemoryPolicyStore()
	telemetry := newSequencePolicyRuleMetrics([][]dataplane.RuleMetrics{
		{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Packets:    100,
			Rejected:   0,
		}},
		{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Packets:    120,
			Rejected:   1,
		}},
		{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Packets:    140,
			Rejected:   21,
		}},
	})

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:            "node-a",
		Store:           store,
		PolicyTelemetry: telemetry,
	})
	if err != nil {
		t.Fatal(err)
	}
	var result ReconcileResult
	ApplyPolicyRolloutResults(&result, rollouts)
	if result.PolicyRollouts != 1 || result.PolicyRolloutSLOFailed != 1 || result.PolicyRolloutRolledBack != 1 || result.PolicyRolloutSkipped != 1 {
		t.Fatalf("rollout result = %+v rollouts=%+v, want desired-state SLO rollback", result, rollouts)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.SLOFailed || rollouts[0].Rollout.SLODropPercent != 52 {
		t.Fatalf("rollouts = %+v, want SLO failure propagated", rollouts)
	}
	if rollouts[0].Rollout.SLOWindowCount != 2 || rollouts[0].Rollout.SLOWindowIntervalMS != 1 {
		t.Fatalf("rollout SLO window settings = %+v, want desired-state settings propagated", rollouts[0].Rollout)
	}
}

func TestApplyPolicyRolloutsHonorsPausedRollout(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:      "paused",
		Node:      "node-a",
		Endpoints: []string{"prod/pod-a", "prod/pod-b"},
		BatchSize: 1,
		Paused:    true,
	}}
	store := dataplane.NewInMemoryPolicyStore()

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	var result ReconcileResult
	ApplyPolicyRolloutResults(&result, rollouts)
	if result.PolicyRollouts != 1 || result.PolicyRolloutPaused != 1 || result.PolicyRolloutApplied != 0 || result.PolicyRolloutSkipped != 2 {
		t.Fatalf("rollout result = %+v rollouts=%+v, want paused without mutations", result, rollouts)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.Paused || rollouts[0].Rollout.PausedAfterBatch != 0 {
		t.Fatalf("rollouts = %+v, want explicitly paused rollout", rollouts)
	}
	if reasons := []string{rollouts[0].Rollout.Items[0].Reason, rollouts[0].Rollout.Items[1].Reason}; !slices.Equal(reasons, []string{"operator_paused", "operator_paused"}) {
		t.Fatalf("paused rollout item reasons = %+v, want operator_paused", reasons)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation while paused", entries)
	}
}

func TestApplyPolicyRolloutsWaitsForFinalize(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:             "finalize-gated",
		Node:             "node-a",
		Endpoints:        []string{"prod/pod-a", "prod/pod-b"},
		BatchSize:        1,
		FinalizeRequired: true,
		FinalizeRef:      "final-1234",
	}}
	store := dataplane.NewInMemoryPolicyStore()

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	var result ReconcileResult
	ApplyPolicyRolloutResults(&result, rollouts)
	if result.PolicyRollouts != 1 || result.PolicyRolloutPaused != 1 || result.PolicyRolloutApplied != 1 || result.PolicyRolloutSkipped != 1 {
		t.Fatalf("rollout result = %+v rollouts=%+v, want finalize pending after one canary", result, rollouts)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.FinalizeRequired || !rollouts[0].Rollout.FinalizePending || rollouts[0].Rollout.FinalizeRef != "final-1234" {
		t.Fatalf("rollouts = %+v, want finalize pending metadata", rollouts)
	}
	if reasons := []string{rollouts[0].Rollout.Items[0].Reason, rollouts[0].Rollout.Items[1].Reason}; !slices.Equal(reasons, []string{"", "finalize_pending"}) {
		t.Fatalf("finalize rollout item reasons = %+v, want canary applied then finalize_pending", reasons)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want canary policy applied", entries)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-b")); len(entries) != 0 {
		t.Fatalf("pod-b entries = %+v, want finalize-paused endpoint untouched", entries)
	}
}

func TestApplyPolicyRolloutsRequiresApproval(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:             "approval-gated",
		Node:             "node-a",
		Endpoints:        []string{"prod/pod-a", "prod/pod-b"},
		BatchSize:        1,
		ApprovalRequired: true,
		ApprovalRef:      "chg-1234",
	}}
	store := dataplane.NewInMemoryPolicyStore()

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	var result ReconcileResult
	ApplyPolicyRolloutResults(&result, rollouts)
	if result.PolicyRollouts != 1 || result.PolicyRolloutPaused != 1 || result.PolicyRolloutApplied != 0 || result.PolicyRolloutSkipped != 2 {
		t.Fatalf("rollout result = %+v rollouts=%+v, want approval-gated pause", result, rollouts)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.ApprovalRequired || !rollouts[0].Rollout.ApprovalPending || !rollouts[0].Rollout.Paused || rollouts[0].Rollout.ApprovalRef != "chg-1234" {
		t.Fatalf("rollouts = %+v, want approval pending pause", rollouts)
	}
	if reasons := []string{rollouts[0].Rollout.Items[0].Reason, rollouts[0].Rollout.Items[1].Reason}; !slices.Equal(reasons, []string{"approval_pending", "approval_pending"}) {
		t.Fatalf("approval rollout item reasons = %+v, want approval_pending", reasons)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation before approval", entries)
	}

	state.PolicyRollouts[0].Approved = true
	rollouts, err = ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.Approved || rollouts[0].Rollout.ApprovalPending || rollouts[0].Rollout.Applied != 2 || rollouts[0].Rollout.ApprovalRef != "chg-1234" {
		t.Fatalf("approved rollouts = %+v, want applied rollout", rollouts)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want applied after approval", entries)
	}
}

func TestApplyPolicyRolloutsRejectsExpiredApproval(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:              "approval-gated",
		Node:              "node-a",
		Endpoints:         []string{"prod/pod-a", "prod/pod-b"},
		BatchSize:         1,
		ApprovalRequired:  true,
		Approved:          true,
		ApprovalRef:       "chg-1234",
		ApprovalExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}}
	store := dataplane.NewInMemoryPolicyStore()

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	var result ReconcileResult
	ApplyPolicyRolloutResults(&result, rollouts)
	if result.PolicyRollouts != 1 || result.PolicyRolloutPaused != 1 || result.PolicyRolloutApplied != 0 || result.PolicyRolloutSkipped != 2 {
		t.Fatalf("rollout result = %+v rollouts=%+v, want expired approval pause", result, rollouts)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.ApprovalExpired || !rollouts[0].Rollout.Paused || rollouts[0].Rollout.ApprovalExpiresAt == "" {
		t.Fatalf("rollouts = %+v, want expired approval pause with deadline", rollouts)
	}
	if reasons := []string{rollouts[0].Rollout.Items[0].Reason, rollouts[0].Rollout.Items[1].Reason}; !slices.Equal(reasons, []string{"approval_expired", "approval_expired"}) {
		t.Fatalf("approval rollout item reasons = %+v, want approval_expired", reasons)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation after expired approval", entries)
	}
}

func TestApplyPolicyRolloutsRequiresAcknowledgement(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:        "ack-gated",
		Node:        "node-a",
		Endpoints:   []string{"prod/pod-a", "prod/pod-b"},
		BatchSize:   1,
		AckRequired: true,
		AckRef:      "ack-1234",
	}}
	store := dataplane.NewInMemoryPolicyStore()

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	var result ReconcileResult
	ApplyPolicyRolloutResults(&result, rollouts)
	if result.PolicyRollouts != 1 || result.PolicyRolloutPaused != 1 || result.PolicyRolloutApplied != 0 || result.PolicyRolloutSkipped != 2 {
		t.Fatalf("rollout result = %+v rollouts=%+v, want ack-gated pause", result, rollouts)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.AckRequired || !rollouts[0].Rollout.AckPending || !rollouts[0].Rollout.Paused || rollouts[0].Rollout.AckRef != "ack-1234" {
		t.Fatalf("rollouts = %+v, want ack pending pause", rollouts)
	}
	if reasons := []string{rollouts[0].Rollout.Items[0].Reason, rollouts[0].Rollout.Items[1].Reason}; !slices.Equal(reasons, []string{"ack_pending", "ack_pending"}) {
		t.Fatalf("ack rollout item reasons = %+v, want ack_pending", reasons)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation before ack", entries)
	}

	state.PolicyRollouts[0].Acknowledged = true
	rollouts, err = ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.Acknowledged || rollouts[0].Rollout.AckPending || rollouts[0].Rollout.Applied != 2 || rollouts[0].Rollout.AckRef != "ack-1234" {
		t.Fatalf("acknowledged rollouts = %+v, want applied rollout", rollouts)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want mutation after ack", entries)
	}
}

func TestApplyPolicyRolloutsRejectsExpiredAcknowledgement(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:         "ack-gated",
		Node:         "node-a",
		Endpoints:    []string{"prod/pod-a", "prod/pod-b"},
		BatchSize:    1,
		AckRequired:  true,
		Acknowledged: true,
		AckRef:       "ack-1234",
		AckExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}}
	store := dataplane.NewInMemoryPolicyStore()

	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	var result ReconcileResult
	ApplyPolicyRolloutResults(&result, rollouts)
	if result.PolicyRollouts != 1 || result.PolicyRolloutPaused != 1 || result.PolicyRolloutApplied != 0 || result.PolicyRolloutSkipped != 2 {
		t.Fatalf("rollout result = %+v rollouts=%+v, want expired ack pause", result, rollouts)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.AckExpired || !rollouts[0].Rollout.Paused || rollouts[0].Rollout.AckExpiresAt == "" {
		t.Fatalf("rollouts = %+v, want expired ack pause with deadline", rollouts)
	}
	if reasons := []string{rollouts[0].Rollout.Items[0].Reason, rollouts[0].Rollout.Items[1].Reason}; !slices.Equal(reasons, []string{"ack_expired", "ack_expired"}) {
		t.Fatalf("ack rollout item reasons = %+v, want ack_expired", reasons)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation after expired ack", entries)
	}
}

func TestApplyPolicyRolloutsVerifiesApprovalSignature(t *testing.T) {
	state := rolloutPolicyState()
	state.PolicyRollouts = []control.PolicyRollout{{
		Name:             "approval-signed",
		Node:             "node-a",
		Endpoints:        []string{"prod/pod-a", "prod/pod-b"},
		BatchSize:        1,
		ApprovalRequired: true,
		Approved:         true,
		ApprovalRef:      "chg-5678",
	}}
	store := dataplane.NewInMemoryPolicyStore()
	_, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:                        "node-a",
		Store:                       store,
		PolicyRolloutApprovalSecret: "secret",
	})
	if err == nil || !strings.Contains(err.Error(), "approval signature is required") {
		t.Fatalf("err = %v, want missing approval signature failure", err)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation with missing signature", entries)
	}

	state.PolicyRollouts[0].ApprovalSignature = "sha256=invalid"
	_, err = ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:                        "node-a",
		Store:                       store,
		PolicyRolloutApprovalSecret: "secret",
	})
	if err == nil || !strings.Contains(err.Error(), "approval signature is invalid") {
		t.Fatalf("err = %v, want invalid approval signature failure", err)
	}

	endpointIDs := []string{model.EndpointKey("prod", "pod-a"), model.EndpointKey("prod", "pod-b")}
	state.PolicyRollouts[0].ApprovalSignature = PolicyRolloutApprovalSignature("secret", "chg-5678", endpointIDs)
	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:                        "node-a",
		Store:                       store,
		PolicyRolloutApprovalSecret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.ApprovalSignatureVerified || rollouts[0].Rollout.Applied != 2 {
		t.Fatalf("rollouts = %+v, want verified signed approval rollout", rollouts)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want applied after signed approval", entries)
	}
}

func TestApplyPolicyRolloutsChecksApprovalCallback(t *testing.T) {
	state := rolloutPolicyState()
	var callbackRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbackRequests++
		if r.Method != http.MethodPost {
			t.Fatalf("callback method = %s, want POST", r.Method)
		}
		var request struct {
			ApprovalRef string   `json:"approval_ref"`
			Revision    string   `json:"revision"`
			Endpoints   []string `json:"endpoints"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode callback request: %v", err)
		}
		if request.ApprovalRef != "chg-7777" || request.Revision != "approval-rev-1" || !slices.Equal(request.Endpoints, []string{model.EndpointKey("prod", "pod-a"), model.EndpointKey("prod", "pod-b")}) {
			t.Fatalf("callback request = %+v, want approval ref, revision, and sorted endpoints", request)
		}
		_, _ = w.Write([]byte(`{"approved":true}`))
	}))
	defer server.Close()

	state.PolicyRollouts = []control.PolicyRollout{{
		Name:                      "approval-callback",
		Node:                      "node-a",
		Revision:                  "approval-rev-1",
		Endpoints:                 []string{"prod/pod-a", "prod/pod-b"},
		BatchSize:                 1,
		ApprovalRequired:          true,
		Approved:                  true,
		ApprovalRef:               "chg-7777",
		ApprovalCallbackURL:       server.URL,
		ApprovalCallbackTimeoutMS: 500,
	}}
	store := dataplane.NewInMemoryPolicyStore()
	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if callbackRequests != 1 {
		t.Fatalf("callback requests = %d, want 1", callbackRequests)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.ApprovalCallbackApproved || rollouts[0].Rollout.Applied != 2 {
		t.Fatalf("rollouts = %+v, want callback approved applied rollout", rollouts)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want applied after callback approval", entries)
	}
}

func TestApplyPolicyRolloutsPausesWhenApprovalCallbackRejects(t *testing.T) {
	state := rolloutPolicyState()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"approved":false,"reason":"change window closed"}`))
	}))
	defer server.Close()

	state.PolicyRollouts = []control.PolicyRollout{{
		Name:                "approval-callback",
		Node:                "node-a",
		Endpoints:           []string{"prod/pod-a"},
		BatchSize:           1,
		ApprovalRequired:    true,
		Approved:            true,
		ApprovalRef:         "chg-8888",
		ApprovalCallbackURL: server.URL,
	}}
	store := dataplane.NewInMemoryPolicyStore()
	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.ApprovalPending || !rollouts[0].Rollout.Paused || rollouts[0].Rollout.Applied != 0 || rollouts[0].Rollout.Skipped != 1 {
		t.Fatalf("rollouts = %+v, want rejected callback to pause without mutation", rollouts)
	}
	if !strings.Contains(rollouts[0].Rollout.ApprovalCallbackError, "change window closed") {
		t.Fatalf("callback error = %q, want rejection reason", rollouts[0].Rollout.ApprovalCallbackError)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation after callback rejection", entries)
	}
}

func TestApplyPolicyRolloutsSyncsExternalChangeStatus(t *testing.T) {
	state := rolloutPolicyState()
	var statusRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusRequests++
		if r.Method != http.MethodPost {
			t.Fatalf("status method = %s, want POST", r.Method)
		}
		var request struct {
			ApprovalRef string   `json:"approval_ref"`
			Status      string   `json:"status"`
			Endpoints   []string `json:"endpoints"`
			Planned     int      `json:"planned"`
			Applied     int      `json:"applied"`
			Skipped     int      `json:"skipped"`
			Failed      int      `json:"failed"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode status request: %v", err)
		}
		if request.ApprovalRef != "chg-9999" || request.Status != "applied" || request.Planned != 2 || request.Applied != 2 || request.Skipped != 0 || request.Failed != 0 {
			t.Fatalf("status request = %+v, want applied summary", request)
		}
		if !slices.Equal(request.Endpoints, []string{model.EndpointKey("prod", "pod-a"), model.EndpointKey("prod", "pod-b")}) {
			t.Fatalf("status endpoints = %+v, want sorted endpoints", request.Endpoints)
		}
		_, _ = w.Write([]byte(`{"synced":true,"status":"implemented","url":"https://changes.example/chg-9999"}`))
	}))
	defer server.Close()

	state.PolicyRollouts = []control.PolicyRollout{{
		Name:                  "change-status",
		Node:                  "node-a",
		Endpoints:             []string{"prod/pod-a", "prod/pod-b"},
		BatchSize:             1,
		ApprovalRequired:      true,
		Approved:              true,
		ApprovalRef:           "chg-9999",
		ChangeStatusURL:       server.URL,
		ChangeStatusTimeoutMS: 500,
	}}
	store := dataplane.NewInMemoryPolicyStore()
	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if statusRequests != 1 {
		t.Fatalf("status requests = %d, want 1", statusRequests)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.ChangeStatusSynced || rollouts[0].Rollout.ExternalChangeStatus != "implemented" || rollouts[0].Rollout.ExternalChangeURL != "https://changes.example/chg-9999" {
		t.Fatalf("rollouts = %+v, want synced external change status", rollouts)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want applied despite external sync being observational", entries)
	}
}

func TestApplyPolicyRolloutsSyncsAckPendingChangeStatus(t *testing.T) {
	state := rolloutPolicyState()
	var statusRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusRequests++
		if r.Method != http.MethodPost {
			t.Fatalf("status method = %s, want POST", r.Method)
		}
		var request struct {
			ApprovalRef string `json:"approval_ref"`
			AckRef      string `json:"ack_ref"`
			Status      string `json:"status"`
			AckPending  bool   `json:"ack_pending"`
			Paused      bool   `json:"paused"`
			Applied     int    `json:"applied"`
			Skipped     int    `json:"skipped"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode status request: %v", err)
		}
		if request.ApprovalRef != "chg-ack" || request.AckRef != "ack-1234" || request.Status != "ack_pending" || !request.AckPending || !request.Paused || request.Applied != 0 || request.Skipped != 1 {
			t.Fatalf("status request = %+v, want ack pending summary", request)
		}
		_, _ = w.Write([]byte(`{"synced":true}`))
	}))
	defer server.Close()

	state.PolicyRollouts = []control.PolicyRollout{{
		Name:            "ack-status",
		Node:            "node-a",
		Endpoints:       []string{"prod/pod-a"},
		BatchSize:       1,
		ApprovalRef:     "chg-ack",
		AckRequired:     true,
		AckRef:          "ack-1234",
		ChangeStatusURL: server.URL,
	}}
	store := dataplane.NewInMemoryPolicyStore()
	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if statusRequests != 1 {
		t.Fatalf("status requests = %d, want 1", statusRequests)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.ChangeStatusSynced || !rollouts[0].Rollout.AckPending {
		t.Fatalf("rollouts = %+v, want synced ack pending rollout", rollouts)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation before ack", entries)
	}
}

func TestApplyPolicyRolloutsSyncsRiskAckPendingChangeStatus(t *testing.T) {
	state := rolloutPolicyState()
	state.SecurityGroups[0].Rules[0].Action = model.ActionReject
	state.SecurityGroups[0].Rules[0].ID = "reject-http"
	var statusRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusRequests++
		if r.Method != http.MethodPost {
			t.Fatalf("status method = %s, want POST", r.Method)
		}
		var request struct {
			ApprovalRef        string `json:"approval_ref"`
			RiskAckRef         string `json:"risk_ack_ref"`
			Status             string `json:"status"`
			RiskAckRequired    bool   `json:"risk_ack_required"`
			RiskAcknowledged   bool   `json:"risk_acknowledged"`
			RiskAckPending     bool   `json:"risk_ack_pending"`
			RiskBlockingChange bool   `json:"risk_blocking_change"`
			Paused             bool   `json:"paused"`
			Applied            int    `json:"applied"`
			Skipped            int    `json:"skipped"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode status request: %v", err)
		}
		if request.ApprovalRef != "chg-risk" ||
			request.RiskAckRef != "risk-9999" ||
			request.Status != "risk_ack_pending" ||
			!request.RiskAckRequired ||
			request.RiskAcknowledged ||
			!request.RiskAckPending ||
			!request.RiskBlockingChange ||
			!request.Paused ||
			request.Applied != 0 ||
			request.Skipped != 1 {
			t.Fatalf("status request = %+v, want risk ack pending summary", request)
		}
		_, _ = w.Write([]byte(`{"synced":true}`))
	}))
	defer server.Close()

	state.PolicyRollouts = []control.PolicyRollout{{
		Name:            "risk-ack-status",
		Node:            "node-a",
		Endpoints:       []string{"prod/pod-a"},
		BatchSize:       1,
		ApprovalRef:     "chg-risk",
		RiskAckRequired: true,
		RiskAckRef:      "risk-9999",
		ChangeStatusURL: server.URL,
	}}
	store := dataplane.NewInMemoryPolicyStore()
	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if statusRequests != 1 {
		t.Fatalf("status requests = %d, want 1", statusRequests)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.ChangeStatusSynced || !rollouts[0].Rollout.RiskAckPending || !rollouts[0].Rollout.Risk.BlockingChange {
		t.Fatalf("rollouts = %+v, want synced risk ack pending rollout", rollouts)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation before risk ack", entries)
	}
}

func TestApplyPolicyRolloutsSyncsCancelledChangeStatus(t *testing.T) {
	state := rolloutPolicyState()
	var statusRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusRequests++
		if r.Method != http.MethodPost {
			t.Fatalf("status method = %s, want POST", r.Method)
		}
		var request struct {
			ApprovalRef string `json:"approval_ref"`
			Status      string `json:"status"`
			Cancelled   bool   `json:"cancelled"`
			Paused      bool   `json:"paused"`
			Applied     int    `json:"applied"`
			Skipped     int    `json:"skipped"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode status request: %v", err)
		}
		if request.ApprovalRef != "chg-cancel" || request.Status != "cancelled" || !request.Cancelled || request.Paused || request.Applied != 0 || request.Skipped != 1 {
			t.Fatalf("status request = %+v, want cancelled summary", request)
		}
		_, _ = w.Write([]byte(`{"synced":true,"status":"cancelled","url":"https://changes.example/chg-cancel"}`))
	}))
	defer server.Close()

	state.PolicyRollouts = []control.PolicyRollout{{
		Name:            "cancel-status",
		Node:            "node-a",
		Endpoints:       []string{"prod/pod-a"},
		BatchSize:       1,
		ApprovalRef:     "chg-cancel",
		Cancelled:       true,
		ChangeStatusURL: server.URL,
	}}
	store := dataplane.NewInMemoryPolicyStore()
	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if statusRequests != 1 {
		t.Fatalf("status requests = %d, want 1", statusRequests)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.ChangeStatusSynced || !rollouts[0].Rollout.Cancelled || rollouts[0].Rollout.ExternalChangeStatus != "cancelled" || rollouts[0].Rollout.ExternalChangeURL != "https://changes.example/chg-cancel" {
		t.Fatalf("rollouts = %+v, want synced cancelled rollout", rollouts)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation for cancelled rollout", entries)
	}
}

func TestApplyPolicyRolloutsPollsExternalChangeStatusBeforeApply(t *testing.T) {
	state := rolloutPolicyState()
	var pollRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pollRequests++
		if r.Method != http.MethodPost {
			t.Fatalf("poll method = %s, want POST", r.Method)
		}
		var request struct {
			ApprovalRef string   `json:"approval_ref"`
			Revision    string   `json:"revision"`
			Endpoints   []string `json:"endpoints"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode poll request: %v", err)
		}
		if request.ApprovalRef != "chg-1000" || request.Revision != "poll-rev-1" || !slices.Equal(request.Endpoints, []string{model.EndpointKey("prod", "pod-a")}) {
			t.Fatalf("poll request = %+v, want approval ref, revision, and endpoint", request)
		}
		_, _ = w.Write([]byte(`{"allowed":true,"status":"approved","url":"https://changes.example/chg-1000"}`))
	}))
	defer server.Close()

	state.PolicyRollouts = []control.PolicyRollout{{
		Name:                "change-poll",
		Node:                "node-a",
		Revision:            "poll-rev-1",
		Endpoints:           []string{"prod/pod-a"},
		BatchSize:           1,
		ApprovalRequired:    true,
		Approved:            true,
		ApprovalRef:         "chg-1000",
		ChangePollURL:       server.URL,
		ChangePollTimeoutMS: 500,
	}}
	store := dataplane.NewInMemoryPolicyStore()
	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pollRequests != 1 {
		t.Fatalf("poll requests = %d, want 1", pollRequests)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.ChangePollAllowed || rollouts[0].Rollout.ChangePollStatus != "approved" || rollouts[0].Rollout.ExternalChangeURL != "https://changes.example/chg-1000" || rollouts[0].Rollout.Applied != 1 {
		t.Fatalf("rollouts = %+v, want allowed change poll and applied rollout", rollouts)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want applied after change poll approval", entries)
	}
}

func TestApplyPolicyRolloutsPausesWhenExternalChangePollRejects(t *testing.T) {
	state := rolloutPolicyState()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"allowed":false,"status":"closed","reason":"change was closed"}`))
	}))
	defer server.Close()

	state.PolicyRollouts = []control.PolicyRollout{{
		Name:          "change-poll-rejected",
		Node:          "node-a",
		Endpoints:     []string{"prod/pod-a"},
		BatchSize:     1,
		ApprovalRef:   "chg-1001",
		ChangePollURL: server.URL,
	}}
	store := dataplane.NewInMemoryPolicyStore()
	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rollouts) != 1 || !rollouts[0].Rollout.ApprovalPending || !rollouts[0].Rollout.Paused || rollouts[0].Rollout.Applied != 0 || rollouts[0].Rollout.Skipped != 1 {
		t.Fatalf("rollouts = %+v, want rejected change poll to pause without mutation", rollouts)
	}
	if !strings.Contains(rollouts[0].Rollout.ChangePollError, "change was closed") || rollouts[0].Rollout.ChangePollStatus != "closed" {
		t.Fatalf("change poll result = status %q err %q, want closed rejection", rollouts[0].Rollout.ChangePollStatus, rollouts[0].Rollout.ChangePollError)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation after change poll rejection", entries)
	}
}

func TestApplyPolicyRolloutsRecordsExternalChangeStatusFailure(t *testing.T) {
	state := rolloutPolicyState()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	state.PolicyRollouts = []control.PolicyRollout{{
		Name:            "change-status-failed",
		Node:            "node-a",
		Endpoints:       []string{"prod/pod-a"},
		BatchSize:       1,
		ChangeStatusURL: server.URL,
	}}
	store := dataplane.NewInMemoryPolicyStore()
	rollouts, err := ApplyPolicyRollouts(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rollouts) != 1 || rollouts[0].Rollout.ChangeStatusSynced || !strings.Contains(rollouts[0].Rollout.ChangeStatusError, "status 502") || rollouts[0].Rollout.Applied != 1 {
		t.Fatalf("rollouts = %+v, want recorded sync failure without rollout rollback", rollouts)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want policy mutation to remain applied", entries)
	}
}

func TestRolloutPolicyEndpointsPausesAfterBatch(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{
			model.EndpointKey("prod", "pod-a"),
			model.EndpointKey("prod", "pod-b"),
			model.EndpointKey("prod", "pod-c"),
		},
		BatchSize:         1,
		PauseAfterBatches: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollout.Paused || rollout.PausedAfterBatch != 1 || rollout.Applied != 1 || rollout.Skipped != 2 || rollout.Failed != 0 {
		t.Fatalf("rollout = %+v, want paused after first batch", rollout)
	}
	phases := []string{rollout.Items[0].Phase, rollout.Items[1].Phase, rollout.Items[2].Phase}
	if !slices.Equal(phases, []string{"applied", "paused", "paused"}) {
		t.Fatalf("rollout phases = %+v, want applied paused paused", phases)
	}
	reasons := []string{rollout.Items[0].Reason, rollout.Items[1].Reason, rollout.Items[2].Reason}
	if !slices.Equal(reasons, []string{"", "pause_after_batch", "pause_after_batch"}) {
		t.Fatalf("rollout reasons = %+v, want pause_after_batch for paused endpoints", reasons)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want first batch applied", entries)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-b")); len(entries) != 0 {
		t.Fatalf("pod-b entries = %+v, want paused endpoint untouched", entries)
	}
}

func TestRolloutPolicyEndpointsWaitsForFinalizeAfterBatch(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{
			model.EndpointKey("prod", "pod-a"),
			model.EndpointKey("prod", "pod-b"),
			model.EndpointKey("prod", "pod-c"),
		},
		BatchSize:        1,
		FinalizeRequired: true,
		FinalizeRef:      "final-1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollout.Paused || !rollout.FinalizeRequired || !rollout.FinalizePending || rollout.Finalized || rollout.FinalizeRef != "final-1234" ||
		rollout.PausedAfterBatch != 1 || rollout.Applied != 1 || rollout.Skipped != 2 || rollout.Failed != 0 {
		t.Fatalf("rollout = %+v, want finalize pending after first batch", rollout)
	}
	phases := []string{rollout.Items[0].Phase, rollout.Items[1].Phase, rollout.Items[2].Phase}
	if !slices.Equal(phases, []string{"applied", "paused", "paused"}) {
		t.Fatalf("rollout phases = %+v, want applied paused paused", phases)
	}
	reasons := []string{rollout.Items[0].Reason, rollout.Items[1].Reason, rollout.Items[2].Reason}
	if !slices.Equal(reasons, []string{"", "finalize_pending", "finalize_pending"}) {
		t.Fatalf("rollout reasons = %+v, want finalize_pending for paused endpoints", reasons)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want first batch applied", entries)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-b")); len(entries) != 0 {
		t.Fatalf("pod-b entries = %+v, want finalize-paused endpoint untouched", entries)
	}
}

func TestRolloutPolicyEndpointsRejectsExpiredFinalize(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{
			model.EndpointKey("prod", "pod-a"),
			model.EndpointKey("prod", "pod-b"),
		},
		BatchSize:         1,
		FinalizeRequired:  true,
		FinalizeExpiresAt: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollout.Paused || !rollout.FinalizeExpired || rollout.Applied != 0 || rollout.Skipped != 2 || rollout.Failed != 0 {
		t.Fatalf("rollout = %+v, want expired finalize pause without applying", rollout)
	}
	reasons := []string{rollout.Items[0].Reason, rollout.Items[1].Reason}
	if !slices.Equal(reasons, []string{"finalize_expired", "finalize_expired"}) {
		t.Fatalf("rollout reasons = %+v, want finalize_expired", reasons)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no policy mutation after expired finalize", entries)
	}
}

func TestRolloutPolicyEndpointsContinuesAfterFinalize(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{
			model.EndpointKey("prod", "pod-a"),
			model.EndpointKey("prod", "pod-b"),
		},
		BatchSize:        1,
		FinalizeRequired: true,
		Finalized:        true,
		FinalizeRef:      "final-1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rollout.Paused || rollout.FinalizePending || !rollout.Finalized || rollout.Applied != 2 || rollout.Skipped != 0 || rollout.Failed != 0 {
		t.Fatalf("rollout = %+v, want finalized rollout to continue both endpoints", rollout)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want policy applied", entries)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-b")); len(entries) != 1 {
		t.Fatalf("pod-b entries = %+v, want policy applied", entries)
	}
}

func TestRolloutPolicyEndpointsPausesAtPromotionPercent(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{
			model.EndpointKey("prod", "pod-a"),
			model.EndpointKey("prod", "pod-b"),
			model.EndpointKey("prod", "pod-c"),
		},
		BatchSize:        1,
		PromotionPercent: 34,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollout.Paused || rollout.PromotionPercent != 34 || rollout.PromotionLimit != 2 || rollout.Applied != 2 || rollout.Skipped != 1 || rollout.Failed != 0 {
		t.Fatalf("rollout = %+v, want paused after 34%% promotion limit", rollout)
	}
	phases := []string{rollout.Items[0].Phase, rollout.Items[1].Phase, rollout.Items[2].Phase}
	if !slices.Equal(phases, []string{"applied", "applied", "paused"}) {
		t.Fatalf("rollout phases = %+v, want applied applied paused", phases)
	}
	reasons := []string{rollout.Items[0].Reason, rollout.Items[1].Reason, rollout.Items[2].Reason}
	if !slices.Equal(reasons, []string{"", "", "promotion_limit"}) {
		t.Fatalf("rollout reasons = %+v, want promotion_limit for paused endpoint", reasons)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-c")); len(entries) != 0 {
		t.Fatalf("pod-c entries = %+v, want promotion-paused endpoint untouched", entries)
	}
}

func TestRolloutPolicyEndpointsPressureAwareShrinksBatchSize(t *testing.T) {
	state := rolloutPolicyState()
	store := &rolloutPressurePolicyStore{
		InMemoryPolicyStore: dataplane.NewInMemoryPolicyStore(),
		usage: []dataplane.PolicyMapUsage{
			{
				EndpointID: model.EndpointKey("prod", "pod-a"),
				Entries:    9,
				Capacity:   10,
			},
			{
				EndpointID: model.EndpointKey("prod", "pod-b"),
				Entries:    8,
				Capacity:   10,
			},
		},
	}

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		BatchSize:                3,
		DryRun:                   true,
		PressureAware:            true,
		PressureThresholdPercent: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollout.PressureAware || !rollout.PressureAdjusted || rollout.RequestedBatchSize != 3 || rollout.BatchSize != 1 {
		t.Fatalf("rollout = %+v, want pressure adjusted batch 1 from requested 3", rollout)
	}
	if rollout.PressureMaxPercent != 90 || rollout.PressureEndpoint != model.EndpointKey("prod", "pod-a") || rollout.PressureThresholdPercent != 80 {
		t.Fatalf("rollout pressure fields = %+v, want max=90 endpoint pod-a threshold 80", rollout)
	}
	wantHotspots := []dataplane.PolicyMapPressureHotspot{
		{EndpointID: model.EndpointKey("prod", "pod-a"), Entries: 9, Capacity: 10, PressurePercent: 90},
		{EndpointID: model.EndpointKey("prod", "pod-b"), Entries: 8, Capacity: 10, PressurePercent: 80},
	}
	if !slices.EqualFunc(rollout.PressureHotspots, wantHotspots, func(a, b dataplane.PolicyMapPressureHotspot) bool {
		return a == b
	}) {
		t.Fatalf("rollout pressure hotspots = %+v, want %+v", rollout.PressureHotspots, wantHotspots)
	}
	if len(rollout.Items) != 3 || rollout.Items[0].Batch != 1 || rollout.Items[1].Batch != 2 || rollout.Items[2].Batch != 3 {
		t.Fatalf("rollout batches = %+v, want one endpoint per batch", rollout.Items)
	}
}

func TestRolloutPolicyEndpointsPressureAwareKeepsBatchBelowThreshold(t *testing.T) {
	state := rolloutPolicyState()
	store := &rolloutPressurePolicyStore{
		InMemoryPolicyStore: dataplane.NewInMemoryPolicyStore(),
		usage: []dataplane.PolicyMapUsage{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Entries:    4,
			Capacity:   10,
		}},
	}

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		BatchSize:                3,
		DryRun:                   true,
		PressureAware:            true,
		PressureThresholdPercent: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rollout.PressureAdjusted || rollout.BatchSize != 3 || rollout.PressureMaxPercent != 40 {
		t.Fatalf("rollout = %+v, want unchanged batch below pressure threshold", rollout)
	}
	if len(rollout.Items) != 3 || rollout.Items[0].Batch != 1 || rollout.Items[1].Batch != 1 || rollout.Items[2].Batch != 1 {
		t.Fatalf("rollout batches = %+v, want original batch size 3", rollout.Items)
	}
}

func TestRolloutPolicyEndpointsStopsAfterApplyFailure(t *testing.T) {
	state := rolloutPolicyState()
	store := &failingPolicyStore{
		InMemoryPolicyStore: dataplane.NewInMemoryPolicyStore(),
		failEndpoint:        model.EndpointKey("prod", "pod-b"),
	}
	oldEntries := []dataplane.PolicyMapEntry{{
		Key: dataplane.PolicyKey{
			PrefixLen:      dataplane.StaticPrefixBits + 24,
			RemoteIdentity: 2,
			Direction:      dataplane.DirectionIngress,
		},
		Value:      dataplane.PolicyEntry{Deny: 1, RuleCookie: 99},
		RemoteCIDR: netip.MustParsePrefix("198.51.100.0/24"),
	}}
	if err := store.ReplaceEndpoint(context.Background(), model.EndpointKey("prod", "pod-a"), oldEntries); err != nil {
		t.Fatal(err)
	}

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{
			model.EndpointKey("prod", "pod-a"),
			model.EndpointKey("prod", "pod-b"),
			model.EndpointKey("prod", "pod-c"),
		},
		BatchSize: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rollout.Planned != 3 || rollout.Applied != 1 || rollout.Failed != 1 || rollout.Skipped != 1 || rollout.RolledBack != 1 || rollout.RollbackFailed != 0 {
		t.Fatalf("rollout summary = %+v, want applied=1 failed=1 skipped=1 rolled_back=1", rollout)
	}
	phases := []string{rollout.Items[0].Phase, rollout.Items[1].Phase, rollout.Items[2].Phase}
	if !slices.Equal(phases, []string{"rolled_back", "failed", "skipped"}) {
		t.Fatalf("rollout phases = %+v, want rolled_back failed skipped", phases)
	}
	reasons := []string{rollout.Items[0].Reason, rollout.Items[1].Reason, rollout.Items[2].Reason}
	if !slices.Equal(reasons, []string{"rollback", "apply_failed", "rollout_failed"}) {
		t.Fatalf("rollout reasons = %+v, want rollback apply_failed rollout_failed", reasons)
	}
	if rollout.Items[1].Error == "" {
		t.Fatalf("failed rollout item = %+v, want error", rollout.Items[1])
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); !slices.Equal(entries, oldEntries) {
		t.Fatalf("pod-a entries = %+v, want rolled back entries %+v", entries, oldEntries)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-c")); len(entries) != 0 {
		t.Fatalf("pod-c entries = %+v, want skipped endpoint untouched", entries)
	}
}

func TestRolloutPolicyEndpointsSLOGateRollsBackFailedCanary(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()
	telemetry := staticPolicyRuleMetrics{metrics: []dataplane.RuleMetrics{{
		EndpointID: model.EndpointKey("prod", "pod-a"),
		Packets:    100,
		Dropped:    60,
	}}}

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:            "node-a",
		Store:           store,
		PolicyTelemetry: telemetry,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{
			model.EndpointKey("prod", "pod-a"),
			model.EndpointKey("prod", "pod-b"),
			model.EndpointKey("prod", "pod-c"),
		},
		BatchSize:               1,
		SLOGated:                true,
		SLODropThresholdPercent: 10,
		SLOMinPackets:           10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollout.SLOGated || !rollout.SLOFailed || rollout.SLODropPercent != 60 || rollout.SLOPackets != 100 || rollout.SLOError == "" {
		t.Fatalf("rollout SLO = %+v, want failed 60%% over threshold", rollout)
	}
	if rollout.Applied != 1 || rollout.Failed != 1 || rollout.Skipped != 2 || rollout.RolledBack != 1 || rollout.RollbackFailed != 0 {
		t.Fatalf("rollout summary = %+v, want canary rollback and skipped remaining endpoints", rollout)
	}
	phases := []string{rollout.Items[0].Phase, rollout.Items[1].Phase, rollout.Items[2].Phase}
	if !slices.Equal(phases, []string{"rolled_back", "skipped", "skipped"}) {
		t.Fatalf("rollout phases = %+v, want rolled_back skipped skipped", phases)
	}
	reasons := []string{rollout.Items[0].Reason, rollout.Items[1].Reason, rollout.Items[2].Reason}
	if !slices.Equal(reasons, []string{"slo_failed", "rollout_failed", "rollout_failed"}) {
		t.Fatalf("rollout reasons = %+v, want slo_failed then rollout_failed", reasons)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want SLO rollback to remove canary policy", entries)
	}
}

func TestRolloutPolicyEndpointsSLOGateWaitsForMinimumSamples(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()
	telemetry := staticPolicyRuleMetrics{metrics: []dataplane.RuleMetrics{{
		EndpointID: model.EndpointKey("prod", "pod-a"),
		Packets:    5,
		Dropped:    5,
	}}}

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:            "node-a",
		Store:           store,
		PolicyTelemetry: telemetry,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{
			model.EndpointKey("prod", "pod-a"),
		},
		BatchSize:               1,
		SLOGated:                true,
		SLODropThresholdPercent: 10,
		SLOMinPackets:           10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rollout.SLOFailed || rollout.Applied != 1 || rollout.RolledBack != 0 || rollout.SLOPackets != 5 || rollout.SLODropPercent != 100 {
		t.Fatalf("rollout = %+v, want SLO sample below minimum without rollback", rollout)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want canary policy kept while SLO waits for samples", entries)
	}
}

func TestRolloutPolicyEndpointsSLOGateUsesMultiWindowDeltas(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()
	telemetry := newSequencePolicyRuleMetrics([][]dataplane.RuleMetrics{
		{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Packets:    100,
			Dropped:    0,
		}},
		{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Packets:    120,
			Dropped:    1,
		}},
		{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Packets:    140,
			Dropped:    9,
		}},
	})

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:            "node-a",
		Store:           store,
		PolicyTelemetry: telemetry,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{
			model.EndpointKey("prod", "pod-a"),
			model.EndpointKey("prod", "pod-b"),
		},
		BatchSize:               1,
		SLOGated:                true,
		SLODropThresholdPercent: 10,
		SLOMinPackets:           10,
		SLOWindowCount:          2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollout.SLOFailed || rollout.SLOPackets != 40 || rollout.SLODropPercent != 22 || rollout.RolledBack != 1 || rollout.Skipped != 1 {
		t.Fatalf("rollout = %+v, want second SLO window rollback from delta samples", rollout)
	}
	if len(rollout.SLOWindows) != 2 {
		t.Fatalf("SLO windows = %+v, want 2 windows", rollout.SLOWindows)
	}
	if first := rollout.SLOWindows[0]; !first.Passed || first.Packets != 20 || first.Drops != 1 || first.DropPercent != 5 {
		t.Fatalf("first SLO window = %+v, want passing 1/20", first)
	}
	if second := rollout.SLOWindows[1]; second.Passed || second.Reason != "drop_threshold_exceeded" || second.Packets != 20 || second.Drops != 8 || second.DropPercent != 40 {
		t.Fatalf("second SLO window = %+v, want failed 8/20", second)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want SLO rollback", entries)
	}
}

func TestRolloutPolicyEndpointsProbeRollsBackFailedCanary(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{
			model.EndpointKey("prod", "pod-a"),
			model.EndpointKey("prod", "pod-b"),
		},
		BatchSize: 1,
		Probes: []control.PolicyRolloutProbe{{
			Name:           "web-ready",
			Type:           "http",
			URL:            server.URL,
			ExpectedStatus: http.StatusOK,
			TimeoutMS:      1000,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollout.ProbeFailed || rollout.ProbeError == "" || rollout.Failed != 1 || rollout.RolledBack != 1 || rollout.Skipped != 1 {
		t.Fatalf("rollout = %+v, want failed probe rollback", rollout)
	}
	if len(rollout.Probes) != 1 || rollout.Probes[0].Passed || rollout.Probes[0].StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("probe results = %+v, want failed HTTP probe", rollout.Probes)
	}
	reasons := []string{rollout.Items[0].Reason, rollout.Items[1].Reason}
	if !slices.Equal(reasons, []string{"probe_failed", "rollout_failed"}) {
		t.Fatalf("rollout reasons = %+v, want probe_failed then rollout_failed", reasons)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want probe rollback", entries)
	}
}

func TestRolloutPolicyEndpointsProbeRollsBackBodyMismatch(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("warming"))
	}))
	defer server.Close()

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{
			model.EndpointKey("prod", "pod-a"),
			model.EndpointKey("prod", "pod-b"),
		},
		BatchSize: 1,
		Probes: []control.PolicyRolloutProbe{{
			Name:                 "web-ready",
			Type:                 "http",
			URL:                  server.URL,
			ExpectedStatus:       http.StatusOK,
			ExpectedBodyContains: "ready",
			TimeoutMS:            1000,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollout.ProbeFailed || rollout.ProbeError == "" || rollout.Failed != 1 || rollout.RolledBack != 1 || rollout.Skipped != 1 {
		t.Fatalf("rollout = %+v, want body-mismatch probe rollback", rollout)
	}
	if len(rollout.Probes) != 1 || rollout.Probes[0].Passed || !strings.Contains(rollout.Probes[0].Error, `body missing "ready"`) {
		t.Fatalf("probe results = %+v, want failed HTTP body probe", rollout.Probes)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want probe rollback", entries)
	}
}

func TestRolloutPolicyEndpointsProbeAcceptsTCP(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{
			model.EndpointKey("prod", "pod-a"),
		},
		BatchSize: 1,
		Probes: []control.PolicyRolloutProbe{{
			Name:      "tcp-ready",
			Type:      "tcp",
			Address:   listener.Addr().String(),
			TimeoutMS: 1000,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if rollout.ProbeFailed || rollout.Failed != 0 || rollout.Applied != 1 || rollout.RolledBack != 0 {
		t.Fatalf("rollout = %+v, want successful TCP probe", rollout)
	}
	if len(rollout.Probes) != 1 || !rollout.Probes[0].Passed || rollout.Probes[0].Type != "tcp" {
		t.Fatalf("probe results = %+v, want passed TCP probe", rollout.Probes)
	}
}

func TestRolloutPolicyEndpointsProbeAcceptsTLS(t *testing.T) {
	state := rolloutPolicyState()
	store := dataplane.NewInMemoryPolicyStore()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()

	rollout, err := RolloutPolicyEndpoints(context.Background(), state, ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, PolicyEndpointRolloutOptions{
		EndpointIDs: []string{
			model.EndpointKey("prod", "pod-a"),
		},
		BatchSize: 1,
		Probes: []control.PolicyRolloutProbe{{
			Name:      "tls-ready",
			Type:      "tls",
			Address:   server.Listener.Addr().String(),
			TimeoutMS: 1000,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rollout.ProbeFailed || rollout.Failed != 0 || rollout.Applied != 1 || rollout.RolledBack != 0 {
		t.Fatalf("rollout = %+v, want successful TLS probe", rollout)
	}
	if len(rollout.Probes) != 1 || !rollout.Probes[0].Passed || rollout.Probes[0].Type != "tls" || rollout.Probes[0].Target != server.Listener.Addr().String() {
		t.Fatalf("probe results = %+v, want passed TLS probe", rollout.Probes)
	}
}

type failingPolicyStore struct {
	*dataplane.InMemoryPolicyStore
	failEndpoint string
}

func (s *failingPolicyStore) ReplaceEndpoint(ctx context.Context, endpointID string, entries []dataplane.PolicyMapEntry) error {
	if endpointID == s.failEndpoint {
		return fmt.Errorf("forced rollout failure for %s", endpointID)
	}
	return s.InMemoryPolicyStore.ReplaceEndpoint(ctx, endpointID, entries)
}

type rolloutPressurePolicyStore struct {
	*dataplane.InMemoryPolicyStore
	usage []dataplane.PolicyMapUsage
}

func (s *rolloutPressurePolicyStore) PolicyMapUsage(context.Context) ([]dataplane.PolicyMapUsage, error) {
	return append([]dataplane.PolicyMapUsage(nil), s.usage...), nil
}

type staticPolicyRuleMetrics struct {
	metrics []dataplane.RuleMetrics
}

func (s staticPolicyRuleMetrics) PolicyRuleMetrics(context.Context) ([]dataplane.RuleMetrics, error) {
	return append([]dataplane.RuleMetrics(nil), s.metrics...), nil
}

type sequencePolicyRuleMetrics struct {
	mu      sync.Mutex
	metrics [][]dataplane.RuleMetrics
	next    int
}

func newSequencePolicyRuleMetrics(metrics [][]dataplane.RuleMetrics) *sequencePolicyRuleMetrics {
	return &sequencePolicyRuleMetrics{metrics: metrics}
}

func (s *sequencePolicyRuleMetrics) PolicyRuleMetrics(context.Context) ([]dataplane.RuleMetrics, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.metrics) == 0 {
		return nil, nil
	}
	index := s.next
	if index >= len(s.metrics) {
		index = len(s.metrics) - 1
	} else {
		s.next++
	}
	return append([]dataplane.RuleMetrics(nil), s.metrics[index]...), nil
}

func rolloutPolicyState() control.DesiredState {
	return control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
			{ID: "pod-b", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.11"), Node: "node-a", SecurityGroups: []string{"web"}},
			{ID: "pod-c", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.12"), Node: "node-a", SecurityGroups: []string{"web"}},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	}
}

func desiredPolicyEntriesForTest(t *testing.T, state control.DesiredState, node string, store PolicyStore, endpointID string) []dataplane.PolicyMapEntry {
	t.Helper()
	program, err := compileEndpointPolicyProgram(state, ReconcileOptions{Node: node, Store: store}, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := dataplane.EncodeProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	return entries
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

func TestReconcileNodeReportsPolicyRuleCatalog(t *testing.T) {
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
	store := dataplane.NewInMemoryPolicyStore()
	result, err := ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.PolicyRuleCatalog) != 1 {
		t.Fatalf("policy rule catalog = %+v, want one compiled rule", result.PolicyRuleCatalog)
	}
	entry := result.PolicyRuleCatalog[0]
	if entry.EndpointID != model.EndpointKey("prod", "pod-a") ||
		entry.RuleRef != "prod/web/allow-web" ||
		entry.VPC != "prod" ||
		entry.SecurityGroup != "web" ||
		entry.RuleID != "allow-web" ||
		entry.RuleCookie != dataplane.PolicyRuleCookie("prod/web/allow-web") {
		t.Fatalf("policy rule catalog entry = %+v, want endpoint-qualified rule reference", entry)
	}
	entries := store.Entries(model.EndpointKey("prod", "pod-a"))
	if len(entries) != 1 || entries[0].Value.RuleCookie != entry.RuleCookie {
		t.Fatalf("policy map entries = %+v, want catalog cookie %d", entries, entry.RuleCookie)
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
				}, {
					RuleCookie:  43,
					Packets:     1,
					Bytes:       64,
					Rejected:    1,
					RejectDrops: 1,
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
	if result.PolicyRulePackets != 3 || result.PolicyRuleBytes != 192 || result.PolicyRuleDropped != 2 || result.PolicyRuleRejected != 1 || result.PolicyRuleAllowed != 0 {
		t.Fatalf("policy rule metric summary = %+v", result)
	}
	if len(result.PolicyRuleStats) != 2 {
		t.Fatalf("policy rule stats = %+v, want two tcx rule buckets", result.PolicyRuleStats)
	}
	if result.PolicyRuleStats[0].EndpointID != endpointID || result.PolicyRuleStats[0].RuleCookie != 42 || result.PolicyRuleStats[0].DenyDrops != 2 {
		t.Fatalf("tcx rule stats = %+v, want endpoint-labelled drop counters", result.PolicyRuleStats[0])
	}
	if result.PolicyRuleStats[1].EndpointID != endpointID || result.PolicyRuleStats[1].RuleCookie != 43 || result.PolicyRuleStats[1].Rejected != 1 || result.PolicyRuleStats[1].RejectDrops != 1 {
		t.Fatalf("tcx reject rule stats = %+v, want endpoint-labelled reject counters", result.PolicyRuleStats[1])
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

func TestReconcileNodeWithTCXProjectsRemoteEndpointPolicyToFastPath(t *testing.T) {
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
	if result.Entries != 1 || result.TCXEligible != 1 || result.TCXSkipped != 0 {
		t.Fatalf("result = %+v, want remote-group drop in policy map and TCX fast path", result)
	}
	if len(targets) != 1 || len(programs) != 1 {
		t.Fatalf("targets/programs = %d/%d, want one TCX target and one policy program", len(targets), len(programs))
	}
	rules, err := dataplane.IPv4L4ACLRulesFromProgramsForDirection(targets[0].programs, model.DirectionIngress)
	if err != nil {
		t.Fatalf("IPv4 TCX rules: %v", err)
	}
	if len(rules) != 1 ||
		rules[0].SourceCIDR != netip.MustParsePrefix("10.10.0.11/32") ||
		rules[0].DestPort != 8080 ||
		rules[0].Action != dataplane.TCXDrop {
		t.Fatalf("IPv4 TCX rules = %+v, want remote endpoint /32 drop", rules)
	}
	entries := store.Entries(model.EndpointKey("prod", "pod-a"))
	if len(entries) != 1 {
		t.Fatalf("policy map entries = %d, want 1", len(entries))
	}
	if entries[0].Key.RemoteIdentity != policy.EndpointIdentity(model.EndpointKey("prod", "pod-b")) || entries[0].Value.RequireIdentity != 1 {
		t.Fatalf("policy map entry = %+v, want required pod-b identity", entries[0])
	}
	if entries[0].RemoteCIDR != netip.MustParsePrefix("10.10.0.11/32") {
		t.Fatalf("remote cidr = %s, want pod-b /32", entries[0].RemoteCIDR)
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
			TenantQuotas: []model.ProviderNetworkTenantQuota{{
				Tenant:       "prod",
				MaxSubnets:   1,
				MaxEndpoints: 2,
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
		},
		LinuxDatapathApply: linuxDatapathApplyResult(linuxdatapath.Result{
			Device:                 "nl0",
			ProviderNetworks:       1,
			ProviderLinks:          1,
			ProviderReady:          0,
			ProviderDegraded:       1,
			ProviderInventoryTotal: 1,
			ProviderInventoryReady: 1,
			ProviderInventoryStatus: []linuxdatapath.ProviderInterface{
				{Name: "eth1", Ready: true},
			},
			ProviderStatus: []linuxdatapath.ProviderLinkStatus{{
				ProviderNetwork: "physnet-a",
				ParentDevice:    "eth1",
				VLAN:            100,
				LinkName:        "nlv100",
				ParentState:     "up",
				LinkState:       "missing",
			}},
			ProviderNetworkStatus: []linuxdatapath.ProviderNetworkStatus{{
				ProviderNetwork: "physnet-a",
				Ready:           false,
				LinkCount:       1,
				TenantCount:     1,
				SubnetCount:     1,
				EndpointCount:   1,
				TenantUsage: []linuxdatapath.ProviderTenantUsage{{
					Tenant:       "prod",
					Subnets:      1,
					Endpoints:    1,
					MaxSubnets:   1,
					MaxEndpoints: 2,
				}},
			}},
		}, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderNetworks != 1 || result.ProviderLinks != 1 {
		t.Fatalf("provider counts = %+v, want provider_networks=1 provider_links=1", result)
	}
	if len(result.ProviderNetworkStatus) != 1 {
		t.Fatalf("provider network status = %+v, want 1 entry", result.ProviderNetworkStatus)
	}
	status := result.ProviderNetworkStatus[0]
	if status.TenantCount != 1 || status.SubnetCount != 1 || status.EndpointCount != 1 {
		t.Fatalf("provider network status = %+v, want prod tenant usage", status)
	}
	if len(status.TenantUsage) != 1 {
		t.Fatalf("tenant usage = %+v, want 1 entry", status.TenantUsage)
	}
	usage := status.TenantUsage[0]
	if usage.Tenant != "prod" || usage.Subnets != 1 || usage.Endpoints != 1 || usage.MaxSubnets != 1 || usage.MaxEndpoints != 2 || usage.Exceeded {
		t.Fatalf("tenant usage = %+v, want prod quota usage", usage)
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
			StrictProviderHealth: true,
		},
		LinuxDatapathApply: linuxDatapathApplyResult(linuxdatapath.Result{
			Device:           "nl0",
			ProviderDegraded: 1,
		}, fmt.Errorf("provider health degraded: ready=0 degraded=1")),
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
		},
		LinuxDatapathApply: linuxDatapathApplyResult(linuxdatapath.Result{
			Device:                    "nl0",
			ProviderInventoryTotal:    2,
			ProviderInventoryReady:    1,
			ProviderInventoryDegraded: 1,
			ProviderInventoryStatus: []linuxdatapath.ProviderInterface{
				{Name: "eth1", Ready: true, State: "up"},
				{Name: "eth2", Ready: false, State: "down"},
			},
			ProviderIssues: []linuxdatapath.ProviderIssue{{
				ProviderNetwork: "physnet-a",
				Node:            "node-a",
				Reason:          "candidate-unresolved",
				Detail:          "ens5,bond0",
			}},
		}, fmt.Errorf(`provider network "physnet-a" on node "node-a" could not resolve candidate interfaces ens5,bond0`)),
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
		},
		LinuxDatapathApply: linuxDatapathApplyResult(linuxdatapath.Result{
			Device:                    "nl0",
			ProviderInventoryTotal:    2,
			ProviderInventoryReady:    1,
			ProviderInventoryDegraded: 1,
			ProviderInventoryStatus: []linuxdatapath.ProviderInterface{
				{Name: "eth1", Ready: true, State: "up"},
				{Name: "eth2", Ready: false, State: "down"},
			},
			ProviderIssues: []linuxdatapath.ProviderIssue{{
				ProviderNetwork: "physnet-a",
				Node:            "node-a",
				VLAN:            100,
				Reason:          "missing-parent-mapping",
			}},
			ProviderNetworkStatus: []linuxdatapath.ProviderNetworkStatus{{
				ProviderNetwork: "physnet-a",
				Ready:           false,
				IssueCount:      1,
				Reasons:         []string{"missing-parent-mapping"},
			}},
		}, fmt.Errorf(`provider network "physnet-a" requires parent device mapping on node "node-a"`)),
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
		},
		LinuxDatapathApply: linuxDatapathApplyResult(linuxdatapath.Result{
			Device:                    "nl0",
			ProviderInventoryTotal:    2,
			ProviderInventoryReady:    1,
			ProviderInventoryDegraded: 1,
			ProviderInventoryStatus: []linuxdatapath.ProviderInterface{
				{Name: "eth1", Ready: true, State: "up"},
				{Name: "eth2", Ready: false, State: "down"},
			},
			ProviderIssues: []linuxdatapath.ProviderIssue{{
				ProviderNetwork: "physnet-a",
				Node:            "node-a",
				ParentDevice:    "eth1",
				VLAN:            100,
				Reason:          "parent-vlan-conflict",
			}},
		}, fmt.Errorf(`provider networks "physnet-a" and "physnet-b" both require parent eth1 vlan 100`)),
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

func linuxDatapathApplyResult(result linuxdatapath.Result, err error) func(context.Context, control.DesiredState, linuxdatapath.Options) (linuxdatapath.Result, error) {
	return func(context.Context, control.DesiredState, linuxdatapath.Options) (linuxdatapath.Result, error) {
		return result, err
	}
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
