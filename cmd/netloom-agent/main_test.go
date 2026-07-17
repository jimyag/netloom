package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/database/inmemory"
	ovsmodel "github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"github.com/ovn-kubernetes/libovsdb/server"

	"github.com/jimyag/netloom/internal/agent"
	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/linuxdatapath"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/vswitch"
	"github.com/jimyag/netloom/internal/policy"
	"github.com/jimyag/netloom/internal/topology"
)

func TestEBPFMapPinRootUsesExplicitEnv(t *testing.T) {
	t.Setenv("NETLOOM_EBPF_MAP_PIN_ROOT", " /tmp/netloom-ebpf ")
	if got := ebpfMapPinRoot(); got != "/tmp/netloom-ebpf" {
		t.Fatalf("ebpfMapPinRoot() = %q, want %q", got, "/tmp/netloom-ebpf")
	}
}

func TestPolicyStoreConfiguresEBPFMapOverflowAction(t *testing.T) {
	t.Setenv("NETLOOM_POLICY_STORE", "ebpf")
	t.Setenv("NETLOOM_EBPF_MAP_PIN_ROOT", t.TempDir())
	t.Setenv("NETLOOM_EBPF_MAP_METADATA_ROOT", t.TempDir())
	t.Setenv("NETLOOM_EBPF_MAP_OVERFLOW_ACTION", "clear")

	store, name, closeStore := policyStore()
	defer closeStore()

	ebpfStore, ok := store.(*dataplane.EBPFPolicyStore)
	if !ok || name != "ebpf" {
		t.Fatalf("policyStore() = %T/%s, want eBPF store", store, name)
	}
	if got := ebpfStore.OverflowAction(); got != dataplane.PolicyMapOverflowClear {
		t.Fatalf("overflow action = %q, want %q", got, dataplane.PolicyMapOverflowClear)
	}
}

func TestEnsureDirAccessibleRejectsMissingPath(t *testing.T) {
	if err := ensureDirAccessible(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("ensureDirAccessible() should reject missing path")
	}
}

func TestEnsureDirAccessibleRejectsRegularFile(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureDirAccessible(file); err == nil {
		t.Fatal("ensureDirAccessible() should reject regular file")
	}
}

func TestEnsureDirAccessibleAcceptsDirectory(t *testing.T) {
	if err := ensureDirAccessible(t.TempDir()); err != nil {
		t.Fatalf("ensureDirAccessible() error = %v", err)
	}
}

func TestDesiredStateRuntimePathFromEnvUsesOVSDBWithoutStateFile(t *testing.T) {
	t.Setenv("NETLOOM_OVSDB_ENDPOINT", "unix:/var/run/openvswitch/db.sock")

	path, ok := desiredStateRuntimePathFromEnv()
	if !ok || path != "" {
		t.Fatalf("desiredStateRuntimePathFromEnv() = %q/%v, want OVSDB runtime with empty path", path, ok)
	}
}

func TestDesiredStateRuntimePathFromEnvPrefersExplicitStateFile(t *testing.T) {
	t.Setenv("NETLOOM_STATE_FILE", " /tmp/netloom-state.json ")
	t.Setenv("NETLOOM_OVSDB_ENDPOINT", "unix:/var/run/openvswitch/db.sock")

	path, ok := desiredStateRuntimePathFromEnv()
	if !ok || path != "/tmp/netloom-state.json" {
		t.Fatalf("desiredStateRuntimePathFromEnv() = %q/%v, want explicit state file", path, ok)
	}
}

func TestReconcileIntervalParsesMilliseconds(t *testing.T) {
	t.Setenv("NETLOOM_RECONCILE_INTERVAL_MS", "250")
	interval, err := reconcileInterval()
	if err != nil {
		t.Fatal(err)
	}
	if interval != 250*time.Millisecond {
		t.Fatalf("interval = %s, want 250ms", interval)
	}
}

func TestReconcileIntervalRejectsInvalidValue(t *testing.T) {
	t.Setenv("NETLOOM_RECONCILE_INTERVAL_MS", "soon")
	_, err := reconcileInterval()
	if err == nil {
		t.Fatal("expected invalid interval to fail")
	}
}

func TestConntrackIdleTimeoutParsesMilliseconds(t *testing.T) {
	t.Setenv("NETLOOM_CONNTRACK_MAX_IDLE_MS", "1500")
	if got := conntrackIdleTimeout(); got != 1500*time.Millisecond {
		t.Fatalf("conntrack idle timeout = %s, want 1500ms", got)
	}
}

func TestConntrackIdleTimeoutDefaultsToReconcilerDefault(t *testing.T) {
	if got := conntrackIdleTimeout(); got != 0 {
		t.Fatalf("conntrack idle timeout = %s, want zero for default", got)
	}
}

func TestPolicyPressureMitigationThresholdParsesPercent(t *testing.T) {
	t.Setenv("NETLOOM_POLICY_PRESSURE_MITIGATION_THRESHOLD", "85")
	if got := policyPressureMitigationThreshold(); got != 85 {
		t.Fatalf("policy pressure mitigation threshold = %d, want 85", got)
	}
	t.Setenv("NETLOOM_POLICY_PRESSURE_MITIGATION_THRESHOLD", "125")
	if got := policyPressureMitigationThreshold(); got != 100 {
		t.Fatalf("policy pressure mitigation threshold = %d, want capped 100", got)
	}
}

func TestPolicyPressureQuarantineThresholdParsesPercent(t *testing.T) {
	t.Setenv("NETLOOM_POLICY_PRESSURE_QUARANTINE_THRESHOLD", "95")
	if got := policyPressureQuarantineThreshold(); got != 95 {
		t.Fatalf("policy pressure quarantine threshold = %d, want 95", got)
	}
	t.Setenv("NETLOOM_POLICY_PRESSURE_QUARANTINE_THRESHOLD", "125")
	if got := policyPressureQuarantineThreshold(); got != 100 {
		t.Fatalf("policy pressure quarantine threshold = %d, want capped 100", got)
	}
}

func TestPolicyPressureQuarantineParsesEnabledValues(t *testing.T) {
	for _, value := range []string{"1", "true", "yes", "on"} {
		t.Setenv("NETLOOM_POLICY_PRESSURE_QUARANTINE", value)
		if !policyPressureQuarantine() {
			t.Fatalf("policy pressure quarantine = false for %q, want true", value)
		}
	}
	t.Setenv("NETLOOM_POLICY_PRESSURE_QUARANTINE", "0")
	if policyPressureQuarantine() {
		t.Fatal("policy pressure quarantine = true, want false")
	}
}

func TestLinuxDatapathOptionsUsesNetlinkBackend(t *testing.T) {
	t.Setenv("NETLOOM_LINUX_DATAPATH", "1")
	t.Setenv("NETLOOM_LINUX_DATAPATH_MODE", "netns")
	t.Setenv("NETLOOM_LINUX_DATAPATH_BACKEND", "command")
	t.Setenv("NETLOOM_PROVIDER_NETWORK_LINKS", "physnet-a=eth1, physnet-b = bond0.100")
	t.Setenv("NETLOOM_POLICY_ROUTE_TABLE_BASE", "22000")
	t.Setenv("NETLOOM_POLICY_ROUTE_TABLE_SIZE", "64")
	t.Setenv("NETLOOM_PROVIDER_HEALTH_STRICT", "1")
	t.Setenv("NETLOOM_OVSDB_SYNC", "1")

	options := linuxDatapathOptions()
	if options == nil {
		t.Fatal("expected linux datapath options")
	}
	if options.Mode != "netns" {
		t.Fatalf("mode = %s, want netns", options.Mode)
	}
	if options.Backend != "netlink" {
		t.Fatalf("backend = %s, want hard-coded netlink package path", options.Backend)
	}
	if options.ProviderLinks["physnet-a"] != "eth1" || options.ProviderLinks["physnet-b"] != "bond0.100" {
		t.Fatalf("provider links = %#v", options.ProviderLinks)
	}
	if options.PolicyTableBase != 22000 {
		t.Fatalf("policy table base = %d, want 22000", options.PolicyTableBase)
	}
	if options.PolicyTableSize != 64 {
		t.Fatalf("policy table size = %d, want 64", options.PolicyTableSize)
	}
	if !options.StrictProviderHealth {
		t.Fatal("strict provider health should be enabled")
	}
	if !options.SyncOVSDB {
		t.Fatal("ovsdb sync should be enabled")
	}
}

func TestLinuxDatapathOptionsEnablesOVSDBSyncWhenEndpointConfigured(t *testing.T) {
	t.Setenv("NETLOOM_LINUX_DATAPATH", "1")
	t.Setenv("NETLOOM_OVSDB_ENDPOINT", "unix:/run/openvswitch/db.sock")

	options := linuxDatapathOptions()
	if options == nil {
		t.Fatal("expected linux datapath options")
	}
	if !options.SyncOVSDB {
		t.Fatal("ovsdb sync should be enabled when NETLOOM_OVSDB_ENDPOINT is configured")
	}
}

func TestLinuxDatapathOptionsDefaultsToNetlinkBackend(t *testing.T) {
	t.Setenv("NETLOOM_LINUX_DATAPATH", "1")

	options := linuxDatapathOptions()
	if options == nil {
		t.Fatal("expected linux datapath options")
	}
	if options.Backend != "netlink" {
		t.Fatalf("backend = %s, want netlink", options.Backend)
	}
}

func TestParseProviderLinksSkipsInvalidEntries(t *testing.T) {
	got := parseProviderLinks("physnet-a=eth1,broken,=eth2,physnet-b=,physnet-c = bond0")
	if len(got) != 2 || got["physnet-a"] != "eth1" || got["physnet-c"] != "bond0" {
		t.Fatalf("parseProviderLinks() = %#v", got)
	}
}

func TestParseNodeUnderlaysKeepsMultipleAddressesPerNode(t *testing.T) {
	got := parseNodeUnderlays("node-a=172.30.0.11,node-a=fd00::11,node-b=bad,node-b=172.30.0.12")
	want := map[string][]netip.Addr{
		"node-a": {
			netip.MustParseAddr("172.30.0.11"),
			netip.MustParseAddr("fd00::11"),
		},
		"node-b": {
			netip.MustParseAddr("172.30.0.12"),
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseNodeUnderlays() = %#v, want %#v", got, want)
	}
}

func TestWithDNSObservationsMergesObservedRecords(t *testing.T) {
	raw, err := control.MarshalDNSObservationsJSON([]model.DNSRecord{{
		Name: "api.example.com",
		IPs:  []netip.Addr{netip.MustParseAddr("203.0.113.10")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ovsdb := fakeOpenVSwitchExternalIDStore{
		values: map[string]string{
			control.DNSObservationsOpenVSwitchExternalID: string(raw),
		},
	}

	state, err := withDNSObservationsAtContextStore(t.Context(), control.DesiredState{
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
			Name: "static.example.com",
			IPs:  []netip.Addr{netip.MustParseAddr("203.0.113.20")},
		}},
	}, time.Now().UTC(), ovsdbDNSObservationStore{syncer: &ovsdb})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.DNSRecords) != 2 {
		t.Fatalf("dns records = %d, want 2", len(state.DNSRecords))
	}
	if state.DNSRecords[0].Name != "api.example.com" || state.DNSRecords[1].Name != "static.example.com" {
		t.Fatalf("dns records = %+v", state.DNSRecords)
	}

	store := dataplane.NewInMemoryPolicyStore()
	result, err := agent.ReconcileNode(context.Background(), state, "node-a", store)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 1 {
		t.Fatalf("entries = %d, want observed FQDN policy entry", result.Entries)
	}
	entries := store.Entries(model.EndpointKey("prod", "pod-a"))
	if len(entries) != 1 || entries[0].RemoteCIDR.String() != "203.0.113.10/32" {
		t.Fatalf("policy entries = %+v, want observed FQDN CIDR", entries)
	}
}

func TestRunIdentityGroupsImportWithStoreWritesOpenVSwitchExternalID(t *testing.T) {
	store := &fakeOpenVSwitchExternalIDStore{}
	var stdout bytes.Buffer
	err := runIdentityGroupsImportWithStore(t.Context(), identityGroupsImportOptions{inputFile: "-"}, strings.NewReader(`[
		{"name":"frontend","vpc":"prod","source":"cmdb","endpoint_ids":["pod-a"]}
	]`), &stdout, store)
	if err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); !strings.Contains(got, "identity_groups=1") || !strings.Contains(got, control.IdentityGroupObservationsOpenVSwitchExternalID) {
		t.Fatalf("stdout = %q, want import summary", got)
	}
	raw, ok := store.values[control.IdentityGroupObservationsOpenVSwitchExternalID]
	if !ok {
		t.Fatalf("missing %s external_id", control.IdentityGroupObservationsOpenVSwitchExternalID)
	}
	groups, err := control.LoadIdentityGroupObservationsJSON(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Name != "frontend" || groups[0].VPC != "prod" {
		t.Fatalf("groups = %+v, want imported frontend group", groups)
	}
}

func TestRunIdentityGroupsImportWritesRealOpenVSwitchOVSDB(t *testing.T) {
	endpoint, client, cleanup := newTestAgentVSwitchOVSDB(t)
	defer cleanup()
	insertAgentVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{ExternalIDs: map[string]string{
		"ovn-bridge-mappings": "physnet-a:br-provider",
	}})
	var stdout bytes.Buffer
	err := runIdentityGroupsImport(t.Context(), []string{"-ovsdb", endpoint}, strings.NewReader(`{"identity_groups":[
		{"name":"frontend","vpc":"prod","source":"cmdb","endpoint_ids":["pod-a"]}
	]}`), &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); !strings.Contains(got, "identity_groups=1") || !strings.Contains(got, control.IdentityGroupObservationsOpenVSwitchExternalID) {
		t.Fatalf("stdout = %q, want import summary", got)
	}
	root := singleAgentVSwitchRoot(t, t.Context(), client)
	if got := root.ExternalIDs["ovn-bridge-mappings"]; got != "physnet-a:br-provider" {
		t.Fatalf("ovn-bridge-mappings = %q, want preserved existing external_id", got)
	}
	raw := root.ExternalIDs[control.IdentityGroupObservationsOpenVSwitchExternalID]
	if raw == "" {
		t.Fatalf("root external IDs = %+v, want identity group observations", root.ExternalIDs)
	}
	groups, err := control.LoadIdentityGroupObservationsJSON(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Name != "frontend" || groups[0].VPC != "prod" || groups[0].EndpointIDs[0] != "pod-a" {
		t.Fatalf("groups = %+v, want imported frontend group", groups)
	}
}

func TestRunIdentityGroupsExportWithStoreReadsResolvedOpenVSwitchExternalID(t *testing.T) {
	store := &fakeOpenVSwitchExternalIDStore{values: map[string]string{
		identityGroupsStateKey: `{"version":1,"groups":[{"vpc":"prod","name":"frontend","resolved_endpoints":[{"id":"pod-a","ip":"10.10.0.10"}]}]}`,
	}}
	var stdout bytes.Buffer
	if err := runIdentityGroupsExportWithStore(t.Context(), identityGroupsExportOptions{}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version int `json:"version"`
		Groups  []struct {
			VPC               string `json:"vpc"`
			Name              string `json:"name"`
			ResolvedEndpoints []struct {
				ID string `json:"id"`
				IP string `json:"ip"`
			} `json:"resolved_endpoints"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 || len(doc.Groups) != 1 || doc.Groups[0].Name != "frontend" || doc.Groups[0].ResolvedEndpoints[0].ID != "pod-a" {
		t.Fatalf("exported identity groups = %+v, want resolved frontend/pod-a", doc)
	}
}

func TestRunIdentityGroupsExportWithStoreReadsObservationSource(t *testing.T) {
	store := &fakeOpenVSwitchExternalIDStore{values: map[string]string{
		control.IdentityGroupObservationsOpenVSwitchExternalID: `{"identity_groups":[{"name":"frontend","vpc":"prod","source":"cmdb","endpoint_ids":["pod-a"]}]}`,
	}}
	var stdout bytes.Buffer
	if err := runIdentityGroupsExportWithStore(t.Context(), identityGroupsExportOptions{source: "observations"}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	groups, err := control.LoadIdentityGroupObservationsJSON(strings.NewReader(stdout.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Name != "frontend" || groups[0].Source != "cmdb" {
		t.Fatalf("exported observations = %+v, want frontend cmdb group", groups)
	}
}

func TestRunIdentityGroupsExportReadsRealOpenVSwitchOVSDB(t *testing.T) {
	endpoint, client, cleanup := newTestAgentVSwitchOVSDB(t)
	defer cleanup()
	insertAgentVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{ExternalIDs: map[string]string{
		identityGroupsStateKey: `{"version":1,"groups":[{"vpc":"prod","name":"frontend","resolved_endpoints":[{"id":"pod-a","ip":"10.10.0.10"}]}]}`,
	}})
	var stdout bytes.Buffer
	if err := runIdentityGroupsExport(t.Context(), []string{"-ovsdb", endpoint}, &stdout); err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); !strings.Contains(got, `"name": "frontend"`) || !strings.Contains(got, `"id": "pod-a"`) {
		t.Fatalf("stdout = %s, want resolved frontend identity group", got)
	}
}

func TestRunIdentityGroupsExportWithStoreRejectsUnknownSource(t *testing.T) {
	var stdout bytes.Buffer
	err := runIdentityGroupsExportWithStore(t.Context(), identityGroupsExportOptions{source: "bad"}, &stdout, &fakeOpenVSwitchExternalIDStore{})
	if err == nil || !strings.Contains(err.Error(), "unsupported identity groups source") {
		t.Fatalf("err = %v, want unsupported source", err)
	}
}

func TestRunDNSObservationsExportWithStoreReadsOpenVSwitchExternalID(t *testing.T) {
	raw, err := control.MarshalDNSObservationsJSON([]model.DNSRecord{{
		Name:       "api.example.com",
		IPs:        []netip.Addr{netip.MustParseAddr("203.0.113.10")},
		TTLSeconds: 60,
		ObservedAt: time.Date(2026, 7, 17, 1, 2, 3, 0, time.UTC),
	}})
	if err != nil {
		t.Fatal(err)
	}
	store := ovsdbDNSObservationStore{syncer: &fakeOpenVSwitchExternalIDStore{values: map[string]string{
		control.DNSObservationsOpenVSwitchExternalID: string(raw),
	}}}
	var stdout bytes.Buffer
	if err := runDNSObservationsExportWithStore(t.Context(), &stdout, store); err != nil {
		t.Fatal(err)
	}
	records, err := control.LoadDNSObservationsJSON(strings.NewReader(stdout.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Name != "api.example.com" || records[0].IPs[0] != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("exported DNS observations = %+v, want api.example.com", records)
	}
}

func TestRunDNSObservationsExportWithStoreReportsEmptyDocument(t *testing.T) {
	var stdout bytes.Buffer
	if err := runDNSObservationsExportWithStore(t.Context(), &stdout, ovsdbDNSObservationStore{syncer: &fakeOpenVSwitchExternalIDStore{}}); err != nil {
		t.Fatal(err)
	}
	records, err := control.LoadDNSObservationsJSON(strings.NewReader(stdout.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("dns records = %+v, want none", records)
	}
}

func TestRunDNSObservationsExportReadsRealOpenVSwitchOVSDB(t *testing.T) {
	endpoint, client, cleanup := newTestAgentVSwitchOVSDB(t)
	defer cleanup()
	raw, err := control.MarshalDNSObservationsJSON([]model.DNSRecord{{
		Name: "api.example.com",
		IPs:  []netip.Addr{netip.MustParseAddr("203.0.113.10")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	insertAgentVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{ExternalIDs: map[string]string{
		control.DNSObservationsOpenVSwitchExternalID: string(raw),
	}})
	var stdout bytes.Buffer
	if err := runDNSObservationsExport(t.Context(), []string{"-ovsdb", endpoint}, &stdout); err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); !strings.Contains(got, `"name": "api.example.com"`) || !strings.Contains(got, `"203.0.113.10"`) {
		t.Fatalf("stdout = %s, want api.example.com DNS observation", got)
	}
}

func TestRunDesiredStateImportWithStoreWritesOpenVSwitchExternalID(t *testing.T) {
	store := &fakeOpenVSwitchExternalIDStore{}
	var stdout bytes.Buffer
	err := runDesiredStateImportWithStore(t.Context(), desiredStateImportOptions{inputFile: "-"}, strings.NewReader(`{
		"vpcs": [{"name": "prod"}],
		"subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1"}],
		"endpoints": [{"id": "pod-a", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.10", "node": "node-a"}],
		"route_tables": [],
		"policy_routes": [],
		"gateways": [],
		"nat_rules": [],
		"load_balancers": [],
		"security_groups": []
	}`), &stdout, store)
	if err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); !strings.Contains(got, "desired_state vpcs=1 subnets=1 endpoints=1") || !strings.Contains(got, "revision=sha256:") || !strings.Contains(got, control.DesiredStateOpenVSwitchExternalID) {
		t.Fatalf("stdout = %q, want import summary", got)
	}
	if owner := store.values["netloom_owner"]; owner != "netloom" {
		t.Fatalf("netloom_owner = %q, want netloom", owner)
	}
	raw, ok := store.values[control.DesiredStateOpenVSwitchExternalID]
	if !ok {
		t.Fatalf("missing %s external_id", control.DesiredStateOpenVSwitchExternalID)
	}
	state, err := control.LoadDesiredStateJSON(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(state.VPCs) != 1 || state.VPCs[0].Name != "prod" || len(state.Endpoints) != 1 || state.Endpoints[0].ID != "pod-a" {
		t.Fatalf("state = %+v, want imported prod/pod-a state", state)
	}
	if got := store.values[control.DesiredStateRevisionOpenVSwitchExternalID]; got != control.DesiredStateRevision([]byte(raw)) {
		t.Fatalf("revision external_id = %q, want hash for desired state", got)
	}
	var summary control.DesiredStateSummary
	if err := json.Unmarshal([]byte(store.values[control.DesiredStateSummaryOpenVSwitchExternalID]), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.VPCs != 1 || summary.Subnets != 1 || summary.Endpoints != 1 {
		t.Fatalf("summary = %+v, want imported object counts", summary)
	}
}

func TestRunDesiredStateImportWritesRealOpenVSwitchOVSDB(t *testing.T) {
	endpoint, client, cleanup := newTestAgentVSwitchOVSDB(t)
	defer cleanup()
	insertAgentVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{ExternalIDs: map[string]string{
		"ovn-bridge-mappings": "physnet-a:br-provider",
	}})
	var stdout bytes.Buffer
	err := runDesiredStateImport(t.Context(), []string{"-ovsdb", endpoint}, strings.NewReader(`{
		"vpcs": [{"name": "prod"}],
		"subnets": [],
		"endpoints": [],
		"route_tables": [],
		"policy_routes": [],
		"gateways": [],
		"nat_rules": [],
		"load_balancers": [],
		"security_groups": []
	}`), &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); !strings.Contains(got, "desired_state vpcs=1") || !strings.Contains(got, "revision=sha256:") || !strings.Contains(got, control.DesiredStateOpenVSwitchExternalID) {
		t.Fatalf("stdout = %q, want import summary", got)
	}
	root := singleAgentVSwitchRoot(t, t.Context(), client)
	if got := root.ExternalIDs["ovn-bridge-mappings"]; got != "physnet-a:br-provider" {
		t.Fatalf("ovn-bridge-mappings = %q, want preserved existing external_id", got)
	}
	raw := root.ExternalIDs[control.DesiredStateOpenVSwitchExternalID]
	if raw == "" {
		t.Fatalf("root external IDs = %+v, want desired state", root.ExternalIDs)
	}
	state, err := control.LoadDesiredStateJSON(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(state.VPCs) != 1 || state.VPCs[0].Name != "prod" {
		t.Fatalf("state = %+v, want imported prod VPC", state)
	}
	if got := root.ExternalIDs[control.DesiredStateRevisionOpenVSwitchExternalID]; got != control.DesiredStateRevision([]byte(raw)) {
		t.Fatalf("revision external_id = %q, want hash for desired state", got)
	}
	if root.ExternalIDs[control.DesiredStateSummaryOpenVSwitchExternalID] == "" {
		t.Fatalf("root external IDs = %+v, want desired state summary", root.ExternalIDs)
	}
}

func TestRunDesiredStateExportWithStoreReadsOpenVSwitchExternalID(t *testing.T) {
	raw, err := control.MarshalDesiredStateJSON(control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeOpenVSwitchExternalIDStore{values: map[string]string{
		control.DesiredStateOpenVSwitchExternalID:         string(raw),
		control.DesiredStateRevisionOpenVSwitchExternalID: control.DesiredStateRevision(raw),
	}}
	var stdout bytes.Buffer
	if err := runDesiredStateExportWithStore(t.Context(), &stdout, store); err != nil {
		t.Fatal(err)
	}
	state, err := control.LoadDesiredStateJSON(strings.NewReader(stdout.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(state.VPCs) != 1 || state.VPCs[0].Name != "prod" || len(state.Subnets) != 1 || state.Subnets[0].Name != "apps" {
		t.Fatalf("exported state = %+v, want prod/apps from OVSDB", state)
	}
}

func TestRunDesiredStateExportReadsRealOpenVSwitchOVSDB(t *testing.T) {
	endpoint, client, cleanup := newTestAgentVSwitchOVSDB(t)
	defer cleanup()
	raw, err := control.MarshalDesiredStateJSON(control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	insertAgentVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{ExternalIDs: map[string]string{
		control.DesiredStateOpenVSwitchExternalID:         string(raw),
		control.DesiredStateRevisionOpenVSwitchExternalID: control.DesiredStateRevision(raw),
	}})
	var stdout bytes.Buffer
	if err := runDesiredStateExport(t.Context(), []string{"-ovsdb", endpoint}, &stdout); err != nil {
		t.Fatal(err)
	}
	state, err := control.LoadDesiredStateJSON(strings.NewReader(stdout.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(state.VPCs) != 1 || state.VPCs[0].Name != "prod" {
		t.Fatalf("exported state = %+v, want prod from real OVSDB", state)
	}
}

func TestLoadDesiredStateFromOpenVSwitchExternalIDStore(t *testing.T) {
	raw, err := control.MarshalDesiredStateJSON(control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Endpoints: []model.Endpoint{{
			ID:   "pod-a",
			VPC:  "prod",
			Node: "node-a",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeOpenVSwitchExternalIDStore{values: map[string]string{
		control.DesiredStateOpenVSwitchExternalID: string(raw),
	}}

	state, err := loadDesiredStateFromPathOrOVSDB(t.Context(), "", store)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.VPCs) != 1 || state.VPCs[0].Name != "prod" || len(state.Endpoints) != 1 || state.Endpoints[0].ID != "pod-a" {
		t.Fatalf("state = %+v, want OVSDB desired state", state)
	}
}

func TestLoadDesiredStateFromOpenVSwitchExternalIDRejectsRevisionMismatch(t *testing.T) {
	raw, err := control.MarshalDesiredStateJSON(control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeOpenVSwitchExternalIDStore{values: map[string]string{
		control.DesiredStateOpenVSwitchExternalID:         string(raw),
		control.DesiredStateRevisionOpenVSwitchExternalID: "sha256:bad",
	}}

	_, err = loadDesiredStateFromPathOrOVSDB(t.Context(), "", store)
	if err == nil || !strings.Contains(err.Error(), "revision mismatch") {
		t.Fatalf("err = %v, want revision mismatch", err)
	}
}

func TestRunIdentityGroupsImportWithStoreRejectsPatchOnlyFeed(t *testing.T) {
	store := &fakeOpenVSwitchExternalIDStore{}
	var stdout bytes.Buffer
	err := runIdentityGroupsImportWithStore(t.Context(), identityGroupsImportOptions{inputFile: "-"}, strings.NewReader(`{"identity_group_patches":[{"op":"delete","vpc":"prod","name":"old"}]}`), &stdout, store)
	if err == nil || !strings.Contains(err.Error(), "requires cached groups") {
		t.Fatalf("err = %v, want cached groups error", err)
	}
	if len(store.values) != 0 {
		t.Fatalf("store values = %+v, want no write on invalid import", store.values)
	}
}

func TestWithDNSObservationsPrunesExpiredRecords(t *testing.T) {
	raw, err := control.MarshalDNSObservationsJSON([]model.DNSRecord{
		{Name: "expired.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.10")}, TTLSeconds: 30, ObservedAt: time.Date(2026, 5, 30, 11, 59, 30, 0, time.UTC)},
		{Name: "active.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.20")}, TTLSeconds: 31, ObservedAt: time.Date(2026, 5, 30, 11, 59, 30, 0, time.UTC)},
		{Name: "static.example.com", IPs: []netip.Addr{netip.MustParseAddr("203.0.113.30")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ovsdb := fakeOpenVSwitchExternalIDStore{
		values: map[string]string{
			control.DNSObservationsOpenVSwitchExternalID: string(raw),
		},
	}
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)

	state, err := withDNSObservationsAtContextStore(t.Context(), control.DesiredState{}, now, ovsdbDNSObservationStore{syncer: &ovsdb})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.DNSRecords) != 2 {
		t.Fatalf("dns records = %d, want 2: %+v", len(state.DNSRecords), state.DNSRecords)
	}
	if state.DNSRecords[0].Name != "active.example.com" || state.DNSRecords[1].Name != "static.example.com" {
		t.Fatalf("dns records = %+v", state.DNSRecords)
	}
}

func TestWithDNSObservationsReadsOpenVSwitchExternalIDStore(t *testing.T) {
	raw, err := control.MarshalDNSObservationsJSON([]model.DNSRecord{{
		Name: "api.example.com",
		IPs:  []netip.Addr{netip.MustParseAddr("203.0.113.10")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	store := fakeOpenVSwitchExternalIDStore{
		values: map[string]string{
			control.DNSObservationsOpenVSwitchExternalID: string(raw),
		},
	}

	state, err := withDNSObservationsAtContextStore(t.Context(), control.DesiredState{
		DNSRecords: []model.DNSRecord{{
			Name: "static.example.com",
			IPs:  []netip.Addr{netip.MustParseAddr("203.0.113.20")},
		}},
	}, time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC), ovsdbDNSObservationStore{syncer: &store})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.DNSRecords) != 2 {
		t.Fatalf("dns records = %d, want 2: %+v", len(state.DNSRecords), state.DNSRecords)
	}
	if state.DNSRecords[0].Name != "api.example.com" || state.DNSRecords[1].Name != "static.example.com" {
		t.Fatalf("dns records = %+v", state.DNSRecords)
	}
}

func TestWithRuntimeObservationsMergesIdentityGroups(t *testing.T) {
	ovsdb := fakeOpenVSwitchExternalIDStore{
		values: map[string]string{
			control.IdentityGroupObservationsOpenVSwitchExternalID: `{"identity_groups": [{"name": "frontend-api", "vpc": "prod", "source": "cmdb", "observed_at": "2026-07-10T01:00:00Z", "ttl_seconds": 120, "endpoint_ids": ["pod-a"]}]}`,
		},
	}
	now := time.Date(2026, 7, 10, 1, 1, 0, 0, time.UTC)

	state, err := withRuntimeObservationsAtContextCacheStore(t.Context(), control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "eth1",
			}},
			TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
				Tenant:         "prod",
				QueueID:        10,
				IdentityGroups: []string{"frontend-api"},
				MaxRateBPS:     500000000,
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
	}, now, nil, nil, &ovsdb)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.IdentityGroups) != 1 || state.IdentityGroups[0].Name != "frontend-api" || state.IdentityGroups[0].Source != "cmdb" {
		t.Fatalf("identity groups = %+v, want observed frontend-api", state.IdentityGroups)
	}

	ops, result, err := linuxdatapath.Plan(context.Background(), state, linuxdatapath.Options{
		Node:              "node-a",
		SyncOVSDB:         true,
		ProviderInventory: []linuxdatapath.ProviderInterface{{Name: "eth1", Ready: true, State: "up"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderNetworks != 1 || result.ProviderLinks != 1 {
		t.Fatalf("provider result = %+v, want provider network/link from observed identity group state", result)
	}
	if !strings.Contains(stringifyAgentOps(ops), "nw_src=10.10.0.10") {
		t.Fatalf("provider queue ops = %s, want endpoint-scoped identity group flow", stringifyAgentOps(ops))
	}
}

func TestWithIdentityGroupObservationsPrunesExpiredGroups(t *testing.T) {
	ovsdb := fakeOpenVSwitchExternalIDStore{
		values: map[string]string{
			control.IdentityGroupObservationsOpenVSwitchExternalID: `{"identity_groups": [
		{"name": "expired", "vpc": "prod", "observed_at": "2026-07-10T01:00:00Z", "ttl_seconds": 60, "endpoint_ids": ["pod-a"]},
		{"name": "active", "vpc": "prod", "observed_at": "2026-07-10T01:00:01Z", "ttl_seconds": 60, "endpoint_ids": ["pod-b"]},
		{"name": "static", "vpc": "prod", "endpoint_ids": ["pod-c"]}
	]}`,
		},
	}
	now := time.Date(2026, 7, 10, 1, 1, 0, 0, time.UTC)

	state, err := withIdentityGroupObservationsAtContextCacheStore(t.Context(), control.DesiredState{}, now, nil, &ovsdb)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.IdentityGroups) != 2 || state.IdentityGroups[0].Name != "active" || state.IdentityGroups[1].Name != "static" {
		t.Fatalf("identity groups = %+v, want active and static", state.IdentityGroups)
	}
}

func TestWithIdentityGroupObservationsMergesRemoteFeed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer feed-token" {
			t.Fatalf("authorization = %q, want bearer token", got)
		}
		_, _ = w.Write([]byte(`{"identity_groups":[{"name":"remote","vpc":"prod","source":"cmdb","endpoint_ids":["pod-a"]}]}`))
	}))
	defer server.Close()
	t.Setenv("NETLOOM_IDENTITY_GROUPS_URL", server.URL)
	t.Setenv("NETLOOM_IDENTITY_GROUPS_BEARER_TOKEN", "feed-token")
	t.Setenv("NETLOOM_IDENTITY_GROUPS_TIMEOUT_MS", "1000")

	state, err := withIdentityGroupObservationsAt(control.DesiredState{}, time.Date(2026, 7, 10, 1, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(state.IdentityGroups) != 1 || state.IdentityGroups[0].Name != "remote" || state.IdentityGroups[0].Source != "cmdb" {
		t.Fatalf("identity groups = %+v, want remote cmdb group", state.IdentityGroups)
	}
}

func TestRunPolicyStatusReportsEndpointLifecycleJSON(t *testing.T) {
	statePath := writeAgentState(t, control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
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
				RemoteCIDR: netip.MustParsePrefix("0.0.0.0/0"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	})

	var out bytes.Buffer
	if err := runPolicyStatus([]string{"-state", statePath, "-node", "node-a", "-endpoint", "pod-a"}, &out); err != nil {
		t.Fatal(err)
	}
	var got policyStatusOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-status output: %v\n%s", err, out.String())
	}
	if got.Node != "node-a" || got.Store != "memory" || got.EndpointCount != 1 {
		t.Fatalf("policy status summary = %+v, want node-a memory with one endpoint", got)
	}
	if got.PolicyMapEntries == 0 || got.PolicyRevisionMax != 1 {
		t.Fatalf("policy status policy summary = %+v, want programmed entries at revision 1", got)
	}
	if len(got.Statuses) != 1 {
		t.Fatalf("statuses = %d, want one: %+v", len(got.Statuses), got.Statuses)
	}
	status := got.Statuses[0]
	if status.EndpointID != model.EndpointKey("prod", "pod-a") || status.Revision != 1 || status.Entries == 0 {
		t.Fatalf("endpoint status = %+v, want pod-a revision with entries", status)
	}
	if !status.HasLastEvent || !status.LastEvent.Success || status.LastEvent.Revision != 1 {
		t.Fatalf("last event = %+v has=%t, want successful revision event", status.LastEvent, status.HasLastEvent)
	}
	if status.Drift.Drifted {
		t.Fatalf("drift = %+v, want clean in-memory status", status.Drift)
	}
}

func TestRunPolicyStatusExportWithStoreReportsFilteredJSON(t *testing.T) {
	store := ovsdbPolicyStatusStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	endpointID := model.EndpointKey("prod", "pod-a")
	if err := store.Save(t.Context(), policyStatusDocument{
		Node:                 "node-a",
		Store:                "ebpf",
		LastReconcileSuccess: true,
		UpdatedAt:            time.Date(2026, 7, 17, 1, 2, 3, 0, time.UTC),
		EndpointCount:        2,
		PolicyMapEntries:     3,
		PolicyMapCapacity:    64,
		PressureMax:          5,
		PressureEndpoint:     endpointID,
		PolicyRevisionMax:    7,
		Statuses: []dataplane.PolicyEndpointStatus{{
			EndpointID:      endpointID,
			Revision:        7,
			Entries:         2,
			Capacity:        64,
			PressurePercent: 5,
			LastEvent:       dataplane.PolicyUpdateEvent{EndpointID: endpointID, Revision: 7, Success: true},
			HasLastEvent:    true,
		}, {
			EndpointID: model.EndpointKey("prod", "pod-b"),
			Revision:   1,
			Entries:    1,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runPolicyStatusExportWithStore(t.Context(), policyStatusExportOptions{endpoint: "prod/pod-a"}, &out, store); err != nil {
		t.Fatal(err)
	}
	var got policyStatusOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-status-export output: %v\n%s", err, out.String())
	}
	if !got.Ready || !got.LastReconcileSuccess || got.Node != "node-a" || got.Store != "ebpf" || got.FilterEndpoint != "prod/pod-a" {
		t.Fatalf("policy status summary = %+v, want ready filtered node-a ebpf", got)
	}
	if got.EndpointCount != 1 || got.PolicyMapEntries != 3 || got.PolicyMapCapacity != 64 || got.PolicyRevisionMax != 7 {
		t.Fatalf("policy status counters = %+v, want persisted counters and one filtered endpoint", got)
	}
	if len(got.Statuses) != 1 || got.Statuses[0].EndpointID != endpointID || got.Statuses[0].Revision != 7 || !got.Statuses[0].HasLastEvent {
		t.Fatalf("statuses = %+v, want filtered pod-a revision 7 status", got.Statuses)
	}
}

func TestRunPolicyRevisionWaitWithStoreReportsReadyRevision(t *testing.T) {
	store := ovsdbPolicyStatusStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	endpointID := model.EndpointKey("prod", "pod-a")
	if err := store.Save(t.Context(), policyStatusDocument{
		Node:                 "node-a",
		Store:                "ebpf",
		LastReconcileSuccess: true,
		UpdatedAt:            time.Date(2026, 7, 17, 1, 2, 3, 0, time.UTC),
		PolicyRevisionMax:    9,
		Statuses: []dataplane.PolicyEndpointStatus{{
			EndpointID:   endpointID,
			Revision:     9,
			Entries:      2,
			LastEvent:    dataplane.PolicyUpdateEvent{EndpointID: endpointID, Revision: 9, Success: true},
			HasLastEvent: true,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runPolicyRevisionWaitWithStore(t.Context(), policyRevisionWaitOptions{
		endpoint:       "prod/pod-a",
		targetRevision: 7,
		timeout:        0,
	}, &out, store); err != nil {
		t.Fatal(err)
	}
	var got policyRevisionWaitOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-revision-wait output: %v\n%s", err, out.String())
	}
	if !got.Ready || got.Node != "node-a" || got.Store != "ebpf" || got.EndpointID != endpointID || got.TargetRevision != 7 || got.Revision != 9 {
		t.Fatalf("policy revision wait = %+v, want ready pod-a revision 9 for target 7", got)
	}
	if got.Status.EndpointID != endpointID || got.Status.Revision != 9 || !got.Status.HasLastEvent {
		t.Fatalf("policy revision wait status = %+v, want persisted endpoint status", got.Status)
	}
}

func TestRunPolicyRevisionWaitWithStoreTimesOutBeforeTargetRevision(t *testing.T) {
	store := ovsdbPolicyStatusStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	endpointID := model.EndpointKey("prod", "pod-a")
	if err := store.Save(t.Context(), policyStatusDocument{
		Node:              "node-a",
		Store:             "ebpf",
		UpdatedAt:         time.Date(2026, 7, 17, 1, 2, 3, 0, time.UTC),
		PolicyRevisionMax: 3,
		Statuses: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   3,
			Entries:    1,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := runPolicyRevisionWaitWithStore(t.Context(), policyRevisionWaitOptions{
		endpoint:       "prod/pod-a",
		targetRevision: 4,
		timeout:        0,
	}, &out, store)
	if err == nil || !strings.Contains(err.Error(), "did not reach target revision 4") {
		t.Fatalf("error = %v, want target revision timeout", err)
	}
	if out.Len() != 0 {
		t.Fatalf("output = %s, want no success JSON", out.String())
	}
}

func TestRunPolicyStatusExportReadsRealOpenVSwitchOVSDB(t *testing.T) {
	endpoint, client, cleanup := newTestAgentVSwitchOVSDB(t)
	defer cleanup()
	endpointID := model.EndpointKey("prod", "pod-a")
	raw, err := json.Marshal(policyStatusDocument{
		Node:                 "node-a",
		Store:                "ebpf",
		LastReconcileSuccess: true,
		EndpointCount:        1,
		PolicyMapEntries:     1,
		PolicyRevisionMax:    3,
		Statuses: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   3,
			Entries:    1,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	insertAgentVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{ExternalIDs: map[string]string{
		policyEndpointStatusKey: string(raw),
	}})
	var out bytes.Buffer
	if err := runPolicyStatusExport(t.Context(), []string{"-ovsdb", endpoint}, &out); err != nil {
		t.Fatal(err)
	}
	var got policyStatusOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-status-export output: %v\n%s", err, out.String())
	}
	if got.Node != "node-a" || got.Store != "ebpf" || got.EndpointCount != 1 || got.Statuses[0].EndpointID != endpointID {
		t.Fatalf("policy status = %+v, want persisted pod-a status", got)
	}
}

func TestAgentMetricsPersistsPolicyEndpointStatusToOpenVSwitchExternalID(t *testing.T) {
	ovsdb := &fakeOpenVSwitchExternalIDStore{}
	metrics := newAgentMetrics()
	configurePolicyStatusStore(metrics, ovsdbPolicyStatusStore{syncer: ovsdb})
	endpointID := model.EndpointKey("prod", "pod-a")

	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node:                      "node-a",
		PolicyMapEntries:          2,
		PolicyMapCapacity:         64,
		PolicyRevisionMax:         5,
		PolicyMapPressureMax:      3,
		PolicyMapPressureEndpoint: endpointID,
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID:      endpointID,
			Revision:        5,
			Entries:         2,
			Capacity:        64,
			PressurePercent: 3,
			LastEvent:       dataplane.PolicyUpdateEvent{EndpointID: endpointID, Revision: 5, Success: true},
			HasLastEvent:    true,
		}},
	}, "ebpf", time.Millisecond)

	raw := ovsdb.values[policyEndpointStatusKey]
	if raw == "" {
		t.Fatalf("missing %s external_id", policyEndpointStatusKey)
	}
	var doc policyStatusDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Node != "node-a" || doc.Store != "ebpf" || !doc.LastReconcileSuccess || doc.EndpointCount != 1 || doc.PolicyRevisionMax != 5 {
		t.Fatalf("policy status doc = %+v, want successful node-a ebpf snapshot", doc)
	}
	if len(doc.Statuses) != 1 || doc.Statuses[0].EndpointID != endpointID || doc.Statuses[0].Revision != 5 || !doc.Statuses[0].HasLastEvent {
		t.Fatalf("policy endpoint statuses = %+v, want persisted pod-a status", doc.Statuses)
	}
}

func TestRunPolicyEntriesReportsEndpointMapJSON(t *testing.T) {
	statePath := writeAgentState(t, control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
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
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
	})

	var out bytes.Buffer
	if err := runPolicyEntries([]string{"-state", statePath, "-node", "node-a", "-endpoint", "prod/pod-a"}, &out); err != nil {
		t.Fatal(err)
	}
	var got policyEntriesOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-entries output: %v\n%s", err, out.String())
	}
	if !got.Ready || got.Node != "node-a" || got.Store != "memory" || got.EndpointID != model.EndpointKey("prod", "pod-a") {
		t.Fatalf("policy entries summary = %+v, want node-a memory pod-a", got)
	}
	if got.EntryCount == 0 || len(got.Entries) == 0 {
		t.Fatalf("entries = %+v, want compiled policy map entries", got.Entries)
	}
	found := false
	for _, entry := range got.Entries {
		if entry.RemoteCIDR == "172.30.0.0/24" && entry.Key.Direction == dataplane.DirectionIngress && entry.Key.Protocol == 6 {
			if entry.RuleRef != "prod/web/allow-web" || entry.SecurityGroup != "web" || entry.RuleID != "allow-web" {
				t.Fatalf("entry rule metadata = %+v, want prod/web/allow-web", entry)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("entries = %+v, want ingress TCP entry for remote CIDR", got.Entries)
	}
}

func TestRunPolicyEntriesRequiresEndpoint(t *testing.T) {
	var out bytes.Buffer
	err := runPolicyEntries([]string{"-state", "unused.json", "-node", "node-a"}, &out)
	if err == nil || !strings.Contains(err.Error(), "missing -endpoint") {
		t.Fatalf("error = %v, want missing endpoint", err)
	}
}

func TestRunAgentStatusWithStoreReportsOpenVSwitchStatus(t *testing.T) {
	status := agentOVSDBStatus{
		SchemaVersion:                 1,
		UpdatedAt:                     time.Now().UTC().Format(time.RFC3339Nano),
		Node:                          "node-a",
		Store:                         "ebpf",
		Status:                        "success",
		Endpoints:                     2,
		PolicyMapEntries:              4,
		PolicyRolloutApplied:          1,
		TCX:                           "attached",
		RuntimeReady:                  true,
		RuntimeFailed:                 0,
		RuntimeWarned:                 1,
		Runtime:                       []agent.RuntimeCheck{{Name: "bpffs", Status: "ok", Required: true, Detail: "/sys/fs/bpf"}, {Name: "ovsdb", Status: "warn", Detail: "not configured"}},
		Datapath:                      "linux",
		ProviderReady:                 1,
		ReconcileDurationMilliseconds: 12,
	}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeOpenVSwitchExternalIDStore{values: map[string]string{
		agentOVSDBStatusKey: string(raw),
	}}
	var out bytes.Buffer
	if err := runAgentStatusWithStore(t.Context(), &out, store); err != nil {
		t.Fatal(err)
	}
	var got agentOVSDBStatus
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode agent-status output: %v\n%s", err, out.String())
	}
	if got.Node != "node-a" || got.Store != "ebpf" || got.Status != "success" || got.PolicyMapEntries != 4 || got.PolicyRolloutApplied != 1 || got.ProviderReady != 1 || !got.RuntimeReady || got.RuntimeWarned != 1 || len(got.Runtime) != 2 {
		t.Fatalf("agent status = %+v, want decoded OVSDB status", got)
	}
}

func TestRunAgentStatusWithStoreRequiresStatusExternalID(t *testing.T) {
	var out bytes.Buffer
	err := runAgentStatusWithStore(t.Context(), &out, &fakeOpenVSwitchExternalIDStore{})
	if err == nil || !strings.Contains(err.Error(), "missing Open_vSwitch external_ids:netloom_agent_status") {
		t.Fatalf("err = %v, want missing agent status", err)
	}
}

func TestRunPolicyActionHistoryWithStoreReportsFilteredJSON(t *testing.T) {
	history := []policyActionHistoryEntry{
		{ID: "1", Action: "freeze", EndpointID: model.EndpointKey("prod", "vm-a"), Node: "node-a", Store: "ebpf", CompletedAt: time.Now().Add(-3 * time.Minute), Success: true},
		{ID: "2", Action: "regenerate", EndpointID: model.EndpointKey("prod", "vm-a"), Node: "node-a", Store: "ebpf", CompletedAt: time.Now().Add(-2 * time.Minute), Success: false, Error: "policy endpoint is frozen"},
		{ID: "3", Action: "regenerate", EndpointID: model.EndpointKey("prod", "vm-b"), Node: "node-a", Store: "ebpf", CompletedAt: time.Now().Add(-time.Minute), Success: true},
	}
	raw, err := json.Marshal(history)
	if err != nil {
		t.Fatal(err)
	}
	store := ovsdbPolicyActionHistoryStore{syncer: &fakeOpenVSwitchExternalIDStore{values: map[string]string{
		policyActionHistoryKey: string(raw),
	}}}
	var out bytes.Buffer
	err = runPolicyActionHistoryWithStore(t.Context(), policyActionHistoryOptions{
		endpoint: "prod/vm-a",
		action:   "regenerate",
		success:  "false",
		limit:    10,
	}, &out, store)
	if err != nil {
		t.Fatal(err)
	}
	var got policyActionHistoryOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-action-history output: %v\n%s", err, out.String())
	}
	if !got.Ready || got.TotalEvents != 3 || got.EventCount != 1 || got.FilterEndpoint != "prod/vm-a" || got.FilterAction != "regenerate" || got.FilterSuccess == nil || *got.FilterSuccess {
		t.Fatalf("output = %+v, want failed regenerate filter metadata", got)
	}
	if len(got.History) != 1 || got.History[0].ID != "2" || got.History[0].Success || !strings.Contains(got.History[0].Error, "frozen") {
		t.Fatalf("history = %+v, want failed regenerate action", got.History)
	}
}

func TestRunPolicyActionHistoryWithStoreRejectsInvalidFilters(t *testing.T) {
	var out bytes.Buffer
	store := ovsdbPolicyActionHistoryStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	err := runPolicyActionHistoryWithStore(t.Context(), policyActionHistoryOptions{success: "maybe", limit: 10}, &out, store)
	if err == nil || !strings.Contains(err.Error(), `invalid success "maybe"`) {
		t.Fatalf("err = %v, want invalid success", err)
	}
	err = runPolicyActionHistoryWithStore(t.Context(), policyActionHistoryOptions{limit: -1}, &out, store)
	if err == nil || !strings.Contains(err.Error(), "invalid limit -1") {
		t.Fatalf("err = %v, want invalid limit", err)
	}
}

func TestRunPolicyRolloutHistoryWithStoreReportsFilteredJSON(t *testing.T) {
	history := []policyRolloutHistoryEntry{
		{
			ID:          "1",
			Source:      "manual",
			Name:        "canary",
			Node:        "node-a",
			Store:       "ebpf",
			CompletedAt: time.Now().Add(-3 * time.Minute),
			Rollout:     agent.PolicyEndpointRollout{Planned: 1, Applied: 1},
		},
		{
			ID:          "2",
			Source:      "desired-state",
			Name:        "nightly",
			Node:        "node-a",
			Store:       "ebpf",
			CompletedAt: time.Now().Add(-2 * time.Minute),
			Rollout:     agent.PolicyEndpointRollout{Planned: 2, Applied: 1, Failed: 1},
		},
		{
			ID:          "3",
			Source:      "manual",
			Name:        "canary",
			Node:        "node-b",
			Store:       "ebpf",
			CompletedAt: time.Now().Add(-time.Minute),
			Rollout:     agent.PolicyEndpointRollout{Planned: 1, Applied: 1},
		},
	}
	raw, err := json.Marshal(history)
	if err != nil {
		t.Fatal(err)
	}
	store := ovsdbPolicyRolloutHistoryStore{syncer: &fakeOpenVSwitchExternalIDStore{values: map[string]string{
		policyRolloutHistoryKey: string(raw),
	}}}
	var out bytes.Buffer
	err = runPolicyRolloutHistoryWithStore(t.Context(), policyRolloutHistoryOptions{
		source: "manual",
		name:   "canary",
		limit:  1,
	}, &out, store)
	if err != nil {
		t.Fatal(err)
	}
	var got policyRolloutHistoryOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-rollout-history output: %v\n%s", err, out.String())
	}
	if !got.Ready || got.TotalEvents != 3 || got.EventCount != 1 || got.Limit != 1 || got.FilterSource != "manual" || got.FilterName != "canary" {
		t.Fatalf("output = %+v, want filtered rollout metadata", got)
	}
	if len(got.History) != 1 || got.History[0].ID != "3" || got.History[0].Source != "manual" || got.History[0].Name != "canary" {
		t.Fatalf("history = %+v, want latest manual canary rollout", got.History)
	}
}

func TestRunPolicyRolloutHistoryWithStoreRejectsInvalidLimit(t *testing.T) {
	var out bytes.Buffer
	store := ovsdbPolicyRolloutHistoryStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	err := runPolicyRolloutHistoryWithStore(t.Context(), policyRolloutHistoryOptions{limit: -1}, &out, store)
	if err == nil || !strings.Contains(err.Error(), "invalid limit -1") {
		t.Fatalf("err = %v, want invalid limit", err)
	}
}

func TestRunPolicyRolloutStateWithStoreReportsFilteredJSON(t *testing.T) {
	doc := policyRolloutStateDocument{Rollouts: []policyRolloutStateEntry{
		{
			Name:             "canary",
			Node:             "node-a",
			Revision:         "rev-a",
			Store:            "ebpf",
			UpdatedAt:        time.Now().Add(-time.Minute),
			AppliedEndpoints: []string{model.EndpointKey("prod", "vm-a")},
			Paused:           true,
		},
		{
			Name:             "canary",
			Node:             "node-b",
			Revision:         "rev-b",
			Store:            "ebpf",
			UpdatedAt:        time.Now(),
			AppliedEndpoints: []string{model.EndpointKey("prod", "vm-b")},
			Failed:           1,
		},
	}}
	store := ovsdbPolicyRolloutStateStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	if err := store.Save(t.Context(), doc); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runPolicyRolloutStateWithStore(t.Context(), policyRolloutStateOptions{
		name: "canary",
		node: "node-b",
	}, &out, store)
	if err != nil {
		t.Fatal(err)
	}
	var got policyRolloutStateOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-rollout-state output: %v\n%s", err, out.String())
	}
	if !got.Ready || got.TotalRollouts != 2 || got.RolloutCount != 1 || got.FilterName != "canary" || got.FilterNode != "node-b" {
		t.Fatalf("output = %+v, want filtered rollout state metadata", got)
	}
	if len(got.Rollouts) != 1 || got.Rollouts[0].Revision != "rev-b" || got.Rollouts[0].Failed != 1 || len(got.Rollouts[0].AppliedEndpoints) != 1 || got.Rollouts[0].AppliedEndpoints[0] != model.EndpointKey("prod", "vm-b") {
		t.Fatalf("rollouts = %+v, want node-b failed rollout state", got.Rollouts)
	}
}

func TestRunPolicyFreezeStateWithStoreReportsActiveFrozenEndpoints(t *testing.T) {
	now := time.Now().UTC()
	doc := policyFreezeStateDocument{
		FrozenEndpoints: []policyFreezeStateEntry{
			{EndpointID: model.EndpointKey("prod", "vm-a"), ExpiresAt: now.Add(time.Hour)},
			{EndpointID: model.EndpointKey("prod", "vm-b"), ExpiresAt: now.Add(-time.Minute)},
			{EndpointID: model.EndpointKey("prod", "vm-c")},
			{EndpointID: model.EndpointKey("prod", "vm-a"), ExpiresAt: now.Add(2 * time.Hour)},
		},
		UpdatedAt: now.Add(-time.Minute),
	}
	store := ovsdbPolicyFreezeStateStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	if err := store.Save(t.Context(), doc); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runPolicyFreezeStateWithStore(t.Context(), policyFreezeStateOptions{
		endpoint: "prod/vm-a",
	}, &out, store, now)
	if err != nil {
		t.Fatal(err)
	}
	var got policyFreezeStateOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-freeze-state output: %v\n%s", err, out.String())
	}
	if !got.Ready || got.TotalFrozenEndpoints != 2 || got.ActiveFrozenEndpoints != 2 || got.FilterEndpoint != "prod/vm-a" || !got.UpdatedAt.Equal(doc.UpdatedAt) {
		t.Fatalf("output = %+v, want filtered active freeze metadata", got)
	}
	if len(got.FrozenEndpoints) != 1 || got.FrozenEndpoints[0].EndpointID != model.EndpointKey("prod", "vm-a") || !got.FrozenEndpoints[0].ExpiresAt.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("frozen endpoints = %+v, want latest active vm-a freeze", got.FrozenEndpoints)
	}
}

func TestRunPolicyExplainReportsSelectorAllow(t *testing.T) {
	statePath := writePolicyExplainState(t)
	var stdout bytes.Buffer

	err := runPolicyExplain([]string{
		"-state", statePath,
		"-vpc", "prod",
		"-endpoint", "pod-a",
		"-remote-endpoint", "pod-b",
		"-direction", "ingress",
		"-protocol", "tcp",
		"-dest-port", "443",
	}, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	var explanation dataplane.PolicyExplanation
	if err := json.Unmarshal(stdout.Bytes(), &explanation); err != nil {
		t.Fatalf("decode explanation: %v\n%s", err, stdout.String())
	}
	if explanation.EndpointID != model.EndpointKey("prod", "pod-a") {
		t.Fatalf("endpoint = %q, want pod-a key", explanation.EndpointID)
	}
	if explanation.Verdict != dataplane.VerdictAllow || explanation.Reason != dataplane.ExplainReasonPolicyAllow {
		t.Fatalf("explanation = %+v, want policy allow", explanation)
	}
	if !explanation.Matched || explanation.RuleCookie == 0 {
		t.Fatalf("explanation = %+v, want matched rule cookie", explanation)
	}
	if explanation.MatchedRule == nil {
		t.Fatalf("matched rule metadata missing from explanation: %+v", explanation)
	}
	if explanation.MatchedRule.RuleRef != "prod/web/allow-client-https" ||
		explanation.MatchedRule.SecurityGroup != "web" ||
		explanation.MatchedRule.RuleID != "allow-client-https" ||
		explanation.MatchedRule.Priority != 100 ||
		explanation.MatchedRule.Action != string(model.ActionAllow) {
		t.Fatalf("matched rule = %+v, want web/allow-client-https metadata", explanation.MatchedRule)
	}
	if explanation.Packet.RemoteIP != netip.MustParseAddr("10.10.0.11") {
		t.Fatalf("remote IP = %s, want remote endpoint IP", explanation.Packet.RemoteIP)
	}
	if explanation.Packet.RemoteIdentity != policy.EndpointIdentity(model.EndpointKey("prod", "pod-b")) {
		t.Fatalf("remote identity = %d, want derived endpoint identity", explanation.Packet.RemoteIdentity)
	}
}

func TestRunPolicyExplainReportsNoMatchDrop(t *testing.T) {
	statePath := writePolicyExplainState(t)
	var stdout bytes.Buffer

	err := runPolicyExplain([]string{
		"-state", statePath,
		"-vpc", "prod",
		"-endpoint", "pod-a",
		"-remote-endpoint", "pod-b",
		"-direction", "ingress",
		"-protocol", "tcp",
		"-dest-port", "80",
	}, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	var explanation dataplane.PolicyExplanation
	if err := json.Unmarshal(stdout.Bytes(), &explanation); err != nil {
		t.Fatalf("decode explanation: %v\n%s", err, stdout.String())
	}
	if explanation.Verdict != dataplane.VerdictDrop || explanation.Reason != dataplane.ExplainReasonNoPolicyMatch {
		t.Fatalf("explanation = %+v, want no-match drop", explanation)
	}
	if explanation.Matched || explanation.RuleCookie != 0 {
		t.Fatalf("explanation = %+v, want no matched rule", explanation)
	}
	if explanation.MatchedRule != nil {
		t.Fatalf("matched rule = %+v, want nil for no-match drop", explanation.MatchedRule)
	}
}

func TestRunRouteExplainReportsPolicyRouteReroute(t *testing.T) {
	statePath := writeRouteExplainState(t)
	var stdout bytes.Buffer

	err := runRouteExplain([]string{
		"-state", statePath,
		"-vpc", "prod",
		"-source", "10.10.0.10",
		"-dest", "172.16.1.10",
		"-protocol", "tcp",
		"-source-port", "32001",
		"-dest-port", "443",
	}, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	var decision topology.Decision
	if err := json.Unmarshal(stdout.Bytes(), &decision); err != nil {
		t.Fatalf("decode decision: %v\n%s", err, stdout.String())
	}
	if decision.Action != model.ActionReroute || decision.MatchedBy != "policy-route/private-via-fw" {
		t.Fatalf("decision = %+v, want policy-route reroute", decision)
	}
	if decision.PolicyRoute == nil {
		t.Fatalf("policy route selection missing from route explain output: %+v", decision)
	}
	if decision.PolicyRoute.Name != "private-via-fw" || decision.PolicyRoute.Priority != 100 || decision.PolicyRoute.Action != model.ActionReroute {
		t.Fatalf("policy route selection = %+v, want private-via-fw reroute priority 100", decision.PolicyRoute)
	}
	if decision.PolicyRoute.SelectedNextHop != netip.MustParseAddr("10.10.0.253") {
		t.Fatalf("selected policy route next hop = %s, want 10.10.0.253", decision.PolicyRoute.SelectedNextHop)
	}
	if decision.NextHop != netip.MustParseAddr("10.10.0.253") || decision.Gateway != "gw-fw" {
		t.Fatalf("decision = %+v, want firewall next hop and gateway", decision)
	}
	if decision.Translated != netip.MustParseAddr("198.51.100.10") {
		t.Fatalf("translated = %s, want SNAT external IP", decision.Translated)
	}
}

func TestRunRouteExplainReportsNoRouteDrop(t *testing.T) {
	statePath := writeRouteExplainState(t)
	var stdout bytes.Buffer

	err := runRouteExplain([]string{
		"-state", statePath,
		"-vpc", "prod",
		"-source", "10.10.0.10",
		"-dest", "203.0.113.200",
	}, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	var decision topology.Decision
	if err := json.Unmarshal(stdout.Bytes(), &decision); err != nil {
		t.Fatalf("decode decision: %v\n%s", err, stdout.String())
	}
	if decision.Action != model.ActionDrop || decision.MatchedBy != "no-route" {
		t.Fatalf("decision = %+v, want no-route drop", decision)
	}
}

func writePolicyExplainState(t *testing.T) string {
	t.Helper()
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
				ID:     "pod-b",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.11"),
				Node:   "node-b",
				Labels: model.Labels{"role": "client"},
			},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:                     "allow-client-https",
				Priority:               100,
				Direction:              model.DirectionIngress,
				Protocol:               model.ProtocolTCP,
				RemoteEndpointSelector: model.Labels{"role": "client"},
				Ports:                  []model.PortRange{{From: 443, To: 443}},
				Action:                 model.ActionAllow,
			}},
		}},
	}
	return writeAgentState(t, state)
}

func writeAgentState(t *testing.T, state control.DesiredState) string {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReconcileStateFileOnceAppliesDesiredPolicyRollout(t *testing.T) {
	statePath := writeAgentState(t, control.DesiredState{
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
				ID:         "allow-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionAllow,
			}},
		}},
		PolicyRollouts: []control.PolicyRollout{{
			Name:      "web-canary",
			Node:      "node-a",
			Endpoints: []string{"prod/pod-a"},
			BatchSize: 1,
		}},
	})
	store := dataplane.NewInMemoryPolicyStore()
	metrics := newAgentMetrics(store)
	historyOVSDB := &fakeOpenVSwitchExternalIDStore{}
	if err := configurePolicyRolloutHistory(t.Context(), metrics, ovsdbPolicyRolloutHistoryStore{syncer: historyOVSDB}); err != nil {
		t.Fatal(err)
	}
	rolloutOVSDB := &fakeOpenVSwitchExternalIDStore{}

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = oldStdout
	}()

	err = reconcileStateFileOnceWithRuntimeStores(context.Background(), statePath, "node-a", "memory", store, time.Second, metrics, nil, nil, ovsdbPolicyRolloutStateStore{syncer: rolloutOVSDB}, nil, nil)
	if closeErr := writer.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, reader); copyErr != nil {
		t.Fatal(copyErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	for _, expected := range []string{
		"policy_rollouts=1",
		"policy_rollout_planned=1",
		"policy_rollout_applied=1",
		"policy_rollout_failed=0",
		"policy_rollout_cancelled=0",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output missing %q:\n%s", expected, output)
		}
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want rollout applied policy", entries)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-b")); len(entries) != 0 {
		t.Fatalf("pod-b entries = %+v, want deferred non-rollout policy", entries)
	}
	snapshot, _, ready := metrics.snapshotValue()
	if !ready || snapshot.Result.PolicyRolloutApplied != 1 {
		t.Fatalf("metrics snapshot = %+v ready=%t, want rollout applied", snapshot.Result, ready)
	}
	history := metrics.policyRolloutHistory()
	if len(history) != 1 || history[0].Source != "desired-state" || history[0].Name != "web-canary" || history[0].Rollout.Applied != 1 {
		t.Fatalf("rollout history = %+v, want desired-state web-canary entry", history)
	}
	raw := historyOVSDB.values[policyRolloutHistoryKey]
	if !strings.Contains(raw, `"source":"desired-state"`) || !strings.Contains(raw, `"name":"web-canary"`) {
		t.Fatalf("history external_id = %s, want desired-state rollout entry", raw)
	}
}

func TestReconcileStateFileOnceWritesAgentStatusToOpenVSwitchExternalID(t *testing.T) {
	t.Setenv("NETLOOM_POLICY_STORE", "")
	t.Setenv("NETLOOM_TCX_WORKLOAD", "")
	t.Setenv("NETLOOM_LINUX_DATAPATH", "")
	t.Setenv("NETLOOM_PROVIDER_NETWORK_LINKS", "")
	statePath := writeAgentState(t, control.DesiredState{
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
	})
	store := dataplane.NewInMemoryPolicyStore()
	statusStore := &fakeOpenVSwitchExternalIDStore{}

	if err := reconcileStateFileOnceWithRuntimeStores(context.Background(), statePath, "node-a", "memory", store, time.Second, nil, nil, nil, nil, nil, statusStore); err != nil {
		t.Fatal(err)
	}

	if owner := statusStore.values["netloom_owner"]; owner != "netloom" {
		t.Fatalf("netloom_owner = %q, want netloom", owner)
	}
	raw := statusStore.values[agentOVSDBStatusKey]
	if raw == "" {
		t.Fatalf("missing %s external_id", agentOVSDBStatusKey)
	}
	var status agentOVSDBStatus
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		t.Fatalf("decode %s: %v", agentOVSDBStatusKey, err)
	}
	if status.Status != "success" || status.Node != "node-a" || status.Store != "memory" || status.Endpoints != 1 || status.PolicyMapEntries != 1 {
		t.Fatalf("agent OVSDB status = %+v, want successful node-a memory reconcile with one policy entry", status)
	}
	if !status.RuntimeReady || len(status.Runtime) == 0 {
		t.Fatalf("agent OVSDB runtime status = ready:%t checks:%+v, want ready runtime preflight checks", status.RuntimeReady, status.Runtime)
	}
}

func TestReconcileStateFileOnceStrictRuntimePreflightFailsClosed(t *testing.T) {
	t.Setenv("NETLOOM_RUNTIME_PREFLIGHT_STRICT", "1")
	originalPreflight := runAgentRuntimePreflight
	runAgentRuntimePreflight = func() []agent.RuntimeCheck {
		return []agent.RuntimeCheck{{
			Name:     "bpffs",
			Status:   "fail",
			Required: true,
			Detail:   "/sys/fs/bpf is not bpffs",
		}, {
			Name:   "ovsdb",
			Status: "warn",
			Detail: "not configured",
		}}
	}
	t.Cleanup(func() {
		runAgentRuntimePreflight = originalPreflight
	})
	statePath := writeAgentState(t, control.DesiredState{
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
	})
	store := dataplane.NewInMemoryPolicyStore()
	statusStore := &fakeOpenVSwitchExternalIDStore{}
	metrics := newAgentMetrics(store)

	err := reconcileStateFileOnceWithRuntimeStores(context.Background(), statePath, "node-a", "memory", store, time.Second, metrics, nil, nil, nil, nil, statusStore)
	if err == nil || !strings.Contains(err.Error(), "runtime preflight failed") || !strings.Contains(err.Error(), "bpffs=fail") {
		t.Fatalf("err = %v, want strict runtime preflight failure", err)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("policy entries = %+v, want no mutation after strict runtime preflight failure", entries)
	}
	var status agentOVSDBStatus
	if raw := statusStore.values[agentOVSDBStatusKey]; raw == "" {
		t.Fatalf("missing %s external_id", agentOVSDBStatusKey)
	} else if err := json.Unmarshal([]byte(raw), &status); err != nil {
		t.Fatalf("decode %s: %v", agentOVSDBStatusKey, err)
	}
	if status.Status != "error" || status.RuntimeReady || status.RuntimeFailed != 1 || len(status.Runtime) != 2 {
		t.Fatalf("agent OVSDB status = %+v, want strict runtime preflight error", status)
	}
	snapshot, _, ready := metrics.snapshotValue()
	if !ready || snapshot.Success || !strings.Contains(snapshot.Error, "runtime preflight failed") || agent.RuntimeChecksReady(snapshot.Runtime) {
		t.Fatalf("metrics snapshot = %+v ready=%t, want runtime preflight failure", snapshot, ready)
	}
}

func TestReconcileStateFileOnceResumesPersistedPolicyRolloutState(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
			{ID: "pod-b", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.11"), Node: "node-a", SecurityGroups: []string{"web"}},
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
		PolicyRollouts: []control.PolicyRollout{{
			Name:             "web-canary",
			Node:             "node-a",
			Endpoints:        []string{"prod/pod-a", "prod/pod-b"},
			BatchSize:        1,
			PromotionPercent: 50,
		}},
	}
	statePath := writeAgentState(t, state)
	rolloutOVSDB := &fakeOpenVSwitchExternalIDStore{}
	store := dataplane.NewInMemoryPolicyStore()

	linuxOptions := (*linuxdatapath.Options)(nil)
	rolloutStore := ovsdbPolicyRolloutStateStore{syncer: rolloutOVSDB}
	dnsStore := dnsObservationStore(nil)
	if err := reconcileStateFileOnceWithRuntimeStores(context.Background(), statePath, "node-a", "memory", store, time.Second, nil, nil, linuxOptions, rolloutStore, dnsStore, nil); err != nil {
		t.Fatal(err)
	}
	doc, err := rolloutStore.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Rollouts) != 1 || doc.Rollouts[0].Name != "web-canary" || doc.Rollouts[0].Revision == "" || !reflect.DeepEqual(doc.Rollouts[0].AppliedEndpoints, []string{model.EndpointKey("prod", "pod-a")}) {
		t.Fatalf("rollout state = %+v, want paused web-canary with pod-a applied", doc)
	}
	eventsAfterFirst := len(store.Events())

	state.PolicyRollouts[0].PromotionPercent = 100
	statePath = writeAgentState(t, state)
	if err := reconcileStateFileOnceWithRuntimeStores(context.Background(), statePath, "node-a", "memory", store, time.Second, nil, nil, linuxOptions, rolloutStore, dnsStore, nil); err != nil {
		t.Fatal(err)
	}
	if got := len(store.Events()) - eventsAfterFirst; got != 1 {
		t.Fatalf("new policy events after resume = %d, want only pod-b written", got)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want retained policy", entries)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-b")); len(entries) != 1 {
		t.Fatalf("pod-b entries = %+v, want resumed rollout applied remaining policy", entries)
	}
	doc, err = rolloutStore.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Rollouts) != 0 {
		t.Fatalf("rollout state after completion = %+v, want cleared state", doc)
	}
}

func TestLoadPolicyRolloutResumeIgnoresStaleRevision(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
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
		PolicyRollouts: []control.PolicyRollout{{
			Name:      "web-canary",
			Node:      "node-a",
			Endpoints: []string{"prod/pod-a"},
			BatchSize: 1,
		}},
	}
	revision, err := agent.PolicyRolloutRevision(state, state.PolicyRollouts[0], []string{model.EndpointKey("prod", "pod-a")})
	if err != nil {
		t.Fatal(err)
	}
	store := ovsdbPolicyRolloutStateStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	if err := store.Save(t.Context(), policyRolloutStateDocument{Rollouts: []policyRolloutStateEntry{{
		Name:             "web-canary",
		Node:             "node-a",
		Revision:         "stale",
		AppliedEndpoints: []string{model.EndpointKey("prod", "pod-a")},
	}}}); err != nil {
		t.Fatal(err)
	}
	resume, err := loadPolicyRolloutResume(t.Context(), store, "node-a", state)
	if err != nil {
		t.Fatal(err)
	}
	if len(resume) != 0 {
		t.Fatalf("resume = %+v, want stale revision ignored", resume)
	}

	if err := store.Save(t.Context(), policyRolloutStateDocument{Rollouts: []policyRolloutStateEntry{{
		Name:             "web-canary",
		Node:             "node-a",
		Revision:         revision,
		AppliedEndpoints: []string{model.EndpointKey("prod", "pod-a")},
	}}}); err != nil {
		t.Fatal(err)
	}
	resume, err = loadPolicyRolloutResume(t.Context(), store, "node-a", state)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resume["web-canary"], []string{model.EndpointKey("prod", "pod-a")}) {
		t.Fatalf("resume = %+v, want matching revision restored", resume)
	}
}

func writeRouteExplainState(t *testing.T) string {
	t.Helper()
	state := control.DesiredState{
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "private-via-fw",
			VPC:      "prod",
			Priority: 100,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("172.16.0.0/16"),
				Protocol:    model.ProtocolTCP,
				SrcPorts:    []model.PortRange{{From: 32000, To: 32010}},
				DstPorts:    []model.PortRange{{From: 443, To: 443}},
			},
			Action: model.RouteAction{
				Type:     model.ActionReroute,
				NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")},
			},
		}},
		Gateways: []model.Gateway{
			{Name: "gw-main", VPC: "prod", Node: "node-a", ExternalIF: "eth0", LANIP: netip.MustParseAddr("10.10.0.254")},
			{Name: "gw-fw", VPC: "prod", Node: "node-b", ExternalIF: "eth0", LANIP: netip.MustParseAddr("10.10.0.253")},
		},
		NATRules: []model.NATRule{{
			Name:       "egress",
			VPC:        "prod",
			Type:       model.ActionSNAT,
			MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
			ExternalIP: netip.MustParseAddr("198.51.100.10"),
		}},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "route-state.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPrintReconcileResultIncludesPolicyMapUsageSummary(t *testing.T) {
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = oldStdout
	}()

	printReconcileResult(agent.ReconcileResult{
		Node:                             "node-a",
		Endpoints:                        1,
		Programs:                         1,
		Entries:                          3,
		PolicyMapEntries:                 12,
		PolicyMapCapacity:                16,
		PolicyMapPressureMax:             75,
		PolicyMapPressureEndpoint:        "prod\x00pod-a",
		PolicyMapPressureEndpoints:       0,
		PolicyPressureMitigated:          2,
		PolicyPressureQuarantined:        1,
		PolicyPressureQuarantineEndpoint: "prod\x00pod-a",
		PolicyRollouts:                   1,
		PolicyRolloutPlanned:             3,
		PolicyRolloutApplied:             2,
		PolicyRolloutSkipped:             1,
		PolicyRolloutFailed:              0,
		PolicyRolloutRolledBack:          1,
		PolicyRolloutRollbackFailed:      0,
		PolicyRolloutSLOFailed:           1,
		PolicyRolloutProbeFailed:         1,
		PolicyRolloutPaused:              1,
		PolicyRolloutCancelled:           1,
		PolicyMapDriftEndpoints:          1,
		PolicyMapDriftMissing:            2,
		PolicyMapDriftExtra:              3,
		PolicyMapDriftChanged:            4,
		PolicyFailedEndpoint:             "prod\x00pod-b",
		PolicyFailedRevision:             3,
		PolicyRulePackets:                3,
		PolicyRuleBytes:                  384,
		PolicyRuleAllowed:                2,
		PolicyRuleDropped:                1,
		PolicyRuleLogged:                 1,
		PolicyRuleStats: []dataplane.RuleMetrics{
			{EndpointID: "prod\x00pod-a", RuleCookie: 7, Packets: 1, Bytes: 256, Dropped: 1, DenyDrops: 1},
			{EndpointID: "prod\x00pod-a", RuleCookie: 42, Packets: 2, Bytes: 128, Allowed: 2, Logged: 1},
		},
		TCXSkipped:       2,
		TCXFailedTarget:  "iface=eth0 direction=ingress attach=2",
		ProviderNetworks: 1,
		ProviderLinks:    2,
		ProviderReady:    1,
		ProviderDegraded: 1,
		ProviderStatus: []linuxdatapath.ProviderLinkStatus{
			{ProviderNetwork: "physnet-a", ParentDevice: "eth1", VLAN: 100, LinkName: "nlv-a", Ready: true, ParentState: "up", LinkState: "up"},
			{ProviderNetwork: "physnet-b", ParentDevice: "bond0", VLAN: 200, LinkName: "nlv-b", Ready: false, ParentState: "up", LinkState: "down"},
		},
		ProviderNetworkStatus: []linuxdatapath.ProviderNetworkStatus{
			{
				ProviderNetwork: "physnet-a",
				Ready:           true,
				LinkCount:       1,
				ReadyLinks:      1,
				IssueCount:      0,
				TenantCount:     1,
				SubnetCount:     1,
				EndpointCount:   2,
				TenantUsage: []linuxdatapath.ProviderTenantUsage{{
					Tenant:       "prod",
					Subnets:      1,
					Endpoints:    2,
					MaxSubnets:   2,
					MaxEndpoints: 3,
				}},
			},
			{ProviderNetwork: "physnet-b", Ready: false, LinkCount: 1, ReadyLinks: 0, IssueCount: 1, Reasons: []string{"type-mismatch"}},
		},
		ProviderInventoryTotal:    3,
		ProviderInventoryReady:    2,
		ProviderInventoryDegraded: 1,
		ProviderInventoryStatus: []linuxdatapath.ProviderInterface{
			{Name: "eth1", Ready: true, State: "up"},
			{Name: "bond0", Ready: true, State: "up"},
			{Name: "ens5", Ready: false, State: "down"},
		},
		Datapath: "not-requested",
		TCX:      "not-requested",
	}, "ebpf", 250*time.Millisecond)

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	for _, expected := range []string{
		"policy_map_entries=12",
		"policy_map_capacity=16",
		"policy_map_pressure_max=75",
		`policy_map_pressure_endpoint="prod\x00pod-a"`,
		"policy_map_pressure_endpoints=0",
		"policy_pressure_mitigated=2",
		"policy_pressure_quarantined=1",
		`policy_pressure_quarantine_endpoint="prod\x00pod-a"`,
		"policy_rollouts=1",
		"policy_rollout_planned=3",
		"policy_rollout_applied=2",
		"policy_rollout_skipped=1",
		"policy_rollout_failed=0",
		"policy_rollout_rolled_back=1",
		"policy_rollout_rollback_failed=0",
		"policy_rollout_slo_failed=1",
		"policy_rollout_probe_failed=1",
		"policy_rollout_paused=1",
		"policy_rollout_cancelled=1",
		"policy_map_drift_endpoints=1",
		"policy_map_drift_missing=2",
		"policy_map_drift_extra=3",
		"policy_map_drift_changed=4",
		`policy_failed_endpoint="prod\x00pod-b"`,
		"policy_failed_revision=3",
		"policy_rule_packets=3",
		"policy_rule_bytes=384",
		"policy_rule_allowed=2",
		"policy_rule_dropped=1",
		"policy_rule_rejected=0",
		"policy_rule_logged=1",
		`policy_rule_stats="prod\x00pod-a"/7:p=1,b=256,a=0,d=1,r=0,nm=0,ct=0,est=0,log=0;"prod\x00pod-a"/42:p=2,b=128,a=2,d=0,r=0,nm=0,ct=0,est=0,log=1`,
		"tcx_skipped=2",
		`tcx_failed_target="iface=eth0 direction=ingress attach=2"`,
		"provider_networks=1",
		"provider_links=2",
		"provider_ready=1",
		"provider_degraded=1",
		"provider_status=physnet-a:eth1:100:nlv-a:ready:up:up,physnet-b:bond0:200:nlv-b:pending:up:down",
		"provider_network_status=physnet-a:ready:1/1:0:none:tenants=1:subnets=1:endpoints=2:prod=ok:1/2:2/3,physnet-b:degraded:0/1:1:type-mismatch",
		"provider_inventory_total=3",
		"provider_inventory_ready=2",
		"provider_inventory_degraded=1",
		"provider_inventory_status=eth1:up,bond0:up,ens5:down",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output missing %q:\n%s", expected, output)
		}
	}
}

func TestPrintReconcileFailureIncludesPolicyFailureLocation(t *testing.T) {
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = oldStdout
	}()

	printReconcileFailure(agent.ReconcileResult{
		Node:                 "node-a",
		Endpoints:            1,
		Programs:             1,
		Entries:              2,
		PolicyEvents:         1,
		PolicyFailed:         1,
		PolicyRollbacks:      1,
		PolicyFailedEndpoint: "prod\x00pod-a",
		PolicyFailedRevision: 2,
		PolicyRevisionMax:    2,
		PolicyLastError:      "in-memory policy update failed after 1 operations",
		PolicyRulePackets:    1,
		PolicyRuleBytes:      64,
		PolicyRuleDropped:    1,
		PolicyRuleStats: []dataplane.RuleMetrics{
			{EndpointID: "prod\x00pod-a", RuleCookie: 0, Packets: 1, Bytes: 64, Dropped: 1, NoMatchDrops: 1},
		},
		TCXFailedTarget: "iface=eth0 direction=ingress attach=2",
		TCXLastError:    "kernel attach failed",
		TCX:             "not-requested",
	}, "memory", errors.New("apply failed"), 125*time.Millisecond)

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	for _, expected := range []string{
		"policy_failed=1",
		"policy_rollbacks=1",
		`policy_failed_endpoint="prod\x00pod-a"`,
		"policy_failed_revision=2",
		`policy_last_error="in-memory policy update failed after 1 operations"`,
		"policy_rule_packets=1",
		"policy_rule_bytes=64",
		"policy_rule_dropped=1",
		`policy_rule_stats="prod\x00pod-a"/0:p=1,b=64,a=0,d=1,r=0,nm=1,ct=0,est=0,log=0`,
		`tcx_failed_target="iface=eth0 direction=ingress attach=2"`,
		`tcx_last_error="kernel attach failed"`,
		`err="apply failed"`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("failure output missing %q:\n%s", expected, output)
		}
	}
}

func TestFormatRuleStatsIncludesCounters(t *testing.T) {
	formatted := formatRuleStats([]dataplane.RuleMetrics{
		{
			RuleCookie:   0,
			Packets:      1,
			Bytes:        512,
			Dropped:      1,
			NoMatchDrops: 1,
		},
		{
			RuleCookie:  42,
			Packets:     2,
			Bytes:       256,
			Allowed:     2,
			Conntrack:   1,
			Established: 1,
			Logged:      2,
		},
	})
	for _, expected := range []string{
		"0:p=1,b=512,a=0,d=1,r=0,nm=1,ct=0,est=0,log=0",
		"42:p=2,b=256,a=2,d=0,r=0,nm=0,ct=1,est=1,log=2",
	} {
		if !strings.Contains(formatted, expected) {
			t.Fatalf("formatted rule stats missing %q: %s", expected, formatted)
		}
	}
}

func TestFormatRuleCatalogIncludesCookieAndReference(t *testing.T) {
	formatted := formatRuleCatalog([]agent.PolicyRuleCatalogEntry{{
		RuleCookie: 7,
		RuleRef:    "prod/web/deny-client",
	}})
	if formatted != "7:prod/web/deny-client" {
		t.Fatalf("formatted rule catalog = %s, want cookie and rule reference", formatted)
	}
}

func TestFormatRuntimeChecks(t *testing.T) {
	formatted := formatRuntimeChecks([]agent.RuntimeCheck{{
		Name:     "bpffs",
		Status:   "ok",
		Required: true,
		Detail:   "/sys/fs/bpf",
	}, {
		Name:   "ovsdb",
		Status: "skip",
		Detail: "not configured",
	}})
	if formatted != "bpffs:ok:required:/sys/fs/bpf;ovsdb:skip:optional:not_configured" {
		t.Fatalf("formatted runtime checks = %q", formatted)
	}
}

func TestFormatEndpointRuleStatsIncludesEndpointAndCounters(t *testing.T) {
	formatted := formatEndpointRuleStats([]dataplane.RuleMetrics{
		{
			EndpointID:   "prod\x00pod-a",
			RuleCookie:   42,
			Packets:      2,
			Bytes:        256,
			Allowed:      2,
			Conntrack:    1,
			Established:  1,
			Logged:       1,
			NoMatchDrops: 0,
		},
	})
	expected := `"prod\x00pod-a"/42:p=2,b=256,a=2,d=0,r=0,nm=0,ct=1,est=1,log=1`
	if formatted != expected {
		t.Fatalf("formatted endpoint rule stats = %s, want %s", formatted, expected)
	}
}

func TestAgentMetricsReportsNotReadyBeforeFirstReconcile(t *testing.T) {
	metrics := newAgentMetrics()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)

	metrics.handleMetrics(recorder, request)

	output := recorder.Body.String()
	if !strings.Contains(output, "netloom_agent_reconcile_ready 0") {
		t.Fatalf("metrics output missing not-ready gauge:\n%s", output)
	}
}

func TestPolicyEndpointAPIReportsNotReady(t *testing.T) {
	metrics := newAgentMetrics()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/endpoints", nil)

	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "not ready") {
		t.Fatalf("body missing not ready error: %s", recorder.Body.String())
	}
}

func TestPolicyRulesAPIReportsNotReady(t *testing.T) {
	metrics := newAgentMetrics()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/rules", nil)

	metrics.handlePolicyRules(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "not ready") {
		t.Fatalf("body missing not ready error: %s", recorder.Body.String())
	}
}

func TestPolicyEventsAPIReportsNotReady(t *testing.T) {
	metrics := newAgentMetrics(dataplane.NewInMemoryPolicyStore())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/events", nil)

	metrics.handlePolicyEvents(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "not ready") {
		t.Fatalf("body missing not ready error: %s", recorder.Body.String())
	}
}

func TestPolicyEntriesAPIReportsNotReady(t *testing.T) {
	metrics := newAgentMetrics(dataplane.NewInMemoryPolicyStore())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/entries/prod/pod-a", nil)

	metrics.handlePolicyEntries(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "not ready") {
		t.Fatalf("body missing not ready error: %s", recorder.Body.String())
	}
}

func TestPolicyEntriesAPIReportsNotEnabled(t *testing.T) {
	metrics := newAgentMetrics()
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
	}, "none", time.Millisecond, control.DesiredState{
		Endpoints: []model.Endpoint{{ID: "pod-a", VPC: "prod", Node: "node-a"}},
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/entries/prod/pod-a", nil)

	metrics.handlePolicyEntries(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "not enabled") {
		t.Fatalf("body missing not enabled error: %s", recorder.Body.String())
	}
}

func TestPolicyEntriesAPIReportsEndpointPolicyMapEntries(t *testing.T) {
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")
	entries := []dataplane.PolicyMapEntry{{
		Key: dataplane.PolicyKey{
			PrefixLen:      dataplane.StaticPrefixBits,
			RemoteIdentity: 42,
			Direction:      dataplane.DirectionIngress,
			Protocol:       6,
			DestPortBE:     80,
		},
		Value: dataplane.PolicyEntry{
			Stateful:        1,
			Log:             1,
			Precedence:      100,
			RuleCookie:      7,
			RequireIdentity: 1,
			Packets:         3,
			Bytes:           240,
		},
		RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
	}}
	if err := store.ReplaceEndpoint(context.Background(), endpointID, entries); err != nil {
		t.Fatal(err)
	}
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyRuleCatalog: []agent.PolicyRuleCatalogEntry{{
			EndpointID:    endpointID,
			RuleCookie:    7,
			RuleRef:       "prod/web/allow-client",
			VPC:           "prod",
			SecurityGroup: "web",
			RuleID:        "allow-client",
		}},
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
			Entries:    1,
		}},
	}, "memory", time.Millisecond, control.DesiredState{
		Endpoints: []model.Endpoint{{ID: "pod-a", VPC: "prod", Node: "node-a"}},
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/entries/prod/pod-a", nil)

	metrics.handlePolicyEntries(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEntriesOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy entries response: %v\n%s", err, recorder.Body.String())
	}
	if !got.Ready || got.EndpointID != endpointID || got.EntryCount != 1 || len(got.Entries) != 1 {
		t.Fatalf("entries output = %+v, want one ready endpoint entry", got)
	}
	entry := got.Entries[0]
	if entry.Key.RemoteIdentity != 42 || entry.Key.Direction != dataplane.DirectionIngress || entry.Key.Protocol != 6 || entry.Value.RuleCookie != 7 {
		t.Fatalf("entry = %+v, want key/value fields from store", entry)
	}
	if entry.RemoteCIDR != "172.30.0.0/24" || entry.Value.Packets != 3 || entry.Value.Bytes != 240 {
		t.Fatalf("entry counters/cidr = %+v, want remote cidr and counters", entry)
	}
	if entry.RuleRef != "prod/web/allow-client" || entry.VPC != "prod" || entry.SecurityGroup != "web" || entry.RuleID != "allow-client" {
		t.Fatalf("entry rule metadata = %+v, want allow-client catalog", entry)
	}
}

func TestPolicyEntriesAPIFiltersEndpointEntriesByRuleCookie(t *testing.T) {
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")
	entries := []dataplane.PolicyMapEntry{{
		Key: dataplane.PolicyKey{
			PrefixLen:      dataplane.StaticPrefixBits,
			RemoteIdentity: 42,
			Direction:      dataplane.DirectionIngress,
			Protocol:       6,
		},
		Value:      dataplane.PolicyEntry{RuleCookie: 7, Packets: 3},
		RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
	}, {
		Key: dataplane.PolicyKey{
			PrefixLen:      dataplane.StaticPrefixBits,
			RemoteIdentity: 43,
			Direction:      dataplane.DirectionIngress,
			Protocol:       6,
		},
		Value:      dataplane.PolicyEntry{RuleCookie: 42, Packets: 5},
		RemoteCIDR: netip.MustParsePrefix("172.31.0.0/24"),
	}}
	if err := store.ReplaceEndpoint(context.Background(), endpointID, entries); err != nil {
		t.Fatal(err)
	}
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyRuleCatalog: []agent.PolicyRuleCatalogEntry{{
			EndpointID:    endpointID,
			RuleCookie:    42,
			RuleRef:       "prod/web/allow-https",
			VPC:           "prod",
			SecurityGroup: "web",
			RuleID:        "allow-https",
		}},
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
			Entries:    2,
		}},
	}, "memory", time.Millisecond, control.DesiredState{
		Endpoints: []model.Endpoint{{ID: "pod-a", VPC: "prod", Node: "node-a"}},
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/entries/prod/pod-a?rule_cookie=42", nil)
	metrics.handlePolicyEntries(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEntriesOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy entries response: %v\n%s", err, recorder.Body.String())
	}
	if got.FilterRuleCookie != 42 || got.EntryCount != 1 || len(got.Entries) != 1 {
		t.Fatalf("entries output = %+v, want one cookie 42 entry", got)
	}
	if got.Entries[0].Value.RuleCookie != 42 || got.Entries[0].RemoteCIDR != "172.31.0.0/24" {
		t.Fatalf("entry = %+v, want filtered cookie 42 remote cidr", got.Entries[0])
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/policy/entries/prod/pod-a?rule_ref=prod/web/allow-https", nil)
	metrics.handlePolicyEntries(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	got = policyEntriesOutput{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode rule-ref filtered policy entries response: %v\n%s", err, recorder.Body.String())
	}
	if got.FilterRuleRef != "prod/web/allow-https" || got.EntryCount != 1 || len(got.Entries) != 1 || got.Entries[0].RuleRef != "prod/web/allow-https" {
		t.Fatalf("rule-ref filtered entries = %+v, want allow-https entry", got)
	}
}

func TestPolicyEntriesAPIRejectsInvalidRuleCookie(t *testing.T) {
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
		}},
	}, "memory", time.Millisecond, control.DesiredState{
		Endpoints: []model.Endpoint{{ID: "pod-a", VPC: "prod", Node: "node-a"}},
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/entries/prod/pod-a?rule_cookie=bad", nil)
	metrics.handlePolicyEntries(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPolicyExplainAPIReportsNotReady(t *testing.T) {
	metrics := newAgentMetrics()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/explain", nil)

	metrics.handlePolicyExplain(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "not ready") {
		t.Fatalf("body missing not ready error: %s", recorder.Body.String())
	}
}

func TestPolicyEventsAPIReportsRecentEndpointEvents(t *testing.T) {
	store := dataplane.NewInMemoryPolicyStore()
	podA := model.EndpointKey("prod", "pod-a")
	podB := model.EndpointKey("prod", "pod-b")
	if err := store.ReplaceEndpoint(context.Background(), podA, []dataplane.PolicyMapEntry{{
		Key: dataplane.PolicyKey{
			PrefixLen:      dataplane.StaticPrefixBits,
			Direction:      dataplane.DirectionIngress,
			Protocol:       6,
			RemoteIdentity: 10,
		},
		Value: dataplane.PolicyEntry{RuleCookie: 42},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceEndpoint(context.Background(), podB, []dataplane.PolicyMapEntry{{
		Key: dataplane.PolicyKey{
			PrefixLen:      dataplane.StaticPrefixBits,
			Direction:      dataplane.DirectionEgress,
			Protocol:       6,
			RemoteIdentity: 20,
		},
		Value: dataplane.PolicyEntry{RuleCookie: 7},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceEndpoint(context.Background(), podA, []dataplane.PolicyMapEntry{{
		Key: dataplane.PolicyKey{
			PrefixLen:      dataplane.StaticPrefixBits,
			Direction:      dataplane.DirectionIngress,
			Protocol:       6,
			RemoteIdentity: 10,
		},
		Value: dataplane.PolicyEntry{RuleCookie: 42},
	}, {
		Key: dataplane.PolicyKey{
			PrefixLen:      dataplane.StaticPrefixBits,
			Direction:      dataplane.DirectionEgress,
			Protocol:       6,
			RemoteIdentity: 30,
		},
		Value: dataplane.PolicyEntry{RuleCookie: 43},
	}}); err != nil {
		t.Fatal(err)
	}
	metrics := newAgentMetrics(store)
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyRuleCatalog: []agent.PolicyRuleCatalogEntry{
			{EndpointID: podA, RuleCookie: 42, RuleRef: "prod/web/allow-old", VPC: "prod", SecurityGroup: "web", RuleID: "allow-old"},
			{EndpointID: podA, RuleCookie: 43, RuleRef: "prod/web/allow-new", VPC: "prod", SecurityGroup: "web", RuleID: "allow-new"},
		},
	}, "memory", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/events/prod/pod-a?limit=1", nil)
	metrics.handlePolicyEvents(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEventsOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy events response: %v\n%s", err, recorder.Body.String())
	}
	if !got.Ready || !got.LastReconcileSuccess || got.Node != "node-a" || got.Store != "memory" {
		t.Fatalf("policy events summary = %+v, want ready node-a memory success", got)
	}
	if got.TotalEvents != 3 || got.EventCount != 1 || got.Limit != 1 || got.FilterEndpoint != "prod/pod-a" {
		t.Fatalf("policy event counts = %+v, want total=3 event_count=1 limit=1 filter=prod/pod-a", got)
	}
	if len(got.Events) != 1 || got.Events[0].EndpointID != podA || got.Events[0].Revision != 2 || !got.Events[0].Success {
		t.Fatalf("events = %+v, want latest successful pod-a revision 2", got.Events)
	}
	if got.Events[0].Stats.Added != 1 || got.Events[0].Stats.Unchanged != 1 {
		t.Fatalf("event stats = %+v, want second pod-a update stats", got.Events[0].Stats)
	}
	if !slices.Equal(got.Events[0].RuleCookies, []uint32{43}) || !slices.Equal(got.Events[0].RuleRefs, []string{"prod/web/allow-new"}) {
		t.Fatalf("event rule refs = cookies %v refs %v, want allow-new", got.Events[0].RuleCookies, got.Events[0].RuleRefs)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/policy/events?rule_ref=prod/web/allow-new", nil)
	metrics.handlePolicyEvents(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	got = policyEventsOutput{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode rule-ref filtered policy events response: %v\n%s", err, recorder.Body.String())
	}
	if got.FilterRuleRef != "prod/web/allow-new" || got.EventCount != 1 || len(got.Events) != 1 || got.Events[0].Revision != 2 {
		t.Fatalf("rule-ref filtered events = %+v, want only allow-new revision 2", got)
	}
}

func TestPolicyEventsAPIFiltersFailedEvents(t *testing.T) {
	store := dataplane.NewInMemoryPolicyStore()
	podA := model.EndpointKey("prod", "pod-a")
	if err := store.ReplaceEndpoint(context.Background(), podA, []dataplane.PolicyMapEntry{{
		Key:   dataplane.PolicyKey{PrefixLen: dataplane.StaticPrefixBits, Direction: dataplane.DirectionIngress, Protocol: 6, RemoteIdentity: 10},
		Value: dataplane.PolicyEntry{RuleCookie: 42},
	}}); err != nil {
		t.Fatal(err)
	}
	store.SetFailAfter(1)
	if err := store.ReplaceEndpoint(context.Background(), podA, []dataplane.PolicyMapEntry{{
		Key:   dataplane.PolicyKey{PrefixLen: dataplane.StaticPrefixBits, Direction: dataplane.DirectionIngress, Protocol: 6, RemoteIdentity: 11},
		Value: dataplane.PolicyEntry{RuleCookie: 43},
	}}); err == nil {
		t.Fatal("expected failed policy update")
	}
	metrics := newAgentMetrics(store)
	observeAgentReconcileResult(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/events?success=false", nil)
	metrics.handlePolicyEvents(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEventsOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy events response: %v\n%s", err, recorder.Body.String())
	}
	if got.FilterSuccess == nil || *got.FilterSuccess || got.EventCount != 1 || len(got.Events) != 1 {
		t.Fatalf("events output = %+v, want one failed event", got)
	}
	if got.Events[0].Success || got.Events[0].EndpointID != podA || got.Events[0].Error == "" {
		t.Fatalf("events = %+v, want failed pod-a event with error", got.Events)
	}
}

func TestPolicyEventsAPIRejectsInvalidRemediatedFilter(t *testing.T) {
	metrics := newAgentMetrics(dataplane.NewInMemoryPolicyStore())
	observeAgentReconcileResult(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/events?remediated=maybe", nil)
	metrics.handlePolicyEvents(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPolicyEventsAPIRejectsInvalidRuleCookie(t *testing.T) {
	metrics := newAgentMetrics(dataplane.NewInMemoryPolicyStore())
	observeAgentReconcileResult(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/events?rule_cookie=not-a-cookie", nil)
	metrics.handlePolicyEvents(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "invalid rule cookie") {
		t.Fatalf("body missing invalid rule cookie error: %s", recorder.Body.String())
	}
}

func TestPolicyEventsAPIReportsNotEnabled(t *testing.T) {
	metrics := newAgentMetrics()
	observeAgentReconcileResult(metrics, agent.ReconcileResult{Node: "node-a"}, "custom", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/events", nil)
	metrics.handlePolicyEvents(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "not enabled") {
		t.Fatalf("body missing not enabled error: %s", recorder.Body.String())
	}
}

func TestPolicyEventsAPIRejectsInvalidLimit(t *testing.T) {
	metrics := newAgentMetrics(dataplane.NewInMemoryPolicyStore())
	observeAgentReconcileResult(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/events?limit=bad", nil)
	metrics.handlePolicyEvents(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "invalid limit") {
		t.Fatalf("body missing invalid limit error: %s", recorder.Body.String())
	}
}

func TestRunPolicyEventsWithStoreReportsFilteredJSON(t *testing.T) {
	store := ovsdbPolicyEventsStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	if err := store.Save(t.Context(), policyEventsDocument{
		Node:                 "node-a",
		Store:                "ebpf",
		LastReconcileSuccess: true,
		UpdatedAt:            time.Date(2026, 7, 17, 1, 2, 3, 0, time.UTC),
		TotalEvents:          3,
		Events: []dataplane.PolicyUpdateEvent{{
			EndpointID:  model.EndpointKey("prod", "pod-a"),
			Revision:    1,
			RuleCookies: []uint32{42},
			RuleRefs:    []string{"prod/web/allow-http"},
			Success:     true,
		}, {
			EndpointID:  model.EndpointKey("prod", "pod-b"),
			Revision:    1,
			RuleCookies: []uint32{43},
			RuleRefs:    []string{"prod/db/allow-db"},
			Success:     true,
		}, {
			EndpointID:  model.EndpointKey("prod", "pod-a"),
			Revision:    2,
			RuleCookies: []uint32{44},
			RuleRefs:    []string{"prod/web/deny-ssh"},
			Success:     false,
			Error:       "apply failed",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := runPolicyEventsWithStore(t.Context(), policyEventsOptions{endpoint: "prod/pod-a", limit: 1}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	var got policyEventsOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-events output: %v\n%s", err, stdout.String())
	}
	if !got.Ready || !got.LastReconcileSuccess || got.Node != "node-a" || got.Store != "ebpf" {
		t.Fatalf("policy events summary = %+v, want ready node-a ebpf", got)
	}
	if got.TotalEvents != 3 || got.EventCount != 1 || got.Limit != 1 || got.FilterEndpoint != "prod/pod-a" {
		t.Fatalf("policy event counts = %+v, want total=3 event_count=1 limit=1 filter=prod/pod-a", got)
	}
	if len(got.Events) != 1 || got.Events[0].Revision != 2 || got.Events[0].Success {
		t.Fatalf("events = %+v, want latest failed pod-a revision 2", got.Events)
	}

	stdout.Reset()
	if err := runPolicyEventsWithStore(t.Context(), policyEventsOptions{ruleCookie: "42", limit: 10}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	got = policyEventsOutput{}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode rule-cookie filtered policy-events output: %v\n%s", err, stdout.String())
	}
	if got.FilterRuleCookie != 42 || got.EventCount != 1 || len(got.Events) != 1 || got.Events[0].Revision != 1 || got.Events[0].EndpointID != model.EndpointKey("prod", "pod-a") {
		t.Fatalf("rule-cookie filtered events = %+v, want pod-a revision 1", got)
	}

	stdout.Reset()
	if err := runPolicyEventsWithStore(t.Context(), policyEventsOptions{ruleRef: "prod/db/allow-db", limit: 10}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	got = policyEventsOutput{}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode rule-ref filtered policy-events output: %v\n%s", err, stdout.String())
	}
	if got.FilterRuleRef != "prod/db/allow-db" || got.EventCount != 1 || len(got.Events) != 1 || got.Events[0].Revision != 1 || got.Events[0].EndpointID != model.EndpointKey("prod", "pod-b") {
		t.Fatalf("rule-ref filtered events = %+v, want pod-b allow-db revision 1", got)
	}
}

func TestRunPolicyEventsWithStoreFiltersRemediatedEvents(t *testing.T) {
	store := ovsdbPolicyEventsStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	if err := store.Save(t.Context(), policyEventsDocument{
		Node:                 "node-a",
		Store:                "ebpf",
		LastReconcileSuccess: true,
		TotalEvents:          3,
		Events: []dataplane.PolicyUpdateEvent{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Revision:   1,
			Success:    true,
		}, {
			EndpointID:  model.EndpointKey("prod", "pod-a"),
			Revision:    2,
			Success:     true,
			Remediated:  true,
			Remediation: "clear",
		}, {
			EndpointID: model.EndpointKey("prod", "pod-b"),
			Revision:   1,
			Success:    false,
			Error:      "apply failed",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := runPolicyEventsWithStore(t.Context(), policyEventsOptions{remediated: "true", limit: 10}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	var got policyEventsOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-events output: %v\n%s", err, stdout.String())
	}
	if got.FilterRemediated == nil || !*got.FilterRemediated || got.EventCount != 1 || len(got.Events) != 1 {
		t.Fatalf("policy events summary = %+v, want one remediated event", got)
	}
	if !got.Events[0].Remediated || got.Events[0].Remediation != "clear" {
		t.Fatalf("events = %+v, want clear remediated event", got.Events)
	}
}

func TestRunPolicyEventsReadsRealOpenVSwitchOVSDB(t *testing.T) {
	endpoint, client, cleanup := newTestAgentVSwitchOVSDB(t)
	defer cleanup()
	raw, err := json.Marshal(policyEventsDocument{
		Node:                 "node-a",
		Store:                "ebpf",
		LastReconcileSuccess: true,
		TotalEvents:          1,
		Events: []dataplane.PolicyUpdateEvent{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Revision:   1,
			Success:    true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	insertAgentVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{ExternalIDs: map[string]string{
		policyEventsKey: string(raw),
	}})
	var stdout bytes.Buffer
	if err := runPolicyEvents(t.Context(), []string{"-ovsdb", endpoint}, &stdout); err != nil {
		t.Fatal(err)
	}
	var got policyEventsOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-events output: %v\n%s", err, stdout.String())
	}
	if got.Node != "node-a" || got.Store != "ebpf" || len(got.Events) != 1 || got.Events[0].EndpointID != model.EndpointKey("prod", "pod-a") {
		t.Fatalf("policy events = %+v, want persisted pod-a event", got)
	}
}

func TestAgentMetricsPersistsPolicyEventsToOpenVSwitchExternalID(t *testing.T) {
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")
	if err := store.ReplaceEndpoint(t.Context(), endpointID, []dataplane.PolicyMapEntry{{
		Key: dataplane.PolicyKey{
			PrefixLen:      dataplane.StaticPrefixBits,
			Direction:      dataplane.DirectionIngress,
			Protocol:       6,
			RemoteIdentity: 10,
		},
		Value: dataplane.PolicyEntry{RuleCookie: 42},
	}}); err != nil {
		t.Fatal(err)
	}
	ovsdb := &fakeOpenVSwitchExternalIDStore{}
	metrics := newAgentMetrics(store)
	configurePolicyEventsStore(metrics, ovsdbPolicyEventsStore{syncer: ovsdb})

	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node:              "node-a",
		PolicyRuleCatalog: []agent.PolicyRuleCatalogEntry{{EndpointID: endpointID, RuleCookie: 42, RuleRef: "prod/web/allow-http", VPC: "prod", SecurityGroup: "web", RuleID: "allow-http"}},
	}, "ebpf", time.Millisecond)

	raw := ovsdb.values[policyEventsKey]
	if raw == "" {
		t.Fatalf("missing %s external_id", policyEventsKey)
	}
	var doc policyEventsDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Node != "node-a" || doc.Store != "ebpf" || !doc.LastReconcileSuccess || doc.TotalEvents != 1 {
		t.Fatalf("policy events doc = %+v, want successful node-a ebpf snapshot", doc)
	}
	if len(doc.Events) != 1 || doc.Events[0].EndpointID != endpointID || doc.Events[0].Revision != 1 {
		t.Fatalf("policy events = %+v, want pod-a revision 1", doc.Events)
	}
	if !slices.Equal(doc.Events[0].RuleCookies, []uint32{42}) || !slices.Equal(doc.Events[0].RuleRefs, []string{"prod/web/allow-http"}) {
		t.Fatalf("persisted event rule refs = cookies %v refs %v, want allow-http", doc.Events[0].RuleCookies, doc.Events[0].RuleRefs)
	}
}

func TestRunPolicyEntriesExportWithStoreReportsFilteredJSON(t *testing.T) {
	store := ovsdbPolicyEntriesStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	if err := store.Save(t.Context(), policyEntriesDocument{
		Node:                 "node-a",
		Store:                "ebpf",
		LastReconcileSuccess: true,
		UpdatedAt:            time.Date(2026, 7, 17, 1, 2, 3, 0, time.UTC),
		Endpoints: []policyEntriesEndpointOutput{{
			EndpointID: "prod\x00pod-a",
			EntryCount: 1,
			Entries: []policyMapEntryOutput{{
				Key: policyMapKeyOutput{
					PrefixLen:      dataplane.StaticPrefixBits,
					RemoteIdentity: 10,
					Direction:      dataplane.DirectionIngress,
					Protocol:       6,
				},
				Value:   policyMapValueOutput{RuleCookie: 42, Packets: 5},
				RuleRef: "prod/web/allow-http",
			}},
		}, {
			EndpointID: "prod\x00pod-b",
			EntryCount: 1,
			Entries: []policyMapEntryOutput{{
				Key: policyMapKeyOutput{
					PrefixLen:      dataplane.StaticPrefixBits,
					RemoteIdentity: 20,
					Direction:      dataplane.DirectionEgress,
					Protocol:       17,
				},
				Value:   policyMapValueOutput{RuleCookie: 7, Packets: 9},
				RuleRef: "prod/db/allow-db",
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := runPolicyEntriesExportWithStore(t.Context(), policyEntriesExportOptions{endpoint: "prod/pod-a"}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	var got policyEntriesExportOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-entries-export output: %v\n%s", err, stdout.String())
	}
	if !got.Ready || !got.LastReconcileSuccess || got.Node != "node-a" || got.Store != "ebpf" || got.FilterEndpoint != "prod/pod-a" {
		t.Fatalf("policy entries summary = %+v, want ready filtered node-a ebpf", got)
	}
	if got.TotalEndpoints != 2 || got.EndpointCount != 1 {
		t.Fatalf("policy entries counts = %+v, want total=2 endpoint_count=1", got)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].EndpointID != "prod\x00pod-a" || got.Endpoints[0].EntryCount != 1 || got.Endpoints[0].Entries[0].Value.RuleCookie != 42 {
		t.Fatalf("policy entries = %+v, want filtered pod-a entry", got.Endpoints)
	}
}

func TestRunPolicyEntriesExportWithStoreFiltersByRuleCookie(t *testing.T) {
	store := ovsdbPolicyEntriesStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	if err := store.Save(t.Context(), policyEntriesDocument{
		Node:                 "node-a",
		Store:                "ebpf",
		LastReconcileSuccess: true,
		Endpoints: []policyEntriesEndpointOutput{{
			EndpointID: "prod\x00pod-a",
			EntryCount: 2,
			Entries: []policyMapEntryOutput{{
				Key: policyMapKeyOutput{
					PrefixLen:      dataplane.StaticPrefixBits,
					RemoteIdentity: 10,
					Direction:      dataplane.DirectionIngress,
					Protocol:       6,
				},
				Value:   policyMapValueOutput{RuleCookie: 42, Packets: 5},
				RuleRef: "prod/web/allow-http",
			}, {
				Key: policyMapKeyOutput{
					PrefixLen:      dataplane.StaticPrefixBits,
					RemoteIdentity: 11,
					Direction:      dataplane.DirectionIngress,
					Protocol:       6,
				},
				Value:   policyMapValueOutput{RuleCookie: 7, Packets: 1},
				RuleRef: "prod/web/deny-ssh",
			}},
		}, {
			EndpointID: "prod\x00pod-b",
			EntryCount: 1,
			Entries: []policyMapEntryOutput{{
				Key:     policyMapKeyOutput{PrefixLen: dataplane.StaticPrefixBits, RemoteIdentity: 20, Direction: dataplane.DirectionEgress, Protocol: 17},
				Value:   policyMapValueOutput{RuleCookie: 7, Packets: 9},
				RuleRef: "prod/db/allow-db",
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := runPolicyEntriesExportWithStore(t.Context(), policyEntriesExportOptions{ruleCookie: "42"}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	var got policyEntriesExportOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-entries-export output: %v\n%s", err, stdout.String())
	}
	if got.FilterRuleCookie != 42 || got.TotalEndpoints != 2 || got.EndpointCount != 1 {
		t.Fatalf("policy entries summary = %+v, want one endpoint with cookie 42", got)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].EndpointID != "prod\x00pod-a" || got.Endpoints[0].EntryCount != 1 || got.Endpoints[0].Entries[0].Value.RuleCookie != 42 {
		t.Fatalf("policy entries = %+v, want only cookie 42 entry", got.Endpoints)
	}

	stdout.Reset()
	if err := runPolicyEntriesExportWithStore(t.Context(), policyEntriesExportOptions{ruleRef: "prod/db/allow-db"}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	got = policyEntriesExportOutput{}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode rule-ref filtered policy-entries-export output: %v\n%s", err, stdout.String())
	}
	if got.FilterRuleRef != "prod/db/allow-db" || got.TotalEndpoints != 2 || got.EndpointCount != 1 {
		t.Fatalf("policy entries summary = %+v, want one endpoint with rule ref", got)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].EndpointID != "prod\x00pod-b" || got.Endpoints[0].EntryCount != 1 || got.Endpoints[0].Entries[0].RuleRef != "prod/db/allow-db" {
		t.Fatalf("policy entries = %+v, want only prod/db/allow-db entry", got.Endpoints)
	}
}

func TestRunPolicyEntriesExportReadsRealOpenVSwitchOVSDB(t *testing.T) {
	endpoint, client, cleanup := newTestAgentVSwitchOVSDB(t)
	defer cleanup()
	raw, err := json.Marshal(policyEntriesDocument{
		Node:                 "node-a",
		Store:                "ebpf",
		LastReconcileSuccess: true,
		Endpoints: []policyEntriesEndpointOutput{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			EntryCount: 1,
			Entries: []policyMapEntryOutput{{
				Key:   policyMapKeyOutput{PrefixLen: dataplane.StaticPrefixBits, RemoteIdentity: 10, Direction: dataplane.DirectionIngress, Protocol: 6},
				Value: policyMapValueOutput{RuleCookie: 42},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	insertAgentVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{ExternalIDs: map[string]string{
		policyEntriesKey: string(raw),
	}})
	var stdout bytes.Buffer
	if err := runPolicyEntriesExport(t.Context(), []string{"-ovsdb", endpoint}, &stdout); err != nil {
		t.Fatal(err)
	}
	var got policyEntriesExportOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-entries-export output: %v\n%s", err, stdout.String())
	}
	if got.Node != "node-a" || got.Store != "ebpf" || got.EndpointCount != 1 || got.Endpoints[0].EndpointID != model.EndpointKey("prod", "pod-a") {
		t.Fatalf("policy entries = %+v, want persisted pod-a entries", got)
	}
}

func TestAgentMetricsPersistsPolicyEntriesToOpenVSwitchExternalID(t *testing.T) {
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")
	if err := store.ReplaceEndpoint(t.Context(), endpointID, []dataplane.PolicyMapEntry{{
		Key: dataplane.PolicyKey{
			PrefixLen:      dataplane.StaticPrefixBits,
			Direction:      dataplane.DirectionIngress,
			Protocol:       6,
			RemoteIdentity: 10,
		},
		Value: dataplane.PolicyEntry{RuleCookie: 42, Packets: 5},
	}}); err != nil {
		t.Fatal(err)
	}
	ovsdb := &fakeOpenVSwitchExternalIDStore{}
	metrics := newAgentMetrics(store)
	configurePolicyEntriesStore(metrics, ovsdbPolicyEntriesStore{syncer: ovsdb})

	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node:              "node-a",
		PolicyRuleCatalog: []agent.PolicyRuleCatalogEntry{{EndpointID: endpointID, RuleCookie: 42, RuleRef: "prod/web/allow-http", VPC: "prod", SecurityGroup: "web", RuleID: "allow-http"}},
	}, "ebpf", time.Millisecond)

	raw := ovsdb.values[policyEntriesKey]
	if raw == "" {
		t.Fatalf("missing %s external_id", policyEntriesKey)
	}
	var doc policyEntriesDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Node != "node-a" || doc.Store != "ebpf" || !doc.LastReconcileSuccess {
		t.Fatalf("policy entries doc = %+v, want successful node-a ebpf snapshot", doc)
	}
	if len(doc.Endpoints) != 1 || doc.Endpoints[0].EndpointID != endpointID || doc.Endpoints[0].EntryCount != 1 || doc.Endpoints[0].Entries[0].Value.RuleCookie != 42 {
		t.Fatalf("policy entries = %+v, want persisted pod-a entry", doc.Endpoints)
	}
	if doc.Endpoints[0].Entries[0].RuleRef != "prod/web/allow-http" || doc.Endpoints[0].Entries[0].SecurityGroup != "web" || doc.Endpoints[0].Entries[0].RuleID != "allow-http" {
		t.Fatalf("policy entries rule metadata = %+v, want persisted allow-http metadata", doc.Endpoints[0].Entries[0])
	}
}

func TestPolicyRulesAPIReportsCatalogAndCounters(t *testing.T) {
	metrics := newAgentMetrics()
	endpointID := model.EndpointKey("prod", "pod-a")
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyRuleStats: []dataplane.RuleMetrics{{
			EndpointID: endpointID,
			RuleCookie: 42,
			Packets:    5,
			Bytes:      640,
			Allowed:    3,
			Dropped:    2,
			DenyDrops:  2,
			Logged:     1,
		}},
		PolicyRuleCatalog: []agent.PolicyRuleCatalogEntry{
			{
				EndpointID:    endpointID,
				RuleCookie:    42,
				RuleRef:       "sg/web/allow-http",
				VPC:           "prod",
				SecurityGroup: "web",
				RuleID:        "allow-http",
			},
			{
				EndpointID:    endpointID,
				RuleCookie:    43,
				RuleRef:       "sg/web/allow-https",
				VPC:           "prod",
				SecurityGroup: "web",
				RuleID:        "allow-https",
			},
		},
	}, "ebpf", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/rules/prod/pod-a", nil)
	metrics.handlePolicyRules(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyRulesOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy rules response: %v\n%s", err, recorder.Body.String())
	}
	if !got.Ready || !got.LastReconcileSuccess || got.Node != "node-a" || got.Store != "ebpf" {
		t.Fatalf("policy rules summary = %+v, want ready node-a ebpf success", got)
	}
	if got.RuleCount != 2 || got.Packets != 5 || got.Bytes != 640 || got.Allowed != 3 || got.Dropped != 2 || got.DenyDrops != 2 || got.Logged != 1 {
		t.Fatalf("policy rules counters = %+v, want merged totals", got)
	}
	if len(got.Rules) != 2 {
		t.Fatalf("rules = %+v, want two entries", got.Rules)
	}
	if got.Rules[0].EndpointID != endpointID || got.Rules[0].RuleCookie != 42 || got.Rules[0].RuleRef != "sg/web/allow-http" || got.Rules[0].Packets != 5 {
		t.Fatalf("first rule = %+v, want catalog and counters for cookie 42", got.Rules[0])
	}
	if got.Rules[1].EndpointID != endpointID || got.Rules[1].RuleCookie != 43 || got.Rules[1].RuleRef != "sg/web/allow-https" || got.Rules[1].Packets != 0 {
		t.Fatalf("second rule = %+v, want catalog-only zero counter for cookie 43", got.Rules[1])
	}
}

func TestPolicyRulesAPIFiltersByRuleCookie(t *testing.T) {
	metrics := newAgentMetrics()
	endpointID := model.EndpointKey("prod", "pod-a")
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyRuleStats: []dataplane.RuleMetrics{{
			EndpointID: endpointID,
			RuleCookie: 42,
			Packets:    5,
			Bytes:      640,
			Allowed:    3,
		}},
		PolicyRuleCatalog: []agent.PolicyRuleCatalogEntry{{
			EndpointID:    endpointID,
			RuleCookie:    42,
			RuleRef:       "sg/web/allow-http",
			VPC:           "prod",
			SecurityGroup: "web",
			RuleID:        "allow-http",
		}, {
			EndpointID:    endpointID,
			RuleCookie:    43,
			RuleRef:       "sg/web/allow-https",
			VPC:           "prod",
			SecurityGroup: "web",
			RuleID:        "allow-https",
		}},
	}, "ebpf", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/rules?rule_cookie=42", nil)
	metrics.handlePolicyRules(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyRulesOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy rules response: %v\n%s", err, recorder.Body.String())
	}
	if got.FilterRuleCookie != 42 || got.RuleCount != 1 || got.Packets != 5 {
		t.Fatalf("policy rules summary = %+v, want cookie 42 counters", got)
	}
	if len(got.Rules) != 1 || got.Rules[0].RuleCookie != 42 || got.Rules[0].RuleRef != "sg/web/allow-http" {
		t.Fatalf("rules = %+v, want only cookie 42", got.Rules)
	}
}

func TestPolicyRulesAPIRejectsInvalidRuleCookie(t *testing.T) {
	metrics := newAgentMetrics()
	observeAgentReconcileResult(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/rules?rule_cookie=bad", nil)
	metrics.handlePolicyRules(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRunPolicyRulesWithStoreReportsFilteredJSON(t *testing.T) {
	store := ovsdbPolicyRulesStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	if err := store.Save(t.Context(), policyRulesDocument{
		Node:                 "node-a",
		Store:                "ebpf",
		LastReconcileSuccess: true,
		UpdatedAt:            time.Date(2026, 7, 17, 1, 2, 3, 0, time.UTC),
		Rules: []policyRuleOutput{{
			EndpointID: "prod\x00pod-a",
			RuleCookie: 42,
			RuleRef:    "sg/web/allow-http",
			Packets:    5,
			Bytes:      640,
			Allowed:    3,
			Dropped:    2,
			DenyDrops:  2,
		}, {
			EndpointID: "prod\x00pod-b",
			RuleCookie: 7,
			RuleRef:    "sg/db/allow-db",
			Packets:    9,
			Bytes:      900,
			Allowed:    9,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := runPolicyRulesWithStore(t.Context(), policyRulesOptions{endpoint: "prod/pod-a"}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	var got policyRulesOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-rules output: %v\n%s", err, stdout.String())
	}
	if !got.Ready || !got.LastReconcileSuccess || got.Node != "node-a" || got.Store != "ebpf" || got.FilterEndpoint != "prod/pod-a" {
		t.Fatalf("policy rules summary = %+v, want ready filtered node-a ebpf", got)
	}
	if got.RuleCount != 1 || got.Packets != 5 || got.Bytes != 640 || got.Allowed != 3 || got.Dropped != 2 || got.DenyDrops != 2 {
		t.Fatalf("policy rules counters = %+v, want pod-a totals", got)
	}
	if len(got.Rules) != 1 || got.Rules[0].RuleCookie != 42 || got.Rules[0].RuleRef != "sg/web/allow-http" {
		t.Fatalf("rules = %+v, want pod-a allow-http rule", got.Rules)
	}
}

func TestRunPolicyRulesWithStoreFiltersByRuleRef(t *testing.T) {
	store := ovsdbPolicyRulesStore{syncer: &fakeOpenVSwitchExternalIDStore{}}
	if err := store.Save(t.Context(), policyRulesDocument{
		Node:                 "node-a",
		Store:                "ebpf",
		LastReconcileSuccess: true,
		Rules: []policyRuleOutput{{
			EndpointID: "prod\x00pod-a",
			RuleCookie: 42,
			RuleRef:    "sg/web/allow-http",
			Packets:    5,
			Bytes:      640,
			Allowed:    3,
		}, {
			EndpointID: "prod\x00pod-a",
			RuleCookie: 43,
			RuleRef:    "sg/web/allow-https",
			Packets:    7,
			Bytes:      700,
			Allowed:    7,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := runPolicyRulesWithStore(t.Context(), policyRulesOptions{ruleRef: "sg/web/allow-https"}, &stdout, store); err != nil {
		t.Fatal(err)
	}
	var got policyRulesOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-rules output: %v\n%s", err, stdout.String())
	}
	if got.FilterRuleRef != "sg/web/allow-https" || got.RuleCount != 1 || got.Packets != 7 || got.Allowed != 7 {
		t.Fatalf("policy rules summary = %+v, want filtered allow-https rule", got)
	}
	if len(got.Rules) != 1 || got.Rules[0].RuleCookie != 43 || got.Rules[0].RuleRef != "sg/web/allow-https" {
		t.Fatalf("rules = %+v, want allow-https rule", got.Rules)
	}
}

func TestRunPolicyRulesReadsRealOpenVSwitchOVSDB(t *testing.T) {
	endpoint, client, cleanup := newTestAgentVSwitchOVSDB(t)
	defer cleanup()
	raw, err := json.Marshal(policyRulesDocument{
		Node:                 "node-a",
		Store:                "ebpf",
		LastReconcileSuccess: true,
		Rules: []policyRuleOutput{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			RuleCookie: 42,
			RuleRef:    "sg/web/allow-http",
			Packets:    5,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	insertAgentVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{ExternalIDs: map[string]string{
		policyRulesKey: string(raw),
	}})
	var stdout bytes.Buffer
	if err := runPolicyRules(t.Context(), []string{"-ovsdb", endpoint}, &stdout); err != nil {
		t.Fatal(err)
	}
	var got policyRulesOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode policy-rules output: %v\n%s", err, stdout.String())
	}
	if got.Node != "node-a" || got.Store != "ebpf" || got.RuleCount != 1 || got.Rules[0].EndpointID != model.EndpointKey("prod", "pod-a") {
		t.Fatalf("policy rules = %+v, want persisted pod-a rule", got)
	}
}

func TestAgentMetricsPersistsPolicyRulesToOpenVSwitchExternalID(t *testing.T) {
	ovsdb := &fakeOpenVSwitchExternalIDStore{}
	metrics := newAgentMetrics()
	configurePolicyRulesStore(metrics, ovsdbPolicyRulesStore{syncer: ovsdb})
	endpointID := model.EndpointKey("prod", "pod-a")

	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyRuleStats: []dataplane.RuleMetrics{{
			EndpointID: endpointID,
			RuleCookie: 42,
			Packets:    5,
			Bytes:      640,
			Allowed:    3,
		}},
		PolicyRuleCatalog: []agent.PolicyRuleCatalogEntry{{
			EndpointID:    endpointID,
			RuleCookie:    42,
			RuleRef:       "sg/web/allow-http",
			VPC:           "prod",
			SecurityGroup: "web",
			RuleID:        "allow-http",
		}},
	}, "ebpf", time.Millisecond)

	raw := ovsdb.values[policyRulesKey]
	if raw == "" {
		t.Fatalf("missing %s external_id", policyRulesKey)
	}
	var doc policyRulesDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Node != "node-a" || doc.Store != "ebpf" || !doc.LastReconcileSuccess {
		t.Fatalf("policy rules doc = %+v, want successful node-a ebpf snapshot", doc)
	}
	if len(doc.Rules) != 1 || doc.Rules[0].EndpointID != endpointID || doc.Rules[0].RuleRef != "sg/web/allow-http" || doc.Rules[0].Packets != 5 {
		t.Fatalf("policy rules = %+v, want persisted allow-http counters", doc.Rules)
	}
}

func TestPolicyExplainAPIUsesLatestReconciledState(t *testing.T) {
	metrics := newAgentMetrics()
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
				ID:     "pod-b",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.11"),
				Node:   "node-b",
				Labels: model.Labels{"role": "client"},
			},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:                     "allow-client-https",
				Priority:               100,
				Direction:              model.DirectionIngress,
				Protocol:               model.ProtocolTCP,
				RemoteEndpointSelector: model.Labels{"role": "client"},
				Ports:                  []model.PortRange{{From: 443, To: 443}},
				Action:                 model.ActionAllow,
			}},
		}},
	}
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond, state)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/explain?vpc=prod&endpoint=pod-a&remote_endpoint=pod-b&direction=ingress&protocol=tcp&dest_port=443", nil)
	metrics.handlePolicyExplain(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var explanation dataplane.PolicyExplanation
	if err := json.Unmarshal(recorder.Body.Bytes(), &explanation); err != nil {
		t.Fatalf("decode policy explain response: %v\n%s", err, recorder.Body.String())
	}
	if explanation.EndpointID != model.EndpointKey("prod", "pod-a") || explanation.Verdict != dataplane.VerdictAllow || explanation.Reason != dataplane.ExplainReasonPolicyAllow {
		t.Fatalf("explanation = %+v, want selector allow", explanation)
	}
	if !explanation.Matched || explanation.RuleCookie == 0 {
		t.Fatalf("explanation = %+v, want matched policy rule", explanation)
	}
	if explanation.MatchedRule == nil || explanation.MatchedRule.RuleRef != "prod/web/allow-client-https" {
		t.Fatalf("matched rule = %+v, want prod/web/allow-client-https", explanation.MatchedRule)
	}
}

func TestPolicyExplainAPIReturnsBadRequestForInvalidPacket(t *testing.T) {
	metrics := newAgentMetrics()
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond, control.DesiredState{})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/explain?vpc=prod&endpoint=pod-a&direction=ingress&remote_identity=bad", nil)
	metrics.handlePolicyExplain(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRouteExplainAPIReportsNotReady(t *testing.T) {
	metrics := newAgentMetrics()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/route/explain", nil)

	metrics.handleRouteExplain(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "not ready") {
		t.Fatalf("body missing not ready error: %s", recorder.Body.String())
	}
}

func TestRouteExplainAPIUsesLatestReconciledState(t *testing.T) {
	metrics := newAgentMetrics()
	state := control.DesiredState{
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "private-via-fw",
			VPC:      "prod",
			Priority: 100,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("172.16.0.0/16"),
				Protocol:    model.ProtocolTCP,
				DstPorts:    []model.PortRange{{From: 443, To: 443}},
			},
			Action: model.RouteAction{
				Type:     model.ActionReroute,
				NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")},
			},
		}},
	}
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond, state)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/route/explain?vpc=prod&source=10.10.0.10&dest=172.16.0.20&protocol=tcp&dest_port=443", nil)
	metrics.handleRouteExplain(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var decision topology.Decision
	if err := json.Unmarshal(recorder.Body.Bytes(), &decision); err != nil {
		t.Fatalf("decode route explain response: %v\n%s", err, recorder.Body.String())
	}
	if decision.Action != model.ActionReroute || decision.NextHop != netip.MustParseAddr("10.10.0.253") || decision.MatchedBy != "policy-route/private-via-fw" {
		t.Fatalf("decision = %+v, want policy-route reroute via firewall", decision)
	}
}

func TestRouteExplainAPIReturnsBadRequestForInvalidPacket(t *testing.T) {
	metrics := newAgentMetrics()
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond, control.DesiredState{})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/route/explain?vpc=prod&source=bad&dest=172.16.0.20", nil)
	metrics.handleRouteExplain(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPolicyEndpointAPIReportsLifecycleStatus(t *testing.T) {
	metrics := newAgentMetrics()
	endpointID := model.EndpointKey("prod", "pod-a")
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node:                      "node-a",
		PolicyMapEntries:          1,
		PolicyMapCapacity:         16,
		PolicyMapPressureMax:      6,
		PolicyMapPressureEndpoint: endpointID,
		PolicyRevisionMax:         3,
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID:      endpointID,
			Revision:        3,
			Entries:         1,
			Capacity:        16,
			PressurePercent: 6,
			LastStats:       dataplane.PolicyUpdateStats{Revision: 3, Added: 1},
			LastEvent: dataplane.PolicyUpdateEvent{
				EndpointID: endpointID,
				Revision:   3,
				Success:    true,
			},
			HasLastEvent: true,
		}},
	}, "ebpf", 25*time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/endpoints?endpoint=prod/pod-a", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyStatusOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint API response: %v\n%s", err, recorder.Body.String())
	}
	if !got.Ready || !got.LastReconcileSuccess || got.Node != "node-a" || got.Store != "ebpf" {
		t.Fatalf("policy endpoint API summary = %+v, want ready node-a ebpf success", got)
	}
	if got.EndpointCount != 1 || got.PolicyMapEntries != 1 || got.PolicyRevisionMax != 3 {
		t.Fatalf("policy endpoint API counters = %+v, want one revision 3 endpoint", got)
	}
	if len(got.Statuses) != 1 || got.Statuses[0].EndpointID != endpointID || got.Statuses[0].Revision != 3 {
		t.Fatalf("policy endpoint API statuses = %+v, want pod-a revision 3", got.Statuses)
	}
}

func TestPolicyEndpointAPIReportsReadyRevision(t *testing.T) {
	metrics := newAgentMetrics()
	endpointID := model.EndpointKey("prod", "pod-a")
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node:              "node-a",
		PolicyRevisionMax: 5,
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID:   endpointID,
			Revision:     5,
			Entries:      2,
			LastEvent:    dataplane.PolicyUpdateEvent{EndpointID: endpointID, Revision: 5, Success: true},
			HasLastEvent: true,
		}},
	}, "ebpf", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/endpoints/prod/pod-a/revision?target_revision=4", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyRevisionWaitOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint revision response: %v\n%s", err, recorder.Body.String())
	}
	if !got.Ready || got.Node != "node-a" || got.Store != "ebpf" || got.EndpointID != endpointID || got.TargetRevision != 4 || got.Revision != 5 {
		t.Fatalf("revision output = %+v, want ready pod-a revision 5 for target 4", got)
	}
	if got.Status.EndpointID != endpointID || got.Status.Revision != 5 || !got.Status.HasLastEvent {
		t.Fatalf("revision status = %+v, want persisted endpoint status", got.Status)
	}
}

func TestPolicyEndpointAPIReturnsConflictWhenRevisionIsNotReady(t *testing.T) {
	metrics := newAgentMetrics()
	endpointID := model.EndpointKey("prod", "pod-a")
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node:              "node-a",
		PolicyRevisionMax: 3,
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   3,
			Entries:    1,
		}},
	}, "ebpf", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/endpoints/prod/pod-a/revision?target_revision=4", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "did not reach target revision 4") {
		t.Fatalf("body = %s, want target revision error", recorder.Body.String())
	}
}

func TestPolicyEndpointAPIRevisionRequiresTargetRevision(t *testing.T) {
	metrics := newAgentMetrics()
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Revision:   1,
		}},
	}, "memory", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/endpoints/prod/pod-a/revision", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPolicyEndpointAPIReturnsNotFoundForUnknownEndpoint(t *testing.T) {
	metrics := newAgentMetrics()
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Revision:   1,
		}},
	}, "memory", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/endpoints?endpoint=prod/missing", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPolicyEndpointAPIDeletesEndpointPolicyMap(t *testing.T) {
	store := dataplane.NewInMemoryPolicyStore()
	endpointID := model.EndpointKey("prod", "pod-a")
	if err := store.ReplaceEndpoint(context.Background(), endpointID, []dataplane.PolicyMapEntry{{
		Key: dataplane.PolicyKey{
			PrefixLen:      dataplane.StaticPrefixBits,
			Direction:      dataplane.DirectionIngress,
			Protocol:       6,
			RemoteIdentity: 42,
		},
		Value: dataplane.PolicyEntry{},
	}}); err != nil {
		t.Fatal(err)
	}
	metrics := newAgentMetrics(store)
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
			Entries:    1,
		}},
	}, "memory", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/policy/endpoints/prod/pod-a", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint action response: %v\n%s", err, recorder.Body.String())
	}
	if !got.Deleted || got.Action != "delete" || got.EndpointID != endpointID {
		t.Fatalf("delete response = %+v, want endpoint delete", got)
	}
	statuses, err := store.PolicyEndpointStatuses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 0 {
		t.Fatalf("store statuses = %+v, want endpoint removed", statuses)
	}
	snapshot, _, ready := metrics.snapshotValue()
	if !ready || len(snapshot.Result.PolicyEndpointStatus) != 0 {
		t.Fatalf("snapshot statuses = %+v, want endpoint removed", snapshot.Result.PolicyEndpointStatus)
	}
}

func TestPolicyEndpointAPIDeleteRequiresActionStore(t *testing.T) {
	metrics := newAgentMetrics()
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Revision:   1,
		}},
	}, "memory", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/policy/endpoints/prod/pod-a", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPolicyEndpointAPIRegeneratesEndpointPolicyMap(t *testing.T) {
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
	if err := store.ReplaceEndpoint(context.Background(), endpointID, []dataplane.PolicyMapEntry{{
		Key: dataplane.PolicyKey{
			PrefixLen:      dataplane.StaticPrefixBits,
			RemoteIdentity: 42,
			Direction:      dataplane.DirectionIngress,
		},
		Value: dataplane.PolicyEntry{Deny: 1},
	}}); err != nil {
		t.Fatal(err)
	}
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
			Entries:    1,
		}},
	}, "memory", time.Millisecond, state)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/regenerate", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint action response: %v\n%s", err, recorder.Body.String())
	}
	if !got.Regenerated || got.Action != "regenerate" || got.EndpointID != endpointID || got.EndpointInfo.Revision != 2 {
		t.Fatalf("regenerate response = %+v, want endpoint regenerated at revision 2", got)
	}
	entries := store.Entries(endpointID)
	if len(entries) != 1 || entries[0].RemoteCIDR != netip.MustParsePrefix("172.30.0.0/24") || entries[0].Value.Deny != 0 {
		t.Fatalf("entries = %+v, want regenerated allow-http policy", entries)
	}
	snapshot, _, ready := metrics.snapshotValue()
	if !ready || len(snapshot.Result.PolicyEndpointStatus) != 1 || snapshot.Result.PolicyEndpointStatus[0].Revision != 2 {
		t.Fatalf("snapshot statuses = %+v, want regenerated revision", snapshot.Result.PolicyEndpointStatus)
	}
}

func TestPolicyEndpointAPIRegeneratesDesiredEndpointWithoutExistingStatus(t *testing.T) {
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
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
	}, "memory", time.Millisecond, state)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/regenerate", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint action response: %v\n%s", err, recorder.Body.String())
	}
	if !got.Regenerated || got.EndpointID != endpointID || got.EndpointInfo.Revision != 1 {
		t.Fatalf("regenerate response = %+v, want desired endpoint regenerated without prior status", got)
	}
	if entries := store.Entries(endpointID); len(entries) != 1 {
		t.Fatalf("entries = %+v, want regenerated desired policy", entries)
	}
}

func TestPolicyEndpointAPIRegenerateRequiresReadyDesiredState(t *testing.T) {
	endpointID := model.EndpointKey("prod", "pod-a")
	store := dataplane.NewInMemoryPolicyStore()
	metrics := newAgentMetrics(store)
	observeAgentReconcileFailure(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
		}},
	}, "memory", errors.New("broken desired state"), time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/regenerate", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPolicyEndpointAPIPlanRecordsFailureHistory(t *testing.T) {
	metrics := newAgentMetrics()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/plan", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", recorder.Code, recorder.Body.String())
	}
	history := metrics.policyActionHistory()
	if len(history) != 1 ||
		history[0].Action != "plan" ||
		history[0].EndpointID != "prod/pod-a" ||
		history[0].Success ||
		!strings.Contains(history[0].Error, "not enabled") {
		t.Fatalf("action history = %+v, want failed plan audit event", history)
	}
}

func TestPolicyEndpointAPIPlansDesiredEndpointPolicyMap(t *testing.T) {
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
	catalogResult, err := agent.ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err != nil {
		t.Fatal(err)
	}
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node:              "node-a",
		PolicyRuleCatalog: catalogResult.PolicyRuleCatalog,
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   beforeRevision,
			Entries:    1,
		}},
	}, "memory", time.Millisecond, state)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/plan", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint action response: %v\n%s", err, recorder.Body.String())
	}
	if !got.Planned || got.Action != "plan" || got.EndpointID != endpointID || !got.Plan.Changed {
		t.Fatalf("plan response = %+v, want changed dry-run plan", got)
	}
	if got.Plan.Stats.Added != 1 || got.Plan.Stats.Deleted != 1 || got.Plan.CurrentEntries != 1 || got.Plan.DesiredEntries != 1 {
		t.Fatalf("plan = %+v, want add/delete counts", got.Plan)
	}
	if got.Plan.Risk.BlockingChange || got.Plan.Risk.AddedDenyEntries != 0 || got.Plan.Risk.DeletedAllowEntries != 0 {
		t.Fatalf("plan risk = %+v, want no additional blocking risk for allow replacing deny", got.Plan.Risk)
	}
	if len(got.Plan.AddedEntries) != 1 || got.Plan.AddedEntries[0].RuleRef != "prod/web/allow-http" || got.Plan.AddedEntries[0].SecurityGroup != "web" || got.Plan.AddedEntries[0].RuleID != "allow-http" {
		t.Fatalf("added entries = %+v, want desired allow-http rule metadata", got.Plan.AddedEntries)
	}
	if len(got.Plan.DeletedEntries) != 1 || got.Plan.DeletedEntries[0].RemoteCIDR != "198.51.100.0/24" || got.Plan.DeletedEntries[0].Value.Deny != 1 {
		t.Fatalf("deleted entries = %+v, want old deny entry details", got.Plan.DeletedEntries)
	}
	if len(got.Plan.UpdatedEntries) != 0 || len(got.Plan.UnchangedEntries) != 0 {
		t.Fatalf("unexpected updated/unchanged entries in plan: updated=%+v unchanged=%+v", got.Plan.UpdatedEntries, got.Plan.UnchangedEntries)
	}
	if revision := store.Revision(endpointID); revision != beforeRevision {
		t.Fatalf("revision = %d, want unchanged %d", revision, beforeRevision)
	}
	if entries := store.Entries(endpointID); len(entries) != 1 || entries[0].RemoteCIDR != oldEntries[0].RemoteCIDR || entries[0].Value.Deny != 1 {
		t.Fatalf("entries = %+v, want old entries preserved", entries)
	}
	history := metrics.policyActionHistory()
	if len(history) != 1 ||
		history[0].Action != "plan" ||
		history[0].EndpointID != endpointID ||
		!history[0].Success ||
		history[0].Revision != got.Plan.Stats.Revision ||
		history[0].Entries != uint32(got.Plan.DesiredEntries) {
		t.Fatalf("action history = %+v, want successful plan audit event", history)
	}
}

func TestPolicyEndpointAPIFreezesAndUnfreezesEndpointPolicyMap(t *testing.T) {
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
	if _, err := agent.RegeneratePolicyEndpoint(context.Background(), state, agent.ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, endpointID); err != nil {
		t.Fatal(err)
	}
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
			Entries:    1,
		}},
	}, "memory", time.Millisecond, state)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/freeze", nil)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("freeze status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var freeze policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &freeze); err != nil {
		t.Fatalf("decode freeze response: %v\n%s", err, recorder.Body.String())
	}
	if !freeze.Frozen || freeze.EndpointID != endpointID {
		t.Fatalf("freeze response = %+v, want frozen endpoint", freeze)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/policy/endpoints", nil)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var status policyStatusOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode policy status response: %v\n%s", err, recorder.Body.String())
	}
	if !reflect.DeepEqual(status.FrozenEndpoints, []string{endpointID}) {
		t.Fatalf("frozen endpoints = %+v, want %s", status.FrozenEndpoints, endpointID)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/regenerate", nil)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("regenerate status = %d, want 409; body=%s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/plan", nil)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("plan status = %d, want 409; body=%s", recorder.Code, recorder.Body.String())
	}
	history := metrics.policyActionHistory()
	if len(history) < 3 ||
		history[len(history)-1].Action != "plan" ||
		history[len(history)-1].EndpointID != endpointID ||
		history[len(history)-1].Success ||
		!strings.Contains(history[len(history)-1].Error, "frozen") {
		t.Fatalf("action history = %+v, want failed frozen plan audit event", history)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/unfreeze", nil)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unfreeze status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var unfreeze policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &unfreeze); err != nil {
		t.Fatalf("decode unfreeze response: %v\n%s", err, recorder.Body.String())
	}
	if !unfreeze.Unfrozen || unfreeze.EndpointID != endpointID {
		t.Fatalf("unfreeze response = %+v, want unfrozen endpoint", unfreeze)
	}
}

func TestPolicyEndpointAPIPersistsFreezeStateToOpenVSwitchExternalID(t *testing.T) {
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
	ovsdb := &fakeOpenVSwitchExternalIDStore{}
	metrics := newAgentMetrics(store)
	if err := configurePolicyFreezeState(t.Context(), metrics, ovsdbPolicyFreezeStateStore{syncer: ovsdb}); err != nil {
		t.Fatal(err)
	}
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
			Entries:    1,
		}},
	}, "memory", time.Millisecond, state)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/freeze", bytes.NewBufferString(`{"ttl_seconds":3600}`))
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("freeze status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var freeze policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &freeze); err != nil {
		t.Fatalf("decode freeze response: %v\n%s", err, recorder.Body.String())
	}
	if freeze.ExpiresAt == nil || freeze.ExpiresAt.IsZero() {
		t.Fatalf("freeze response = %+v, want expires_at", freeze)
	}
	var frozen policyFreezeStateDocument
	if err := json.Unmarshal([]byte(ovsdb.values[policyFreezeStateKey]), &frozen); err != nil {
		t.Fatalf("decode freeze state: %v", err)
	}
	if len(frozen.FrozenEndpoints) != 1 || frozen.FrozenEndpoints[0].EndpointID != endpointID || frozen.FrozenEndpoints[0].ExpiresAt.IsZero() || frozen.UpdatedAt.IsZero() {
		t.Fatalf("freeze state = %+v, want persisted endpoint and updated_at", frozen)
	}

	reloaded := newAgentMetrics(store)
	if err := configurePolicyFreezeState(t.Context(), reloaded, ovsdbPolicyFreezeStateStore{syncer: ovsdb}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reloaded.frozenPolicyEndpointIDs(), []string{endpointID}) {
		t.Fatalf("reloaded frozen endpoints = %+v, want %s", reloaded.frozenPolicyEndpointIDs(), endpointID)
	}

	observeAgentReconcileResultWithState(reloaded, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
			Entries:    1,
		}},
	}, "memory", time.Millisecond, state)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/unfreeze", nil)
	reloaded.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unfreeze status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var unfrozen policyFreezeStateDocument
	if err := json.Unmarshal([]byte(ovsdb.values[policyFreezeStateKey]), &unfrozen); err != nil {
		t.Fatalf("decode unfreeze state: %v", err)
	}
	if len(unfrozen.FrozenEndpoints) != 0 || unfrozen.UpdatedAt.IsZero() {
		t.Fatalf("freeze state after unfreeze = %+v, want empty persisted endpoint list", unfrozen)
	}
}

func TestPolicyEndpointAPIPersistsActionHistoryToOpenVSwitchExternalID(t *testing.T) {
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
	historyOVSDB := &fakeOpenVSwitchExternalIDStore{}
	freezeOVSDB := &fakeOpenVSwitchExternalIDStore{}
	metrics := newAgentMetrics(store)
	if err := configurePolicyActionHistory(t.Context(), metrics, ovsdbPolicyActionHistoryStore{syncer: historyOVSDB}); err != nil {
		t.Fatal(err)
	}
	if err := configurePolicyFreezeState(t.Context(), metrics, ovsdbPolicyFreezeStateStore{syncer: freezeOVSDB}); err != nil {
		t.Fatal(err)
	}
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
			Entries:    1,
		}},
	}, "memory", time.Millisecond, state)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/freeze", bytes.NewBufferString(`{"ttl_seconds":3600}`))
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("freeze status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/unfreeze", nil)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unfreeze status = %d, body=%s", recorder.Code, recorder.Body.String())
	}

	raw := historyOVSDB.values[policyActionHistoryKey]
	var persisted []policyActionHistoryEntry
	if err := json.Unmarshal([]byte(raw), &persisted); err != nil {
		t.Fatalf("decode persisted action history: %v", err)
	}
	if len(persisted) != 2 {
		t.Fatalf("persisted action history entries = %d, want 2: %s", len(persisted), raw)
	}
	if persisted[0].Action != "freeze" || persisted[0].EndpointID != endpointID || persisted[0].Node != "node-a" || persisted[0].Store != "memory" || persisted[0].ExpiresAt.IsZero() || !persisted[0].Success {
		t.Fatalf("persisted freeze action = %+v, want audited freeze", persisted[0])
	}
	if persisted[1].Action != "unfreeze" || persisted[1].EndpointID != endpointID || persisted[1].Node != "node-a" || persisted[1].Store != "memory" || !persisted[1].Success {
		t.Fatalf("persisted unfreeze action = %+v, want audited unfreeze", persisted[1])
	}

	reloaded := newAgentMetrics(store)
	if err := configurePolicyActionHistory(t.Context(), reloaded, ovsdbPolicyActionHistoryStore{syncer: historyOVSDB}); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/policy/endpoints/actions/history", nil)
	reloaded.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("history status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var output policyActionHistoryOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &output); err != nil {
		t.Fatalf("decode action history response: %v\n%s", err, recorder.Body.String())
	}
	if !output.Ready || len(output.History) != 2 || output.History[0].Action != "freeze" || output.History[1].Action != "unfreeze" {
		t.Fatalf("action history output = %+v, want reloaded freeze/unfreeze actions", output)
	}
}

func TestPolicyEndpointActionHistoryAPIFiltersEndpointActionAndLimit(t *testing.T) {
	history := []policyActionHistoryEntry{
		{ID: "1", Action: "freeze", EndpointID: model.EndpointKey("prod", "pod-a"), Node: "node-a", Store: "memory", CompletedAt: time.Now().Add(-3 * time.Minute), Success: true},
		{ID: "2", Action: "unfreeze", EndpointID: model.EndpointKey("prod", "pod-a"), Node: "node-a", Store: "memory", CompletedAt: time.Now().Add(-2 * time.Minute), Success: true},
		{ID: "3", Action: "freeze", EndpointID: model.EndpointKey("prod", "pod-b"), Node: "node-a", Store: "memory", CompletedAt: time.Now().Add(-time.Minute), Success: false, Error: "policy endpoint is frozen"},
	}
	raw, err := json.Marshal(history)
	if err != nil {
		t.Fatal(err)
	}
	metrics := newAgentMetrics(dataplane.NewInMemoryPolicyStore())
	if err := configurePolicyActionHistory(t.Context(), metrics, ovsdbPolicyActionHistoryStore{syncer: &fakeOpenVSwitchExternalIDStore{values: map[string]string{
		policyActionHistoryKey: string(raw),
	}}}); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/policy/endpoints/actions/history?endpoint=prod/pod-a&action=freeze&success=true&limit=1", nil)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("history status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var output policyActionHistoryOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &output); err != nil {
		t.Fatalf("decode action history response: %v\n%s", err, recorder.Body.String())
	}
	if !output.Ready || output.TotalEvents != 3 || output.EventCount != 1 || output.Limit != 1 || output.FilterEndpoint != "prod/pod-a" || output.FilterAction != "freeze" || output.FilterSuccess == nil || !*output.FilterSuccess {
		t.Fatalf("action history metadata = %+v, want filtered endpoint/action/limit", output)
	}
	if len(output.History) != 1 || output.History[0].ID != "1" || output.History[0].EndpointID != model.EndpointKey("prod", "pod-a") || output.History[0].Action != "freeze" || !output.History[0].Success {
		t.Fatalf("action history = %+v, want only prod/pod-a freeze", output.History)
	}
}

func TestPolicyEndpointActionHistoryRecordsFailedAction(t *testing.T) {
	endpointID := model.EndpointKey("prod", "pod-a")
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
	historyOVSDB := &fakeOpenVSwitchExternalIDStore{}
	freezeOVSDB := &fakeOpenVSwitchExternalIDStore{}
	metrics := newAgentMetrics(store)
	if err := configurePolicyActionHistory(t.Context(), metrics, ovsdbPolicyActionHistoryStore{syncer: historyOVSDB}); err != nil {
		t.Fatal(err)
	}
	if err := configurePolicyFreezeState(t.Context(), metrics, ovsdbPolicyFreezeStateStore{syncer: freezeOVSDB}); err != nil {
		t.Fatal(err)
	}
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
			Entries:    1,
		}},
	}, "memory", time.Millisecond, state)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/freeze", nil)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("freeze status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/regenerate", nil)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("regenerate status = %d, body=%s", recorder.Code, recorder.Body.String())
	}

	raw := historyOVSDB.values[policyActionHistoryKey]
	var persisted []policyActionHistoryEntry
	if err := json.Unmarshal([]byte(raw), &persisted); err != nil {
		t.Fatalf("decode persisted action history: %v", err)
	}
	if len(persisted) != 2 {
		t.Fatalf("persisted action history entries = %d, want 2: %s", len(persisted), raw)
	}
	if persisted[0].Action != "freeze" || persisted[0].EndpointID != endpointID || !persisted[0].Success {
		t.Fatalf("persisted freeze action = %+v, want successful freeze", persisted[0])
	}
	if persisted[1].Action != "regenerate" || persisted[1].EndpointID != endpointID || persisted[1].Success || !strings.Contains(persisted[1].Error, "frozen") {
		t.Fatalf("persisted regenerate action = %+v, want failed frozen regenerate", persisted[1])
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/policy/endpoints/actions/history?action=regenerate&success=false", nil)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("history status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var output policyActionHistoryOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &output); err != nil {
		t.Fatalf("decode action history response: %v\n%s", err, recorder.Body.String())
	}
	if output.FilterSuccess == nil || *output.FilterSuccess || output.EventCount != 1 || len(output.History) != 1 || output.History[0].Success {
		t.Fatalf("action history output = %+v, want failed regenerate only", output)
	}
}

func TestPolicyEndpointAPIDropsExpiredFreezeStateFromOpenVSwitchExternalID(t *testing.T) {
	endpointID := model.EndpointKey("prod", "pod-a")
	raw, err := json.Marshal(policyFreezeStateDocument{
		FrozenEndpoints: []policyFreezeStateEntry{{
			EndpointID: endpointID,
			ExpiresAt:  time.Now().Add(-time.Minute),
		}},
		UpdatedAt: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	ovsdb := &fakeOpenVSwitchExternalIDStore{values: map[string]string{
		policyFreezeStateKey: string(raw),
	}}
	metrics := newAgentMetrics(dataplane.NewInMemoryPolicyStore())
	if err := configurePolicyFreezeState(t.Context(), metrics, ovsdbPolicyFreezeStateStore{syncer: ovsdb}); err != nil {
		t.Fatal(err)
	}
	if got := metrics.frozenPolicyEndpointIDs(); len(got) != 0 {
		t.Fatalf("frozen endpoints = %+v, want expired entry dropped", got)
	}
	if metrics.policyEndpointFrozen(endpointID) {
		t.Fatalf("endpoint %s is frozen, want expired freeze ignored", endpointID)
	}
}

func TestPolicyEndpointAPIQuarantinesEndpointPolicyMap(t *testing.T) {
	endpointID := model.EndpointKey("prod", "pod-a")
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
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
			Entries:    1,
		}},
	}, "memory", time.Millisecond, state)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/quarantine", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint action response: %v\n%s", err, recorder.Body.String())
	}
	if !got.Quarantined || got.Action != "quarantine" || got.EndpointID != endpointID || got.EndpointInfo.Revision != 1 || got.EndpointInfo.Entries != 2 {
		t.Fatalf("quarantine response = %+v, want endpoint quarantined", got)
	}
	entries := store.Entries(endpointID)
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want quarantine entries", entries)
	}
	decision := dataplane.Evaluate(entries, dataplane.Packet{
		RemoteIdentity: 99,
		RemoteIP:       netip.MustParseAddr("203.0.113.10"),
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	})
	if decision.Verdict != dataplane.VerdictDrop || decision.Match == nil || decision.Match.Value.Deny == 0 {
		t.Fatalf("decision = %+v, want quarantine drop", decision)
	}
	snapshot, _, ready := metrics.snapshotValue()
	if !ready || len(snapshot.Result.PolicyEndpointStatus) != 1 || snapshot.Result.PolicyEndpointStatus[0].Entries != 2 {
		t.Fatalf("snapshot statuses = %+v, want quarantine status", snapshot.Result.PolicyEndpointStatus)
	}
}

func TestPolicyEndpointAPIUnquarantinesEndpointPolicyMap(t *testing.T) {
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
	if _, err := agent.QuarantinePolicyEndpoint(context.Background(), state, agent.ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, endpointID); err != nil {
		t.Fatal(err)
	}
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
			Entries:    2,
		}},
	}, "memory", time.Millisecond, state)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/unquarantine", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint action response: %v\n%s", err, recorder.Body.String())
	}
	if !got.Unquarantined || got.Action != "unquarantine" || got.EndpointID != endpointID || got.EndpointInfo.Revision != 2 || got.EndpointInfo.Entries != 1 {
		t.Fatalf("unquarantine response = %+v, want endpoint restored", got)
	}
	entries := store.Entries(endpointID)
	if len(entries) != 1 || entries[0].RemoteCIDR != netip.MustParsePrefix("172.30.0.0/24") || entries[0].Value.Deny != 0 {
		t.Fatalf("entries = %+v, want restored desired policy", entries)
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
	snapshot, _, ready := metrics.snapshotValue()
	if !ready || len(snapshot.Result.PolicyEndpointStatus) != 1 || snapshot.Result.PolicyEndpointStatus[0].Revision != 2 || snapshot.Result.PolicyEndpointStatus[0].Entries != 1 {
		t.Fatalf("snapshot statuses = %+v, want unquarantine status", snapshot.Result.PolicyEndpointStatus)
	}
}

func TestPolicyEndpointAPIRollsBackEndpointPolicyMap(t *testing.T) {
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
	if _, err := agent.QuarantinePolicyEndpoint(context.Background(), state, agent.ReconcileOptions{
		Node:  "node-a",
		Store: store,
	}, endpointID); err != nil {
		t.Fatal(err)
	}
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID: endpointID,
			Revision:   1,
			Entries:    2,
		}},
	}, "memory", time.Millisecond, state)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a/rollback", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint action response: %v\n%s", err, recorder.Body.String())
	}
	if !got.RolledBack || got.Action != "rollback" || got.EndpointID != endpointID || got.EndpointInfo.Revision != 2 || got.EndpointInfo.Entries != 1 {
		t.Fatalf("rollback response = %+v, want endpoint restored", got)
	}
	entries := store.Entries(endpointID)
	if len(entries) != 1 || entries[0].RemoteCIDR != netip.MustParsePrefix("172.30.0.0/24") || entries[0].Value.Deny != 0 {
		t.Fatalf("entries = %+v, want rolled back desired policy", entries)
	}
	snapshot, _, ready := metrics.snapshotValue()
	if !ready || len(snapshot.Result.PolicyEndpointStatus) != 1 || snapshot.Result.PolicyEndpointStatus[0].Revision != 2 || snapshot.Result.PolicyEndpointStatus[0].Entries != 1 {
		t.Fatalf("snapshot statuses = %+v, want rollback status", snapshot.Result.PolicyEndpointStatus)
	}
}

func TestPolicyEndpointAPIRolloutAppliesMultipleEndpoints(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
			{ID: "pod-b", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.11"), Node: "node-a", SecurityGroups: []string{"web"}},
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
	store := dataplane.NewInMemoryPolicyStore()
	catalogResult, err := agent.ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err != nil {
		t.Fatal(err)
	}
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node:              "node-a",
		PolicyRuleCatalog: catalogResult.PolicyRuleCatalog,
	}, "memory", time.Millisecond, state)

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a","prod/pod-b"],"batch_size":1}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint rollout response: %v\n%s", err, recorder.Body.String())
	}
	if !got.RolledOut || got.Action != "rollout" || got.Rollout.Planned != 2 || got.Rollout.Applied != 2 || got.Rollout.Failed != 0 {
		t.Fatalf("rollout response = %+v, want two applied endpoints", got)
	}
	if len(got.Rollout.Items) != 2 || got.Rollout.Items[0].Batch != 1 || got.Rollout.Items[1].Batch != 2 {
		t.Fatalf("rollout items = %+v, want two staged batches", got.Rollout.Items)
	}
	if len(got.Rollout.Items[0].Plan.AddedEntries) != 1 || got.Rollout.Items[0].Plan.AddedEntries[0].RuleRef != "prod/web/allow-http" || got.Rollout.Items[0].Plan.AddedEntries[0].SecurityGroup != "web" {
		t.Fatalf("first rollout item plan endpoint=%q entries=%+v, want allow-http rule metadata", got.Rollout.Items[0].Plan.EndpointID, got.Rollout.Items[0].Plan.AddedEntries)
	}
	if got.Rollout.Risk.BlockingChange {
		t.Fatalf("rollout risk = %+v, want non-blocking allow rollout", got.Rollout.Risk)
	}
	if got.Rollout.Items[0].Plan.Risk.BlockingChange {
		t.Fatalf("first rollout item risk = %+v, want non-blocking allow rollout", got.Rollout.Items[0].Plan.Risk)
	}
	for _, endpointID := range []string{model.EndpointKey("prod", "pod-a"), model.EndpointKey("prod", "pod-b")} {
		if entries := store.Entries(endpointID); len(entries) != 1 {
			t.Fatalf("entries for %s = %+v, want rolled out policy", endpointID, entries)
		}
	}
	snapshot, _, ready := metrics.snapshotValue()
	if !ready || len(snapshot.Result.PolicyEndpointStatus) != 2 {
		t.Fatalf("snapshot statuses = %+v, want two rolled out endpoints", snapshot.Result.PolicyEndpointStatus)
	}
}

func TestPolicyEndpointAPIRolloutPausesBlockingRiskUntilAcknowledged(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
		},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:         "reject-http",
				Priority:   100,
				Direction:  model.DirectionIngress,
				Protocol:   model.ProtocolTCP,
				RemoteCIDR: netip.MustParsePrefix("172.30.0.0/24"),
				Ports:      []model.PortRange{{From: 80, To: 80}},
				Action:     model.ActionReject,
			}},
		}},
	}
	store := dataplane.NewInMemoryPolicyStore()
	catalogResult, err := agent.ReconcileNode(context.Background(), state, "node-a", dataplane.NewInMemoryPolicyStore())
	if err != nil {
		t.Fatal(err)
	}
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node:              "node-a",
		PolicyRuleCatalog: catalogResult.PolicyRuleCatalog,
	}, "memory", time.Millisecond, state)

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"batch_size":1,"risk_ack_required":true,"risk_ack_ref":"risk-1234"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint rollout response: %v\n%s", err, recorder.Body.String())
	}
	if got.RolledOut || !got.Rollout.RiskAckRequired || !got.Rollout.RiskAckPending || !got.Rollout.Paused || !got.Rollout.Risk.BlockingChange || got.Rollout.Applied != 0 || got.Rollout.Skipped != 1 {
		t.Fatalf("rollout response = %+v, want risk-ack paused blocking rollout", got)
	}
	if got.Rollout.Items[0].Reason != "risk_ack_pending" {
		t.Fatalf("rollout items = %+v, want risk_ack_pending reason", got.Rollout.Items)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation before risk ack", entries)
	}

	body = bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"batch_size":1,"risk_ack_required":true,"risk_acknowledged":true,"risk_ack_ref":"risk-1234"}`)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("acknowledged status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	got = policyEndpointActionOutput{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode acknowledged rollout response: %v\n%s", err, recorder.Body.String())
	}
	if !got.RolledOut || got.Rollout.RiskAckPending || !got.Rollout.RiskAcknowledged || got.Rollout.Applied != 1 {
		t.Fatalf("acknowledged rollout response = %+v, want risk-acknowledged apply", got)
	}
	entries := store.Entries(model.EndpointKey("prod", "pod-a"))
	if len(entries) != 1 || entries[0].Value.Reject == 0 {
		t.Fatalf("pod-a entries = %+v, want reject policy after risk ack", entries)
	}
}

func TestPolicyEndpointAPIRolloutPersistsHistory(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
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
	store := dataplane.NewInMemoryPolicyStore()
	historyOVSDB := &fakeOpenVSwitchExternalIDStore{}
	historyStore := ovsdbPolicyRolloutHistoryStore{syncer: historyOVSDB}
	metrics := newAgentMetrics(store)
	if err := configurePolicyRolloutHistory(t.Context(), metrics, historyStore); err != nil {
		t.Fatal(err)
	}
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
	}, "memory", time.Millisecond, state)

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"batch_size":1}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}

	raw := historyOVSDB.values[policyRolloutHistoryKey]
	var persisted policyRolloutHistoryEntry
	var persistedHistory []policyRolloutHistoryEntry
	if err := json.Unmarshal([]byte(raw), &persistedHistory); err != nil {
		t.Fatalf("decode persisted history: %v", err)
	}
	if len(persistedHistory) != 1 {
		t.Fatalf("persisted history entries = %d, want 1: %s", len(persistedHistory), raw)
	}
	persisted = persistedHistory[0]
	if persisted.Source != "manual" || persisted.Node != "node-a" || persisted.Store != "memory" || persisted.Rollout.Applied != 1 || persisted.Rollout.Planned != 1 {
		t.Fatalf("persisted history = %+v, want manual applied rollout", persisted)
	}

	reloaded := newAgentMetrics(store)
	if err := configurePolicyRolloutHistory(t.Context(), reloaded, historyStore); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/policy/endpoints/rollout/history", nil)
	reloaded.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("history status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var output policyRolloutHistoryOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &output); err != nil {
		t.Fatalf("decode history response: %v\n%s", err, recorder.Body.String())
	}
	if !output.Ready || len(output.History) != 1 || output.History[0].Rollout.Applied != 1 {
		t.Fatalf("history output = %+v, want reloaded rollout", output)
	}
}

func TestPolicyEndpointAPIRolloutHonorsSLOGate(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
			{ID: "pod-b", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.11"), Node: "node-a", SecurityGroups: []string{"web"}},
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
	store := &policyRolloutUsageStore{
		InMemoryPolicyStore: dataplane.NewInMemoryPolicyStore(),
		metrics: []dataplane.RuleMetrics{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Packets:    100,
			Dropped:    40,
		}},
	}
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
	}, "memory", time.Millisecond, state)

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a","prod/pod-b"],"batch_size":1,"slo_gated":true,"slo_drop_threshold_percent":10,"slo_min_packets":10,"slo_window_count":1,"slo_window_interval_ms":250}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint rollout response: %v\n%s", err, recorder.Body.String())
	}
	if got.RolledOut || !got.Rollout.SLOFailed || got.Rollout.SLODropPercent != 40 || got.Rollout.RolledBack != 1 || got.Rollout.Skipped != 1 {
		t.Fatalf("rollout response = %+v, want SLO failure rollback", got)
	}
	if got.Rollout.SLOWindowCount != 1 || got.Rollout.SLOWindowIntervalMS != 250 {
		t.Fatalf("rollout SLO window settings = %+v, want request settings", got.Rollout)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want SLO rollback", entries)
	}
}

func TestPolicyEndpointAPIRolloutRunsProbe(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}))
	defer server.Close()
	store := dataplane.NewInMemoryPolicyStore()
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
	}, "memory", time.Millisecond, state)

	body := bytes.NewBufferString(fmt.Sprintf(`{"endpoints":["prod/pod-a"],"batch_size":1,"probes":[{"name":"web-ready","type":"http","url":%q,"expected_status":200,"expected_body_contains":"ready","timeout_ms":1000}]}`, server.URL))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint rollout response: %v\n%s", err, recorder.Body.String())
	}
	if !got.RolledOut || got.Rollout.ProbeFailed || got.Rollout.Failed != 0 || got.Rollout.Applied != 1 {
		t.Fatalf("rollout response = %+v, want successful probed rollout", got)
	}
	if len(got.Rollout.Probes) != 1 || !got.Rollout.Probes[0].Passed || got.Rollout.Probes[0].StatusCode != http.StatusOK {
		t.Fatalf("probe results = %+v, want passed HTTP probe", got.Rollout.Probes)
	}
}

func TestPolicyEndpointAPIRolloutPausesAfterBatch(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
			{ID: "pod-b", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.11"), Node: "node-a", SecurityGroups: []string{"web"}},
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
	store := dataplane.NewInMemoryPolicyStore()
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
	}, "memory", time.Millisecond, state)

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a","prod/pod-b"],"batch_size":1,"pause_after_batches":1}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint rollout response: %v\n%s", err, recorder.Body.String())
	}
	if got.RolledOut || !got.Rollout.Paused || got.Rollout.PausedAfterBatch != 1 || got.Rollout.Applied != 1 || got.Rollout.Skipped != 1 {
		t.Fatalf("rollout response = %+v, want paused rollout after first batch", got)
	}
}

func TestPolicyEndpointAPIRolloutWaitsForFinalize(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
			{ID: "pod-b", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.11"), Node: "node-a", SecurityGroups: []string{"web"}},
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
	store := dataplane.NewInMemoryPolicyStore()
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
	}, "memory", time.Millisecond, state)

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a","prod/pod-b"],"batch_size":1,"finalize_required":true,"finalize_ref":"final-1234"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint rollout response: %v\n%s", err, recorder.Body.String())
	}
	if got.RolledOut || !got.Rollout.Paused || !got.Rollout.FinalizeRequired || !got.Rollout.FinalizePending || got.Rollout.FinalizeRef != "final-1234" || got.Rollout.Applied != 1 || got.Rollout.Skipped != 1 {
		t.Fatalf("rollout response = %+v, want finalize-pending rollout after canary", got)
	}
	if got.Rollout.Items[1].Reason != "finalize_pending" {
		t.Fatalf("rollout items = %+v, want finalize_pending remaining endpoint", got.Rollout.Items)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-b")); len(entries) != 0 {
		t.Fatalf("pod-b entries = %+v, want no mutation before finalize", entries)
	}
}

func TestPolicyEndpointAPIRolloutRequiresApproval(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
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
	store := dataplane.NewInMemoryPolicyStore()
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
	}, "memory", time.Millisecond, state)

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"batch_size":1,"approval_required":true,"approval_ref":"chg-5678"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint rollout response: %v\n%s", err, recorder.Body.String())
	}
	if got.RolledOut || !got.Rollout.ApprovalRequired || !got.Rollout.ApprovalPending || !got.Rollout.Paused || got.Rollout.ApprovalRef != "chg-5678" || got.Rollout.Applied != 0 || got.Rollout.Skipped != 1 {
		t.Fatalf("rollout response = %+v, want approval-gated paused rollout", got)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation before approval", entries)
	}

	body = bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"batch_size":1,"approval_required":true,"approved":true,"approval_ref":"chg-5678"}`)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("approved status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	got = policyEndpointActionOutput{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode approved rollout response: %v\n%s", err, recorder.Body.String())
	}
	if !got.RolledOut || !got.Rollout.Approved || got.Rollout.ApprovalPending || got.Rollout.ApprovalRef != "chg-5678" || got.Rollout.Applied != 1 {
		t.Fatalf("approved rollout response = %+v, want applied approval-gated rollout", got)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 1 {
		t.Fatalf("pod-a entries = %+v, want applied after approval", entries)
	}
}

func TestPolicyEndpointAPIRolloutRejectsExpiredApproval(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
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
	store := dataplane.NewInMemoryPolicyStore()
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond, state)

	expired := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"batch_size":1,"approval_required":true,"approved":true,"approval_ref":"chg-5678","approval_expires_at":"` + expired + `"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode expired approval rollout response: %v\n%s", err, recorder.Body.String())
	}
	if got.RolledOut || !got.Rollout.ApprovalExpired || !got.Rollout.Paused || got.Rollout.Applied != 0 || got.Rollout.Skipped != 1 || got.Rollout.Items[0].Reason != "approval_expired" {
		t.Fatalf("rollout response = %+v, want expired approval pause", got)
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation after expired approval", entries)
	}
}

func TestPolicyEndpointAPIRolloutVerifiesApprovalSignature(t *testing.T) {
	t.Setenv("NETLOOM_POLICY_ROLLOUT_APPROVAL_SECRET", "secret")
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
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond, state)

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"batch_size":1,"approval_required":true,"approved":true,"approval_ref":"chg-9012"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "approval signature is required") {
		t.Fatalf("missing signature status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if entries := store.Entries(model.EndpointKey("prod", "pod-a")); len(entries) != 0 {
		t.Fatalf("pod-a entries = %+v, want no mutation with missing signature", entries)
	}

	signature := agent.PolicyRolloutApprovalSignature("secret", "chg-9012", []string{model.EndpointKey("prod", "pod-a")})
	body = bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"batch_size":1,"approval_required":true,"approved":true,"approval_ref":"chg-9012","approval_signature":"` + signature + `"}`)
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("signed approval status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode signed approval response: %v\n%s", err, recorder.Body.String())
	}
	if !got.RolledOut || !got.Rollout.ApprovalSignatureVerified || got.Rollout.Applied != 1 {
		t.Fatalf("signed rollout response = %+v, want verified applied rollout", got)
	}
}

func TestPolicyEndpointAPIRolloutChecksApprovalCallback(t *testing.T) {
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
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond, state)

	callbackRequests := 0
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
		if request.ApprovalRef != "chg-3456" || request.Revision != "manual-callback-rev-1" || !reflect.DeepEqual(request.Endpoints, []string{model.EndpointKey("prod", "pod-a")}) {
			t.Fatalf("callback request = %+v, want approval ref, revision, and endpoint", request)
		}
		_, _ = w.Write([]byte(`{"approved":true}`))
	}))
	defer server.Close()

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"revision":"manual-callback-rev-1","batch_size":1,"approval_required":true,"approved":true,"approval_ref":"chg-3456","approval_callback_url":"` + server.URL + `","approval_callback_timeout_ms":500}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("callback approval status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode callback approval response: %v\n%s", err, recorder.Body.String())
	}
	if callbackRequests != 1 {
		t.Fatalf("callback requests = %d, want 1", callbackRequests)
	}
	if !got.RolledOut || !got.Rollout.ApprovalCallbackApproved || got.Rollout.Applied != 1 {
		t.Fatalf("callback rollout response = %+v, want approved applied rollout", got)
	}
}

func TestPolicyEndpointAPIRolloutSyncsExternalChangeStatus(t *testing.T) {
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
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond, state)

	statusRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusRequests++
		if r.Method != http.MethodPost {
			t.Fatalf("status method = %s, want POST", r.Method)
		}
		var request struct {
			ApprovalRef string   `json:"approval_ref"`
			Revision    string   `json:"revision"`
			Status      string   `json:"status"`
			Endpoints   []string `json:"endpoints"`
			Applied     int      `json:"applied"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode change status request: %v", err)
		}
		if request.ApprovalRef != "chg-4567" || request.Revision != "manual-rev-1" || request.Status != "applied" || request.Applied != 1 || !reflect.DeepEqual(request.Endpoints, []string{model.EndpointKey("prod", "pod-a")}) {
			t.Fatalf("status request = %+v, want applied change status", request)
		}
		_, _ = w.Write([]byte(`{"synced":true,"status":"implemented","url":"https://changes.example/chg-4567"}`))
	}))
	defer server.Close()

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"revision":"manual-rev-1","batch_size":1,"approval_required":true,"approved":true,"approval_ref":"chg-4567","change_status_url":"` + server.URL + `","change_status_timeout_ms":500}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("change status rollout status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode change status rollout response: %v\n%s", err, recorder.Body.String())
	}
	if statusRequests != 1 {
		t.Fatalf("status requests = %d, want 1", statusRequests)
	}
	if got.Rollout.Revision != "manual-rev-1" {
		t.Fatalf("rollout revision = %q, want manual-rev-1", got.Rollout.Revision)
	}
	if !got.RolledOut || !got.Rollout.ChangeStatusSynced || got.Rollout.ExternalChangeStatus != "implemented" || got.Rollout.ExternalChangeURL != "https://changes.example/chg-4567" {
		t.Fatalf("change status rollout response = %+v, want synced external change status", got)
	}
}

func TestPolicyEndpointAPIRolloutPollsExternalChangeStatus(t *testing.T) {
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
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", time.Millisecond, state)

	pollRequests := 0
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
			t.Fatalf("decode change poll request: %v", err)
		}
		if request.ApprovalRef != "chg-5678" || request.Revision != "manual-poll-rev-1" || !reflect.DeepEqual(request.Endpoints, []string{model.EndpointKey("prod", "pod-a")}) {
			t.Fatalf("poll request = %+v, want approval ref, revision, and endpoint", request)
		}
		_, _ = w.Write([]byte(`{"allowed":true,"status":"approved"}`))
	}))
	defer server.Close()

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"revision":"manual-poll-rev-1","batch_size":1,"approval_ref":"chg-5678","change_poll_url":"` + server.URL + `","change_poll_timeout_ms":500}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("change poll rollout status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode change poll rollout response: %v\n%s", err, recorder.Body.String())
	}
	if pollRequests != 1 {
		t.Fatalf("poll requests = %d, want 1", pollRequests)
	}
	if !got.RolledOut || !got.Rollout.ChangePollAllowed || got.Rollout.ChangePollStatus != "approved" || got.Rollout.Applied != 1 {
		t.Fatalf("change poll rollout response = %+v, want allowed applied rollout", got)
	}
}

func TestPolicyEndpointAPIRolloutUsesPromotionPercent(t *testing.T) {
	state := control.DesiredState{
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
	store := dataplane.NewInMemoryPolicyStore()
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
	}, "memory", time.Millisecond, state)

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a","prod/pod-b","prod/pod-c"],"batch_size":1,"promotion_percent":34}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint rollout response: %v\n%s", err, recorder.Body.String())
	}
	if got.RolledOut || !got.Rollout.Paused || got.Rollout.PromotionPercent != 34 || got.Rollout.PromotionLimit != 2 || got.Rollout.Applied != 2 || got.Rollout.Skipped != 1 {
		t.Fatalf("rollout response = %+v, want promotion-limited rollout", got)
	}
}

func TestPolicyEndpointAPIRolloutUsesPressureAwareBatchSize(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a", SecurityGroups: []string{"web"}},
			{ID: "pod-b", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.11"), Node: "node-a", SecurityGroups: []string{"web"}},
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
	store := &policyRolloutUsageStore{
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
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
	}, "memory", time.Millisecond, state)

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a","prod/pod-b"],"batch_size":2,"pressure_aware":true,"pressure_threshold_percent":80}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/rollout", body)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var got policyEndpointActionOutput
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode policy endpoint rollout response: %v\n%s", err, recorder.Body.String())
	}
	if !got.Rollout.PressureAware || !got.Rollout.PressureAdjusted || got.Rollout.RequestedBatchSize != 2 || got.Rollout.BatchSize != 1 {
		t.Fatalf("rollout = %+v, want pressure-aware batch shrink from 2 to 1", got.Rollout)
	}
	if got.Rollout.PressureMaxPercent != 90 || got.Rollout.PressureEndpoint != model.EndpointKey("prod", "pod-a") || got.Rollout.PressureSeverity != dataplane.PolicyMapPressureCritical {
		t.Fatalf("rollout pressure = %+v, want pod-a at 90%% severity critical", got.Rollout)
	}
	wantHotspots := []dataplane.PolicyMapPressureHotspot{
		{EndpointID: model.EndpointKey("prod", "pod-a"), Entries: 9, Capacity: 10, PressurePercent: 90, Severity: dataplane.PolicyMapPressureCritical},
		{EndpointID: model.EndpointKey("prod", "pod-b"), Entries: 8, Capacity: 10, PressurePercent: 80, Severity: dataplane.PolicyMapPressureWarning},
	}
	if !reflect.DeepEqual(got.Rollout.PressureHotspots, wantHotspots) {
		t.Fatalf("rollout pressure hotspots = %+v, want %+v", got.Rollout.PressureHotspots, wantHotspots)
	}
	if len(got.Rollout.Items) != 2 || got.Rollout.Items[0].Batch != 1 || got.Rollout.Items[1].Batch != 2 {
		t.Fatalf("rollout items = %+v, want one endpoint per pressure-adjusted batch", got.Rollout.Items)
	}
}

func TestPolicyEndpointAPIRejectsUnsupportedPostAction(t *testing.T) {
	metrics := newAgentMetrics(dataplane.NewInMemoryPolicyStore())
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node: "node-a",
	}, "memory", time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a?action=suspend", nil)
	metrics.handlePolicyEndpoints(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", recorder.Code, recorder.Body.String())
	}
}

type policyRolloutUsageStore struct {
	*dataplane.InMemoryPolicyStore
	usage   []dataplane.PolicyMapUsage
	metrics []dataplane.RuleMetrics
}

func (s *policyRolloutUsageStore) PolicyMapUsage(context.Context) ([]dataplane.PolicyMapUsage, error) {
	return append([]dataplane.PolicyMapUsage(nil), s.usage...), nil
}

func (s *policyRolloutUsageStore) PolicyRuleMetrics(context.Context) ([]dataplane.RuleMetrics, error) {
	return append([]dataplane.RuleMetrics(nil), s.metrics...), nil
}

func TestAgentMetricsExportsLatestPolicyAndTCXCounters(t *testing.T) {
	metrics := newAgentMetrics()
	lastSeen := time.Unix(1_725_000_123, 0).UTC()
	eventTime := time.Unix(1_725_000_120, 0).UTC()
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node:                       "node-a",
		Endpoints:                  1,
		Programs:                   1,
		Entries:                    2,
		PolicyMapEntries:           12,
		PolicyMapCapacity:          16,
		PolicyMapPressureMax:       75,
		PolicyMapPressureEndpoint:  "prod\x00pod-a",
		PolicyMapPressureSeverity:  dataplane.PolicyMapPressureNormal,
		PolicyMapPressureEndpoints: 1,
		PolicyMapPressureHotspots: []dataplane.PolicyMapPressureHotspot{{
			EndpointID:      "prod\x00pod-a",
			Entries:         12,
			Capacity:        16,
			PressurePercent: 75,
			Severity:        dataplane.PolicyMapPressureNormal,
		}},
		PolicyPressureMitigated:          2,
		PolicyPressureQuarantined:        1,
		PolicyPressureQuarantineEndpoint: "prod\x00pod-a",
		PolicyRollouts:                   1,
		PolicyRolloutPlanned:             3,
		PolicyRolloutApplied:             2,
		PolicyRolloutSkipped:             1,
		PolicyRolloutFailed:              0,
		PolicyRolloutRolledBack:          1,
		PolicyRolloutRollbackFailed:      0,
		PolicyRolloutSLOFailed:           1,
		PolicyRolloutProbeFailed:         1,
		PolicyRolloutPaused:              1,
		PolicyRolloutCancelled:           1,
		PolicyRolloutStatus: []agent.NamedPolicyEndpointRollout{{
			Name: "prod-rollout",
			Rollout: agent.PolicyEndpointRollout{
				PressureAware:    true,
				PressureSeverity: dataplane.PolicyMapPressureCritical,
			},
		}},
		PolicyMapDriftEndpoints: 1,
		PolicyMapDriftMissing:   2,
		PolicyMapDriftExtra:     3,
		PolicyMapDriftChanged:   4,
		PolicyEndpointStatus: []dataplane.PolicyEndpointStatus{{
			EndpointID:       "prod\x00pod-a",
			Revision:         7,
			Entries:          12,
			Capacity:         16,
			PressurePercent:  75,
			PressureSeverity: dataplane.PolicyMapPressureNormal,
			Drift:            dataplane.PolicyMapDrift{Drifted: true, Missing: 2, Extra: 3, Changed: 4},
			LastEvent:        dataplane.PolicyUpdateEvent{EndpointID: "prod\x00pod-a", Revision: 7, OccurredAt: &eventTime, Stats: dataplane.PolicyUpdateStats{Added: 2, Updated: 3, Deleted: 4, Unchanged: 5}, RuleCookies: []uint32{7, 8}, RuleRefs: []string{"prod/web/deny-client", "prod/web/allow-api"}, Success: true, Remediated: true, Remediation: string(dataplane.PolicyMapOverflowClear)},
			HasLastEvent:     true,
			LastSeen:         &lastSeen,
		}},
		PolicyRulePackets: 3,
		PolicyRuleBytes:   384,
		PolicyRuleAllowed: 2,
		PolicyRuleDropped: 1,
		PolicyRuleLogged:  1,
		PolicyRuleStats: []dataplane.RuleMetrics{
			{EndpointID: "prod\x00pod-a", RuleCookie: 7, Packets: 1, Bytes: 256, Dropped: 1, DenyDrops: 1},
			{EndpointID: "tcx:iface=eth0 direction=ingress attach=2", RuleCookie: 42, Packets: 2, Bytes: 128, Allowed: 2, Logged: 1},
		},
		PolicyRuleCatalog: []agent.PolicyRuleCatalogEntry{{
			EndpointID:    "prod\x00pod-a",
			RuleCookie:    7,
			RuleRef:       "prod/web/deny-client",
			VPC:           "prod",
			SecurityGroup: "web",
			RuleID:        "deny-client",
		}},
		TCXEligible:      1,
		TCXSkipped:       2,
		TCXFailed:        0,
		TCXRollbacks:     0,
		TCXFailedTarget:  "",
		TCXLastError:     "",
		Datapath:         "not-requested",
		TCX:              "attached:eth0:ingress:policy-l4",
		ProviderNetworks: 0,
		ProviderNetworkStatus: []linuxdatapath.ProviderNetworkStatus{{
			ProviderNetwork: "physnet-a",
			TenantUsage: []linuxdatapath.ProviderTenantUsage{{
				Tenant:       "prod",
				Subnets:      1,
				Endpoints:    2,
				MaxSubnets:   2,
				MaxEndpoints: 3,
			}},
		}},
	}, "ebpf", 250*time.Millisecond, []agent.RuntimeCheck{
		{Name: "bpffs", Status: "ok", Required: true, Detail: "/sys/fs/bpf"},
		{Name: "ovsdb", Status: "warn", Detail: "not configured"},
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metrics.handleMetrics(recorder, request)

	output := recorder.Body.String()
	for _, expected := range []string{
		"netloom_agent_reconcile_ready 1",
		`netloom_agent_reconcile_success{node="node-a",store="ebpf"} 1`,
		`netloom_agent_reconcile_duration_milliseconds{node="node-a",store="ebpf"} 250`,
		`netloom_agent_runtime_ready{node="node-a",store="ebpf"} 1`,
		`netloom_agent_runtime_failed_checks{node="node-a",store="ebpf"} 0`,
		`netloom_agent_runtime_warned_checks{node="node-a",store="ebpf"} 1`,
		`netloom_agent_runtime_check_status{check="bpffs",node="node-a",required="true",status="ok",store="ebpf"} 1`,
		`netloom_agent_runtime_check_status{check="ovsdb",node="node-a",required="false",status="warn",store="ebpf"} 0`,
		`netloom_agent_policy_map_entries{node="node-a",store="ebpf"} 12`,
		`netloom_agent_policy_map_pressure_percent{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 75`,
		`netloom_agent_policy_map_pressure_severity{endpoint="prod\x00pod-a",node="node-a",severity="normal",store="ebpf"} 1`,
		`netloom_agent_policy_map_pressure_hotspot_percent{endpoint="prod\x00pod-a",node="node-a",rank="1",store="ebpf"} 75`,
		`netloom_agent_policy_map_pressure_hotspot_entries{endpoint="prod\x00pod-a",node="node-a",rank="1",store="ebpf"} 12`,
		`netloom_agent_policy_map_pressure_hotspot_capacity{endpoint="prod\x00pod-a",node="node-a",rank="1",store="ebpf"} 16`,
		`netloom_agent_policy_map_pressure_hotspot_severity{endpoint="prod\x00pod-a",node="node-a",rank="1",severity="normal",store="ebpf"} 1`,
		`netloom_agent_policy_pressure_mitigated_endpoints{node="node-a",store="ebpf"} 2`,
		`netloom_agent_policy_pressure_mitigated_endpoints_total{node="node-a",store="ebpf"} 2`,
		`netloom_agent_policy_pressure_quarantined_endpoints{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_pressure_quarantined_endpoints_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_pressure_quarantine_endpoint{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollouts{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollout_planned_endpoints{node="node-a",store="ebpf"} 3`,
		`netloom_agent_policy_rollout_applied_endpoints{node="node-a",store="ebpf"} 2`,
		`netloom_agent_policy_rollout_skipped_endpoints{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollout_failed_endpoints{node="node-a",store="ebpf"} 0`,
		`netloom_agent_policy_rollout_rolled_back_endpoints{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollout_rollback_failed_endpoints{node="node-a",store="ebpf"} 0`,
		`netloom_agent_policy_rollout_slo_failed{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollout_probe_failed{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollout_paused{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollout_cancelled{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollout_pressure_severity{node="node-a",rollout="prod-rollout",severity="critical",store="ebpf"} 1`,
		`netloom_agent_provider_tenant_subnets{node="node-a",provider_network="physnet-a",store="ebpf",tenant="prod"} 1`,
		`netloom_agent_provider_tenant_endpoints{node="node-a",provider_network="physnet-a",store="ebpf",tenant="prod"} 2`,
		`netloom_agent_provider_tenant_max_subnets{node="node-a",provider_network="physnet-a",store="ebpf",tenant="prod"} 2`,
		`netloom_agent_provider_tenant_max_endpoints{node="node-a",provider_network="physnet-a",store="ebpf",tenant="prod"} 3`,
		`netloom_agent_provider_tenant_quota_exceeded{node="node-a",provider_network="physnet-a",store="ebpf",tenant="prod"} 0`,
		`netloom_agent_policy_rollout_planned_endpoints_total{node="node-a",store="ebpf"} 3`,
		`netloom_agent_policy_rollout_applied_endpoints_total{node="node-a",store="ebpf"} 2`,
		`netloom_agent_policy_rollout_skipped_endpoints_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollout_failed_endpoints_total{node="node-a",store="ebpf"} 0`,
		`netloom_agent_policy_rollout_rolled_back_endpoints_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollout_rollback_failed_endpoints_total{node="node-a",store="ebpf"} 0`,
		`netloom_agent_policy_rollout_slo_failed_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollout_probe_failed_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollout_paused_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollout_cancelled_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_endpoint_revision{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 7`,
		`netloom_agent_policy_endpoint_entries{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 12`,
		`netloom_agent_policy_endpoint_capacity{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 16`,
		`netloom_agent_policy_endpoint_pressure_percent{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 75`,
		`netloom_agent_policy_endpoint_pressure_severity{endpoint="prod\x00pod-a",node="node-a",severity="normal",store="ebpf"} 1`,
		`netloom_agent_policy_endpoint_drifted{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_endpoint_drift_missing_entries{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 2`,
		`netloom_agent_policy_endpoint_drift_extra_entries{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 3`,
		`netloom_agent_policy_endpoint_drift_changed_entries{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 4`,
		`netloom_agent_policy_endpoint_last_event_revision{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 7`,
		`netloom_agent_policy_endpoint_last_event_success{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_endpoint_last_event_remediated{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_endpoint_last_event_timestamp_seconds{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 1725000120`,
		`netloom_agent_policy_endpoint_last_event_added_entries{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 2`,
		`netloom_agent_policy_endpoint_last_event_updated_entries{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 3`,
		`netloom_agent_policy_endpoint_last_event_deleted_entries{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 4`,
		`netloom_agent_policy_endpoint_last_event_unchanged_entries{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 5`,
		`netloom_agent_policy_endpoint_last_event_rule_cookies{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 2`,
		`netloom_agent_policy_endpoint_last_event_rule_refs{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 2`,
		`netloom_agent_policy_endpoint_last_seen_timestamp_seconds{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 1725000123`,
		`netloom_agent_policy_map_drift_endpoints{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_map_drift_missing_entries{node="node-a",store="ebpf"} 2`,
		`netloom_agent_policy_map_drift_extra_entries{node="node-a",store="ebpf"} 3`,
		`netloom_agent_policy_map_drift_changed_entries{node="node-a",store="ebpf"} 4`,
		`netloom_agent_policy_rule_packets_total{node="node-a",store="ebpf"} 3`,
		`netloom_agent_policy_rule_dropped_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rule_no_match_drops_total{node="node-a",store="ebpf"} 0`,
		`netloom_agent_policy_rule_deny_drops_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rule_reject_drops_total{node="node-a",store="ebpf"} 0`,
		`netloom_agent_policy_rule_packets_by_rule_total{endpoint="prod\x00pod-a",node="node-a",rule_cookie="7",rule_id="deny-client",rule_ref="prod/web/deny-client",security_group="web",store="ebpf",vpc="prod"} 1`,
		`netloom_agent_policy_rule_deny_drops_by_rule_total{endpoint="prod\x00pod-a",node="node-a",rule_cookie="7",rule_id="deny-client",rule_ref="prod/web/deny-client",security_group="web",store="ebpf",vpc="prod"} 1`,
		`netloom_agent_policy_rule_packets_by_rule_total{endpoint="tcx:iface=eth0 direction=ingress attach=2",node="node-a",rule_cookie="42",rule_id="",rule_ref="",security_group="",store="ebpf",vpc=""} 2`,
		`netloom_agent_policy_rule_reject_drops_by_rule_total{endpoint="tcx:iface=eth0 direction=ingress attach=2",node="node-a",rule_cookie="42",rule_id="",rule_ref="",security_group="",store="ebpf",vpc=""} 0`,
		`netloom_agent_tcx_eligible{node="node-a",store="ebpf"} 1`,
		`netloom_agent_tcx_skipped{node="node-a",store="ebpf"} 2`,
		`netloom_agent_tcx_failed{node="node-a",store="ebpf",target=""} 0`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("metrics output missing %q:\n%s", expected, output)
		}
	}
}

func TestAgentMetricsExportsLatestFailure(t *testing.T) {
	metrics := newAgentMetrics()
	observeAgentReconcileFailure(metrics, agent.ReconcileResult{Node: "node-a"}, "memory", errors.New("apply failed"), 125*time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metrics.handleMetrics(recorder, request)

	output := recorder.Body.String()
	for _, expected := range []string{
		`netloom_agent_reconcile_success{node="node-a",store="memory"} 0`,
		`netloom_agent_reconcile_duration_milliseconds{node="node-a",store="memory"} 125`,
		`netloom_agent_reconcile_last_error{error="apply failed",node="node-a",store="memory"} 1`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("failure metrics output missing %q:\n%s", expected, output)
		}
	}
}

func TestAgentMetricsAccumulatesReconcileCountersAndBuckets(t *testing.T) {
	metrics := newAgentMetrics()
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node:               "node-a",
		PolicyAdded:        2,
		PolicyUpdated:      1,
		PolicyDeleted:      1,
		PolicyEvents:       4,
		ConntrackExpired:   3,
		PolicyRulePackets:  5,
		PolicyRuleBytes:    512,
		PolicyRuleDropped:  2,
		PolicyRuleRejected: 1,
		PolicyRuleStats: []dataplane.RuleMetrics{
			{EndpointID: "prod\x00pod-a", RuleCookie: 0, Packets: 1, Bytes: 64, Dropped: 1, NoMatchDrops: 1},
			{EndpointID: "prod\x00pod-a", RuleCookie: 7, Packets: 1, Bytes: 128, Dropped: 1, DenyDrops: 1},
			{EndpointID: "prod\x00pod-a", RuleCookie: 8, Packets: 1, Bytes: 128, Rejected: 1, RejectDrops: 1},
		},
	}, "ebpf", 250*time.Millisecond)
	observeAgentReconcileFailure(metrics, agent.ReconcileResult{
		Node:            "node-a",
		PolicyFailed:    1,
		PolicyRollbacks: 1,
		TCXFailed:       1,
		TCXRollbacks:    1,
	}, "ebpf", errors.New("attach failed"), 750*time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metrics.handleMetrics(recorder, request)

	output := recorder.Body.String()
	for _, expected := range []string{
		`netloom_agent_reconcile_attempts_total{node="node-a",store="ebpf"} 2`,
		`netloom_agent_reconcile_success_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_reconcile_failure_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_reconcile_duration_milliseconds_histogram_bucket{le="250",node="node-a",store="ebpf"} 1`,
		`netloom_agent_reconcile_duration_milliseconds_histogram_bucket{le="1000",node="node-a",store="ebpf"} 2`,
		`netloom_agent_reconcile_duration_milliseconds_histogram_bucket{le="+Inf",node="node-a",store="ebpf"} 2`,
		`netloom_agent_reconcile_duration_milliseconds_histogram_sum{node="node-a",store="ebpf"} 1000`,
		`netloom_agent_reconcile_duration_milliseconds_histogram_count{node="node-a",store="ebpf"} 2`,
		`netloom_agent_policy_added_total{node="node-a",store="ebpf"} 2`,
		`netloom_agent_policy_updated_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_deleted_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_events_total{node="node-a",store="ebpf"} 4`,
		`netloom_agent_policy_failed_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rollbacks_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_tcx_failed_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_tcx_rollbacks_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_conntrack_expired_total{node="node-a",store="ebpf"} 3`,
		`netloom_agent_policy_rule_packets_observed_total{node="node-a",store="ebpf"} 5`,
		`netloom_agent_policy_rule_bytes_observed_total{node="node-a",store="ebpf"} 512`,
		`netloom_agent_policy_rule_dropped_observed_total{node="node-a",store="ebpf"} 2`,
		`netloom_agent_policy_rule_rejected_observed_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rule_no_match_drops_observed_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rule_deny_drops_observed_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rule_reject_drops_observed_total{node="node-a",store="ebpf"} 1`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("cumulative metrics output missing %q:\n%s", expected, output)
		}
	}
}

type fakeOpenVSwitchExternalIDStore struct {
	values map[string]string
}

func (s *fakeOpenVSwitchExternalIDStore) OpenVSwitchExternalID(_ context.Context, key string) (string, bool, error) {
	if s.values == nil {
		return "", false, nil
	}
	value, ok := s.values[key]
	return value, ok, nil
}

func (s *fakeOpenVSwitchExternalIDStore) SetOpenVSwitchExternalID(_ context.Context, key, value string) error {
	if s.values == nil {
		s.values = map[string]string{}
	}
	s.values[key] = value
	return nil
}

func newTestAgentVSwitchOVSDB(t *testing.T) (string, libovsdbclient.Client, func()) {
	t.Helper()
	clientModel, err := vswitch.FullDatabaseModel()
	if err != nil {
		t.Fatal(err)
	}
	schema := vswitch.Schema()
	databaseModel, errs := ovsmodel.NewDatabaseModel(schema, clientModel)
	if len(errs) > 0 {
		t.Fatalf("database model errors: %+v", errs)
	}
	logger := logr.Discard()
	db := inmemory.NewDatabase(map[string]ovsmodel.ClientDBModel{vswitch.DatabaseName: clientModel}, &logger)
	ovsServer, err := server.NewOvsdbServer(db, &logger, databaseModel)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "ovsdb.sock")
	go func() {
		if err := ovsServer.Serve("unix", socket); err != nil {
			t.Logf("libovsdb test server stopped: %v", err)
		}
	}()
	requireAgentEventually(t, ovsServer.Ready)

	client, err := libovsdbclient.NewOVSDBClient(clientModel, libovsdbclient.WithEndpoint("unix:"+socket))
	if err != nil {
		ovsServer.Close()
		t.Fatal(err)
	}
	if err := client.Connect(t.Context()); err != nil {
		ovsServer.Close()
		t.Fatal(err)
	}
	if _, err := client.MonitorAll(t.Context()); err != nil {
		ovsServer.Close()
		t.Fatal(err)
	}
	return "unix:" + socket, client, func() {
		client.Disconnect()
		client.Close()
		ovsServer.Close()
	}
}

func requireAgentEventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not satisfied")
}

func insertAgentVSwitchRows(t *testing.T, ctx context.Context, client libovsdbclient.Client, rows ...ovsmodel.Model) {
	t.Helper()
	var ops []ovsdb.Operation
	for _, row := range rows {
		next, err := client.Create(row)
		if err != nil {
			t.Fatal(err)
		}
		ops = append(ops, next...)
	}
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("ovsdb transact results = %+v: %v", results, err)
	}
}

func singleAgentVSwitchRoot(t *testing.T, ctx context.Context, client libovsdbclient.Client) vswitch.OpenvSwitch {
	t.Helper()
	var rows []vswitch.OpenvSwitch
	if err := client.List(ctx, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("Open_vSwitch rows = %d, want 1: %+v", len(rows), rows)
	}
	return rows[0]
}

func stringifyAgentOps(ops []linuxdatapath.Operation) string {
	var builder strings.Builder
	for _, op := range ops {
		builder.WriteString(op.Command)
		if len(op.Args) != 0 {
			builder.WriteByte(' ')
			builder.WriteString(strings.Join(op.Args, " "))
		}
		builder.WriteByte('\n')
	}
	return builder.String()
}
