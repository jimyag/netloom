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
	"strings"
	"testing"
	"time"

	"github.com/jimyag/netloom/internal/agent"
	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/linuxdatapath"
	"github.com/jimyag/netloom/internal/model"
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

func TestLinuxDatapathOptionsParsesBackend(t *testing.T) {
	t.Setenv("NETLOOM_LINUX_DATAPATH", "1")
	t.Setenv("NETLOOM_LINUX_DATAPATH_MODE", "netns")
	t.Setenv("NETLOOM_LINUX_DATAPATH_BACKEND", "netlink")
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
		t.Fatalf("backend = %s, want netlink", options.Backend)
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
	path := filepath.Join(t.TempDir(), "dns-observations.json")
	if err := os.WriteFile(path, []byte(`{"dns_records": [{"name": "api.example.com", "ips": ["203.0.113.10"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETLOOM_DNS_OBSERVATIONS_FILE", path)

	state, err := withDNSObservations(control.DesiredState{
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
	})
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

func TestWithDNSObservationsPrunesExpiredRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-observations.json")
	if err := os.WriteFile(path, []byte(`{"dns_records": [
		{"name": "expired.example.com", "ips": ["203.0.113.10"], "ttl_seconds": 30, "observed_at": "2026-05-30T11:59:30Z"},
		{"name": "active.example.com", "ips": ["203.0.113.20"], "ttl_seconds": 31, "observed_at": "2026-05-30T11:59:30Z"},
		{"name": "static.example.com", "ips": ["203.0.113.30"]}
	]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETLOOM_DNS_OBSERVATIONS_FILE", path)
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)

	state, err := withDNSObservationsAt(control.DesiredState{}, now)
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

func TestWithRuntimeObservationsMergesIdentityGroups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-groups.json")
	if err := os.WriteFile(path, []byte(`{"identity_groups": [{"name": "frontend-api", "vpc": "prod", "source": "cmdb", "observed_at": "2026-07-10T01:00:00Z", "ttl_seconds": 120, "endpoint_ids": ["pod-a"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETLOOM_IDENTITY_GROUPS_FILE", path)
	now := time.Date(2026, 7, 10, 1, 1, 0, 0, time.UTC)

	state, err := withRuntimeObservationsAt(control.DesiredState{
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
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.IdentityGroups) != 1 || state.IdentityGroups[0].Name != "frontend-api" || state.IdentityGroups[0].Source != "cmdb" {
		t.Fatalf("identity groups = %+v, want observed frontend-api", state.IdentityGroups)
	}

	result, err := agent.ReconcileNodeWithOptions(context.Background(), state, agent.ReconcileOptions{
		Node:  "node-a",
		Store: dataplane.NewInMemoryPolicyStore(),
		LinuxDatapath: &linuxdatapath.Options{
			Node:              "node-a",
			Backend:           "command",
			SyncOVSDB:         true,
			ProviderInventory: []linuxdatapath.ProviderInterface{{Name: "eth1", Ready: true, State: "up"}},
			Executor:          agentNoopExecutor{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderNetworks != 1 || result.ProviderLinks != 1 {
		t.Fatalf("provider result = %+v, want provider network/link from observed identity group state", result)
	}
}

type agentNoopExecutor struct{}

func (agentNoopExecutor) Execute(context.Context, linuxdatapath.Operation) error {
	return nil
}

func TestWithIdentityGroupObservationsPrunesExpiredGroups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-groups.json")
	if err := os.WriteFile(path, []byte(`{"identity_groups": [
		{"name": "expired", "vpc": "prod", "observed_at": "2026-07-10T01:00:00Z", "ttl_seconds": 60, "endpoint_ids": ["pod-a"]},
		{"name": "active", "vpc": "prod", "observed_at": "2026-07-10T01:00:01Z", "ttl_seconds": 60, "endpoint_ids": ["pod-b"]},
		{"name": "static", "vpc": "prod", "endpoint_ids": ["pod-c"]}
	]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETLOOM_IDENTITY_GROUPS_FILE", path)
	now := time.Date(2026, 7, 10, 1, 1, 0, 0, time.UTC)

	state, err := withIdentityGroupObservationsAt(control.DesiredState{}, now)
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
	historyPath := filepath.Join(t.TempDir(), "rollouts.jsonl")
	if err := configurePolicyRolloutHistory(metrics, historyPath); err != nil {
		t.Fatal(err)
	}

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = oldStdout
	}()

	err = reconcileStateFileOnce(context.Background(), statePath, "node-a", "memory", store, time.Second, metrics, nil)
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
	raw, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"source":"desired-state"`) || !strings.Contains(string(raw), `"name":"web-canary"`) {
		t.Fatalf("history file = %s, want desired-state rollout entry", raw)
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
	stateFile := filepath.Join(t.TempDir(), "rollout-state.json")
	t.Setenv("NETLOOM_POLICY_ROLLOUT_STATE_FILE", stateFile)
	store := dataplane.NewInMemoryPolicyStore()

	if err := reconcileStateFileOnce(context.Background(), statePath, "node-a", "memory", store, time.Second, nil, nil); err != nil {
		t.Fatal(err)
	}
	doc, err := loadPolicyRolloutState(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Rollouts) != 1 || doc.Rollouts[0].Name != "web-canary" || !reflect.DeepEqual(doc.Rollouts[0].AppliedEndpoints, []string{model.EndpointKey("prod", "pod-a")}) {
		t.Fatalf("rollout state = %+v, want paused web-canary with pod-a applied", doc)
	}
	eventsAfterFirst := len(store.Events())

	state.PolicyRollouts[0].PromotionPercent = 100
	statePath = writeAgentState(t, state)
	if err := reconcileStateFileOnce(context.Background(), statePath, "node-a", "memory", store, time.Second, nil, nil); err != nil {
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
	doc, err = loadPolicyRolloutState(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Rollouts) != 0 {
		t.Fatalf("rollout state after completion = %+v, want cleared state", doc)
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
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
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
	if revision := store.Revision(endpointID); revision != beforeRevision {
		t.Fatalf("revision = %d, want unchanged %d", revision, beforeRevision)
	}
	if entries := store.Entries(endpointID); len(entries) != 1 || entries[0].RemoteCIDR != oldEntries[0].RemoteCIDR || entries[0].Value.Deny != 1 {
		t.Fatalf("entries = %+v, want old entries preserved", entries)
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
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
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
	historyPath := filepath.Join(t.TempDir(), "rollouts.jsonl")
	metrics := newAgentMetrics(store)
	if err := configurePolicyRolloutHistory(metrics, historyPath); err != nil {
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

	raw, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("history lines = %d, want 1: %s", len(lines), raw)
	}
	var persisted policyRolloutHistoryEntry
	if err := json.Unmarshal([]byte(lines[0]), &persisted); err != nil {
		t.Fatalf("decode persisted history: %v", err)
	}
	if persisted.Source != "manual" || persisted.Node != "node-a" || persisted.Store != "memory" || persisted.Rollout.Applied != 1 || persisted.Rollout.Planned != 1 {
		t.Fatalf("persisted history = %+v, want manual applied rollout", persisted)
	}

	reloaded := newAgentMetrics(store)
	if err := configurePolicyRolloutHistory(reloaded, historyPath); err != nil {
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
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	store := dataplane.NewInMemoryPolicyStore()
	metrics := newAgentMetrics(store)
	observeAgentReconcileResultWithState(metrics, agent.ReconcileResult{
		Node: "node-a",
	}, "memory", time.Millisecond, state)

	body := bytes.NewBufferString(fmt.Sprintf(`{"endpoints":["prod/pod-a"],"batch_size":1,"probes":[{"name":"web-ready","type":"http","url":%q,"expected_status":204,"timeout_ms":1000}]}`, server.URL))
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
	if len(got.Rollout.Probes) != 1 || !got.Rollout.Probes[0].Passed || got.Rollout.Probes[0].StatusCode != http.StatusNoContent {
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
	if !got.RolledOut || !got.Rollout.Paused || got.Rollout.PausedAfterBatch != 1 || got.Rollout.Applied != 1 || got.Rollout.Skipped != 1 {
		t.Fatalf("rollout response = %+v, want paused rollout after first batch", got)
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
			Endpoints   []string `json:"endpoints"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode callback request: %v", err)
		}
		if request.ApprovalRef != "chg-3456" || !reflect.DeepEqual(request.Endpoints, []string{model.EndpointKey("prod", "pod-a")}) {
			t.Fatalf("callback request = %+v, want approval ref and endpoint", request)
		}
		_, _ = w.Write([]byte(`{"approved":true}`))
	}))
	defer server.Close()

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"batch_size":1,"approval_required":true,"approved":true,"approval_ref":"chg-3456","approval_callback_url":"` + server.URL + `","approval_callback_timeout_ms":500}`)
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
			Status      string   `json:"status"`
			Endpoints   []string `json:"endpoints"`
			Applied     int      `json:"applied"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode change status request: %v", err)
		}
		if request.ApprovalRef != "chg-4567" || request.Status != "applied" || request.Applied != 1 || !reflect.DeepEqual(request.Endpoints, []string{model.EndpointKey("prod", "pod-a")}) {
			t.Fatalf("status request = %+v, want applied change status", request)
		}
		_, _ = w.Write([]byte(`{"synced":true,"status":"implemented","url":"https://changes.example/chg-4567"}`))
	}))
	defer server.Close()

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"batch_size":1,"approval_required":true,"approved":true,"approval_ref":"chg-4567","change_status_url":"` + server.URL + `","change_status_timeout_ms":500}`)
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
			Endpoints   []string `json:"endpoints"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode change poll request: %v", err)
		}
		if request.ApprovalRef != "chg-5678" || !reflect.DeepEqual(request.Endpoints, []string{model.EndpointKey("prod", "pod-a")}) {
			t.Fatalf("poll request = %+v, want approval ref and endpoint", request)
		}
		_, _ = w.Write([]byte(`{"allowed":true,"status":"approved"}`))
	}))
	defer server.Close()

	body := bytes.NewBufferString(`{"endpoints":["prod/pod-a"],"batch_size":1,"approval_ref":"chg-5678","change_poll_url":"` + server.URL + `","change_poll_timeout_ms":500}`)
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
	if !got.RolledOut || !got.Rollout.Paused || got.Rollout.PromotionPercent != 34 || got.Rollout.PromotionLimit != 2 || got.Rollout.Applied != 2 || got.Rollout.Skipped != 1 {
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
		usage: []dataplane.PolicyMapUsage{{
			EndpointID: model.EndpointKey("prod", "pod-a"),
			Entries:    9,
			Capacity:   10,
		}},
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
	if got.Rollout.PressureMaxPercent != 90 || got.Rollout.PressureEndpoint != model.EndpointKey("prod", "pod-a") {
		t.Fatalf("rollout pressure = %+v, want pod-a at 90%%", got.Rollout)
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
	request := httptest.NewRequest(http.MethodPost, "/policy/endpoints/prod/pod-a?action=freeze", nil)
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
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node:                             "node-a",
		Endpoints:                        1,
		Programs:                         1,
		Entries:                          2,
		PolicyMapEntries:                 12,
		PolicyMapCapacity:                16,
		PolicyMapPressureMax:             75,
		PolicyMapPressureEndpoint:        "prod\x00pod-a",
		PolicyMapPressureEndpoints:       1,
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
		PolicyMapDriftEndpoints:          1,
		PolicyMapDriftMissing:            2,
		PolicyMapDriftExtra:              3,
		PolicyMapDriftChanged:            4,
		PolicyRulePackets:                3,
		PolicyRuleBytes:                  384,
		PolicyRuleAllowed:                2,
		PolicyRuleDropped:                1,
		PolicyRuleLogged:                 1,
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
	}, "ebpf", 250*time.Millisecond)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metrics.handleMetrics(recorder, request)

	output := recorder.Body.String()
	for _, expected := range []string{
		"netloom_agent_reconcile_ready 1",
		`netloom_agent_reconcile_success{node="node-a",store="ebpf"} 1`,
		`netloom_agent_reconcile_duration_milliseconds{node="node-a",store="ebpf"} 250`,
		`netloom_agent_policy_map_entries{node="node-a",store="ebpf"} 12`,
		`netloom_agent_policy_map_pressure_percent{endpoint="prod\x00pod-a",node="node-a",store="ebpf"} 75`,
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
