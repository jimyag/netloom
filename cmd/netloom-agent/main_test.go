package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func TestLinuxDatapathOptionsParsesBackend(t *testing.T) {
	t.Setenv("NETLOOM_LINUX_DATAPATH", "1")
	t.Setenv("NETLOOM_LINUX_DATAPATH_MODE", "netns")
	t.Setenv("NETLOOM_LINUX_DATAPATH_BACKEND", "netlink")
	t.Setenv("NETLOOM_PROVIDER_NETWORK_LINKS", "physnet-a=eth1, physnet-b = bond0.100")
	t.Setenv("NETLOOM_POLICY_ROUTE_TABLE_BASE", "22000")
	t.Setenv("NETLOOM_POLICY_ROUTE_TABLE_SIZE", "64")
	t.Setenv("NETLOOM_PROVIDER_HEALTH_STRICT", "1")

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
		Node:                       "node-a",
		Endpoints:                  1,
		Programs:                   1,
		Entries:                    3,
		PolicyMapEntries:           12,
		PolicyMapCapacity:          16,
		PolicyMapPressureMax:       75,
		PolicyMapPressureEndpoint:  "prod\x00pod-a",
		PolicyMapPressureEndpoints: 0,
		PolicyFailedEndpoint:       "prod\x00pod-b",
		PolicyFailedRevision:       3,
		PolicyRulePackets:          3,
		PolicyRuleBytes:            384,
		PolicyRuleAllowed:          2,
		PolicyRuleDropped:          1,
		PolicyRuleLogged:           1,
		PolicyRuleStats: []dataplane.RuleMetrics{
			{EndpointID: "prod\x00pod-a", RuleCookie: 7, Packets: 1, Bytes: 256, Dropped: 1, DenyDrops: 1},
			{EndpointID: "prod\x00pod-a", RuleCookie: 42, Packets: 2, Bytes: 128, Allowed: 2, Logged: 1},
		},
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
			{ProviderNetwork: "physnet-a", Ready: true, LinkCount: 1, ReadyLinks: 1, IssueCount: 0},
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
		`policy_failed_endpoint="prod\x00pod-b"`,
		"policy_failed_revision=3",
		"policy_rule_packets=3",
		"policy_rule_bytes=384",
		"policy_rule_allowed=2",
		"policy_rule_dropped=1",
		"policy_rule_rejected=0",
		"policy_rule_logged=1",
		`policy_rule_stats="prod\x00pod-a"/7:p=1,b=256,a=0,d=1,r=0,nm=0,ct=0,est=0,log=0;"prod\x00pod-a"/42:p=2,b=128,a=2,d=0,r=0,nm=0,ct=0,est=0,log=1`,
		`tcx_failed_target="iface=eth0 direction=ingress attach=2"`,
		"provider_networks=1",
		"provider_links=2",
		"provider_ready=1",
		"provider_degraded=1",
		"provider_status=physnet-a:eth1:100:nlv-a:ready:up:up,physnet-b:bond0:200:nlv-b:pending:up:down",
		"provider_network_status=physnet-a:ready:1/1:0:none,physnet-b:degraded:0/1:1:type-mismatch",
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

func TestAgentMetricsExportsLatestPolicyAndTCXCounters(t *testing.T) {
	metrics := newAgentMetrics()
	observeAgentReconcileResult(metrics, agent.ReconcileResult{
		Node:                       "node-a",
		Endpoints:                  1,
		Programs:                   1,
		Entries:                    2,
		PolicyMapEntries:           12,
		PolicyMapCapacity:          16,
		PolicyMapPressureMax:       75,
		PolicyMapPressureEndpoint:  "prod\x00pod-a",
		PolicyMapPressureEndpoints: 1,
		PolicyRulePackets:          3,
		PolicyRuleBytes:            384,
		PolicyRuleAllowed:          2,
		PolicyRuleDropped:          1,
		PolicyRuleLogged:           1,
		PolicyRuleStats: []dataplane.RuleMetrics{
			{EndpointID: "prod\x00pod-a", RuleCookie: 7, Packets: 1, Bytes: 256, Dropped: 1, DenyDrops: 1},
			{EndpointID: "tcx:iface=eth0 direction=ingress attach=2", RuleCookie: 42, Packets: 2, Bytes: 128, Allowed: 2, Logged: 1},
		},
		TCXEligible:      1,
		TCXFailed:        0,
		TCXRollbacks:     0,
		TCXFailedTarget:  "",
		TCXLastError:     "",
		Datapath:         "not-requested",
		TCX:              "attached:eth0:ingress:policy-l4",
		ProviderNetworks: 0,
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
		`netloom_agent_policy_rule_packets_total{node="node-a",store="ebpf"} 3`,
		`netloom_agent_policy_rule_dropped_total{node="node-a",store="ebpf"} 1`,
		`netloom_agent_policy_rule_packets_by_rule_total{endpoint="prod\x00pod-a",node="node-a",rule_cookie="7",store="ebpf"} 1`,
		`netloom_agent_policy_rule_packets_by_rule_total{endpoint="tcx:iface=eth0 direction=ingress attach=2",node="node-a",rule_cookie="42",store="ebpf"} 2`,
		`netloom_agent_tcx_eligible{node="node-a",store="ebpf"} 1`,
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
		Node:              "node-a",
		PolicyAdded:       2,
		PolicyUpdated:     1,
		PolicyDeleted:     1,
		PolicyEvents:      4,
		ConntrackExpired:  3,
		PolicyRulePackets: 5,
		PolicyRuleBytes:   512,
		PolicyRuleDropped: 1,
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
		`netloom_agent_policy_rule_dropped_observed_total{node="node-a",store="ebpf"} 1`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("cumulative metrics output missing %q:\n%s", expected, output)
		}
	}
}
