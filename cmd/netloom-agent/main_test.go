package main

import (
	"bytes"
	"context"
	"io"
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
	"github.com/jimyag/netloom/internal/model"
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
		PolicyMapPressureEndpoints: 0,
		Datapath:                   "not-requested",
		TCX:                        "not-requested",
	}, "ebpf")

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
		"policy_map_pressure_endpoints=0",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output missing %q:\n%s", expected, output)
		}
	}
}
