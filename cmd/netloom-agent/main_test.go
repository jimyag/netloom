package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jimyag/netloom/internal/agent"
	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/model"
)

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

func TestLinuxDatapathOptionsParsesBackend(t *testing.T) {
	t.Setenv("NETLOOM_LINUX_DATAPATH", "1")
	t.Setenv("NETLOOM_LINUX_DATAPATH_MODE", "netns")
	t.Setenv("NETLOOM_LINUX_DATAPATH_BACKEND", "netlink")
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
	entries := store.Entries("pod-a")
	if len(entries) != 1 || entries[0].RemoteCIDR.String() != "203.0.113.10/32" {
		t.Fatalf("policy entries = %+v, want observed FQDN CIDR", entries)
	}
}
