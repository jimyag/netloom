package linuxdatapath

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/model"
)

func TestPlanProgramsLocalAddressesAndRemoteRoutes(t *testing.T) {
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
				ID:     "pod-b",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.11"),
				Node:   "node-b",
			},
		},
	}
	ops, result, err := Plan(context.Background(), state, Options{
		Node:           "node-a",
		LocalDevice:    "nl0",
		UnderlayDevice: "eth9",
		NodeUnderlays: map[string]netip.Addr{
			"node-b": netip.MustParseAddr("172.30.0.12"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.LocalAddresses != 1 || result.RemoteRoutes != 1 || result.Device != "nl0" {
		t.Fatalf("unexpected result: %+v", result)
	}
	want := []Operation{
		{Command: "ip", Args: []string{"link", "set", "nl0", "up"}},
		{Command: "ip", Args: []string{"addr", "replace", "10.10.0.10/32", "dev", "nl0"}},
		{Command: "ip", Args: []string{"route", "replace", "10.10.0.11/32", "via", "172.30.0.12", "dev", "eth9"}},
	}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("ops = %#v, want %#v", ops, want)
	}
}

func TestPlanRequiresRemoteUnderlay(t *testing.T) {
	_, _, err := Plan(context.Background(), control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-b",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.11"),
			Node:   "missing-node",
		}},
	}, Options{Node: "node-a"})
	if err == nil {
		t.Fatal("expected missing remote underlay to fail")
	}
}

func TestPlanNetNSProgramsVethAndNamespace(t *testing.T) {
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
				ID:     "pod-b",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("10.10.0.11"),
				Node:   "node-b",
			},
		},
	}
	ops, result, err := Plan(context.Background(), state, Options{
		Node:          "node-a",
		Mode:          "netns",
		WorkloadIF:    "eth0",
		NodeUnderlays: map[string]netip.Addr{"node-b": netip.MustParseAddr("172.30.0.12")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != "netns" || result.Device != "netns" || result.LocalAddresses != 1 || result.RemoteRoutes != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"ip_forward=1",
		"ip netns add nl-pod-a",
		"ip netns exec nl-pod-a ip addr replace 10.10.0.10/32 dev eth0",
		"ip netns exec nl-pod-a ip route replace default via 169.254.1.1 dev eth0 onlink",
		"ip route replace 10.10.0.11/32 via 172.30.0.12 dev eth0",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanNetNSCleanupDeletesStaleNamespaces(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
	}
	ops, result, err := Plan(context.Background(), state, Options{
		Node:         "node-a",
		Mode:         "netns",
		CleanupStale: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.CleanupPlanned {
		t.Fatal("cleanup was not marked as planned")
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{"ip netns list", "grep '^nl-'", " nl-pod-a ", "ip netns del"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("cleanup ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestHostVethNameIsStableAndShort(t *testing.T) {
	first := HostVethName("file-pod-a")
	second := HostVethName("file-pod-a")
	if first != second {
		t.Fatalf("host veth name is not stable: %s != %s", first, second)
	}
	if len(first) > 15 {
		t.Fatalf("host veth name %q is longer than Linux ifname limit", first)
	}
}

func stringifyOps(ops []Operation) string {
	lines := make([]string, 0, len(ops))
	for _, op := range ops {
		lines = append(lines, op.Command+" "+strings.Join(op.Args, " "))
	}
	return strings.Join(lines, "\n")
}
