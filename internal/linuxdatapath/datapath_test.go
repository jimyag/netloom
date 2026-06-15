package linuxdatapath

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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
		NodeUnderlays: map[string][]netip.Addr{
			"node-b": {netip.MustParseAddr("172.30.0.12")},
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
		{Command: "ip", Args: []string{"route", "replace", "10.10.0.11/32", "via", "172.30.0.12", "dev", "eth9", "proto", "187"}},
	}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("ops = %#v, want %#v", ops, want)
	}
}

func TestPlanReportsProviderNetworkCounts(t *testing.T) {
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
					Interface: "eth2",
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
				VLAN:            200,
			},
		},
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps-a", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a"},
			{ID: "pod-b", VPC: "prod", Subnet: "apps-b", IP: netip.MustParseAddr("10.20.0.10"), Node: "node-a"},
		},
	}
	_, result, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderNetworks != 2 || result.ProviderLinks != 2 {
		t.Fatalf("provider counts = %+v, want provider_networks=2 provider_links=2", result)
	}
	if result.ProviderReady != 0 || result.ProviderDegraded != 2 {
		t.Fatalf("provider health summary = %+v, want provider_ready=0 provider_degraded=2", result)
	}
	if len(result.ProviderStatus) != 2 {
		t.Fatalf("provider status = %+v, want 2 entries", result.ProviderStatus)
	}
	if got := result.ProviderStatus[0]; got.ProviderNetwork != "physnet-a" || got.ParentDevice != "eth1" || got.VLAN != 100 || got.LinkName == "" || got.Ready || got.ParentState != "planned" || got.LinkState != "planned" {
		t.Fatalf("provider status[0] = %+v", got)
	}
	if got := result.ProviderStatus[1]; got.ProviderNetwork != "physnet-b" || got.ParentDevice != "eth2" || got.VLAN != 200 || got.LinkName == "" || got.Ready || got.ParentState != "planned" || got.LinkState != "planned" {
		t.Fatalf("provider status[1] = %+v", got)
	}
}

func TestProviderOperStateReady(t *testing.T) {
	tests := []struct {
		state netlink.LinkOperState
		ready bool
	}{
		{state: netlink.OperUp, ready: true},
		{state: netlink.OperUnknown, ready: true},
		{state: netlink.OperDormant, ready: true},
		{state: netlink.OperTesting, ready: true},
		{state: netlink.OperDown, ready: false},
		{state: netlink.OperLowerLayerDown, ready: false},
		{state: netlink.OperNotPresent, ready: false},
	}
	for _, tt := range tests {
		if got := providerOperStateReady(tt.state); got != tt.ready {
			t.Fatalf("providerOperStateReady(%v) = %t, want %t", tt.state, got, tt.ready)
		}
	}
}

func TestSummarizeProviderLinkHealth(t *testing.T) {
	ready, degraded := summarizeProviderLinkHealth([]ProviderLinkStatus{
		{Ready: true},
		{Ready: false},
		{Ready: true},
	})
	if ready != 2 || degraded != 1 {
		t.Fatalf("summarizeProviderLinkHealth() = ready:%d degraded:%d, want 2/1", ready, degraded)
	}
}

func TestPlanRequiresRemoteUnderlay(t *testing.T) {
	_, _, err := Plan(context.Background(), control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-b",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.11"),
			Node:   "missing node",
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
		NodeUnderlays: map[string][]netip.Addr{"node-b": {netip.MustParseAddr("172.30.0.12"), netip.MustParseAddr("fd00::12")}},
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
		"net.ipv6.conf.all.forwarding=1",
		"ip netns add nl-prod_x000000pod-a",
		"ip netns exec nl-prod_x000000pod-a ip addr replace 10.10.0.10/32 dev eth0",
		"ip netns exec nl-prod_x000000pod-a ip route replace default via 169.254.1.1 dev eth0 onlink",
		"ip route replace 10.10.0.11/32 via 172.30.0.12 dev eth0 proto 187",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanNetNSProgramsIPv6VethAndNamespace(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{
				ID:     "pod-a",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("fd00:10::10"),
				Node:   "node-a",
			},
			{
				ID:     "pod-b",
				VPC:    "prod",
				Subnet: "apps",
				IP:     netip.MustParseAddr("fd00:10::11"),
				Node:   "node-b",
			},
		},
	}
	ops, result, err := Plan(context.Background(), state, Options{
		Node:          "node-a",
		Mode:          "netns",
		WorkloadIF:    "eth0",
		NodeUnderlays: map[string][]netip.Addr{"node-b": {netip.MustParseAddr("172.30.0.12"), netip.MustParseAddr("fd00::12")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != "netns" || result.Device != "netns" || result.LocalAddresses != 1 || result.RemoteRoutes != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"net.ipv6.conf.all.forwarding=1",
		"ip netns add nl-prod_x000000pod-a",
		"ip addr replace fd00::1/128 dev",
		" nodad",
		"ip netns exec nl-prod_x000000pod-a ip addr replace fd00:10::10/128 dev eth0 nodad",
		"ip netns exec nl-prod_x000000pod-a ip route replace default via fd00::1 dev eth0 onlink",
		"ip route replace fd00:10::11/128 via fd00::12 dev eth0 proto 187",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanProgramsProviderNetworkVLANLinkForLocalEndpoints(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "eth1",
			}},
		}},
		Subnets: []model.Subnet{{
			Name:            "baremetal",
			VPC:             "prod",
			CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
			Gateway:         netip.MustParseAddr("10.10.0.1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
		}},
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "baremetal",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
	}
	ops, _, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringifyOps(ops)
	linkName := providerNetworkLinkName("physnet-a", "eth1", 100)
	for _, expected := range []string{
		"ip link show " + linkName + " >/dev/null 2>&1 || ip link add link eth1 name " + linkName + " type vlan id 100",
		"ip link set " + linkName + " up",
		"ip addr replace 10.10.0.10/32 dev nl0",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("provider vlan link ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanProgramsProviderNetworkVLANLinkWithoutLocalEndpoints(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "eth1",
			}},
		}},
		Subnets: []model.Subnet{{
			Name:            "baremetal",
			VPC:             "prod",
			CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
			Gateway:         netip.MustParseAddr("10.10.0.1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
		}},
	}
	ops, result, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderNetworks != 1 || result.ProviderLinks != 1 {
		t.Fatalf("provider counts = %+v, want provider_networks=1 provider_links=1", result)
	}
	joined := stringifyOps(ops)
	linkName := providerNetworkLinkName("physnet-a", "eth1", 100)
	for _, expected := range []string{
		"ip link show " + linkName + " >/dev/null 2>&1 || ip link add link eth1 name " + linkName + " type vlan id 100",
		"ip link set " + linkName + " up",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("provider vlan preprovision ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanSkipsProviderSubnetWithoutNodeMappingWhenNoLocalEndpoints(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-b",
				Interface: "eth1",
			}},
		}},
		Subnets: []model.Subnet{{
			Name:            "baremetal",
			VPC:             "prod",
			CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
			Gateway:         netip.MustParseAddr("10.10.0.1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
		}},
	}
	ops, result, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderNetworks != 0 || result.ProviderLinks != 0 {
		t.Fatalf("provider counts = %+v, want provider_networks=0 provider_links=0", result)
	}
	joined := stringifyOps(ops)
	if strings.Contains(joined, "type vlan id 100") {
		t.Fatalf("unexpected provider vlan preprovision on non-participating node:\n%s", joined)
	}
}

func TestPlanCleansStaleProviderNetworkVLANLinks(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "eth1",
			}},
		}},
		Subnets: []model.Subnet{{
			Name:            "baremetal",
			VPC:             "prod",
			CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
			Gateway:         netip.MustParseAddr("10.10.0.1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
		}},
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "baremetal",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
	}
	ops, result, err := Plan(context.Background(), state, Options{
		Node:         "node-a",
		LocalDevice:  "nl0",
		CleanupStale: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.CleanupPlanned {
		t.Fatal("cleanup was not marked as planned")
	}
	linkName := providerNetworkLinkName("physnet-a", "eth1", 100)
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"grep '^nlv'",
		" " + linkName + " ",
		"ip link del \"$link\"",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("provider vlan cleanup ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanRejectsProviderSubnetWithoutParentLinkMapping(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-b",
				Interface: "eth1",
			}},
		}},
		Subnets: []model.Subnet{{
			Name:            "baremetal",
			VPC:             "prod",
			CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
			Gateway:         netip.MustParseAddr("10.10.0.1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
		}},
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "baremetal",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
	}
	_, _, err := Plan(context.Background(), state, Options{Node: "node-a", LocalDevice: "nl0"})
	if err == nil || !strings.Contains(err.Error(), `provider network "physnet-a" requires parent device mapping on node "node-a"`) {
		t.Fatalf("err = %v, want missing provider mapping failure", err)
	}
}

func TestPlanRejectsConflictingProviderNetworksOnSameParentVLAN(t *testing.T) {
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
				Name:            "baremetal-a",
				VPC:             "prod",
				CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
				Gateway:         netip.MustParseAddr("10.10.0.1"),
				ProviderNetwork: "physnet-a",
				VLAN:            100,
			},
			{
				Name:            "baremetal-b",
				VPC:             "prod",
				CIDR:            netip.MustParsePrefix("10.20.0.0/24"),
				Gateway:         netip.MustParseAddr("10.20.0.1"),
				ProviderNetwork: "physnet-b",
				VLAN:            100,
			},
		},
		Endpoints: []model.Endpoint{
			{
				ID:     "pod-a",
				VPC:    "prod",
				Subnet: "baremetal-a",
				IP:     netip.MustParseAddr("10.10.0.10"),
				Node:   "node-a",
			},
			{
				ID:     "pod-b",
				VPC:    "prod",
				Subnet: "baremetal-b",
				IP:     netip.MustParseAddr("10.20.0.10"),
				Node:   "node-a",
			},
		},
	}
	_, _, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
	})
	if err == nil || !strings.Contains(err.Error(), `provider networks "physnet-a" and "physnet-b" both require parent eth1 vlan 100`) {
		t.Fatalf("err = %v, want conflicting provider network failure", err)
	}
}

func TestPlanDeduplicatesSharedProviderNetworkLinkAcrossSubnets(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "eth1",
			}},
		}},
		Subnets: []model.Subnet{
			{
				Name:            "baremetal-a",
				VPC:             "prod",
				CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
				Gateway:         netip.MustParseAddr("10.10.0.1"),
				ProviderNetwork: "physnet-a",
				VLAN:            100,
			},
			{
				Name:            "baremetal-b",
				VPC:             "prod",
				CIDR:            netip.MustParsePrefix("10.20.0.0/24"),
				Gateway:         netip.MustParseAddr("10.20.0.1"),
				ProviderNetwork: "physnet-a",
				VLAN:            100,
			},
		},
		Endpoints: []model.Endpoint{
			{
				ID:     "pod-a",
				VPC:    "prod",
				Subnet: "baremetal-a",
				IP:     netip.MustParseAddr("10.10.0.10"),
				Node:   "node-a",
			},
			{
				ID:     "pod-b",
				VPC:    "prod",
				Subnet: "baremetal-b",
				IP:     netip.MustParseAddr("10.20.0.10"),
				Node:   "node-a",
			},
		},
	}
	ops, _, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
	})
	if err != nil {
		t.Fatal(err)
	}
	linkName := providerNetworkLinkName("physnet-a", "eth1", 100)
	joined := stringifyOps(ops)
	if got := strings.Count(joined, "ip link show "+linkName+" >/dev/null 2>&1 || ip link add link eth1 name "+linkName+" type vlan id 100"); got != 1 {
		t.Fatalf("provider vlan create count = %d, want 1:\n%s", got, joined)
	}
	if got := strings.Count(joined, "ip link set "+linkName+" up"); got != 1 {
		t.Fatalf("provider vlan setup count = %d, want 1:\n%s", got, joined)
	}
}

func TestPlanPrefersStateProviderNetworkMappingOverEnvFallback(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "bond0",
			}},
		}},
		Subnets: []model.Subnet{{
			Name:            "baremetal",
			VPC:             "prod",
			CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
			Gateway:         netip.MustParseAddr("10.10.0.1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
		}},
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "baremetal",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
	}
	ops, _, err := Plan(context.Background(), state, Options{
		Node:          "node-a",
		LocalDevice:   "nl0",
		ProviderLinks: map[string]string{"physnet-a": "eth1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringifyOps(ops)
	linkName := providerNetworkLinkName("physnet-a", "bond0", 100)
	if !strings.Contains(joined, "ip link show "+linkName+" >/dev/null 2>&1 || ip link add link bond0 name "+linkName+" type vlan id 100") {
		t.Fatalf("state provider mapping should override env fallback:\n%s", joined)
	}
	if strings.Contains(joined, "link eth1 name") {
		t.Fatalf("state provider mapping should not fall back to env parent when node mapping exists:\n%s", joined)
	}
}

func TestPlanRemoteRouteCleanupDeletesOnlyManagedStaleRoutes(t *testing.T) {
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
		NodeUnderlays: map[string][]netip.Addr{
			"node-b": {netip.MustParseAddr("172.30.0.12")},
		},
		CleanupStale: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.CleanupPlanned {
		t.Fatal("cleanup was not marked as planned")
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"ip route replace 10.10.0.11/32 via 172.30.0.12 dev eth9 proto 187",
		"ip $family -o route show proto 187 dev eth9",
		" 10.10.0.11/32 ",
		"ip $family route del \"$dst\" dev eth9 proto 187",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("managed remote route cleanup missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanLocalAddressCleanupDeletesOnlyManagedEndpointAddresses(t *testing.T) {
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
				ID:     "pod-v6",
				VPC:    "prod",
				Subnet: "apps-v6",
				IP:     netip.MustParseAddr("fd00:10::10"),
				Node:   "node-a",
			},
		},
	}
	ops, result, err := Plan(context.Background(), state, Options{
		Node:         "node-a",
		LocalDevice:  "nl0",
		CleanupStale: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.CleanupPlanned {
		t.Fatal("cleanup was not marked as planned")
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"ip $family -o addr show dev nl0",
		" 10.10.0.10/32 fd00:10::10/128 ",
		"127.0.0.1/8|::1/128",
		"ip $family addr del \"$addr\" dev nl0",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("managed local address cleanup missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanNetNSLocalRouteCleanupDeletesOnlyManagedHostVethRoutes(t *testing.T) {
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
				ID:     "pod-v6",
				VPC:    "prod",
				Subnet: "apps-v6",
				IP:     netip.MustParseAddr("fd00:10::10"),
				Node:   "node-a",
			},
		},
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
	for _, expected := range []string{
		"ip $family -o route show table main",
		"dev ~ /^nlh/",
		" 10.10.0.10/32 fd00:10::10/128 ",
		"ip $family route del \"$dst\" dev \"$dev\"",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("managed netns route cleanup missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanProgramsLinuxPolicyRoutes(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "https-via-fw",
			VPC:      "prod",
			Priority: 200,
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
		}, {
			Name:     "drop-lab",
			VPC:      "prod",
			Priority: 100,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("198.51.100.0/24"),
			},
			Action: model.RouteAction{Type: model.ActionDrop},
		}},
	}

	ops, result, err := Plan(context.Background(), state, Options{
		Node:            "node-a",
		LocalDevice:     "nl0",
		UnderlayDevice:  "eth9",
		PolicyTableBase: 20000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyRoutes != 2 {
		t.Fatalf("policy routes = %d, want 2", result.PolicyRoutes)
	}
	joined := stringifyOps(ops)
	tables := mustPolicyTables(t, state.PolicyRoutes, Options{PolicyTableBase: 20000, PolicyTableSize: 1024})
	httpsTable := tables[policyRouteTableKey(state.PolicyRoutes[0])]
	dropTable := tables[policyRouteTableKey(state.PolicyRoutes[1])]
	for _, expected := range []string{
		fmt.Sprintf("ip route replace 172.16.0.0/16 via 10.10.0.253 dev eth9 table %d", httpsTable),
		fmt.Sprintf("ip rule add priority 9800 from 10.10.0.0/24 to 172.16.0.0/16 ipproto tcp dport 443 table %d protocol 186", httpsTable),
		fmt.Sprintf("ip route replace blackhole 198.51.100.0/24 table %d", dropTable),
		fmt.Sprintf("ip rule add priority 9900 from 10.10.0.0/24 to 198.51.100.0/24 table %d protocol 186", dropTable),
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("policy route ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanProgramsAllowPolicyRouteToMainTable(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "allow-https",
			VPC:      "prod",
			Priority: 300,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("198.51.100.10/32"),
				Protocol:    model.ProtocolTCP,
				DstPorts:    []model.PortRange{{From: 443, To: 443}},
			},
			Action: model.RouteAction{Type: model.ActionAllow},
		}, {
			Name:     "drop-lab",
			VPC:      "prod",
			Priority: 100,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("198.51.100.0/24"),
			},
			Action: model.RouteAction{Type: model.ActionDrop},
		}},
	}

	ops, result, err := Plan(context.Background(), state, Options{
		Node:            "node-a",
		LocalDevice:     "nl0",
		UnderlayDevice:  "eth9",
		PolicyTableBase: 20000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyRoutes != 2 {
		t.Fatalf("policy routes = %d, want 2", result.PolicyRoutes)
	}
	joined := stringifyOps(ops)
	tables := mustPolicyTables(t, state.PolicyRoutes, Options{PolicyTableBase: 20000, PolicyTableSize: 1024})
	dropTable := tables[policyRouteTableKey(state.PolicyRoutes[1])]
	for _, expected := range []string{
		"ip rule add priority 9700 from 10.10.0.0/24 to 198.51.100.10/32 ipproto tcp dport 443 table 254 protocol 186",
		fmt.Sprintf("ip route replace blackhole 198.51.100.0/24 table %d", dropTable),
		fmt.Sprintf("ip rule add priority 9900 from 10.10.0.0/24 to 198.51.100.0/24 table %d protocol 186", dropTable),
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("allow policy route ops missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "ip route replace 198.51.100.10/32") {
		t.Fatalf("allow policy route must not program a managed route table:\n%s", joined)
	}
}

func TestPlanProgramsIPv6LinuxPolicyRoute(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps-v6",
			IP:     netip.MustParseAddr("fd00:10::10"),
			Node:   "node-a",
		}},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "v6-via-fw",
			VPC:      "prod",
			Priority: 200,
			Match: model.RouteMatch{
				Source:   netip.MustParsePrefix("fd00:10::/64"),
				Protocol: model.ProtocolICMP,
			},
			Action: model.RouteAction{
				Type:     model.ActionReroute,
				NextHops: []netip.Addr{netip.MustParseAddr("fd00:10::fe")},
			},
		}},
	}

	ops, result, err := Plan(context.Background(), state, Options{
		Node:            "node-a",
		LocalDevice:     "nl0",
		UnderlayDevice:  "eth9",
		PolicyTableBase: 20000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyRoutes != 1 {
		t.Fatalf("policy routes = %d, want 1", result.PolicyRoutes)
	}
	joined := stringifyOps(ops)
	tables := mustPolicyTables(t, state.PolicyRoutes, Options{PolicyTableBase: 20000, PolicyTableSize: 1024})
	table := tables[policyRouteTableKey(state.PolicyRoutes[0])]
	for _, expected := range []string{
		"ip addr replace fd00:10::10/128 dev nl0",
		fmt.Sprintf("ip route replace ::/0 via fd00:10::fe dev eth9 table %d", table),
		fmt.Sprintf("ip rule add priority 9800 from fd00:10::/64 ipproto ipv6-icmp table %d protocol 186", table),
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("IPv6 policy route ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanProgramsECMPPolicyRoute(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "centralized-egress",
			VPC:      "prod",
			Priority: 200,
			Match: model.RouteMatch{
				Source: netip.MustParsePrefix("10.10.0.0/24"),
			},
			Action: model.RouteAction{
				Type: model.ActionReroute,
				NextHops: []netip.Addr{
					netip.MustParseAddr("10.10.0.253"),
					netip.MustParseAddr("10.10.0.254"),
				},
			},
		}},
	}

	ops, result, err := Plan(context.Background(), state, Options{
		Node:            "node-a",
		LocalDevice:     "nl0",
		UnderlayDevice:  "eth9",
		PolicyTableBase: 20000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyRoutes != 1 {
		t.Fatalf("policy routes = %d, want 1", result.PolicyRoutes)
	}
	joined := stringifyOps(ops)
	tables := mustPolicyTables(t, state.PolicyRoutes, Options{PolicyTableBase: 20000, PolicyTableSize: 1024})
	table := tables[policyRouteTableKey(state.PolicyRoutes[0])]
	for _, expected := range []string{
		fmt.Sprintf("ip route replace 0.0.0.0/0 nexthop via 10.10.0.253 dev eth9 nexthop via 10.10.0.254 dev eth9 table %d", table),
		fmt.Sprintf("ip rule add priority 9800 from 10.10.0.0/24 table %d protocol 186", table),
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("ECMP policy route ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanProgramsSamePolicyRouteNameAcrossVPCs(t *testing.T) {
	prod := testReroutePolicyRoute("centralized-egress", 200)
	dev := testReroutePolicyRoute("centralized-egress", 100)
	dev.VPC = "dev"
	dev.Match.Source = netip.MustParsePrefix("10.20.0.0/24")
	dev.Action.NextHops = []netip.Addr{netip.MustParseAddr("10.20.0.253")}
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a"},
			{ID: "pod-b", VPC: "dev", Subnet: "apps-dev", IP: netip.MustParseAddr("10.20.0.10"), Node: "node-a"},
		},
		PolicyRoutes: []model.PolicyRoute{prod, dev},
	}

	ops, result, err := Plan(context.Background(), state, Options{
		Node:            "node-a",
		LocalDevice:     "nl0",
		UnderlayDevice:  "eth9",
		PolicyTableBase: 20000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyRoutes != 2 {
		t.Fatalf("policy routes = %d, want 2", result.PolicyRoutes)
	}
	tables := mustPolicyTables(t, state.PolicyRoutes, Options{PolicyTableBase: 20000, PolicyTableSize: 1024})
	prodTable := tables[policyRouteTableKey(prod)]
	devTable := tables[policyRouteTableKey(dev)]
	if prodTable == devTable {
		t.Fatalf("same-name routes in different VPCs share table %d", prodTable)
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{
		fmt.Sprintf("ip route replace 172.16.0.0/16 via 10.10.0.253 dev eth9 table %d", prodTable),
		fmt.Sprintf("ip rule add priority 9800 from 10.10.0.0/24 to 172.16.0.0/16 table %d protocol 186", prodTable),
		fmt.Sprintf("ip route replace 172.16.0.0/16 via 10.20.0.253 dev eth9 table %d", devTable),
		fmt.Sprintf("ip rule add priority 9900 from 10.20.0.0/24 to 172.16.0.0/16 table %d protocol 186", devTable),
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("same-name policy route op missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanCleansManagedPolicyRouteRulesWhenRequested(t *testing.T) {
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
		Node:            "node-a",
		PolicyTableBase: 22000,
		PolicyTableSize: 64,
		CleanupStale:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyRoutes != 0 {
		t.Fatalf("policy routes = %d, want 0", result.PolicyRoutes)
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"ip rule show",
		"start=22000",
		"end=22064",
		"proto=186",
		"ip rule del priority",
		"for family in '' '-6'",
		"ip $family route flush table \"$table\"",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("cleanup ops missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlanSkipsPolicyRoutesWithoutLocalVPC(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "other-vpc",
			VPC:      "other",
			Priority: 100,
			Match:    model.RouteMatch{Destination: netip.MustParsePrefix("172.16.0.0/16")},
			Action:   model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
		}},
	}
	ops, result, err := Plan(context.Background(), state, Options{Node: "node-a", UnderlayDevice: "eth9"})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyRoutes != 0 {
		t.Fatalf("policy routes = %d, want 0", result.PolicyRoutes)
	}
	if strings.Contains(stringifyOps(ops), "ip rule") {
		t.Fatalf("unexpected policy route ops:\n%s", stringifyOps(ops))
	}
}

func TestApplicablePolicyRoutesValidatesAndSkipsNonLocalRoutes(t *testing.T) {
	routes := []model.PolicyRoute{{
		Name:   "invalid-any-port",
		VPC:    "prod",
		Match:  model.RouteMatch{Protocol: model.ProtocolAny, DstPorts: []model.PortRange{{From: 53, To: 53}}},
		Action: model.RouteAction{Type: model.ActionDrop},
	}, {
		Name:   "other-vpc",
		VPC:    "other",
		Match:  model.RouteMatch{Destination: netip.MustParsePrefix("192.0.2.0/24")},
		Action: model.RouteAction{Type: model.ActionDrop},
	}, {
		Name:   "local-allow",
		VPC:    "prod",
		Match:  model.RouteMatch{Destination: netip.MustParsePrefix("203.0.113.10/32")},
		Action: model.RouteAction{Type: model.ActionAllow},
	}}
	_, err := applicablePolicyRoutes(routes, map[string]struct{}{"prod": struct{}{}})
	if err == nil {
		t.Fatal("expected local invalid policy route to fail")
	}
	applicable, err := applicablePolicyRoutes(routes, map[string]struct{}{"other": struct{}{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(applicable) != 1 || applicable[0].Name != "other-vpc" {
		t.Fatalf("applicable routes = %+v, want only other-vpc", applicable)
	}
	applicable, err = applicablePolicyRoutes(routes[1:], map[string]struct{}{"prod": struct{}{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(applicable) != 1 || applicable[0].Name != "local-allow" {
		t.Fatalf("applicable routes = %+v, want local allow route", applicable)
	}
}

func TestManagedPolicyTableRange(t *testing.T) {
	options := Options{PolicyTableBase: 22000, PolicyTableSize: 64}
	for _, table := range []int{22000, 22063} {
		if !managedPolicyTable(table, options) {
			t.Fatalf("table %d should be managed", table)
		}
	}
	for _, table := range []int{21999, 22064} {
		if managedPolicyTable(table, options) {
			t.Fatalf("table %d should not be managed", table)
		}
	}
	if got := managedPolicyTables(Options{PolicyTableBase: 22000, PolicyTableSize: 3}); !reflect.DeepEqual(got, []int{22000, 22001, 22002}) {
		t.Fatalf("managed policy tables = %#v, want exact managed range", got)
	}
}

func TestNetlinkPolicyRuleCleanupCoversIPv4AndIPv6(t *testing.T) {
	families := netlinkPolicyRuleFamilies()
	if !reflect.DeepEqual(families, []int{unix.AF_INET, unix.AF_INET6}) {
		t.Fatalf("cleanup families = %#v, want IPv4 and IPv6", families)
	}
}

func TestManagedPolicyRuleIncludesProtocolMarker(t *testing.T) {
	options := Options{PolicyTableBase: 22000, PolicyTableSize: 64}
	if !managedPolicyRule(netlink.Rule{Table: linuxMainRouteTable, Protocol: linuxPolicyRuleProtocolID}, options) {
		t.Fatal("rule with netloom protocol marker should be managed")
	}
	if managedPolicyRule(netlink.Rule{Table: linuxMainRouteTable}, options) {
		t.Fatal("main table rule without netloom protocol marker should not be managed")
	}
}

func TestPlanManagedPolicyRuleSyncAlwaysConvergesManagedRules(t *testing.T) {
	options := Options{PolicyTableBase: 22000, PolicyTableSize: 64}
	desired := []*netlink.Rule{
		{Priority: 9800, Table: 22000, Family: unix.AF_INET, Protocol: linuxPolicyRuleProtocolID},
		{Priority: 9700, Table: linuxMainRouteTable, Family: unix.AF_INET, Protocol: linuxPolicyRuleProtocolID},
	}
	existing := []netlink.Rule{
		{Priority: 9800, Table: 22000, Family: unix.AF_INET, Protocol: linuxPolicyRuleProtocolID},
		{Priority: 9900, Table: 22001, Family: unix.AF_INET, Protocol: linuxPolicyRuleProtocolID},
		{Priority: 9600, Table: linuxMainRouteTable, Family: unix.AF_INET, Protocol: linuxPolicyRuleProtocolID},
		{Priority: 9600, Table: linuxMainRouteTable, Family: unix.AF_INET},
	}

	plan := planManagedPolicyRuleSync(existing, desired, options)
	if len(plan.Delete) != 2 || !hasPolicyRule(plan.Delete, netlink.Rule{Priority: 9900, Table: 22001, Family: unix.AF_INET, Protocol: linuxPolicyRuleProtocolID}) ||
		!hasPolicyRule(plan.Delete, netlink.Rule{Priority: 9600, Table: linuxMainRouteTable, Family: unix.AF_INET, Protocol: linuxPolicyRuleProtocolID}) {
		t.Fatalf("delete = %+v, want stale managed table and stale protocol-marked main rule", plan.Delete)
	}
	if len(plan.Add) != 1 || policyRuleKey(*plan.Add[0]) != policyRuleKey(*desired[1]) {
		t.Fatalf("add = %+v, want only missing desired main-table marker rule", plan.Add)
	}
}

func hasPolicyRule(rules []*netlink.Rule, want netlink.Rule) bool {
	for _, rule := range rules {
		if rule != nil && policyRuleKey(*rule) == policyRuleKey(want) {
			return true
		}
	}
	return false
}

func TestAllocatePolicyRouteTablesKeepsExistingNamesStable(t *testing.T) {
	options := Options{PolicyTableBase: 22000, PolicyTableSize: 1024}
	routes := []model.PolicyRoute{
		testReroutePolicyRoute("web", 200),
		testReroutePolicyRoute("db", 100),
	}
	before, err := allocatePolicyRouteTables(routes, options)
	if err != nil {
		t.Fatal(err)
	}
	after, err := allocatePolicyRouteTables(append([]model.PolicyRoute{testReroutePolicyRoute("api", 300)}, routes...), options)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		key := policyRouteTableKey(route)
		if before[key] != after[key] {
			t.Fatalf("table for %s/%s changed from %d to %d after inserting another policy route", route.VPC, route.Name, before[key], after[key])
		}
	}
	webKey := policyRouteTableKey(routes[0])
	dbKey := policyRouteTableKey(routes[1])
	apiKey := policyRouteTableKey(testReroutePolicyRoute("api", 300))
	if before[webKey] == before[dbKey] || after[apiKey] == after[webKey] || after[apiKey] == after[dbKey] {
		t.Fatalf("allocated duplicate tables: before=%v after=%v", before, after)
	}
}

func TestPlanPolicyRouteTablesRemainStableAfterPriorityInsertion(t *testing.T) {
	baseState := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
		PolicyRoutes: []model.PolicyRoute{
			testReroutePolicyRoute("web", 200),
			testReroutePolicyRoute("db", 100),
		},
	}
	insertedState := baseState
	insertedState.PolicyRoutes = append([]model.PolicyRoute{testReroutePolicyRoute("api", 300)}, baseState.PolicyRoutes...)
	options := Options{
		Node:            "node-a",
		LocalDevice:     "nl0",
		UnderlayDevice:  "eth9",
		PolicyTableBase: 22000,
		PolicyTableSize: 1024,
	}

	baseOps, _, err := Plan(context.Background(), baseState, options)
	if err != nil {
		t.Fatal(err)
	}
	insertedOps, _, err := Plan(context.Background(), insertedState, options)
	if err != nil {
		t.Fatal(err)
	}
	tables := mustPolicyTables(t, baseState.PolicyRoutes, options)
	baseJoined := stringifyOps(baseOps)
	insertedJoined := stringifyOps(insertedOps)
	for _, route := range baseState.PolicyRoutes {
		expected := fmt.Sprintf("table %d", tables[policyRouteTableKey(route)])
		if !strings.Contains(baseJoined, expected) || !strings.Contains(insertedJoined, expected) {
			t.Fatalf("policy route %s/%s did not keep table %d after insertion:\nbase:\n%s\ninserted:\n%s", route.VPC, route.Name, tables[policyRouteTableKey(route)], baseJoined, insertedJoined)
		}
	}
}

func TestAllocatePolicyRouteTablesRejectsExhaustedRange(t *testing.T) {
	_, err := allocatePolicyRouteTables([]model.PolicyRoute{
		testReroutePolicyRoute("web", 200),
		testReroutePolicyRoute("db", 100),
	}, Options{PolicyTableBase: 22000, PolicyTableSize: 1})
	if err == nil {
		t.Fatal("expected exhausted policy table range to fail")
	}
}

func TestAllocatePolicyRouteTablesRejectsDuplicateNames(t *testing.T) {
	_, err := allocatePolicyRouteTables([]model.PolicyRoute{
		testReroutePolicyRoute("web", 200),
		testReroutePolicyRoute("web", 100),
	}, Options{PolicyTableBase: 22000, PolicyTableSize: 64})
	if err == nil {
		t.Fatal("expected duplicate policy route names to fail")
	}
}

func TestAllocatePolicyRouteTablesAllowsSameNameAcrossVPCs(t *testing.T) {
	prod := testReroutePolicyRoute("egress", 200)
	dev := testReroutePolicyRoute("egress", 100)
	dev.VPC = "dev"
	dev.Match.Source = netip.MustParsePrefix("10.20.0.0/24")
	dev.Action.NextHops = []netip.Addr{netip.MustParseAddr("10.20.0.253")}

	tables, err := allocatePolicyRouteTables([]model.PolicyRoute{prod, dev}, Options{PolicyTableBase: 22000, PolicyTableSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	prodTable := tables[policyRouteTableKey(prod)]
	devTable := tables[policyRouteTableKey(dev)]
	if prodTable == 0 || devTable == 0 {
		t.Fatalf("missing VPC-scoped table allocation: %v", tables)
	}
	if prodTable == devTable {
		t.Fatalf("same-name policy routes in different VPCs share table %d: %v", prodTable, tables)
	}
}

func TestPolicyRuleKeySeparatesPortsAndProtocolMarker(t *testing.T) {
	route := model.PolicyRoute{
		Name:     "https-via-fw",
		VPC:      "prod",
		Priority: 200,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("172.16.0.0/16"),
			Protocol:    model.ProtocolTCP,
			DstPorts:    []model.PortRange{{From: 443, To: 443}, {From: 8443, To: 8443}},
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	}
	rules := netlinkPolicyRules(route, linuxPolicyRulePriority(route.Priority), 20000)
	if policyRuleKey(*rules[0]) == policyRuleKey(*rules[1]) {
		t.Fatalf("policy rule keys should include destination port: %q", policyRuleKey(*rules[0]))
	}
	unmarked := *rules[0]
	unmarked.Protocol = 0
	if policyRuleKey(*rules[0]) == policyRuleKey(unmarked) {
		t.Fatalf("policy rule keys should include protocol marker: %q", policyRuleKey(*rules[0]))
	}
}

func TestRouteEquivalentDetectsNextHopChanges(t *testing.T) {
	route := testReroutePolicyRoute("web", 200)
	first, err := policyRouteNetlinkRoute(route, 22000, 10)
	if err != nil {
		t.Fatal(err)
	}
	route.Action.NextHops = []netip.Addr{netip.MustParseAddr("10.10.0.254")}
	second, err := policyRouteNetlinkRoute(route, 22000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if routeEquivalent(*first, *second) {
		t.Fatalf("routes with different next hops should not be equivalent: %#v %#v", first, second)
	}
	clone, err := policyRouteNetlinkRoute(testReroutePolicyRoute("web", 200), 22000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !routeEquivalent(*first, *clone) {
		t.Fatalf("identical routes should be equivalent: %#v %#v", first, clone)
	}

	ecmp := testReroutePolicyRoute("ecmp-web", 200)
	ecmp.Action.NextHops = []netip.Addr{netip.MustParseAddr("10.10.0.253"), netip.MustParseAddr("10.10.0.254")}
	left, err := policyRouteNetlinkRoute(ecmp, 22000, 10)
	if err != nil {
		t.Fatal(err)
	}
	ecmp.Action.NextHops = []netip.Addr{netip.MustParseAddr("10.10.0.254"), netip.MustParseAddr("10.10.0.253")}
	right, err := policyRouteNetlinkRoute(ecmp, 22000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !routeEquivalent(*left, *right) {
		t.Fatalf("ECMP routes with reordered next hops should be equivalent: %#v %#v", left, right)
	}
	right.MultiPath[0].Hops = 10
	if routeEquivalent(*left, *right) {
		t.Fatalf("ECMP routes with different next-hop weights should not be equivalent: %#v %#v", left, right)
	}
}

func TestRemoteEndpointNetlinkRouteCarriesProtocolMarker(t *testing.T) {
	route, err := remoteEndpointNetlinkRoute(netip.MustParseAddr("10.10.0.11"), netip.MustParseAddr("172.30.0.12"), 9)
	if err != nil {
		t.Fatal(err)
	}
	if route.Table != linuxMainRouteTable || route.LinkIndex != 9 || route.Dst.String() != "10.10.0.11/32" || route.Gw.String() != "172.30.0.12" {
		t.Fatalf("unexpected remote route: %+v", route)
	}
	if int(route.Protocol) != linuxRemoteRouteProtocolID {
		t.Fatalf("remote route protocol = %d, want %d", route.Protocol, linuxRemoteRouteProtocolID)
	}
}

func TestRemoteEndpointPrefixesExcludeLocalEndpoints(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{
			{ID: "pod-a", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a"},
			{ID: "pod-b", IP: netip.MustParseAddr("10.10.0.11"), Node: "node-b"},
			{ID: "pod-v6", IP: netip.MustParseAddr("fd00:10::11"), Node: "node-b"},
		},
	}
	want := []string{"10.10.0.11/32", "fd00:10::11/128"}
	if got := remoteEndpointPrefixes(state, "node-a"); !reflect.DeepEqual(got, want) {
		t.Fatalf("remote endpoint prefixes = %#v, want %#v", got, want)
	}
}

func TestNetlinkPolicyRuleEncodesL4Match(t *testing.T) {
	route := model.PolicyRoute{
		Name:     "https-via-fw",
		VPC:      "prod",
		Priority: 200,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("172.16.0.0/16"),
			Protocol:    model.ProtocolTCP,
			SrcPorts:    []model.PortRange{{From: 32000, To: 32010}},
			DstPorts:    []model.PortRange{{From: 443, To: 443}},
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	}
	rules := netlinkPolicyRules(route, linuxPolicyRulePriority(route.Priority), 20000)
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	rule := rules[0]
	if rule.Priority != 9800 || rule.Table != 20000 || rule.Src.String() != "10.10.0.0/24" || rule.Dst.String() != "172.16.0.0/16" {
		t.Fatalf("unexpected rule: %+v", rule)
	}
	if int(rule.Protocol) != linuxPolicyRuleProtocolID {
		t.Fatalf("rule protocol = %d, want %d", rule.Protocol, linuxPolicyRuleProtocolID)
	}
	if rule.IPProto != 6 || rule.Sport == nil || rule.Sport.Start != 32000 || rule.Sport.End != 32010 || rule.Dport == nil || rule.Dport.Start != 443 || rule.Dport.End != 443 {
		t.Fatalf("unexpected L4 match: proto=%d sport=%+v dport=%+v", rule.IPProto, rule.Sport, rule.Dport)
	}
}

func TestPolicyRuleArgsExpandSourceAndDestinationPortCombinations(t *testing.T) {
	route := model.PolicyRoute{
		Name:     "tenant-api",
		VPC:      "prod",
		Priority: 200,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("198.51.100.0/24"),
			Protocol:    model.ProtocolTCP,
			SrcPorts: []model.PortRange{
				{From: 32000, To: 32000},
				{From: 32100, To: 32110},
			},
			DstPorts: []model.PortRange{
				{From: 443, To: 443},
				{From: 8443, To: 8444},
			},
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	}
	args := linuxPolicyRuleArgs(route, linuxPolicyRulePriority(route.Priority), 20000)
	if len(args) != 4 {
		t.Fatalf("policy rule args = %d, want src/dst port cross product: %v", len(args), args)
	}
	joined := strings.Join(args, "\n")
	for _, expected := range []string{
		"sport 32000 dport 443",
		"sport 32000 dport 8443-8444",
		"sport 32100-32110 dport 443",
		"sport 32100-32110 dport 8443-8444",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("policy rule args missing %q:\n%s", expected, joined)
		}
	}
}

func testReroutePolicyRoute(name string, priority int) model.PolicyRoute {
	return model.PolicyRoute{
		Name:     name,
		VPC:      "prod",
		Priority: priority,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("172.16.0.0/16"),
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	}
}

func mustPolicyTables(t *testing.T, routes []model.PolicyRoute, options Options) map[string]int {
	t.Helper()
	tables, err := allocatePolicyRouteTables(routes, options)
	if err != nil {
		t.Fatal(err)
	}
	return tables
}

func TestNetlinkPolicyRuleEncodesIPv6Family(t *testing.T) {
	route := model.PolicyRoute{
		Name:     "v6-via-fw",
		VPC:      "prod",
		Priority: 200,
		Match: model.RouteMatch{
			Source:   netip.MustParsePrefix("fd00:10::/64"),
			Protocol: model.ProtocolICMP,
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("fd00:10::fe")}},
	}
	rules := netlinkPolicyRules(route, linuxPolicyRulePriority(route.Priority), 20000)
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	rule := rules[0]
	if rule.Family != unix.AF_INET6 || rule.Src.String() != "fd00:10::/64" {
		t.Fatalf("unexpected IPv6 rule: %+v", rule)
	}
	if rule.IPProto != unix.IPPROTO_ICMPV6 {
		t.Fatalf("ipproto = %d, want ICMPv6", rule.IPProto)
	}
}

func TestManagedAddrKeyRecognizesEndpointStyleAddresses(t *testing.T) {
	tests := []struct {
		name string
		addr netlink.Addr
		want string
		ok   bool
	}{
		{
			name: "ipv4 endpoint",
			addr: netlink.Addr{IPNet: mustIPNet(t, "10.10.0.10/32")},
			want: "10.10.0.10/32",
			ok:   true,
		},
		{
			name: "ipv6 endpoint",
			addr: netlink.Addr{IPNet: mustIPNet(t, "fd00:10::10/128")},
			want: "fd00:10::10/128",
			ok:   true,
		},
		{
			name: "loopback protected",
			addr: netlink.Addr{IPNet: mustIPNet(t, "::1/128")},
			ok:   false,
		},
		{
			name: "non host prefix ignored",
			addr: netlink.Addr{IPNet: mustIPNet(t, "10.10.0.0/24")},
			ok:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := managedAddrKey(tt.addr)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("managedAddrKey(%v) = %q,%t want %q,%t", tt.addr.IPNet, got, ok, tt.want, tt.ok)
			}
		})
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
	for _, expected := range []string{"ip netns list", "grep '^nl-'", " nl-prod_x000000pod-a ", "ip netns del"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("cleanup ops missing %q:\n%s", expected, joined)
		}
	}
}

func mustIPNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return ipNet
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

func TestNetNSNamesEncodeEndpointIDsWithoutCollisions(t *testing.T) {
	tests := map[string]string{
		"pod.1":          "nl-pod_d1",
		"pod_1":          "nl-pod__1",
		"pod/1":          "nl-pod_s1",
		"pod:1":          "nl-pod_c1",
		"pod 1":          "nl-pod_w1",
		"pod-1":          "nl-pod-1",
		"pod\U0001f6001": "nl-pod_x01f6001",
	}
	seen := make(map[string]string, len(tests))
	for endpointID, want := range tests {
		got := netnsName(endpointID, "nl")
		if got != want {
			t.Fatalf("netnsName(%q) = %q, want %q", endpointID, got, want)
		}
		if prev := seen[got]; prev != "" {
			t.Fatalf("endpoint IDs %q and %q collided on netns name %q", prev, endpointID, got)
		}
		seen[got] = endpointID
	}
	if got := netnsName("", "nl"); got != "nl-" {
		t.Fatalf("empty endpoint prefix = %q, want cleanup prefix nl-", got)
	}
}

func TestNetNSNamesDifferentVPCsDoNotCollide(t *testing.T) {
	prod := netnsName(model.EndpointKey("prod", "pod-a"), "nl")
	dev := netnsName(model.EndpointKey("dev", "pod-a"), "nl")
	if prod == dev {
		t.Fatalf("netns names for different VPCs colliding: %q", prod)
	}
	if prod != "nl-prod_x000000pod-a" {
		t.Fatalf("prod vpc netns = %q, want nl-prod_x000000pod-a", prod)
	}
	if dev != "nl-dev_x000000pod-a" {
		t.Fatalf("dev vpc netns = %q, want nl-dev_x000000pod-a", dev)
	}
}

func TestListManagedNetNSFiltersByPrefix(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"nl-pod-a", "nl-pod-b", "other-pod", "nlx-pod"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	names, err := listManagedNetNSAt(dir, "nl")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"nl-pod-a", "nl-pod-b"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %#v, want %#v", names, want)
	}
}

func TestNormalizeOptionsDefaultsNetlinkSettings(t *testing.T) {
	options, result, err := normalizeOptions(Options{Node: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	if options.Mode != "local" || options.LocalDevice != "lo" || options.UnderlayDevice != "eth0" || options.WorkloadIF != "eth0" {
		t.Fatalf("unexpected defaults: %+v", options)
	}
	if options.HostGateway != netip.MustParseAddr("169.254.1.1") {
		t.Fatalf("host gateway = %s", options.HostGateway)
	}
	if options.PolicyTableBase != 10000 {
		t.Fatalf("policy table base = %d, want 10000", options.PolicyTableBase)
	}
	if result.Device != "lo" || result.Mode != "local" {
		t.Fatalf("unexpected result defaults: %+v", result)
	}
}

func TestWorkloadHostGatewayChoosesFamilyAwareDefault(t *testing.T) {
	if got := workloadHostGateway(netip.MustParseAddr("10.10.0.10"), netip.Addr{}); got != netip.MustParseAddr("169.254.1.1") {
		t.Fatalf("ipv4 host gateway = %s, want 169.254.1.1", got)
	}
	if got := workloadHostGateway(netip.MustParseAddr("fd00:10::10"), netip.Addr{}); got != netip.MustParseAddr("fd00::1") {
		t.Fatalf("ipv6 host gateway = %s, want fd00::1", got)
	}
	if got := workloadHostGateway(netip.MustParseAddr("fd00:10::10"), netip.MustParseAddr("169.254.1.1")); got != netip.MustParseAddr("fd00::1") {
		t.Fatalf("ipv6 host gateway with mismatched configured family = %s, want fd00::1", got)
	}
	if got := workloadHostGateway(netip.MustParseAddr("fd00:10::10"), netip.MustParseAddr("fd00::1")); got != netip.MustParseAddr("fd00::1") {
		t.Fatalf("ipv6 host gateway should keep matching configured family, got %s", got)
	}
}

func TestResolveNodePrefersMatchingAddressFamilyFromConfiguredUnderlays(t *testing.T) {
	underlays := map[string][]netip.Addr{
		"node-b": {
			netip.MustParseAddr("172.30.0.12"),
			netip.MustParseAddr("fd00::12"),
		},
	}

	got4, err := resolveNode(context.Background(), "node-b", netip.MustParseAddr("10.10.0.11"), underlays)
	if err != nil {
		t.Fatal(err)
	}
	if got4 != netip.MustParseAddr("172.30.0.12") {
		t.Fatalf("resolveNode(ipv4) = %s, want 172.30.0.12", got4)
	}

	got6, err := resolveNode(context.Background(), "node-b", netip.MustParseAddr("fd00:10::11"), underlays)
	if err != nil {
		t.Fatal(err)
	}
	if got6 != netip.MustParseAddr("fd00::12") {
		t.Fatalf("resolveNode(ipv6) = %s, want fd00::12", got6)
	}
}

func TestDatapathBackendDefaultsToNetlink(t *testing.T) {
	if got := datapathBackend(""); got != "netlink" {
		t.Fatalf("default backend = %s, want netlink", got)
	}
	if got := datapathBackend("command"); got != "command" {
		t.Fatalf("explicit backend = %s, want command", got)
	}
}

func stringifyOps(ops []Operation) string {
	lines := make([]string, 0, len(ops))
	for _, op := range ops {
		lines = append(lines, op.Command+" "+strings.Join(op.Args, " "))
	}
	return strings.Join(lines, "\n")
}
