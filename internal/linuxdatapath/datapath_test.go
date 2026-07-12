package linuxdatapath

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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
	if result.ProviderInventoryTotal != 0 || result.ProviderInventoryReady != 0 || result.ProviderInventoryDegraded != 0 {
		t.Fatalf("provider inventory summary = %+v, want zero inventory in pure planner path", result)
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

func TestPlanSyncsProviderBridgeMappingsToOVSDB(t *testing.T) {
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
	ops, _, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
		SyncOVSDB:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	link := providerNetworkLinkName("physnet-a", "eth1", 100)
	bridge := providerNetworkBridgeName("physnet-a")
	want := []Operation{
		shellOperation("ip link show " + link + " >/dev/null 2>&1 || ip link add link eth1 name " + link + " type vlan id 100"),
		{Command: "ip", Args: []string{"link", "set", link, "up"}},
		{Command: "ovs-vsctl", Args: []string{"--may-exist", "add-br", bridge}},
		{Command: "ovs-vsctl", Args: []string{"set", "bridge", bridge, "external_ids:netloom_owner=netloom", "external_ids:netloom_provider_network=physnet-a"}},
		planProviderOVSDBPort(bridge, link),
		{Command: "ovs-vsctl", Args: []string{"set", "port", link, "external_ids:netloom_owner=netloom", "external_ids:netloom_parent_device=eth1", "external_ids:netloom_provider_network=physnet-a", "external_ids:netloom_vlan=100"}},
		planProviderOVSDBClearManagedQoS(link),
		{Command: "ovs-vsctl", Args: []string{"set", "interface", link, "external_ids:netloom_owner=netloom", "external_ids:netloom_parent_device=eth1", "external_ids:netloom_provider_network=physnet-a", "external_ids:netloom_vlan=100"}},
		{Command: "ovs-vsctl", Args: []string{"set", "Open_vSwitch", ".", "external_ids:netloom_identity_groups=", "external_ids:netloom_owner=netloom", "external_ids:ovn-bridge-mappings=physnet-a:" + bridge}},
		{Command: "ip", Args: []string{"link", "set", "nl0", "up"}},
		{Command: "ip", Args: []string{"addr", "replace", "10.10.0.10/32", "dev", "nl0"}},
	}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("ops = %#v, want %#v", ops, want)
	}
}

func TestApplyRejectsCommandBackend(t *testing.T) {
	_, err := Apply(context.Background(), control.DesiredState{}, Options{Backend: "command"})
	if err == nil || !strings.Contains(err.Error(), "command backend has been removed") {
		t.Fatalf("err = %v, want command backend removed error", err)
	}
}

func TestExecuteProviderOVSDBSyncUsesDirectSyncer(t *testing.T) {
	syncer := &recordingProviderOVSDBSyncer{}
	var flowCleanupOps int
	err := executeProviderOVSDBSync(context.Background(), Options{
		SyncOVSDB:           true,
		ProviderOVSDBSyncer: syncer,
		Executor: commandExecutorFunc(func(_ context.Context, op Operation) error {
			if op.Command == "ovs-vsctl" {
				t.Fatalf("direct provider OVSDB sync should avoid ovs-vsctl op: %+v", op)
			}
			if op.Command == "sh" && strings.Contains(strings.Join(op.Args, " "), "ovs-ofctl") {
				flowCleanupOps++
				return nil
			}
			t.Fatalf("unexpected direct provider OVSDB sync command op: %+v", op)
			return nil
		}),
	}, control.DesiredState{}, []providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if syncer.calls != 1 || !syncer.cleanup {
		t.Fatalf("syncer calls=%d cleanup=%t, want one cleanup sync", syncer.calls, syncer.cleanup)
	}
	if flowCleanupOps != 1 {
		t.Fatalf("flow cleanup ops = %d, want one", flowCleanupOps)
	}
}

func TestExecuteProviderOVSDBSyncRequiresDirectSyncer(t *testing.T) {
	err := executeProviderOVSDBSync(context.Background(), Options{
		SyncOVSDB: true,
	}, control.DesiredState{}, []providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}}, false)
	if err == nil || !strings.Contains(err.Error(), "requires libovsdb syncer") {
		t.Fatalf("err = %v, want direct OVSDB syncer requirement", err)
	}
}

func TestAppendProviderOVSDBIssuesUsesDirectStatusReader(t *testing.T) {
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
	reader := staticProviderOVSDBStatusReader{statuses: []ProviderOVSDBStatus{{
		ProviderNetwork: "physnet-a",
		Bridge:          providerNetworkBridgeName("physnet-a"),
		LinkName:        providerNetworkLinkName("physnet-a", "eth1", 100),
		ParentDevice:    "eth1",
		VLAN:            100,
		BridgeState:     "up",
		MappingState:    "missing",
		PortState:       "up",
		InterfaceState:  "up",
	}}}
	inventory := []ProviderInterface{{Name: "eth1", Ready: true}, {Name: providerNetworkLinkName("physnet-a", "eth1", 100), Ready: true}}
	specs, err := desiredProviderNetworkLinkSpecs(state, "node-a", nil, inventory)
	if err != nil {
		t.Fatal(err)
	}
	result := Result{
		ProviderStatus: providerLinkStatusesFromInventory(specs, inventory),
	}
	result.ProviderReady, result.ProviderDegraded = summarizeProviderLinkHealth(result.ProviderStatus)
	result.ProviderNetworkStatus = providerNetworkStatuses(state, result.ProviderStatus, result.ProviderIssues)

	err = appendProviderOVSDBIssues(context.Background(), &result, state, Options{
		Node:                "node-a",
		SyncOVSDB:           true,
		ProviderOVSDBSyncer: &recordingProviderOVSDBSyncer{},
		ProviderOVSDBReader: reader,
	}, specs)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProviderHealth(result, Options{StrictProviderHealth: true}); err == nil || !strings.Contains(err.Error(), "ovsdb-mapping-missing") {
		t.Fatalf("err = %v, want strict provider health failure with direct OVSDB reader issue", err)
	}
	if !providerIssuesContainReason(result.ProviderIssues, "ovsdb-mapping-missing") {
		t.Fatalf("provider issues = %+v, want ovsdb-mapping-missing", result.ProviderIssues)
	}
	if len(result.ProviderNetworkStatus) != 1 || !providerNetworkStatusContainsReason(result.ProviderNetworkStatus[0], "ovsdb-mapping-missing") {
		t.Fatalf("provider network status = %+v, want mapping issue", result.ProviderNetworkStatus)
	}
}

type recordingProviderOVSDBSyncer struct {
	calls   int
	rows    ProviderOVSDBDesiredRows
	cleanup bool
}

func (s *recordingProviderOVSDBSyncer) SyncProviderOVSDB(_ context.Context, rows ProviderOVSDBDesiredRows, cleanup bool) error {
	s.calls++
	s.rows = rows
	s.cleanup = cleanup
	return nil
}

type staticProviderOVSDBStatusReader struct {
	statuses []ProviderOVSDBStatus
	err      error
}

func (r staticProviderOVSDBStatusReader) ReadProviderOVSDBStatus(context.Context, ProviderOVSDBDesiredRows) ([]ProviderOVSDBStatus, error) {
	return append([]ProviderOVSDBStatus(nil), r.statuses...), r.err
}

func TestPlanClearsProviderBridgeMappingsWhenOVSDBSyncHasNoProviders(t *testing.T) {
	ops, _, err := Plan(context.Background(), control.DesiredState{}, Options{
		Node:      "node-a",
		SyncOVSDB: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []Operation{
		{Command: "ovs-vsctl", Args: []string{"set", "Open_vSwitch", ".", "external_ids:netloom_owner=netloom", "external_ids:ovn-bridge-mappings=", "external_ids:netloom_identity_groups="}},
		{Command: "ip", Args: []string{"link", "set", "lo", "up"}},
	}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("ops = %#v, want %#v", ops, want)
	}
}

func TestPlanProviderOVSDBPortRepairsWrongBridgeDrift(t *testing.T) {
	op := planProviderOVSDBPort("nlbr-good", "nlv100")
	script := strings.Join(op.Args, " ")
	for _, expected := range []string{
		"ovs-vsctl port-to-br nlv100",
		"[ \"$current\" != nlbr-good ]",
		"ovs-vsctl --if-exists del-port \"$current\" nlv100",
		"ovs-vsctl --may-exist add-port nlbr-good nlv100",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("provider ovsdb port repair script missing %q:\n%s", expected, script)
		}
	}
}

func TestPlanProviderOVSDBMappingsDeduplicatesProviderBridgeMappings(t *testing.T) {
	bridge := providerNetworkBridgeName("physnet-a")
	ops := planProviderOVSDBMappings([]providerNetworkLinkSpec{
		{ProviderNetwork: "physnet-a", ParentDevice: "eth1", VLAN: 100, Name: "nlv100"},
		{ProviderNetwork: "physnet-a", ParentDevice: "eth1", VLAN: 200, Name: "nlv200"},
	})
	if len(ops) == 0 {
		t.Fatal("expected ovsdb operations")
	}
	last := ops[len(ops)-1]
	want := Operation{Command: "ovs-vsctl", Args: []string{"set", "Open_vSwitch", ".", "external_ids:netloom_identity_groups=", "external_ids:netloom_owner=netloom", "external_ids:ovn-bridge-mappings=physnet-a:" + bridge}}
	if !reflect.DeepEqual(last, want) {
		t.Fatalf("last op = %#v, want %#v", last, want)
	}
}

func TestPlanProviderOVSDBMappingsProgramsQoSAndQueues(t *testing.T) {
	ops := planProviderOVSDBMappings([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
		QoS: model.ProviderNetworkQoS{
			EgressRateBPS: 1000000000,
		},
		TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
			Tenant:     "prod",
			QueueID:    10,
			MaxRateBPS: 500000000,
		}},
	}})
	var script string
	for _, op := range ops {
		if op.Command == "sh" && strings.Contains(strings.Join(op.Args, " "), "find qos external_ids:netloom_owner=netloom external_ids:netloom_provider_qos='qos-nlv100'") {
			script = strings.Join(op.Args, " ")
			break
		}
	}
	if script == "" {
		t.Fatalf("ops = %#v, want provider QoS sync script", ops)
	}
	for _, expected := range []string{
		"find qos external_ids:netloom_owner=netloom external_ids:netloom_provider_qos='qos-nlv100'",
		"create qos 'external_ids:netloom_owner=netloom'",
		"set qos \"$qos\" type='linux-htb' queues={}",
		"'other_config:max-rate=1000000000'",
		"find queue external_ids:netloom_owner=netloom external_ids:netloom_provider_queue='queue-nlv100-10'",
		"create queue 'external_ids:netloom_owner=netloom'",
		"clear queue \"$queue_10\" external_ids other_config",
		"set queue \"$queue_10\"",
		"'other_config:max-rate=500000000'",
		"set qos \"$qos\" queues:10=\"$queue_10\"",
		"set port 'nlv100' qos=\"$qos\"",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("provider QoS script missing %q:\n%s", expected, script)
		}
	}
}

func TestDesiredProviderOVSDBRowsBuildsTypedVSwitchRows(t *testing.T) {
	bridgeA := providerNetworkBridgeName("physnet-a")
	bridgeB := providerNetworkBridgeName("physnet-b")
	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{
		{ProviderNetwork: "physnet-b", ParentDevice: "eth2", VLAN: 200, Name: "nlv200"},
		{
			ProviderNetwork: "physnet-a",
			ParentDevice:    "eth1",
			VLAN:            100,
			Name:            "nlv100",
			Isolation:       "exclusive",
			ControllerTargets: []string{
				"tcp:192.0.2.10:6653",
			},
			QoS: model.ProviderNetworkQoS{EgressRateBPS: 1000000000, EgressBurstBPS: 64000},
			TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
				Tenant:   "prod",
				QueueID:  10,
				Protocol: model.ProtocolTCP,
				Ports:    []model.PortRange{{From: 443, To: 443}},
				EndpointSelector: model.Labels{
					"app": "web",
				},
				EndpointExpressions: []model.LabelExpr{{
					Key:      "env",
					Operator: "In",
					Values:   []string{"prod"},
				}},
				IdentitySelector: model.Labels{
					"tier": "frontend",
				},
				IdentityExpressions: []model.LabelExpr{{
					Key:      "role",
					Operator: "In",
					Values:   []string{"api"},
				}},
				IdentityGroups: []string{"frontend-api"},
				MaxRateBPS:     500000000,
			}},
		},
		{ProviderNetwork: "physnet-a", ParentDevice: "eth1", VLAN: 300, Name: "nlv300", Isolation: "exclusive"},
	})

	if got, want := rows.OpenVSwitch.ExternalIDs["ovn-bridge-mappings"], "physnet-a:"+bridgeA+",physnet-b:"+bridgeB; got != want {
		t.Fatalf("ovn-bridge-mappings = %q, want %q", got, want)
	}
	wantBridges := []string{bridgeA, bridgeB}
	sort.Strings(wantBridges)
	if !reflect.DeepEqual(rows.OpenVSwitch.Bridges, wantBridges) {
		t.Fatalf("open_vswitch bridges = %#v", rows.OpenVSwitch.Bridges)
	}
	if len(rows.Bridges) != 2 || rows.Bridges[0].Name != wantBridges[0] || rows.Bridges[1].Name != wantBridges[1] {
		t.Fatalf("bridges = %#v", rows.Bridges)
	}
	bridgePorts := make(map[string][]string, len(rows.Bridges))
	for _, bridge := range rows.Bridges {
		bridgePorts[bridge.ExternalIDs["netloom_provider_network"]] = bridge.Ports
	}
	if !reflect.DeepEqual(bridgePorts["physnet-a"], []string{"nlv100", "nlv300"}) {
		t.Fatalf("bridge physnet-a ports = %#v", bridgePorts["physnet-a"])
	}
	for _, bridge := range rows.Bridges {
		if bridge.ExternalIDs["netloom_provider_network"] == "physnet-a" && bridge.ExternalIDs["netloom_provider_isolation"] != "exclusive" {
			t.Fatalf("bridge external IDs = %+v, want exclusive isolation", bridge.ExternalIDs)
		}
	}
	if len(rows.Controllers) != 1 || rows.Controllers[0].Target != "tcp:192.0.2.10:6653" || rows.Controllers[0].ExternalIDs["netloom_provider_network"] != "physnet-a" {
		t.Fatalf("controllers = %+v, want physnet-a controller target", rows.Controllers)
	}
	for _, bridge := range rows.Bridges {
		if bridge.ExternalIDs["netloom_provider_network"] == "physnet-a" && len(bridge.Controller) != 1 {
			t.Fatalf("bridge controllers = %+v, want physnet-a controller identity", bridge.Controller)
		}
	}
	if len(rows.Ports) != 3 || rows.Ports[0].Name != "nlv100" || rows.Ports[0].Interfaces[0] != "nlv100" {
		t.Fatalf("ports = %#v", rows.Ports)
	}
	if got := rows.Interfaces[0].ExternalIDs["netloom_parent_device"]; got != "eth1" {
		t.Fatalf("interface parent external id = %q, want eth1", got)
	}
	if got := rows.Ports[0].ExternalIDs["netloom_provider_isolation"]; got != "exclusive" {
		t.Fatalf("port isolation external id = %q, want exclusive", got)
	}
	if rows.Ports[0].QOS == nil || *rows.Ports[0].QOS != "qos-nlv100" {
		t.Fatalf("port qos = %v, want qos-nlv100", rows.Ports[0].QOS)
	}
	if len(rows.QoS) != 1 || rows.QoS[0].Type != "linux-htb" || rows.QoS[0].OtherConfig["max-rate"] != "1000000000" || rows.QoS[0].OtherConfig["burst"] != "64000" {
		t.Fatalf("qos rows = %+v, want linux-htb max-rate and burst", rows.QoS)
	}
	if got := rows.QoS[0].ExternalIDs["netloom_provider_qos"]; got != "qos-nlv100" {
		t.Fatalf("qos external IDs = %+v, want qos-nlv100", rows.QoS[0].ExternalIDs)
	}
	if rows.QoS[0].Queues[10] != "queue-nlv100-10" {
		t.Fatalf("qos queues = %+v, want tenant queue ref", rows.QoS[0].Queues)
	}
	if len(rows.Queues) != 1 || rows.Queues[0].ExternalIDs["netloom_provider_queue"] != "queue-nlv100-10" || rows.Queues[0].ExternalIDs["netloom_tenant"] != "prod" {
		t.Fatalf("queue rows = %+v, want prod tenant queue", rows.Queues)
	}
	if rows.Queues[0].ExternalIDs["netloom_queue_protocol"] != "tcp" || rows.Queues[0].ExternalIDs["netloom_queue_ports"] != "443" {
		t.Fatalf("queue external IDs = %+v, want tcp/443 selector", rows.Queues[0].ExternalIDs)
	}
	if rows.Queues[0].ExternalIDs["netloom_queue_endpoint_selector"] != "app=web" || rows.Queues[0].ExternalIDs["netloom_queue_endpoint_expressions"] != "env:in:prod" {
		t.Fatalf("queue external IDs = %+v, want endpoint selector metadata", rows.Queues[0].ExternalIDs)
	}
	if rows.Queues[0].ExternalIDs["netloom_queue_identity_selector"] != "tier=frontend" || rows.Queues[0].ExternalIDs["netloom_queue_identity_expressions"] != "role:in:api" {
		t.Fatalf("queue external IDs = %+v, want identity selector metadata", rows.Queues[0].ExternalIDs)
	}
	if rows.Queues[0].ExternalIDs["netloom_queue_identity_groups"] != "frontend-api" {
		t.Fatalf("queue external IDs = %+v, want identity group metadata", rows.Queues[0].ExternalIDs)
	}
	if got := rows.Queues[0].OtherConfig["max-rate"]; got != "500000000" {
		t.Fatalf("queue max-rate = %q, want 500000000", got)
	}
	if got := rows.Interfaces[2].ExternalIDs["netloom_vlan"]; got != "300" {
		t.Fatalf("interface vlan external id = %q, want 300", got)
	}
}

func TestPlanSkipsProviderOVSDBShellCleanupWhenDirectSyncEnabled(t *testing.T) {
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
	ops, result, err := Plan(context.Background(), state, Options{
		Node:         "node-a",
		LocalDevice:  "nl0",
		SyncOVSDB:    true,
		CleanupStale: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.CleanupPlanned {
		t.Fatal("cleanup was not marked as planned")
	}
	bridge := providerNetworkBridgeName("physnet-a")
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"external_ids:ovn-bridge-mappings=physnet-a:" + bridge,
		"ip link del \"$link\"",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("provider cleanup ops missing %q:\n%s", expected, joined)
		}
	}
	for _, unexpected := range []string{
		"find bridge external_ids:netloom_owner=netloom",
		"find qos external_ids:netloom_owner=netloom",
		"find queue external_ids:netloom_owner=netloom",
		"del-br \"$br\"",
		"destroy qos \"$qos\"",
		"destroy queue \"$queue\"",
	} {
		if strings.Contains(joined, unexpected) {
			t.Fatalf("direct provider OVSDB cleanup should avoid shell fragment %q:\n%s", unexpected, joined)
		}
	}
}

func TestPlanProgramsProviderTenantQueueFlows(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "eth1",
			}},
			TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
				Tenant:     "prod",
				QueueID:    10,
				MaxRateBPS: 500000000,
			}, {
				Tenant:     "prod",
				QueueID:    11,
				Protocol:   model.ProtocolTCP,
				Ports:      []model.PortRange{{From: 443, To: 444}},
				MaxRateBPS: 100000000,
			}, {
				Tenant:           "prod",
				QueueID:          12,
				Protocol:         model.ProtocolTCP,
				Ports:            []model.PortRange{{From: 8443, To: 8443}},
				EndpointSelector: model.Labels{"app": "web"},
				MaxRateBPS:       100000000,
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
			Labels: model.Labels{"app": "web"},
		}, {
			ID:     "pod-b",
			VPC:    "prod",
			Subnet: "baremetal",
			IP:     netip.MustParseAddr("10.10.0.11"),
			Node:   "node-a",
			Labels: model.Labels{"app": "db"},
		}},
	}
	ops, _, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
		SyncOVSDB:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	bridge := providerNetworkBridgeName("physnet-a")
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"ovs-ofctl --bundle add-flow " + bridge,
		"table=0,priority=210,ip,nw_src=10.10.0.0/24,actions=set_queue:10,NORMAL",
		"table=0,priority=220,tcp,nw_src=10.10.0.0/24,tp_dst=443,actions=set_queue:11,NORMAL",
		"table=0,priority=220,tcp,nw_src=10.10.0.0/24,tp_dst=444,actions=set_queue:11,NORMAL",
		"table=0,priority=230,tcp,nw_src=10.10.0.10/32,tp_dst=8443,actions=set_queue:12,NORMAL",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("provider tenant queue flow ops missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "nw_src=10.10.0.11/32,tp_dst=8443") {
		t.Fatalf("provider tenant queue selector should not match pod-b:\n%s", joined)
	}
}

func TestPlanProgramsProviderTenantQueueIPv6Flows(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "eth1",
			}},
			TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
				Tenant:     "prod",
				QueueID:    10,
				Protocol:   model.ProtocolTCP,
				Ports:      []model.PortRange{{From: 443, To: 443}},
				MaxRateBPS: 500000000,
			}},
		}},
		Subnets: []model.Subnet{{
			Name:            "baremetal",
			VPC:             "prod",
			CIDR:            netip.MustParsePrefix("fd00:10::/64"),
			Gateway:         netip.MustParseAddr("fd00:10::1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
		}},
	}
	ops, _, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
		SyncOVSDB:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringifyOps(ops)
	if !strings.Contains(joined, "table=0,priority=220,tcp6,ipv6_src=fd00:10::/64,tp_dst=443,actions=set_queue:10,NORMAL") {
		t.Fatalf("provider tenant queue IPv6 flow ops missing:\n%s", joined)
	}
}

func TestPlanProgramsProviderTenantQueueIdentitySelectorFlows(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "eth1",
			}},
			TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
				Tenant:           "prod",
				QueueID:          20,
				IdentitySelector: model.Labels{"tier": "frontend"},
				IdentityExpressions: []model.LabelExpr{{
					Key:      "role",
					Operator: "In",
					Values:   []string{"api"},
				}},
				MaxRateBPS: 500000000,
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
			Labels: model.Labels{"tier": "frontend", "role": "api"},
		}, {
			ID:     "pod-b",
			VPC:    "prod",
			Subnet: "baremetal",
			IP:     netip.MustParseAddr("10.10.0.11"),
			Node:   "node-a",
			Labels: model.Labels{"tier": "frontend", "role": "worker"},
		}},
	}
	ops, _, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
		SyncOVSDB:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringifyOps(ops)
	if !strings.Contains(joined, "table=0,priority=225,ip,nw_src=10.10.0.10/32,actions=set_queue:20,NORMAL") {
		t.Fatalf("provider identity queue flow ops missing pod-a /32:\n%s", joined)
	}
	if strings.Contains(joined, "nw_src=10.10.0.0/24") || strings.Contains(joined, "nw_src=10.10.0.11/32") {
		t.Fatalf("provider identity queue should only match selected endpoints:\n%s", joined)
	}
}

func TestPlanProgramsProviderTenantQueueIdentityGroupFlows(t *testing.T) {
	state := control.DesiredState{
		IdentityGroups: []model.IdentityGroup{{
			Name:        "frontend-api",
			VPC:         "prod",
			EndpointIDs: []string{"pod-c"},
			EndpointSelector: model.Labels{
				"tier": "frontend",
			},
			EndpointExpressions: []model.LabelExpr{{
				Key:      "role",
				Operator: "In",
				Values:   []string{"api"},
			}},
		}},
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "eth1",
			}},
			TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
				Tenant:         "prod",
				QueueID:        30,
				IdentityGroups: []string{"frontend-api"},
				MaxRateBPS:     500000000,
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
			Labels: model.Labels{"tier": "frontend", "role": "api"},
		}, {
			ID:     "pod-b",
			VPC:    "prod",
			Subnet: "baremetal",
			IP:     netip.MustParseAddr("10.10.0.11"),
			Node:   "node-a",
			Labels: model.Labels{"tier": "frontend", "role": "worker"},
		}, {
			ID:     "pod-c",
			VPC:    "prod",
			Subnet: "baremetal",
			IP:     netip.MustParseAddr("10.10.0.12"),
			Node:   "node-a",
			Labels: model.Labels{"tier": "backend", "role": "worker"},
		}},
	}
	ops, _, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
		SyncOVSDB:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"table=0,priority=225,ip,nw_src=10.10.0.10/32,actions=set_queue:30,NORMAL",
		"table=0,priority=225,ip,nw_src=10.10.0.12/32,actions=set_queue:30,NORMAL",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("provider identity group queue flow ops missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "nw_src=10.10.0.0/24") || strings.Contains(joined, "nw_src=10.10.0.11/32") {
		t.Fatalf("provider identity group queue should only match group members:\n%s", joined)
	}
}

func TestPlanCleansStaleProviderTenantQueueFlows(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "eth1",
			}},
			TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
				Tenant:     "prod",
				QueueID:    10,
				MaxRateBPS: 500000000,
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
	ops, _, err := Plan(context.Background(), state, Options{
		Node:         "node-a",
		LocalDevice:  "nl0",
		SyncOVSDB:    true,
		CleanupStale: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	bridge := providerNetworkBridgeName("physnet-a")
	joined := stringifyOps(ops)
	for _, expected := range []string{
		"dump-flows " + shellQuote(bridge) + " cookie=0x4e51000000000000/0xffff000000000000",
		"ovs-ofctl --strict del-flows " + shellQuote(bridge) + " \"cookie=$cookie/-1\"",
		" 0x4e51",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("provider tenant queue cleanup ops missing %q:\n%s", expected, joined)
		}
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

func TestValidateProviderHealthFailsForDegradedProviderLinks(t *testing.T) {
	err := validateProviderHealth(Result{
		ProviderDegraded: 1,
		ProviderStatus: []ProviderLinkStatus{{
			ProviderNetwork: "physnet-a",
			ParentDevice:    "eth1",
			VLAN:            100,
			LinkName:        "nlv100",
			ParentState:     "up",
			LinkState:       "missing",
		}},
		ProviderNetworkStatus: []ProviderNetworkStatus{{
			ProviderNetwork: "physnet-a",
			Ready:           false,
			IssueCount:      1,
			Reasons:         []string{"link-missing"},
		}},
	}, Options{StrictProviderHealth: true})
	if err == nil || !strings.Contains(err.Error(), "provider health degraded") {
		t.Fatalf("err = %v, want strict provider health failure", err)
	}
}

type commandExecutorFunc func(context.Context, Operation) error

func (f commandExecutorFunc) Execute(ctx context.Context, op Operation) error { return f(ctx, op) }

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

func TestDiscoverProviderInventorySelectsCandidateProviderInterface(t *testing.T) {
	previous := listSystemInterfaces
	defer func() { listSystemInterfaces = previous }()
	listSystemInterfaces = func() ([]net.Interface, error) {
		return []net.Interface{
			{Name: "lo", Flags: net.FlagLoopback},
			{Name: "eth1", Flags: net.FlagUp},
		}, nil
	}

	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:       "node-a",
				Interfaces: []string{"ens5", "eth1"},
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
	inventory, err := discoverProviderInventory()
	if err != nil {
		t.Fatal(err)
	}
	specs, err := desiredProviderNetworkLinkSpecs(state, "node-a", nil, inventory)
	if err != nil {
		t.Fatal(err)
	}
	total, ready, degraded := summarizeProviderInventory(inventory)
	if total != 2 || ready != 1 || degraded != 1 {
		t.Fatalf("provider inventory summary = total:%d ready:%d degraded:%d, want 2/1/1", total, ready, degraded)
	}
	if got := inventory[0]; got.Name != "lo" || got.State != "down" {
		t.Fatalf("provider inventory status[0] = %+v, want lo down", got)
	}
	if len(specs) != 1 {
		t.Fatalf("provider specs = %+v, want one spec", specs)
	}
	if got := specs[0].ParentDevice; got != "eth1" {
		t.Fatalf("selected provider parent = %s, want eth1", got)
	}
}

func TestProviderLinkStatusesFromInventoryReportsReadyLink(t *testing.T) {
	linkName := providerNetworkLinkName("physnet-a", "eth1", 100)
	statuses := providerLinkStatusesFromInventory([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            linkName,
	}}, []ProviderInterface{
		{Name: "eth1", Ready: true, State: "up"},
		{Name: linkName, Ready: true, State: "up"},
	})
	ready, degraded := summarizeProviderLinkHealth(statuses)
	if ready != 1 || degraded != 0 {
		t.Fatalf("provider health = ready:%d degraded:%d, want 1/0", ready, degraded)
	}
	if got := statuses[0]; !got.Ready || got.ParentState != "up" || got.LinkState != "up" {
		t.Fatalf("provider status = %+v, want ready up/up", got)
	}
}

func TestProviderLinkStatusesFromInventoryReportsRuntimeLinkDrift(t *testing.T) {
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
	inventory := []ProviderInterface{{Name: "eth1", Ready: true, State: "up"}}
	specs, err := desiredProviderNetworkLinkSpecs(state, "node-a", nil, inventory)
	if err != nil {
		t.Fatal(err)
	}
	statuses := providerLinkStatusesFromInventory(specs, inventory)
	ready, degraded := summarizeProviderLinkHealth(statuses)
	if ready != 0 || degraded != 1 {
		t.Fatalf("provider health = ready:%d degraded:%d, want 0/1", ready, degraded)
	}
	issues := providerRuntimeIssues(statuses, nil, "node-a")
	if len(issues) != 1 || issues[0].Reason != "link-missing" {
		t.Fatalf("provider issues = %+v, want link-missing", issues)
	}
	if issues[0].ProviderNetwork != "physnet-a" || issues[0].Node != "node-a" || issues[0].ParentDevice != "eth1" || issues[0].VLAN != 100 {
		t.Fatalf("provider issue identity = %+v, want physnet-a eth1 vlan 100", issues[0])
	}
	networkStatuses := providerNetworkStatuses(state, statuses, issues)
	if len(networkStatuses) != 1 || networkStatuses[0].Ready || networkStatuses[0].IssueCount != 1 || networkStatuses[0].Reasons[0] != "link-missing" {
		t.Fatalf("provider network status = %+v, want link-missing reason", networkStatuses)
	}
}

func TestProviderRuntimeIssuesReportsParentAndLinkDrift(t *testing.T) {
	issues := providerRuntimeIssues([]ProviderLinkStatus{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		LinkName:        "nlv-test",
		ParentState:     "down",
		LinkState:       "type-mismatch",
	}}, nil, "node-a")
	if len(issues) != 2 {
		t.Fatalf("issues = %+v, want parent and link drift", issues)
	}
	if issues[0].Reason != "parent-down" || issues[1].Reason != "link-drift" {
		t.Fatalf("issues = %+v, want parent-down and link-drift", issues)
	}
	if issues[0].Node != "node-a" || issues[1].Node != "node-a" {
		t.Fatalf("issues = %+v, want node-a on runtime issues", issues)
	}
}

func TestProviderOVSDBRuntimeIssuesReportsDatabaseDrift(t *testing.T) {
	issues := providerOVSDBRuntimeIssues(nil, []ProviderOVSDBStatus{{
		ProviderNetwork:  "physnet-a",
		Bridge:           "nlbr-a",
		LinkName:         "nlv-a",
		ParentDevice:     "eth1",
		VLAN:             100,
		BridgeState:      "up",
		MappingState:     "missing",
		PortState:        "bridge-mismatch",
		InterfaceState:   "external-ids-mismatch",
		ControllerState:  "disconnected",
		ControllerDetail: "target=tcp:192.0.2.10:6653,connected=false,state=BACKOFF,last_error=Connection refused",
	}}, "node-a")
	if len(issues) != 4 {
		t.Fatalf("issues = %+v, want four ovsdb drift issues", issues)
	}
	wantReasons := []string{"ovsdb-mapping-missing", "ovsdb-port-drift", "ovsdb-interface-drift", "ovsdb-controller-drift"}
	for i, want := range wantReasons {
		if issues[i].Reason != want {
			t.Fatalf("issue[%d] = %+v, want reason %s", i, issues[i], want)
		}
		if issues[i].Node != "node-a" || issues[i].ProviderNetwork != "physnet-a" || issues[i].ParentDevice != "eth1" || issues[i].VLAN != 100 {
			t.Fatalf("issue[%d] identity = %+v, want node-a physnet-a eth1 vlan 100", i, issues[i])
		}
	}
	if issues[3].Detail != "nlbr-a:disconnected:target=tcp:192.0.2.10:6653,connected=false,state=BACKOFF,last_error=Connection refused" {
		t.Fatalf("controller issue detail = %q, want OVSDB controller status detail", issues[3].Detail)
	}
}

func TestProviderOVSDBRuntimeIssuesReportsControllerQuorumDegraded(t *testing.T) {
	issues := providerOVSDBRuntimeIssues(nil, []ProviderOVSDBStatus{{
		ProviderNetwork:  "physnet-a",
		Bridge:           "nlbr-a",
		LinkName:         "nlv-a",
		ParentDevice:     "eth1",
		VLAN:             100,
		BridgeState:      "up",
		MappingState:     "up",
		PortState:        "up",
		InterfaceState:   "up",
		ControllerState:  "degraded",
		ControllerDetail: "connected=1/2;target=tcp:192.0.2.10:6653,connected=true;target=tcp:192.0.2.11:6653,connected=false",
	}}, "node-a")
	if len(issues) != 1 || issues[0].Reason != "ovsdb-controller-drift" {
		t.Fatalf("issues = %+v, want controller drift issue", issues)
	}
	if issues[0].Detail != "nlbr-a:degraded:connected=1/2;target=tcp:192.0.2.10:6653,connected=true;target=tcp:192.0.2.11:6653,connected=false" {
		t.Fatalf("controller issue detail = %q, want degraded quorum detail", issues[0].Detail)
	}
}

func TestProviderOVSDBRuntimeIssuesReportsQoSAndQueueDrift(t *testing.T) {
	issues := providerOVSDBRuntimeIssues(nil, []ProviderOVSDBStatus{{
		ProviderNetwork: "physnet-a",
		Bridge:          "nlbr-a",
		LinkName:        "nlv-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		BridgeState:     "up",
		MappingState:    "up",
		PortState:       "up",
		InterfaceState:  "up",
		QoSState:        "mismatch",
		QueueState:      "missing",
	}}, "node-a")
	if len(issues) != 2 {
		t.Fatalf("issues = %+v, want qos and queue drift issues", issues)
	}
	if issues[0].Reason != "ovsdb-qos-drift" || issues[0].Detail != "nlv-a:mismatch" {
		t.Fatalf("qos issue = %+v, want qos drift detail", issues[0])
	}
	if issues[1].Reason != "ovsdb-queue-missing" || issues[1].Detail != "nlv-a:missing" {
		t.Fatalf("queue issue = %+v, want queue missing detail", issues[1])
	}
}

func TestAppendProviderOVSDBIssuesReportsProvidedStatusIssues(t *testing.T) {
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
	specs, err := desiredProviderNetworkLinkSpecs(state, "node-a", nil, []ProviderInterface{{Name: "eth1", Ready: true}})
	if err != nil {
		t.Fatal(err)
	}
	result := Result{
		ProviderStatus: providerLinkStatusesFromInventory(specs, []ProviderInterface{{Name: "eth1", Ready: true}, {Name: providerNetworkLinkName("physnet-a", "eth1", 100), Ready: true}}),
	}
	err = appendProviderOVSDBIssues(context.Background(), &result, state, Options{
		Node: "node-a",
		ProviderOVSDBStatus: []ProviderOVSDBStatus{{
			ProviderNetwork: "physnet-a",
			Bridge:          providerNetworkBridgeName("physnet-a"),
			LinkName:        providerNetworkLinkName("physnet-a", "eth1", 100),
			ParentDevice:    "eth1",
			VLAN:            100,
			BridgeState:     "missing",
			MappingState:    "up",
			PortState:       "up",
			InterfaceState:  "up",
		}},
	}, specs)
	if err != nil {
		t.Fatal(err)
	}
	if !providerIssuesContainReason(result.ProviderIssues, "ovsdb-bridge-missing") {
		t.Fatalf("provider issues = %+v, want ovsdb-bridge-missing", result.ProviderIssues)
	}
	if len(result.ProviderNetworkStatus) != 1 || result.ProviderNetworkStatus[0].Ready || !providerNetworkStatusContainsReason(result.ProviderNetworkStatus[0], "ovsdb-bridge-missing") {
		t.Fatalf("provider network status = %+v, want ovsdb bridge issue", result.ProviderNetworkStatus)
	}
}

func TestStrictProviderHealthFailsOnProviderOVSDBStatusIssue(t *testing.T) {
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
	specs, err := desiredProviderNetworkLinkSpecs(state, "node-a", nil, []ProviderInterface{{Name: "eth1", Ready: true}})
	if err != nil {
		t.Fatal(err)
	}
	result := Result{
		ProviderStatus: providerLinkStatusesFromInventory(specs, []ProviderInterface{{Name: "eth1", Ready: true}, {Name: providerNetworkLinkName("physnet-a", "eth1", 100), Ready: true}}),
	}
	err = appendProviderOVSDBIssues(context.Background(), &result, state, Options{
		Node: "node-a",
		ProviderOVSDBStatus: []ProviderOVSDBStatus{{
			ProviderNetwork: "physnet-a",
			Bridge:          providerNetworkBridgeName("physnet-a"),
			LinkName:        providerNetworkLinkName("physnet-a", "eth1", 100),
			ParentDevice:    "eth1",
			VLAN:            100,
			BridgeState:     "up",
			MappingState:    "missing",
			PortState:       "up",
			InterfaceState:  "up",
		}},
	}, specs)
	if err != nil {
		t.Fatal(err)
	}
	err = validateProviderHealth(result, Options{StrictProviderHealth: true})
	if err == nil || !strings.Contains(err.Error(), "ovsdb-mapping-missing") {
		t.Fatalf("err = %v, want strict provider health failure with ovsdb-mapping-missing", err)
	}
}

func providerIssuesContainReason(issues []ProviderIssue, reason string) bool {
	for _, issue := range issues {
		if issue.Reason == reason {
			return true
		}
	}
	return false
}

func providerNetworkStatusContainsReason(status ProviderNetworkStatus, reason string) bool {
	for _, got := range status.Reasons {
		if got == reason {
			return true
		}
	}
	return false
}

func providerNetworkStatusByName(statuses []ProviderNetworkStatus, name string) (ProviderNetworkStatus, bool) {
	for _, status := range statuses {
		if status.ProviderNetwork == name {
			return status, true
		}
	}
	return ProviderNetworkStatus{}, false
}

func TestProviderLinkFailureStatusReportsDriftReason(t *testing.T) {
	spec := providerNetworkLinkSpec{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv-test",
	}
	status := providerLinkFailureStatus(spec, "up", "vlan-mismatch")
	if status.ProviderNetwork != "physnet-a" || status.ParentDevice != "eth1" || status.VLAN != 100 || status.LinkName != "nlv-test" {
		t.Fatalf("status identity = %+v", status)
	}
	if status.Ready {
		t.Fatalf("status = %+v, want degraded", status)
	}
	if status.ParentState != "up" || status.LinkState != "vlan-mismatch" {
		t.Fatalf("status drift detail = %+v, want up/vlan-mismatch", status)
	}
}

func TestSummarizeProviderStatusIncludesDriftReason(t *testing.T) {
	summary := summarizeProviderStatus([]ProviderLinkStatus{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		LinkName:        "nlv-test",
		Ready:           false,
		ParentState:     "up",
		LinkState:       "type-mismatch",
	}})
	if summary != "physnet-a:eth1:100:nlv-test:pending:up:type-mismatch" {
		t.Fatalf("summary = %q, want drift reason in provider status", summary)
	}
}

func TestSummarizeProviderNetworkStatusAggregatesLinksAndIssues(t *testing.T) {
	statuses := summarizeProviderNetworkStatus(
		[]ProviderLinkStatus{
			{ProviderNetwork: "physnet-a", Ready: true},
			{ProviderNetwork: "physnet-b", Ready: false},
		},
		[]ProviderIssue{
			{ProviderNetwork: "physnet-b", Reason: "type-mismatch"},
			{ProviderNetwork: "physnet-b", Reason: "type-mismatch"},
			{ProviderNetwork: "physnet-c", Reason: "candidate-unresolved"},
		},
	)
	if len(statuses) != 3 {
		t.Fatalf("network status len = %d, want 3: %+v", len(statuses), statuses)
	}
	if got := statuses[0]; got.ProviderNetwork != "physnet-a" || !got.Ready || got.LinkCount != 1 || got.ReadyLinks != 1 || got.IssueCount != 0 {
		t.Fatalf("status[0] = %+v", got)
	}
	if got := statuses[1]; got.ProviderNetwork != "physnet-b" || got.Ready || got.LinkCount != 1 || got.ReadyLinks != 0 || got.IssueCount != 1 || got.Reasons[0] != "type-mismatch" {
		t.Fatalf("status[1] = %+v", got)
	}
	if got := statuses[2]; got.ProviderNetwork != "physnet-c" || got.Ready || got.LinkCount != 0 || got.ReadyLinks != 0 || got.IssueCount != 1 || got.Reasons[0] != "candidate-unresolved" {
		t.Fatalf("status[2] = %+v", got)
	}
}

func TestProviderNetworkStatusesIncludesTenantQuotaUsage(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			TenantQuotas: []model.ProviderNetworkTenantQuota{{
				Tenant:       "prod",
				MaxSubnets:   2,
				MaxEndpoints: 3,
			}},
		}},
		Subnets: []model.Subnet{{
			Name:            "apps",
			VPC:             "prod",
			ProviderNetwork: "physnet-a",
		}},
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps"},
			{ID: "pod-b", VPC: "prod", Subnet: "apps"},
		},
	}

	statuses := providerNetworkStatuses(state, []ProviderLinkStatus{{ProviderNetwork: "physnet-a", Ready: true}}, nil)
	if len(statuses) != 1 {
		t.Fatalf("statuses = %d, want 1", len(statuses))
	}
	status := statuses[0]
	if !status.Ready || status.TenantCount != 1 || status.SubnetCount != 1 || status.EndpointCount != 2 {
		t.Fatalf("provider network status = %+v, want ready with tenant usage", status)
	}
	if len(status.TenantUsage) != 1 {
		t.Fatalf("tenant usage = %d, want 1", len(status.TenantUsage))
	}
	usage := status.TenantUsage[0]
	if usage.Tenant != "prod" || usage.Subnets != 1 || usage.Endpoints != 2 || usage.MaxSubnets != 2 || usage.MaxEndpoints != 3 || usage.Exceeded {
		t.Fatalf("tenant usage = %+v, want prod 1/2 subnets and 2/3 endpoints", usage)
	}
}

func TestProviderNetworkStatusesMarksTenantQuotaExceeded(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			TenantQuotas: []model.ProviderNetworkTenantQuota{{
				Tenant:       "prod",
				MaxEndpoints: 1,
			}},
		}},
		Subnets: []model.Subnet{{
			Name:            "apps",
			VPC:             "prod",
			ProviderNetwork: "physnet-a",
		}},
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "apps"},
			{ID: "pod-b", VPC: "prod", Subnet: "apps"},
		},
	}

	statuses := providerNetworkStatuses(state, []ProviderLinkStatus{{ProviderNetwork: "physnet-a", Ready: true}}, nil)
	if len(statuses) != 1 {
		t.Fatalf("statuses = %d, want 1", len(statuses))
	}
	status := statuses[0]
	if status.Ready || status.IssueCount != 1 || !providerNetworkStatusContainsReason(status, "tenant-quota-exceeded") {
		t.Fatalf("provider network status = %+v, want tenant quota exceeded", status)
	}
	if len(status.TenantUsage) != 1 || !status.TenantUsage[0].Exceeded {
		t.Fatalf("tenant usage = %+v, want exceeded", status.TenantUsage)
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

func TestProviderLinkSetupCanDegrade(t *testing.T) {
	if !providerLinkSetupCanDegrade(unix.ENETDOWN) {
		t.Fatal("expected ENETDOWN to be treated as a degraded provider-link condition")
	}
	if providerLinkSetupCanDegrade(unix.EINVAL) {
		t.Fatal("did not expect EINVAL to be treated as a degraded provider-link condition")
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

func TestPlanReturnsInventorySummaryOnMissingProviderMapping(t *testing.T) {
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
	_, result, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
		ProviderInventory: []ProviderInterface{
			{Name: "eth1", Ready: true, State: "up"},
			{Name: "eth2", Ready: false, State: "down"},
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
	if result.ProviderIssues[0].Detail != "no parent device mapping for local provider network" {
		t.Fatalf("provider issue detail = %q, want missing mapping detail", result.ProviderIssues[0].Detail)
	}
	if len(result.ProviderNetworkStatus) != 1 || result.ProviderNetworkStatus[0].ProviderNetwork != "physnet-a" || result.ProviderNetworkStatus[0].Ready || result.ProviderNetworkStatus[0].IssueCount != 1 {
		t.Fatalf("provider network status = %+v, want degraded physnet-a with one issue", result.ProviderNetworkStatus)
	}
	if len(result.ProviderNetworkStatus[0].Reasons) != 1 || result.ProviderNetworkStatus[0].Reasons[0] != "missing-parent-mapping" {
		t.Fatalf("provider network reasons = %+v, want missing-parent-mapping", result.ProviderNetworkStatus[0].Reasons)
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

func TestPlanRejectsExclusiveProviderNetworkParentSharing(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{
			{
				Name:      "physnet-a",
				Isolation: "exclusive",
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
				VLAN:            200,
			},
		},
		Endpoints: []model.Endpoint{
			{ID: "pod-a", VPC: "prod", Subnet: "baremetal-a", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a"},
			{ID: "pod-b", VPC: "prod", Subnet: "baremetal-b", IP: netip.MustParseAddr("10.20.0.10"), Node: "node-a"},
		},
	}
	_, result, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
	})
	if err == nil || !strings.Contains(err.Error(), `provider networks "physnet-a" and "physnet-b" cannot share exclusive parent eth1`) {
		t.Fatalf("err = %v, want exclusive parent sharing failure", err)
	}
	if len(result.ProviderIssues) != 1 || result.ProviderIssues[0].Reason != "parent-isolation-conflict" || result.ProviderIssues[0].ParentDevice != "eth1" || result.ProviderIssues[0].Detail != "physnet-a" {
		t.Fatalf("provider issues = %+v, want parent-isolation-conflict with physnet-a detail", result.ProviderIssues)
	}
	status, ok := providerNetworkStatusByName(result.ProviderNetworkStatus, "physnet-b")
	if !ok || status.Ready || !providerNetworkStatusContainsReason(status, "parent-isolation-conflict") {
		t.Fatalf("provider network status = %+v, want physnet-b isolation conflict", result.ProviderNetworkStatus)
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

func TestPlanAutoSelectsReadyCandidateProviderInterface(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:       "node-a",
				Interfaces: []string{"ens5", "eth1", "bond0"},
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
		ProviderInventory: []ProviderInterface{
			{Name: "eth1", Ready: false},
			{Name: "bond0", Ready: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringifyOps(ops)
	linkName := providerNetworkLinkName("physnet-a", "bond0", 100)
	if !strings.Contains(joined, "ip link show "+linkName+" >/dev/null 2>&1 || ip link add link bond0 name "+linkName+" type vlan id 100") {
		t.Fatalf("ready candidate interface should be selected:\n%s", joined)
	}
	if strings.Contains(joined, "link eth1 name") {
		t.Fatalf("degraded candidate should not win over ready candidate:\n%s", joined)
	}
}

func TestPlanFallsBackToPresentCandidateProviderInterfaceWhenNoneReady(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:       "node-a",
				Interfaces: []string{"ens5", "eth1"},
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
		ProviderInventory: []ProviderInterface{
			{Name: "eth1", Ready: false},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringifyOps(ops)
	linkName := providerNetworkLinkName("physnet-a", "eth1", 100)
	if !strings.Contains(joined, "ip link show "+linkName+" >/dev/null 2>&1 || ip link add link eth1 name "+linkName+" type vlan id 100") {
		t.Fatalf("present degraded candidate should still be selected for health reporting:\n%s", joined)
	}
}

func TestPlanRejectsUnresolvableCandidateProviderInterfaces(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:       "node-a",
				Interfaces: []string{"ens5", "bond0"},
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
	_, _, err := Plan(context.Background(), state, Options{
		Node:              "node-a",
		LocalDevice:       "nl0",
		ProviderInventory: []ProviderInterface{{Name: "eth1", Ready: true}},
	})
	if err == nil || !strings.Contains(err.Error(), `provider network "physnet-a" on node "node-a" could not resolve candidate interfaces ens5,bond0`) {
		t.Fatalf("err = %v, want unresolved candidate interface failure", err)
	}
}

func TestPlanReturnsInventorySummaryOnUnresolvableCandidateProviderInterfaces(t *testing.T) {
	state := control.DesiredState{
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:       "node-a",
				Interfaces: []string{"ens5", "bond0"},
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
	_, result, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
		ProviderInventory: []ProviderInterface{
			{Name: "eth1", Ready: true, State: "up"},
			{Name: "eth2", Ready: false, State: "down"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), `provider network "physnet-a" on node "node-a" could not resolve candidate interfaces ens5,bond0`) {
		t.Fatalf("err = %v, want unresolved candidate interface failure", err)
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

func TestPlanReturnsInventorySummaryOnConflictingProviderNetworks(t *testing.T) {
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
			{ID: "pod-a", VPC: "prod", Subnet: "baremetal-a", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a"},
			{ID: "pod-b", VPC: "prod", Subnet: "baremetal-b", IP: netip.MustParseAddr("10.20.0.10"), Node: "node-a"},
		},
	}
	_, result, err := Plan(context.Background(), state, Options{
		Node:        "node-a",
		LocalDevice: "nl0",
		ProviderInventory: []ProviderInterface{
			{Name: "eth1", Ready: true, State: "up"},
			{Name: "eth2", Ready: false, State: "down"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), `provider networks "physnet-a" and "physnet-b" both require parent eth1 vlan 100`) {
		t.Fatalf("err = %v, want conflicting provider network failure", err)
	}
	if result.ProviderInventoryTotal != 2 || result.ProviderInventoryReady != 1 || result.ProviderInventoryDegraded != 1 {
		t.Fatalf("provider inventory summary = %+v, want total=2 ready=1 degraded=1", result)
	}
	if len(result.ProviderIssues) != 1 || result.ProviderIssues[0].Reason != "parent-vlan-conflict" || result.ProviderIssues[0].ParentDevice != "eth1" || result.ProviderIssues[0].VLAN != 100 {
		t.Fatalf("provider issues = %+v, want parent-vlan-conflict on eth1/100", result.ProviderIssues)
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

func TestPlanProgramsRejectPolicyRouteAsUnreachable(t *testing.T) {
	state := control.DesiredState{
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "reject-lab",
			VPC:      "prod",
			Priority: 150,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("198.51.100.0/24"),
				Protocol:    model.ProtocolTCP,
				DstPorts:    []model.PortRange{{From: 443, To: 443}},
			},
			Action: model.RouteAction{Type: model.ActionReject},
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
		fmt.Sprintf("ip route replace unreachable 198.51.100.0/24 table %d", table),
		fmt.Sprintf("ip rule add priority 9850 from 10.10.0.0/24 to 198.51.100.0/24 ipproto tcp dport 443 table %d protocol 186", table),
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("reject policy route ops missing %q:\n%s", expected, joined)
		}
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

func TestPolicyRouteNetlinkRouteMapsRejectToUnreachable(t *testing.T) {
	route := model.PolicyRoute{
		Name:     "reject-lab",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Destination: netip.MustParsePrefix("198.51.100.0/24"),
		},
		Action: model.RouteAction{Type: model.ActionReject},
	}
	nlRoute, err := policyRouteNetlinkRoute(route, 22000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if nlRoute.Type != unix.RTN_UNREACHABLE {
		t.Fatalf("netlink route type = %d, want RTN_UNREACHABLE", nlRoute.Type)
	}
	if nlRoute.LinkIndex != 0 || nlRoute.Gw != nil {
		t.Fatalf("reject route should not carry nexthop data: %#v", nlRoute)
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
