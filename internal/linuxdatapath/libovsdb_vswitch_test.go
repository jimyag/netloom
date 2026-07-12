package linuxdatapath

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/database/inmemory"
	ovsmodel "github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"github.com/ovn-kubernetes/libovsdb/server"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/vswitch"
)

func TestLibOVSDBProviderSyncerCreatesProviderRows(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
		QoS: model.ProviderNetworkQoS{
			EgressRateBPS: 1000000000,
		},
	}})
	if err := NewLibOVSDBProviderSyncer(client).SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}

	root := singleVSwitchRoot(t, ctx, client)
	bridge := singleBridgeByName(t, ctx, client, providerNetworkBridgeName("physnet-a"))
	port := singlePortByName(t, ctx, client, "nlv100")
	iface := singleInterfaceByName(t, ctx, client, "nlv100")
	if root.ExternalIDs["ovn-bridge-mappings"] != "physnet-a:"+bridge.Name {
		t.Fatalf("root external IDs = %+v, want bridge mapping", root.ExternalIDs)
	}
	if !containsProviderString(root.Bridges, bridge.UUID) {
		t.Fatalf("root bridges = %+v, want %s", root.Bridges, bridge.UUID)
	}
	if bridge.ExternalIDs["netloom_provider_network"] != "physnet-a" || !containsProviderString(bridge.Ports, port.UUID) {
		t.Fatalf("bridge = %+v, want provider external IDs and port ref", bridge)
	}
	if port.ExternalIDs["netloom_parent_device"] != "eth1" || port.Interfaces[0] != iface.UUID {
		t.Fatalf("port = %+v, want parent external IDs and interface ref %s", port, iface.UUID)
	}
	if iface.ExternalIDs["netloom_vlan"] != "100" {
		t.Fatalf("interface external IDs = %+v, want vlan 100", iface.ExternalIDs)
	}
}

func TestLibOVSDBProviderSyncerRepairsProviderInterfaceConfig(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}})
	mtuRequest := 9000
	ofportRequest := 42
	rows.Interfaces[0].Type = "internal"
	rows.Interfaces[0].Options = map[string]string{"peer": "nlv100-peer"}
	rows.Interfaces[0].OtherConfig = map[string]string{"hwaddr": "02:00:00:00:00:2a"}
	rows.Interfaces[0].MTURequest = &mtuRequest
	rows.Interfaces[0].OfportRequest = &ofportRequest

	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}
	iface := singleInterfaceByName(t, ctx, client, "nlv100")
	if iface.Type != "internal" || iface.Options["peer"] != "nlv100-peer" ||
		iface.OtherConfig["hwaddr"] != "02:00:00:00:00:2a" ||
		iface.MTURequest == nil || *iface.MTURequest != 9000 ||
		iface.OfportRequest == nil || *iface.OfportRequest != 42 {
		t.Fatalf("interface = %+v, want desired OVSDB config columns persisted", iface)
	}

	iface.Type = ""
	iface.Options = nil
	iface.OtherConfig = nil
	iface.MTURequest = nil
	iface.OfportRequest = nil
	updateOps, err := client.Where(iface).Update(iface, &iface.Type, &iface.Options, &iface.OtherConfig, &iface.MTURequest, &iface.OfportRequest)
	if err != nil {
		t.Fatal(err)
	}
	transactVSwitchOps(t, ctx, client, updateOps)

	statuses, err := syncer.ReadProviderOVSDBStatus(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].InterfaceState != "mismatch" {
		t.Fatalf("statuses = %+v, want provider interface config mismatch", statuses)
	}

	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}
	iface = singleInterfaceByName(t, ctx, client, "nlv100")
	if iface.Type != "internal" || iface.Options["peer"] != "nlv100-peer" ||
		iface.OtherConfig["hwaddr"] != "02:00:00:00:00:2a" ||
		iface.MTURequest == nil || *iface.MTURequest != 9000 ||
		iface.OfportRequest == nil || *iface.OfportRequest != 42 {
		t.Fatalf("interface after drift repair = %+v, want desired OVSDB config columns restored", iface)
	}
}

func TestLibOVSDBProviderSyncerOpenVSwitchExternalID(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{
		ExternalIDs: map[string]string{
			"ovn-bridge-mappings": "physnet-a:br-physnet-a",
		},
	})
	syncer := NewLibOVSDBProviderSyncer(client)

	if err := syncer.SetOpenVSwitchExternalID(ctx, "netloom_policy_rollout_state", `{"rollouts":[]}`); err != nil {
		t.Fatal(err)
	}
	value, ok, err := syncer.OpenVSwitchExternalID(ctx, "netloom_policy_rollout_state")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || value != `{"rollouts":[]}` {
		t.Fatalf("rollout state external ID = %q ok=%v, want JSON state", value, ok)
	}
	root := singleVSwitchRoot(t, ctx, client)
	if root.ExternalIDs["ovn-bridge-mappings"] != "physnet-a:br-physnet-a" {
		t.Fatalf("root external IDs = %+v, want existing bridge mapping preserved", root.ExternalIDs)
	}
}

func TestLibOVSDBProviderSyncerCreatesProviderControllers(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork:   "physnet-a",
		ParentDevice:      "eth1",
		VLAN:              100,
		Name:              "nlv100",
		ControllerTargets: []string{"tcp:192.0.2.10:6653"},
	}})
	if len(rows.Controllers) != 1 || rows.Controllers[0].Target != "tcp:192.0.2.10:6653" {
		t.Fatalf("desired controllers = %+v, want target tcp:192.0.2.10:6653", rows.Controllers)
	}
	if len(rows.Bridges) != 1 || len(rows.Bridges[0].Controller) != 1 {
		t.Fatalf("desired bridge controllers = %+v, want controller identity", rows.Bridges)
	}
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}

	bridge := singleBridgeByName(t, ctx, client, providerNetworkBridgeName("physnet-a"))
	controller := singleControllerByProviderName(t, ctx, client, rows.Controllers[0].ExternalIDs["netloom_provider_controller"])
	if !containsProviderString(bridge.Controller, controller.UUID) {
		t.Fatalf("bridge controllers = %+v, want %s", bridge.Controller, controller.UUID)
	}
	if controller.Target != "tcp:192.0.2.10:6653" || controller.ExternalIDs["netloom_provider_network"] != "physnet-a" {
		t.Fatalf("controller = %+v, want target and provider external IDs", controller)
	}

	statuses, err := syncer.ReadProviderOVSDBStatus(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].ControllerState != "disconnected" ||
		statuses[0].ControllerDetail != "target=tcp:192.0.2.10:6653,connected=false" {
		t.Fatalf("statuses = %+v, want disconnected controller before OVS connects with target detail", statuses)
	}
	if !containsProviderString(statuses[0].ControllerUUIDs, controller.UUID) ||
		!containsProviderString(statuses[0].ControllerTargets, "tcp:192.0.2.10:6653") ||
		statuses[0].BridgeUUID != bridge.UUID {
		t.Fatalf("status path = %+v, want controller and bridge attribution", statuses[0])
	}
	controller.IsConnected = true
	controller.Status = map[string]string{
		"state": "ACTIVE",
		"role":  "master",
	}
	connectOps, err := client.Where(controller).Update(controller, &controller.IsConnected)
	if err != nil {
		t.Fatal(err)
	}
	statusOps, err := client.Where(controller).Update(controller, &controller.Status)
	if err != nil {
		t.Fatal(err)
	}
	connectOps = append(connectOps, statusOps...)
	transactVSwitchOps(t, ctx, client, connectOps)
	statuses, err = syncer.ReadProviderOVSDBStatus(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].ControllerState != "up" ||
		statuses[0].ControllerDetail != "target=tcp:192.0.2.10:6653,connected=true,state=ACTIVE,role=master" {
		t.Fatalf("statuses = %+v, want connected controller with OVSDB status detail", statuses)
	}

	withoutController := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}})
	if err := syncer.SyncProviderOVSDB(ctx, withoutController, false); err != nil {
		t.Fatal(err)
	}
	bridge = singleBridgeByName(t, ctx, client, providerNetworkBridgeName("physnet-a"))
	if containsProviderString(bridge.Controller, controller.UUID) {
		t.Fatalf("bridge controllers = %+v, want Netloom controller detached after desired target removal", bridge.Controller)
	}
	if countControllersByProviderName(t, ctx, client, rows.Controllers[0].ExternalIDs["netloom_provider_controller"]) != 0 {
		t.Fatal("unreferenced provider controller row was not removed after target removal")
	}

	stale := &vswitch.Controller{
		UUID:   "@stale_controller",
		Target: "tcp:192.0.2.11:6653",
		ExternalIDs: map[string]string{
			"netloom_owner":               "netloom",
			"netloom_provider_network":    "physnet-a",
			"netloom_provider_controller": "controller-stale",
		},
	}
	createStale, err := client.Create(stale)
	if err != nil {
		t.Fatal(err)
	}
	transactVSwitchOps(t, ctx, client, createStale)
	if err := syncer.SyncProviderOVSDB(ctx, withoutController, true); err != nil {
		t.Fatal(err)
	}
	if countControllersByProviderName(t, ctx, client, "controller-stale") != 0 {
		t.Fatal("stale provider controller was not deleted")
	}
}

func TestLibOVSDBProviderSyncerReportsProviderControllerQuorum(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork:   "physnet-a",
		ParentDevice:      "eth1",
		VLAN:              100,
		Name:              "nlv100",
		ControllerTargets: []string{"tcp:192.0.2.10:6653", "tcp:192.0.2.11:6653"},
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}

	first := singleControllerByTarget(t, ctx, client, "tcp:192.0.2.10:6653")
	first.IsConnected = true
	first.Status = map[string]string{"role": "master"}
	firstOps, err := client.Where(first).Update(first, &first.IsConnected, &first.Status)
	if err != nil {
		t.Fatal(err)
	}
	transactVSwitchOps(t, ctx, client, firstOps)
	statuses, err := syncer.ReadProviderOVSDBStatus(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].ControllerState != "degraded" ||
		!strings.Contains(statuses[0].ControllerDetail, "connected=1/2") ||
		!strings.Contains(statuses[0].ControllerDetail, "target=tcp:192.0.2.11:6653,connected=false") {
		t.Fatalf("statuses = %+v, want degraded quorum detail", statuses)
	}

	second := singleControllerByTarget(t, ctx, client, "tcp:192.0.2.11:6653")
	second.IsConnected = true
	second.Status = map[string]string{"role": "backup"}
	secondOps, err := client.Where(second).Update(second, &second.IsConnected, &second.Status)
	if err != nil {
		t.Fatal(err)
	}
	transactVSwitchOps(t, ctx, client, secondOps)
	statuses, err = syncer.ReadProviderOVSDBStatus(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].ControllerState != "up" ||
		!strings.Contains(statuses[0].ControllerDetail, "connected=2/2") {
		t.Fatalf("statuses = %+v, want full controller quorum up", statuses)
	}
}

func TestLibOVSDBProviderSyncerCreatesProviderQoS(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
		QoS: model.ProviderNetworkQoS{
			EgressRateBPS:  1000000000,
			EgressBurstBPS: 64000,
		},
	}})
	if err := NewLibOVSDBProviderSyncer(client).SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}

	port := singlePortByName(t, ctx, client, "nlv100")
	if port.QOS == nil {
		t.Fatalf("port = %+v, want QoS ref", port)
	}
	qos := singleQoSByProviderName(t, ctx, client, "qos-nlv100")
	if *port.QOS != qos.UUID {
		t.Fatalf("port qos = %q, want %q", *port.QOS, qos.UUID)
	}
	if qos.Type != "linux-htb" || qos.OtherConfig["max-rate"] != "1000000000" || qos.OtherConfig["burst"] != "64000" {
		t.Fatalf("qos = %+v, want linux-htb max-rate and burst", qos)
	}
	if qos.ExternalIDs["netloom_provider_network"] != "physnet-a" || qos.ExternalIDs["netloom_parent_device"] != "eth1" {
		t.Fatalf("qos external IDs = %+v, want provider link ownership", qos.ExternalIDs)
	}
}

func TestLibOVSDBProviderSyncerCreatesProviderTenantQueues(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
		TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
			Tenant:   "prod",
			QueueID:  10,
			Protocol: model.ProtocolTCP,
			Ports:    []model.PortRange{{From: 443, To: 443}},
			IdentityGroups: []string{
				"frontend-api",
			},
			IdentitySelector: model.Labels{
				"tier": "frontend",
			},
			IdentityExpressions: []model.LabelExpr{{
				Key:      "role",
				Operator: "In",
				Values:   []string{"api"},
			}},
			MinRateBPS: 100000000,
			MaxRateBPS: 500000000,
			BurstBPS:   64000,
		}},
	}})
	if err := NewLibOVSDBProviderSyncer(client).SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}

	port := singlePortByName(t, ctx, client, "nlv100")
	if port.QOS == nil {
		t.Fatalf("port = %+v, want QoS ref", port)
	}
	qos := singleQoSByProviderName(t, ctx, client, "qos-nlv100")
	if *port.QOS != qos.UUID {
		t.Fatalf("port qos = %q, want %q", *port.QOS, qos.UUID)
	}
	queue := singleQueueByProviderName(t, ctx, client, "queue-nlv100-10")
	if qos.Queues[10] != queue.UUID {
		t.Fatalf("qos queues = %+v, want queue id 10 -> %s", qos.Queues, queue.UUID)
	}
	if queue.ExternalIDs["netloom_tenant"] != "prod" || queue.ExternalIDs["netloom_queue_id"] != "10" {
		t.Fatalf("queue external IDs = %+v, want tenant prod queue 10", queue.ExternalIDs)
	}
	if queue.ExternalIDs["netloom_queue_protocol"] != "tcp" || queue.ExternalIDs["netloom_queue_ports"] != "443" {
		t.Fatalf("queue external IDs = %+v, want tcp/443 selector", queue.ExternalIDs)
	}
	if queue.ExternalIDs["netloom_queue_identity_selector"] != "tier=frontend" || queue.ExternalIDs["netloom_queue_identity_expressions"] != "role:in:api" {
		t.Fatalf("queue external IDs = %+v, want identity selector metadata", queue.ExternalIDs)
	}
	if queue.ExternalIDs["netloom_queue_identity_groups"] != "frontend-api" {
		t.Fatalf("queue external IDs = %+v, want identity group metadata", queue.ExternalIDs)
	}
	if queue.OtherConfig["min-rate"] != "100000000" || queue.OtherConfig["max-rate"] != "500000000" || queue.OtherConfig["burst"] != "64000" {
		t.Fatalf("queue other_config = %+v, want configured rates", queue.OtherConfig)
	}

	updatedRows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
		TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
			Tenant:     "prod",
			QueueID:    10,
			MinRateBPS: 100000000,
		}},
	}})
	if err := NewLibOVSDBProviderSyncer(client).SyncProviderOVSDB(ctx, updatedRows, false); err != nil {
		t.Fatal(err)
	}
	queue = singleQueueByProviderName(t, ctx, client, "queue-nlv100-10")
	for _, stale := range []string{"netloom_queue_protocol", "netloom_queue_ports", "netloom_queue_identity_groups", "netloom_queue_identity_selector", "netloom_queue_identity_expressions"} {
		if _, ok := queue.ExternalIDs[stale]; ok {
			t.Fatalf("queue external IDs retained stale %s: %+v", stale, queue.ExternalIDs)
		}
	}
	if queue.ExternalIDs["netloom_tenant"] != "prod" || queue.OtherConfig["min-rate"] != "100000000" || len(queue.OtherConfig) != 1 {
		t.Fatalf("queue after update = external_ids:%+v other_config:%+v, want selector metadata removed and min-rate preserved", queue.ExternalIDs, queue.OtherConfig)
	}
}

func TestLibOVSDBProviderSyncerPersistsIdentityGroupsOnOpenVSwitch(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRowsForIdentityGroups([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
		TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
			Tenant:         "prod",
			QueueID:        10,
			IdentityGroups: []string{"frontend-api"},
			MaxRateBPS:     500000000,
		}},
	}}, []model.IdentityGroup{{
		Name:        "frontend-api",
		VPC:         "prod",
		Source:      "cmdb/team-a",
		ObservedAt:  time.Date(2026, 7, 10, 1, 2, 3, 0, time.UTC),
		TTLSeconds:  300,
		EndpointIDs: []string{"pod-a"},
		EndpointSelector: model.Labels{
			"tier": "frontend",
		},
	}}, []model.Endpoint{{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		IP:     netip.MustParseAddr("10.10.0.10"),
		Node:   "node-a",
	}, {
		ID:     "pod-b",
		VPC:    "prod",
		Subnet: "apps",
		IP:     netip.MustParseAddr("10.10.0.11"),
		Node:   "node-a",
		Labels: model.Labels{
			"tier": "frontend",
		},
	}})
	if err := NewLibOVSDBProviderSyncer(client).SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}

	root := singleVSwitchRoot(t, ctx, client)
	raw := root.ExternalIDs["netloom_identity_groups"]
	if raw == "" {
		t.Fatalf("root external IDs = %+v, want identity group snapshot", root.ExternalIDs)
	}
	var snapshot providerOVSDBIdentityGroupsSnapshotDoc
	if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
		t.Fatalf("identity group snapshot JSON = %q: %v", raw, err)
	}
	if snapshot.Version != 1 || len(snapshot.Groups) != 1 {
		t.Fatalf("snapshot = %+v, want one v1 identity group", snapshot)
	}
	group := snapshot.Groups[0]
	if group.VPC != "prod" || group.Name != "frontend-api" || group.Source != "cmdb/team-a" || group.TTLSeconds != 300 || group.ExpiresAt != "2026-07-10T01:07:03Z" {
		t.Fatalf("snapshot group = %+v, want persisted source and ttl metadata", group)
	}
	if len(group.ResolvedEndpoints) != 2 || group.ResolvedEndpoints[0].ID != "pod-a" || group.ResolvedEndpoints[0].IP != "10.10.0.10" || group.ResolvedEndpoints[1].ID != "pod-b" {
		t.Fatalf("snapshot resolved endpoints = %+v, want pod-a and pod-b", group.ResolvedEndpoints)
	}

	if err := NewLibOVSDBProviderSyncer(client).SyncProviderOVSDB(ctx, desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}}), false); err != nil {
		t.Fatal(err)
	}
	root = singleVSwitchRoot(t, ctx, client)
	if root.ExternalIDs["netloom_identity_groups"] != "" {
		t.Fatalf("root external IDs = %+v, want identity group snapshot cleared", root.ExternalIDs)
	}
}

func TestLibOVSDBProviderSyncerRepairsPortBridgeDrift(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}
	port := singlePortByName(t, ctx, client, "nlv100")
	good := singleBridgeByName(t, ctx, client, providerNetworkBridgeName("physnet-a"))
	root := singleVSwitchRoot(t, ctx, client)
	wrong := &vswitch.Bridge{
		UUID:        "@wrong_br",
		Name:        "wrong-br",
		ExternalIDs: map[string]string{"netloom_owner": "other"},
		Ports:       []string{port.UUID},
	}
	createOps, err := client.Create(wrong)
	if err != nil {
		t.Fatal(err)
	}
	attachWrongOps, err := client.Where(root).Mutate(root, ovsmodel.Mutation{
		Field:   &root.Bridges,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{wrong.UUID},
	})
	if err != nil {
		t.Fatal(err)
	}
	removeOps, err := client.Where(good).Mutate(good, ovsmodel.Mutation{
		Field:   &good.Ports,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{port.UUID},
	})
	if err != nil {
		t.Fatal(err)
	}
	driftOps := append(createOps, attachWrongOps...)
	driftOps = append(driftOps, removeOps...)
	transactVSwitchOps(t, ctx, client, driftOps)

	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}
	good = singleBridgeByName(t, ctx, client, providerNetworkBridgeName("physnet-a"))
	wrong = singleBridgeByName(t, ctx, client, "wrong-br")
	if !containsProviderString(good.Ports, port.UUID) {
		t.Fatalf("good bridge ports = %+v, want repaired port %s", good.Ports, port.UUID)
	}
	if containsProviderString(wrong.Ports, port.UUID) {
		t.Fatalf("wrong bridge ports = %+v, want port detached", wrong.Ports)
	}
}

func TestLibOVSDBProviderSyncerReadsProviderStatus(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}
	statuses, err := syncer.ReadProviderOVSDBStatus(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 {
		t.Fatalf("statuses = %+v, want one", statuses)
	}
	status := statuses[0]
	if status.ProviderNetwork != "physnet-a" || status.BridgeState != "up" || status.MappingState != "up" || status.PortState != "up" || status.InterfaceState != "up" {
		t.Fatalf("status = %+v, want all up", status)
	}
	root := singleVSwitchRoot(t, ctx, client)
	bridge := singleBridgeByName(t, ctx, client, providerNetworkBridgeName("physnet-a"))
	port := singlePortByName(t, ctx, client, "nlv100")
	iface := singleInterfaceByName(t, ctx, client, "nlv100")
	if status.OpenVSwitchUUID != root.UUID || status.BridgeUUID != bridge.UUID || status.PortUUID != port.UUID || status.InterfaceUUID != iface.UUID {
		t.Fatalf("status path = %+v, want root/bridge/port/interface attribution", status)
	}
}

func TestLibOVSDBProviderSyncerReadsProviderStatusDrift(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}
	root := singleVSwitchRoot(t, ctx, client)
	root.ExternalIDs["ovn-bridge-mappings"] = ""
	rootOps, err := client.Where(root).Update(root, &root.ExternalIDs)
	if err != nil {
		t.Fatal(err)
	}
	iface := singleInterfaceByName(t, ctx, client, "nlv100")
	iface.ExternalIDs["netloom_vlan"] = "200"
	ifaceOps, err := client.Where(iface).Update(iface, &iface.ExternalIDs)
	if err != nil {
		t.Fatal(err)
	}
	transactVSwitchOps(t, ctx, client, append(rootOps, ifaceOps...))

	statuses, err := syncer.ReadProviderOVSDBStatus(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 {
		t.Fatalf("statuses = %+v, want one", statuses)
	}
	if statuses[0].MappingState != "missing" || statuses[0].InterfaceState != "external-ids-mismatch" {
		t.Fatalf("status = %+v, want mapping missing and interface drift", statuses[0])
	}
}

func TestLibOVSDBProviderSyncerReadsProviderBridgeExternalIDDrift(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}
	bridge := singleBridgeByName(t, ctx, client, providerNetworkBridgeName("physnet-a"))
	bridge.ExternalIDs["netloom_provider_network"] = "physnet-b"
	ops, err := client.Where(bridge).Update(bridge, &bridge.ExternalIDs)
	if err != nil {
		t.Fatal(err)
	}
	transactVSwitchOps(t, ctx, client, ops)

	statuses, err := syncer.ReadProviderOVSDBStatus(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].BridgeState != "external-ids-mismatch" {
		t.Fatalf("statuses = %+v, want bridge external id drift", statuses)
	}
}

func TestLibOVSDBProviderSyncerReadsProviderPortInterfaceDrift(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}
	wrongIface := &vswitch.Interface{
		UUID: "@wrong_provider_interface",
		Name: "wrong-provider-interface",
	}
	createIfaceOps, err := client.Create(wrongIface)
	if err != nil {
		t.Fatal(err)
	}
	port := singlePortByName(t, ctx, client, "nlv100")
	port.Interfaces = []string{wrongIface.UUID}
	portOps, err := client.Where(port).Update(port, &port.Interfaces)
	if err != nil {
		t.Fatal(err)
	}
	transactVSwitchOps(t, ctx, client, append(createIfaceOps, portOps...))

	statuses, err := syncer.ReadProviderOVSDBStatus(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].PortState != "interface-missing" || statuses[0].InterfaceState != "missing" {
		t.Fatalf("statuses = %+v, want missing desired interface reported on port and interface state", statuses)
	}
}

func TestLibOVSDBProviderSyncerReadsProviderControllerDrift(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}
	bridge := singleBridgeByName(t, ctx, client, providerNetworkBridgeName("physnet-a"))
	controller := &vswitch.Controller{
		UUID:        "@ctl_physnet_a",
		Target:      "tcp:192.0.2.10:6653",
		IsConnected: false,
	}
	createController, err := client.Create(controller)
	if err != nil {
		t.Fatal(err)
	}
	bridge.Controller = []string{controller.UUID}
	updateBridge, err := client.Where(bridge).Update(bridge, &bridge.Controller)
	if err != nil {
		t.Fatal(err)
	}
	ops := append(createController, updateBridge...)
	transactVSwitchOps(t, ctx, client, ops)

	statuses, err := syncer.ReadProviderOVSDBStatus(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].ControllerState != "disconnected" ||
		statuses[0].ControllerDetail != "target=tcp:192.0.2.10:6653,connected=false" {
		t.Fatalf("statuses = %+v, want disconnected controller with target detail", statuses)
	}

	controller = singleControllerByTarget(t, ctx, client, "tcp:192.0.2.10:6653")
	controller.IsConnected = true
	connectOps, err := client.Where(controller).Update(controller, &controller.IsConnected)
	if err != nil {
		t.Fatal(err)
	}
	transactVSwitchOps(t, ctx, client, connectOps)
	statuses, err = syncer.ReadProviderOVSDBStatus(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].ControllerState != "up" {
		t.Fatalf("statuses = %+v, want connected controller", statuses)
	}
}

func TestLibOVSDBProviderSyncerReadsProviderQoSDrift(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
		QoS: model.ProviderNetworkQoS{
			EgressRateBPS: 1000000000,
		},
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}
	qos := singleQoSByProviderName(t, ctx, client, "qos-nlv100")
	qos.OtherConfig["max-rate"] = "500000000"
	qosOps, err := client.Where(qos).Update(qos, &qos.OtherConfig)
	if err != nil {
		t.Fatal(err)
	}
	transactVSwitchOps(t, ctx, client, qosOps)

	statuses, err := syncer.ReadProviderOVSDBStatus(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 {
		t.Fatalf("statuses = %+v, want one", statuses)
	}
	if statuses[0].PortState != "up" || statuses[0].QoSState != "mismatch" || statuses[0].QueueState != "up" {
		t.Fatalf("status = %+v, want port up, qos mismatch, queue up", statuses[0])
	}
	if statuses[0].QoSUUID != qos.UUID {
		t.Fatalf("status QoS UUID = %q, want %q", statuses[0].QoSUUID, qos.UUID)
	}
}

func TestLibOVSDBProviderSyncerReadsProviderQueueDrift(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
		TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
			Tenant:     "prod",
			QueueID:    10,
			MaxRateBPS: 500000000,
		}},
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}
	queue := singleQueueByProviderName(t, ctx, client, "queue-nlv100-10")
	queue.OtherConfig["max-rate"] = "250000000"
	queueOps, err := client.Where(queue).Update(queue, &queue.OtherConfig)
	if err != nil {
		t.Fatal(err)
	}
	transactVSwitchOps(t, ctx, client, queueOps)

	statuses, err := syncer.ReadProviderOVSDBStatus(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 {
		t.Fatalf("statuses = %+v, want one", statuses)
	}
	if statuses[0].PortState != "up" || statuses[0].QoSState != "up" || statuses[0].QueueState != "mismatch" {
		t.Fatalf("status = %+v, want port up, qos up, queue mismatch", statuses[0])
	}
	if !containsProviderString(statuses[0].QueueUUIDs, queue.UUID) {
		t.Fatalf("status queue UUIDs = %+v, want %s", statuses[0].QueueUUIDs, queue.UUID)
	}
}

func TestLibOVSDBProviderSyncerCleansStaleProviderRows(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
		TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
			Tenant:     "prod",
			QueueID:    10,
			MaxRateBPS: 500000000,
		}},
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncProviderOVSDB(ctx, desiredProviderOVSDBRows(nil), true); err != nil {
		t.Fatal(err)
	}

	root := singleVSwitchRoot(t, ctx, client)
	if root.ExternalIDs["ovn-bridge-mappings"] != "" {
		t.Fatalf("root external IDs = %+v, want cleared mapping", root.ExternalIDs)
	}
	if len(root.Bridges) != 0 {
		t.Fatalf("root bridges = %+v, want stale provider bridge detached", root.Bridges)
	}
	if countBridgesByName(t, ctx, client, providerNetworkBridgeName("physnet-a")) != 0 {
		t.Fatal("stale provider bridge was not deleted")
	}
	if countPortsByName(t, ctx, client, "nlv100") != 0 {
		t.Fatal("stale provider port was not deleted")
	}
	if countInterfacesByName(t, ctx, client, "nlv100") != 0 {
		t.Fatal("stale provider interface was not deleted")
	}
	if countQoSByProviderName(t, ctx, client, "qos-nlv100") != 0 {
		t.Fatal("stale provider qos was not deleted")
	}
	if countQueuesByProviderName(t, ctx, client, "queue-nlv100-10") != 0 {
		t.Fatal("stale provider queue was not deleted")
	}
}

func TestLibOVSDBProviderSyncerCleansStaleProviderPortOnSharedBridge(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	withTwoLinks := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}, {
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            200,
		Name:            "nlv200",
		TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
			Tenant:     "prod",
			QueueID:    20,
			MaxRateBPS: 250000000,
		}},
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, withTwoLinks, false); err != nil {
		t.Fatal(err)
	}

	onlyVLAN100 := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}})
	if err := syncer.SyncProviderOVSDB(ctx, onlyVLAN100, true); err != nil {
		t.Fatal(err)
	}

	bridge := singleBridgeByName(t, ctx, client, providerNetworkBridgeName("physnet-a"))
	port := singlePortByName(t, ctx, client, "nlv100")
	if !containsProviderString(bridge.Ports, port.UUID) {
		t.Fatalf("bridge ports = %+v, want desired port %s retained", bridge.Ports, port.UUID)
	}
	if countPortsByName(t, ctx, client, "nlv200") != 0 {
		t.Fatal("stale provider port nlv200 was not deleted")
	}
	if countInterfacesByName(t, ctx, client, "nlv200") != 0 {
		t.Fatal("stale provider interface nlv200 was not deleted")
	}
	if countQoSByProviderName(t, ctx, client, "qos-nlv200") != 0 {
		t.Fatal("stale provider QoS nlv200 was not deleted")
	}
	if countQueuesByProviderName(t, ctx, client, "queue-nlv200-20") != 0 {
		t.Fatal("stale provider Queue nlv200 was not deleted")
	}
}

func TestLibOVSDBProviderSyncerDetachesStaleProviderInterfaceFromPorts(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	rows := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, rows, false); err != nil {
		t.Fatal(err)
	}
	bridge := singleBridgeByName(t, ctx, client, providerNetworkBridgeName("physnet-a"))
	keeperInterface := &vswitch.Interface{
		UUID: "@manual_keep_interface",
		Name: "manual-keep",
	}
	staleInterface := &vswitch.Interface{
		UUID: "@stale_provider_interface",
		Name: "nlv-stale",
		ExternalIDs: map[string]string{
			"netloom_owner":            "netloom",
			"netloom_provider_network": "physnet-a",
			"netloom_parent_device":    "eth1",
			"netloom_vlan":             "200",
		},
	}
	keeperOps, err := client.Create(keeperInterface)
	if err != nil {
		t.Fatal(err)
	}
	staleOps, err := client.Create(staleInterface)
	if err != nil {
		t.Fatal(err)
	}
	manualPort := &vswitch.Port{
		UUID:        "@manual_stale_interface_port",
		Name:        "manual-stale-interface-port",
		ExternalIDs: map[string]string{"owner": "test"},
		Interfaces:  []string{keeperInterface.UUID, staleInterface.UUID},
	}
	portOps, err := client.Create(manualPort)
	if err != nil {
		t.Fatal(err)
	}
	attachOps, err := client.Where(bridge).Mutate(bridge, ovsmodel.Mutation{
		Field:   &bridge.Ports,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{manualPort.UUID},
	})
	if err != nil {
		t.Fatal(err)
	}
	transactVSwitchOps(t, ctx, client, append(append(append(keeperOps, staleOps...), portOps...), attachOps...))
	keeperInterface = singleInterfaceByName(t, ctx, client, "manual-keep")
	staleInterface = singleInterfaceByName(t, ctx, client, "nlv-stale")

	if err := syncer.SyncProviderOVSDB(ctx, rows, true); err != nil {
		t.Fatal(err)
	}
	if countInterfacesByName(t, ctx, client, "nlv-stale") != 0 {
		t.Fatal("stale provider interface was not deleted")
	}
	var ports []vswitch.Port
	if err := client.WhereCache(func(row *vswitch.Port) bool { return row.Name == "manual-stale-interface-port" }).List(ctx, &ports); err != nil {
		t.Fatal(err)
	}
	if len(ports) != 1 || !containsProviderString(ports[0].Interfaces, keeperInterface.UUID) || containsProviderString(ports[0].Interfaces, staleInterface.UUID) {
		t.Fatalf("manual port interfaces = %+v, want stale provider interface detached and keeper retained", ports)
	}
}

func TestLibOVSDBProviderSyncerDetachesStaleQoSFromPorts(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	withQoS := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
		QoS: model.ProviderNetworkQoS{
			EgressRateBPS: 1000000000,
		},
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, withQoS, false); err != nil {
		t.Fatal(err)
	}
	qos := singleQoSByProviderName(t, ctx, client, "qos-nlv100")
	bridge := singleBridgeByName(t, ctx, client, providerNetworkBridgeName("physnet-a"))
	manualInterface := &vswitch.Interface{
		UUID: "manual_qos_interface",
		Name: "manual-qos-port",
	}
	manualPort := &vswitch.Port{
		UUID:        "manual_qos_port",
		Name:        "manual-qos-port",
		ExternalIDs: map[string]string{"owner": "test"},
		Interfaces:  []string{manualInterface.UUID},
		QOS:         &qos.UUID,
	}
	createIfaceOps, err := client.Create(manualInterface)
	if err != nil {
		t.Fatal(err)
	}
	createOps, err := client.Create(manualPort)
	if err != nil {
		t.Fatal(err)
	}
	attachOps, err := client.Where(bridge).Mutate(bridge, ovsmodel.Mutation{
		Field:   &bridge.Ports,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{manualPort.UUID},
	})
	if err != nil {
		t.Fatal(err)
	}
	transactVSwitchOps(t, ctx, client, append(append(createIfaceOps, createOps...), attachOps...))

	withoutQoS := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
	}})
	if err := syncer.SyncProviderOVSDB(ctx, withoutQoS, true); err != nil {
		t.Fatal(err)
	}
	if countQoSByProviderName(t, ctx, client, "qos-nlv100") != 0 {
		t.Fatal("stale provider QoS was not deleted")
	}
	var ports []vswitch.Port
	if err := client.WhereCache(func(row *vswitch.Port) bool { return row.Name == "manual-qos-port" }).List(ctx, &ports); err != nil {
		t.Fatal(err)
	}
	if len(ports) != 1 || ports[0].QOS != nil {
		t.Fatalf("manual port = %+v, want stale QoS ref detached", ports)
	}
}

func TestLibOVSDBProviderSyncerDetachesStaleQueueFromQoS(t *testing.T) {
	client, cleanup := newTestVSwitchClient(t)
	defer cleanup()
	ctx := context.Background()
	insertVSwitchRows(t, ctx, client, &vswitch.OpenvSwitch{})

	withQueues := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
		TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
			Tenant:     "prod",
			QueueID:    10,
			MaxRateBPS: 500000000,
		}, {
			Tenant:     "prod",
			QueueID:    20,
			MaxRateBPS: 250000000,
		}},
	}})
	syncer := NewLibOVSDBProviderSyncer(client)
	if err := syncer.SyncProviderOVSDB(ctx, withQueues, false); err != nil {
		t.Fatal(err)
	}
	staleQueue := singleQueueByProviderName(t, ctx, client, "queue-nlv100-20")
	bridge := singleBridgeByName(t, ctx, client, providerNetworkBridgeName("physnet-a"))
	manualQoS := &vswitch.QoS{
		UUID:        "manual_queue_qos",
		Type:        "linux-htb",
		ExternalIDs: map[string]string{"owner": "test"},
		Queues:      map[int]string{20: staleQueue.UUID},
	}
	manualInterface := &vswitch.Interface{
		UUID: "manual_queue_interface",
		Name: "manual-queue-port",
	}
	manualPort := &vswitch.Port{
		UUID:        "manual_queue_port",
		Name:        "manual-queue-port",
		ExternalIDs: map[string]string{"owner": "test"},
		Interfaces:  []string{manualInterface.UUID},
		QOS:         &manualQoS.UUID,
	}
	createOps, err := client.Create(manualQoS)
	if err != nil {
		t.Fatal(err)
	}
	createIfaceOps, err := client.Create(manualInterface)
	if err != nil {
		t.Fatal(err)
	}
	createPortOps, err := client.Create(manualPort)
	if err != nil {
		t.Fatal(err)
	}
	attachOps, err := client.Where(bridge).Mutate(bridge, ovsmodel.Mutation{
		Field:   &bridge.Ports,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{manualPort.UUID},
	})
	if err != nil {
		t.Fatal(err)
	}
	transactVSwitchOps(t, ctx, client, append(append(append(createOps, createIfaceOps...), createPortOps...), attachOps...))

	withoutQueue20 := desiredProviderOVSDBRows([]providerNetworkLinkSpec{{
		ProviderNetwork: "physnet-a",
		ParentDevice:    "eth1",
		VLAN:            100,
		Name:            "nlv100",
		TenantQueues: []model.ProviderNetworkTenantQueuePolicy{{
			Tenant:     "prod",
			QueueID:    10,
			MaxRateBPS: 500000000,
		}},
	}})
	if err := syncer.SyncProviderOVSDB(ctx, withoutQueue20, true); err != nil {
		t.Fatal(err)
	}
	if countQueuesByProviderName(t, ctx, client, "queue-nlv100-20") != 0 {
		t.Fatal("stale provider queue was not deleted")
	}
	var qosRows []vswitch.QoS
	if err := client.WhereCache(func(row *vswitch.QoS) bool { return row.ExternalIDs["owner"] == "test" }).List(ctx, &qosRows); err != nil {
		t.Fatal(err)
	}
	if len(qosRows) != 1 || len(qosRows[0].Queues) != 0 {
		t.Fatalf("manual QoS = %+v, want stale queue ref detached", qosRows)
	}
}

func newTestVSwitchClient(t *testing.T) (libovsdbclient.Client, func()) {
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
	socket := fmt.Sprintf("/tmp/netloom-vswitch-%d.sock", rand.Int())
	_ = os.Remove(socket)
	go func() {
		if err := ovsServer.Serve("unix", socket); err != nil {
			t.Logf("libovsdb test server stopped: %v", err)
		}
	}()
	requireEventuallyVSwitch(t, ovsServer.Ready)

	client, err := libovsdbclient.NewOVSDBClient(clientModel, libovsdbclient.WithEndpoint("unix:"+socket))
	if err != nil {
		ovsServer.Close()
		t.Fatal(err)
	}
	if err := client.Connect(context.Background()); err != nil {
		ovsServer.Close()
		t.Fatal(err)
	}
	if _, err := client.MonitorAll(context.Background()); err != nil {
		ovsServer.Close()
		t.Fatal(err)
	}
	return client, func() {
		client.Disconnect()
		client.Close()
		ovsServer.Close()
		_ = os.Remove(socket)
	}
}

func insertVSwitchRows(t *testing.T, ctx context.Context, client libovsdbclient.Client, rows ...ovsmodel.Model) {
	t.Helper()
	var ops []ovsdb.Operation
	for _, row := range rows {
		next, err := client.Create(row)
		if err != nil {
			t.Fatal(err)
		}
		ops = append(ops, next...)
	}
	transactVSwitchOps(t, ctx, client, ops)
}

func transactVSwitchOps(t *testing.T, ctx context.Context, client libovsdbclient.Client, ops []ovsdb.Operation) {
	t.Helper()
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("operation errors=%+v err=%v", opErrors, err)
	}
}

func singleVSwitchRoot(t *testing.T, ctx context.Context, client libovsdbclient.Client) *vswitch.OpenvSwitch {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var rows []vswitch.OpenvSwitch
		if err := client.List(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 {
			return &rows[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("Open_vSwitch rows = %+v, want one", rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func singleBridgeByName(t *testing.T, ctx context.Context, client libovsdbclient.Client, name string) *vswitch.Bridge {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var rows []vswitch.Bridge
		if err := client.WhereCache(func(row *vswitch.Bridge) bool { return row.Name == name }).List(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 {
			return &rows[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("bridge %s rows = %+v, want one", name, rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func singlePortByName(t *testing.T, ctx context.Context, client libovsdbclient.Client, name string) *vswitch.Port {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var rows []vswitch.Port
		if err := client.WhereCache(func(row *vswitch.Port) bool { return row.Name == name }).List(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 {
			return &rows[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("port %s rows = %+v, want one", name, rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func singleInterfaceByName(t *testing.T, ctx context.Context, client libovsdbclient.Client, name string) *vswitch.Interface {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var rows []vswitch.Interface
		if err := client.WhereCache(func(row *vswitch.Interface) bool { return row.Name == name }).List(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 {
			return &rows[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("interface %s rows = %+v, want one", name, rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func singleQoSByProviderName(t *testing.T, ctx context.Context, client libovsdbclient.Client, name string) *vswitch.QoS {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var rows []vswitch.QoS
		if err := client.WhereCache(func(row *vswitch.QoS) bool {
			return row.ExternalIDs["netloom_provider_qos"] == name
		}).List(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 {
			return &rows[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("qos %s rows = %+v, want one", name, rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func singleQueueByProviderName(t *testing.T, ctx context.Context, client libovsdbclient.Client, name string) *vswitch.Queue {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var rows []vswitch.Queue
		if err := client.WhereCache(func(row *vswitch.Queue) bool {
			return row.ExternalIDs["netloom_provider_queue"] == name
		}).List(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 {
			return &rows[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue %s rows = %+v, want one", name, rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func singleControllerByTarget(t *testing.T, ctx context.Context, client libovsdbclient.Client, target string) *vswitch.Controller {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var rows []vswitch.Controller
		if err := client.WhereCache(func(row *vswitch.Controller) bool {
			return row.Target == target
		}).List(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 {
			return &rows[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("controller %s rows = %+v, want one", target, rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func singleControllerByProviderName(t *testing.T, ctx context.Context, client libovsdbclient.Client, name string) *vswitch.Controller {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var rows []vswitch.Controller
		if err := client.WhereCache(func(row *vswitch.Controller) bool {
			return row.ExternalIDs["netloom_provider_controller"] == name
		}).List(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 {
			return &rows[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("controller %s rows = %+v, want one", name, rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func countBridgesByName(t *testing.T, ctx context.Context, client libovsdbclient.Client, name string) int {
	t.Helper()
	var rows []vswitch.Bridge
	if err := client.WhereCache(func(row *vswitch.Bridge) bool { return row.Name == name }).List(ctx, &rows); err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func countPortsByName(t *testing.T, ctx context.Context, client libovsdbclient.Client, name string) int {
	t.Helper()
	var rows []vswitch.Port
	if err := client.WhereCache(func(row *vswitch.Port) bool { return row.Name == name }).List(ctx, &rows); err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func countInterfacesByName(t *testing.T, ctx context.Context, client libovsdbclient.Client, name string) int {
	t.Helper()
	var rows []vswitch.Interface
	if err := client.WhereCache(func(row *vswitch.Interface) bool { return row.Name == name }).List(ctx, &rows); err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func countQoSByProviderName(t *testing.T, ctx context.Context, client libovsdbclient.Client, name string) int {
	t.Helper()
	var rows []vswitch.QoS
	if err := client.WhereCache(func(row *vswitch.QoS) bool {
		return row.ExternalIDs["netloom_provider_qos"] == name
	}).List(ctx, &rows); err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func countQueuesByProviderName(t *testing.T, ctx context.Context, client libovsdbclient.Client, name string) int {
	t.Helper()
	var rows []vswitch.Queue
	if err := client.WhereCache(func(row *vswitch.Queue) bool {
		return row.ExternalIDs["netloom_provider_queue"] == name
	}).List(ctx, &rows); err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func countControllersByProviderName(t *testing.T, ctx context.Context, client libovsdbclient.Client, name string) int {
	t.Helper()
	var rows []vswitch.Controller
	if err := client.WhereCache(func(row *vswitch.Controller) bool {
		return row.ExternalIDs["netloom_provider_controller"] == name
	}).List(ctx, &rows); err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func requireEventuallyVSwitch(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !condition() {
		t.Fatal("condition did not become true")
	}
}
