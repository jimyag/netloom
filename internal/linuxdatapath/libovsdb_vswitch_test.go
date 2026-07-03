package linuxdatapath

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/go-logr/logr"
	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/database/inmemory"
	ovsmodel "github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"github.com/ovn-kubernetes/libovsdb/server"

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
