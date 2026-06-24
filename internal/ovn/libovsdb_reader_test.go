package ovn

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/go-logr/logr"
	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/database/inmemory"
	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"github.com/ovn-kubernetes/libovsdb/server"

	netloommodel "github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/ovnnb"
	"github.com/jimyag/netloom/internal/topology"
)

func TestLibOVSDBManagedReaderReadsManagedRowsFromCache(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	managed := &ovnnb.LogicalSwitch{
		ExternalIDs: map[string]string{
			"netloom_owner":  "netloom",
			"netloom_vpc":    "prod",
			"netloom_subnet": "apps",
		},
	}
	unmanaged := &ovnnb.LogicalSwitch{
		ExternalIDs: map[string]string{"netloom_vpc": "prod"},
	}
	insertRows(t, ctx, client, managed, unmanaged)

	reader := NewLibOVSDBManagedReader(client)
	var rows []ManagedOVNRow
	requireEventually(t, func() bool {
		var err error
		rows, err = reader.ManagedOVNRows(ctx, "Logical_Switch")
		return err == nil && len(rows) == 1
	})
	if rows[0].Table != "Logical_Switch" || rows[0].UUID == "" {
		t.Fatalf("managed row = %+v, want table and UUID", rows[0])
	}
	if rows[0].ExternalIDs["netloom_subnet"] != "apps" {
		t.Fatalf("external IDs = %+v, want managed logical switch external IDs", rows[0].ExternalIDs)
	}
}

func TestAuditManagedObjectsFromLibOVSDBReader(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	insertRows(t, ctx, client,
		&ovnnb.LogicalSwitch{Name: "apps-a", ExternalIDs: map[string]string{
			"netloom_owner":  "netloom",
			"netloom_vpc":    "prod",
			"netloom_subnet": "apps",
		}},
		&ovnnb.LogicalSwitch{Name: "apps-b", ExternalIDs: map[string]string{
			"netloom_owner":  "netloom",
			"netloom_vpc":    "prod",
			"netloom_subnet": "apps",
		}},
		&ovnnb.DHCPOptions{ExternalIDs: map[string]string{
			"netloom_owner": "netloom",
			"netloom_vpc":   "prod",
		}},
	)

	reader := NewLibOVSDBManagedReader(client)
	var stats AuditStats
	var auditErr error
	if !eventually(func() bool {
		stats, auditErr = AuditManagedObjectsFromReader(ctx, reader)
		return auditErr == nil && stats.ManagedLogicalSwitches == 2 && stats.ManagedDHCPOptions == 1
	}) {
		t.Fatalf("audit stats = %+v err=%v, want logical switch and DHCP rows visible from libovsdb cache", stats, auditErr)
	}
	if auditErr != nil {
		t.Fatalf("audit managed objects: %v", auditErr)
	}
	if stats.ManagedLogicalSwitches != 2 || stats.ManagedDHCPOptions != 1 {
		t.Fatalf("audit stats = %+v, want logical switch and DHCP rows visible from libovsdb cache", stats)
	}
	if stats.DuplicateManagedRows != 1 || stats.IncompleteManagedRows != 1 {
		t.Fatalf("audit stats = %+v, want duplicate policy route and incomplete DHCP row", stats)
	}
}

func TestAuditManagedObjectsReportsColumnDriftFromLibOVSDBReader(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := netloommodel.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}
	nat := netloommodel.NATRule{
		Name:       "egress",
		VPC:        "prod",
		Type:       netloommodel.ActionSNAT,
		MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
		ExternalIP: netip.MustParseAddr("198.51.100.10"),
	}
	routeTable := netloommodel.RouteTable{
		Name: "main",
		VPC:  "prod",
		Routes: []netloommodel.Route{{
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
			NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.253")},
		}},
	}
	if err := writer.EnsureVPC(ctx, netloommodel.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureRouteTable(ctx, routeTable); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureNATRule(ctx, nat); err != nil {
		t.Fatal(err)
	}
	desired := topology.State{
		VPCs:        map[string]netloommodel.VPC{"prod": {Name: "prod"}},
		Subnets:     map[string]netloommodel.Subnet{"prod/apps": subnet},
		RouteTables: map[string]netloommodel.RouteTable{"prod/main": routeTable},
		NATRules: map[string]netloommodel.NATRule{
			"prod/egress": nat,
		},
	}
	reader := NewLibOVSDBManagedReader(client)
	requireEventually(t, func() bool {
		stats, err := AuditManagedObjectsFromReaderWithDesired(ctx, reader, desired)
		return err == nil && stats.DriftedManagedRows == 0 && stats.DriftedManagedFields == 0
	})

	var switches []ovnnb.LogicalSwitch
	if err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool {
		return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_subnet"] == "apps"
	}).List(ctx, &switches); err != nil {
		t.Fatal(err)
	}
	if len(switches) != 1 {
		t.Fatalf("logical switches = %d, want one", len(switches))
	}
	switches[0].OtherConfig["subnet"] = "10.99.0.0/24"
	updateSwitch, err := client.Where(&switches[0]).Update(&switches[0], &switches[0].OtherConfig)
	if err != nil {
		t.Fatal(err)
	}
	var nats []ovnnb.NAT
	if err := client.WhereCache(func(row *ovnnb.NAT) bool {
		return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_nat"] == "egress"
	}).List(ctx, &nats); err != nil {
		t.Fatal(err)
	}
	if len(nats) != 1 {
		t.Fatalf("NAT rows = %d, want one", len(nats))
	}
	nats[0].ExternalIP = "198.51.100.99"
	updateNAT, err := client.Where(&nats[0]).Update(&nats[0], &nats[0].ExternalIP)
	if err != nil {
		t.Fatal(err)
	}
	var routes []ovnnb.LogicalRouterStaticRoute
	if err := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
		return row.ExternalIDs["netloom_vpc"] == "prod" &&
			row.ExternalIDs["netloom_route_table"] == "main" &&
			row.ExternalIDs["netloom_route_key"] == "10.20.0.0/24|10.10.0.253"
	}).List(ctx, &routes); err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatalf("static routes = %d, want one", len(routes))
	}
	routes[0].Nexthop = "10.10.0.99"
	updateRoute, err := client.Where(&routes[0]).Update(&routes[0], &routes[0].Nexthop)
	if err != nil {
		t.Fatal(err)
	}
	ops := append(updateSwitch, updateNAT...)
	ops = append(ops, updateRoute...)
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("operation errors=%+v err=%v", opErrors, err)
	}

	var stats AuditStats
	requireEventually(t, func() bool {
		var err error
		stats, err = AuditManagedObjectsFromReaderWithDesired(ctx, reader, desired)
		return err == nil && stats.DriftedManagedRows == 3 && stats.DriftedManagedFields == 3
	})
	if stats.DriftedManagedRows != 3 || stats.DriftedManagedFields != 3 {
		t.Fatalf("audit stats = %+v, want three column drifted managed rows", stats)
	}
}

func newTestOVNNBClient(t *testing.T) (libovsdbclient.Client, func()) {
	t.Helper()
	clientModel, err := ovnnb.FullDatabaseModel()
	if err != nil {
		t.Fatal(err)
	}
	schema, err := ovnnb.DatabaseSchema()
	if err != nil {
		t.Fatal(err)
	}
	databaseModel, errs := model.NewDatabaseModel(schema, clientModel)
	if len(errs) > 0 {
		t.Fatalf("database model errors: %+v", errs)
	}
	logger := logr.Discard()
	db := inmemory.NewDatabase(map[string]model.ClientDBModel{ovnnb.DatabaseName: clientModel}, &logger)
	ovsServer, err := server.NewOvsdbServer(db, &logger, databaseModel)
	if err != nil {
		t.Fatal(err)
	}
	socket := fmt.Sprintf("/tmp/netloom-ovnnb-%d.sock", rand.Int())
	_ = os.Remove(socket)
	go func() {
		if err := ovsServer.Serve("unix", socket); err != nil {
			t.Logf("libovsdb test server stopped: %v", err)
		}
	}()
	requireEventually(t, ovsServer.Ready)

	client, err := libovsdbclient.NewOVSDBClient(clientModel, libovsdbclient.WithEndpoint("unix:"+socket))
	if err != nil {
		ovsServer.Close()
		t.Fatal(err)
	}
	if err := client.Connect(context.Background()); err != nil {
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

func insertRows(t *testing.T, ctx context.Context, client libovsdbclient.Client, rows ...model.Model) {
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
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("operation errors=%+v err=%v", opErrors, err)
	}
}

func requireEventually(t *testing.T, condition func() bool) {
	t.Helper()
	if !eventually(condition) {
		t.Fatal("condition did not become true")
	}
}

func eventually(condition func() bool) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return condition()
}
