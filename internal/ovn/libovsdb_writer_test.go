package ovn

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	ovsmodel "github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/ovnnb"
	"github.com/jimyag/netloom/internal/topology"
)

func TestLibOVSDBTopologyWriterEnsuresVPCLogicalRouter(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}

	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1
	})
	if routers[0].ExternalIDs["netloom_owner"] != "netloom" || routers[0].ExternalIDs["netloom_vpc"] != "prod" {
		t.Fatalf("logical router external IDs = %+v, want netloom ownership", routers[0].ExternalIDs)
	}
}

func TestLibOVSDBTopologyWriterClearsStaleVPCLogicalRouterOptions(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}

	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1
	})
	staleGroup := &ovnnb.LoadBalancerGroup{
		UUID: ovsdbNamedUUID("stale-router-lbg"),
		Name: "stale-router-lbg",
	}
	createGroupOps, err := client.Create(staleGroup)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, createGroupOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, createGroupOps); err != nil {
		t.Fatalf("create stale router load balancer group operation errors=%+v: %v", opErrors, err)
	}
	var groups []ovnnb.LoadBalancerGroup
	requireEventually(t, func() bool {
		groups = nil
		err := client.WhereCache(func(row *ovnnb.LoadBalancerGroup) bool { return row.Name == "stale-router-lbg" }).List(ctx, &groups)
		return err == nil && len(groups) == 1
	})
	routers[0].Options = map[string]string{"chassis": "node-old"}
	routers[0].LoadBalancerGroup = []string{groups[0].UUID}
	ops, err := client.Where(&routers[0]).Update(&routers[0], &routers[0].Options, &routers[0].LoadBalancerGroup)
	if err != nil {
		t.Fatal(err)
	}
	results, err = client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("seed router options drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 && routers[0].Options["chassis"] == "node-old" && len(routers[0].LoadBalancerGroup) == 1
	})

	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 && len(routers[0].Options) == 0 && len(routers[0].LoadBalancerGroup) == 0
	})
}

func TestLibOVSDBTopologyWriterCleanupRepairsVPCRouterDriftInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	state := topology.State{
		VPCs: map[string]model.VPC{"prod": {Name: "prod"}},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}

	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1
	})
	routerUUID := routers[0].UUID
	staleGroup := &ovnnb.LoadBalancerGroup{
		UUID: ovsdbNamedUUID("cleanup-stale-router-lbg"),
		Name: "cleanup-stale-router-lbg",
	}
	createGroupOps, err := client.Create(staleGroup)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, createGroupOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, createGroupOps); err != nil {
		t.Fatalf("create stale router load balancer group operation errors=%+v: %v", opErrors, err)
	}
	var groups []ovnnb.LoadBalancerGroup
	requireEventually(t, func() bool {
		groups = nil
		err := client.WhereCache(func(row *ovnnb.LoadBalancerGroup) bool { return row.Name == "cleanup-stale-router-lbg" }).List(ctx, &groups)
		return err == nil && len(groups) == 1
	})

	routers[0].ExternalIDs = map[string]string{
		"netloom_owner": "netloom",
		"netloom_vpc":   "wrong",
		"custom":        "keep",
	}
	routers[0].Options = map[string]string{"chassis": "node-old", "custom": "keep"}
	routers[0].LoadBalancerGroup = []string{groups[0].UUID}
	updateOps, err := client.Where(&routers[0]).Update(&routers[0], &routers[0].ExternalIDs, &routers[0].Options, &routers[0].LoadBalancerGroup)
	if err != nil {
		t.Fatal(err)
	}
	results, err = client.Transact(ctx, updateOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, updateOps); err != nil {
		t.Fatalf("seed router drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 &&
			routers[0].UUID == routerUUID &&
			routers[0].ExternalIDs["netloom_vpc"] == "wrong" &&
			routers[0].Options["chassis"] == "node-old" &&
			len(routers[0].LoadBalancerGroup) == 1
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	finalStateOK := func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 &&
			routers[0].UUID == routerUUID &&
			routers[0].ExternalIDs["custom"] == "keep" &&
			routers[0].ExternalIDs["netloom_vpc"] == "prod" &&
			routers[0].Options["custom"] == "keep" &&
			routers[0].Options["chassis"] == "" &&
			len(routers[0].LoadBalancerGroup) == 0
	}
	if !eventually(finalStateOK) {
		routers = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("router after repair = %+v", routers)
	}
	stats := writer.LastCleanupStats()
	if stats.FirstReconcileGC || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want steady-state VPC router repair operations", stats)
	}
}

func TestLibOVSDBTopologyWriterEnsuresSubnetLogicalSwitch(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, model.Subnet{
		Name:         "apps",
		VPC:          "prod",
		CIDR:         netip.MustParsePrefix("10.10.0.0/24"),
		Gateway:      netip.MustParseAddr("10.10.0.1"),
		ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("10.10.0.10/32")},
	}); err != nil {
		t.Fatal(err)
	}

	var switches []ovnnb.LogicalSwitch
	requireEventually(t, func() bool {
		switches = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == logicalSwitch("prod", "apps") }).List(ctx, &switches)
		return err == nil && len(switches) == 1
	})
	sw := switches[0]
	if sw.ExternalIDs["netloom_owner"] != "netloom" || sw.ExternalIDs["netloom_vpc"] != "prod" || sw.ExternalIDs["netloom_subnet"] != "apps" {
		t.Fatalf("logical switch external IDs = %+v, want netloom subnet ownership", sw.ExternalIDs)
	}
	if sw.OtherConfig["subnet"] != "10.10.0.0/24" || sw.OtherConfig["exclude_ips"] != "10.10.0.1 10.10.0.10" {
		t.Fatalf("logical switch other_config = %+v, want IPv4 IPAM config", sw.OtherConfig)
	}
	staleGroup := &ovnnb.LoadBalancerGroup{
		UUID: ovsdbNamedUUID("stale-lbg"),
		Name: "stale-lbg",
	}
	createGroupOps, err := client.Create(staleGroup)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, createGroupOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, createGroupOps); err != nil {
		t.Fatalf("create stale load balancer group operation errors=%+v: %v", opErrors, err)
	}
	var groups []ovnnb.LoadBalancerGroup
	requireEventually(t, func() bool {
		groups = nil
		err := client.WhereCache(func(row *ovnnb.LoadBalancerGroup) bool { return row.Name == "stale-lbg" }).List(ctx, &groups)
		return err == nil && len(groups) == 1
	})
	sw.LoadBalancerGroup = []string{groups[0].UUID}
	updateSwitchOps, err := client.Where(&sw).Update(&sw, &sw.LoadBalancerGroup)
	if err != nil {
		t.Fatal(err)
	}
	results, err = client.Transact(ctx, updateSwitchOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, updateSwitchOps); err != nil {
		t.Fatalf("seed stale switch group operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		switches = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == logicalSwitch("prod", "apps") }).List(ctx, &switches)
		return err == nil && len(switches) == 1 && len(switches[0].LoadBalancerGroup) == 1
	})
	if err := writer.EnsureSubnet(ctx, model.Subnet{
		Name:         "apps",
		VPC:          "prod",
		CIDR:         netip.MustParsePrefix("10.10.0.0/24"),
		Gateway:      netip.MustParseAddr("10.10.0.1"),
		ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("10.10.0.10/32")},
	}); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		switches = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == logicalSwitch("prod", "apps") }).List(ctx, &switches)
		return err == nil && len(switches) == 1 && len(switches[0].LoadBalancerGroup) == 0
	})
	var routerPorts []ovnnb.LogicalRouterPort
	requireEventually(t, func() bool {
		routerPorts = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool {
			return row.Name == routerPortName(logicalRouter("prod"), "apps")
		}).List(ctx, &routerPorts)
		return err == nil && len(routerPorts) == 1
	})
	if routerPorts[0].MAC == "" || len(routerPorts[0].Networks) != 1 || routerPorts[0].Networks[0] != "10.10.0.1/24" {
		t.Fatalf("logical router port = %+v, want gateway MAC and network", routerPorts[0])
	}
	if routerPorts[0].ExternalIDs["netloom_vpc"] != "prod" || routerPorts[0].ExternalIDs["netloom_subnet"] != "apps" {
		t.Fatalf("logical router port external IDs = %+v, want VPC-scoped subnet identity", routerPorts[0].ExternalIDs)
	}
	var switchPorts []ovnnb.LogicalSwitchPort
	requireEventually(t, func() bool {
		switchPorts = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool {
			return row.Name == switchRouterPortName(logicalSwitch("prod", "apps"), "apps")
		}).List(ctx, &switchPorts)
		return err == nil && len(switchPorts) == 1
	})
	if switchPorts[0].Type != "router" || switchPorts[0].Options["router-port"] != routerPorts[0].Name {
		t.Fatalf("logical switch router port = %+v, want router port options", switchPorts[0])
	}
	if switchPorts[0].ExternalIDs["netloom_vpc"] != "prod" || switchPorts[0].ExternalIDs["netloom_subnet"] != "apps" {
		t.Fatalf("logical switch router port external IDs = %+v, want VPC-scoped subnet identity", switchPorts[0].ExternalIDs)
	}
	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 && containsString(routers[0].Ports, routerPorts[0].UUID)
	})
	requireEventually(t, func() bool {
		switches = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == logicalSwitch("prod", "apps") }).List(ctx, &switches)
		return err == nil && len(switches) == 1 && containsString(switches[0].Ports, switchPorts[0].UUID)
	})
}

func TestLibOVSDBTopologyWriterUpdatesSubnetIPAMConfig(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	insertRows(t, ctx, client, &ovnnb.LogicalSwitch{
		Name:        logicalSwitch("prod", "apps"),
		ExternalIDs: map[string]string{"custom": "keep"},
		OtherConfig: map[string]string{"subnet": "10.10.0.0/24", "exclude_ips": "10.10.0.1", "custom": "keep"},
	})
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("fd00:10::/64"),
		Gateway: netip.MustParseAddr("fd00:10::1"),
	}); err != nil {
		t.Fatal(err)
	}

	var switches []ovnnb.LogicalSwitch
	requireEventually(t, func() bool {
		switches = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == logicalSwitch("prod", "apps") }).List(ctx, &switches)
		return err == nil && len(switches) == 1 && switches[0].OtherConfig["ipv6_prefix"] == "fd00:10::"
	})
	sw := switches[0]
	if sw.ExternalIDs["custom"] != "keep" || sw.ExternalIDs["netloom_owner"] != "netloom" || sw.ExternalIDs["netloom_subnet"] != "apps" {
		t.Fatalf("logical switch external IDs after update = %+v, want preserved custom and netloom ownership", sw.ExternalIDs)
	}
	if _, ok := sw.OtherConfig["subnet"]; ok {
		t.Fatalf("logical switch other_config = %+v, want IPv4 subnet key removed", sw.OtherConfig)
	}
	if _, ok := sw.OtherConfig["exclude_ips"]; ok {
		t.Fatalf("logical switch other_config = %+v, want IPv4 exclude_ips key removed", sw.OtherConfig)
	}
	if sw.OtherConfig["custom"] != "keep" {
		t.Fatalf("logical switch other_config = %+v, want custom key preserved", sw.OtherConfig)
	}
}

func TestLibOVSDBTopologyWriterCleanupRepairsSubnetSwitchDriftInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := model.Subnet{
		Name:         "apps",
		VPC:          "prod",
		CIDR:         netip.MustParsePrefix("10.10.0.0/24"),
		Gateway:      netip.MustParseAddr("10.10.0.1"),
		ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("10.10.0.10/32")},
	}
	state := topology.State{
		VPCs:    map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets: map[string]model.Subnet{subnetStateKey("prod", "apps"): subnet},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}

	staleGroup := &ovnnb.LoadBalancerGroup{
		UUID: ovsdbNamedUUID("cleanup-stale-lbg"),
		Name: "cleanup-stale-lbg",
	}
	createGroupOps, err := client.Create(staleGroup)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, createGroupOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, createGroupOps); err != nil {
		t.Fatalf("create stale load balancer group operation errors=%+v: %v", opErrors, err)
	}
	var groups []ovnnb.LoadBalancerGroup
	requireEventually(t, func() bool {
		groups = nil
		err := client.WhereCache(func(row *ovnnb.LoadBalancerGroup) bool { return row.Name == "cleanup-stale-lbg" }).List(ctx, &groups)
		return err == nil && len(groups) == 1
	})

	sw := singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "apps"))
	sw.ExternalIDs = map[string]string{
		"netloom_owner":  "netloom",
		"netloom_vpc":    "prod",
		"netloom_subnet": "wrong",
		"custom":         "keep",
	}
	sw.OtherConfig = map[string]string{
		"subnet":      "10.99.0.0/24",
		"exclude_ips": "10.99.0.1",
		"custom":      "keep",
	}
	sw.LoadBalancerGroup = []string{groups[0].UUID}
	updateSwitchOps, err := client.Where(&sw).Update(&sw, &sw.ExternalIDs, &sw.OtherConfig, &sw.LoadBalancerGroup)
	if err != nil {
		t.Fatal(err)
	}
	results, err = client.Transact(ctx, updateSwitchOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, updateSwitchOps); err != nil {
		t.Fatalf("seed subnet switch drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		next := singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "apps"))
		return next.ExternalIDs["netloom_subnet"] == "wrong" &&
			next.OtherConfig["subnet"] == "10.99.0.0/24" &&
			len(next.LoadBalancerGroup) == 1
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		var switches []ovnnb.LogicalSwitch
		err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool {
			return row.Name == logicalSwitch("prod", "apps")
		}).List(ctx, &switches)
		if err != nil || len(switches) != 1 {
			return false
		}
		next := switches[0]
		return next.ExternalIDs["custom"] == "keep" &&
			next.ExternalIDs["netloom_subnet"] == "apps" &&
			next.OtherConfig["custom"] == "keep" &&
			next.OtherConfig["subnet"] == "10.10.0.0/24" &&
			next.OtherConfig["exclude_ips"] == "10.10.0.1 10.10.0.10" &&
			len(next.LoadBalancerGroup) == 0
	})
	stats := writer.LastCleanupStats()
	if stats.FirstReconcileGC || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want steady-state subnet switch repair operations", stats)
	}
}

func TestLibOVSDBTopologyWriterEnsuresSubnetLocalnetPort(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, model.Subnet{
		Name:            "apps",
		VPC:             "prod",
		CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
		Gateway:         netip.MustParseAddr("10.10.0.1"),
		ProviderNetwork: "physnet-a",
		VLAN:            100,
	}); err != nil {
		t.Fatal(err)
	}

	var ports []ovnnb.LogicalSwitchPort
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool {
			return row.Name == localnetPortName(logicalSwitch("prod", "apps"), "apps")
		}).List(ctx, &ports)
		return err == nil && len(ports) == 1
	})
	port := ports[0]
	if port.Type != "localnet" || port.Options["network_name"] != "physnet-a" || port.Tag == nil || *port.Tag != 100 {
		t.Fatalf("localnet port = %+v, want provider network and VLAN tag", port)
	}
	if port.ExternalIDs["netloom_vpc"] != "prod" || port.ExternalIDs["netloom_subnet"] != "apps" {
		t.Fatalf("localnet port external IDs = %+v, want VPC-scoped subnet identity", port.ExternalIDs)
	}
	var switches []ovnnb.LogicalSwitch
	requireEventually(t, func() bool {
		switches = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == logicalSwitch("prod", "apps") }).List(ctx, &switches)
		return err == nil && len(switches) == 1 && containsString(switches[0].Ports, port.UUID)
	})

	if err := writer.EnsureSubnet(ctx, model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool {
			return row.Name == localnetPortName(logicalSwitch("prod", "apps"), "apps")
		}).List(ctx, &ports)
		return err == nil && len(ports) == 0
	})
	requireEventually(t, func() bool {
		switches = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == logicalSwitch("prod", "apps") }).List(ctx, &switches)
		return err == nil && len(switches) == 1 && !containsString(switches[0].Ports, port.UUID)
	})
}

func TestLibOVSDBTopologyWriterSyncsDNSRecords(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	subnets := []model.Subnet{{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}, {
		Name:    "db",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.20.0.0/24"),
		Gateway: netip.MustParseAddr("10.20.0.1"),
	}}
	for _, subnet := range subnets {
		if err := writer.EnsureSubnet(ctx, subnet); err != nil {
			t.Fatal(err)
		}
	}
	records := []model.DNSRecord{{
		Name: "api.example.com.",
		IPs: []netip.Addr{
			netip.MustParseAddr("203.0.113.10"),
			netip.MustParseAddr("2001:db8::10"),
		},
	}, {
		Name: "api.example.com",
		IPs:  []netip.Addr{netip.MustParseAddr("203.0.113.20")},
	}}

	if err := writer.SyncDNSRecords(ctx, subnets, records); err != nil {
		t.Fatal(err)
	}

	var dnsRows []ovnnb.DNS
	requireEventually(t, func() bool {
		dnsRows = nil
		err := client.WhereCache(func(row *ovnnb.DNS) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &dnsRows)
		return err == nil && len(dnsRows) == 1
	})
	if dnsRows[0].ExternalIDs["netloom_dns"] != "desired" ||
		dnsRows[0].Records["api.example.com"] != "2001:db8::10 203.0.113.10 203.0.113.20" {
		t.Fatalf("DNS row = %+v, want merged desired records", dnsRows[0])
	}
	for _, subnet := range subnets {
		sw := singleLogicalSwitchByName(t, ctx, client, logicalSwitch(subnet.VPC, subnet.Name))
		if !containsString(sw.DNSRecords, dnsRows[0].UUID) {
			t.Fatalf("switch %s DNS records = %+v, want %s", sw.Name, sw.DNSRecords, dnsRows[0].UUID)
		}
	}
	stats, err := AuditManagedObjectsFromReaderWithDesired(ctx, NewLibOVSDBManagedReader(client), topology.State{
		VPCs:       map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets:    map[string]model.Subnet{"prod/apps": subnets[0], "prod/db": subnets[1]},
		DNSRecords: records,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.ManagedDNSRecords != 1 || stats.MissingManagedRows != 0 || stats.UnexpectedManagedRows != 0 || stats.DriftedManagedRows != 0 {
		t.Fatalf("audit stats = %+v, want one healthy managed DNS row", stats)
	}

	if err := writer.SyncDNSRecords(ctx, subnets[:1], []model.DNSRecord{{
		Name: "api.example.com",
		IPs:  []netip.Addr{netip.MustParseAddr("203.0.113.30")},
	}}); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		dnsRows = nil
		err := client.WhereCache(func(row *ovnnb.DNS) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &dnsRows)
		return err == nil && len(dnsRows) == 1 && dnsRows[0].Records["api.example.com"] == "203.0.113.30"
	})
	appSwitch := singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "apps"))
	dbSwitch := singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "db"))
	if !containsString(appSwitch.DNSRecords, dnsRows[0].UUID) {
		t.Fatalf("apps switch DNS records = %+v, want %s", appSwitch.DNSRecords, dnsRows[0].UUID)
	}
	if containsString(dbSwitch.DNSRecords, dnsRows[0].UUID) {
		t.Fatalf("db switch DNS records = %+v, want DNS reference removed", dbSwitch.DNSRecords)
	}

	if err := writer.SyncDNSRecords(ctx, subnets, nil); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		dnsRows = nil
		err := client.WhereCache(func(row *ovnnb.DNS) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &dnsRows)
		return err == nil && len(dnsRows) == 0
	})
	appSwitch = singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "apps"))
	if len(appSwitch.DNSRecords) != 0 {
		t.Fatalf("apps switch DNS records = %+v, want cleared after empty sync", appSwitch.DNSRecords)
	}
}

func TestLibOVSDBTopologyWriterCleanupRepairsDNSRowAndSwitchDriftInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnets := []model.Subnet{{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}, {
		Name:    "db",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.20.0.0/24"),
		Gateway: netip.MustParseAddr("10.20.0.1"),
	}}
	records := []model.DNSRecord{{
		Name: "api.example.com.",
		IPs: []netip.Addr{
			netip.MustParseAddr("203.0.113.10"),
			netip.MustParseAddr("2001:db8::10"),
		},
	}, {
		Name: "api.example.com",
		IPs:  []netip.Addr{netip.MustParseAddr("203.0.113.20")},
	}}
	state := topology.State{
		VPCs: map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps"): subnets[0],
			subnetStateKey("prod", "db"):   subnets[1],
		},
		DNSRecords: records,
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}
	for _, subnet := range subnets {
		if err := writer.EnsureSubnet(ctx, subnet); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.SyncDNSRecords(ctx, subnets, records); err != nil {
		t.Fatal(err)
	}

	var dnsRows []ovnnb.DNS
	requireEventually(t, func() bool {
		dnsRows = nil
		err := client.WhereCache(func(row *ovnnb.DNS) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &dnsRows)
		return err == nil && len(dnsRows) == 1
	})
	dnsRows[0].Records = map[string]string{"api.example.com": "198.51.100.10"}
	dnsRows[0].Options = map[string]string{"legacy": "true"}
	updateDNS, err := client.Where(&dnsRows[0]).Update(&dnsRows[0], &dnsRows[0].Records, &dnsRows[0].Options)
	if err != nil {
		t.Fatal(err)
	}
	detachDB, err := writer.detachDNSRowFromSwitch(singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "db")).UUID, dnsRows[0].UUID)
	if err != nil {
		t.Fatal(err)
	}
	ops := append(updateDNS, detachDB...)
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("seed DNS drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		dnsRows = nil
		err := client.WhereCache(func(row *ovnnb.DNS) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &dnsRows)
		if err != nil || len(dnsRows) != 1 || dnsRows[0].Records["api.example.com"] != "198.51.100.10" || dnsRows[0].Options["legacy"] != "true" {
			return false
		}
		dbSwitch := singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "db"))
		return !containsString(dbSwitch.DNSRecords, dnsRows[0].UUID)
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		dnsRows = nil
		err := client.WhereCache(func(row *ovnnb.DNS) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &dnsRows)
		if err != nil || len(dnsRows) != 1 || dnsRows[0].Records["api.example.com"] != "2001:db8::10 203.0.113.10 203.0.113.20" || len(dnsRows[0].Options) != 0 {
			return false
		}
		for _, subnet := range subnets {
			sw := singleLogicalSwitchByName(t, ctx, client, logicalSwitch(subnet.VPC, subnet.Name))
			if !containsString(sw.DNSRecords, dnsRows[0].UUID) {
				return false
			}
		}
		return true
	})
	stats := writer.LastCleanupStats()
	if stats.FirstReconcileGC || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want steady-state DNS repair operations", stats)
	}
}

func TestLibOVSDBTopologyWriterRepairsSubnetPortReferences(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}
	routerPort := &ovnnb.LogicalRouterPort{
		Name:     routerPortName(logicalRouter("prod"), "apps"),
		MAC:      deterministicMAC(subnet),
		Networks: []string{"10.10.0.1/24"},
	}
	switchPort := &ovnnb.LogicalSwitchPort{
		Name:      switchRouterPortName(logicalSwitch("prod", "apps"), "apps"),
		Type:      "router",
		Addresses: []string{deterministicMAC(subnet)},
		Options:   map[string]string{"router-port": routerPort.Name},
	}
	insertRows(t, ctx, client,
		&ovnnb.LogicalRouter{Name: logicalRouter("prod")},
		&ovnnb.LogicalSwitch{Name: logicalSwitch("prod", "apps")},
		routerPort,
		switchPort,
	)

	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}

	var routerPorts []ovnnb.LogicalRouterPort
	requireEventually(t, func() bool {
		routerPorts = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool { return row.Name == routerPort.Name }).List(ctx, &routerPorts)
		return err == nil && len(routerPorts) == 1
	})
	var switchPorts []ovnnb.LogicalSwitchPort
	requireEventually(t, func() bool {
		switchPorts = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == switchPort.Name }).List(ctx, &switchPorts)
		return err == nil && len(switchPorts) == 1
	})
	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 && containsString(routers[0].Ports, routerPorts[0].UUID)
	})
	var switches []ovnnb.LogicalSwitch
	requireEventually(t, func() bool {
		switches = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == logicalSwitch("prod", "apps") }).List(ctx, &switches)
		return err == nil && len(switches) == 1 && containsString(switches[0].Ports, switchPorts[0].UUID)
	})
}

func TestLibOVSDBTopologyWriterCleanupRepairsSubnetPortAttachmentDriftInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := model.Subnet{
		Name:            "apps",
		VPC:             "prod",
		CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
		Gateway:         netip.MustParseAddr("10.10.0.1"),
		ProviderNetwork: "physnet",
		VLAN:            42,
	}
	state := topology.State{
		VPCs:    map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets: map[string]model.Subnet{subnetStateKey("prod", "apps"): subnet},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}

	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 && len(routers[0].Ports) == 1
	})
	sw := singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "apps"))
	routerPort := routerPortName(logicalRouter("prod"), "apps")
	switchRouterPort := switchRouterPortName(logicalSwitch("prod", "apps"), "apps")
	localnetPort := localnetPortName(logicalSwitch("prod", "apps"), "apps")
	var switchPorts []ovnnb.LogicalSwitchPort
	requireEventually(t, func() bool {
		switchPorts = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool {
			return row.Name == switchRouterPort || row.Name == localnetPort
		}).List(ctx, &switchPorts)
		sw = singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "apps"))
		return err == nil && len(switchPorts) == 2 && len(sw.Ports) == 2
	})

	routers[0].Ports = nil
	sw.Ports = nil
	updateRouter, err := client.Where(&routers[0]).Update(&routers[0], &routers[0].Ports)
	if err != nil {
		t.Fatal(err)
	}
	updateSwitch, err := client.Where(&sw).Update(&sw, &sw.Ports)
	if err != nil {
		t.Fatal(err)
	}
	ops := append(updateRouter, updateSwitch...)
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("seed subnet port attachment drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		routers = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers); err != nil || len(routers) != 1 || len(routers[0].Ports) != 0 {
			return false
		}
		sw = singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "apps"))
		return len(sw.Ports) == 0
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		var routerPorts []ovnnb.LogicalRouterPort
		if err := client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool { return row.Name == routerPort }).List(ctx, &routerPorts); err != nil || len(routerPorts) != 1 {
			return false
		}
		var switchRouterPorts []ovnnb.LogicalSwitchPort
		if err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == switchRouterPort }).List(ctx, &switchRouterPorts); err != nil || len(switchRouterPorts) != 1 {
			return false
		}
		var localnetPorts []ovnnb.LogicalSwitchPort
		if err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == localnetPort }).List(ctx, &localnetPorts); err != nil || len(localnetPorts) != 1 {
			return false
		}
		routers = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers); err != nil || len(routers) != 1 || !containsString(routers[0].Ports, routerPorts[0].UUID) {
			return false
		}
		sw = singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "apps"))
		return containsString(sw.Ports, switchRouterPorts[0].UUID) && containsString(sw.Ports, localnetPorts[0].UUID)
	})
	stats := writer.LastCleanupStats()
	if stats.FirstReconcileGC || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want steady-state subnet port attachment repair operations", stats)
	}
}

func TestLibOVSDBTopologyWriterCleanupRepairsIPv6RouterPortRADriftInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := model.Subnet{
		Name:    "apps-v6",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("fd00:10::/64"),
		Gateway: netip.MustParseAddr("fd00:10::1"),
		DHCP:    model.DHCPOptions{Enabled: true},
	}
	state := topology.State{
		VPCs:    map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets: map[string]model.Subnet{subnetStateKey("prod", "apps-v6"): subnet},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}

	var ports []ovnnb.LogicalRouterPort
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool {
			return row.Name == routerPortName(logicalRouter("prod"), "apps-v6")
		}).List(ctx, &ports)
		return err == nil && len(ports) == 1 && ports[0].Ipv6RaConfigs["address_mode"] == "dhcpv6_stateful"
	})
	ports[0].Ipv6RaConfigs = nil
	updateOps, err := client.Where(&ports[0]).Update(&ports[0], &ports[0].Ipv6RaConfigs)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, updateOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, updateOps); err != nil {
		t.Fatalf("seed IPv6 RA drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool {
			return row.Name == routerPortName(logicalRouter("prod"), "apps-v6")
		}).List(ctx, &ports)
		return err == nil && len(ports) == 1 && len(ports[0].Ipv6RaConfigs) == 0
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool {
			return row.Name == routerPortName(logicalRouter("prod"), "apps-v6")
		}).List(ctx, &ports)
		return err == nil && len(ports) == 1 && ports[0].Ipv6RaConfigs["address_mode"] == "dhcpv6_stateful"
	})
	stats := writer.LastCleanupStats()
	if stats.FirstReconcileGC || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want steady-state IPv6 RA repair operations", stats)
	}
}

func TestLibOVSDBTopologyWriterRepairsDisabledLogicalRouterAndRouterPort(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}

	disabled := false
	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1
	})
	routers[0].Enabled = &disabled
	routerOps, err := client.Where(&routers[0]).Update(&routers[0], &routers[0].Enabled)
	if err != nil {
		t.Fatal(err)
	}
	var ports []ovnnb.LogicalRouterPort
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool {
			return row.Name == routerPortName(logicalRouter("prod"), "apps")
		}).List(ctx, &ports)
		return err == nil && len(ports) == 1
	})
	ports[0].Enabled = &disabled
	portOps, err := client.Where(&ports[0]).Update(&ports[0], &ports[0].Enabled)
	if err != nil {
		t.Fatal(err)
	}
	ops := append(routerOps, portOps...)
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("seed disabled router drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		routers = nil
		ports = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers); err != nil {
			return false
		}
		if err := client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool {
			return row.Name == routerPortName(logicalRouter("prod"), "apps")
		}).List(ctx, &ports); err != nil {
			return false
		}
		return len(routers) == 1 && routers[0].Enabled != nil && !*routers[0].Enabled &&
			len(ports) == 1 && ports[0].Enabled != nil && !*ports[0].Enabled
	})

	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		routers = nil
		ports = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers); err != nil {
			return false
		}
		if err := client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool {
			return row.Name == routerPortName(logicalRouter("prod"), "apps")
		}).List(ctx, &ports); err != nil {
			return false
		}
		return len(routers) == 1 && routers[0].Enabled == nil &&
			len(ports) == 1 && ports[0].Enabled == nil
	})
}

func TestLibOVSDBTopologyWriterCleanupRepairsCoreNameDriftInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}
	endpoint := model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		Node:   "node-a",
		IP:     netip.MustParseAddr("10.10.0.20"),
		MAC:    "02:00:00:00:00:20",
	}
	state := topology.State{
		VPCs:      map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets:   map[string]model.Subnet{subnetStateKey("prod", "apps"): subnet},
		Endpoints: map[string]model.Endpoint{"prod/pod-a": endpoint},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}

	var routers []ovnnb.LogicalRouter
	var switches []ovnnb.LogicalSwitch
	var routerPorts []ovnnb.LogicalRouterPort
	var switchPorts []ovnnb.LogicalSwitchPort
	requireEventually(t, func() bool {
		routers = nil
		switches = nil
		routerPorts = nil
		switchPorts = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.ExternalIDs["netloom_vpc"] == "prod" }).List(ctx, &routers); err != nil {
			return false
		}
		if err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_subnet"] == "apps"
		}).List(ctx, &switches); err != nil {
			return false
		}
		if err := client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool { return row.ExternalIDs["netloom_subnet"] == "apps" }).List(ctx, &routerPorts); err != nil {
			return false
		}
		if err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool {
			return row.ExternalIDs["netloom_subnet"] == "apps" &&
				(row.ExternalIDs["netloom_role"] == "router" || row.ExternalIDs["netloom_endpoint"] == endpointExternalID("prod", "pod-a"))
		}).List(ctx, &switchPorts); err != nil {
			return false
		}
		return len(routers) == 1 && len(switches) == 1 && len(routerPorts) == 1 && len(switchPorts) == 2
	})
	routers[0].Name = "renamed-router"
	switches[0].Name = "renamed-switch"
	routerPorts[0].Name = "renamed-router-port"
	for i := range switchPorts {
		if switchPorts[i].ExternalIDs["netloom_role"] == "router" {
			switchPorts[i].Name = "renamed-switch-router-port"
		} else {
			switchPorts[i].Name = "renamed-endpoint-port"
		}
	}
	var ops []ovsdb.Operation
	updateRouter, err := client.Where(&routers[0]).Update(&routers[0], &routers[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	ops = append(ops, updateRouter...)
	updateSwitch, err := client.Where(&switches[0]).Update(&switches[0], &switches[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	ops = append(ops, updateSwitch...)
	updateRouterPort, err := client.Where(&routerPorts[0]).Update(&routerPorts[0], &routerPorts[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	ops = append(ops, updateRouterPort...)
	for i := range switchPorts {
		updateSwitchPort, err := client.Where(&switchPorts[i]).Update(&switchPorts[i], &switchPorts[i].Name)
		if err != nil {
			t.Fatal(err)
		}
		ops = append(ops, updateSwitchPort...)
	}
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("seed core name drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		routers = nil
		switches = nil
		routerPorts = nil
		switchPorts = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == "renamed-router" }).List(ctx, &routers); err != nil {
			return false
		}
		if err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == "renamed-switch" }).List(ctx, &switches); err != nil {
			return false
		}
		if err := client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool { return row.Name == "renamed-router-port" }).List(ctx, &routerPorts); err != nil {
			return false
		}
		if err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool {
			return row.Name == "renamed-switch-router-port" || row.Name == "renamed-endpoint-port"
		}).List(ctx, &switchPorts); err != nil {
			return false
		}
		return len(routers) == 1 && len(switches) == 1 && len(routerPorts) == 1 && len(switchPorts) == 2
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		routers = nil
		switches = nil
		routerPorts = nil
		switchPorts = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers); err != nil {
			return false
		}
		if err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == logicalSwitch("prod", "apps") }).List(ctx, &switches); err != nil {
			return false
		}
		if err := client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool {
			return row.Name == routerPortName(logicalRouter("prod"), "apps")
		}).List(ctx, &routerPorts); err != nil {
			return false
		}
		if err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool {
			return row.Name == switchRouterPortName(logicalSwitch("prod", "apps"), "apps") || row.Name == logicalPort("prod", "pod-a")
		}).List(ctx, &switchPorts); err != nil {
			return false
		}
		return len(routers) == 1 && len(switches) == 1 && len(routerPorts) == 1 && len(switchPorts) == 2
	})
	stats := writer.LastCleanupStats()
	if stats.FirstReconcileGC || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want steady-state core name repair operations", stats)
	}
}

func TestLibOVSDBTopologyWriterEnsuresEndpointWithDHCPv4(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
		DHCP: model.DHCPOptions{
			Enabled:       true,
			LeaseTime:     7200,
			MTU:           1400,
			DNSServers:    []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("fd00::53")},
			DomainName:    "svc.local",
			SearchDomains: []string{"apps.local", "svc.local"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	endpoint := model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		IP:     netip.MustParseAddr("10.10.0.20"),
		MAC:    "02:00:00:00:00:20",
		Node:   "node-a",
	}
	if err := writer.EnsureEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}

	var ports []ovnnb.LogicalSwitchPort
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == logicalPort("prod", "pod-a") }).List(ctx, &ports)
		return err == nil && len(ports) == 1 && ports[0].Dhcpv4Options != nil
	})
	port := ports[0]
	if len(port.Addresses) != 1 || port.Addresses[0] != "02:00:00:00:00:20 10.10.0.20" {
		t.Fatalf("endpoint port addresses = %+v, want static MAC/IP", port.Addresses)
	}
	if len(port.PortSecurity) != 1 || port.PortSecurity[0] != "02:00:00:00:00:20 10.10.0.20" {
		t.Fatalf("endpoint port security = %+v, want static MAC/IP", port.PortSecurity)
	}
	var dhcpRows []ovnnb.DHCPOptions
	requireEventually(t, func() bool {
		dhcpRows = nil
		err := client.WhereCache(func(row *ovnnb.DHCPOptions) bool {
			return row.ExternalIDs["netloom_endpoint"] == endpointExternalID("prod", "pod-a")
		}).List(ctx, &dhcpRows)
		return err == nil && len(dhcpRows) == 1
	})
	dhcp := dhcpRows[0]
	if *port.Dhcpv4Options != dhcp.UUID || port.Dhcpv6Options != nil {
		t.Fatalf("endpoint DHCP bindings v4=%v v6=%v, want only DHCPv4 %s", port.Dhcpv4Options, port.Dhcpv6Options, dhcp.UUID)
	}
	if dhcp.Cidr != "10.10.0.0/24" ||
		dhcp.Options["server_id"] != "10.10.0.1" ||
		dhcp.Options["router"] != "10.10.0.1" ||
		dhcp.Options["lease_time"] != "7200" ||
		dhcp.Options["mtu"] != "1400" ||
		dhcp.Options["dns_server"] != `["1.1.1.1"]` ||
		dhcp.Options["domain_name"] != "svc.local" ||
		dhcp.Options["domain_search_list"] != `["apps.local","svc.local"]` {
		t.Fatalf("DHCPv4 options = %+v cidr=%s, want subnet DHCP projection", dhcp.Options, dhcp.Cidr)
	}
	if dhcp.ExternalIDs["netloom_dhcp_family"] != "4" || dhcp.ExternalIDs["netloom_vpc"] != "prod" {
		t.Fatalf("DHCP external IDs = %+v, want managed endpoint identity", dhcp.ExternalIDs)
	}

	insertRows(t, ctx, client, &ovnnb.DHCPOptions{
		Cidr:    "10.10.0.0/24",
		Options: map[string]string{"lease_time": "60"},
		ExternalIDs: map[string]string{
			"netloom_owner":       "netloom",
			"netloom_vpc":         "prod",
			"netloom_endpoint":    endpointExternalID("prod", "pod-a"),
			"netloom_dhcp_family": "4",
		},
	})
	requireEventually(t, func() bool {
		dhcpRows = nil
		err := client.WhereCache(func(row *ovnnb.DHCPOptions) bool {
			return row.ExternalIDs["netloom_endpoint"] == endpointExternalID("prod", "pod-a")
		}).List(ctx, &dhcpRows)
		return err == nil && len(dhcpRows) == 2
	})
	if err := writer.EnsureEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		dhcpRows = nil
		err := client.WhereCache(func(row *ovnnb.DHCPOptions) bool {
			return row.ExternalIDs["netloom_endpoint"] == endpointExternalID("prod", "pod-a")
		}).List(ctx, &dhcpRows)
		return err == nil && len(dhcpRows) == 1
	})
	ports = nil
	requireEventually(t, func() bool {
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == logicalPort("prod", "pod-a") }).List(ctx, &ports)
		return err == nil && len(ports) == 1 && ports[0].Dhcpv4Options != nil && *ports[0].Dhcpv4Options == dhcpRows[0].UUID
	})
}

func TestLibOVSDBTopologyWriterRepairsEndpointSwitchPortStaleTypeOptionsAndTag(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}); err != nil {
		t.Fatal(err)
	}
	endpoint := model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		IP:     netip.MustParseAddr("10.10.0.20"),
		MAC:    "02:00:00:00:00:20",
		Node:   "node-a",
	}
	if err := writer.EnsureEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}

	var ports []ovnnb.LogicalSwitchPort
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == logicalPort("prod", "pod-a") }).List(ctx, &ports)
		return err == nil && len(ports) == 1
	})
	port := ports[0]
	tag := 100
	port.Type = "localnet"
	port.Options = map[string]string{"network_name": "physnet-a"}
	port.Tag = &tag
	updateOps, err := client.Where(&port).Update(&port, &port.Type, &port.Options, &port.Tag)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, updateOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, updateOps); err != nil {
		t.Fatalf("seed endpoint switch port drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == logicalPort("prod", "pod-a") }).List(ctx, &ports)
		return err == nil && len(ports) == 1 && ports[0].Type == "localnet" && ports[0].Options["network_name"] == "physnet-a" && ports[0].Tag != nil && *ports[0].Tag == 100
	})

	if err := writer.EnsureEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == logicalPort("prod", "pod-a") }).List(ctx, &ports)
		return err == nil && len(ports) == 1 && ports[0].Type == "" && len(ports[0].Options) == 0 && ports[0].Tag == nil
	})
}

func TestLibOVSDBTopologyWriterCleanupRepairsEndpointSwitchPortDriftInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}
	endpoint := model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		IP:     netip.MustParseAddr("10.10.0.20"),
		MAC:    "02:00:00:00:00:20",
		Node:   "node-a",
	}
	state := topology.State{
		VPCs:      map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets:   map[string]model.Subnet{subnetStateKey("prod", "apps"): subnet},
		Endpoints: map[string]model.Endpoint{model.EndpointKey("prod", "pod-a"): endpoint},
	}
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	writer.RestoreTopologyState(state)

	var ports []ovnnb.LogicalSwitchPort
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == logicalPort("prod", "pod-a") }).List(ctx, &ports)
		return err == nil && len(ports) == 1
	})
	port := ports[0]
	tag := 200
	port.Type = "localnet"
	port.Addresses = []string{"unknown"}
	port.PortSecurity = nil
	port.Options = map[string]string{"network_name": "physnet-a"}
	port.Tag = &tag
	disabled := false
	port.Enabled = &disabled
	updateOps, err := client.Where(&port).Update(&port, &port.Type, &port.Addresses, &port.PortSecurity, &port.Options, &port.Tag, &port.Enabled)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, updateOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, updateOps); err != nil {
		t.Fatalf("seed endpoint LSP drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == logicalPort("prod", "pod-a") }).List(ctx, &ports)
		return err == nil &&
			len(ports) == 1 &&
			ports[0].Type == "localnet" &&
			len(ports[0].PortSecurity) == 0 &&
			ports[0].Options["network_name"] == "physnet-a" &&
			ports[0].Tag != nil &&
			*ports[0].Tag == 200 &&
			ports[0].Enabled != nil &&
			!*ports[0].Enabled
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == logicalPort("prod", "pod-a") }).List(ctx, &ports)
		return err == nil &&
			len(ports) == 1 &&
			ports[0].Type == "" &&
			len(ports[0].Options) == 0 &&
			ports[0].Tag == nil &&
			ports[0].Enabled == nil &&
			len(ports[0].Addresses) == 1 &&
			ports[0].Addresses[0] == "02:00:00:00:00:20 10.10.0.20" &&
			len(ports[0].PortSecurity) == 1 &&
			ports[0].PortSecurity[0] == "02:00:00:00:00:20 10.10.0.20"
	})
	stats := writer.LastCleanupStats()
	if stats.FirstReconcileGC || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want steady-state endpoint LSP repair operations", stats)
	}
}

func TestLibOVSDBTopologyWriterClearsEndpointDHCPWhenSubnetDHCPDisabled(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
		DHCP:    model.DHCPOptions{Enabled: true},
	}
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	endpoint := model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		IP:     netip.MustParseAddr("10.10.0.20"),
		MAC:    "02:00:00:00:00:20",
	}
	if err := writer.EnsureEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		var rows []ovnnb.DHCPOptions
		err := client.WhereCache(func(row *ovnnb.DHCPOptions) bool {
			return row.ExternalIDs["netloom_endpoint"] == endpointExternalID("prod", "pod-a")
		}).List(ctx, &rows)
		return err == nil && len(rows) == 1
	})

	subnet.DHCP.Enabled = false
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		var rows []ovnnb.DHCPOptions
		err := client.WhereCache(func(row *ovnnb.DHCPOptions) bool {
			return row.ExternalIDs["netloom_endpoint"] == endpointExternalID("prod", "pod-a")
		}).List(ctx, &rows)
		return err == nil && len(rows) == 0
	})
	var ports []ovnnb.LogicalSwitchPort
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == logicalPort("prod", "pod-a") }).List(ctx, &ports)
		return err == nil && len(ports) == 1 && ports[0].Dhcpv4Options == nil && ports[0].Dhcpv6Options == nil
	})
}

func TestLibOVSDBTopologyWriterEnsuresEndpointWithDHCPv6(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, model.Subnet{
		Name:    "v6",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("fd00:10::/64"),
		Gateway: netip.MustParseAddr("fd00:10::1"),
		DHCP: model.DHCPOptions{
			Enabled:       true,
			DNSServers:    []netip.Addr{netip.MustParseAddr("fd00::53"), netip.MustParseAddr("1.1.1.1")},
			DomainName:    "svc.local",
			SearchDomains: []string{"apps.local"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	endpoint := model.Endpoint{
		ID:     "pod-v6",
		VPC:    "prod",
		Subnet: "v6",
		IP:     netip.MustParseAddr("fd00:10::20"),
	}
	if err := writer.EnsureEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}

	var ports []ovnnb.LogicalSwitchPort
	requireEventually(t, func() bool {
		ports = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == logicalPort("prod", "pod-v6") }).List(ctx, &ports)
		return err == nil && len(ports) == 1 && ports[0].Dhcpv6Options != nil
	})
	if len(ports[0].Addresses) != 1 || ports[0].Addresses[0] != "dynamic fd00:10::20" {
		t.Fatalf("IPv6 endpoint port addresses = %+v, want dynamic address binding", ports[0].Addresses)
	}
	var dhcpRows []ovnnb.DHCPOptions
	requireEventually(t, func() bool {
		dhcpRows = nil
		err := client.WhereCache(func(row *ovnnb.DHCPOptions) bool {
			return row.ExternalIDs["netloom_endpoint"] == endpointExternalID("prod", "pod-v6")
		}).List(ctx, &dhcpRows)
		return err == nil && len(dhcpRows) == 1
	})
	dhcp := dhcpRows[0]
	if *ports[0].Dhcpv6Options != dhcp.UUID || ports[0].Dhcpv4Options != nil {
		t.Fatalf("endpoint DHCP bindings v4=%v v6=%v, want only DHCPv6 %s", ports[0].Dhcpv4Options, ports[0].Dhcpv6Options, dhcp.UUID)
	}
	if dhcp.Cidr != "fd00:10::/64" ||
		dhcp.Options["dns_server"] != `["fd00::53"]` ||
		dhcp.Options["domain_search"] != "apps.local,svc.local" ||
		dhcp.Options["server_id"] == "" {
		t.Fatalf("DHCPv6 options = %+v cidr=%s, want IPv6 DHCP projection", dhcp.Options, dhcp.Cidr)
	}
}

func TestLibOVSDBTopologyWriterEnsuresRouteTableStaticRoutes(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	table := model.RouteTable{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
			NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.253"), netip.MustParseAddr("10.10.0.254")},
		}, {
			Destination: netip.MustParsePrefix("10.30.0.0/24"),
			Blackhole:   true,
		}},
	}
	if err := writer.EnsureRouteTable(ctx, table); err != nil {
		t.Fatal(err)
	}

	var routes []ovnnb.LogicalRouterStaticRoute
	requireEventually(t, func() bool {
		routes = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
			return row.ExternalIDs["netloom_route_table"] == "main"
		}).List(ctx, &routes)
		return err == nil && len(routes) == 3
	})
	got := map[string]ovnnb.LogicalRouterStaticRoute{}
	for _, route := range routes {
		got[route.IPPrefix+"|"+route.Nexthop] = route
		if route.RouteTable != "main" || route.ExternalIDs["netloom_vpc"] != "prod" {
			t.Fatalf("static route = %+v, want route table ownership", route)
		}
	}
	for _, key := range []string{"10.20.0.0/24|10.10.0.253", "10.20.0.0/24|10.10.0.254", "10.30.0.0/24|discard"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("static routes missing %s from %+v", key, got)
		}
	}
	keptECMPUUID := got["10.20.0.0/24|10.10.0.253"].UUID
	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 && len(routers[0].StaticRoutes) == 3
	})

	table.Routes[0].NextHops = []netip.Addr{netip.MustParseAddr("10.10.0.253"), netip.MustParseAddr("10.10.0.252")}
	table.Routes = table.Routes[:1]
	var driftedRoutes []ovnnb.LogicalRouterStaticRoute
	if err := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
		return row.ExternalIDs["netloom_route_key"] == "10.20.0.0/24|10.10.0.253"
	}).List(ctx, &driftedRoutes); err != nil {
		t.Fatal(err)
	}
	if len(driftedRoutes) != 1 {
		t.Fatalf("drift target routes = %d, want one", len(driftedRoutes))
	}
	driftPolicy := ovnnb.LogicalRouterStaticRoutePolicySrcIP
	driftedRoutes[0].RouteTable = "legacy"
	driftedRoutes[0].Options = map[string]string{"ecmp_symmetric_reply": "true"}
	driftedRoutes[0].Policy = &driftPolicy
	driftedRoutes[0].SelectionFields = []ovnnb.LogicalRouterStaticRouteSelectionFields{ovnnb.LogicalRouterStaticRouteSelectionFieldsIPSrc}
	driftOps, err := client.Where(&driftedRoutes[0]).Update(&driftedRoutes[0], &driftedRoutes[0].RouteTable, &driftedRoutes[0].Options, &driftedRoutes[0].Policy, &driftedRoutes[0].SelectionFields)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, driftOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, driftOps); err != nil {
		t.Fatalf("operation errors=%+v err=%v", opErrors, err)
	}

	if err := writer.EnsureRouteTable(ctx, table); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		routes = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
			return row.ExternalIDs["netloom_route_table"] == "main"
		}).List(ctx, &routes)
		if err != nil || len(routes) != 2 {
			return false
		}
		keys := map[string]struct{}{}
		for _, route := range routes {
			keys[route.IPPrefix+"|"+route.Nexthop] = struct{}{}
		}
		_, keep := keys["10.20.0.0/24|10.10.0.253"]
		_, add := keys["10.20.0.0/24|10.10.0.252"]
		_, staleHop := keys["10.20.0.0/24|10.10.0.254"]
		_, staleBlackhole := keys["10.30.0.0/24|discard"]
		keptRoute := staticRoutesByKey(routes)["10.20.0.0/24|10.10.0.253"]
		return keep && add && !staleHop && !staleBlackhole &&
			keptRoute.UUID == keptECMPUUID &&
			keptRoute.RouteTable == "main" &&
			len(keptRoute.Options) == 0 &&
			keptRoute.Policy == nil &&
			len(keptRoute.SelectionFields) == 0
	})
}

func TestLibOVSDBTopologyWriterKeepsReferencedDuplicateStaticRoute(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "dev"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, model.Subnet{
		Name:    "db",
		VPC:     "dev",
		CIDR:    netip.MustParsePrefix("10.20.0.0/24"),
		Gateway: netip.MustParseAddr("10.20.0.1"),
	}); err != nil {
		t.Fatal(err)
	}
	table := model.RouteTable{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("10.40.0.0/24"),
			NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.253")},
		}},
	}
	if err := writer.EnsureRouteTable(ctx, table); err != nil {
		t.Fatal(err)
	}

	var prodRouters []ovnnb.LogicalRouter
	var routes []ovnnb.LogicalRouterStaticRoute
	requireEventually(t, func() bool {
		prodRouters = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &prodRouters); err != nil || len(prodRouters) != 1 || len(prodRouters[0].StaticRoutes) != 1 {
			return false
		}
		routes = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" &&
				row.ExternalIDs["netloom_route_table"] == "main" &&
				row.ExternalIDs["netloom_route_key"] == "10.40.0.0/24|10.10.0.253"
		}).List(ctx, &routes)
		return err == nil && len(routes) == 1
	})
	referencedUUID := prodRouters[0].StaticRoutes[0]
	if routes[0].UUID != referencedUUID {
		t.Fatalf("router static routes = %+v route row = %s, want referenced row", prodRouters[0].StaticRoutes, routes[0].UUID)
	}

	duplicate := desiredStaticRouteRows(table, table.Routes[0])[0]
	duplicate.UUID = ovsdbNamedUUID("duplicate_static_route")
	duplicate.RouteTable = "legacy"
	duplicate.Options = map[string]string{"ecmp_symmetric_reply": "true"}
	var devRouters []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		devRouters = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("dev") }).List(ctx, &devRouters)
		return err == nil && len(devRouters) == 1
	})
	createOps, err := client.Create(&duplicate)
	if err != nil {
		t.Fatal(err)
	}
	attachDuplicate, err := writer.attachStaticRoute(&devRouters[0], duplicate.UUID)
	if err != nil {
		t.Fatal(err)
	}
	duplicateOps := append(createOps, attachDuplicate...)
	results, err := client.Transact(ctx, duplicateOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, duplicateOps); err != nil {
		t.Fatalf("attach duplicate static route operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		routes = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" &&
				row.ExternalIDs["netloom_route_table"] == "main" &&
				row.ExternalIDs["netloom_route_key"] == "10.40.0.0/24|10.10.0.253"
		}).List(ctx, &routes)
		return err == nil && len(routes) == 2
	})

	if err := writer.EnsureRouteTable(ctx, table); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		prodRouters = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &prodRouters); err != nil || len(prodRouters) != 1 || len(prodRouters[0].StaticRoutes) != 1 {
			return false
		}
		routes = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" &&
				row.ExternalIDs["netloom_route_table"] == "main" &&
				row.ExternalIDs["netloom_route_key"] == "10.40.0.0/24|10.10.0.253"
		}).List(ctx, &routes)
		if err != nil ||
			len(routes) != 1 ||
			routes[0].UUID != referencedUUID ||
			prodRouters[0].StaticRoutes[0] != referencedUUID ||
			routes[0].RouteTable != "main" ||
			len(routes[0].Options) != 0 {
			return false
		}
		devRouters = nil
		err = client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("dev") }).List(ctx, &devRouters)
		return err == nil && len(devRouters) == 1 && len(devRouters[0].StaticRoutes) == 0
	})
}

func TestLibOVSDBTopologyWriterEnsuresStaticRouteBFD(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	table := model.RouteTable{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
			NextHops: []netip.Addr{
				netip.MustParseAddr("10.10.0.253"),
				netip.MustParseAddr("10.10.0.254"),
			},
			BFD: model.RouteBFD{
				Enabled:     true,
				LogicalPort: routerPortName(logicalRouter("prod"), "apps"),
				MinTx:       300,
				MinRx:       300,
				DetectMult:  3,
			},
		}},
	}
	if err := writer.EnsureRouteTable(ctx, table); err != nil {
		t.Fatal(err)
	}

	var routes []ovnnb.LogicalRouterStaticRoute
	var bfds []ovnnb.BFD
	requireEventually(t, func() bool {
		routes = nil
		bfds = nil
		routesErr := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
			return row.ExternalIDs["netloom_route_table"] == "main"
		}).List(ctx, &routes)
		bfdErr := client.WhereCache(func(row *ovnnb.BFD) bool {
			return row.ExternalIDs["netloom_route_table"] == "main"
		}).List(ctx, &bfds)
		return routesErr == nil && bfdErr == nil && len(routes) == 2 && len(bfds) == 2
	})
	bfdByRouteKey := make(map[string]ovnnb.BFD, len(bfds))
	for _, bfd := range bfds {
		bfdByRouteKey[bfd.ExternalIDs["netloom_route_key"]] = bfd
		if bfd.LogicalPort != routerPortName(logicalRouter("prod"), "apps") ||
			intPointerField(bfd.MinTx) != "300" ||
			intPointerField(bfd.MinRx) != "300" ||
			intPointerField(bfd.DetectMult) != "3" {
			t.Fatalf("BFD row = %+v, want initial route BFD config", bfd)
		}
	}
	for _, route := range routes {
		routeKey := route.ExternalIDs["netloom_route_key"]
		bfd, ok := bfdByRouteKey[routeKey]
		if !ok {
			t.Fatalf("route %s has no BFD row in %+v", routeKey, bfdByRouteKey)
		}
		if route.BFD == nil || *route.BFD != bfd.UUID {
			t.Fatalf("route %s BFD = %v, want %s", routeKey, route.BFD, bfd.UUID)
		}
	}
	auditState := topology.State{
		VPCs:        map[string]model.VPC{"prod": {Name: "prod"}},
		RouteTables: map[string]model.RouteTable{"prod/main": table},
	}
	stats, err := AuditManagedObjectsFromReaderWithDesired(ctx, NewLibOVSDBManagedReader(client), auditState)
	if err != nil {
		t.Fatal(err)
	}
	if stats.ManagedBFDs != 2 || stats.DriftedManagedRows != 0 || stats.MissingManagedRows != 0 || stats.UnexpectedManagedRows != 0 {
		t.Fatalf("audit stats after BFD create = %+v, want two clean managed BFD rows", stats)
	}

	driftedMinRx := 100
	bfds[0].MinRx = &driftedMinRx
	driftOps, err := client.Where(&bfds[0]).Update(&bfds[0], &bfds[0].MinRx)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, driftOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, driftOps); err != nil {
		t.Fatalf("operation errors=%+v err=%v", opErrors, err)
	}
	requireEventually(t, func() bool {
		stats, err = AuditManagedObjectsFromReaderWithDesired(ctx, NewLibOVSDBManagedReader(client), auditState)
		return err == nil && stats.ManagedBFDs == 2 && stats.DriftedManagedRows == 1 && stats.DriftedManagedFields == 1
	})

	table.Routes[0].NextHops = []netip.Addr{netip.MustParseAddr("10.10.0.253")}
	table.Routes[0].BFD.MinTx = 500
	if err := writer.EnsureRouteTable(ctx, table); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		routes = nil
		bfds = nil
		routesErr := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
			return row.ExternalIDs["netloom_route_table"] == "main"
		}).List(ctx, &routes)
		bfdErr := client.WhereCache(func(row *ovnnb.BFD) bool {
			return row.ExternalIDs["netloom_route_table"] == "main"
		}).List(ctx, &bfds)
		if routesErr != nil || bfdErr != nil || len(routes) != 1 || len(bfds) != 1 {
			return false
		}
		return routes[0].BFD != nil &&
			*routes[0].BFD == bfds[0].UUID &&
			routes[0].Nexthop == "10.10.0.253" &&
			bfds[0].DstIP == "10.10.0.253" &&
			intPointerField(bfds[0].MinTx) == "500"
	})

	table.Routes[0].BFD = model.RouteBFD{}
	if err := writer.EnsureRouteTable(ctx, table); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		routes = nil
		bfds = nil
		routesErr := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
			return row.ExternalIDs["netloom_route_table"] == "main"
		}).List(ctx, &routes)
		bfdErr := client.WhereCache(func(row *ovnnb.BFD) bool {
			return row.ExternalIDs["netloom_route_table"] == "main"
		}).List(ctx, &bfds)
		return routesErr == nil && bfdErr == nil && len(routes) == 1 && routes[0].BFD == nil && len(bfds) == 0
	})
}

func TestLibOVSDBTopologyWriterEnsuresPolicyRouteByName(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	first := model.PolicyRoute{
		Name:     "egress-a",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	}
	second := first
	second.Name = "egress-b"
	second.Action = model.RouteAction{Type: model.ActionDrop}
	if err := writer.EnsurePolicyRoute(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsurePolicyRoute(ctx, second); err != nil {
		t.Fatal(err)
	}

	var policies []ovnnb.LogicalRouterPolicy
	requireEventually(t, func() bool {
		policies = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_policy_route"] != ""
		}).List(ctx, &policies)
		return err == nil && len(policies) == 2
	})
	byName := map[string]ovnnb.LogicalRouterPolicy{}
	for _, policy := range policies {
		byName[policy.ExternalIDs["netloom_policy_route"]] = policy
	}
	if byName["egress-a"].Action != ovnnb.LogicalRouterPolicyActionReroute ||
		byName["egress-a"].Nexthop == nil ||
		*byName["egress-a"].Nexthop != "10.10.0.253" ||
		byName["egress-b"].Action != ovnnb.LogicalRouterPolicyActionDrop {
		t.Fatalf("policies = %+v, want distinct name-owned route rows", byName)
	}

	first.Action = model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.252"), netip.MustParseAddr("10.10.0.253")}}
	if err := writer.EnsurePolicyRoute(ctx, first); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		policies = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_policy_route"] != ""
		}).List(ctx, &policies)
		if err != nil || len(policies) != 2 {
			return false
		}
		for _, policy := range policies {
			if policy.ExternalIDs["netloom_policy_route"] == "egress-a" {
				return policy.Nexthop == nil && len(policy.Nexthops) == 2 && policy.Nexthops[0] == "10.10.0.252" && policy.Nexthops[1] == "10.10.0.253"
			}
		}
		return false
	})
}

func TestLibOVSDBTopologyWriterKeepsReferencedDuplicatePolicyRoute(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "dev"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, model.Subnet{
		Name:    "db",
		VPC:     "dev",
		CIDR:    netip.MustParsePrefix("10.20.0.0/24"),
		Gateway: netip.MustParseAddr("10.20.0.1"),
	}); err != nil {
		t.Fatal(err)
	}
	route := model.PolicyRoute{
		Name:     "via-fw",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("10.30.0.0/24"),
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.254")}},
	}
	if err := writer.EnsurePolicyRoute(ctx, route); err != nil {
		t.Fatal(err)
	}

	var routers []ovnnb.LogicalRouter
	var policies []ovnnb.LogicalRouterPolicy
	requireEventually(t, func() bool {
		routers = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers); err != nil || len(routers) != 1 || len(routers[0].Policies) != 1 {
			return false
		}
		policies = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_policy_route"] == "via-fw"
		}).List(ctx, &policies)
		return err == nil && len(policies) == 1
	})
	referencedUUID := routers[0].Policies[0]
	if policies[0].UUID != referencedUUID {
		t.Fatalf("router policy refs = %+v policy row = %s, want referenced row", routers[0].Policies, policies[0].UUID)
	}

	duplicate := desiredPolicyRouteRow(route)
	duplicate.UUID = ovsdbNamedUUID("duplicate_policy_route")
	duplicate.Priority = 90
	duplicate.Action = ovnnb.LogicalRouterPolicyActionDrop
	duplicate.Nexthop = nil
	duplicate.Nexthops = nil
	var devRouters []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		devRouters = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("dev") }).List(ctx, &devRouters)
		return err == nil && len(devRouters) == 1
	})
	createOps, err := client.Create(&duplicate)
	if err != nil {
		t.Fatal(err)
	}
	attachDuplicate, err := writer.attachPolicyRoute(&devRouters[0], duplicate.UUID)
	if err != nil {
		t.Fatal(err)
	}
	duplicateOps := append(createOps, attachDuplicate...)
	results, err := client.Transact(ctx, duplicateOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, duplicateOps); err != nil {
		t.Fatalf("attach duplicate policy route operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		policies = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_policy_route"] == "via-fw"
		}).List(ctx, &policies)
		return err == nil && len(policies) == 2
	})

	if err := writer.EnsurePolicyRoute(ctx, route); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		routers = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers); err != nil || len(routers) != 1 || len(routers[0].Policies) != 1 {
			return false
		}
		policies = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_policy_route"] == "via-fw"
		}).List(ctx, &policies)
		if err != nil ||
			len(policies) != 1 ||
			policies[0].UUID != referencedUUID ||
			routers[0].Policies[0] != referencedUUID ||
			policies[0].Priority != 100 ||
			policies[0].Action != ovnnb.LogicalRouterPolicyActionReroute ||
			policies[0].Nexthop == nil ||
			*policies[0].Nexthop != "10.10.0.254" {
			return false
		}
		devRouters = nil
		err = client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("dev") }).List(ctx, &devRouters)
		return err == nil && len(devRouters) == 1 && len(devRouters[0].Policies) == 0
	})
}

func TestLibOVSDBTopologyWriterEnsuresGatewayRouterMetadata(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureGateway(ctx, model.Gateway{
		Name:       "gw-a",
		VPC:        "prod",
		Node:       "node-a",
		ExternalIF: "eth0",
		LANIP:      netip.MustParseAddr("10.10.0.1"),
	}); err != nil {
		t.Fatal(err)
	}
	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 && routers[0].Options["chassis"] == "node-a"
	})
	router := routers[0]
	if router.ExternalIDs["netloom_owner"] != "netloom" ||
		router.ExternalIDs["netloom_gateway"] != "gw-a" ||
		router.ExternalIDs["netloom_gateway_lan_ip"] != "10.10.0.1" ||
		router.ExternalIDs["netloom_external_if"] != "eth0" ||
		router.ExternalIDs["netloom_gateway_distributed"] != "false" {
		t.Fatalf("gateway router external IDs = %+v, want centralized gateway metadata", router.ExternalIDs)
	}
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 && routers[0].Options["chassis"] == "node-a"
	})

	if err := writer.EnsureGateway(ctx, model.Gateway{
		Name:        "gw-a",
		VPC:         "prod",
		Node:        "node-a",
		LANIP:       netip.MustParseAddr("10.10.0.1"),
		Distributed: true,
	}); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		if err != nil || len(routers) != 1 {
			return false
		}
		_, hasChassis := routers[0].Options["chassis"]
		_, hasExternalIF := routers[0].ExternalIDs["netloom_external_if"]
		return !hasChassis && !hasExternalIF && routers[0].ExternalIDs["netloom_gateway_distributed"] == "true"
	})
}

func TestLibOVSDBTopologyWriterEnsuresNATRules(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	for _, rule := range []model.NATRule{{
		Name:       "egress",
		VPC:        "prod",
		Type:       model.ActionSNAT,
		MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
		ExternalIP: netip.MustParseAddr("198.51.100.10"),
	}, {
		Name:         "web",
		VPC:          "prod",
		Type:         model.ActionDNAT,
		ExternalIP:   netip.MustParseAddr("198.51.100.80"),
		TargetIP:     netip.MustParseAddr("10.10.0.20"),
		Protocol:     model.ProtocolTCP,
		ExternalPort: 8443,
		TargetPort:   443,
	}, {
		Name:         "fip",
		VPC:          "prod",
		Type:         model.ActionDNATSNAT,
		ExternalIP:   netip.MustParseAddr("198.51.100.81"),
		TargetIP:     netip.MustParseAddr("10.10.0.21"),
		LogicalPort:  "nl_lp_prod_pod-a",
		ExternalMAC:  "0a:58:0a:0a:00:15",
		ExternalPort: 9443,
		TargetPort:   443,
	}} {
		if err := writer.EnsureNATRule(ctx, rule); err != nil {
			t.Fatal(err)
		}
	}

	var nats []ovnnb.NAT
	requireEventually(t, func() bool {
		nats = nil
		err := client.WhereCache(func(row *ovnnb.NAT) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_nat"] != ""
		}).List(ctx, &nats)
		return err == nil && len(nats) == 3
	})
	byName := natRowsByName(nats)
	if byName["egress"].Type != ovnnb.NATTypeSNAT ||
		byName["egress"].LogicalIP != "10.10.0.0/24" ||
		byName["web"].Type != ovnnb.NATTypeDNAT ||
		byName["web"].ExternalPortRange != "8443" ||
		byName["web"].Options["netloom_logical_port_range"] != "443" ||
		byName["web"].Options["netloom_protocol"] != "tcp" ||
		byName["fip"].Type != ovnnb.NATTypeDNATAndSNAT ||
		byName["fip"].LogicalPort == nil ||
		*byName["fip"].LogicalPort != "nl_lp_prod_pod-a" ||
		byName["fip"].ExternalMAC == nil ||
		*byName["fip"].ExternalMAC != "0a:58:0a:0a:00:15" {
		t.Fatalf("NAT rows = %+v, want SNAT, DNAT port metadata, and distributed floating IP fields", byName)
	}
	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 && len(routers[0].Nat) == 3
	})

	duplicateNAT := &ovnnb.NAT{
		UUID:       "duplicate_web_nat",
		Type:       ovnnb.NATTypeDNAT,
		ExternalIP: "198.51.100.80",
		LogicalIP:  "10.10.0.99",
		ExternalIDs: map[string]string{
			"netloom_owner": "netloom",
			"netloom_vpc":   "prod",
			"netloom_nat":   "web",
		},
	}
	createOps, err := client.Create(duplicateNAT)
	if err != nil {
		t.Fatal(err)
	}
	attachOps, err := writer.attachNATRule(&ovnnb.LogicalRouter{UUID: routers[0].UUID}, duplicateNAT.UUID)
	if err != nil {
		t.Fatal(err)
	}
	ops := append(createOps, attachOps...)
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("operation errors=%+v err=%v", opErrors, err)
	}
	requireEventually(t, func() bool {
		nats = nil
		err := client.WhereCache(func(row *ovnnb.NAT) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_nat"] == "web"
		}).List(ctx, &nats)
		return err == nil && len(nats) == 2
	})
	if err := writer.EnsureNATRule(ctx, model.NATRule{
		Name:         "web",
		VPC:          "prod",
		Type:         model.ActionDNAT,
		ExternalIP:   netip.MustParseAddr("198.51.100.80"),
		TargetIP:     netip.MustParseAddr("10.10.0.22"),
		Protocol:     model.ProtocolTCP,
		ExternalPort: 8443,
		TargetPort:   444,
	}); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		nats = nil
		err := client.WhereCache(func(row *ovnnb.NAT) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_nat"] == "web"
		}).List(ctx, &nats)
		return err == nil && len(nats) == 1 && nats[0].LogicalIP == "10.10.0.22" && nats[0].Options["netloom_logical_port_range"] == "444"
	})
	if err := writer.EnsureNATRule(ctx, model.NATRule{
		Name:       "web",
		VPC:        "prod",
		Type:       model.ActionDNAT,
		ExternalIP: netip.MustParseAddr("198.51.100.80"),
		TargetIP:   netip.MustParseAddr("10.10.0.22"),
	}); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		nats = nil
		err := client.WhereCache(func(row *ovnnb.NAT) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_nat"] == "web"
		}).List(ctx, &nats)
		if err != nil || len(nats) != 1 || nats[0].ExternalPortRange != "" || len(nats[0].Options) != 0 {
			return false
		}
		if _, ok := nats[0].ExternalIDs["netloom_external_port"]; ok {
			return false
		}
		if _, ok := nats[0].ExternalIDs["netloom_target_port"]; ok {
			return false
		}
		if _, ok := nats[0].ExternalIDs["netloom_protocol"]; ok {
			return false
		}
		return nats[0].ExternalIDs["netloom_owner"] == "netloom"
	})
}

func TestLibOVSDBTopologyWriterKeepsReferencedDuplicateNATRule(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "dev"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, model.Subnet{
		Name:    "db",
		VPC:     "dev",
		CIDR:    netip.MustParsePrefix("10.20.0.0/24"),
		Gateway: netip.MustParseAddr("10.20.0.1"),
	}); err != nil {
		t.Fatal(err)
	}
	rule := model.NATRule{
		Name:       "egress",
		VPC:        "prod",
		Type:       model.ActionSNAT,
		MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
		ExternalIP: netip.MustParseAddr("198.51.100.10"),
	}
	if err := writer.EnsureNATRule(ctx, rule); err != nil {
		t.Fatal(err)
	}

	var prodRouters []ovnnb.LogicalRouter
	var nats []ovnnb.NAT
	requireEventually(t, func() bool {
		prodRouters = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &prodRouters); err != nil || len(prodRouters) != 1 || len(prodRouters[0].Nat) != 1 {
			return false
		}
		nats = nil
		err := client.WhereCache(func(row *ovnnb.NAT) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_nat"] == "egress"
		}).List(ctx, &nats)
		return err == nil && len(nats) == 1
	})
	referencedUUID := prodRouters[0].Nat[0]
	if nats[0].UUID != referencedUUID {
		t.Fatalf("router NAT refs = %+v NAT row = %s, want referenced row", prodRouters[0].Nat, nats[0].UUID)
	}

	duplicate := desiredNATRuleRow(rule)
	duplicate.UUID = ovsdbNamedUUID("duplicate_nat_rule")
	duplicate.LogicalIP = "10.99.0.0/24"
	var devRouters []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		devRouters = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("dev") }).List(ctx, &devRouters)
		return err == nil && len(devRouters) == 1
	})
	createOps, err := client.Create(&duplicate)
	if err != nil {
		t.Fatal(err)
	}
	attachDuplicate, err := writer.attachNATRule(&devRouters[0], duplicate.UUID)
	if err != nil {
		t.Fatal(err)
	}
	duplicateOps := append(createOps, attachDuplicate...)
	results, err := client.Transact(ctx, duplicateOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, duplicateOps); err != nil {
		t.Fatalf("attach duplicate NAT operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		nats = nil
		err := client.WhereCache(func(row *ovnnb.NAT) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_nat"] == "egress"
		}).List(ctx, &nats)
		return err == nil && len(nats) == 2
	})

	if err := writer.EnsureNATRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		prodRouters = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &prodRouters); err != nil || len(prodRouters) != 1 || len(prodRouters[0].Nat) != 1 {
			return false
		}
		nats = nil
		err := client.WhereCache(func(row *ovnnb.NAT) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_nat"] == "egress"
		}).List(ctx, &nats)
		if err != nil ||
			len(nats) != 1 ||
			nats[0].UUID != referencedUUID ||
			prodRouters[0].Nat[0] != referencedUUID ||
			nats[0].LogicalIP != "10.10.0.0/24" {
			return false
		}
		devRouters = nil
		err = client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("dev") }).List(ctx, &devRouters)
		return err == nil && len(devRouters) == 1 && len(devRouters[0].Nat) == 0
	})
}

func TestLibOVSDBTopologyWriterEnsuresLoadBalancerAndHealthChecks(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}); err != nil {
		t.Fatal(err)
	}
	lb := model.LoadBalancer{
		Name:            "api",
		VPC:             "prod",
		VIP:             netip.MustParseAddr("10.96.0.10"),
		Subnets:         []string{"apps"},
		SessionAffinity: true,
		AffinityTimeout: 120,
		Ports: []model.LoadBalancerPort{{
			Port:     443,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{
				{IP: netip.MustParseAddr("10.10.0.20"), Port: 8443},
				{IP: netip.MustParseAddr("10.10.0.21"), Port: 8443},
			},
		}, {
			Port:     53,
			Protocol: model.ProtocolUDP,
			Backends: []model.LoadBalancerBackend{
				{IP: netip.MustParseAddr("10.10.0.30"), Port: 5353},
			},
		}},
		HealthCheck: model.LoadBalancerHealthCheck{
			Enabled:      true,
			Interval:     7,
			Timeout:      3,
			SuccessCount: 2,
			FailureCount: 4,
		},
	}
	if err := writer.EnsureLoadBalancer(ctx, lb); err != nil {
		t.Fatal(err)
	}

	var lbs []ovnnb.LoadBalancer
	requireEventually(t, func() bool {
		lbs = nil
		err := client.WhereCache(func(row *ovnnb.LoadBalancer) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_load_balancer"] == "api"
		}).List(ctx, &lbs)
		return err == nil && len(lbs) == 2
	})
	lbByProtocol := loadBalancersByProtocol(lbs)
	tcpLB := lbByProtocol["tcp"]
	if tcpLB.Name != loadBalancerProtocolName("prod", "api", model.ProtocolTCP) ||
		tcpLB.Vips["10.96.0.10:443"] != "10.10.0.20:8443,10.10.0.21:8443" ||
		tcpLB.Options["affinity_timeout"] != "120" ||
		len(tcpLB.SelectionFields) != 1 ||
		tcpLB.SelectionFields[0] != ovnnb.LoadBalancerSelectionFieldsIPSrc {
		t.Fatalf("tcp load balancer = %+v, want vips, affinity, and selection fields", tcpLB)
	}
	udpLB := lbByProtocol["udp"]
	if udpLB.Vips["10.96.0.10:53"] != "10.10.0.30:5353" {
		t.Fatalf("udp load balancer = %+v, want DNS vip", udpLB)
	}
	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 && len(routers[0].LoadBalancer) == 2
	})
	var switches []ovnnb.LogicalSwitch
	requireEventually(t, func() bool {
		switches = nil
		err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == logicalSwitch("prod", "apps") }).List(ctx, &switches)
		return err == nil && len(switches) == 1 && len(switches[0].LoadBalancer) == 2
	})
	var checks []ovnnb.LoadBalancerHealthCheck
	requireEventually(t, func() bool {
		checks = nil
		err := client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_load_balancer"] == "api"
		}).List(ctx, &checks)
		return err == nil && len(checks) == 2
	})
	for _, check := range checks {
		if check.Options["interval"] != "7" || check.Options["timeout"] != "3" || check.Options["success_count"] != "2" || check.Options["failure_count"] != "4" {
			t.Fatalf("health check = %+v, want configured options", check)
		}
	}

	lb.HealthCheck.Enabled = false
	lb.Ports = lb.Ports[:1]
	if err := writer.EnsureLoadBalancer(ctx, lb); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		checks = nil
		err := client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_load_balancer"] == "api"
		}).List(ctx, &checks)
		return err == nil && len(checks) == 0
	})
	requireEventually(t, func() bool {
		lbs = nil
		err := client.WhereCache(func(row *ovnnb.LoadBalancer) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_load_balancer"] == "api"
		}).List(ctx, &lbs)
		return err == nil && len(lbs) == 1 && lbs[0].ExternalIDs["netloom_protocol"] == "tcp" && len(lbs[0].HealthCheck) == 0
	})
}

func TestLibOVSDBTopologyWriterDeletesDuplicateHealthChecksFromAllParents(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}); err != nil {
		t.Fatal(err)
	}
	lb := model.LoadBalancer{
		Name:    "api",
		VPC:     "prod",
		VIP:     netip.MustParseAddr("10.96.0.10"),
		Subnets: []string{"apps"},
		Ports: []model.LoadBalancerPort{{
			Port:     443,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{
				IP:   netip.MustParseAddr("10.10.0.20"),
				Port: 8443,
			}},
		}, {
			Port:     53,
			Protocol: model.ProtocolUDP,
			Backends: []model.LoadBalancerBackend{{
				IP:   netip.MustParseAddr("10.10.0.30"),
				Port: 5353,
			}},
		}},
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
	}
	if err := writer.EnsureLoadBalancer(ctx, lb); err != nil {
		t.Fatal(err)
	}

	var lbs []ovnnb.LoadBalancer
	requireEventually(t, func() bool {
		lbs = nil
		err := client.WhereCache(func(row *ovnnb.LoadBalancer) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_load_balancer"] == "api"
		}).List(ctx, &lbs)
		return err == nil && len(lbs) == 2
	})
	lbByProtocol := loadBalancersByProtocol(lbs)
	tcpLB := lbByProtocol["tcp"]
	udpLB := lbByProtocol["udp"]
	if len(tcpLB.HealthCheck) != 1 || len(udpLB.HealthCheck) != 1 {
		t.Fatalf("load balancers = %+v, want one health check per protocol", lbByProtocol)
	}

	tcpFrontend := loadBalancerFrontendsByProtocol(lb)[model.ProtocolTCP][0]
	duplicate := desiredLoadBalancerHealthCheck(lb, tcpFrontend)
	duplicate.UUID = ovsdbNamedUUID("duplicate_lbhc")
	duplicate.Options = map[string]string{"interval": "99"}
	createOps, err := client.Create(&duplicate)
	if err != nil {
		t.Fatal(err)
	}
	udpRef := &ovnnb.LoadBalancer{UUID: udpLB.UUID}
	attachOps, err := client.Where(udpRef).Mutate(udpRef, ovsmodel.Mutation{
		Field:   &udpRef.HealthCheck,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{duplicate.UUID},
	})
	if err != nil {
		t.Fatal(err)
	}
	ops := append(createOps, attachOps...)
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("attach duplicate health check operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		var checks []ovnnb.LoadBalancerHealthCheck
		err = client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" &&
				row.ExternalIDs["netloom_load_balancer"] == "api" &&
				row.Vip == "10.96.0.10:443"
		}).List(ctx, &checks)
		if err != nil || len(checks) != 2 {
			return false
		}
		var rows []ovnnb.LoadBalancer
		err = client.WhereCache(func(row *ovnnb.LoadBalancer) bool { return row.UUID == udpLB.UUID }).List(ctx, &rows)
		return err == nil && len(rows) == 1 && len(rows[0].HealthCheck) == 2
	})

	if err := writer.EnsureLoadBalancer(ctx, lb); err != nil {
		t.Fatal(err)
	}
	finalStateOK := func() bool {
		var checks []ovnnb.LoadBalancerHealthCheck
		err = client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" &&
				row.ExternalIDs["netloom_load_balancer"] == "api" &&
				row.Vip == "10.96.0.10:443"
		}).List(ctx, &checks)
		if err != nil || len(checks) != 1 {
			return false
		}
		var rows []ovnnb.LoadBalancer
		err = client.WhereCache(func(row *ovnnb.LoadBalancer) bool { return row.UUID == tcpLB.UUID || row.UUID == udpLB.UUID }).List(ctx, &rows)
		if err != nil || len(rows) != 2 {
			return false
		}
		refsByUUID := make(map[string][]string, len(rows))
		for _, row := range rows {
			refsByUUID[row.UUID] = row.HealthCheck
		}
		return len(refsByUUID[tcpLB.UUID]) == 1 &&
			refsByUUID[tcpLB.UUID][0] == checks[0].UUID &&
			len(refsByUUID[udpLB.UUID]) == 1 &&
			refsByUUID[udpLB.UUID][0] != checks[0].UUID
	}
	if !eventually(finalStateOK) {
		var checks []ovnnb.LoadBalancerHealthCheck
		if err := client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_load_balancer"] == "api"
		}).List(ctx, &checks); err != nil {
			t.Fatal(err)
		}
		var rows []ovnnb.LoadBalancer
		if err := client.WhereCache(func(row *ovnnb.LoadBalancer) bool { return row.UUID == tcpLB.UUID || row.UUID == udpLB.UUID }).List(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("health checks after repair = %+v load balancers = %+v", checks, rows)
	}
}

func TestLibOVSDBTopologyWriterCleanupTopologyDeletesRemovedDesiredObjects(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
		DHCP: model.DHCPOptions{
			Enabled:   true,
			LeaseTime: 3600,
		},
	}
	endpoint := model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		Node:   "node-a",
		IP:     netip.MustParseAddr("10.10.0.20"),
		MAC:    "02:00:00:00:00:20",
	}
	routeTable := model.RouteTable{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
			NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
		}},
	}
	policyRoute := model.PolicyRoute{
		Name:     "egress-a",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	}
	gateway := model.Gateway{
		Name:        "gw-a",
		VPC:         "prod",
		Node:        "node-a",
		ExternalIF:  "eth0",
		LANIP:       netip.MustParseAddr("10.10.0.1"),
		Distributed: false,
	}
	natRule := model.NATRule{
		Name:       "egress",
		VPC:        "prod",
		Type:       model.ActionSNAT,
		MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
		ExternalIP: netip.MustParseAddr("198.51.100.10"),
	}
	lb := model.LoadBalancer{
		Name:    "api",
		VPC:     "prod",
		VIP:     netip.MustParseAddr("10.96.0.10"),
		Subnets: []string{"apps"},
		Ports: []model.LoadBalancerPort{{
			Port:     443,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{
				IP:   netip.MustParseAddr("10.10.0.20"),
				Port: 8443,
			}},
		}},
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
	}
	state := topology.State{
		VPCs:          map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets:       map[string]model.Subnet{"prod/apps": subnet},
		Endpoints:     map[string]model.Endpoint{model.EndpointKey("prod", "pod-a"): endpoint},
		RouteTables:   map[string]model.RouteTable{"prod/main": routeTable},
		PolicyRoutes:  []model.PolicyRoute{policyRoute},
		Gateways:      map[string]model.Gateway{"prod/gw-a": gateway},
		NATRules:      map[string]model.NATRule{"prod/egress": natRule},
		LoadBalancers: map[string]model.LoadBalancer{"prod/api": lb},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		name string
		fn   func() error
	}{
		{"vpc", func() error { return writer.EnsureVPC(ctx, state.VPCs["prod"]) }},
		{"subnet", func() error { return writer.EnsureSubnet(ctx, subnet) }},
		{"route table", func() error { return writer.EnsureRouteTable(ctx, routeTable) }},
		{"policy route", func() error { return writer.EnsurePolicyRoute(ctx, policyRoute) }},
		{"gateway", func() error { return writer.EnsureGateway(ctx, gateway) }},
		{"endpoint", func() error { return writer.EnsureEndpoint(ctx, endpoint) }},
		{"nat", func() error { return writer.EnsureNATRule(ctx, natRule) }},
		{"load balancer", func() error { return writer.EnsureLoadBalancer(ctx, lb) }},
	} {
		if err := step.fn(); err != nil {
			t.Fatalf("ensure %s: %v", step.name, err)
		}
	}
	requireEventually(t, func() bool {
		counts, err := managedOVNRowCounts(ctx, client)
		return err == nil &&
			counts["Logical_Router"] == 1 &&
			counts["Logical_Switch"] == 1 &&
			counts["Logical_Switch_Port"] == 2 &&
			counts["Logical_Router_Port"] == 1 &&
			counts["Logical_Router_Static_Route"] == 1 &&
			counts["Logical_Router_Policy"] == 1 &&
			counts["NAT"] == 1 &&
			counts["Load_Balancer"] == 1 &&
			counts["Load_Balancer_Health_Check"] == 1 &&
			counts["DHCP_Options"] == 1
	})

	if err := writer.CleanupTopology(ctx, topology.State{}); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		counts, err := managedOVNRowCounts(ctx, client)
		if err != nil {
			return false
		}
		for _, count := range counts {
			if count != 0 {
				return false
			}
		}
		return true
	})
	stats := writer.LastCleanupStats()
	if stats.StaleVPCs != 1 ||
		stats.StaleSubnets != 1 ||
		stats.StaleEndpoints != 1 ||
		stats.StaleRoutes != 1 ||
		stats.StalePolicyRoutes != 1 ||
		stats.StaleGateways != 1 ||
		stats.StaleNATRules != 1 ||
		stats.StaleLoadBalancers != 1 {
		t.Fatalf("cleanup stats = %+v, want one stale object in every topology category", stats)
	}
}

func TestLibOVSDBTopologyWriterFirstCleanupDeletesUnexpectedLiveObjects(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
		DHCP:    model.DHCPOptions{Enabled: true},
	}
	endpoint := model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		Node:   "node-a",
		IP:     netip.MustParseAddr("10.10.0.20"),
	}
	routeTable := model.RouteTable{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
			NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
		}},
	}
	policyRoute := model.PolicyRoute{
		Name:     "egress-a",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	}
	natRule := model.NATRule{
		Name:       "egress",
		VPC:        "prod",
		Type:       model.ActionSNAT,
		MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
		ExternalIP: netip.MustParseAddr("198.51.100.10"),
	}
	lb := model.LoadBalancer{
		Name:    "api",
		VPC:     "prod",
		VIP:     netip.MustParseAddr("10.96.0.10"),
		Subnets: []string{"apps"},
		Ports: []model.LoadBalancerPort{{
			Port:     443,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{
				IP:   netip.MustParseAddr("10.10.0.20"),
				Port: 8443,
			}},
		}},
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
	}
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureRouteTable(ctx, routeTable); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsurePolicyRoute(ctx, policyRoute); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureNATRule(ctx, natRule); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureLoadBalancer(ctx, lb); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		counts, err := managedOVNRowCounts(ctx, client)
		return err == nil &&
			counts["Logical_Router"] == 1 &&
			counts["Logical_Switch"] == 1 &&
			counts["Logical_Switch_Port"] == 2 &&
			counts["Logical_Router_Port"] == 1 &&
			counts["Logical_Router_Static_Route"] == 1 &&
			counts["Logical_Router_Policy"] == 1 &&
			counts["NAT"] == 1 &&
			counts["Load_Balancer"] == 1 &&
			counts["Load_Balancer_Health_Check"] == 1 &&
			counts["DHCP_Options"] == 1
	})

	gcWriter := NewLibOVSDBTopologyWriter(client)
	if err := gcWriter.CleanupTopology(ctx, topology.State{}); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		counts, err := managedOVNRowCounts(ctx, client)
		if err != nil {
			return false
		}
		for _, count := range counts {
			if count != 0 {
				return false
			}
		}
		return true
	})
	stats := gcWriter.LastCleanupStats()
	if !stats.FirstReconcileGC || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want first reconcile GC operations", stats)
	}
	if stats.StaleVPCs != 1 ||
		stats.StaleSubnets != 1 ||
		stats.StaleRoutes != 1 ||
		stats.StalePolicyRoutes != 1 ||
		stats.StaleNATRules != 1 ||
		stats.StaleLoadBalancers != 1 ||
		stats.StaleLogicalSwitchPorts != 2 ||
		stats.StaleLogicalRouterPorts != 1 ||
		stats.StaleDHCPOptions != 1 ||
		stats.StaleLBHealthChecks != 1 {
		t.Fatalf("cleanup stats = %+v, want first reconcile live orphan counts by OVN table category", stats)
	}
}

func TestLibOVSDBTopologyWriterFirstCleanupClearsUnexpectedGatewayMetadata(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	state := topology.State{
		VPCs: map[string]model.VPC{"prod": {Name: "prod"}},
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}

	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1
	})
	routers[0].ExternalIDs["netloom_gateway"] = "gw-stale"
	routers[0].ExternalIDs["netloom_external_if"] = "eth9"
	routers[0].ExternalIDs["netloom_gateway_lan_ip"] = "10.10.0.254"
	routers[0].ExternalIDs["netloom_gateway_distributed"] = "false"
	routers[0].ExternalIDs["custom"] = "keep"
	routers[0].Options = map[string]string{"chassis": "node-old", "custom": "keep"}
	updateOps, err := client.Where(&routers[0]).Update(&routers[0], &routers[0].ExternalIDs, &routers[0].Options)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, updateOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, updateOps); err != nil {
		t.Fatalf("seed stale gateway metadata operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 &&
			routers[0].ExternalIDs["netloom_gateway"] == "gw-stale" &&
			routers[0].Options["chassis"] == "node-old"
	})

	gcWriter := NewLibOVSDBTopologyWriter(client)
	if err := gcWriter.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		if err != nil || len(routers) != 1 {
			return false
		}
		_, hasGateway := routers[0].ExternalIDs["netloom_gateway"]
		_, hasExternalIF := routers[0].ExternalIDs["netloom_external_if"]
		_, hasGatewayLANIP := routers[0].ExternalIDs["netloom_gateway_lan_ip"]
		_, hasDistributed := routers[0].ExternalIDs["netloom_gateway_distributed"]
		_, hasChassis := routers[0].Options["chassis"]
		return !hasGateway &&
			!hasExternalIF &&
			!hasGatewayLANIP &&
			!hasDistributed &&
			!hasChassis &&
			routers[0].ExternalIDs["netloom_owner"] == "netloom" &&
			routers[0].ExternalIDs["netloom_vpc"] == "prod" &&
			routers[0].ExternalIDs["custom"] == "keep" &&
			routers[0].Options["custom"] == "keep"
	})
	stats := gcWriter.LastCleanupStats()
	if !stats.FirstReconcileGC || stats.StaleGateways != 1 || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want first reconcile stale gateway metadata cleanup", stats)
	}
}

func TestLibOVSDBTopologyWriterCleanupRepairsUnexpectedLiveObjectsInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
		DHCP:    model.DHCPOptions{Enabled: true},
	}
	endpoint := model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		Node:   "node-a",
		IP:     netip.MustParseAddr("10.10.0.20"),
	}
	state := topology.State{
		VPCs:      map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets:   map[string]model.Subnet{subnetStateKey("prod", "apps"): subnet},
		Endpoints: map[string]model.Endpoint{model.EndpointKey("prod", "pod-a"): endpoint},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		counts, err := managedOVNRowCounts(ctx, client)
		return err == nil && counts["DHCP_Options"] == 1
	})

	stale := &ovnnb.DHCPOptions{
		Cidr: "10.10.0.99/32",
		ExternalIDs: map[string]string{
			"netloom_owner":       "netloom",
			"netloom_vpc":         "prod",
			"netloom_endpoint":    endpointExternalID("prod", "pod-stale"),
			"netloom_subnet":      "apps",
			"netloom_dhcp_family": "4",
		},
		Options: map[string]string{"lease_time": "30"},
	}
	ops, err := client.Create(stale)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("create stale DHCP operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		counts, err := managedOVNRowCounts(ctx, client)
		return err == nil && counts["DHCP_Options"] == 2
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if !eventually(func() bool {
		counts, err := managedOVNRowCounts(ctx, client)
		return err == nil && counts["DHCP_Options"] == 1
	}) {
		var rows []ovnnb.DHCPOptions
		if err := client.WhereCache(func(row *ovnnb.DHCPOptions) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("managed DHCP rows after repair = %+v, want 1", rows)
	}
	stats := writer.LastCleanupStats()
	if stats.FirstReconcileGC || stats.StaleDHCPOptions != 1 || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want non-first-reconcile stale DHCP repair", stats)
	}
}

func TestLibOVSDBTopologyWriterCleanupRepairsEndpointDHCPAttachmentAndFamilyDriftInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
		DHCP:    model.DHCPOptions{Enabled: true},
	}
	endpoint := model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		Node:   "node-a",
		IP:     netip.MustParseAddr("10.10.0.20"),
	}
	state := topology.State{
		VPCs:      map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets:   map[string]model.Subnet{subnetStateKey("prod", "apps"): subnet},
		Endpoints: map[string]model.Endpoint{model.EndpointKey("prod", "pod-a"): endpoint},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}

	var dhcpRows []ovnnb.DHCPOptions
	requireEventually(t, func() bool {
		dhcpRows = nil
		err := client.WhereCache(func(row *ovnnb.DHCPOptions) bool {
			return row.ExternalIDs["netloom_endpoint"] == endpointExternalID("prod", "pod-a")
		}).List(ctx, &dhcpRows)
		return err == nil && len(dhcpRows) == 1 && dhcpRows[0].ExternalIDs["netloom_dhcp_family"] == "4"
	})
	driftedDHCP := dhcpRows[0]
	driftedDHCP.ExternalIDs["netloom_dhcp_family"] = "6"
	updateDHCP, err := client.Where(&driftedDHCP).Update(&driftedDHCP, &driftedDHCP.ExternalIDs)
	if err != nil {
		t.Fatal(err)
	}
	var ports []ovnnb.LogicalSwitchPort
	if err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == logicalPort("prod", "pod-a") }).List(ctx, &ports); err != nil {
		t.Fatal(err)
	}
	if len(ports) != 1 {
		t.Fatalf("endpoint ports = %d, want one", len(ports))
	}
	ports[0].Dhcpv4Options = nil
	updatePort, err := client.Where(&ports[0]).Update(&ports[0], &ports[0].Dhcpv4Options)
	if err != nil {
		t.Fatal(err)
	}
	ops := append(updateDHCP, updatePort...)
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("seed DHCP drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		dhcpRows = nil
		err := client.WhereCache(func(row *ovnnb.DHCPOptions) bool {
			return row.ExternalIDs["netloom_endpoint"] == endpointExternalID("prod", "pod-a")
		}).List(ctx, &dhcpRows)
		if err != nil || len(dhcpRows) != 1 || dhcpRows[0].ExternalIDs["netloom_dhcp_family"] != "6" {
			return false
		}
		ports = nil
		err = client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == logicalPort("prod", "pod-a") }).List(ctx, &ports)
		return err == nil && len(ports) == 1 && ports[0].Dhcpv4Options == nil
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		dhcpRows = nil
		err := client.WhereCache(func(row *ovnnb.DHCPOptions) bool {
			return row.ExternalIDs["netloom_endpoint"] == endpointExternalID("prod", "pod-a")
		}).List(ctx, &dhcpRows)
		if err != nil || len(dhcpRows) != 1 || dhcpRows[0].ExternalIDs["netloom_dhcp_family"] != "4" {
			return false
		}
		ports = nil
		err = client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == logicalPort("prod", "pod-a") }).List(ctx, &ports)
		return err == nil && len(ports) == 1 && ports[0].Dhcpv4Options != nil && *ports[0].Dhcpv4Options == dhcpRows[0].UUID
	})
	stats := writer.LastCleanupStats()
	if stats.FirstReconcileGC || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want steady-state DHCP repair operations", stats)
	}
}

func TestLibOVSDBTopologyWriterCleanupRepairsNATRowDriftInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	nat := model.NATRule{
		Name:       "egress",
		VPC:        "prod",
		Type:       model.ActionSNAT,
		MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
		ExternalIP: netip.MustParseAddr("198.51.100.10"),
	}
	state := topology.State{
		VPCs:     map[string]model.VPC{"prod": {Name: "prod"}},
		NATRules: map[string]model.NATRule{"prod/egress": nat},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureNATRule(ctx, nat); err != nil {
		t.Fatal(err)
	}

	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 && len(routers[0].Nat) == 1
	})
	var nats []ovnnb.NAT
	requireEventually(t, func() bool {
		nats = nil
		err := client.WhereCache(func(row *ovnnb.NAT) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_nat"] == "egress"
		}).List(ctx, &nats)
		return err == nil && len(nats) == 1
	})
	natUUID := nats[0].UUID
	nats[0].LogicalIP = "10.99.0.0/24"
	nats[0].ExternalIDs["netloom_protocol"] = "tcp"
	updateNAT, err := client.Where(&nats[0]).Update(&nats[0], &nats[0].LogicalIP, &nats[0].ExternalIDs)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, updateNAT...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, updateNAT); err != nil {
		t.Fatalf("seed NAT drift operation errors=%+v: %v", opErrors, err)
	}
	if !eventually(func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		if err != nil || len(routers) != 1 || len(routers[0].Nat) != 1 || !containsString(routers[0].Nat, natUUID) {
			return false
		}
		nats = nil
		err = client.WhereCache(func(row *ovnnb.NAT) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_nat"] == "egress"
		}).List(ctx, &nats)
		if err != nil || len(nats) != 1 {
			return false
		}
		return nats[0].UUID == natUUID && nats[0].LogicalIP == "10.99.0.0/24" && nats[0].ExternalIDs["netloom_protocol"] == "tcp"
	}) {
		t.Fatalf("seeded NAT drift routers=%+v nats=%+v", routers, nats)
	}

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if !eventually(func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		if err != nil || len(routers) != 1 || len(routers[0].Nat) != 1 || !containsString(routers[0].Nat, natUUID) {
			return false
		}
		nats = nil
		err = client.WhereCache(func(row *ovnnb.NAT) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_nat"] == "egress"
		}).List(ctx, &nats)
		if err != nil || len(nats) != 1 {
			return false
		}
		_, staleProtocol := nats[0].ExternalIDs["netloom_protocol"]
		return nats[0].UUID == natUUID && nats[0].LogicalIP == "10.10.0.0/24" && !staleProtocol
	}) {
		t.Fatalf("repaired NAT drift routers=%+v nats=%+v", routers, nats)
	}
	stats := writer.LastCleanupStats()
	if stats.FirstReconcileGC || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want steady-state NAT repair operations", stats)
	}
}

func TestLibOVSDBTopologyWriterCleanupRepairsRouteAndPolicyRowDriftInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	routeTable := model.RouteTable{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
			NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.253")},
		}},
	}
	policyRoute := model.PolicyRoute{
		Name:     "via-fw",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("10.30.0.0/24"),
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.254")}},
	}
	state := topology.State{
		VPCs:         map[string]model.VPC{"prod": {Name: "prod"}},
		RouteTables:  map[string]model.RouteTable{"prod/main": routeTable},
		PolicyRoutes: []model.PolicyRoute{policyRoute},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureRouteTable(ctx, routeTable); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsurePolicyRoute(ctx, policyRoute); err != nil {
		t.Fatal(err)
	}

	var routes []ovnnb.LogicalRouterStaticRoute
	requireEventually(t, func() bool {
		routes = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_route_table"] == "main"
		}).List(ctx, &routes)
		return err == nil && len(routes) == 1
	})
	driftPolicy := ovnnb.LogicalRouterStaticRoutePolicySrcIP
	routes[0].RouteTable = "legacy"
	routes[0].Options = map[string]string{"ecmp_symmetric_reply": "true"}
	routes[0].Policy = &driftPolicy
	updateRoute, err := client.Where(&routes[0]).Update(&routes[0], &routes[0].RouteTable, &routes[0].Options, &routes[0].Policy)
	if err != nil {
		t.Fatal(err)
	}
	var policies []ovnnb.LogicalRouterPolicy
	requireEventually(t, func() bool {
		policies = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_policy_route"] == "via-fw"
		}).List(ctx, &policies)
		return err == nil && len(policies) == 1
	})
	policies[0].Action = ovnnb.LogicalRouterPolicyActionDrop
	policies[0].Nexthop = nil
	policies[0].ExternalIDs["netloom_action"] = string(model.ActionDrop)
	updatePolicy, err := client.Where(&policies[0]).Update(&policies[0], &policies[0].Action, &policies[0].Nexthop, &policies[0].ExternalIDs)
	if err != nil {
		t.Fatal(err)
	}
	ops := append(updateRoute, updatePolicy...)
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("seed route drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		routes = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_route_table"] == "main"
		}).List(ctx, &routes)
		if err != nil || len(routes) != 1 || routes[0].RouteTable != "legacy" {
			return false
		}
		policies = nil
		err = client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_policy_route"] == "via-fw"
		}).List(ctx, &policies)
		return err == nil && len(policies) == 1 && policies[0].Action == ovnnb.LogicalRouterPolicyActionDrop
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		routes = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_route_table"] == "main"
		}).List(ctx, &routes)
		if err != nil || len(routes) != 1 || routes[0].RouteTable != "main" || len(routes[0].Options) != 0 || routes[0].Policy != nil {
			return false
		}
		policies = nil
		err = client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool {
			return row.ExternalIDs["netloom_vpc"] == "prod" && row.ExternalIDs["netloom_policy_route"] == "via-fw"
		}).List(ctx, &policies)
		if err != nil || len(policies) != 1 || policies[0].Action != ovnnb.LogicalRouterPolicyActionReroute || policies[0].Nexthop == nil {
			return false
		}
		return *policies[0].Nexthop == "10.10.0.254" && policies[0].ExternalIDs["netloom_action"] == string(model.ActionReroute)
	})
	stats := writer.LastCleanupStats()
	if stats.FirstReconcileGC || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want steady-state route repair operations", stats)
	}
}

func TestLibOVSDBTopologyWriterCleanupRepairsGatewayRouterDriftInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	gateway := model.Gateway{
		Name:       "gw-a",
		VPC:        "prod",
		Node:       "node-a",
		ExternalIF: "eth0",
		LANIP:      netip.MustParseAddr("10.10.0.1"),
	}
	state := topology.State{
		VPCs:     map[string]model.VPC{"prod": {Name: "prod"}},
		Gateways: map[string]model.Gateway{"prod/gw-a": gateway},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureGateway(ctx, gateway); err != nil {
		t.Fatal(err)
	}

	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 && routers[0].Options["chassis"] == "node-a"
	})
	routers[0].Options["chassis"] = "node-b"
	routers[0].ExternalIDs["netloom_gateway"] = "gw-old"
	routers[0].ExternalIDs["netloom_external_if"] = "eth9"
	updateOps, err := client.Where(&routers[0]).Update(&routers[0], &routers[0].Options, &routers[0].ExternalIDs)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, updateOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, updateOps); err != nil {
		t.Fatalf("seed gateway drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 &&
			routers[0].Options["chassis"] == "node-b" &&
			routers[0].ExternalIDs["netloom_gateway"] == "gw-old" &&
			routers[0].ExternalIDs["netloom_external_if"] == "eth9"
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 &&
			routers[0].Options["chassis"] == "node-a" &&
			routers[0].ExternalIDs["netloom_gateway"] == "gw-a" &&
			routers[0].ExternalIDs["netloom_external_if"] == "eth0" &&
			routers[0].ExternalIDs["netloom_gateway_lan_ip"] == "10.10.0.1" &&
			routers[0].ExternalIDs["netloom_gateway_distributed"] == "false"
	})
	stats := writer.LastCleanupStats()
	if stats.FirstReconcileGC || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want steady-state gateway repair operations", stats)
	}
}

func TestLibOVSDBTopologyWriterCleanupRepairsLoadBalancerParentAttachmentDriftInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	apps := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}
	db := model.Subnet{
		Name:    "db",
		VPC:     "dev",
		CIDR:    netip.MustParsePrefix("10.20.0.0/24"),
		Gateway: netip.MustParseAddr("10.20.0.1"),
	}
	lb := model.LoadBalancer{
		Name:    "api",
		VPC:     "prod",
		VIP:     netip.MustParseAddr("10.96.0.10"),
		Subnets: []string{"apps"},
		Ports: []model.LoadBalancerPort{{
			Port:     443,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{
				IP:   netip.MustParseAddr("10.10.0.20"),
				Port: 8443,
			}},
		}},
	}
	state := topology.State{
		VPCs: map[string]model.VPC{
			"prod": {Name: "prod"},
			"dev":  {Name: "dev"},
		},
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps"): apps,
			subnetStateKey("dev", "db"):    db,
		},
		LoadBalancers: map[string]model.LoadBalancer{"prod/api": lb},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	for _, vpc := range []model.VPC{state.VPCs["prod"], state.VPCs["dev"]} {
		if err := writer.EnsureVPC(ctx, vpc); err != nil {
			t.Fatal(err)
		}
	}
	for _, subnet := range []model.Subnet{apps, db} {
		if err := writer.EnsureSubnet(ctx, subnet); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.EnsureLoadBalancer(ctx, lb); err != nil {
		t.Fatal(err)
	}

	lbRow, ok, err := writer.loadBalancerByName(ctx, loadBalancerProtocolName("prod", "api", model.ProtocolTCP))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("load balancer row was not created")
	}
	var prodRouters []ovnnb.LogicalRouter
	var devRouters []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		prodRouters = nil
		devRouters = nil
		errProd := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &prodRouters)
		errDev := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("dev") }).List(ctx, &devRouters)
		appsSwitch := singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "apps"))
		return errProd == nil && errDev == nil &&
			len(prodRouters) == 1 && len(devRouters) == 1 &&
			containsString(prodRouters[0].LoadBalancer, lbRow.UUID) &&
			containsString(appsSwitch.LoadBalancer, lbRow.UUID)
	})
	appsSwitch := singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "apps"))
	dbSwitch := singleLogicalSwitchByName(t, ctx, client, logicalSwitch("dev", "db"))
	var ops []ovsdb.Operation
	detachRouter, err := writer.detachLoadBalancerFromRouter(prodRouters[0].UUID, lbRow.UUID)
	if err != nil {
		t.Fatal(err)
	}
	ops = append(ops, detachRouter...)
	detachSwitch, err := writer.detachLoadBalancerFromSwitch(appsSwitch.UUID, lbRow.UUID)
	if err != nil {
		t.Fatal(err)
	}
	ops = append(ops, detachSwitch...)
	attachRouter, err := writer.attachLoadBalancerToRouter(&devRouters[0], lbRow.UUID)
	if err != nil {
		t.Fatal(err)
	}
	ops = append(ops, attachRouter...)
	attachSwitch, err := writer.attachLoadBalancerToSwitch(&dbSwitch, lbRow.UUID)
	if err != nil {
		t.Fatal(err)
	}
	ops = append(ops, attachSwitch...)
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("seed load balancer parent drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		prodRouters = nil
		devRouters = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &prodRouters); err != nil || len(prodRouters) != 1 || containsString(prodRouters[0].LoadBalancer, lbRow.UUID) {
			return false
		}
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("dev") }).List(ctx, &devRouters); err != nil || len(devRouters) != 1 || !containsString(devRouters[0].LoadBalancer, lbRow.UUID) {
			return false
		}
		appsSwitch = singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "apps"))
		dbSwitch = singleLogicalSwitchByName(t, ctx, client, logicalSwitch("dev", "db"))
		return !containsString(appsSwitch.LoadBalancer, lbRow.UUID) && containsString(dbSwitch.LoadBalancer, lbRow.UUID)
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		prodRouters = nil
		devRouters = nil
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &prodRouters); err != nil || len(prodRouters) != 1 || !containsString(prodRouters[0].LoadBalancer, lbRow.UUID) {
			return false
		}
		if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("dev") }).List(ctx, &devRouters); err != nil || len(devRouters) != 1 || containsString(devRouters[0].LoadBalancer, lbRow.UUID) {
			return false
		}
		appsSwitch = singleLogicalSwitchByName(t, ctx, client, logicalSwitch("prod", "apps"))
		dbSwitch = singleLogicalSwitchByName(t, ctx, client, logicalSwitch("dev", "db"))
		return containsString(appsSwitch.LoadBalancer, lbRow.UUID) && !containsString(dbSwitch.LoadBalancer, lbRow.UUID)
	})
	stats := writer.LastCleanupStats()
	if stats.FirstReconcileGC || stats.Operations == 0 {
		t.Fatalf("cleanup stats = %+v, want steady-state load balancer parent repair operations", stats)
	}
}

func TestLibOVSDBTopologyWriterCleanupRepairsLoadBalancerColumnDriftInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}
	lb := model.LoadBalancer{
		Name:            "api",
		VPC:             "prod",
		VIP:             netip.MustParseAddr("10.96.0.10"),
		SelectionFields: []string{"ip_src", "tp_src"},
		SessionAffinity: true,
		Ports: []model.LoadBalancerPort{{
			Port:     443,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{
				IP:   netip.MustParseAddr("10.10.0.20"),
				Port: 8443,
			}},
		}},
	}
	state := topology.State{
		VPCs:          map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets:       map[string]model.Subnet{subnetStateKey("prod", "apps"): subnet},
		LoadBalancers: map[string]model.LoadBalancer{"prod/api": lb},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureLoadBalancer(ctx, lb); err != nil {
		t.Fatal(err)
	}

	existing, ok, err := writer.loadBalancerByName(ctx, loadBalancerProtocolName("prod", "api", model.ProtocolTCP))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("load balancer row was not created")
	}
	wrongProtocol := ovnnb.LoadBalancerProtocolUDP
	existing.Vips = map[string]string{"10.96.0.99:444": "10.10.0.99:8444"}
	existing.Protocol = &wrongProtocol
	existing.SelectionFields = nil
	existing.ExternalIDs["netloom_session_affinity"] = "false"
	existing.Options = map[string]string{
		"affinity_timeout": "7200",
		"external_owner":   "keep",
	}
	updateOps, err := client.Where(existing).Update(existing, &existing.Vips, &existing.Protocol, &existing.SelectionFields, &existing.ExternalIDs, &existing.Options)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, updateOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, updateOps); err != nil {
		t.Fatalf("seed load balancer drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		drifted, ok, err := writer.loadBalancerByName(ctx, existing.Name)
		return err == nil &&
			ok &&
			drifted.Vips["10.96.0.99:444"] == "10.10.0.99:8444" &&
			drifted.Protocol != nil &&
			*drifted.Protocol == ovnnb.LoadBalancerProtocolUDP &&
			len(drifted.SelectionFields) == 0 &&
			drifted.ExternalIDs["netloom_session_affinity"] == "false" &&
			drifted.Options["affinity_timeout"] == "7200"
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	requireEventually(t, func() bool {
		repaired, ok, err := writer.loadBalancerByName(ctx, existing.Name)
		if err != nil || !ok {
			return false
		}
		want := desiredLoadBalancerRow(lb, model.ProtocolTCP, loadBalancerFrontendsByProtocol(lb)[model.ProtocolTCP])
		return reflect.DeepEqual(repaired.Vips, want.Vips) &&
			repaired.Protocol != nil &&
			want.Protocol != nil &&
			*repaired.Protocol == *want.Protocol &&
			reflect.DeepEqual(repaired.SelectionFields, want.SelectionFields) &&
			repaired.ExternalIDs["netloom_session_affinity"] == "true" &&
			repaired.Options["affinity_timeout"] == "10800" &&
			repaired.Options["external_owner"] == "keep"
	})
}

func TestLibOVSDBTopologyWriterCleanupRepairsLoadBalancerHealthCheckAttachmentInSteadyState(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}
	lb := model.LoadBalancer{
		Name: "api",
		VPC:  "prod",
		VIP:  netip.MustParseAddr("10.96.0.10"),
		Ports: []model.LoadBalancerPort{{
			Port:     443,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{
				IP:   netip.MustParseAddr("10.10.0.20"),
				Port: 8443,
			}},
		}},
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
	}
	state := topology.State{
		VPCs:          map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets:       map[string]model.Subnet{subnetStateKey("prod", "apps"): subnet},
		LoadBalancers: map[string]model.LoadBalancer{"prod/api": lb},
	}
	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureVPC(ctx, state.VPCs["prod"]); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureSubnet(ctx, subnet); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsureLoadBalancer(ctx, lb); err != nil {
		t.Fatal(err)
	}

	existing, ok, err := writer.loadBalancerByName(ctx, loadBalancerProtocolName("prod", "api", model.ProtocolTCP))
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(existing.HealthCheck) != 1 {
		t.Fatalf("load balancer row = %+v, want one attached health check", existing)
	}
	existing.HealthCheck = nil
	updateOps, err := client.Where(existing).Update(existing, &existing.HealthCheck)
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.Transact(ctx, updateOps...)
	if err != nil {
		t.Fatal(err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, updateOps); err != nil {
		t.Fatalf("seed load balancer health check drift operation errors=%+v: %v", opErrors, err)
	}
	requireEventually(t, func() bool {
		drifted, ok, err := writer.loadBalancerByName(ctx, existing.Name)
		return err == nil && ok && len(drifted.HealthCheck) == 0
	})

	if err := writer.CleanupTopology(ctx, state); err != nil {
		t.Fatal(err)
	}
	if !eventually(func() bool {
		repaired, ok, err := writer.loadBalancerByName(ctx, existing.Name)
		if err != nil || !ok || len(repaired.HealthCheck) != 1 {
			return false
		}
		var checks []ovnnb.LoadBalancerHealthCheck
		err = client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool {
			return row.UUID == repaired.HealthCheck[0] && row.Vip == "10.96.0.10:443"
		}).List(ctx, &checks)
		return err == nil && len(checks) == 1
	}) {
		repaired, _, err := writer.loadBalancerByName(ctx, existing.Name)
		if err != nil {
			t.Fatal(err)
		}
		var checks []ovnnb.LoadBalancerHealthCheck
		if err := client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &checks); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("load balancer after repair = %+v checks=%+v stats=%+v, want one VIP health check reattached", repaired, checks, writer.LastCleanupStats())
	}
}

func TestLibOVSDBTopologyWriterHealthCheckUsesLibOVSDBEcho(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	if latency, err := writer.HealthCheck(ctx); err != nil {
		t.Fatalf("health check failed: latency=%s err=%v", latency, err)
	}

	client.Disconnect()
	if _, err := writer.HealthCheck(ctx); err == nil {
		t.Fatal("expected disconnected libovsdb client health check to fail")
	}
}

func TestLibOVSDBTopologyWriterHealthCheckReconnectsDisconnectedClient(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)

	if _, err := client.MonitorAll(ctx); err != nil {
		closeFn()
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	writer.EnableHealthReconnect(0, 0)
	writer.SetHealthReconnectClientFactory(closeFn, func(context.Context) (libovsdbclient.Client, func(), error) {
		nextClient, nextClose := newTestOVNNBClient(t)
		if _, err := nextClient.MonitorAll(ctx); err != nil {
			nextClose()
			return nil, nil, err
		}
		return nextClient, nextClose, nil
	})
	t.Cleanup(writer.Close)

	client.Disconnect()
	if latency, err := writer.HealthCheck(ctx); err != nil {
		t.Fatalf("health check should reconnect disconnected client: latency=%s err=%v", latency, err)
	}
	if client.Connected() {
		t.Fatal("old client should remain disconnected after replacement")
	}
}

func TestLibOVSDBTopologyWriterHealthCheckReconnectsAfterEchoFailure(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)

	if _, err := client.MonitorAll(ctx); err != nil {
		closeFn()
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
	writer.EnableHealthReconnect(0, 0)
	writer.SetHealthReconnectClientFactory(closeFn, func(context.Context) (libovsdbclient.Client, func(), error) {
		nextClient, nextClose := newTestOVNNBClient(t)
		if _, err := nextClient.MonitorAll(ctx); err != nil {
			nextClose()
			return nil, nil, err
		}
		return nextClient, nextClose, nil
	})
	writer.healthEcho = func(ctx context.Context, c libovsdbclient.Client) error {
		if c == client {
			return fmt.Errorf("forced echo failure")
		}
		return c.Echo(ctx)
	}
	t.Cleanup(writer.Close)

	if !client.Connected() {
		t.Fatal("initial client should be connected before echo failure")
	}
	if latency, err := writer.HealthCheck(ctx); err != nil {
		t.Fatalf("health check should reconnect after echo failure: latency=%s err=%v", latency, err)
	}
	if client.Connected() {
		t.Fatal("old client should be closed after echo-failure replacement")
	}
}

func TestLibOVSDBReconnectBackoffCapsAtMax(t *testing.T) {
	initial := 100 * time.Millisecond
	maxBackoff := 250 * time.Millisecond
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{failures: 0, want: 0},
		{failures: 1, want: 100 * time.Millisecond},
		{failures: 2, want: 200 * time.Millisecond},
		{failures: 3, want: 250 * time.Millisecond},
		{failures: 20, want: 250 * time.Millisecond},
	}
	for _, tc := range cases {
		if got := reconnectBackoff(initial, maxBackoff, tc.failures); got != tc.want {
			t.Fatalf("reconnectBackoff(%d) = %s, want %s", tc.failures, got, tc.want)
		}
	}
}

func TestLibOVSDBTopologyWriterUpdatesExistingVPCRouter(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	insertRows(t, ctx, client, &ovnnb.LogicalRouter{
		Name:        logicalRouter("prod"),
		ExternalIDs: map[string]string{"custom": "keep"},
	})
	writer := NewLibOVSDBTopologyWriter(client)
	if err := writer.EnsureVPC(ctx, model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}

	var routers []ovnnb.LogicalRouter
	requireEventually(t, func() bool {
		routers = nil
		err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == logicalRouter("prod") }).List(ctx, &routers)
		return err == nil && len(routers) == 1 && routers[0].ExternalIDs["netloom_owner"] == "netloom"
	})
	externalIDs := routers[0].ExternalIDs
	if externalIDs["custom"] != "keep" || externalIDs["netloom_owner"] != "netloom" || externalIDs["netloom_vpc"] != "prod" {
		t.Fatalf("logical router external IDs after update = %+v, want preserved custom and netloom ownership", externalIDs)
	}
}

func staticRoutesByKey(routes []ovnnb.LogicalRouterStaticRoute) map[string]ovnnb.LogicalRouterStaticRoute {
	out := make(map[string]ovnnb.LogicalRouterStaticRoute, len(routes))
	for _, route := range routes {
		out[route.IPPrefix+"|"+route.Nexthop] = route
	}
	return out
}

func natRowsByName(rows []ovnnb.NAT) map[string]ovnnb.NAT {
	out := make(map[string]ovnnb.NAT, len(rows))
	for _, row := range rows {
		out[row.ExternalIDs["netloom_nat"]] = row
	}
	return out
}

func loadBalancersByProtocol(rows []ovnnb.LoadBalancer) map[string]ovnnb.LoadBalancer {
	out := make(map[string]ovnnb.LoadBalancer, len(rows))
	for _, row := range rows {
		out[row.ExternalIDs["netloom_protocol"]] = row
	}
	return out
}

func singleLogicalSwitchByName(t *testing.T, ctx context.Context, client libovsdbclient.Client, name string) ovnnb.LogicalSwitch {
	t.Helper()
	var rows []ovnnb.LogicalSwitch
	if err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == name }).List(ctx, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("logical switch %s rows = %d, want 1: %+v", name, len(rows), rows)
	}
	return rows[0]
}

func managedOVNRowCounts(ctx context.Context, client libovsdbclient.Client) (map[string]int, error) {
	counts := map[string]int{}
	var routers []ovnnb.LogicalRouter
	if err := client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &routers); err != nil {
		return nil, err
	}
	counts["Logical_Router"] = len(routers)
	var switches []ovnnb.LogicalSwitch
	if err := client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &switches); err != nil {
		return nil, err
	}
	counts["Logical_Switch"] = len(switches)
	var switchPorts []ovnnb.LogicalSwitchPort
	if err := client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &switchPorts); err != nil {
		return nil, err
	}
	counts["Logical_Switch_Port"] = len(switchPorts)
	var routerPorts []ovnnb.LogicalRouterPort
	if err := client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &routerPorts); err != nil {
		return nil, err
	}
	counts["Logical_Router_Port"] = len(routerPorts)
	var staticRoutes []ovnnb.LogicalRouterStaticRoute
	if err := client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &staticRoutes); err != nil {
		return nil, err
	}
	counts["Logical_Router_Static_Route"] = len(staticRoutes)
	var policies []ovnnb.LogicalRouterPolicy
	if err := client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &policies); err != nil {
		return nil, err
	}
	counts["Logical_Router_Policy"] = len(policies)
	var nats []ovnnb.NAT
	if err := client.WhereCache(func(row *ovnnb.NAT) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &nats); err != nil {
		return nil, err
	}
	counts["NAT"] = len(nats)
	var lbs []ovnnb.LoadBalancer
	if err := client.WhereCache(func(row *ovnnb.LoadBalancer) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &lbs); err != nil {
		return nil, err
	}
	counts["Load_Balancer"] = len(lbs)
	var checks []ovnnb.LoadBalancerHealthCheck
	if err := client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &checks); err != nil {
		return nil, err
	}
	counts["Load_Balancer_Health_Check"] = len(checks)
	var dhcp []ovnnb.DHCPOptions
	if err := client.WhereCache(func(row *ovnnb.DHCPOptions) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &dhcp); err != nil {
		return nil, err
	}
	counts["DHCP_Options"] = len(dhcp)
	var dns []ovnnb.DNS
	if err := client.WhereCache(func(row *ovnnb.DNS) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &dns); err != nil {
		return nil, err
	}
	counts["DNS"] = len(dns)
	return counts, nil
}
