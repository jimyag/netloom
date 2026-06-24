package ovn

import (
	"context"
	"net/netip"
	"testing"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/ovnnb"
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

func TestLibOVSDBTopologyWriterEnsuresSubnetLogicalSwitch(t *testing.T) {
	ctx := context.Background()
	client, closeFn := newTestOVNNBClient(t)
	defer closeFn()

	if _, err := client.MonitorAll(ctx); err != nil {
		t.Fatal(err)
	}
	writer := NewLibOVSDBTopologyWriter(client)
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
