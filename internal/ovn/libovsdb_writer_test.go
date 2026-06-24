package ovn

import (
	"context"
	"net/netip"
	"testing"

	"github.com/ovn-kubernetes/libovsdb/ovsdb"

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
		return keep && add && !staleHop && !staleBlackhole &&
			staticRoutesByKey(routes)["10.20.0.0/24|10.10.0.253"].UUID == keptECMPUUID
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
		return !hasChassis && routers[0].ExternalIDs["netloom_gateway_distributed"] == "true"
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
