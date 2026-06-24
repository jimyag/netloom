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
