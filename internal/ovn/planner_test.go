package ovn_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn"
)

func TestPlannerMapsNetloomObjectsToOVNOperations(t *testing.T) {
	planner := ovn.NewPlanner()
	state := control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:            "apps",
			VPC:             "prod",
			CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
			Gateway:         netip.MustParseAddr("10.10.0.1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
			DHCP: model.DHCPOptions{
				Enabled:       true,
				LeaseTime:     7200,
				MTU:           1400,
				DNSServers:    []netip.Addr{netip.MustParseAddr("10.96.0.10"), netip.MustParseAddr("fd00:96::10")},
				DomainName:    "svc.cluster.local",
				SearchDomains: []string{"cluster.local", "svc.cluster.local"},
			},
		}},
		Endpoints: []model.Endpoint{{
			ID:     "pod-a",
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
		RouteTables: []model.RouteTable{{
			Name: "main",
			VPC:  "prod",
			Routes: []model.Route{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
			}},
		}},
		PolicyRoutes: []model.PolicyRoute{{
			Name:     "fw",
			VPC:      "prod",
			Priority: 100,
			Match: model.RouteMatch{
				Source:      netip.MustParsePrefix("10.10.0.0/24"),
				Destination: netip.MustParsePrefix("172.16.0.0/16"),
				Protocol:    model.ProtocolTCP,
				DstPorts:    []model.PortRange{{From: 443, To: 443}},
			},
			Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
		}},
		Gateways: []model.Gateway{{
			Name:       "gw-a",
			VPC:        "prod",
			Node:       "node-a",
			ExternalIF: "eth0",
			LANIP:      netip.MustParseAddr("10.10.0.254"),
		}},
		NATRules: []model.NATRule{{
			Name:       "egress",
			VPC:        "prod",
			Type:       model.ActionSNAT,
			MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
			ExternalIP: netip.MustParseAddr("198.51.100.10"),
		}},
		LoadBalancers: []model.LoadBalancer{{
			Name: "web",
			VPC:  "prod",
			VIP:  netip.MustParseAddr("10.96.0.10"),
			Ports: []model.LoadBalancerPort{{
				Port:     80,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{{
					IP:   netip.MustParseAddr("10.10.0.10"),
					Port: 8080,
				}},
			}},
			Subnets: []string{"apps"},
		}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			VPC:  "prod",
			Rules: []model.SecurityGroupRule{{
				ID:        "allow-web",
				Direction: model.DirectionIngress,
				Protocol:  model.ProtocolTCP,
				Ports:     []model.PortRange{{From: 443, To: 443}},
				Action:    model.ActionAllow,
			}},
		}},
	}
	controller := control.NewController(planner, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"--may-exist lr-add nl_lr_prod",
		"--may-exist ls-add nl_ls_apps",
		"--if-exists lsp-del nl_ls_apps_to_apps_localnet",
		"lsp-add-localnet-port nl_ls_apps nl_ls_apps_to_apps_localnet physnet-a",
		"external_ids:netloom_provider_network=physnet-a",
		"set logical_switch_port nl_ls_apps_to_apps_localnet tag=100",
		"--id=@nl_dhcp_pod_ha create DHCP_Options cidr=10.10.0.0/24",
		"options:server_id=10.10.0.1",
		"options:server_mac=0a:58:3e:f3:95:f0",
		"options:dns_server=[\"10.96.0.10\",\"fd00:96::10\"]",
		"options:domain_name=svc.cluster.local",
		"options:domain_search_list=[\"cluster.local\",\"svc.cluster.local\"]",
		"options:lease_time=7200",
		"options:mtu=1400",
		"lsp-set-dhcpv4-options nl_lp_pod-a",
		"lsp-set-dhcpv6-options nl_lp_pod-a",
		"set logical_switch_port nl_lp_pod-a dhcpv4_options=@nl_dhcp_pod_ha",
		"external_ids:netloom_owner=netloom",
		"external_ids:netloom_vpc=prod",
		"lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.254",
		"lr-policy-add nl_lr_prod 100",
		"external_ids:netloom_gateway=gw-a",
		"external_ids:netloom_gateway_lan_ip=10.10.0.254",
		"external_ids:netloom_gateway_distributed=false",
		"options:chassis=node-a",
		"lr-nat-add nl_lr_prod snat 198.51.100.10 10.10.0.0/24",
		"lb-add nl_lb_web 10.96.0.10:80 10.10.0.10:8080 tcp",
		"lr-lb-add nl_lr_prod nl_lb_web",
		"ls-lb-add nl_ls_apps nl_lb_web",
		"lsp-add nl_ls_apps nl_lp_pod-a",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("OVN operations missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "acl") {
		t.Fatalf("OVN planner must not generate ACL operations; got:\n%s", joined)
	}
}

func TestPlannerBuildsECMPStaticRouteOperations(t *testing.T) {
	planner := ovn.NewPlanner()
	state := control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
		RouteTables: []model.RouteTable{{
			Name: "main",
			VPC:  "prod",
			Routes: []model.Route{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				NextHops: []netip.Addr{
					netip.MustParseAddr("10.10.0.253"),
					netip.MustParseAddr("10.10.0.254"),
				},
			}},
		}},
	}
	controller := control.NewController(planner, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"--may-exist --ecmp lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.253",
		"--may-exist --ecmp lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.254",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("ECMP static route operation missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "lr-route-del") {
		t.Fatalf("planner should not delete routes during idempotent ensure:\n%s", joined)
	}
}

func TestPlannerDeletesLocalnetWhenProviderNetworkDisabled(t *testing.T) {
	planner := ovn.NewPlanner()
	if err := planner.EnsureSubnet(context.Background(), model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}); err != nil {
		t.Fatal(err)
	}

	joined := stringify(planner.Operations())
	if !strings.Contains(joined, "--if-exists lsp-del nl_ls_apps_to_apps_localnet") {
		t.Fatalf("provider network disable should delete localnet port:\n%s", joined)
	}
	if strings.Contains(joined, "lsp-add-localnet-port") {
		t.Fatalf("provider network disable should not recreate localnet port:\n%s", joined)
	}
}

func TestPlannerClearsEndpointDHCPWhenSubnetDHCPDisabled(t *testing.T) {
	planner := ovn.NewPlanner()
	if err := planner.EnsureSubnet(context.Background(), model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := planner.EnsureEndpoint(context.Background(), model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		IP:     netip.MustParseAddr("10.10.0.10"),
		Node:   "node-a",
	}); err != nil {
		t.Fatal(err)
	}

	joined := stringify(planner.Operations())
	if !strings.Contains(joined, "lsp-set-dhcpv4-options nl_lp_pod-a") {
		t.Fatalf("endpoint DHCPv4 clear operation missing:\n%s", joined)
	}
	if !strings.Contains(joined, "lsp-set-dhcpv6-options nl_lp_pod-a") {
		t.Fatalf("endpoint DHCPv6 clear operation missing:\n%s", joined)
	}
	if !strings.Contains(joined, "gc-dhcp-options pod-a") {
		t.Fatalf("disabled DHCP should GC stale endpoint DHCP options:\n%s", joined)
	}
	if strings.Contains(joined, "create DHCP_Options") || strings.Contains(joined, "dhcpv4_options=@") || strings.Contains(joined, "dhcpv6_options=@") {
		t.Fatalf("disabled DHCP should not create or bind DHCP options:\n%s", joined)
	}
}

func TestPlannerGCDHCPOptionsBeforeRecreate(t *testing.T) {
	planner := ovn.NewPlanner()
	if err := planner.EnsureSubnet(context.Background(), model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
		DHCP:    model.DHCPOptions{Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := planner.EnsureEndpoint(context.Background(), model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		IP:     netip.MustParseAddr("10.10.0.10"),
		Node:   "node-a",
	}); err != nil {
		t.Fatal(err)
	}

	joined := stringify(planner.Operations())
	gc := strings.Index(joined, "gc-dhcp-options pod-a")
	create := strings.Index(joined, "create DHCP_Options")
	if gc < 0 || create < 0 {
		t.Fatalf("expected DHCP GC and recreate operations:\n%s", joined)
	}
	if gc > create {
		t.Fatalf("DHCP GC must run before recreating endpoint DHCP options:\n%s", joined)
	}
}

func TestPlannerEncodesOVNNamesWithoutCollisions(t *testing.T) {
	planner := ovn.NewPlanner()
	for _, endpoint := range []model.Endpoint{
		{ID: "pod.1", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10"), Node: "node-a"},
		{ID: "pod_1", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.11"), Node: "node-a"},
	} {
		if err := planner.EnsureEndpoint(context.Background(), endpoint); err != nil {
			t.Fatal(err)
		}
	}

	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"lsp-add nl_ls_apps nl_lp_pod_d1",
		"lsp-add nl_ls_apps nl_lp_pod__1",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("OVN name encoding missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlannerBuildsStaticEndpointMACAddress(t *testing.T) {
	planner := ovn.NewPlanner()
	if err := planner.EnsureEndpoint(context.Background(), model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		IP:     netip.MustParseAddr("10.10.0.10"),
		MAC:    "0A:58:0A:0A:00:0A",
		Node:   "node-a",
	}); err != nil {
		t.Fatal(err)
	}

	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"lsp-set-addresses nl_lp_pod-a 0a:58:0a:0a:00:0a 10.10.0.10",
		"lsp-set-port-security nl_lp_pod-a 0a:58:0a:0a:00:0a 10.10.0.10",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("OVN operations missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlannerBuildsIPv6DHCPOptions(t *testing.T) {
	planner := ovn.NewPlanner()
	if err := planner.EnsureSubnet(context.Background(), model.Subnet{
		Name:    "apps-v6",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("fd00:10::/64"),
		Gateway: netip.MustParseAddr("fd00:10::1"),
		DHCP: model.DHCPOptions{
			Enabled:       true,
			LeaseTime:     7200,
			MTU:           1400,
			DNSServers:    []netip.Addr{netip.MustParseAddr("fd00:96::10")},
			DomainName:    "svc.cluster.local",
			SearchDomains: []string{"cluster.local"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := planner.EnsureEndpoint(context.Background(), model.Endpoint{
		ID:     "pod-v6",
		VPC:    "prod",
		Subnet: "apps-v6",
		IP:     netip.MustParseAddr("fd00:10::10"),
		Node:   "node-a",
	}); err != nil {
		t.Fatal(err)
	}

	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"set logical_router_port nl_lr_prod_to_apps-v6 ipv6_ra_configs:address_mode=dhcpv6_stateful",
		"lsp-set-dhcpv6-options nl_lp_pod-v6",
		"--id=@nl_dhcp6_pod_hv6 create DHCP_Options cidr=fd00:10::/64",
		"options:server_id=0a:58:85:d4:23:26",
		"options:dns_server=[\"fd00:96::10\"]",
		"options:domain_name=svc.cluster.local",
		"options:domain_search_list=[\"cluster.local\"]",
		"set logical_switch_port nl_lp_pod-v6 dhcpv6_options=@nl_dhcp6_pod_hv6",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("IPv6 DHCP operation missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "dhcpv4_options=@") {
		t.Fatalf("IPv6 endpoint should not bind DHCPv4 options:\n%s", joined)
	}
	if strings.Contains(joined, "options:router=") || strings.Contains(joined, "options:server_mac=") {
		t.Fatalf("DHCPv6 options should not include DHCPv4-only options:\n%s", joined)
	}
}

func TestPlannerClearsIPv6DHCPRAWhenSubnetDHCPDisabled(t *testing.T) {
	planner := ovn.NewPlanner()
	if err := planner.EnsureSubnet(context.Background(), model.Subnet{
		Name:    "apps-v6",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("fd00:10::/64"),
		Gateway: netip.MustParseAddr("fd00:10::1"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := planner.EnsureEndpoint(context.Background(), model.Endpoint{
		ID:     "pod-v6",
		VPC:    "prod",
		Subnet: "apps-v6",
		IP:     netip.MustParseAddr("fd00:10::10"),
		Node:   "node-a",
	}); err != nil {
		t.Fatal(err)
	}

	joined := stringify(planner.Operations())
	if !strings.Contains(joined, "remove logical_router_port nl_lr_prod_to_apps-v6 ipv6_ra_configs address_mode") {
		t.Fatalf("disabled IPv6 DHCP should clear RA address mode:\n%s", joined)
	}
	if !strings.Contains(joined, "lsp-set-dhcpv6-options nl_lp_pod-v6") {
		t.Fatalf("disabled IPv6 DHCP should clear endpoint DHCPv6 options:\n%s", joined)
	}
	if strings.Contains(joined, "dhcpv6_options=@") || strings.Contains(joined, "create DHCP_Options") {
		t.Fatalf("disabled IPv6 DHCP should not create or bind DHCPv6 options:\n%s", joined)
	}
}

func TestPlannerBuildsDistributedGatewayOperations(t *testing.T) {
	planner := ovn.NewPlanner()
	err := planner.EnsureGateway(context.Background(), model.Gateway{
		Name:        "gw-dist",
		VPC:         "prod",
		Node:        "node-a",
		ExternalIF:  "eth0",
		LANIP:       netip.MustParseAddr("10.10.0.254"),
		Distributed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"external_ids:netloom_gateway=gw-dist",
		"external_ids:netloom_external_if=eth0",
		"external_ids:netloom_gateway_lan_ip=10.10.0.254",
		"external_ids:netloom_gateway_distributed=true",
		"remove logical_router nl_lr_prod options chassis",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("OVN operations missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "options:chassis=node-a") {
		t.Fatalf("distributed gateway must not pin chassis:\n%s", joined)
	}
}

func TestPlannerBuildsLoadBalancerOperations(t *testing.T) {
	unhealthy := false
	planner := ovn.NewPlanner()
	err := planner.EnsureLoadBalancer(context.Background(), model.LoadBalancer{
		Name:            "web",
		VPC:             "prod",
		VIP:             netip.MustParseAddr("10.96.0.10"),
		SessionAffinity: true,
		AffinityTimeout: 7200,
		HealthCheck: model.LoadBalancerHealthCheck{
			Enabled:      true,
			Interval:     10,
			Timeout:      30,
			SuccessCount: 2,
			FailureCount: 4,
		},
		Ports: []model.LoadBalancerPort{{
			Port:     80,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{
				{IP: netip.MustParseAddr("10.10.0.11"), Port: 8080},
				{IP: netip.MustParseAddr("10.10.0.12"), Port: 8080, Healthy: &unhealthy},
				{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080},
			},
		}},
		Subnets: []string{"apps"},
	})
	if err != nil {
		t.Fatal(err)
	}

	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"--if-exists lb-del nl_lb_web 10.96.0.10:80",
		"--may-exist lb-add nl_lb_web 10.96.0.10:80 10.10.0.10:8080,10.10.0.11:8080 tcp",
		"external_ids:netloom_load_balancer=web",
		"selection_fields=[\"ip_src\"]",
		"external_ids:netloom_session_affinity=true",
		"options:affinity_timeout=7200",
		"clear load_balancer nl_lb_web health_check",
		"--id=@nl_lbhc_web_tcp_80 create Load_Balancer_Health_Check vip=10.96.0.10:80",
		"options:interval=10",
		"options:timeout=30",
		"options:success_count=2",
		"options:failure_count=4",
		"external_ids:netloom_load_balancer=web",
		"add load_balancer nl_lb_web health_check @nl_lbhc_web_tcp_80",
		"--may-exist lr-lb-add nl_lr_prod nl_lb_web",
		"--may-exist ls-lb-add nl_ls_apps nl_lb_web",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("OVN operations missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "10.10.0.12:8080") {
		t.Fatalf("unhealthy backend should not be programmed in OVN LB VIPs:\n%s", joined)
	}
}

func TestPlannerBuildsMultiPortLoadBalancerOperations(t *testing.T) {
	planner := ovn.NewPlanner()
	err := planner.EnsureLoadBalancer(context.Background(), model.LoadBalancer{
		Name: "web",
		VPC:  "prod",
		VIP:  netip.MustParseAddr("10.96.0.10"),
		Ports: []model.LoadBalancerPort{
			{
				Name:     "http",
				Port:     80,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080}},
			},
			{
				Name:     "metrics",
				Port:     9090,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 9091}},
			},
		},
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"--may-exist lb-add nl_lb_web 10.96.0.10:80 10.10.0.10:8080 tcp",
		"--may-exist lb-add nl_lb_web 10.96.0.10:9090 10.10.0.10:9091 tcp",
		"--id=@nl_lbhc_web_tcp_80 create Load_Balancer_Health_Check vip=10.96.0.10:80",
		"--id=@nl_lbhc_web_tcp_9090 create Load_Balancer_Health_Check vip=10.96.0.10:9090",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("OVN operations missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlannerClearsLoadBalancerAffinityWhenDisabled(t *testing.T) {
	planner := ovn.NewPlanner()
	err := planner.EnsureLoadBalancer(context.Background(), model.LoadBalancer{
		Name: "web",
		VPC:  "prod",
		VIP:  netip.MustParseAddr("10.96.0.10"),
		Ports: []model.LoadBalancerPort{{
			Port:     80,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"selection_fields=[]",
		"external_ids:netloom_session_affinity=false",
		"remove load_balancer nl_lb_web options affinity_timeout",
		"clear load_balancer nl_lb_web health_check",
		"gc-load-balancer-health-checks web",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("OVN operations missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlannerDefaultsLoadBalancerAffinityTimeout(t *testing.T) {
	planner := ovn.NewPlanner()
	err := planner.EnsureLoadBalancer(context.Background(), model.LoadBalancer{
		Name:            "web",
		VPC:             "prod",
		VIP:             netip.MustParseAddr("10.96.0.10"),
		SessionAffinity: true,
		Ports: []model.LoadBalancerPort{{
			Port:     80,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringify(planner.Operations())
	if !strings.Contains(joined, "options:affinity_timeout=10800") {
		t.Fatalf("OVN operations missing default affinity timeout:\n%s", joined)
	}
	if !strings.Contains(joined, "selection_fields=[\"ip_src\"]") {
		t.Fatalf("OVN operations missing default affinity selection field:\n%s", joined)
	}
}

func TestPlannerBuildsLoadBalancerSelectionFields(t *testing.T) {
	planner := ovn.NewPlanner()
	err := planner.EnsureLoadBalancer(context.Background(), model.LoadBalancer{
		Name:            "web",
		VPC:             "prod",
		VIP:             netip.MustParseAddr("10.96.0.10"),
		SelectionFields: []string{"tp_src", "ip_src"},
		Ports: []model.LoadBalancerPort{{
			Port:     80,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringify(planner.Operations())
	if !strings.Contains(joined, "selection_fields=[\"ip_src\",\"tp_src\"]") {
		t.Fatalf("OVN operations missing explicit selection fields:\n%s", joined)
	}
}

func TestPlannerDefaultsLoadBalancerHealthCheckOptions(t *testing.T) {
	planner := ovn.NewPlanner()
	err := planner.EnsureLoadBalancer(context.Background(), model.LoadBalancer{
		Name:        "web",
		VPC:         "prod",
		VIP:         netip.MustParseAddr("10.96.0.10"),
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
		Ports: []model.LoadBalancerPort{{
			Port:     80,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"options:interval=5",
		"options:timeout=20",
		"options:success_count=3",
		"options:failure_count=3",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("OVN operations missing default health check option %q:\n%s", expected, joined)
		}
	}
}

func TestPlannerDoesNotRecreateUnchangedLoadBalancerHealthCheck(t *testing.T) {
	planner := ovn.NewPlanner()
	lb := model.LoadBalancer{
		Name:        "web",
		VPC:         "prod",
		VIP:         netip.MustParseAddr("10.96.0.10"),
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
		Ports: []model.LoadBalancerPort{{
			Port:     80,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080}},
		}},
	}
	if err := planner.EnsureLoadBalancer(context.Background(), lb); err != nil {
		t.Fatal(err)
	}
	if err := planner.EnsureLoadBalancer(context.Background(), lb); err != nil {
		t.Fatal(err)
	}
	joined := stringify(planner.Operations())
	if got := strings.Count(joined, "create Load_Balancer_Health_Check"); got != 1 {
		t.Fatalf("health check create count = %d, want 1:\n%s", got, joined)
	}

	lb.HealthCheck.Timeout = 30
	if err := planner.EnsureLoadBalancer(context.Background(), lb); err != nil {
		t.Fatal(err)
	}
	joined = stringify(planner.Operations())
	if got := strings.Count(joined, "create Load_Balancer_Health_Check"); got != 2 {
		t.Fatalf("changed health check create count = %d, want 2:\n%s", got, joined)
	}
	if got := strings.Count(joined, "gc-load-balancer-health-checks web"); got != 2 {
		t.Fatalf("health check GC count = %d, want 2:\n%s", got, joined)
	}
	if !strings.Contains(joined, "options:timeout=30") {
		t.Fatalf("changed health check timeout missing:\n%s", joined)
	}
}

func TestPlannerBuildsPolicyRouteOperation(t *testing.T) {
	planner := ovn.NewPlanner()
	err := planner.EnsurePolicyRoute(context.Background(), model.PolicyRoute{
		Name:     "fw",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("172.16.0.0/16"),
			Protocol:    model.ProtocolTCP,
			DstPorts:    []model.PortRange{{From: 443, To: 443}},
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	match := stringify(planner.Operations())
	for _, expected := range []string{"lr-policy-add nl_lr_prod 100", "ip4.src == 10.10.0.0/24", "ip4.dst == 172.16.0.0/16", "tcp", "tcp.dst == 443"} {
		if !strings.Contains(match, expected) {
			t.Fatalf("match %q missing %q", match, expected)
		}
	}
	if strings.Contains(match, "lr-policy-del") {
		t.Fatalf("single-next-hop policy route should not delete during idempotent ensure:\n%s", match)
	}
}

func TestPlannerBuildsAllowPolicyRouteOperation(t *testing.T) {
	planner := ovn.NewPlanner()
	err := planner.EnsurePolicyRoute(context.Background(), model.PolicyRoute{
		Name:     "allow-api",
		VPC:      "prod",
		Priority: 300,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("198.51.100.10/32"),
			Protocol:    model.ProtocolTCP,
			DstPorts:    []model.PortRange{{From: 443, To: 443}},
		},
		Action: model.RouteAction{Type: model.ActionAllow},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"lr-policy-add nl_lr_prod 300",
		"allow",
		"ip4.dst == 198.51.100.10/32",
		"tcp.dst == 443",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("allow policy route operation missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "reroute") || strings.Contains(joined, "nexthops=") {
		t.Fatalf("allow policy route must not program reroute nexthops:\n%s", joined)
	}
	if strings.Contains(joined, "lr-policy-del") {
		t.Fatalf("allow policy route should not delete during idempotent ensure:\n%s", joined)
	}
}

func TestPlannerBuildsIPv6PolicyRouteOperation(t *testing.T) {
	planner := ovn.NewPlanner()
	err := planner.EnsurePolicyRoute(context.Background(), model.PolicyRoute{
		Name:     "v6-fw",
		VPC:      "prod",
		Priority: 120,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("fd00:10::/64"),
			Destination: netip.MustParsePrefix("fd00:20::/64"),
			Protocol:    model.ProtocolUDP,
			DstPorts:    []model.PortRange{{From: 53, To: 53}},
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("fd00:10::fe")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	match := stringify(planner.Operations())
	for _, expected := range []string{"ip6.src == fd00:10::/64", "ip6.dst == fd00:20::/64", "udp.dst == 53"} {
		if !strings.Contains(match, expected) {
			t.Fatalf("match %q missing %q", match, expected)
		}
	}
	if strings.Contains(match, "ip4.src == fd00") || strings.Contains(match, "ip4.dst == fd00") {
		t.Fatalf("IPv6 route must not use ip4 match fields:\n%s", match)
	}
}

func TestPlannerBuildsECMPPolicyRouteOperation(t *testing.T) {
	planner := ovn.NewPlanner()
	err := planner.EnsurePolicyRoute(context.Background(), model.PolicyRoute{
		Name:     "centralized-egress",
		VPC:      "prod",
		Priority: 110,
		Match: model.RouteMatch{
			Source: netip.MustParsePrefix("10.10.0.0/24"),
		},
		Action: model.RouteAction{
			Type: model.ActionReroute,
			NextHops: []netip.Addr{
				netip.MustParseAddr("10.10.0.254"),
				netip.MustParseAddr("10.10.0.253"),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"--if-exists lr-policy-del nl_lr_prod 110 ip4.src == 10.10.0.0/24",
		"--id=@nl_lrp_centralized_hegress create Logical_Router_Policy priority=110",
		"action=reroute",
		"nexthops=[\"10.10.0.253\",\"10.10.0.254\"]",
		"external_ids:netloom_policy_route=centralized-egress",
		"add logical_router nl_lr_prod policies @nl_lrp_centralized_hegress",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("ECMP policy route operations missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "lr-policy-add") {
		t.Fatalf("ECMP policy route must use Logical_Router_Policy nexthops set:\n%s", joined)
	}
}

func TestPlannerECMPPolicyRouteNamedUUIDAvoidsEscapedNameCollisions(t *testing.T) {
	planner := ovn.NewPlanner()
	for _, name := range []string{"pod-1", "pod_1"} {
		err := planner.EnsurePolicyRoute(context.Background(), model.PolicyRoute{
			Name:     name,
			VPC:      "prod",
			Priority: 100,
			Match:    model.RouteMatch{Source: netip.MustParsePrefix("10.10.0.0/24")},
			Action: model.RouteAction{
				Type: model.ActionReroute,
				NextHops: []netip.Addr{
					netip.MustParseAddr("10.10.0.253"),
					netip.MustParseAddr("10.10.0.254"),
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"--id=@nl_lrp_pod_h1 create Logical_Router_Policy",
		"--id=@nl_lrp_pod__1 create Logical_Router_Policy",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("named UUID encoding missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlannerBuildsKubeOVNStyleNATOperations(t *testing.T) {
	planner := ovn.NewPlanner()
	for _, rule := range []model.NATRule{
		{
			Name:       "web",
			VPC:        "prod",
			Type:       model.ActionDNAT,
			ExternalIP: netip.MustParseAddr("198.51.100.20"),
			TargetIP:   netip.MustParseAddr("10.10.0.10"),
		},
		{
			Name:       "fip",
			VPC:        "prod",
			Type:       model.ActionDNATSNAT,
			ExternalIP: netip.MustParseAddr("198.51.100.30"),
			TargetIP:   netip.MustParseAddr("10.10.0.11"),
		},
		{
			Name:        "distributed-fip",
			VPC:         "prod",
			Type:        model.ActionDNATSNAT,
			ExternalIP:  netip.MustParseAddr("198.51.100.31"),
			TargetIP:    netip.MustParseAddr("10.10.0.14"),
			LogicalPort: "nl_lp_pod-a",
			ExternalMAC: "0a:58:0a:0a:00:0e",
		},
		{
			Name:         "ssh",
			VPC:          "prod",
			Type:         model.ActionDNAT,
			ExternalIP:   netip.MustParseAddr("198.51.100.40"),
			TargetIP:     netip.MustParseAddr("10.10.0.12"),
			Protocol:     model.ProtocolTCP,
			ExternalPort: 2222,
			TargetPort:   2222,
		},
		{
			Name:         "web-translate",
			VPC:          "prod",
			Type:         model.ActionDNAT,
			ExternalIP:   netip.MustParseAddr("198.51.100.41"),
			TargetIP:     netip.MustParseAddr("10.10.0.13"),
			Protocol:     model.ProtocolTCP,
			ExternalPort: 8443,
			TargetPort:   443,
		},
	} {
		if err := planner.EnsureNATRule(context.Background(), rule); err != nil {
			t.Fatal(err)
		}
	}

	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"lr-nat-add nl_lr_prod dnat 198.51.100.20 10.10.0.10",
		"lr-nat-add nl_lr_prod dnat_and_snat 198.51.100.30 10.10.0.11",
		"lr-nat-add nl_lr_prod dnat_and_snat 198.51.100.31 10.10.0.14 nl_lp_pod-a 0a:58:0a:0a:00:0e",
		"gc-nat-rule ssh",
		"--id=@nl_nat_ssh create NAT type=dnat external_ip=198.51.100.40 logical_ip=10.10.0.12 external_port_range=2222 logical_port_range=2222 protocol=tcp",
		"external_ids:netloom_nat=ssh",
		"add logical_router nl_lr_prod nat @nl_nat_ssh",
		"gc-nat-rule web-translate",
		"--id=@nl_nat_web_htranslate create NAT type=dnat external_ip=198.51.100.41 logical_ip=10.10.0.13 external_port_range=8443 logical_port_range=443 protocol=tcp",
		"external_ids:netloom_nat=web-translate",
		"add logical_router nl_lr_prod nat @nl_nat_web_htranslate",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("OVN operations missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "nl_natlb_web_translate") {
		t.Fatalf("translated DNAT must not create load balancer operations:\n%s", joined)
	}
	if strings.Contains(joined, "lr-nat-del") {
		t.Fatalf("planner should not delete NAT during ensure; lifecycle cleanup owns deletion:\n%s", joined)
	}
}

func TestPlannerCleanupDeletesDNATSNATRule(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	controller := control.NewController(backend, control.NewMemoryBackend())
	first := control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
		NATRules: []model.NATRule{{
			Name:       "fip",
			VPC:        "prod",
			Type:       model.ActionDNATSNAT,
			ExternalIP: netip.MustParseAddr("198.51.100.30"),
			TargetIP:   netip.MustParseAddr("10.10.0.11"),
		}},
	}
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.NATRules = nil
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringify(recorder.Operations())
	expected := "--if-exists lr-nat-del nl_lr_prod dnat_and_snat 198.51.100.30"
	if !strings.Contains(joined, expected) {
		t.Fatalf("cleanup operations missing %q:\n%s", expected, joined)
	}
}

func stringify(ops []ovn.Operation) string {
	lines := make([]string, 0, len(ops))
	for _, op := range ops {
		lines = append(lines, op.String())
	}
	return strings.Join(lines, "\n")
}
