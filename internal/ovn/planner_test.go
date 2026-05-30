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
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
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
				NextHop:     netip.MustParseAddr("10.10.0.254"),
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
			Action: model.RouteAction{Type: model.ActionReroute, NextHop: netip.MustParseAddr("10.10.0.253")},
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
			Name:     "web",
			VPC:      "prod",
			VIP:      netip.MustParseAddr("10.96.0.10"),
			Port:     80,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{
				IP:   netip.MustParseAddr("10.10.0.10"),
				Port: 8080,
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
		"external_ids:netloom_owner=netloom",
		"external_ids:netloom_vpc=prod",
		"lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.254",
		"lr-policy-add nl_lr_prod 100",
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

func TestPlannerBuildsLoadBalancerOperations(t *testing.T) {
	planner := ovn.NewPlanner()
	err := planner.EnsureLoadBalancer(context.Background(), model.LoadBalancer{
		Name:     "web",
		VPC:      "prod",
		VIP:      netip.MustParseAddr("10.96.0.10"),
		Port:     80,
		Protocol: model.ProtocolTCP,
		Backends: []model.LoadBalancerBackend{
			{IP: netip.MustParseAddr("10.10.0.11"), Port: 8080},
			{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080},
		},
		Subnets: []string{"apps"},
	})
	if err != nil {
		t.Fatal(err)
	}

	joined := stringify(planner.Operations())
	for _, expected := range []string{
		"--may-exist lb-add nl_lb_web 10.96.0.10:80 10.10.0.10:8080,10.10.0.11:8080 tcp",
		"external_ids:netloom_load_balancer=web",
		"--may-exist lr-lb-add nl_lr_prod nl_lb_web",
		"--may-exist ls-lb-add nl_ls_apps nl_lb_web",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("OVN operations missing %q:\n%s", expected, joined)
		}
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
		Action: model.RouteAction{Type: model.ActionReroute, NextHop: netip.MustParseAddr("10.10.0.253")},
	})
	if err != nil {
		t.Fatal(err)
	}
	match := stringify(planner.Operations())
	for _, expected := range []string{"ip4.src == 10.10.0.0/24", "ip4.dst == 172.16.0.0/16", "tcp", "tcp.dst == 443"} {
		if !strings.Contains(match, expected) {
			t.Fatalf("match %q missing %q", match, expected)
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
			Name:         "ssh",
			VPC:          "prod",
			Type:         model.ActionDNAT,
			ExternalIP:   netip.MustParseAddr("198.51.100.40"),
			TargetIP:     netip.MustParseAddr("10.10.0.12"),
			Protocol:     model.ProtocolTCP,
			ExternalPort: 2222,
			TargetPort:   2222,
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
		"--portrange --may-exist lr-nat-add nl_lr_prod dnat 198.51.100.40 10.10.0.12 2222",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("OVN operations missing %q:\n%s", expected, joined)
		}
	}
}

func TestPlannerCleanupDeletesDNATSNATRule(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	controller := control.NewController(backend, control.NewMemoryBackend())
	first := control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
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
