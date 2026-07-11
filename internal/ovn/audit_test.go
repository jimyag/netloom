package ovn

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/topology"
)

func TestNBCTLExecutorAuditManagedObjectsCountsLiveRows(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "args.log")
	binary := filepath.Join(tmp, "ovn-nbctl")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + logPath + `"
case "$*" in
  *"find Logical_Switch external_ids:netloom_owner=netloom"*) printf 'ls-a,"{netloom_owner=netloom,netloom_vpc=prod,netloom_subnet=apps}"\n' ;;
  *"find NAT external_ids:netloom_owner=netloom"*) printf 'nat-a,"{netloom_owner=netloom,netloom_vpc=prod,netloom_nat=egress}"\nnat-b,"{netloom_owner=netloom,netloom_vpc=prod,netloom_nat=egress}"\n' ;;
  *"find DHCP_Options external_ids:netloom_owner=netloom"*) printf 'dhcp-a,"{netloom_owner=netloom,netloom_vpc=prod}"\n' ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	stats, err := executor.AuditManagedObjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.ManagedLogicalSwitches != 1 || stats.ManagedNATRules != 2 || stats.ManagedDHCPOptions != 1 {
		t.Fatalf("stats = %+v, want LS/NAT/DHCP live row counts", stats)
	}
	if stats.DuplicateManagedRows != 1 || stats.IncompleteManagedRows != 1 {
		t.Fatalf("stats = %+v, want one duplicate NAT and one incomplete DHCP row", stats)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logged := string(logData)
	for _, expected := range []string{
		"find Logical_Switch external_ids:netloom_owner=netloom",
		"find Logical_Router external_ids:netloom_owner=netloom",
		"find Logical_Router_Policy external_ids:netloom_owner=netloom",
		"find Load_Balancer_Health_Check external_ids:netloom_owner=netloom",
	} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("audit command log missing %q:\n%s", expected, logged)
		}
	}
}

func TestNBCTLExecutorManagedOVNRowsReadsAuditedColumns(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "args.log")
	binary := filepath.Join(tmp, "ovn-nbctl")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + logPath + `"
case "$*" in
  *"--columns=_uuid,external_ids,name,other_config find Logical_Switch external_ids:netloom_owner=netloom"*) printf 'ls-a,"{netloom_owner=netloom,netloom_vpc=prod,netloom_subnet=apps}",nl_ls_prod_apps,"{mcast_snoop=false,subnet=10.10.0.0/24}"\n' ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	rows, err := executor.ManagedOVNRows(context.Background(), "Logical_Switch")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.UUID != "ls-a" || row.ExternalIDs["netloom_subnet"] != "apps" {
		t.Fatalf("row identity = %+v, want parsed UUID and external IDs", row)
	}
	if row.Fields["name"] != "nl_ls_prod_apps" || row.Fields["other_config"] != "mcast_snoop=false,subnet=10.10.0.0/24" {
		t.Fatalf("row fields = %+v, want audited switch columns", row.Fields)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "--columns=_uuid,external_ids,name,other_config") {
		t.Fatalf("audit command did not request switch columns:\n%s", string(logData))
	}
}

func TestNBCTLExecutorManagedOVNRowsResolvesLogicalRouterReferences(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "args.log")
	binary := filepath.Join(tmp, "ovn-nbctl")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + logPath + `"
case "$*" in
  *"--columns=_uuid,external_ids,name,options,ports,load_balancers,nat,policies,static_routes find Logical_Router external_ids:netloom_owner=netloom"*) printf 'lr-prod,"{netloom_owner=netloom,netloom_vpc=prod}",nl_lr_prod,"{}",[lrp-apps],[lb-api],[nat-egress],[policy-via-fw],[route-main]\n' ;;
  *"--columns=_uuid,external_ids,name find Logical_Router_Port external_ids:netloom_owner=netloom"*) printf 'lrp-apps,"{netloom_owner=netloom,netloom_subnet=apps}",nl_lrp_prod_apps\n' ;;
  *"--columns=_uuid,external_ids,name find Load_Balancer external_ids:netloom_owner=netloom"*) printf 'lb-api,"{netloom_owner=netloom,netloom_vpc=prod,netloom_load_balancer=api,netloom_protocol=tcp}",nl_lb_prod_api_tcp\n' ;;
  *"--columns=_uuid,external_ids find NAT external_ids:netloom_owner=netloom"*) printf 'nat-egress,"{netloom_owner=netloom,netloom_vpc=prod,netloom_nat=egress}"\n' ;;
  *"--columns=_uuid,external_ids find Logical_Router_Policy external_ids:netloom_owner=netloom"*) printf 'policy-via-fw,"{netloom_owner=netloom,netloom_vpc=prod,netloom_policy_route=via-fw}"\n' ;;
  *"--columns=_uuid,external_ids find Logical_Router_Static_Route external_ids:netloom_owner=netloom"*) printf 'route-main,"{netloom_owner=netloom,netloom_vpc=prod,netloom_route_table=main,netloom_route_key=10.20.0.0/24|10.10.0.253}"\n' ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	rows, err := executor.ManagedOVNRows(context.Background(), "Logical_Router")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	fields := rows[0].Fields
	expected := map[string]string{
		"ports":          "nl_lrp_prod_apps",
		"load_balancers": "nl_lb_prod_api_tcp",
		"nat_rules":      "egress",
		"policies":       "via-fw",
		"static_routes":  "10.20.0.0/24|10.10.0.253",
	}
	for key, value := range expected {
		if fields[key] != value {
			t.Fatalf("router field %s = %q, want %q; fields=%+v", key, fields[key], value, fields)
		}
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logged := string(logData)
	for _, expected := range []string{
		"--columns=_uuid,external_ids,name,options,ports,load_balancers,nat,policies,static_routes",
		"find Logical_Router_Port external_ids:netloom_owner=netloom",
		"find NAT external_ids:netloom_owner=netloom",
		"find Logical_Router_Static_Route external_ids:netloom_owner=netloom",
	} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("audit command log missing %q:\n%s", expected, logged)
		}
	}
}

func TestAuditManagedObjectsFromNBCTLReportsColumnDrift(t *testing.T) {
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "ovn-nbctl")
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}
	otherConfig := mapField(logicalSwitchOtherConfig(subnet))
	script := `#!/bin/sh
case "$*" in
  *"find Logical_Switch external_ids:netloom_owner=netloom"*) printf 'ls-a,"{netloom_owner=netloom,netloom_vpc=prod,netloom_subnet=apps}",renamed-switch,"{` + otherConfig + `}"\n' ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	desired := topology.State{
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps"): subnet,
		},
	}

	executor := NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), executor, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("stats = %+v, want one switch name column drift from nbctl rows", stats)
	}
}

func TestAuditManagedRowsCountsDuplicatesAndIncompleteRows(t *testing.T) {
	rows := []ManagedOVNRow{
		{Table: "NAT", UUID: "uuid-a", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod", "netloom_nat": "egress"}},
		{Table: "NAT", UUID: "uuid-b", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod", "netloom_nat": "egress"}},
		{Table: "NAT", UUID: "uuid-c", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod"}},
		{Table: "NAT"},
	}

	result := auditManagedRows("NAT", rows)
	if result.count != 4 {
		t.Fatalf("rows = %d, want 4", result.count)
	}
	if result.duplicates != 1 {
		t.Fatalf("duplicates = %d, want 1", result.duplicates)
	}
	if result.incomplete != 2 {
		t.Fatalf("incomplete = %d, want 2", result.incomplete)
	}
}

func TestAuditLogicalSwitchPortIdentityAcceptsRouterAndLocalnetPorts(t *testing.T) {
	rows := []ManagedOVNRow{
		{Table: "Logical_Switch_Port", UUID: "uuid-router", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_subnet": "apps", "netloom_role": "router"}},
		{Table: "Logical_Switch_Port", UUID: "uuid-localnet", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_subnet": "apps", "netloom_provider_network": "physnet-a"}},
	}

	result := auditManagedRows("Logical_Switch_Port", rows)
	if result.count != 2 || result.incomplete != 0 || result.duplicates != 0 {
		t.Fatalf("logical switch port audit = %+v, want two complete unique managed ports", result)
	}
}

func TestAuditManagedRowsTreatsLoadBalancerProtocolsAsDistinct(t *testing.T) {
	rows := []ManagedOVNRow{
		{Table: "Load_Balancer", UUID: "lb-tcp", ExternalIDs: map[string]string{
			"netloom_owner":         "netloom",
			"netloom_vpc":           "prod",
			"netloom_load_balancer": "api",
			"netloom_protocol":      "tcp",
		}},
		{Table: "Load_Balancer", UUID: "lb-udp", ExternalIDs: map[string]string{
			"netloom_owner":         "netloom",
			"netloom_vpc":           "prod",
			"netloom_load_balancer": "api",
			"netloom_protocol":      "udp",
		}},
	}

	result := auditManagedRows("Load_Balancer", rows)
	if result.count != 2 || result.incomplete != 0 || result.duplicates != 0 || len(result.rows) != 2 {
		t.Fatalf("load balancer audit = %+v, want distinct tcp/udp rows", result)
	}
}

func TestAuditManagedObjectsFromReaderUsesTypedRows(t *testing.T) {
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Switch": {
			{Table: "Logical_Switch", UUID: "ls-a", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod", "netloom_subnet": "apps"}},
		},
		"Logical_Router_Policy": {
			{Table: "Logical_Router_Policy", UUID: "policy-a", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod", "netloom_policy_route": "via-fw"}},
			{Table: "Logical_Router_Policy", UUID: "policy-b", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod", "netloom_policy_route": "via-fw"}},
		},
		"Load_Balancer": {
			{Table: "Load_Balancer", UUID: "lb-a", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod"}},
		},
	}}

	stats, err := AuditManagedObjectsFromReader(context.Background(), reader)
	if err != nil {
		t.Fatal(err)
	}
	if stats.ManagedLogicalSwitches != 1 || stats.ManagedLogicalRouterPolicies != 2 || stats.ManagedLoadBalancers != 1 {
		t.Fatalf("stats = %+v, want typed reader counts", stats)
	}
	if stats.DuplicateManagedRows != 1 || stats.IncompleteManagedRows != 1 {
		t.Fatalf("stats = %+v, want duplicate policy and incomplete load balancer", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsPolicyRouteActionExternalIDDrift(t *testing.T) {
	route := model.PolicyRoute{
		Name:     "allow-api",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
		},
		Action: model.RouteAction{Type: model.ActionAllow},
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router_Policy": {
			{Table: "Logical_Router_Policy", UUID: "policy-allow-api", ExternalIDs: map[string]string{
				"netloom_owner":        "netloom",
				"netloom_vpc":          "prod",
				"netloom_policy_route": "allow-api",
				"netloom_action":       "drop",
			}, Fields: map[string]string{
				"priority": "100",
				"match":    policyRouteMatch(route.Match),
				"action":   "allow",
			}},
		},
	}}
	desired := topology.State{PolicyRoutes: []model.PolicyRoute{route}}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("stats = %+v, want one policy route action external_id drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsLoadBalancerParentAttachmentDrift(t *testing.T) {
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
		Subnets: []string{
			"apps",
		},
		Ports: []model.LoadBalancerPort{{
			Port:     443,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.20"), Port: 8443}},
		}},
	}
	lbName := loadBalancerProtocolName("prod", "api", model.ProtocolTCP)
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router": {
			{Table: "Logical_Router", UUID: "lr-prod", ExternalIDs: map[string]string{
				"netloom_owner": "netloom",
				"netloom_vpc":   "prod",
			}, Fields: map[string]string{
				"name":           logicalRouter("prod"),
				"ports":          routerPortName(logicalRouter("prod"), "apps"),
				"load_balancers": "",
			}},
		},
		"Logical_Switch": {
			{Table: "Logical_Switch", UUID: "ls-apps", ExternalIDs: map[string]string{
				"netloom_owner":  "netloom",
				"netloom_vpc":    "prod",
				"netloom_subnet": "apps",
			}, Fields: map[string]string{
				"name":           logicalSwitch("prod", "apps"),
				"other_config":   mapField(logicalSwitchOtherConfig(subnet)),
				"ports":          switchRouterPortName(logicalSwitch("prod", "apps"), "apps"),
				"load_balancers": "",
			}},
		},
		"Logical_Router_Port": {
			{Table: "Logical_Router_Port", UUID: "lrp-apps", ExternalIDs: map[string]string{
				"netloom_owner":  "netloom",
				"netloom_subnet": "apps",
			}, Fields: map[string]string{
				"name":     routerPortName(logicalRouter("prod"), "apps"),
				"mac":      deterministicMAC(subnet),
				"networks": "10.10.0.1/24",
			}},
		},
		"Logical_Switch_Port": {
			{Table: "Logical_Switch_Port", UUID: "lsp-router", ExternalIDs: map[string]string{
				"netloom_owner":  "netloom",
				"netloom_subnet": "apps",
				"netloom_role":   "router",
			}, Fields: map[string]string{
				"name":      switchRouterPortName(logicalSwitch("prod", "apps"), "apps"),
				"type":      "router",
				"addresses": deterministicMAC(subnet),
				"options":   mapField(map[string]string{"router-port": routerPortName(logicalRouter("prod"), "apps")}),
			}},
		},
		"Load_Balancer": {
			{Table: "Load_Balancer", UUID: "lb-api", ExternalIDs: map[string]string{
				"netloom_owner":            "netloom",
				"netloom_vpc":              "prod",
				"netloom_load_balancer":    "api",
				"netloom_protocol":         "tcp",
				"netloom_session_affinity": "false",
			}, Fields: map[string]string{
				"name":             lbName,
				"vips":             "10.96.0.10:443=10.10.0.20:8443",
				"protocol":         "tcp",
				"selection_fields": "",
			}},
		},
	}}
	desired := topology.State{
		VPCs: map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets: map[string]model.Subnet{
			"prod/apps": subnet,
		},
		LoadBalancers: map[string]model.LoadBalancer{
			"prod/api": lb,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 2 || stats.DriftedManagedFields != 2 {
		t.Fatalf("load balancer parent attachment drift stats = %+v, want router and switch attachment drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsRouterAndSwitchPortAttachmentDrift(t *testing.T) {
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
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router": {
			{Table: "Logical_Router", UUID: "lr-prod", ExternalIDs: map[string]string{
				"netloom_owner": "netloom",
				"netloom_vpc":   "prod",
			}, Fields: map[string]string{
				"name":  logicalRouter("prod"),
				"ports": "",
			}},
		},
		"Logical_Switch": {
			{Table: "Logical_Switch", UUID: "ls-apps", ExternalIDs: map[string]string{
				"netloom_owner":  "netloom",
				"netloom_vpc":    "prod",
				"netloom_subnet": "apps",
			}, Fields: map[string]string{
				"name":         logicalSwitch("prod", "apps"),
				"other_config": mapField(logicalSwitchOtherConfig(subnet)),
				"ports":        "",
			}},
		},
		"Logical_Router_Port": {
			{Table: "Logical_Router_Port", UUID: "lrp-apps", ExternalIDs: map[string]string{
				"netloom_owner":  "netloom",
				"netloom_subnet": "apps",
			}, Fields: map[string]string{
				"name":     routerPortName(logicalRouter("prod"), "apps"),
				"mac":      deterministicMAC(subnet),
				"networks": "10.10.0.1/24",
			}},
		},
		"Logical_Switch_Port": {
			{Table: "Logical_Switch_Port", UUID: "lsp-router", ExternalIDs: map[string]string{
				"netloom_owner":  "netloom",
				"netloom_subnet": "apps",
				"netloom_role":   "router",
			}, Fields: map[string]string{
				"name":      switchRouterPortName(logicalSwitch("prod", "apps"), "apps"),
				"type":      "router",
				"addresses": deterministicMAC(subnet),
				"options":   mapField(map[string]string{"router-port": routerPortName(logicalRouter("prod"), "apps")}),
			}},
			{Table: "Logical_Switch_Port", UUID: "lsp-pod-a", ExternalIDs: map[string]string{
				"netloom_owner":    "netloom",
				"netloom_vpc":      "prod",
				"netloom_endpoint": endpointExternalID("prod", "pod-a"),
				"netloom_node":     "node-a",
				"netloom_subnet":   "apps",
			}, Fields: map[string]string{
				"name":          logicalPort("prod", "pod-a"),
				"addresses":     endpointAddress(endpoint),
				"port_security": endpointAddress(endpoint),
			}},
		},
	}}
	desired := topology.State{
		VPCs: map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets: map[string]model.Subnet{
			"prod/apps": subnet,
		},
		Endpoints: map[string]model.Endpoint{
			"prod/pod-a": endpoint,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 2 || stats.DriftedManagedFields != 2 {
		t.Fatalf("router/switch port attachment drift stats = %+v, want router and switch port attachment drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsIPv6RouterPortRADrift(t *testing.T) {
	subnet := model.Subnet{
		Name:    "apps-v6",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("fd00:10::/64"),
		Gateway: netip.MustParseAddr("fd00:10::1"),
		DHCP:    model.DHCPOptions{Enabled: true},
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router_Port": {
			{Table: "Logical_Router_Port", UUID: "lrp-apps-v6", ExternalIDs: map[string]string{
				"netloom_owner":  "netloom",
				"netloom_subnet": "apps-v6",
			}, Fields: map[string]string{
				"name":            routerPortName(logicalRouter("prod"), "apps-v6"),
				"mac":             deterministicMAC(subnet),
				"networks":        "fd00:10::1/64",
				"ipv6_ra_configs": "",
			}},
		},
	}}
	desired := topology.State{
		VPCs: map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps-v6"): subnet,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("IPv6 router port RA drift stats = %+v, want one RA config field drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsNATParentAttachmentDrift(t *testing.T) {
	nat := model.NATRule{
		Name:       "egress",
		VPC:        "prod",
		Type:       model.ActionSNAT,
		MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
		ExternalIP: netip.MustParseAddr("198.51.100.10"),
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router": {
			{Table: "Logical_Router", UUID: "lr-prod", ExternalIDs: map[string]string{
				"netloom_owner": "netloom",
				"netloom_vpc":   "prod",
			}, Fields: map[string]string{
				"name":      logicalRouter("prod"),
				"nat_rules": "",
			}},
		},
		"NAT": {
			{Table: "NAT", UUID: "nat-egress", ExternalIDs: map[string]string{
				"netloom_owner": "netloom",
				"netloom_vpc":   "prod",
				"netloom_nat":   "egress",
			}, Fields: map[string]string{
				"type":        "snat",
				"external_ip": "198.51.100.10",
				"logical_ip":  "10.10.0.0/24",
			}},
		},
	}}
	desired := topology.State{
		VPCs: map[string]model.VPC{"prod": {Name: "prod"}},
		NATRules: map[string]model.NATRule{
			"prod/egress": nat,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("NAT parent attachment drift stats = %+v, want one router NAT attachment drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsNATExternalIDDrift(t *testing.T) {
	nat := model.NATRule{
		Name:         "api",
		VPC:          "prod",
		Type:         model.ActionDNAT,
		ExternalIP:   netip.MustParseAddr("198.51.100.10"),
		TargetIP:     netip.MustParseAddr("10.10.0.20"),
		ExternalPort: 8443,
		TargetPort:   443,
		Protocol:     model.ProtocolTCP,
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"NAT": {
			{Table: "NAT", UUID: "nat-api", ExternalIDs: map[string]string{
				"netloom_owner":         "netloom",
				"netloom_vpc":           "prod",
				"netloom_nat":           "api",
				"netloom_external_port": "8443",
				"netloom_target_port":   "8443",
				"netloom_protocol":      "tcp",
			}, Fields: map[string]string{
				"type":                "dnat",
				"external_ip":         "198.51.100.10",
				"logical_ip":          "10.10.0.20",
				"external_port_range": "8443",
				"options":             "netloom_logical_port_range=443,netloom_protocol=tcp",
			}},
		},
	}}
	desired := topology.State{
		NATRules: map[string]model.NATRule{
			"prod/api": nat,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("NAT metadata drift stats = %+v, want one target port external_id drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsStaleNATExternalIDs(t *testing.T) {
	nat := model.NATRule{
		Name:       "api",
		VPC:        "prod",
		Type:       model.ActionDNAT,
		ExternalIP: netip.MustParseAddr("198.51.100.10"),
		TargetIP:   netip.MustParseAddr("10.10.0.20"),
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"NAT": {
			{Table: "NAT", UUID: "nat-api", ExternalIDs: map[string]string{
				"netloom_owner":         "netloom",
				"netloom_vpc":           "prod",
				"netloom_nat":           "api",
				"netloom_external_port": "8443",
				"netloom_target_port":   "443",
				"netloom_protocol":      "tcp",
				"custom":                "preserved",
			}, Fields: map[string]string{
				"type":                "dnat",
				"external_ip":         "198.51.100.10",
				"logical_ip":          "10.10.0.20",
				"external_port_range": "8443",
				"options":             "netloom_logical_port_range=443,netloom_protocol=tcp",
			}},
		},
	}}
	desired := topology.State{
		NATRules: map[string]model.NATRule{
			"prod/api": nat,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 5 {
		t.Fatalf("NAT stale external_id drift stats = %+v, want stale managed external_ids and columns", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsRouterPolicyAndStaticRouteAttachmentDrift(t *testing.T) {
	policy := model.PolicyRoute{
		Name:     "via-fw",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
		},
		Action: model.RouteAction{
			Type: model.ActionReroute,
			NextHops: []netip.Addr{
				netip.MustParseAddr("10.10.0.254"),
			},
		},
	}
	routeTable := model.RouteTable{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("10.30.0.0/24"),
			NextHops: []netip.Addr{
				netip.MustParseAddr("10.10.0.253"),
			},
		}},
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router": {
			{Table: "Logical_Router", UUID: "lr-prod", ExternalIDs: map[string]string{
				"netloom_owner": "netloom",
				"netloom_vpc":   "prod",
			}, Fields: map[string]string{
				"name":          logicalRouter("prod"),
				"policies":      "",
				"static_routes": "",
			}},
		},
		"Logical_Router_Policy": {
			{Table: "Logical_Router_Policy", UUID: "policy-via-fw", ExternalIDs: map[string]string{
				"netloom_owner":        "netloom",
				"netloom_vpc":          "prod",
				"netloom_policy_route": "via-fw",
				"netloom_action":       "reroute",
			}, Fields: map[string]string{
				"priority": "100",
				"match":    policyRouteMatch(policy.Match),
				"action":   "reroute",
				"nexthop":  "10.10.0.254",
			}},
		},
		"Logical_Router_Static_Route": {
			{Table: "Logical_Router_Static_Route", UUID: "route-main", ExternalIDs: map[string]string{
				"netloom_owner":       "netloom",
				"netloom_vpc":         "prod",
				"netloom_route_table": "main",
				"netloom_route_key":   "10.30.0.0/24|10.10.0.253",
			}, Fields: map[string]string{
				"ip_prefix":        "10.30.0.0/24",
				"nexthop":          "10.10.0.253",
				"options":          "",
				"route_table":      "main",
				"selection_fields": "",
			}},
		},
	}}
	desired := topology.State{
		VPCs:         map[string]model.VPC{"prod": {Name: "prod"}},
		PolicyRoutes: []model.PolicyRoute{policy},
		RouteTables: map[string]model.RouteTable{
			"prod/main": routeTable,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 2 {
		t.Fatalf("router policy/static route attachment drift stats = %+v, want one router row with two drifted fields", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsDesiredDrift(t *testing.T) {
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Switch": {
			{Table: "Logical_Switch", UUID: "ls-apps", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod", "netloom_subnet": "apps"}},
			{Table: "Logical_Switch", UUID: "ls-old", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod", "netloom_subnet": "old"}},
		},
		"Logical_Router": {
			{Table: "Logical_Router", UUID: "lr-prod", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod"}},
		},
	}}
	desired := topology.State{
		VPCs: map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets: map[string]model.Subnet{
			"prod/apps": {Name: "apps", VPC: "prod"},
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.UnexpectedManagedRows != 1 {
		t.Fatalf("unexpected managed rows = %d, want stale logical switch", stats.UnexpectedManagedRows)
	}
	if stats.MissingManagedRows != 2 {
		t.Fatalf("missing managed rows = %d, want router and switch ports for subnet", stats.MissingManagedRows)
	}
}

func TestAuditManagedObjectsFromReaderReportsFieldDrift(t *testing.T) {
	endpointID := endpointExternalID("prod", "pod-a")
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Switch_Port": {
			{Table: "Logical_Switch_Port", UUID: "lsp-pod-a", ExternalIDs: map[string]string{
				"netloom_owner":    "netloom",
				"netloom_vpc":      "prod",
				"netloom_endpoint": endpointID,
				"netloom_node":     "node-old",
				"netloom_subnet":   "apps",
			}},
		},
	}}
	desired := topology.State{
		Subnets: map[string]model.Subnet{
			"prod/apps": {Name: "apps", VPC: "prod"},
		},
		Endpoints: map[string]model.Endpoint{
			"prod/pod-a": {ID: "pod-a", VPC: "prod", Subnet: "apps", Node: "node-a"},
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("field drift = rows %d fields %d, want one node drift", stats.DriftedManagedRows, stats.DriftedManagedFields)
	}
}

func TestAuditManagedObjectsFromReaderReportsStaleLogicalSwitchPortColumns(t *testing.T) {
	endpoint := model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		Node:   "node-a",
		IP:     netip.MustParseAddr("10.10.0.20"),
		MAC:    "02:00:00:00:00:20",
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Switch_Port": {
			{Table: "Logical_Switch_Port", UUID: "lsp-pod-a", ExternalIDs: map[string]string{
				"netloom_owner":    "netloom",
				"netloom_vpc":      "prod",
				"netloom_endpoint": endpointExternalID("prod", "pod-a"),
				"netloom_node":     "node-a",
				"netloom_subnet":   "apps",
			}, Fields: map[string]string{
				"name":           logicalPort("prod", "pod-a"),
				"addresses":      endpointAddress(endpoint),
				"port_security":  endpointAddress(endpoint),
				"type":           "localnet",
				"options":        "network_name=physnet-a",
				"tag":            "100",
				"dhcpv4_options": "4:10.10.0.0/24",
			}},
		},
	}}
	desired := topology.State{
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps"): {Name: "apps", VPC: "prod"},
		},
		Endpoints: map[string]model.Endpoint{
			"prod/pod-a": endpoint,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 4 {
		t.Fatalf("stale logical switch port column drift stats = %+v, want type/options/tag/dhcp drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsStaleEndpointPortSecurityColumn(t *testing.T) {
	endpoint := model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		Node:   "node-a",
		IP:     netip.MustParseAddr("10.10.0.20"),
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Switch_Port": {
			{Table: "Logical_Switch_Port", UUID: "lsp-pod-a", ExternalIDs: map[string]string{
				"netloom_owner":    "netloom",
				"netloom_vpc":      "prod",
				"netloom_endpoint": endpointExternalID("prod", "pod-a"),
				"netloom_node":     "node-a",
				"netloom_subnet":   "apps",
			}, Fields: map[string]string{
				"name":          logicalPort("prod", "pod-a"),
				"addresses":     endpointAddress(endpoint),
				"port_security": "02:00:00:00:00:20 10.10.0.20",
			}},
		},
	}}
	desired := topology.State{
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps"): {Name: "apps", VPC: "prod"},
		},
		Endpoints: map[string]model.Endpoint{
			"prod/pod-a": endpoint,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("stale endpoint port_security drift stats = %+v, want one field drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsStaleLoadBalancerColumns(t *testing.T) {
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
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Load_Balancer": {
			{Table: "Load_Balancer", UUID: "lb-api", ExternalIDs: map[string]string{
				"netloom_owner":            "netloom",
				"netloom_vpc":              "prod",
				"netloom_load_balancer":    "api",
				"netloom_protocol":         "tcp",
				"netloom_session_affinity": "false",
			}, Fields: map[string]string{
				"name":              loadBalancerProtocolName("prod", "api", model.ProtocolTCP),
				"vips":              "10.96.0.10:443=10.10.0.20:8443",
				"protocol":          "tcp",
				"selection_fields":  "",
				"options":           "affinity_timeout=7200",
				"health_check_vips": "10.96.0.10:443",
			}},
		},
	}}
	desired := topology.State{
		LoadBalancers: map[string]model.LoadBalancer{
			"prod/api": lb,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 2 {
		t.Fatalf("stale load balancer column drift stats = %+v, want options and health check attachment drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsStaticRouteColumnDrift(t *testing.T) {
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router_Static_Route": {
			{Table: "Logical_Router_Static_Route", UUID: "route-a", ExternalIDs: map[string]string{
				"netloom_owner":       "netloom",
				"netloom_vpc":         "prod",
				"netloom_route_table": "main",
				"netloom_route_key":   "10.20.0.0/24|10.10.0.253",
			}, Fields: map[string]string{
				"ip_prefix":   "10.20.0.0/24",
				"nexthop":     "10.10.0.99",
				"options":     "ecmp_symmetric_reply=true",
				"route_table": "legacy",
			}},
		},
	}}
	desired := topology.State{
		RouteTables: map[string]model.RouteTable{
			"prod/main": {
				Name: "main",
				VPC:  "prod",
				Routes: []model.Route{{
					Destination: netip.MustParsePrefix("10.20.0.0/24"),
					NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.253")},
				}},
			},
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.ManagedLogicalRouterStaticRoutes != 1 || stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 3 {
		t.Fatalf("static route audit stats = %+v, want nexthop/options/route-table column drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsCoreNameColumnDrift(t *testing.T) {
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
		IP:     netip.MustParseAddr("10.10.0.10"),
		Node:   "node-a",
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router": {
			{Table: "Logical_Router", UUID: "lr-prod", ExternalIDs: map[string]string{
				"netloom_owner": "netloom",
				"netloom_vpc":   "prod",
			}, Fields: map[string]string{
				"name":  "renamed-router",
				"ports": routerPortName(logicalRouter("prod"), "apps"),
			}},
		},
		"Logical_Switch": {
			{Table: "Logical_Switch", UUID: "ls-apps", ExternalIDs: map[string]string{
				"netloom_owner":  "netloom",
				"netloom_vpc":    "prod",
				"netloom_subnet": "apps",
			}, Fields: map[string]string{
				"name":         "renamed-switch",
				"other_config": mapField(logicalSwitchOtherConfig(subnet)),
				"ports":        stringSetField([]string{switchRouterPortName(logicalSwitch("prod", "apps"), "apps"), logicalPort("prod", "pod-a")}),
			}},
		},
		"Logical_Router_Port": {
			{Table: "Logical_Router_Port", UUID: "lrp-apps", ExternalIDs: map[string]string{
				"netloom_owner":  "netloom",
				"netloom_subnet": "apps",
			}, Fields: map[string]string{
				"name":     "renamed-router-port",
				"mac":      deterministicMAC(subnet),
				"networks": "10.10.0.1/24",
			}},
		},
		"Logical_Switch_Port": {
			{Table: "Logical_Switch_Port", UUID: "lsp-router", ExternalIDs: map[string]string{
				"netloom_owner":  "netloom",
				"netloom_subnet": "apps",
				"netloom_role":   "router",
			}, Fields: map[string]string{
				"name":      "renamed-switch-router-port",
				"type":      "router",
				"addresses": deterministicMAC(subnet),
				"options":   mapField(map[string]string{"router-port": routerPortName(logicalRouter("prod"), "apps")}),
			}},
			{Table: "Logical_Switch_Port", UUID: "lsp-pod-a", ExternalIDs: map[string]string{
				"netloom_owner":    "netloom",
				"netloom_vpc":      "prod",
				"netloom_endpoint": endpointExternalID("prod", "pod-a"),
				"netloom_node":     "node-a",
				"netloom_subnet":   "apps",
			}, Fields: map[string]string{
				"name":      "renamed-endpoint-port",
				"addresses": endpointAddress(endpoint),
			}},
		},
	}}
	desired := topology.State{
		VPCs: map[string]model.VPC{
			"prod": {Name: "prod"},
		},
		Subnets: map[string]model.Subnet{
			"prod/apps": subnet,
		},
		Endpoints: map[string]model.Endpoint{
			"prod/pod-a": endpoint,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 5 || stats.DriftedManagedFields != 5 {
		t.Fatalf("name column drift stats = %+v, want five drifted name fields", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsGatewayOptionsDrift(t *testing.T) {
	gateway := model.Gateway{
		Name:       "gw-a",
		VPC:        "prod",
		Node:       "node-a",
		ExternalIF: "eth0",
		LANIP:      netip.MustParseAddr("10.10.0.1"),
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router": {
			{Table: "Logical_Router", UUID: "lr-prod", ExternalIDs: map[string]string{
				"netloom_owner":               "netloom",
				"netloom_vpc":                 "prod",
				"netloom_gateway":             "gw-a",
				"netloom_external_if":         "eth0",
				"netloom_gateway_lan_ip":      "10.10.0.1",
				"netloom_gateway_distributed": "false",
			}, Fields: map[string]string{
				"name":    logicalRouter("prod"),
				"options": "chassis=node-b",
			}},
		},
	}}
	desired := topology.State{
		VPCs: map[string]model.VPC{
			"prod": {Name: "prod"},
		},
		Gateways: map[string]model.Gateway{
			"prod/gw-a": gateway,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("gateway options drift stats = %+v, want one chassis option drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsLoadBalancerHealthCheckAttachmentDrift(t *testing.T) {
	lb := model.LoadBalancer{
		Name:        "api",
		VPC:         "prod",
		VIP:         netip.MustParseAddr("10.96.0.10"),
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
		Ports: []model.LoadBalancerPort{{
			Port:     443,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.20"), Port: 8443}},
		}},
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router": {
			{Table: "Logical_Router", UUID: "lr-prod", ExternalIDs: map[string]string{
				"netloom_owner": "netloom",
				"netloom_vpc":   "prod",
			}, Fields: map[string]string{
				"name":           logicalRouter("prod"),
				"load_balancers": loadBalancerProtocolName("prod", "api", model.ProtocolTCP),
			}},
		},
		"Load_Balancer": {
			{Table: "Load_Balancer", UUID: "lb-api", ExternalIDs: map[string]string{
				"netloom_owner":            "netloom",
				"netloom_vpc":              "prod",
				"netloom_load_balancer":    "api",
				"netloom_protocol":         "tcp",
				"netloom_session_affinity": "false",
			}, Fields: map[string]string{
				"name":              loadBalancerProtocolName("prod", "api", model.ProtocolTCP),
				"vips":              "10.96.0.10:443=10.10.0.20:8443",
				"protocol":          "tcp",
				"selection_fields":  "",
				"health_check_vips": "",
			}},
		},
		"Load_Balancer_Health_Check": {
			{Table: "Load_Balancer_Health_Check", UUID: "hc-api", ExternalIDs: map[string]string{
				"netloom_owner":             "netloom",
				"netloom_vpc":               "prod",
				"netloom_load_balancer":     "api",
				"netloom_ovn_load_balancer": loadBalancerProtocolName("prod", "api", model.ProtocolTCP),
			}, Fields: map[string]string{
				"vip":     "10.96.0.10:443",
				"options": "failure_count=3,interval=5,success_count=3,timeout=20",
			}},
		},
	}}
	desired := topology.State{
		VPCs: map[string]model.VPC{"prod": {Name: "prod"}},
		LoadBalancers: map[string]model.LoadBalancer{
			"prod/api": lb,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("load balancer health check attachment drift stats = %+v, want one drifted attachment field", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsLoadBalancerHealthCheckMetadataDrift(t *testing.T) {
	lb := model.LoadBalancer{
		Name:        "api",
		VPC:         "prod",
		VIP:         netip.MustParseAddr("10.96.0.10"),
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
		Ports: []model.LoadBalancerPort{{
			Port:     443,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.20"), Port: 8443}},
		}},
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Load_Balancer_Health_Check": {
			{Table: "Load_Balancer_Health_Check", UUID: "hc-api", ExternalIDs: map[string]string{
				"netloom_owner":             "netloom",
				"netloom_vpc":               "prod",
				"netloom_load_balancer":     "api",
				"netloom_ovn_load_balancer": loadBalancerProtocolName("prod", "api", model.ProtocolUDP),
			}, Fields: map[string]string{
				"vip":     "10.96.0.10:443",
				"options": "failure_count=3,interval=5,success_count=3,timeout=20",
			}},
		},
	}}
	desired := topology.State{
		LoadBalancers: map[string]model.LoadBalancer{
			"prod/api": lb,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("load balancer health check metadata drift stats = %+v, want one ovn load balancer external_id drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsDHCPOptionAttachmentDrift(t *testing.T) {
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
		MAC:    "02:00:00:00:00:20",
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Switch_Port": {
			{Table: "Logical_Switch_Port", UUID: "lsp-pod-a", ExternalIDs: map[string]string{
				"netloom_owner":    "netloom",
				"netloom_vpc":      "prod",
				"netloom_endpoint": endpointExternalID("prod", "pod-a"),
				"netloom_node":     "node-a",
				"netloom_subnet":   "apps",
			}, Fields: map[string]string{
				"name":           logicalPort("prod", "pod-a"),
				"addresses":      endpointAddress(endpoint),
				"port_security":  endpointAddress(endpoint),
				"dhcpv4_options": "",
				"dhcpv6_options": "",
			}},
		},
		"DHCP_Options": {
			{Table: "DHCP_Options", UUID: "dhcp-pod-a", ExternalIDs: map[string]string{
				"netloom_owner":       "netloom",
				"netloom_vpc":         "prod",
				"netloom_endpoint":    endpointExternalID("prod", "pod-a"),
				"netloom_subnet":      "apps",
				"netloom_dhcp_family": "4",
			}, Fields: map[string]string{
				"cidr": "10.10.0.0/24",
			}},
		},
	}}
	desired := topology.State{
		VPCs: map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps"): subnet,
		},
		Endpoints: map[string]model.Endpoint{
			"prod/pod-a": endpoint,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("DHCP option attachment drift stats = %+v, want one endpoint attachment field drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsDHCPOptionFamilyMetadataDrift(t *testing.T) {
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
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"DHCP_Options": {
			{Table: "DHCP_Options", UUID: "dhcp-pod-a", ExternalIDs: map[string]string{
				"netloom_owner":       "netloom",
				"netloom_vpc":         "prod",
				"netloom_endpoint":    endpointExternalID("prod", "pod-a"),
				"netloom_subnet":      "apps",
				"netloom_dhcp_family": "6",
			}, Fields: map[string]string{
				"cidr":    "10.10.0.0/24",
				"options": "",
			}},
		},
	}}
	desired := topology.State{
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps"): subnet,
		},
		Endpoints: map[string]model.Endpoint{
			"prod/pod-a": endpoint,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("DHCP option family metadata drift stats = %+v, want one family external_id drift", stats)
	}
}

func TestAuditStatsTotalManagedObjects(t *testing.T) {
	stats := AuditStats{
		ManagedLogicalSwitches:           1,
		ManagedLogicalRouters:            1,
		ManagedLogicalSwitchPorts:        2,
		ManagedLogicalRouterPorts:        1,
		ManagedLogicalRouterPolicies:     3,
		ManagedLogicalRouterStaticRoutes: 5,
		ManagedBFDs:                      2,
		ManagedNATRules:                  2,
		ManagedLoadBalancers:             1,
		ManagedLoadBalancerHealthChecks:  2,
		ManagedDHCPOptions:               4,
	}

	if got := stats.TotalManagedObjects(); got != 24 {
		t.Fatalf("total managed objects = %d, want 24", got)
	}
}

type fakeManagedOVNReader struct {
	rows map[string][]ManagedOVNRow
}

func (r fakeManagedOVNReader) ManagedOVNRows(_ context.Context, table string) ([]ManagedOVNRow, error) {
	return append([]ManagedOVNRow(nil), r.rows[table]...), nil
}
