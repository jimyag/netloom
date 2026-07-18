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
  *"--columns=_uuid,external_ids,name,other_config,ports,load_balancers,dns_records,acls,forwarding_groups,load_balancer_group,qos_rules find Logical_Switch external_ids:netloom_owner=netloom"*) printf 'ls-a,"{netloom_owner=netloom,netloom_vpc=prod,netloom_subnet=apps}",nl_ls_prod_apps,"{mcast_snoop=false,subnet=10.10.0.0/24}",[],[],[],[],[],[],[]\n' ;;
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
	if !strings.Contains(string(logData), "--columns=_uuid,external_ids,name,other_config,ports,load_balancers,dns_records,acls,forwarding_groups,load_balancer_group,qos_rules") {
		t.Fatalf("audit command did not request switch columns:\n%s", string(logData))
	}
}

func TestNBCTLExecutorManagedOVNRowsResolvesLoadBalancerHealthChecks(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "args.log")
	binary := filepath.Join(tmp, "ovn-nbctl")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + logPath + `"
case "$*" in
  *"--columns=_uuid,external_ids,name,vips,protocol,options,ip_port_mappings,selection_fields,health_check find Load_Balancer external_ids:netloom_owner=netloom"*) printf 'lb-api,"{netloom_owner=netloom,netloom_vpc=prod,netloom_load_balancer=api,netloom_protocol=tcp}",nl_lb_prod_api_tcp,"{10.96.0.10:443=10.10.0.20:8443}",tcp,{},{},[],[hc-api]\n' ;;
  *"--columns=_uuid,external_ids,vip find Load_Balancer_Health_Check external_ids:netloom_owner=netloom"*) printf 'hc-api,"{netloom_owner=netloom,netloom_vpc=prod,netloom_load_balancer=api}",10.96.0.10:443\n' ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	rows, err := executor.ManagedOVNRows(context.Background(), "Load_Balancer")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.Fields["health_check_vips"] != "10.96.0.10:443" {
		t.Fatalf("row fields = %+v, want health check UUID resolved to VIP", row.Fields)
	}
	if row.Fields["ip_port_mappings"] != "{}" {
		t.Fatalf("row fields = %+v, want empty ip_port_mappings field", row.Fields)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logged := string(logData)
	for _, expected := range []string{
		"--columns=_uuid,external_ids,name,vips,protocol,options,ip_port_mappings,selection_fields,health_check",
		"--columns=_uuid,external_ids,vip find Load_Balancer_Health_Check",
	} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("audit command log missing %q:\n%s", expected, logged)
		}
	}
}

func TestNBCTLExecutorAuditCountsMalformedReferenceRowsWithoutPanic(t *testing.T) {
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "ovn-nbctl")
	script := `#!/bin/sh
case "$*" in
  *"find Logical_Router external_ids:netloom_owner=netloom"*) printf '"unterminated-router-row\n' ;;
  *"find Logical_Switch external_ids:netloom_owner=netloom"*) printf '"unterminated-switch-row\n' ;;
  *"find Load_Balancer external_ids:netloom_owner=netloom"*) printf '"unterminated-lb-row\n' ;;
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
	if stats.IncompleteManagedRows != 3 {
		t.Fatalf("stats = %+v, want malformed reference rows counted as incomplete", stats)
	}
}

func TestNBCTLExecutorManagedOVNRowsResolvesLogicalRouterReferences(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "args.log")
	binary := filepath.Join(tmp, "ovn-nbctl")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + logPath + `"
case "$*" in
  *"--columns=_uuid,external_ids,name,options,ports,load_balancers,load_balancer_group,nat,policies,static_routes,enabled find Logical_Router external_ids:netloom_owner=netloom"*) printf 'lr-prod,"{netloom_owner=netloom,netloom_vpc=prod}",nl_lr_prod,"{}",[lrp-apps],[lb-api],[],[nat-egress],[policy-via-fw],[route-main],[]\n' ;;
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
		"--columns=_uuid,external_ids,name,options,ports,load_balancers,load_balancer_group,nat,policies,static_routes,enabled",
		"find Logical_Router_Port external_ids:netloom_owner=netloom",
		"find NAT external_ids:netloom_owner=netloom",
		"find Logical_Router_Static_Route external_ids:netloom_owner=netloom",
	} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("audit command log missing %q:\n%s", expected, logged)
		}
	}
}

func TestNBCTLExecutorManagedOVNRowsResolvesSwitchPortDHCPOptions(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "args.log")
	binary := filepath.Join(tmp, "ovn-nbctl")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + logPath + `"
case "$*" in
  *"--columns=_uuid,external_ids,name,type,addresses,port_security,options,tag,tag_request,enabled,ha_chassis_group,mirror_rules,parent_name,peer,dhcpv4_options,dhcpv6_options find Logical_Switch_Port external_ids:netloom_owner=netloom"*) printf 'lsp-pod-a,"{netloom_owner=netloom,netloom_vpc=prod,netloom_endpoint=prod/pod-a}",nl_lp_prod_pod-a,,02:00:00:00:00:20,,{},[],[],true,[],[],[],[],dhcp-v4,[]\n' ;;
  *"--columns=_uuid,external_ids,cidr find DHCP_Options external_ids:netloom_owner=netloom"*) printf 'dhcp-v4,"{netloom_owner=netloom,netloom_dhcp_family=4}",10.10.0.0/24\n' ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	rows, err := executor.ManagedOVNRows(context.Background(), "Logical_Switch_Port")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].Fields["dhcpv4_options"] != "4:10.10.0.0/24" || rows[0].Fields["dhcpv6_options"] != "" {
		t.Fatalf("row fields = %+v, want resolved DHCP option refs", rows[0].Fields)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logged := string(logData)
	for _, expected := range []string{
		"--columns=_uuid,external_ids,name,type,addresses,port_security,options,tag,tag_request,enabled,ha_chassis_group,mirror_rules,parent_name,peer,dhcpv4_options,dhcpv6_options",
		"--columns=_uuid,external_ids,cidr find DHCP_Options",
	} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("audit command log missing %q:\n%s", expected, logged)
		}
	}
}

func TestNBCTLExecutorManagedOVNRowsResolvesStaticRouteBFD(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "args.log")
	binary := filepath.Join(tmp, "ovn-nbctl")
	routeKey := staticRouteKey("10.20.0.0/24", "10.10.0.253")
	bfdRef := staticRouteBFDRef("prod", "main", routeKey)
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + logPath + `"
case "$*" in
  *"--columns=_uuid,external_ids,bfd,ip_prefix,nexthop,options,output_port,policy,route_table,selection_fields find Logical_Router_Static_Route external_ids:netloom_owner=netloom"*) printf 'route-main,"{netloom_owner=netloom,netloom_vpc=prod,netloom_route_table=main,netloom_route_key=` + routeKey + `}",bfd-main,10.20.0.0/24,10.10.0.253,{},[],dst-ip,main,[]\n' ;;
  *"--columns=_uuid,external_ids find BFD external_ids:netloom_owner=netloom"*) printf 'bfd-main,"{netloom_owner=netloom,netloom_vpc=prod,netloom_route_table=main,netloom_route_key=` + routeKey + `,netloom_route_bfd=` + bfdRef + `}"\n' ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	rows, err := executor.ManagedOVNRows(context.Background(), "Logical_Router_Static_Route")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].Fields["bfd"] != bfdRef {
		t.Fatalf("row fields = %+v, want BFD UUID resolved to %q", rows[0].Fields, bfdRef)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logged := string(logData)
	for _, expected := range []string{
		"--columns=_uuid,external_ids,bfd,ip_prefix,nexthop,options,output_port,policy,route_table,selection_fields",
		"--columns=_uuid,external_ids find BFD",
	} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("audit command log missing %q:\n%s", expected, logged)
		}
	}
}

func TestNBCTLExecutorManagedOVNRowsReportsMissingStaticRouteBFD(t *testing.T) {
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "ovn-nbctl")
	routeKey := staticRouteKey("10.20.0.0/24", "10.10.0.253")
	script := `#!/bin/sh
case "$*" in
  *"find Logical_Router_Static_Route external_ids:netloom_owner=netloom"*) printf 'route-main,"{netloom_owner=netloom,netloom_vpc=prod,netloom_route_table=main,netloom_route_key=` + routeKey + `}",[],10.20.0.0/24,10.10.0.253,{},[],dst-ip,main,[]\n' ;;
  *"find BFD external_ids:netloom_owner=netloom"*) ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	rows, err := executor.ManagedOVNRows(context.Background(), "Logical_Router_Static_Route")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if value, ok := rows[0].Fields["bfd"]; !ok || value != "" {
		t.Fatalf("row fields = %+v, want explicit empty BFD attachment", rows[0].Fields)
	}
}

func TestNBCTLExecutorManagedOVNRowsReportsMissingSwitchPortDHCPOptions(t *testing.T) {
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "ovn-nbctl")
	script := `#!/bin/sh
case "$*" in
  *"find Logical_Switch_Port external_ids:netloom_owner=netloom"*) printf 'lsp-pod-a,"{netloom_owner=netloom,netloom_vpc=prod,netloom_endpoint=prod/pod-a}",nl_lp_prod_pod-a,,10.10.0.20,,{},[],[],true,[],[],[],[],[],[]\n' ;;
  *"find DHCP_Options external_ids:netloom_owner=netloom"*) printf 'dhcp-v4,"{netloom_owner=netloom,netloom_dhcp_family=4}",10.10.0.0/24\n' ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	rows, err := executor.ManagedOVNRows(context.Background(), "Logical_Switch_Port")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if value, ok := rows[0].Fields["dhcpv4_options"]; !ok || value != "" {
		t.Fatalf("row fields = %+v, want explicit empty DHCPv4 option attachment", rows[0].Fields)
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
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 2 {
		t.Fatalf("stats = %+v, want switch name and port attachment drift from nbctl rows", stats)
	}
}

func TestAuditManagedObjectsFromNBCTLNormalizesDNSRecords(t *testing.T) {
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "ovn-nbctl")
	script := `#!/bin/sh
case "$*" in
  *"find DNS external_ids:netloom_owner=netloom"*) printf 'dns-a,"{netloom_owner=netloom,netloom_dns=desired}","{api.example.com=10.10.0.20 10.10.0.21}",{}\n' ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	desired := topology.State{
		DNSRecords: []model.DNSRecord{{
			Name: "api.example.com",
			IPs: []netip.Addr{
				netip.MustParseAddr("10.10.0.21"),
				netip.MustParseAddr("10.10.0.20"),
			},
		}},
	}

	executor := NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), executor, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.ManagedDNSRecords != 1 || stats.MissingManagedRows != 0 || stats.DriftedManagedRows != 0 || stats.DriftedManagedFields != 0 {
		t.Fatalf("stats = %+v, want matching DNS records without drift", stats)
	}
}

func TestAuditManagedObjectsFromNBCTLReportsDNSRecordDrift(t *testing.T) {
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "ovn-nbctl")
	script := `#!/bin/sh
case "$*" in
  *"find DNS external_ids:netloom_owner=netloom"*) printf 'dns-a,"{netloom_owner=netloom,netloom_dns=desired}","{api.example.com=10.10.0.99}",{}\n' ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	desired := topology.State{
		DNSRecords: []model.DNSRecord{{
			Name: "api.example.com",
			IPs:  []netip.Addr{netip.MustParseAddr("10.10.0.20")},
		}},
	}

	executor := NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), executor, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.ManagedDNSRecords != 1 || stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("stats = %+v, want one DNS records field drift", stats)
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
		{Table: "Logical_Switch_Port", UUID: "uuid-router", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod", "netloom_subnet": "apps", "netloom_role": "router"}},
		{Table: "Logical_Switch_Port", UUID: "uuid-localnet", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod", "netloom_subnet": "apps", "netloom_provider_network": "physnet-a"}},
	}

	result := auditManagedRows("Logical_Switch_Port", rows)
	if result.count != 2 || result.incomplete != 0 || result.duplicates != 0 {
		t.Fatalf("logical switch port audit = %+v, want two complete unique managed ports", result)
	}
}

func TestAuditManagedObjectsFromReaderReportsStaleRouterAndLocalnetEndpointMetadata(t *testing.T) {
	subnet := model.Subnet{
		Name:            "apps",
		VPC:             "prod",
		CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
		Gateway:         netip.MustParseAddr("10.10.0.1"),
		ProviderNetwork: "physnet-a",
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Switch_Port": {
			{Table: "Logical_Switch_Port", UUID: "lsp-router", ExternalIDs: map[string]string{
				"netloom_owner":    "netloom",
				"netloom_vpc":      "prod",
				"netloom_subnet":   "apps",
				"netloom_role":     "router",
				"netloom_endpoint": "prod/old-pod",
				"netloom_node":     "node-a",
			}, Fields: map[string]string{
				"name":      switchRouterPortName(logicalSwitch("prod", "apps"), "apps"),
				"type":      "router",
				"addresses": deterministicMAC(subnet),
				"options":   mapField(map[string]string{"router-port": routerPortName(logicalRouter("prod"), "apps")}),
			}},
			{Table: "Logical_Switch_Port", UUID: "lsp-localnet", ExternalIDs: map[string]string{
				"netloom_owner":            "netloom",
				"netloom_vpc":              "prod",
				"netloom_subnet":           "apps",
				"netloom_provider_network": "physnet-a",
				"netloom_endpoint":         "prod/old-pod",
				"netloom_node":             "node-a",
			}, Fields: map[string]string{
				"name":      localnetPortName(logicalSwitch("prod", "apps"), "apps"),
				"type":      "localnet",
				"addresses": "unknown",
				"options":   mapField(map[string]string{"network_name": "physnet-a"}),
			}},
		},
	}}
	desired := topology.State{
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps"): subnet,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 2 || stats.DriftedManagedFields != 4 {
		t.Fatalf("stale router/localnet endpoint metadata drift stats = %+v, want endpoint/node drift on both ports", stats)
	}
	if got := stats.DriftedManagedFieldCounts["Logical_Switch_Port.external_ids.netloom_endpoint"]; got != 2 {
		t.Fatalf("field drift counts = %+v, want stale endpoint metadata drift on router and localnet ports", stats.DriftedManagedFieldCounts)
	}
	if got := stats.DriftedManagedFieldCounts["Logical_Switch_Port.external_ids.netloom_node"]; got != 2 {
		t.Fatalf("field drift counts = %+v, want stale node metadata drift on router and localnet ports", stats.DriftedManagedFieldCounts)
	}
}

func TestAuditManagedObjectsScopesSubnetPortsByVPC(t *testing.T) {
	prodSubnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}
	devSubnet := model.Subnet{
		Name:    "apps",
		VPC:     "dev",
		CIDR:    netip.MustParsePrefix("10.20.0.0/24"),
		Gateway: netip.MustParseAddr("10.20.0.1"),
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router": {
			{Table: "Logical_Router", UUID: "lr-prod", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod"}, Fields: map[string]string{
				"name":  logicalRouter("prod"),
				"ports": routerPortName(logicalRouter("prod"), "apps"),
			}},
			{Table: "Logical_Router", UUID: "lr-dev", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "dev"}, Fields: map[string]string{
				"name":  logicalRouter("dev"),
				"ports": routerPortName(logicalRouter("dev"), "apps"),
			}},
		},
		"Logical_Switch": {
			{Table: "Logical_Switch", UUID: "ls-prod-apps", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod", "netloom_subnet": "apps"}, Fields: map[string]string{
				"name":         logicalSwitch("prod", "apps"),
				"other_config": mapField(logicalSwitchOtherConfig(prodSubnet)),
				"ports":        switchRouterPortName(logicalSwitch("prod", "apps"), "apps"),
			}},
			{Table: "Logical_Switch", UUID: "ls-dev-apps", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "dev", "netloom_subnet": "apps"}, Fields: map[string]string{
				"name":         logicalSwitch("dev", "apps"),
				"other_config": mapField(logicalSwitchOtherConfig(devSubnet)),
				"ports":        switchRouterPortName(logicalSwitch("dev", "apps"), "apps"),
			}},
		},
		"Logical_Router_Port": {
			{Table: "Logical_Router_Port", UUID: "lrp-prod-apps", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod", "netloom_subnet": "apps"}, Fields: map[string]string{
				"name":     routerPortName(logicalRouter("prod"), "apps"),
				"mac":      deterministicMAC(prodSubnet),
				"networks": "10.10.0.1/24",
			}},
			{Table: "Logical_Router_Port", UUID: "lrp-dev-apps", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "dev", "netloom_subnet": "apps"}, Fields: map[string]string{
				"name":     routerPortName(logicalRouter("dev"), "apps"),
				"mac":      deterministicMAC(devSubnet),
				"networks": "10.20.0.1/24",
			}},
		},
		"Logical_Switch_Port": {
			{Table: "Logical_Switch_Port", UUID: "lsp-prod-router", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "prod", "netloom_subnet": "apps", "netloom_role": "router"}, Fields: map[string]string{
				"name":      switchRouterPortName(logicalSwitch("prod", "apps"), "apps"),
				"type":      "router",
				"addresses": deterministicMAC(prodSubnet),
				"options":   mapField(map[string]string{"router-port": routerPortName(logicalRouter("prod"), "apps")}),
			}},
			{Table: "Logical_Switch_Port", UUID: "lsp-dev-router", ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": "dev", "netloom_subnet": "apps", "netloom_role": "router"}, Fields: map[string]string{
				"name":      switchRouterPortName(logicalSwitch("dev", "apps"), "apps"),
				"type":      "router",
				"addresses": deterministicMAC(devSubnet),
				"options":   mapField(map[string]string{"router-port": routerPortName(logicalRouter("dev"), "apps")}),
			}},
		},
	}}
	desired := topology.State{
		VPCs: map[string]model.VPC{"prod": {Name: "prod"}, "dev": {Name: "dev"}},
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps"): prodSubnet,
			subnetStateKey("dev", "apps"):  devSubnet,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DuplicateManagedRows != 0 || stats.IncompleteManagedRows != 0 || stats.MissingManagedRows != 0 || stats.UnexpectedManagedRows != 0 || stats.DriftedManagedRows != 0 {
		t.Fatalf("same-subnet-name audit stats = %+v, want no duplicate/missing/drift", stats)
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
	if stats.DuplicateManagedTableCounts["Logical_Router_Policy"] != 1 ||
		stats.IncompleteManagedTableCounts["Load_Balancer"] != 1 {
		t.Fatalf("table counts = duplicate %+v incomplete %+v, want policy duplicate and load balancer incomplete", stats.DuplicateManagedTableCounts, stats.IncompleteManagedTableCounts)
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

func TestAuditManagedObjectsFromReaderReportsPolicyRouteStaleNextHopDrift(t *testing.T) {
	route := model.PolicyRoute{
		Name:     "drop-api",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
		},
		Action: model.RouteAction{Type: model.ActionDrop},
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router_Policy": {
			{Table: "Logical_Router_Policy", UUID: "policy-drop-api", ExternalIDs: map[string]string{
				"netloom_owner":        "netloom",
				"netloom_vpc":          "prod",
				"netloom_policy_route": "drop-api",
				"netloom_action":       "drop",
			}, Fields: map[string]string{
				"priority": "100",
				"match":    policyRouteMatch(route.Match),
				"action":   "drop",
				"nexthop":  "10.10.0.253",
			}},
		},
	}}
	desired := topology.State{PolicyRoutes: []model.PolicyRoute{route}}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("stats = %+v, want one stale policy route nexthop column drift", stats)
	}
	if got := stats.DriftedManagedFieldCounts["Logical_Router_Policy.nexthop"]; got != 1 {
		t.Fatalf("field drift counts = %+v, want policy route nexthop drift", stats.DriftedManagedFieldCounts)
	}
}

func TestAuditManagedObjectsFromReaderReportsPolicyRouteStaleBFDSessionsDrift(t *testing.T) {
	route := model.PolicyRoute{
		Name:     "drop-api",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
		},
		Action: model.RouteAction{Type: model.ActionDrop},
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router_Policy": {
			{Table: "Logical_Router_Policy", UUID: "policy-drop-api", ExternalIDs: map[string]string{
				"netloom_owner":        "netloom",
				"netloom_vpc":          "prod",
				"netloom_policy_route": "drop-api",
				"netloom_action":       "drop",
			}, Fields: map[string]string{
				"priority":     "100",
				"match":        policyRouteMatch(route.Match),
				"action":       "drop",
				"bfd_sessions": "bfd-stale",
			}},
		},
	}}
	desired := topology.State{PolicyRoutes: []model.PolicyRoute{route}}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("stats = %+v, want one stale policy route bfd_sessions column drift", stats)
	}
	if got := stats.DriftedManagedFieldCounts["Logical_Router_Policy.bfd_sessions"]; got != 1 {
		t.Fatalf("field drift counts = %+v, want policy route bfd_sessions drift", stats.DriftedManagedFieldCounts)
	}
}

func TestAuditManagedObjectsFromReaderReportsPolicyRouteStaleSemanticColumnsDrift(t *testing.T) {
	route := model.PolicyRoute{
		Name:     "drop-api",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Destination: netip.MustParsePrefix("10.20.0.0/24"),
		},
		Action: model.RouteAction{Type: model.ActionDrop},
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router_Policy": {
			{Table: "Logical_Router_Policy", UUID: "policy-drop-api", ExternalIDs: map[string]string{
				"netloom_owner":        "netloom",
				"netloom_vpc":          "prod",
				"netloom_policy_route": "drop-api",
				"netloom_action":       "drop",
			}, Fields: map[string]string{
				"priority":   "100",
				"match":      policyRouteMatch(route.Match),
				"action":     "drop",
				"options":    "pkt_mark=1",
				"chain":      "stale-chain",
				"jump_chain": "stale-jump-chain",
			}},
		},
	}}
	desired := topology.State{PolicyRoutes: []model.PolicyRoute{route}}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 3 {
		t.Fatalf("stats = %+v, want stale policy route options/chain/jump_chain drift", stats)
	}
	for _, field := range []string{"Logical_Router_Policy.options", "Logical_Router_Policy.chain", "Logical_Router_Policy.jump_chain"} {
		if got := stats.DriftedManagedFieldCounts[field]; got != 1 {
			t.Fatalf("field drift counts = %+v, want %s drift", stats.DriftedManagedFieldCounts, field)
		}
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
				"netloom_vpc":    "prod",
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
				"netloom_vpc":    "prod",
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
				"netloom_vpc":    "prod",
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
				"netloom_vpc":    "prod",
				"netloom_subnet": "apps",
				"netloom_role":   "router",
			}, Fields: map[string]string{
				"name":      switchRouterPortName(logicalSwitch("prod", "apps"), "apps"),
				"type":      "router",
				"addresses": deterministicMAC(subnet),
				"options":   mapField(map[string]string{"router-port": routerPortName(logicalRouter("prod"), "apps")}),
			}},
			{Table: "Logical_Switch_Port", UUID: "lsp-pod-a", ExternalIDs: map[string]string{
				"netloom_owner":            "netloom",
				"netloom_vpc":              "prod",
				"netloom_endpoint":         endpointExternalID("prod", "pod-a"),
				"netloom_node":             "node-a",
				"netloom_role":             "router",
				"netloom_provider_network": "physnet-a",
				"netloom_subnet":           "apps",
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
	if stats.DriftedManagedRows != 3 || stats.DriftedManagedFields != 4 {
		t.Fatalf("router/switch port attachment drift stats = %+v, want router, switch port, and endpoint role/provider drift", stats)
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
				"netloom_vpc":    "prod",
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
				"allowed_ext_ips":     "addrset-allowed",
				"exempted_ext_ips":    "addrset-exempted",
				"gateway_port":        "lrp-old",
				"match":               "ip4.src == 10.10.0.0/24",
				"priority":            "100",
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
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 10 {
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
	if got := stats.UnexpectedManagedTableCounts["Logical_Switch"]; got != 1 {
		t.Fatalf("unexpected table counts = %+v, want one logical switch", stats.UnexpectedManagedTableCounts)
	}
	if stats.MissingManagedTableCounts["Logical_Router_Port"] != 1 ||
		stats.MissingManagedTableCounts["Logical_Switch_Port"] != 1 {
		t.Fatalf("missing table counts = %+v, want router and switch ports for subnet", stats.MissingManagedTableCounts)
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
	if got := stats.DriftedManagedFieldCounts["Logical_Switch_Port.external_ids.netloom_node"]; got != 1 {
		t.Fatalf("field drift counts = %+v, want logical switch port netloom_node drift", stats.DriftedManagedFieldCounts)
	}
}

func TestAuditManagedObjectsFromReaderReportsStaleLogicalRouterOptions(t *testing.T) {
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router": {
			{Table: "Logical_Router", UUID: "lr-prod", ExternalIDs: map[string]string{
				"netloom_owner": "netloom",
				"netloom_vpc":   "prod",
			}, Fields: map[string]string{
				"name":                logicalRouter("prod"),
				"options":             "chassis=node-old",
				"load_balancer_group": "lbg-old",
			}},
		},
	}}
	desired := topology.State{
		VPCs: map[string]model.VPC{"prod": {Name: "prod"}},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 2 {
		t.Fatalf("stale router options drift stats = %+v, want two field drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsStaleLogicalSwitchReferences(t *testing.T) {
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Switch": {
			{Table: "Logical_Switch", UUID: "ls-apps", ExternalIDs: map[string]string{
				"netloom_owner":  "netloom",
				"netloom_vpc":    "prod",
				"netloom_subnet": "apps",
			}, Fields: map[string]string{
				"name":                logicalSwitch("prod", "apps"),
				"other_config":        mapField(logicalSwitchOtherConfig(subnet)),
				"acls":                "acl-old",
				"forwarding_groups":   "fg-old",
				"load_balancer_group": "lbg-old",
				"qos_rules":           "qos-old",
			}},
		},
	}}
	desired := topology.State{
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps"): subnet,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 4 {
		t.Fatalf("stale logical switch reference drift stats = %+v, want four field drift", stats)
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
				"netloom_owner":            "netloom",
				"netloom_vpc":              "prod",
				"netloom_endpoint":         endpointExternalID("prod", "pod-a"),
				"netloom_node":             "node-a",
				"netloom_role":             "router",
				"netloom_provider_network": "physnet-a",
				"netloom_subnet":           "apps",
			}, Fields: map[string]string{
				"name":             logicalPort("prod", "pod-a"),
				"addresses":        endpointAddress(endpoint),
				"port_security":    endpointAddress(endpoint),
				"type":             "localnet",
				"options":          "network_name=physnet-a",
				"tag":              "100",
				"tag_request":      "4094",
				"ha_chassis_group": "ha-old",
				"mirror_rules":     "mirror-old",
				"parent_name":      "parent-old",
				"peer":             "peer-old",
				"dhcpv4_options":   "4:10.10.0.0/24",
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
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 11 {
		t.Fatalf("stale logical switch port column drift stats = %+v, want role/provider/type/options/tag/tag_request/ha_chassis_group/mirror/parent/peer/dhcp drift", stats)
	}
	if got := stats.DriftedManagedFieldCounts["Logical_Switch_Port.external_ids.netloom_role"]; got != 1 {
		t.Fatalf("field drift counts = %+v, want stale endpoint role external_id drift", stats.DriftedManagedFieldCounts)
	}
	if got := stats.DriftedManagedFieldCounts["Logical_Switch_Port.external_ids.netloom_provider_network"]; got != 1 {
		t.Fatalf("field drift counts = %+v, want stale endpoint provider external_id drift", stats.DriftedManagedFieldCounts)
	}
	if got := stats.DriftedManagedFieldCounts["Logical_Switch_Port.mirror_rules"]; got != 1 {
		t.Fatalf("field drift counts = %+v, want stale endpoint mirror_rules drift", stats.DriftedManagedFieldCounts)
	}
	if got := stats.DriftedManagedFieldCounts["Logical_Switch_Port.tag_request"]; got != 1 {
		t.Fatalf("field drift counts = %+v, want stale endpoint tag_request drift", stats.DriftedManagedFieldCounts)
	}
	if got := stats.DriftedManagedFieldCounts["Logical_Switch_Port.parent_name"]; got != 1 {
		t.Fatalf("field drift counts = %+v, want stale endpoint parent_name drift", stats.DriftedManagedFieldCounts)
	}
	if got := stats.DriftedManagedFieldCounts["Logical_Switch_Port.peer"]; got != 1 {
		t.Fatalf("field drift counts = %+v, want stale endpoint peer drift", stats.DriftedManagedFieldCounts)
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

func TestAuditManagedObjectsFromReaderReportsDisabledEndpointLogicalSwitchPort(t *testing.T) {
	endpoint := model.Endpoint{
		ID:     "pod-a",
		VPC:    "prod",
		Subnet: "apps",
		Node:   "node-a",
		IP:     netip.MustParseAddr("10.10.0.20"),
	}
	desired := topology.State{
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps"): {Name: "apps", VPC: "prod"},
		},
		Endpoints: map[string]model.Endpoint{
			"prod/pod-a": endpoint,
		},
	}
	baseRow := ManagedOVNRow{Table: "Logical_Switch_Port", UUID: "lsp-pod-a", ExternalIDs: map[string]string{
		"netloom_owner":    "netloom",
		"netloom_vpc":      "prod",
		"netloom_endpoint": endpointExternalID("prod", "pod-a"),
		"netloom_node":     "node-a",
		"netloom_subnet":   "apps",
	}, Fields: map[string]string{
		"name":      logicalPort("prod", "pod-a"),
		"addresses": endpointAddress(endpoint),
	}}

	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Switch_Port": {baseRow},
	}}
	reader.rows["Logical_Switch_Port"][0].Fields["enabled"] = "true"
	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 0 || stats.DriftedManagedFields != 0 {
		t.Fatalf("enabled=true drift stats = %+v, want no drift", stats)
	}

	reader.rows["Logical_Switch_Port"][0].Fields["enabled"] = "false"
	stats, err = AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 1 {
		t.Fatalf("enabled=false drift stats = %+v, want one field drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsDisabledLogicalRouterAndRouterPort(t *testing.T) {
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}
	desired := topology.State{
		VPCs: map[string]model.VPC{
			"prod": {Name: "prod"},
		},
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps"): subnet,
		},
	}
	routerRow := ManagedOVNRow{Table: "Logical_Router", UUID: "lr-prod", ExternalIDs: map[string]string{
		"netloom_owner": "netloom",
		"netloom_vpc":   "prod",
	}, Fields: map[string]string{
		"name": logicalRouter("prod"),
	}}
	routerPortRow := ManagedOVNRow{Table: "Logical_Router_Port", UUID: "lrp-apps", ExternalIDs: map[string]string{
		"netloom_owner":  "netloom",
		"netloom_vpc":    "prod",
		"netloom_subnet": "apps",
	}, Fields: map[string]string{
		"name":            routerPortName(logicalRouter("prod"), "apps"),
		"mac":             deterministicMAC(subnet),
		"networks":        "10.10.0.1/24",
		"ipv6_ra_configs": "",
	}}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router":      {routerRow},
		"Logical_Router_Port": {routerPortRow},
	}}
	reader.rows["Logical_Router"][0].Fields["enabled"] = "true"
	reader.rows["Logical_Router_Port"][0].Fields["enabled"] = "true"
	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 0 || stats.DriftedManagedFields != 0 {
		t.Fatalf("enabled=true drift stats = %+v, want no drift", stats)
	}

	reader.rows["Logical_Router"][0].Fields["enabled"] = "false"
	reader.rows["Logical_Router_Port"][0].Fields["enabled"] = "false"
	stats, err = AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 2 || stats.DriftedManagedFields != 2 {
		t.Fatalf("enabled=false drift stats = %+v, want router and router port drift", stats)
	}
}

func TestAuditManagedObjectsFromReaderReportsStaleLogicalRouterPortColumns(t *testing.T) {
	subnet := model.Subnet{
		Name:    "apps",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
		Gateway: netip.MustParseAddr("10.10.0.1"),
	}
	reader := fakeManagedOVNReader{rows: map[string][]ManagedOVNRow{
		"Logical_Router_Port": {
			{Table: "Logical_Router_Port", UUID: "lrp-apps", ExternalIDs: map[string]string{
				"netloom_owner":  "netloom",
				"netloom_vpc":    "prod",
				"netloom_subnet": "apps",
			}, Fields: map[string]string{
				"name":             routerPortName(logicalRouter("prod"), "apps"),
				"mac":              deterministicMAC(subnet),
				"networks":         "10.10.0.1/24",
				"ipv6_ra_configs":  "",
				"options":          "redirect-chassis=node-old",
				"gateway_chassis":  "gc-old",
				"ha_chassis_group": "ha-old",
				"peer":             "transit-old",
			}},
		},
	}}
	desired := topology.State{
		Subnets: map[string]model.Subnet{
			subnetStateKey("prod", "apps"): subnet,
		},
	}

	stats, err := AuditManagedObjectsFromReaderWithDesired(context.Background(), reader, desired)
	if err != nil {
		t.Fatal(err)
	}
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 4 {
		t.Fatalf("stale logical router port drift stats = %+v, want options/gateway_chassis/ha_chassis_group/peer drift", stats)
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
				"ip_port_mappings":  "10.96.0.10=10.10.0.20",
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
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 3 {
		t.Fatalf("stale load balancer column drift stats = %+v, want options, ip_port_mappings, and health check attachment drift", stats)
	}
	if got := stats.DriftedManagedFieldCounts["Load_Balancer.ip_port_mappings"]; got != 1 {
		t.Fatalf("field drift counts = %+v, want stale ip_port_mappings drift", stats.DriftedManagedFieldCounts)
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
				"netloom_vpc":    "prod",
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
				"netloom_vpc":    "prod",
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
				"health_check_vips": "10.96.0.10:443",
			}},
		},
		"Load_Balancer_Health_Check": {
			{Table: "Load_Balancer_Health_Check", UUID: "hc-api", ExternalIDs: map[string]string{
				"netloom_owner":             "netloom",
				"netloom_vpc":               "prod",
				"netloom_load_balancer":     "api",
				"netloom_ovn_load_balancer": loadBalancerProtocolName("prod", "api", model.ProtocolUDP),
			}, Fields: map[string]string{
				"vip":     "10.96.0.10:443",
				"options": "failure_count=3,interval=5,success_count=3,timeout=99",
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
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 2 {
		t.Fatalf("load balancer health check metadata drift stats = %+v, want ovn load balancer external_id and options drift", stats)
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
	if stats.DriftedManagedRows != 1 || stats.DriftedManagedFields != 2 {
		t.Fatalf("DHCP option family metadata drift stats = %+v, want family external_id and options field drift", stats)
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
