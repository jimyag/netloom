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
  *"find Logical_Switch external_ids:netloom_owner=netloom"*) printf 'ls-a,{netloom_owner=netloom,netloom_vpc=prod,netloom_subnet=apps}\n' ;;
  *"find NAT external_ids:netloom_owner=netloom"*) printf 'nat-a,{netloom_owner=netloom,netloom_vpc=prod,netloom_nat=egress}\nnat-b,{netloom_owner=netloom,netloom_vpc=prod,netloom_nat=egress}\n' ;;
  *"find DHCP_Options external_ids:netloom_owner=netloom"*) printf 'dhcp-a,{netloom_owner=netloom,netloom_vpc=prod}\n' ;;
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
			}, Fields: map[string]string{"name": "renamed-router"}},
		},
		"Logical_Switch": {
			{Table: "Logical_Switch", UUID: "ls-apps", ExternalIDs: map[string]string{
				"netloom_owner":  "netloom",
				"netloom_vpc":    "prod",
				"netloom_subnet": "apps",
			}, Fields: map[string]string{
				"name":         "renamed-switch",
				"other_config": mapField(logicalSwitchOtherConfig(subnet)),
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
			}, Fields: map[string]string{"name": logicalRouter("prod")}},
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
				"netloom_owner":         "netloom",
				"netloom_vpc":           "prod",
				"netloom_load_balancer": "api",
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

func TestAuditStatsTotalManagedObjects(t *testing.T) {
	stats := AuditStats{
		ManagedLogicalSwitches:           1,
		ManagedLogicalRouters:            1,
		ManagedLogicalSwitchPorts:        2,
		ManagedLogicalRouterPorts:        1,
		ManagedLogicalRouterPolicies:     3,
		ManagedLogicalRouterStaticRoutes: 5,
		ManagedNATRules:                  2,
		ManagedLoadBalancers:             1,
		ManagedLoadBalancerHealthChecks:  2,
		ManagedDHCPOptions:               4,
	}

	if got := stats.TotalManagedObjects(); got != 22 {
		t.Fatalf("total managed objects = %d, want 22", got)
	}
}

type fakeManagedOVNReader struct {
	rows map[string][]ManagedOVNRow
}

func (r fakeManagedOVNReader) ManagedOVNRows(_ context.Context, table string) ([]ManagedOVNRow, error) {
	return append([]ManagedOVNRow(nil), r.rows[table]...), nil
}
