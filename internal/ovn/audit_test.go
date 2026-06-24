package ovn

import (
	"context"
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

func TestAuditStatsTotalManagedObjects(t *testing.T) {
	stats := AuditStats{
		ManagedLogicalSwitches:          1,
		ManagedLogicalRouters:           1,
		ManagedLogicalSwitchPorts:       2,
		ManagedLogicalRouterPorts:       1,
		ManagedLogicalRouterPolicies:    3,
		ManagedNATRules:                 2,
		ManagedLoadBalancers:            1,
		ManagedLoadBalancerHealthChecks: 2,
		ManagedDHCPOptions:              4,
	}

	if got := stats.TotalManagedObjects(); got != 17 {
		t.Fatalf("total managed objects = %d, want 17", got)
	}
}

type fakeManagedOVNReader struct {
	rows map[string][]ManagedOVNRow
}

func (r fakeManagedOVNReader) ManagedOVNRows(_ context.Context, table string) ([]ManagedOVNRow, error) {
	return append([]ManagedOVNRow(nil), r.rows[table]...), nil
}
