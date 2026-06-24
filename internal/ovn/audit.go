package ovn

import (
	"context"
	"fmt"
	"strings"

	"github.com/jimyag/netloom/internal/topology"
)

type AuditStats struct {
	ManagedLogicalSwitches          int
	ManagedLogicalRouters           int
	ManagedLogicalSwitchPorts       int
	ManagedLogicalRouterPorts       int
	ManagedLogicalRouterPolicies    int
	ManagedNATRules                 int
	ManagedLoadBalancers            int
	ManagedLoadBalancerHealthChecks int
	ManagedDHCPOptions              int
	DuplicateManagedRows            int
	IncompleteManagedRows           int
	MissingManagedRows              int
	UnexpectedManagedRows           int
}

type ManagedOVNRow struct {
	Table       string
	UUID        string
	ExternalIDs map[string]string
}

type ManagedOVNReader interface {
	ManagedOVNRows(context.Context, string) ([]ManagedOVNRow, error)
}

func (s AuditStats) TotalManagedObjects() int {
	return s.ManagedLogicalSwitches +
		s.ManagedLogicalRouters +
		s.ManagedLogicalSwitchPorts +
		s.ManagedLogicalRouterPorts +
		s.ManagedLogicalRouterPolicies +
		s.ManagedNATRules +
		s.ManagedLoadBalancers +
		s.ManagedLoadBalancerHealthChecks +
		s.ManagedDHCPOptions
}

func (e *NBCTLExecutor) AuditManagedObjects(ctx context.Context) (AuditStats, error) {
	return AuditManagedObjectsFromReader(ctx, e)
}

func AuditManagedObjectsFromReader(ctx context.Context, reader ManagedOVNReader) (AuditStats, error) {
	return AuditManagedObjectsFromReaderWithDesired(ctx, reader, topology.State{})
}

func AuditManagedObjectsFromReaderWithDesired(ctx context.Context, reader ManagedOVNReader, desired topology.State) (AuditStats, error) {
	var stats AuditStats
	expected := expectedManagedAuditIdentities(desired)
	seen := make(map[string]struct{})
	for _, table := range managedAuditTables() {
		rows, err := reader.ManagedOVNRows(ctx, table.name)
		if err != nil {
			return AuditStats{}, err
		}
		result := auditManagedRows(table.name, rows)
		table.addCount(&stats, result.rows)
		stats.DuplicateManagedRows += result.duplicates
		stats.IncompleteManagedRows += result.incomplete
		for _, identity := range result.identities {
			if _, ok := expected[identity]; ok {
				seen[identity] = struct{}{}
			} else if len(expected) > 0 {
				stats.UnexpectedManagedRows++
			}
		}
	}
	if len(expected) > 0 {
		for identity := range expected {
			if _, ok := seen[identity]; !ok {
				stats.MissingManagedRows++
			}
		}
	}
	return stats, nil
}

type managedAuditTable struct {
	name     string
	addCount func(*AuditStats, int)
}

func managedAuditTables() []managedAuditTable {
	return []managedAuditTable{
		{"Logical_Switch", func(s *AuditStats, n int) { s.ManagedLogicalSwitches = n }},
		{"Logical_Router", func(s *AuditStats, n int) { s.ManagedLogicalRouters = n }},
		{"Logical_Switch_Port", func(s *AuditStats, n int) { s.ManagedLogicalSwitchPorts = n }},
		{"Logical_Router_Port", func(s *AuditStats, n int) { s.ManagedLogicalRouterPorts = n }},
		{"Logical_Router_Policy", func(s *AuditStats, n int) { s.ManagedLogicalRouterPolicies = n }},
		{"NAT", func(s *AuditStats, n int) { s.ManagedNATRules = n }},
		{"Load_Balancer", func(s *AuditStats, n int) { s.ManagedLoadBalancers = n }},
		{"Load_Balancer_Health_Check", func(s *AuditStats, n int) { s.ManagedLoadBalancerHealthChecks = n }},
		{"DHCP_Options", func(s *AuditStats, n int) { s.ManagedDHCPOptions = n }},
	}
}

func (e *NBCTLExecutor) ManagedOVNRows(ctx context.Context, table string) ([]ManagedOVNRow, error) {
	args := append([]string(nil), e.BaseArgs...)
	args = append(args,
		"--format=csv",
		"--data=bare",
		"--no-headings",
		"--columns=_uuid,external_ids",
		"find",
		table,
		"external_ids:netloom_owner=netloom",
	)
	output, err := e.outputCommand(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("audit managed %s: %w", table, err)
	}
	return parseManagedOVNRows(table, splitAuditRows(string(output))), nil
}

type auditRowResult struct {
	rows       int
	duplicates int
	incomplete int
	identities []string
}

func auditManagedRows(table string, rows []ManagedOVNRow) auditRowResult {
	result := auditRowResult{rows: len(rows)}
	seen := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if row.UUID == "" || row.ExternalIDs == nil {
			result.incomplete++
			continue
		}
		identity, complete := managedAuditIdentity(table, row.UUID, row.ExternalIDs)
		if !complete {
			result.incomplete++
			continue
		}
		if identity == "" {
			continue
		}
		if _, ok := seen[identity]; ok {
			result.duplicates++
			continue
		}
		seen[identity] = struct{}{}
		result.identities = append(result.identities, identity)
	}
	return result
}

func expectedManagedAuditIdentities(desired topology.State) map[string]struct{} {
	out := make(map[string]struct{})
	for name := range desired.VPCs {
		addAuditIdentity(out, "Logical_Router", "netloom_vpc", name)
	}
	for _, subnet := range desired.Subnets {
		addAuditIdentity(out, "Logical_Switch", "netloom_vpc", subnet.VPC, "netloom_subnet", subnet.Name)
		addAuditIdentity(out, "Logical_Router_Port", "netloom_subnet", subnet.Name)
		addAuditIdentity(out, "Logical_Switch_Port", "netloom_subnet", subnet.Name, "netloom_role", "router")
		if subnet.ProviderNetwork != "" {
			addAuditIdentity(out, "Logical_Switch_Port", "netloom_subnet", subnet.Name, "netloom_provider_network", subnet.ProviderNetwork)
		}
	}
	for _, endpoint := range desired.Endpoints {
		addAuditIdentity(out, "Logical_Switch_Port", "netloom_vpc", endpoint.VPC, "netloom_endpoint", endpointExternalID(endpoint.VPC, endpoint.ID))
		if subnet, ok := desired.Subnets[subnetStateKey(endpoint.VPC, endpoint.Subnet)]; ok && subnet.DHCP.Enabled {
			addAuditIdentity(out, "DHCP_Options", "netloom_vpc", endpoint.VPC, "netloom_endpoint", endpointExternalID(endpoint.VPC, endpoint.ID))
		}
	}
	for _, route := range desired.PolicyRoutes {
		addAuditIdentity(out, "Logical_Router_Policy", "netloom_vpc", route.VPC, "netloom_policy_route", route.Name)
	}
	for _, rule := range desired.NATRules {
		addAuditIdentity(out, "NAT", "netloom_vpc", rule.VPC, "netloom_nat", rule.Name)
	}
	for _, lb := range desired.LoadBalancers {
		addAuditIdentity(out, "Load_Balancer", "netloom_vpc", lb.VPC, "netloom_load_balancer", lb.Name)
	}
	return out
}

func addAuditIdentity(out map[string]struct{}, table string, keyValues ...string) {
	if len(keyValues)%2 != 0 {
		return
	}
	externalIDs := make(map[string]string, len(keyValues)/2)
	for i := 0; i < len(keyValues); i += 2 {
		externalIDs[keyValues[i]] = keyValues[i+1]
	}
	identity, complete := managedAuditIdentity(table, "", externalIDs)
	if complete && identity != "" {
		out[identity] = struct{}{}
	}
}

func parseManagedOVNRows(table string, rows []string) []ManagedOVNRow {
	out := make([]ManagedOVNRow, 0, len(rows))
	for _, row := range rows {
		uuid, externalIDs, ok := parseExternalIDsCSVRow(row)
		if !ok {
			out = append(out, ManagedOVNRow{Table: table})
			continue
		}
		out = append(out, ManagedOVNRow{
			Table:       table,
			UUID:        uuid,
			ExternalIDs: externalIDs,
		})
	}
	return out
}

func managedAuditIdentity(table, uuid string, externalIDs map[string]string) (string, bool) {
	switch table {
	case "Logical_Switch":
		return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_subnet")
	case "Logical_Router":
		return auditIdentity(table, externalIDs, "netloom_vpc")
	case "Logical_Switch_Port":
		if externalIDs["netloom_endpoint"] != "" {
			return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_endpoint")
		}
		if externalIDs["netloom_provider_network"] != "" {
			return auditIdentity(table, externalIDs, "netloom_subnet", "netloom_provider_network")
		}
		return auditIdentity(table, externalIDs, "netloom_subnet", "netloom_role")
	case "Logical_Router_Port":
		return auditIdentity(table, externalIDs, "netloom_subnet")
	case "Logical_Router_Policy":
		return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_policy_route")
	case "NAT":
		return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_nat")
	case "Load_Balancer":
		return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_load_balancer")
	case "Load_Balancer_Health_Check":
		if _, complete := auditIdentity(table, externalIDs, "netloom_vpc", "netloom_load_balancer"); !complete {
			return "", false
		}
		return table + "\x00" + uuid, uuid != ""
	case "DHCP_Options":
		return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_endpoint")
	default:
		return "", true
	}
}

func auditIdentity(table string, externalIDs map[string]string, keys ...string) (string, bool) {
	parts := []string{table}
	for _, key := range keys {
		value := externalIDs[key]
		if value == "" {
			return "", false
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, "\x00"), true
}

func splitAuditRows(output string) []string {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}
	lines := strings.Split(output, "\n")
	rows := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			rows = append(rows, line)
		}
	}
	return rows
}
