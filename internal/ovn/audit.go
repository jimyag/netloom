package ovn

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/ovnnb"
	"github.com/jimyag/netloom/internal/topology"
)

type AuditStats struct {
	ManagedLogicalSwitches           int
	ManagedLogicalRouters            int
	ManagedLogicalSwitchPorts        int
	ManagedLogicalRouterPorts        int
	ManagedLogicalRouterPolicies     int
	ManagedLogicalRouterStaticRoutes int
	ManagedNATRules                  int
	ManagedLoadBalancers             int
	ManagedLoadBalancerHealthChecks  int
	ManagedDHCPOptions               int
	DuplicateManagedRows             int
	IncompleteManagedRows            int
	MissingManagedRows               int
	UnexpectedManagedRows            int
	DriftedManagedRows               int
	DriftedManagedFields             int
}

type ManagedOVNRow struct {
	Table       string
	UUID        string
	ExternalIDs map[string]string
	Fields      map[string]string
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
		s.ManagedLogicalRouterStaticRoutes +
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
	expected := expectedManagedAuditRows(desired)
	expectedColumns := expectedManagedAuditColumns(desired)
	for identity := range expectedColumns {
		if _, ok := expected[identity]; !ok {
			expected[identity] = nil
		}
	}
	seen := make(map[string]struct{})
	for _, table := range managedAuditTables() {
		rows, err := reader.ManagedOVNRows(ctx, table.name)
		if err != nil {
			return AuditStats{}, err
		}
		result := auditManagedRows(table.name, rows)
		table.addCount(&stats, result.count)
		stats.DuplicateManagedRows += result.duplicates
		stats.IncompleteManagedRows += result.incomplete
		for _, row := range result.rows {
			if expectedFields, ok := expected[row.identity]; ok {
				seen[row.identity] = struct{}{}
				driftedFields := countManagedFieldDrift(row.externalIDs, expectedFields)
				if row.fields != nil {
					driftedFields += countManagedFieldDrift(row.fields, expectedColumns[row.identity])
				}
				if driftedFields != 0 {
					stats.DriftedManagedRows++
					stats.DriftedManagedFields += driftedFields
				}
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
		{"Logical_Router_Static_Route", func(s *AuditStats, n int) { s.ManagedLogicalRouterStaticRoutes = n }},
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
	count      int
	duplicates int
	incomplete int
	rows       []auditManagedRow
}

type auditManagedRow struct {
	identity    string
	externalIDs map[string]string
	fields      map[string]string
}

func auditManagedRows(table string, rows []ManagedOVNRow) auditRowResult {
	result := auditRowResult{count: len(rows)}
	seen := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if row.UUID == "" || row.ExternalIDs == nil {
			result.incomplete++
			continue
		}
		identity, complete := managedAuditIdentityForRow(table, row.UUID, row.ExternalIDs, row.Fields)
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
		result.rows = append(result.rows, auditManagedRow{
			identity:    identity,
			externalIDs: row.ExternalIDs,
			fields:      row.Fields,
		})
	}
	return result
}

func expectedManagedAuditIdentities(desired topology.State) map[string]struct{} {
	rows := expectedManagedAuditRows(desired)
	out := make(map[string]struct{})
	for identity := range rows {
		out[identity] = struct{}{}
	}
	return out
}

func expectedManagedAuditRows(desired topology.State) map[string]map[string]string {
	out := make(map[string]map[string]string)
	for name := range desired.VPCs {
		addAuditExpectedRow(out, "Logical_Router", "netloom_vpc", name)
	}
	for _, subnet := range desired.Subnets {
		addAuditExpectedRow(out, "Logical_Switch", "netloom_vpc", subnet.VPC, "netloom_subnet", subnet.Name)
		addAuditExpectedRow(out, "Logical_Router_Port", "netloom_subnet", subnet.Name)
		addAuditExpectedRow(out, "Logical_Switch_Port", "netloom_subnet", subnet.Name, "netloom_role", "router")
		if subnet.ProviderNetwork != "" {
			addAuditExpectedRow(out, "Logical_Switch_Port", "netloom_subnet", subnet.Name, "netloom_provider_network", subnet.ProviderNetwork)
		}
	}
	for _, endpoint := range desired.Endpoints {
		addAuditExpectedRow(out, "Logical_Switch_Port",
			"netloom_vpc", endpoint.VPC,
			"netloom_endpoint", endpointExternalID(endpoint.VPC, endpoint.ID),
			"netloom_node", endpoint.Node,
			"netloom_subnet", endpoint.Subnet,
		)
		if subnet, ok := desired.Subnets[subnetStateKey(endpoint.VPC, endpoint.Subnet)]; ok && subnet.DHCP.Enabled {
			addAuditExpectedRow(out, "DHCP_Options",
				"netloom_vpc", endpoint.VPC,
				"netloom_endpoint", endpointExternalID(endpoint.VPC, endpoint.ID),
				"netloom_subnet", endpoint.Subnet,
			)
		}
	}
	for _, route := range desired.PolicyRoutes {
		addAuditExpectedRow(out, "Logical_Router_Policy", "netloom_vpc", route.VPC, "netloom_policy_route", route.Name)
	}
	for _, table := range desired.RouteTables {
		for _, route := range table.Routes {
			for _, row := range desiredStaticRouteRows(table, route) {
				addAuditExpectedRow(out, "Logical_Router_Static_Route",
					"netloom_vpc", table.VPC,
					"netloom_route_table", table.Name,
					"netloom_route_key", row.ExternalIDs["netloom_route_key"],
				)
			}
		}
	}
	for _, rule := range desired.NATRules {
		addAuditExpectedRow(out, "NAT", "netloom_vpc", rule.VPC, "netloom_nat", rule.Name)
	}
	for _, lb := range desired.LoadBalancers {
		frontendsByProtocol := loadBalancerFrontendsByProtocol(lb)
		for _, protocol := range sortedLoadBalancerProtocols(frontendsByProtocol) {
			addAuditExpectedRow(out, "Load_Balancer",
				"netloom_vpc", lb.VPC,
				"netloom_load_balancer", lb.Name,
				"netloom_protocol", string(protocol),
				"netloom_session_affinity", fmt.Sprintf("%t", lb.SessionAffinity),
			)
		}
	}
	for _, gateway := range desired.Gateways {
		addAuditExpectedRow(out, "Logical_Router", gatewayAuditIdentityFields(gateway)...)
	}
	return out
}

func gatewayAuditIdentityFields(gateway model.Gateway) []string {
	fields := []string{
		"netloom_vpc", gateway.VPC,
		"netloom_gateway", gateway.Name,
		"netloom_gateway_lan_ip", gateway.LANIP.String(),
		"netloom_gateway_distributed", fmt.Sprintf("%t", gateway.Distributed),
	}
	if gateway.ExternalIF != "" {
		fields = append(fields, "netloom_external_if", gateway.ExternalIF)
	}
	return fields
}

func expectedManagedAuditColumns(desired topology.State) map[string]map[string]string {
	out := make(map[string]map[string]string)
	for name := range desired.VPCs {
		addAuditExpectedColumns(out, "Logical_Router", map[string]string{
			"name": logicalRouter(name),
		}, "netloom_vpc", name)
	}
	for _, subnet := range desired.Subnets {
		addAuditExpectedColumns(out, "Logical_Switch", logicalSwitchColumnFields(subnet), "netloom_vpc", subnet.VPC, "netloom_subnet", subnet.Name)
		addAuditExpectedColumns(out, "Logical_Router_Port", map[string]string{
			"name":     routerPortName(logicalRouter(subnet.VPC), subnet.Name),
			"mac":      deterministicMAC(subnet),
			"networks": strings.Join([]string{subnet.Gateway.String() + "/" + fmt.Sprint(subnet.CIDR.Bits())}, ","),
		}, "netloom_subnet", subnet.Name)
		addAuditExpectedColumns(out, "Logical_Switch_Port", map[string]string{
			"name":      switchRouterPortName(logicalSwitch(subnet.VPC, subnet.Name), subnet.Name),
			"type":      "router",
			"addresses": deterministicMAC(subnet),
			"options":   mapField(map[string]string{"router-port": routerPortName(logicalRouter(subnet.VPC), subnet.Name)}),
		}, "netloom_subnet", subnet.Name, "netloom_role", "router")
		if subnet.ProviderNetwork != "" {
			fields := map[string]string{
				"name":      localnetPortName(logicalSwitch(subnet.VPC, subnet.Name), subnet.Name),
				"type":      "localnet",
				"addresses": "unknown",
				"options":   mapField(map[string]string{"network_name": subnet.ProviderNetwork}),
			}
			if subnet.VLAN != 0 {
				fields["tag"] = fmt.Sprint(subnet.VLAN)
			}
			addAuditExpectedColumns(out, "Logical_Switch_Port", fields, "netloom_subnet", subnet.Name, "netloom_provider_network", subnet.ProviderNetwork)
		}
	}
	for vpc, names := range expectedRouterLoadBalancers(desired.LoadBalancers) {
		addAuditExpectedColumns(out, "Logical_Router", map[string]string{
			"load_balancers": stringSetField(names),
		}, "netloom_vpc", vpc)
	}
	for vpc, names := range expectedRouterNATRules(desired.NATRules) {
		addAuditExpectedColumns(out, "Logical_Router", map[string]string{
			"nat_rules": stringSetField(names),
		}, "netloom_vpc", vpc)
	}
	for vpc, names := range expectedRouterPolicies(desired.PolicyRoutes) {
		addAuditExpectedColumns(out, "Logical_Router", map[string]string{
			"policies": stringSetField(names),
		}, "netloom_vpc", vpc)
	}
	for vpc, keys := range expectedRouterStaticRoutes(desired.RouteTables) {
		addAuditExpectedColumns(out, "Logical_Router", map[string]string{
			"static_routes": stringSetField(keys),
		}, "netloom_vpc", vpc)
	}
	for key, names := range expectedSwitchLoadBalancers(desired.LoadBalancers) {
		vpc, subnet, ok := splitStateKey(key)
		if !ok {
			continue
		}
		addAuditExpectedColumns(out, "Logical_Switch", map[string]string{
			"load_balancers": stringSetField(names),
		}, "netloom_vpc", vpc, "netloom_subnet", subnet)
	}
	for _, endpoint := range desired.Endpoints {
		fields := map[string]string{
			"name":      logicalPort(endpoint.VPC, endpoint.ID),
			"addresses": endpointAddress(endpoint),
		}
		if endpoint.NormalizedMAC() != "" {
			fields["port_security"] = endpointAddress(endpoint)
		}
		addAuditExpectedColumns(out, "Logical_Switch_Port", fields,
			"netloom_vpc", endpoint.VPC,
			"netloom_endpoint", endpointExternalID(endpoint.VPC, endpoint.ID),
		)
	}
	for _, route := range desired.PolicyRoutes {
		row := desiredPolicyRouteRow(route)
		fields := map[string]string{
			"priority": fmt.Sprint(row.Priority),
			"match":    row.Match,
			"action":   string(row.Action),
		}
		if row.Nexthop != nil {
			fields["nexthop"] = *row.Nexthop
		}
		if len(row.Nexthops) > 0 {
			fields["nexthops"] = strings.Join(row.Nexthops, ",")
		}
		addAuditExpectedColumns(out, "Logical_Router_Policy", fields, "netloom_vpc", route.VPC, "netloom_policy_route", route.Name)
	}
	for _, table := range desired.RouteTables {
		for _, route := range table.Routes {
			for _, row := range desiredStaticRouteRows(table, route) {
				fields := map[string]string{
					"bfd":              pointerStringValue(row.BFD),
					"ip_prefix":        row.IPPrefix,
					"nexthop":          row.Nexthop,
					"options":          mapField(row.Options),
					"output_port":      pointerStringValue(row.OutputPort),
					"policy":           pointerStaticRoutePolicyValue(row.Policy),
					"route_table":      row.RouteTable,
					"selection_fields": staticRouteSelectionFieldsField(row.SelectionFields),
				}
				addAuditExpectedColumns(out, "Logical_Router_Static_Route", fields,
					"netloom_vpc", table.VPC,
					"netloom_route_table", table.Name,
					"netloom_route_key", row.ExternalIDs["netloom_route_key"],
				)
			}
		}
	}
	for _, rule := range desired.NATRules {
		row := desiredNATRuleRow(rule)
		fields := map[string]string{
			"type":        string(row.Type),
			"external_ip": row.ExternalIP,
			"logical_ip":  row.LogicalIP,
		}
		if row.ExternalPortRange != "" {
			fields["external_port_range"] = row.ExternalPortRange
		}
		if row.LogicalPort != nil {
			fields["logical_port"] = *row.LogicalPort
		}
		if row.ExternalMAC != nil {
			fields["external_mac"] = *row.ExternalMAC
		}
		if len(row.Options) > 0 {
			fields["options"] = mapField(row.Options)
		}
		addAuditExpectedColumns(out, "NAT", fields, "netloom_vpc", rule.VPC, "netloom_nat", rule.Name)
	}
	for _, gateway := range desired.Gateways {
		fields := map[string]string{
			"name":    logicalRouter(gateway.VPC),
			"options": mapField(gatewayAuditRouterOptions(gateway)),
		}
		addAuditExpectedColumns(out, "Logical_Router", fields, gatewayAuditIdentityFields(gateway)...)
	}
	for _, lb := range desired.LoadBalancers {
		frontendsByProtocol := loadBalancerFrontendsByProtocol(lb)
		for _, protocol := range sortedLoadBalancerProtocols(frontendsByProtocol) {
			row := desiredLoadBalancerRow(lb, protocol, frontendsByProtocol[protocol])
			fields := map[string]string{
				"name":             row.Name,
				"vips":             mapField(row.Vips),
				"selection_fields": selectionFieldsField(row.SelectionFields),
			}
			if lb.HealthCheck.Enabled {
				fields["health_check_vips"] = loadBalancerHealthCheckVIPsField(frontendsByProtocol[protocol])
			}
			if row.Protocol != nil {
				fields["protocol"] = string(*row.Protocol)
			}
			if len(row.Options) > 0 {
				fields["options"] = mapField(row.Options)
			}
			addAuditExpectedColumns(out, "Load_Balancer", fields,
				"netloom_vpc", lb.VPC,
				"netloom_load_balancer", lb.Name,
				"netloom_protocol", string(protocol),
			)
			if lb.HealthCheck.Enabled {
				for _, frontend := range frontendsByProtocol[protocol] {
					hc := desiredLoadBalancerHealthCheck(lb, frontend)
					addAuditExpectedColumns(out, "Load_Balancer_Health_Check", map[string]string{
						"vip":     hc.Vip,
						"options": mapField(hc.Options),
					}, "netloom_vpc", lb.VPC, "netloom_load_balancer", lb.Name)
				}
			}
		}
	}
	return out
}

func gatewayAuditRouterOptions(gateway model.Gateway) map[string]string {
	if gateway.Distributed {
		return nil
	}
	return map[string]string{"chassis": gateway.Node}
}

func addAuditExpectedColumns(out map[string]map[string]string, table string, fields map[string]string, keyValues ...string) {
	if len(fields) == 0 {
		return
	}
	externalIDs := make(map[string]string, len(keyValues)/2)
	for i := 0; i < len(keyValues)-1; i += 2 {
		externalIDs[keyValues[i]] = keyValues[i+1]
	}
	identity, complete := managedAuditIdentityForRow(table, "", externalIDs, fields)
	if !complete || identity == "" {
		return
	}
	if out[identity] == nil {
		out[identity] = make(map[string]string, len(fields))
	}
	for key, value := range fields {
		out[identity][key] = value
	}
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

func addAuditExpectedRow(out map[string]map[string]string, table string, keyValues ...string) {
	if len(keyValues)%2 != 0 {
		return
	}
	externalIDs := make(map[string]string, len(keyValues)/2)
	for i := 0; i < len(keyValues); i += 2 {
		externalIDs[keyValues[i]] = keyValues[i+1]
	}
	identity, complete := managedAuditIdentity(table, "", externalIDs)
	if !complete || identity == "" {
		return
	}
	expected := out[identity]
	if expected == nil {
		expected = make(map[string]string, len(externalIDs))
		out[identity] = expected
	}
	for key, value := range externalIDs {
		expected[key] = value
	}
}

func countManagedFieldDrift(live, expected map[string]string) int {
	drift := 0
	for key, value := range expected {
		if live[key] != value {
			drift++
		}
	}
	return drift
}

func logicalSwitchColumnFields(subnet model.Subnet) map[string]string {
	fields := map[string]string{
		"name":         logicalSwitch(subnet.VPC, subnet.Name),
		"other_config": mapField(logicalSwitchOtherConfig(subnet)),
	}
	return fields
}

func mapField(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+values[key])
	}
	return strings.Join(parts, ",")
}

func stringSliceField(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, ",")
}

func stringSetField(values []string) string {
	if len(values) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return stringSliceField(out)
}

func selectionFieldsField(values []ovnnb.LoadBalancerSelectionFields) string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return stringSliceField(out)
}

func staticRouteSelectionFieldsField(values []ovnnb.LogicalRouterStaticRouteSelectionFields) string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return stringSliceField(out)
}

func loadBalancerHealthCheckVIPsField(frontends []model.LoadBalancerFrontend) string {
	vips := make([]string, 0, len(frontends))
	for _, frontend := range frontends {
		vips = append(vips, loadBalancerFrontendVIP(frontend))
	}
	sort.Strings(vips)
	return stringSliceField(vips)
}

func expectedRouterLoadBalancers(loadBalancers map[string]model.LoadBalancer) map[string][]string {
	out := make(map[string][]string)
	for _, lb := range loadBalancers {
		names := loadBalancerProtocolNamesFromFrontends(lb.VPC, lb.Name, loadBalancerFrontendsByProtocol(lb))
		out[lb.VPC] = append(out[lb.VPC], names...)
	}
	return out
}

func expectedRouterNATRules(rules map[string]model.NATRule) map[string][]string {
	out := make(map[string][]string)
	for _, rule := range rules {
		out[rule.VPC] = append(out[rule.VPC], rule.Name)
	}
	return out
}

func expectedRouterPolicies(routes []model.PolicyRoute) map[string][]string {
	out := make(map[string][]string)
	for _, route := range routes {
		out[route.VPC] = append(out[route.VPC], route.Name)
	}
	return out
}

func expectedRouterStaticRoutes(tables map[string]model.RouteTable) map[string][]string {
	out := make(map[string][]string)
	for _, table := range tables {
		for _, route := range table.Routes {
			for _, row := range desiredStaticRouteRows(table, route) {
				out[table.VPC] = append(out[table.VPC], row.ExternalIDs["netloom_route_key"])
			}
		}
	}
	return out
}

func expectedSwitchLoadBalancers(loadBalancers map[string]model.LoadBalancer) map[string][]string {
	out := make(map[string][]string)
	for _, lb := range loadBalancers {
		names := loadBalancerProtocolNamesFromFrontends(lb.VPC, lb.Name, loadBalancerFrontendsByProtocol(lb))
		for _, subnet := range lb.Subnets {
			out[subnetStateKey(lb.VPC, subnet)] = append(out[subnetStateKey(lb.VPC, subnet)], names...)
		}
	}
	return out
}

func splitStateKey(key string) (string, string, bool) {
	parts := strings.Split(key, "\x00")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
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

func managedAuditIdentityForRow(table, uuid string, externalIDs, fields map[string]string) (string, bool) {
	if table == "Load_Balancer_Health_Check" && fields["vip"] != "" {
		identity, complete := auditIdentity(table, externalIDs, "netloom_vpc", "netloom_load_balancer")
		if !complete {
			return "", false
		}
		return identity + "\x00" + fields["vip"], true
	}
	return managedAuditIdentity(table, uuid, externalIDs)
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
	case "Logical_Router_Static_Route":
		return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_route_table", "netloom_route_key")
	case "NAT":
		return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_nat")
	case "Load_Balancer":
		return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_load_balancer", "netloom_protocol")
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
