package ovn

import (
	"context"
	"encoding/csv"
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
	ManagedBFDs                      int
	ManagedNATRules                  int
	ManagedLoadBalancers             int
	ManagedLoadBalancerHealthChecks  int
	ManagedDHCPOptions               int
	ManagedDNSRecords                int
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
		s.ManagedBFDs +
		s.ManagedNATRules +
		s.ManagedLoadBalancers +
		s.ManagedLoadBalancerHealthChecks +
		s.ManagedDHCPOptions +
		s.ManagedDNSRecords
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
				driftedFields := countManagedFieldDrift(table.name, row.externalIDs, expectedFields)
				if row.fields != nil {
					driftedFields += countManagedProvidedFieldDrift(table.name, row.fields, expectedColumns[row.identity])
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
		{"BFD", func(s *AuditStats, n int) { s.ManagedBFDs = n }},
		{"NAT", func(s *AuditStats, n int) { s.ManagedNATRules = n }},
		{"Load_Balancer", func(s *AuditStats, n int) { s.ManagedLoadBalancers = n }},
		{"Load_Balancer_Health_Check", func(s *AuditStats, n int) { s.ManagedLoadBalancerHealthChecks = n }},
		{"DHCP_Options", func(s *AuditStats, n int) { s.ManagedDHCPOptions = n }},
		{"DNS", func(s *AuditStats, n int) { s.ManagedDNSRecords = n }},
	}
}

func (e *NBCTLExecutor) ManagedOVNRows(ctx context.Context, table string) ([]ManagedOVNRow, error) {
	columns := managedAuditNBCTLColumns(table)
	args := append([]string(nil), e.BaseArgs...)
	args = append(args,
		"--format=csv",
		"--data=bare",
		"--no-headings",
		"--columns="+strings.Join(columns, ","),
		"find",
		table,
		"external_ids:netloom_owner=netloom",
	)
	output, err := e.outputCommand(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("audit managed %s: %w", table, err)
	}
	rows := parseManagedOVNRows(table, columns, splitAuditRows(string(output)))
	if table == "Logical_Router" {
		if err := e.enrichNBCTLLogicalRouterReferenceFields(ctx, rows); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

func managedAuditNBCTLColumns(table string) []string {
	columns := []string{"_uuid", "external_ids"}
	switch table {
	case "Logical_Switch":
		columns = append(columns, "name", "other_config", "acls", "forwarding_groups", "load_balancer_group", "qos_rules")
	case "Logical_Router":
		columns = append(columns, "name", "options", "ports", "load_balancers", "load_balancer_group", "nat", "policies", "static_routes", "enabled")
	case "Logical_Switch_Port":
		columns = append(columns, "name", "type", "addresses", "port_security", "options", "tag", "enabled")
	case "Logical_Router_Port":
		columns = append(columns, "name", "mac", "networks", "ipv6_ra_configs", "enabled")
	case "Logical_Router_Policy":
		columns = append(columns, "priority", "match", "action", "nexthop", "nexthops")
	case "Logical_Router_Static_Route":
		columns = append(columns, "bfd", "ip_prefix", "nexthop", "options", "output_port", "policy", "route_table", "selection_fields")
	case "BFD":
		columns = append(columns, "logical_port", "dst_ip", "min_tx", "min_rx", "detect_mult", "options")
	case "NAT":
		columns = append(columns, "type", "external_ip", "logical_ip", "external_port_range", "logical_port", "external_mac", "options")
	case "Load_Balancer":
		columns = append(columns, "name", "vips", "protocol", "options", "selection_fields")
	case "Load_Balancer_Health_Check":
		columns = append(columns, "vip", "options")
	case "DHCP_Options":
		columns = append(columns, "cidr", "options")
	case "DNS":
		columns = append(columns, "records", "options")
	}
	return columns
}

func (e *NBCTLExecutor) enrichNBCTLLogicalRouterReferenceFields(ctx context.Context, rows []ManagedOVNRow) error {
	if len(rows) == 0 {
		return nil
	}
	specs := []struct {
		field string
		table string
		key   string
	}{
		{field: "ports", table: "Logical_Router_Port", key: "name"},
		{field: "load_balancers", table: "Load_Balancer", key: "name"},
		{field: "nat_rules", table: "NAT", key: "netloom_nat"},
		{field: "policies", table: "Logical_Router_Policy", key: "netloom_policy_route"},
		{field: "static_routes", table: "Logical_Router_Static_Route", key: "netloom_route_key"},
	}
	for _, spec := range specs {
		refs, err := e.managedNBCTLReferenceNames(ctx, spec.table, spec.key)
		if err != nil {
			return err
		}
		for i := range rows {
			rows[i].Fields[spec.field] = resolveManagedAuditReferenceField(rows[i].Fields[spec.field], refs)
		}
	}
	return nil
}

func (e *NBCTLExecutor) managedNBCTLReferenceNames(ctx context.Context, table, key string) (map[string]string, error) {
	columns := []string{"_uuid", "external_ids"}
	if key == "name" {
		columns = append(columns, "name")
	}
	args := append([]string(nil), e.BaseArgs...)
	args = append(args,
		"--format=csv",
		"--data=bare",
		"--no-headings",
		"--columns="+strings.Join(columns, ","),
		"find",
		table,
		"external_ids:netloom_owner=netloom",
	)
	output, err := e.outputCommand(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("audit managed %s references: %w", table, err)
	}
	out := make(map[string]string)
	for _, row := range splitAuditRows(string(output)) {
		values, ok := parseAuditCSVRow(row)
		if !ok || len(values) < 2 {
			continue
		}
		uuid := trimOVNString(values[0])
		if uuid == "" {
			continue
		}
		var value string
		if key == "name" {
			if len(values) < 3 {
				continue
			}
			value = trimOVNString(values[2])
		} else {
			value = parseOVNMap(values[1])[key]
		}
		if value != "" {
			out[uuid] = value
		}
	}
	return out, nil
}

func resolveManagedAuditReferenceField(value string, refs map[string]string) string {
	if value == "" {
		return ""
	}
	uuids := strings.Split(value, ",")
	resolved := make([]string, 0, len(uuids))
	for _, uuid := range uuids {
		uuid = strings.TrimSpace(uuid)
		if refs[uuid] != "" {
			resolved = append(resolved, refs[uuid])
		}
	}
	return stringSetField(resolved)
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
		addAuditExpectedRow(out, "Logical_Router_Port", "netloom_vpc", subnet.VPC, "netloom_subnet", subnet.Name)
		addAuditExpectedRow(out, "Logical_Switch_Port", "netloom_vpc", subnet.VPC, "netloom_subnet", subnet.Name, "netloom_role", "router")
		if subnet.ProviderNetwork != "" {
			addAuditExpectedRow(out, "Logical_Switch_Port", "netloom_vpc", subnet.VPC, "netloom_subnet", subnet.Name, "netloom_provider_network", subnet.ProviderNetwork)
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
			family := "4"
			if endpoint.IP.Is6() && !endpoint.IP.Is4() {
				family = "6"
			}
			addAuditExpectedRow(out, "DHCP_Options",
				"netloom_vpc", endpoint.VPC,
				"netloom_endpoint", endpointExternalID(endpoint.VPC, endpoint.ID),
				"netloom_subnet", endpoint.Subnet,
				"netloom_dhcp_family", family,
			)
		}
	}
	for _, route := range desired.PolicyRoutes {
		addAuditExpectedRow(out, "Logical_Router_Policy",
			"netloom_vpc", route.VPC,
			"netloom_policy_route", route.Name,
			"netloom_action", string(route.Action.Type),
		)
	}
	for _, table := range desired.RouteTables {
		for _, route := range table.Routes {
			for _, row := range desiredStaticRouteRows(table, route) {
				addAuditExpectedRow(out, "Logical_Router_Static_Route",
					"netloom_vpc", table.VPC,
					"netloom_route_table", table.Name,
					"netloom_route_key", row.ExternalIDs["netloom_route_key"],
				)
				if route.BFD.Enabled {
					addAuditExpectedRow(out, "BFD",
						"netloom_vpc", table.VPC,
						"netloom_route_table", table.Name,
						"netloom_route_key", row.ExternalIDs["netloom_route_key"],
						"netloom_route_bfd", staticRouteBFDRef(table.VPC, table.Name, row.ExternalIDs["netloom_route_key"]),
					)
				}
			}
		}
	}
	for _, rule := range desired.NATRules {
		addAuditExpectedRow(out, "NAT", natAuditExpectedExternalIDs(rule)...)
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
			if lb.HealthCheck.Enabled {
				for _, frontend := range frontendsByProtocol[protocol] {
					hc := desiredLoadBalancerHealthCheck(lb, frontend)
					addAuditExpectedRowWithFields(out, "Load_Balancer_Health_Check", map[string]string{
						"vip": hc.Vip,
					},
						"netloom_vpc", lb.VPC,
						"netloom_load_balancer", lb.Name,
						"netloom_ovn_load_balancer", hc.ExternalIDs["netloom_ovn_load_balancer"],
					)
				}
			}
		}
	}
	for _, gateway := range desired.Gateways {
		addAuditExpectedRow(out, "Logical_Router", gatewayAuditIdentityFields(gateway)...)
	}
	if len(desiredOVNDNSRecords(desired.DNSRecords)) > 0 {
		addAuditExpectedRow(out, "DNS", "netloom_dns", "desired")
	}
	return out
}

func natAuditExpectedExternalIDs(rule model.NATRule) []string {
	fields := []string{
		"netloom_vpc", rule.VPC,
		"netloom_nat", rule.Name,
	}
	if rule.ExternalPort != 0 {
		fields = append(fields, "netloom_external_port", fmt.Sprint(rule.ExternalPort))
	}
	if rule.TargetPort != 0 {
		fields = append(fields, "netloom_target_port", fmt.Sprint(rule.TargetPort))
	}
	if rule.Protocol != "" && rule.Protocol != model.ProtocolAny {
		fields = append(fields, "netloom_protocol", string(rule.Protocol))
	}
	return fields
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
	for vpc, names := range expectedRouterPorts(desired.Subnets) {
		addAuditExpectedColumns(out, "Logical_Router", map[string]string{
			"ports": stringSetField(names),
		}, "netloom_vpc", vpc)
	}
	for _, subnet := range desired.Subnets {
		addAuditExpectedColumns(out, "Logical_Switch", logicalSwitchColumnFields(subnet), "netloom_vpc", subnet.VPC, "netloom_subnet", subnet.Name)
		addAuditExpectedColumns(out, "Logical_Router_Port", map[string]string{
			"name":            routerPortName(logicalRouter(subnet.VPC), subnet.Name),
			"mac":             deterministicMAC(subnet),
			"networks":        strings.Join([]string{subnet.Gateway.String() + "/" + fmt.Sprint(subnet.CIDR.Bits())}, ","),
			"ipv6_ra_configs": routerPortIPv6RAConfigsField(subnet),
		}, "netloom_vpc", subnet.VPC, "netloom_subnet", subnet.Name)
		addAuditExpectedColumns(out, "Logical_Switch_Port", map[string]string{
			"name":      switchRouterPortName(logicalSwitch(subnet.VPC, subnet.Name), subnet.Name),
			"type":      "router",
			"addresses": deterministicMAC(subnet),
			"options":   mapField(map[string]string{"router-port": routerPortName(logicalRouter(subnet.VPC), subnet.Name)}),
		}, "netloom_vpc", subnet.VPC, "netloom_subnet", subnet.Name, "netloom_role", "router")
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
			addAuditExpectedColumns(out, "Logical_Switch_Port", fields, "netloom_vpc", subnet.VPC, "netloom_subnet", subnet.Name, "netloom_provider_network", subnet.ProviderNetwork)
		}
	}
	for key, names := range expectedSwitchPorts(desired.Subnets, desired.Endpoints) {
		vpc, subnet, ok := splitStateKey(key)
		if !ok {
			continue
		}
		addAuditExpectedColumns(out, "Logical_Switch", map[string]string{
			"ports": stringSetField(names),
		}, "netloom_vpc", vpc, "netloom_subnet", subnet)
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
		if subnet, ok := desired.Subnets[subnetStateKey(endpoint.VPC, endpoint.Subnet)]; ok && subnet.DHCP.Enabled {
			if endpoint.IP.Is4() {
				fields["dhcpv4_options"] = dhcpOptionsRef("4", subnet.CIDR.String())
			}
			if endpoint.IP.Is6() {
				fields["dhcpv6_options"] = dhcpOptionsRef("6", subnet.CIDR.String())
			}
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
				if route.BFD.Enabled {
					bfdRow := desiredStaticRouteBFDRow(table, route.BFD, row)
					fields := map[string]string{
						"logical_port": bfdRow.LogicalPort,
						"dst_ip":       bfdRow.DstIP,
						"min_tx":       intPointerField(bfdRow.MinTx),
						"min_rx":       intPointerField(bfdRow.MinRx),
						"detect_mult":  intPointerField(bfdRow.DetectMult),
						"options":      mapField(bfdRow.Options),
					}
					addAuditExpectedColumns(out, "BFD", fields,
						"netloom_vpc", table.VPC,
						"netloom_route_table", table.Name,
						"netloom_route_key", row.ExternalIDs["netloom_route_key"],
						"netloom_route_bfd", staticRouteBFDRef(table.VPC, table.Name, row.ExternalIDs["netloom_route_key"]),
					)
				}
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
	if records := desiredOVNDNSRecords(desired.DNSRecords); len(records) > 0 {
		addAuditExpectedColumns(out, "DNS", map[string]string{
			"records": mapField(records),
		}, "netloom_dns", "desired")
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

func addAuditExpectedRowWithFields(out map[string]map[string]string, table string, fields map[string]string, keyValues ...string) {
	if len(keyValues)%2 != 0 {
		return
	}
	externalIDs := make(map[string]string, len(keyValues)/2)
	for i := 0; i < len(keyValues); i += 2 {
		externalIDs[keyValues[i]] = keyValues[i+1]
	}
	identity, complete := managedAuditIdentityForRow(table, "", externalIDs, fields)
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

func countManagedFieldDrift(table string, live, expected map[string]string) int {
	if expected == nil {
		return 0
	}
	drift := 0
	for key, value := range expected {
		if live[key] != value {
			drift++
		}
	}
	for key := range live {
		if !staleManagedExternalIDShouldDrift(table, key) {
			continue
		}
		if _, ok := expected[key]; !ok {
			drift++
		}
	}
	return drift
}

func staleManagedExternalIDShouldDrift(table, key string) bool {
	switch table {
	case "NAT":
		switch key {
		case "netloom_external_port", "netloom_target_port", "netloom_protocol":
			return true
		default:
			return false
		}
	case "Logical_Router":
		switch key {
		case "netloom_gateway", "netloom_gateway_lan_ip", "netloom_gateway_distributed", "netloom_external_if":
			return true
		default:
			return false
		}
	}
	return false
}

func countManagedProvidedFieldDrift(table string, live, expected map[string]string) int {
	drift := 0
	for key, value := range expected {
		liveValue, ok := live[key]
		if !ok {
			continue
		}
		if liveValue != value {
			drift++
		}
	}
	for key, value := range live {
		if !staleManagedColumnShouldDrift(table, key) || value == "" {
			continue
		}
		if isDefaultEnabledColumnValue(table, key, value) {
			continue
		}
		if _, ok := expected[key]; !ok {
			drift++
		}
	}
	return drift
}

func staleManagedColumnShouldDrift(table, key string) bool {
	switch table {
	case "Logical_Switch":
		switch key {
		case "acls", "forwarding_groups", "load_balancer_group", "qos_rules":
			return true
		default:
			return false
		}
	case "Logical_Router", "Logical_Router_Port":
		return key == "enabled" || (table == "Logical_Router" && (key == "options" || key == "load_balancer_group"))
	case "Logical_Switch_Port":
		switch key {
		case "type", "options", "tag", "enabled", "port_security", "dhcpv4_options", "dhcpv6_options":
			return true
		default:
			return false
		}
	case "NAT":
		switch key {
		case "external_port_range", "logical_port", "external_mac", "options":
			return true
		default:
			return false
		}
	case "Load_Balancer":
		switch key {
		case "options", "health_check_vips":
			return true
		default:
			return false
		}
	case "DNS":
		return key == "records" || key == "options"
	}
	return false
}

func isDefaultEnabledColumnValue(table, key, value string) bool {
	if key != "enabled" {
		return false
	}
	switch table {
	case "Logical_Router", "Logical_Router_Port", "Logical_Switch_Port":
		return strings.EqualFold(value, "true")
	default:
		return false
	}
}

func logicalSwitchColumnFields(subnet model.Subnet) map[string]string {
	fields := map[string]string{
		"name":         logicalSwitch(subnet.VPC, subnet.Name),
		"other_config": mapField(logicalSwitchOtherConfig(subnet)),
	}
	return fields
}

func routerPortIPv6RAConfigsField(subnet model.Subnet) string {
	if !subnet.CIDR.Addr().Is6() || !subnet.DHCP.Enabled {
		return ""
	}
	return mapField(map[string]string{"address_mode": "dhcpv6_stateful"})
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

func expectedRouterPorts(subnets map[string]model.Subnet) map[string][]string {
	out := make(map[string][]string)
	for _, subnet := range subnets {
		out[subnet.VPC] = append(out[subnet.VPC], routerPortName(logicalRouter(subnet.VPC), subnet.Name))
	}
	return out
}

func expectedSwitchPorts(subnets map[string]model.Subnet, endpoints map[string]model.Endpoint) map[string][]string {
	out := make(map[string][]string)
	for _, subnet := range subnets {
		key := subnetStateKey(subnet.VPC, subnet.Name)
		out[key] = append(out[key], switchRouterPortName(logicalSwitch(subnet.VPC, subnet.Name), subnet.Name))
		if subnet.ProviderNetwork != "" {
			out[key] = append(out[key], localnetPortName(logicalSwitch(subnet.VPC, subnet.Name), subnet.Name))
		}
	}
	for _, endpoint := range endpoints {
		key := subnetStateKey(endpoint.VPC, endpoint.Subnet)
		out[key] = append(out[key], logicalPort(endpoint.VPC, endpoint.ID))
	}
	return out
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

func parseManagedOVNRows(table string, columns, rows []string) []ManagedOVNRow {
	out := make([]ManagedOVNRow, 0, len(rows))
	for _, row := range rows {
		values, ok := parseAuditCSVRow(row)
		if !ok || len(values) < 2 {
			out = append(out, ManagedOVNRow{Table: table})
			continue
		}
		uuid := strings.Trim(strings.TrimSpace(values[0]), `"`)
		externalIDs := parseOVNMap(values[1])
		fields := make(map[string]string)
		for i := 2; i < len(columns) && i < len(values); i++ {
			fields[managedAuditFieldName(columns[i])] = normalizeManagedAuditField(columns[i], values[i])
		}
		out = append(out, ManagedOVNRow{
			Table:       table,
			UUID:        uuid,
			ExternalIDs: externalIDs,
			Fields:      fields,
		})
	}
	return out
}

func managedAuditFieldName(column string) string {
	if column == "nat" {
		return "nat_rules"
	}
	return column
}

func parseAuditCSVRow(row string) ([]string, bool) {
	reader := csv.NewReader(strings.NewReader(row))
	reader.FieldsPerRecord = -1
	values, err := reader.Read()
	if err != nil {
		return nil, false
	}
	return values, true
}

func normalizeManagedAuditField(column, value string) string {
	value = strings.TrimSpace(value)
	if value == "[]" {
		return ""
	}
	switch column {
	case "external_ids", "other_config", "options", "ipv6_ra_configs", "vips":
		return mapField(parseOVNMap(value))
	case "addresses", "port_security", "networks", "nexthops", "selection_fields", "ports", "load_balancers", "load_balancer_group", "nat", "policies", "static_routes", "acls", "forwarding_groups", "qos_rules":
		return stringSliceField(parseOVNList(value))
	case "tag":
		return strings.Trim(strings.TrimSpace(value), `"`)
	default:
		return trimOVNString(value)
	}
}

func parseOVNMap(value string) map[string]string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	value = strings.Trim(value, "{} ")
	out := make(map[string]string)
	if value == "" || value == "[]" {
		return out
	}
	for _, field := range splitOVNCollection(value) {
		key, rawValue, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		key = strings.Trim(strings.TrimSpace(key), `"{} `)
		rawValue = trimOVNString(strings.TrimSpace(rawValue))
		if key != "" {
			out[key] = rawValue
		}
	}
	return out
}

func parseOVNList(value string) []string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	value = strings.Trim(value, "[] ")
	if value == "" {
		return nil
	}
	parts := splitOVNCollection(value)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = trimOVNString(strings.TrimSpace(part))
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitOVNCollection(value string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	escaped := false
	for _, r := range value {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			current.WriteRune(r)
			escaped = true
		case r == '"':
			current.WriteRune(r)
			inQuotes = !inQuotes
		case r == ',' && !inQuotes:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	parts = append(parts, current.String())
	return parts
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
			return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_subnet", "netloom_provider_network")
		}
		return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_subnet", "netloom_role")
	case "Logical_Router_Port":
		return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_subnet")
	case "Logical_Router_Policy":
		return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_policy_route")
	case "Logical_Router_Static_Route":
		return auditIdentity(table, externalIDs, "netloom_vpc", "netloom_route_table", "netloom_route_key")
	case "BFD":
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
	case "DNS":
		return auditIdentity(table, externalIDs, "netloom_dns")
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
