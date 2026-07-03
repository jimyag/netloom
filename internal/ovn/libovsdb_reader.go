package ovn

import (
	"context"
	"fmt"
	"sort"

	"github.com/ovn-kubernetes/libovsdb/client"

	"github.com/jimyag/netloom/internal/ovn/ovsdb/ovnnb"
)

type LibOVSDBManagedReader struct {
	client client.Client
}

func NewLibOVSDBManagedReader(client client.Client) *LibOVSDBManagedReader {
	return &LibOVSDBManagedReader{client: client}
}

func (r *LibOVSDBManagedReader) ManagedOVNRows(ctx context.Context, table string) ([]ManagedOVNRow, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("libovsdb managed reader has no client")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch table {
	case "Logical_Switch":
		var rows []ovnnb.LogicalSwitch
		if err := r.client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		loadBalancerNames, err := r.loadBalancerNames(ctx)
		if err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LogicalSwitch) (string, map[string]string, map[string]string) {
			return row.UUID, row.ExternalIDs, map[string]string{
				"name":           row.Name,
				"other_config":   mapField(row.OtherConfig),
				"load_balancers": loadBalancerNamesField(row.LoadBalancer, loadBalancerNames),
			}
		}), nil
	case "Logical_Router":
		var rows []ovnnb.LogicalRouter
		if err := r.client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		loadBalancerNames, err := r.loadBalancerNames(ctx)
		if err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LogicalRouter) (string, map[string]string, map[string]string) {
			return row.UUID, row.ExternalIDs, map[string]string{
				"name":           row.Name,
				"options":        mapField(row.Options),
				"load_balancers": loadBalancerNamesField(row.LoadBalancer, loadBalancerNames),
			}
		}), nil
	case "Logical_Switch_Port":
		var rows []ovnnb.LogicalSwitchPort
		if err := r.client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LogicalSwitchPort) (string, map[string]string, map[string]string) {
			return row.UUID, row.ExternalIDs, map[string]string{
				"name":          row.Name,
				"type":          row.Type,
				"addresses":     stringSliceField(row.Addresses),
				"port_security": stringSliceField(row.PortSecurity),
				"options":       mapField(row.Options),
				"tag":           intPointerField(row.Tag),
			}
		}), nil
	case "Logical_Router_Port":
		var rows []ovnnb.LogicalRouterPort
		if err := r.client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LogicalRouterPort) (string, map[string]string, map[string]string) {
			return row.UUID, row.ExternalIDs, map[string]string{"name": row.Name, "mac": row.MAC, "networks": stringSliceField(row.Networks)}
		}), nil
	case "Logical_Router_Policy":
		var rows []ovnnb.LogicalRouterPolicy
		if err := r.client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LogicalRouterPolicy) (string, map[string]string, map[string]string) {
			return row.UUID, row.ExternalIDs, map[string]string{
				"priority": fmt.Sprint(row.Priority),
				"match":    row.Match,
				"action":   string(row.Action),
				"nexthop":  pointerStringValue(row.Nexthop),
				"nexthops": stringSliceField(row.Nexthops),
			}
		}), nil
	case "Logical_Router_Static_Route":
		var rows []ovnnb.LogicalRouterStaticRoute
		if err := r.client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LogicalRouterStaticRoute) (string, map[string]string, map[string]string) {
			return row.UUID, row.ExternalIDs, map[string]string{
				"bfd":              pointerStringValue(row.BFD),
				"ip_prefix":        row.IPPrefix,
				"nexthop":          row.Nexthop,
				"options":          mapField(row.Options),
				"output_port":      pointerStringValue(row.OutputPort),
				"policy":           pointerStaticRoutePolicyValue(row.Policy),
				"route_table":      row.RouteTable,
				"selection_fields": staticRouteSelectionFieldsField(row.SelectionFields),
			}
		}), nil
	case "NAT":
		var rows []ovnnb.NAT
		if err := r.client.WhereCache(func(row *ovnnb.NAT) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.NAT) (string, map[string]string, map[string]string) {
			return row.UUID, row.ExternalIDs, map[string]string{
				"type":                string(row.Type),
				"external_ip":         row.ExternalIP,
				"logical_ip":          row.LogicalIP,
				"external_port_range": row.ExternalPortRange,
				"logical_port":        pointerStringValue(row.LogicalPort),
				"external_mac":        pointerStringValue(row.ExternalMAC),
				"options":             mapField(row.Options),
			}
		}), nil
	case "Load_Balancer":
		var rows []ovnnb.LoadBalancer
		if err := r.client.WhereCache(func(row *ovnnb.LoadBalancer) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		healthCheckVIPs, err := r.loadBalancerHealthCheckVIPs(ctx)
		if err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LoadBalancer) (string, map[string]string, map[string]string) {
			protocol := ""
			if row.Protocol != nil {
				protocol = string(*row.Protocol)
			}
			return row.UUID, row.ExternalIDs, map[string]string{
				"name":              row.Name,
				"vips":              mapField(row.Vips),
				"protocol":          protocol,
				"options":           mapField(row.Options),
				"selection_fields":  selectionFieldsField(row.SelectionFields),
				"health_check_vips": healthCheckVIPsField(row.HealthCheck, healthCheckVIPs),
			}
		}), nil
	case "Load_Balancer_Health_Check":
		var rows []ovnnb.LoadBalancerHealthCheck
		if err := r.client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LoadBalancerHealthCheck) (string, map[string]string, map[string]string) {
			return row.UUID, row.ExternalIDs, map[string]string{"vip": row.Vip, "options": mapField(row.Options)}
		}), nil
	case "DHCP_Options":
		var rows []ovnnb.DHCPOptions
		if err := r.client.WhereCache(func(row *ovnnb.DHCPOptions) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.DHCPOptions) (string, map[string]string, map[string]string) {
			return row.UUID, row.ExternalIDs, map[string]string{"cidr": row.Cidr, "options": mapField(row.Options)}
		}), nil
	default:
		return nil, fmt.Errorf("unsupported managed OVN table %s", table)
	}
}

func (r *LibOVSDBManagedReader) loadBalancerNames(ctx context.Context) (map[string]string, error) {
	var rows []ovnnb.LoadBalancer
	if err := r.client.WhereCache(func(row *ovnnb.LoadBalancer) bool { return row.Name != "" }).List(ctx, &rows); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		out[row.UUID] = row.Name
	}
	return out, nil
}

func loadBalancerNamesField(uuids []string, nameByUUID map[string]string) string {
	if len(uuids) == 0 {
		return ""
	}
	names := make([]string, 0, len(uuids))
	for _, uuid := range uuids {
		if name := nameByUUID[uuid]; name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return stringSliceField(names)
}

func (r *LibOVSDBManagedReader) loadBalancerHealthCheckVIPs(ctx context.Context) (map[string]string, error) {
	var rows []ovnnb.LoadBalancerHealthCheck
	if err := r.client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool { return row.Vip != "" }).List(ctx, &rows); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		out[row.UUID] = row.Vip
	}
	return out, nil
}

func healthCheckVIPsField(uuids []string, vipByUUID map[string]string) string {
	if len(uuids) == 0 {
		return ""
	}
	vips := make([]string, 0, len(uuids))
	for _, uuid := range uuids {
		if vip := vipByUUID[uuid]; vip != "" {
			vips = append(vips, vip)
		}
	}
	sort.Strings(vips)
	return stringSliceField(vips)
}

func isNetloomManaged(externalIDs map[string]string) bool {
	return externalIDs["netloom_owner"] == "netloom"
}

func managedOVNRowsFromModels[T any](table string, rows []T, identity func(T) (string, map[string]string, map[string]string)) []ManagedOVNRow {
	out := make([]ManagedOVNRow, 0, len(rows))
	for _, row := range rows {
		uuid, externalIDs, fields := identity(row)
		out = append(out, ManagedOVNRow{
			Table:       table,
			UUID:        uuid,
			ExternalIDs: cloneStringMap(externalIDs),
			Fields:      cloneStringMap(fields),
		})
	}
	return out
}

func intPointerField(value *int) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(*value)
}

func pointerStaticRoutePolicyValue(value *ovnnb.LogicalRouterStaticRoutePolicy) string {
	if value == nil {
		return ""
	}
	return *value
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
