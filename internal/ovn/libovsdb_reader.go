package ovn

import (
	"context"
	"fmt"

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
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LogicalSwitch) (string, map[string]string) { return row.UUID, row.ExternalIDs }), nil
	case "Logical_Router":
		var rows []ovnnb.LogicalRouter
		if err := r.client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LogicalRouter) (string, map[string]string) { return row.UUID, row.ExternalIDs }), nil
	case "Logical_Switch_Port":
		var rows []ovnnb.LogicalSwitchPort
		if err := r.client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LogicalSwitchPort) (string, map[string]string) { return row.UUID, row.ExternalIDs }), nil
	case "Logical_Router_Port":
		var rows []ovnnb.LogicalRouterPort
		if err := r.client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LogicalRouterPort) (string, map[string]string) { return row.UUID, row.ExternalIDs }), nil
	case "Logical_Router_Policy":
		var rows []ovnnb.LogicalRouterPolicy
		if err := r.client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LogicalRouterPolicy) (string, map[string]string) { return row.UUID, row.ExternalIDs }), nil
	case "NAT":
		var rows []ovnnb.NAT
		if err := r.client.WhereCache(func(row *ovnnb.NAT) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.NAT) (string, map[string]string) { return row.UUID, row.ExternalIDs }), nil
	case "Load_Balancer":
		var rows []ovnnb.LoadBalancer
		if err := r.client.WhereCache(func(row *ovnnb.LoadBalancer) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LoadBalancer) (string, map[string]string) { return row.UUID, row.ExternalIDs }), nil
	case "Load_Balancer_Health_Check":
		var rows []ovnnb.LoadBalancerHealthCheck
		if err := r.client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.LoadBalancerHealthCheck) (string, map[string]string) {
			return row.UUID, row.ExternalIDs
		}), nil
	case "DHCP_Options":
		var rows []ovnnb.DHCPOptions
		if err := r.client.WhereCache(func(row *ovnnb.DHCPOptions) bool { return isNetloomManaged(row.ExternalIDs) }).List(ctx, &rows); err != nil {
			return nil, err
		}
		return managedOVNRowsFromModels(table, rows, func(row ovnnb.DHCPOptions) (string, map[string]string) { return row.UUID, row.ExternalIDs }), nil
	default:
		return nil, fmt.Errorf("unsupported managed OVN table %s", table)
	}
}

func isNetloomManaged(externalIDs map[string]string) bool {
	return externalIDs["netloom_owner"] == "netloom"
}

func managedOVNRowsFromModels[T any](table string, rows []T, identity func(T) (string, map[string]string)) []ManagedOVNRow {
	out := make([]ManagedOVNRow, 0, len(rows))
	for _, row := range rows {
		uuid, externalIDs := identity(row)
		out = append(out, ManagedOVNRow{
			Table:       table,
			UUID:        uuid,
			ExternalIDs: cloneStringMap(externalIDs),
		})
	}
	return out
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
