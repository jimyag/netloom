package ovn

import (
	"context"
	"fmt"
	"reflect"

	"github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/ovnnb"
)

type LibOVSDBTopologyWriter struct {
	client client.Client
}

func NewLibOVSDBTopologyWriter(client client.Client) *LibOVSDBTopologyWriter {
	return &LibOVSDBTopologyWriter{client: client}
}

func (w *LibOVSDBTopologyWriter) EnsureVPC(ctx context.Context, vpc model.VPC) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	router := &ovnnb.LogicalRouter{
		Name:        logicalRouter(vpc.Name),
		ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": vpc.Name},
	}
	existing, ok, err := w.logicalRouterByName(ctx, router.Name)
	if err != nil {
		return err
	}
	var ops []ovsdb.Operation
	if !ok {
		ops, err = w.client.Create(router)
		if err != nil {
			return fmt.Errorf("create logical router %s: %w", router.Name, err)
		}
	} else {
		nextExternalIDs := mergeStringMap(existing.ExternalIDs, router.ExternalIDs)
		if reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) {
			return nil
		}
		existing.ExternalIDs = nextExternalIDs
		ops, err = w.client.Where(existing).Update(existing, &existing.ExternalIDs)
		if err != nil {
			return fmt.Errorf("update logical router %s external IDs: %w", router.Name, err)
		}
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("transact logical router %s: %w", router.Name, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("logical router %s operation errors=%+v: %w", router.Name, opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) EnsureSubnet(ctx context.Context, subnet model.Subnet) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ls := &ovnnb.LogicalSwitch{
		Name: logicalSwitch(subnet.VPC, subnet.Name),
		ExternalIDs: map[string]string{
			"netloom_owner":  "netloom",
			"netloom_vpc":    subnet.VPC,
			"netloom_subnet": subnet.Name,
		},
		OtherConfig: logicalSwitchOtherConfig(subnet),
	}
	existing, ok, err := w.logicalSwitchByName(ctx, ls.Name)
	if err != nil {
		return err
	}
	var ops []ovsdb.Operation
	if !ok {
		ops, err = w.client.Create(ls)
		if err != nil {
			return fmt.Errorf("create logical switch %s: %w", ls.Name, err)
		}
	} else {
		nextExternalIDs := mergeStringMap(existing.ExternalIDs, ls.ExternalIDs)
		nextOtherConfig := replaceLogicalSwitchIPAMConfig(existing.OtherConfig, ls.OtherConfig)
		if reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) && reflect.DeepEqual(existing.OtherConfig, nextOtherConfig) {
			return nil
		}
		existing.ExternalIDs = nextExternalIDs
		existing.OtherConfig = nextOtherConfig
		ops, err = w.client.Where(existing).Update(existing, &existing.ExternalIDs, &existing.OtherConfig)
		if err != nil {
			return fmt.Errorf("update logical switch %s: %w", ls.Name, err)
		}
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("transact logical switch %s: %w", ls.Name, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("logical switch %s operation errors=%+v: %w", ls.Name, opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) logicalRouterByName(ctx context.Context, name string) (*ovnnb.LogicalRouter, bool, error) {
	var routers []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == name }).List(ctx, &routers); err != nil {
		return nil, false, fmt.Errorf("list logical router %s from libovsdb cache: %w", name, err)
	}
	if len(routers) == 0 {
		return nil, false, nil
	}
	return &routers[0], true, nil
}

func (w *LibOVSDBTopologyWriter) logicalSwitchByName(ctx context.Context, name string) (*ovnnb.LogicalSwitch, bool, error) {
	var switches []ovnnb.LogicalSwitch
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == name }).List(ctx, &switches); err != nil {
		return nil, false, fmt.Errorf("list logical switch %s from libovsdb cache: %w", name, err)
	}
	if len(switches) == 0 {
		return nil, false, nil
	}
	return &switches[0], true, nil
}

func mergeStringMap(base map[string]string, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range overlay {
		out[key] = value
	}
	return out
}

func logicalSwitchOtherConfig(subnet model.Subnet) map[string]string {
	out := make(map[string]string)
	if subnet.CIDR.Addr().Is4() {
		out["subnet"] = subnet.CIDR.String()
		if excludeIPs := ovnExcludeIPs(subnet); excludeIPs != "" {
			out["exclude_ips"] = excludeIPs
		}
		return out
	}
	out["ipv6_prefix"] = subnet.CIDR.Masked().Addr().String()
	return out
}

func replaceLogicalSwitchIPAMConfig(base, desired map[string]string) map[string]string {
	out := cloneStringMap(base)
	if out == nil {
		out = make(map[string]string)
	}
	for _, key := range []string{"subnet", "exclude_ips", "ipv6_prefix"} {
		delete(out, key)
	}
	for key, value := range desired {
		out[key] = value
	}
	return out
}
