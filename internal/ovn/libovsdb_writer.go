package ovn

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/ovn-kubernetes/libovsdb/client"
	ovsmodel "github.com/ovn-kubernetes/libovsdb/model"
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
	routerName := logicalRouter(subnet.VPC)
	router, ok, err := w.logicalRouterByName(ctx, routerName)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("logical router %s must exist before subnet %s", routerName, subnet.Name)
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
	existingSwitch, ok, err := w.logicalSwitchByName(ctx, ls.Name)
	if err != nil {
		return err
	}
	var ops []ovsdb.Operation
	if !ok {
		ls.UUID = ovsdbNamedUUID(ls.Name)
		ops, err = w.client.Create(ls)
		if err != nil {
			return fmt.Errorf("create logical switch %s: %w", ls.Name, err)
		}
	} else {
		nextExternalIDs := mergeStringMap(existingSwitch.ExternalIDs, ls.ExternalIDs)
		nextOtherConfig := replaceLogicalSwitchIPAMConfig(existingSwitch.OtherConfig, ls.OtherConfig)
		if !reflect.DeepEqual(existingSwitch.ExternalIDs, nextExternalIDs) || !reflect.DeepEqual(existingSwitch.OtherConfig, nextOtherConfig) {
			existingSwitch.ExternalIDs = nextExternalIDs
			existingSwitch.OtherConfig = nextOtherConfig
			updateOps, err := w.client.Where(existingSwitch).Update(existingSwitch, &existingSwitch.ExternalIDs, &existingSwitch.OtherConfig)
			if err != nil {
				return fmt.Errorf("update logical switch %s: %w", ls.Name, err)
			}
			ops = append(ops, updateOps...)
		}
	}
	subnetOps, err := w.subnetPortOperations(ctx, router, ls, existingSwitch, subnet)
	if err != nil {
		return err
	}
	ops = append(ops, subnetOps...)
	if len(ops) == 0 {
		return nil
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("transact subnet %s/%s: %w", subnet.VPC, subnet.Name, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("subnet %s/%s operation errors=%+v: %w", subnet.VPC, subnet.Name, opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) subnetPortOperations(ctx context.Context, router *ovnnb.LogicalRouter, logicalSwitch *ovnnb.LogicalSwitch, existingSwitch *ovnnb.LogicalSwitch, subnet model.Subnet) ([]ovsdb.Operation, error) {
	switchUUID := logicalSwitch.UUID
	switchPorts := logicalSwitch.Ports
	if existingSwitch != nil {
		switchUUID = existingSwitch.UUID
		switchPorts = existingSwitch.Ports
	}
	routerPort := &ovnnb.LogicalRouterPort{
		Name:        routerPortName(router.Name, subnet.Name),
		MAC:         deterministicMAC(subnet),
		Networks:    []string{subnet.Gateway.String() + "/" + fmt.Sprint(subnet.CIDR.Bits())},
		ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_subnet": subnet.Name},
	}
	if subnet.DHCP.Enabled && subnet.CIDR.Addr().Is6() {
		routerPort.Ipv6RaConfigs = map[string]string{"address_mode": "dhcpv6_stateful"}
	}
	switchPort := &ovnnb.LogicalSwitchPort{
		Name:        switchRouterPortName(logicalSwitch.Name, subnet.Name),
		Type:        "router",
		Addresses:   []string{routerPort.MAC},
		Options:     map[string]string{"router-port": routerPort.Name},
		ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_subnet": subnet.Name, "netloom_role": "router"},
	}
	var ops []ovsdb.Operation
	_, routerPortOps, err := w.ensureLogicalRouterPort(ctx, router, routerPort)
	if err != nil {
		return nil, err
	}
	ops = append(ops, routerPortOps...)
	_, switchPortOps, err := w.ensureLogicalSwitchPort(ctx, switchUUID, switchPorts, switchPort)
	if err != nil {
		return nil, err
	}
	ops = append(ops, switchPortOps...)
	if subnet.ProviderNetwork != "" {
		localnetPort := &ovnnb.LogicalSwitchPort{
			Name:        localnetPortName(logicalSwitch.Name, subnet.Name),
			Type:        "localnet",
			Addresses:   []string{"unknown"},
			Options:     map[string]string{"network_name": subnet.ProviderNetwork},
			ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_subnet": subnet.Name, "netloom_provider_network": subnet.ProviderNetwork},
		}
		if subnet.VLAN != 0 {
			tag := int(subnet.VLAN)
			localnetPort.Tag = &tag
		}
		_, localnetOps, err := w.ensureLogicalSwitchPort(ctx, switchUUID, switchPorts, localnetPort)
		if err != nil {
			return nil, err
		}
		ops = append(ops, localnetOps...)
	} else {
		localnetName := localnetPortName(logicalSwitch.Name, subnet.Name)
		existingLocalnet, ok, err := w.logicalSwitchPortByName(ctx, localnetName)
		if err != nil {
			return nil, err
		}
		if ok {
			deleteOps, err := w.deleteLogicalSwitchPort(switchUUID, existingLocalnet)
			if err != nil {
				return nil, err
			}
			ops = append(ops, deleteOps...)
		}
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) ensureLogicalRouterPort(ctx context.Context, router *ovnnb.LogicalRouter, desired *ovnnb.LogicalRouterPort) (string, []ovsdb.Operation, error) {
	existing, ok, err := w.logicalRouterPortByName(ctx, desired.Name)
	if err != nil {
		return "", nil, err
	}
	var ops []ovsdb.Operation
	if !ok {
		desired.UUID = ovsdbNamedUUID(desired.Name)
		createOps, err := w.client.Create(desired)
		if err != nil {
			return "", nil, fmt.Errorf("create logical router port %s: %w", desired.Name, err)
		}
		ops = append(ops, createOps...)
		mutateOps, err := w.client.Where(router).Mutate(router, ovsmodel.Mutation{
			Field:   &router.Ports,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{desired.UUID},
		})
		if err != nil {
			return "", nil, fmt.Errorf("attach logical router port %s to router %s: %w", desired.Name, router.Name, err)
		}
		ops = append(ops, mutateOps...)
		return desired.UUID, ops, nil
	}
	nextExternalIDs := mergeStringMap(existing.ExternalIDs, desired.ExternalIDs)
	nextIPv6RAConfigs := replaceManagedRouterPortRAConfig(existing.Ipv6RaConfigs, desired.Ipv6RaConfigs)
	if !containsString(router.Ports, existing.UUID) {
		mutateOps, err := w.client.Where(router).Mutate(router, ovsmodel.Mutation{
			Field:   &router.Ports,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{existing.UUID},
		})
		if err != nil {
			return "", nil, fmt.Errorf("attach logical router port %s to router %s: %w", desired.Name, router.Name, err)
		}
		ops = append(ops, mutateOps...)
	}
	if existing.MAC == desired.MAC &&
		reflect.DeepEqual(existing.Networks, desired.Networks) &&
		reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) &&
		reflect.DeepEqual(existing.Ipv6RaConfigs, nextIPv6RAConfigs) {
		return existing.UUID, ops, nil
	}
	existing.MAC = desired.MAC
	existing.Networks = desired.Networks
	existing.ExternalIDs = nextExternalIDs
	existing.Ipv6RaConfigs = nextIPv6RAConfigs
	updateOps, err := w.client.Where(existing).Update(existing, &existing.MAC, &existing.Networks, &existing.ExternalIDs, &existing.Ipv6RaConfigs)
	if err != nil {
		return "", nil, fmt.Errorf("update logical router port %s: %w", desired.Name, err)
	}
	ops = append(ops, updateOps...)
	return existing.UUID, ops, nil
}

func (w *LibOVSDBTopologyWriter) ensureLogicalSwitchPort(ctx context.Context, switchUUID string, switchPorts []string, desired *ovnnb.LogicalSwitchPort) (string, []ovsdb.Operation, error) {
	existing, ok, err := w.logicalSwitchPortByName(ctx, desired.Name)
	if err != nil {
		return "", nil, err
	}
	var ops []ovsdb.Operation
	if !ok {
		desired.UUID = ovsdbNamedUUID(desired.Name)
		createOps, err := w.client.Create(desired)
		if err != nil {
			return "", nil, fmt.Errorf("create logical switch port %s: %w", desired.Name, err)
		}
		ops = append(ops, createOps...)
		switchRow := &ovnnb.LogicalSwitch{UUID: switchUUID}
		mutateOps, err := w.client.Where(switchRow).Mutate(switchRow, ovsmodel.Mutation{
			Field:   &switchRow.Ports,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{desired.UUID},
		})
		if err != nil {
			return "", nil, fmt.Errorf("attach logical switch port %s to switch %s: %w", desired.Name, switchUUID, err)
		}
		ops = append(ops, mutateOps...)
		return desired.UUID, ops, nil
	}
	nextExternalIDs := mergeStringMap(existing.ExternalIDs, desired.ExternalIDs)
	nextTag := desired.Tag
	if !containsString(switchPorts, existing.UUID) {
		switchRow := &ovnnb.LogicalSwitch{UUID: switchUUID}
		mutateOps, err := w.client.Where(switchRow).Mutate(switchRow, ovsmodel.Mutation{
			Field:   &switchRow.Ports,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{existing.UUID},
		})
		if err != nil {
			return "", nil, fmt.Errorf("attach logical switch port %s to switch %s: %w", desired.Name, switchUUID, err)
		}
		ops = append(ops, mutateOps...)
	}
	if existing.Type == desired.Type &&
		reflect.DeepEqual(existing.Addresses, desired.Addresses) &&
		reflect.DeepEqual(existing.Options, desired.Options) &&
		reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) &&
		equalIntPointers(existing.Tag, nextTag) {
		return existing.UUID, ops, nil
	}
	existing.Type = desired.Type
	existing.Addresses = desired.Addresses
	existing.Options = desired.Options
	existing.ExternalIDs = nextExternalIDs
	existing.Tag = nextTag
	updateOps, err := w.client.Where(existing).Update(existing, &existing.Type, &existing.Addresses, &existing.Options, &existing.ExternalIDs, &existing.Tag)
	if err != nil {
		return "", nil, fmt.Errorf("update logical switch port %s: %w", desired.Name, err)
	}
	ops = append(ops, updateOps...)
	return existing.UUID, ops, nil
}

func (w *LibOVSDBTopologyWriter) deleteLogicalSwitchPort(switchUUID string, port *ovnnb.LogicalSwitchPort) ([]ovsdb.Operation, error) {
	switchRow := &ovnnb.LogicalSwitch{UUID: switchUUID}
	mutateOps, err := w.client.Where(switchRow).Mutate(switchRow, ovsmodel.Mutation{
		Field:   &switchRow.Ports,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{port.UUID},
	})
	if err != nil {
		return nil, fmt.Errorf("detach logical switch port %s from switch %s: %w", port.Name, switchUUID, err)
	}
	deleteOps, err := w.client.Where(port).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete logical switch port %s: %w", port.Name, err)
	}
	return append(mutateOps, deleteOps...), nil
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

func (w *LibOVSDBTopologyWriter) logicalRouterPortByName(ctx context.Context, name string) (*ovnnb.LogicalRouterPort, bool, error) {
	var ports []ovnnb.LogicalRouterPort
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool { return row.Name == name }).List(ctx, &ports); err != nil {
		return nil, false, fmt.Errorf("list logical router port %s from libovsdb cache: %w", name, err)
	}
	if len(ports) == 0 {
		return nil, false, nil
	}
	return &ports[0], true, nil
}

func (w *LibOVSDBTopologyWriter) logicalSwitchPortByName(ctx context.Context, name string) (*ovnnb.LogicalSwitchPort, bool, error) {
	var ports []ovnnb.LogicalSwitchPort
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == name }).List(ctx, &ports); err != nil {
		return nil, false, fmt.Errorf("list logical switch port %s from libovsdb cache: %w", name, err)
	}
	if len(ports) == 0 {
		return nil, false, nil
	}
	return &ports[0], true, nil
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

func replaceManagedRouterPortRAConfig(base, desired map[string]string) map[string]string {
	out := cloneStringMap(base)
	if out == nil {
		out = make(map[string]string)
	}
	delete(out, "address_mode")
	for key, value := range desired {
		out[key] = value
	}
	return out
}

func equalIntPointers(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func ovsdbNamedUUID(name string) string {
	return strings.TrimPrefix(namedUUID(name), "@")
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
