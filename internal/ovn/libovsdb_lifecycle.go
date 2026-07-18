package ovn

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	ovsmodel "github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/ovnnb"
	"github.com/jimyag/netloom/internal/topology"
)

func (w *LibOVSDBTopologyWriter) BeginTopologyReconcile(context.Context, topology.State) error {
	return nil
}

func (w *LibOVSDBTopologyWriter) CleanupTopology(ctx context.Context, state topology.State) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	next := snapshotDesired(state)
	ops, err := w.cleanupSnapshotDiffOperations(ctx, w.last, next)
	if err != nil {
		return err
	}
	stats := cleanupStats(w.last, next, !w.seen, len(ops))
	if !w.seen || len(ops) == 0 {
		liveOps, liveStats, err := w.cleanupUnexpectedLiveOperations(ctx, state)
		if err != nil {
			w.lastCleanup = stats
			return err
		}
		ops = append(liveOps, ops...)
		stats.add(liveStats)
		stats.Operations = len(ops)
	}
	if w.seen && len(ops) == 0 {
		repairOps, err := w.repairSteadyStateCoreNames(ctx, state)
		if err != nil {
			w.lastCleanup = stats
			return err
		}
		ops = append(ops, repairOps...)
		stats.Operations = len(ops)
	}
	if w.seen && len(ops) == 0 {
		repairOps, err := w.repairSteadyStateEndpointSwitchPorts(ctx, state)
		if err != nil {
			w.lastCleanup = stats
			return err
		}
		ops = append(ops, repairOps...)
		stats.Operations = len(ops)
	}
	if w.seen && len(ops) == 0 {
		repairOps, err := w.repairSteadyStateEndpointDHCPOptions(ctx, state)
		if err != nil {
			w.lastCleanup = stats
			return err
		}
		ops = append(ops, repairOps...)
		stats.Operations = len(ops)
	}
	if w.seen && len(ops) == 0 {
		repairOps, err := w.repairSteadyStateRoutes(ctx, state)
		if err != nil {
			w.lastCleanup = stats
			return err
		}
		ops = append(ops, repairOps...)
		stats.Operations = len(ops)
	}
	if w.seen && len(ops) == 0 {
		repairOps, err := w.repairSteadyStateGateways(ctx, state)
		if err != nil {
			w.lastCleanup = stats
			return err
		}
		ops = append(ops, repairOps...)
		stats.Operations = len(ops)
	}
	if w.seen && len(ops) == 0 {
		repairOps, err := w.repairSteadyStateDNSRecords(ctx, state)
		if err != nil {
			w.lastCleanup = stats
			return err
		}
		ops = append(ops, repairOps...)
		stats.Operations = len(ops)
	}
	if w.seen && len(ops) == 0 {
		repairOps, err := w.repairSteadyStateNATRules(ctx, state)
		if err != nil {
			w.lastCleanup = stats
			return err
		}
		ops = append(ops, repairOps...)
		stats.Operations = len(ops)
	}
	if w.seen && len(ops) == 0 {
		repairOps, err := w.repairSteadyStateLoadBalancers(ctx, state)
		if err != nil {
			w.lastCleanup = stats
			return err
		}
		ops = append(ops, repairOps...)
		stats.Operations = len(ops)
	}
	if w.seen && len(ops) == 0 {
		repairOps, err := w.repairSteadyStateSubnetPorts(ctx, state)
		if err != nil {
			w.lastCleanup = stats
			return err
		}
		ops = append(ops, repairOps...)
		stats.Operations = len(ops)
	}
	if err := w.transact(ctx, "cleanup OVN topology", ops); err != nil {
		w.lastCleanup = stats
		return err
	}
	w.last = next
	w.seen = true
	w.lastCleanup = stats
	return nil
}

func (w *LibOVSDBTopologyWriter) LastCleanupStats() CleanupStats {
	if w == nil {
		return CleanupStats{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastCleanup
}

func (w *LibOVSDBTopologyWriter) RestoreTopologyState(state topology.State) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.last = snapshotDesired(state)
	w.lastCleanup = CleanupStats{}
	w.seen = true
}

func (w *LibOVSDBTopologyWriter) cleanupSnapshotDiffOperations(ctx context.Context, old, next desiredSnapshot) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	for _, key := range staleKeys(old.Endpoints, next.Endpoints) {
		nextOps, err := w.deleteEndpointOperations(ctx, old.Endpoints[key])
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	for _, key := range staleKeys(old.Subnets, next.Subnets) {
		nextOps, err := w.deleteSubnetOperations(ctx, old.Subnets[key])
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	for _, key := range staleKeys(old.Routes, next.Routes) {
		nextOps, err := w.deleteStaticRouteDestinationOperations(ctx, old.Routes[key])
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	for _, key := range commonKeys(old.Routes, next.Routes) {
		if routeSignature(old.Routes[key]) == routeSignature(next.Routes[key]) {
			continue
		}
		nextOps, err := w.deleteStaticRouteDestinationOperations(ctx, old.Routes[key])
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	for _, key := range staleKeys(old.PolicyRoutes, next.PolicyRoutes) {
		nextOps, err := w.deletePolicyRouteByNameOperations(ctx, old.PolicyRoutes[key].Route.VPC, old.PolicyRoutes[key].Route.Name)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	for _, key := range commonKeys(old.PolicyRoutes, next.PolicyRoutes) {
		if policyRouteSignature(old.PolicyRoutes[key].Route) == policyRouteSignature(next.PolicyRoutes[key].Route) {
			continue
		}
		nextOps, err := w.deletePolicyRouteByNameOperations(ctx, old.PolicyRoutes[key].Route.VPC, old.PolicyRoutes[key].Route.Name)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	for _, key := range staleKeys(old.NATRules, next.NATRules) {
		nextOps, err := w.deleteNATRuleByNameOperations(ctx, old.NATRules[key].VPC, old.NATRules[key].Name)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	for _, key := range commonKeys(old.NATRules, next.NATRules) {
		if natRuleSignature(old.NATRules[key]) == natRuleSignature(next.NATRules[key]) {
			continue
		}
		nextOps, err := w.deleteNATRuleByNameOperations(ctx, old.NATRules[key].VPC, old.NATRules[key].Name)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	for _, key := range staleKeys(old.LoadBalancers, next.LoadBalancers) {
		nextOps, err := w.deleteLoadBalancerByIdentityOperations(ctx, old.LoadBalancers[key].VPC, old.LoadBalancers[key].Name)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	for _, key := range commonKeys(old.LoadBalancers, next.LoadBalancers) {
		if loadBalancerSignature(old.LoadBalancers[key]) == loadBalancerSignature(next.LoadBalancers[key]) {
			continue
		}
		nextOps, err := w.deleteLoadBalancerByIdentityOperations(ctx, old.LoadBalancers[key].VPC, old.LoadBalancers[key].Name)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	for _, key := range staleKeys(old.Gateways, next.Gateways) {
		nextOps, err := w.clearGatewayOperations(ctx, old.Gateways[key])
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	for _, key := range staleKeys(old.VPCs, next.VPCs) {
		nextOps, err := w.deleteVPCOperations(ctx, key)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) cleanupUnexpectedLiveOperations(ctx context.Context, desired topology.State) ([]ovsdb.Operation, CleanupStats, error) {
	expected := expectedManagedAuditRows(desired)
	staticRouteExpected := expectedStaticRouteRows(desired)
	bfdExpected := expectedStaticRouteBFDRows(desired)
	var ops []ovsdb.Operation
	var stats CleanupStats

	dhcpRows, err := w.unexpectedDHCPOptions(ctx, expected)
	if err != nil {
		return nil, CleanupStats{}, err
	}
	stats.StaleDHCPOptions += len(dhcpRows)
	for i := range dhcpRows {
		nextOps, err := w.deleteDHCPOptionsOperations(ctx, &dhcpRows[i])
		if err != nil {
			return nil, CleanupStats{}, err
		}
		ops = append(ops, nextOps...)
	}
	lspRows, err := w.unexpectedLogicalSwitchPorts(ctx, expected)
	if err != nil {
		return nil, CleanupStats{}, err
	}
	stats.StaleLogicalSwitchPorts += len(lspRows)
	for i := range lspRows {
		nextOps, err := w.deleteLogicalSwitchPortFromParents(&lspRows[i])
		if err != nil {
			return nil, CleanupStats{}, err
		}
		ops = append(ops, nextOps...)
	}
	lrpRows, err := w.unexpectedLogicalRouterPorts(ctx, expected)
	if err != nil {
		return nil, CleanupStats{}, err
	}
	stats.StaleLogicalRouterPorts += len(lrpRows)
	for i := range lrpRows {
		nextOps, err := w.deleteLogicalRouterPortFromParents(&lrpRows[i])
		if err != nil {
			return nil, CleanupStats{}, err
		}
		ops = append(ops, nextOps...)
	}
	staticRoutes, err := w.unexpectedStaticRoutes(ctx, expected, staticRouteExpected, desired.RouteTables)
	if err != nil {
		return nil, CleanupStats{}, err
	}
	stats.StaleRoutes += len(staticRoutes)
	for i := range staticRoutes {
		nextOps, err := w.deleteStaticRouteFromParents(&staticRoutes[i])
		if err != nil {
			return nil, CleanupStats{}, err
		}
		ops = append(ops, nextOps...)
	}
	bfdRows, err := w.unexpectedBFDs(ctx, bfdExpected)
	if err != nil {
		return nil, CleanupStats{}, err
	}
	stats.StaleBFDs += len(bfdRows)
	for i := range bfdRows {
		nextOps, err := w.deleteStaticRouteBFDByUUID(bfdRows[i].UUID)
		if err != nil {
			return nil, CleanupStats{}, err
		}
		ops = append(ops, nextOps...)
	}
	policyRows, err := w.unexpectedPolicyRoutes(ctx, expected, desired.PolicyRoutes)
	if err != nil {
		return nil, CleanupStats{}, err
	}
	stats.StalePolicyRoutes += len(policyRows)
	for i := range policyRows {
		nextOps, err := w.deletePolicyRouteFromParents(&policyRows[i])
		if err != nil {
			return nil, CleanupStats{}, err
		}
		ops = append(ops, nextOps...)
	}
	natRows, err := w.unexpectedNATRules(ctx, expected, desired.NATRules)
	if err != nil {
		return nil, CleanupStats{}, err
	}
	stats.StaleNATRules += len(natRows)
	for i := range natRows {
		nextOps, err := w.deleteNATRuleFromParents(&natRows[i])
		if err != nil {
			return nil, CleanupStats{}, err
		}
		ops = append(ops, nextOps...)
	}
	hcRows, err := w.unexpectedLoadBalancerHealthChecks(ctx, expected)
	if err != nil {
		return nil, CleanupStats{}, err
	}
	stats.StaleLBHealthChecks += len(hcRows)
	for i := range hcRows {
		nextOps, err := w.deleteLoadBalancerHealthCheckFromParents(&hcRows[i])
		if err != nil {
			return nil, CleanupStats{}, err
		}
		ops = append(ops, nextOps...)
	}
	gatewayOps, staleGateways, err := w.unexpectedGatewayMetadataOperations(ctx, desired)
	if err != nil {
		return nil, CleanupStats{}, err
	}
	stats.StaleGateways += staleGateways
	ops = append(ops, gatewayOps...)
	lbRows, err := w.unexpectedLoadBalancers(ctx, expected)
	if err != nil {
		return nil, CleanupStats{}, err
	}
	stats.StaleLoadBalancers += len(lbRows)
	for i := range lbRows {
		nextOps, err := w.deleteLoadBalancerFromParents(ctx, &lbRows[i])
		if err != nil {
			return nil, CleanupStats{}, err
		}
		ops = append(ops, nextOps...)
	}
	lsRows, err := w.unexpectedLogicalSwitches(ctx, expected, expectedLogicalSwitchNames(desired))
	if err != nil {
		return nil, CleanupStats{}, err
	}
	stats.StaleSubnets += len(lsRows)
	for i := range lsRows {
		deleteOps, err := w.client.Where(&lsRows[i]).Delete()
		if err != nil {
			return nil, CleanupStats{}, fmt.Errorf("delete unexpected logical switch %s: %w", lsRows[i].Name, err)
		}
		ops = append(ops, deleteOps...)
	}
	lrRows, err := w.unexpectedLogicalRouters(ctx, expected, expectedLogicalRouterNames(desired))
	if err != nil {
		return nil, CleanupStats{}, err
	}
	stats.StaleVPCs += len(lrRows)
	for i := range lrRows {
		deleteOps, err := w.client.Where(&lrRows[i]).Delete()
		if err != nil {
			return nil, CleanupStats{}, fmt.Errorf("delete unexpected logical router %s: %w", lrRows[i].Name, err)
		}
		ops = append(ops, deleteOps...)
	}
	return ops, stats, nil
}

func (w *LibOVSDBTopologyWriter) repairSteadyStateCoreNames(ctx context.Context, desired topology.State) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	vpcs := make([]string, 0, len(desired.VPCs))
	for name := range desired.VPCs {
		vpcs = append(vpcs, name)
	}
	sort.Strings(vpcs)
	for _, name := range vpcs {
		nextOps, err := w.repairLogicalRouterName(ctx, name, logicalRouter(name))
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
		router, ok, err := w.logicalRouterByName(ctx, logicalRouter(name))
		if err != nil {
			return nil, err
		}
		if ok && isNetloomManaged(router.ExternalIDs) {
			desiredRouter := &ovnnb.LogicalRouter{
				Name:        logicalRouter(name),
				ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": name},
			}
			nextOps, err = w.logicalRouterConfigOperations(router, desiredRouter, desiredHasGatewayForVPC(desired, name))
			if err != nil {
				return nil, err
			}
			ops = append(ops, nextOps...)
		}
	}
	subnets := make([]model.Subnet, 0, len(desired.Subnets))
	for _, subnet := range desired.Subnets {
		subnets = append(subnets, subnet)
	}
	sort.Slice(subnets, func(i, j int) bool {
		if subnets[i].VPC == subnets[j].VPC {
			return subnets[i].Name < subnets[j].Name
		}
		return subnets[i].VPC < subnets[j].VPC
	})
	for _, subnet := range subnets {
		nextOps, err := w.repairLogicalSwitchName(ctx, subnet.VPC, subnet.Name, logicalSwitch(subnet.VPC, subnet.Name))
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
		nextOps, err = w.repairLogicalRouterPortName(ctx, subnet.VPC, subnet.Name, routerPortName(logicalRouter(subnet.VPC), subnet.Name))
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
		nextOps, err = w.repairLogicalSwitchPortName(ctx, func(row *ovnnb.LogicalSwitchPort) bool {
			return row.ExternalIDs["netloom_owner"] == "netloom" &&
				row.ExternalIDs["netloom_vpc"] == subnet.VPC &&
				row.ExternalIDs["netloom_subnet"] == subnet.Name &&
				row.ExternalIDs["netloom_role"] == "router"
		}, switchRouterPortName(logicalSwitch(subnet.VPC, subnet.Name), subnet.Name))
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	endpoints := make([]model.Endpoint, 0, len(desired.Endpoints))
	for _, endpoint := range desired.Endpoints {
		endpoints = append(endpoints, endpoint)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].VPC == endpoints[j].VPC {
			return endpoints[i].ID < endpoints[j].ID
		}
		return endpoints[i].VPC < endpoints[j].VPC
	})
	for _, endpoint := range endpoints {
		endpointID := endpointExternalID(endpoint.VPC, endpoint.ID)
		nextOps, err := w.repairLogicalSwitchPortName(ctx, func(row *ovnnb.LogicalSwitchPort) bool {
			return row.ExternalIDs["netloom_owner"] == "netloom" &&
				row.ExternalIDs["netloom_vpc"] == endpoint.VPC &&
				row.ExternalIDs["netloom_endpoint"] == endpointID
		}, logicalPort(endpoint.VPC, endpoint.ID))
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) repairLogicalRouterName(ctx context.Context, vpc, desiredName string) ([]ovsdb.Operation, error) {
	var rows []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom" && row.ExternalIDs["netloom_vpc"] == vpc
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list logical router identity %s: %w", vpc, err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	var ops []ovsdb.Operation
	for i := range rows {
		if rows[i].Name == desiredName {
			continue
		}
		rows[i].Name = desiredName
		updateOps, err := w.client.Where(&rows[i]).Update(&rows[i], &rows[i].Name)
		if err != nil {
			return nil, fmt.Errorf("repair logical router name %s: %w", desiredName, err)
		}
		ops = append(ops, updateOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) repairLogicalSwitchName(ctx context.Context, vpc, subnet, desiredName string) ([]ovsdb.Operation, error) {
	var rows []ovnnb.LogicalSwitch
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitch) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom" &&
			row.ExternalIDs["netloom_vpc"] == vpc &&
			row.ExternalIDs["netloom_subnet"] == subnet
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list logical switch identity %s/%s: %w", vpc, subnet, err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	var ops []ovsdb.Operation
	for i := range rows {
		if rows[i].Name == desiredName {
			continue
		}
		rows[i].Name = desiredName
		updateOps, err := w.client.Where(&rows[i]).Update(&rows[i], &rows[i].Name)
		if err != nil {
			return nil, fmt.Errorf("repair logical switch name %s: %w", desiredName, err)
		}
		ops = append(ops, updateOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) repairLogicalRouterPortName(ctx context.Context, vpc, subnet, desiredName string) ([]ovsdb.Operation, error) {
	var rows []ovnnb.LogicalRouterPort
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom" &&
			row.ExternalIDs["netloom_vpc"] == vpc &&
			row.ExternalIDs["netloom_subnet"] == subnet
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list logical router port identity %s/%s: %w", vpc, subnet, err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	var ops []ovsdb.Operation
	for i := range rows {
		if rows[i].Name == desiredName {
			continue
		}
		rows[i].Name = desiredName
		updateOps, err := w.client.Where(&rows[i]).Update(&rows[i], &rows[i].Name)
		if err != nil {
			return nil, fmt.Errorf("repair logical router port name %s: %w", desiredName, err)
		}
		ops = append(ops, updateOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) repairLogicalSwitchPortName(ctx context.Context, match func(*ovnnb.LogicalSwitchPort) bool, desiredName string) ([]ovsdb.Operation, error) {
	var rows []ovnnb.LogicalSwitchPort
	if err := w.client.WhereCache(match).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list logical switch port identity %s: %w", desiredName, err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	var ops []ovsdb.Operation
	for i := range rows {
		if rows[i].Name == desiredName {
			continue
		}
		rows[i].Name = desiredName
		updateOps, err := w.client.Where(&rows[i]).Update(&rows[i], &rows[i].Name)
		if err != nil {
			return nil, fmt.Errorf("repair logical switch port name %s: %w", desiredName, err)
		}
		ops = append(ops, updateOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) repairSteadyStateSubnetPorts(ctx context.Context, desired topology.State) ([]ovsdb.Operation, error) {
	subnets := make([]model.Subnet, 0, len(desired.Subnets))
	for _, subnet := range desired.Subnets {
		subnets = append(subnets, subnet)
	}
	sort.Slice(subnets, func(i, j int) bool {
		if subnets[i].VPC == subnets[j].VPC {
			return subnets[i].Name < subnets[j].Name
		}
		return subnets[i].VPC < subnets[j].VPC
	})
	var ops []ovsdb.Operation
	for _, subnet := range subnets {
		router, ok, err := w.logicalRouterByName(ctx, logicalRouter(subnet.VPC))
		if err != nil {
			return nil, err
		}
		if !ok || !isNetloomManaged(router.ExternalIDs) {
			continue
		}
		switchName := logicalSwitch(subnet.VPC, subnet.Name)
		existingSwitch, ok, err := w.logicalSwitchByName(ctx, switchName)
		if err != nil {
			return nil, err
		}
		if !ok || !isNetloomManaged(existingSwitch.ExternalIDs) {
			continue
		}
		desiredSwitch := &ovnnb.LogicalSwitch{
			Name:        switchName,
			ExternalIDs: logicalSwitchExternalIDs(subnet),
			OtherConfig: logicalSwitchOtherConfig(subnet),
		}
		switchOps, err := w.logicalSwitchConfigOperations(existingSwitch, desiredSwitch)
		if err != nil {
			return nil, err
		}
		ops = append(ops, switchOps...)
		nextOps, err := w.subnetPortOperations(ctx, router, desiredSwitch, existingSwitch, subnet)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) repairSteadyStateEndpointSwitchPorts(ctx context.Context, desired topology.State) ([]ovsdb.Operation, error) {
	endpoints := make([]model.Endpoint, 0, len(desired.Endpoints))
	for _, endpoint := range desired.Endpoints {
		endpoints = append(endpoints, endpoint)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].VPC == endpoints[j].VPC {
			return endpoints[i].ID < endpoints[j].ID
		}
		return endpoints[i].VPC < endpoints[j].VPC
	})
	var ops []ovsdb.Operation
	for _, endpoint := range endpoints {
		switchRow, ok, err := w.logicalSwitchByName(ctx, logicalSwitch(endpoint.VPC, endpoint.Subnet))
		if err != nil {
			return nil, err
		}
		if !ok || !isNetloomManaged(switchRow.ExternalIDs) {
			continue
		}
		_, nextOps, err := w.ensureEndpointSwitchPort(ctx, switchRow.UUID, switchRow.Ports, desiredEndpointSwitchPort(endpoint))
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) repairSteadyStateEndpointDHCPOptions(ctx context.Context, desired topology.State) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	for _, endpoint := range desired.Endpoints {
		switchRow, ok, err := w.logicalSwitchByName(ctx, logicalSwitch(endpoint.VPC, endpoint.Subnet))
		if err != nil {
			return nil, err
		}
		if !ok || !isNetloomManaged(switchRow.ExternalIDs) {
			continue
		}
		port, ok, err := w.logicalSwitchPortByName(ctx, logicalPort(endpoint.VPC, endpoint.ID))
		if err != nil {
			return nil, err
		}
		if !ok || !isNetloomManaged(port.ExternalIDs) {
			continue
		}
		if switchRow.ExternalIDs["netloom_dhcp_enabled"] == "true" && endpoint.IP.IsValid() {
			routerPort, ok, err := w.logicalRouterPortByName(ctx, routerPortName(logicalRouter(endpoint.VPC), endpoint.Subnet))
			if err != nil {
				return nil, err
			}
			if !ok || !isNetloomManaged(routerPort.ExternalIDs) {
				continue
			}
		}
		nextOps, err := w.endpointDHCPOptionsOperations(ctx, endpoint, switchRow.ExternalIDs, port)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) repairSteadyStateRoutes(ctx context.Context, desired topology.State) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	for _, table := range desired.RouteTables {
		nextOps, err := w.routeTableOperations(ctx, table, false)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	for _, route := range desired.PolicyRoutes {
		nextOps, err := w.policyRouteOperations(ctx, route, false)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) repairSteadyStateGateways(ctx context.Context, desired topology.State) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	for _, gateway := range desired.Gateways {
		nextOps, err := w.gatewayOperations(ctx, gateway, false)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) repairSteadyStateDNSRecords(ctx context.Context, desired topology.State) ([]ovsdb.Operation, error) {
	subnets := make([]model.Subnet, 0, len(desired.Subnets))
	for _, subnet := range desired.Subnets {
		subnets = append(subnets, subnet)
	}
	sort.Slice(subnets, func(i, j int) bool {
		if subnets[i].VPC == subnets[j].VPC {
			return subnets[i].Name < subnets[j].Name
		}
		return subnets[i].VPC < subnets[j].VPC
	})
	return w.dnsRecordsOperations(ctx, subnets, desired.DNSRecords, false)
}

func (w *LibOVSDBTopologyWriter) repairSteadyStateNATRules(ctx context.Context, desired topology.State) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	for _, rule := range desired.NATRules {
		router, ok, err := w.logicalRouterByName(ctx, logicalRouter(rule.VPC))
		if err != nil {
			return nil, err
		}
		if !ok || !isNetloomManaged(router.ExternalIDs) {
			continue
		}
		existing, err := w.natRulesByName(ctx, rule.VPC, rule.Name)
		if err != nil {
			return nil, err
		}
		desiredRow := desiredNATRuleRow(rule)
		referenced, err := w.referencedNATRulesForDesired(ctx, router.Nat, desiredRow)
		if err != nil {
			return nil, err
		}
		existing = mergeNATRules(existing, referenced)
		if len(existing) == 0 {
			continue
		}
		keepIndex := preferredReferencedRow(router.Nat, existing, func(row ovnnb.NAT) string { return row.UUID })
		keep := existing[keepIndex]
		nextExternalIDs := mergeManagedExternalIDs(keep.ExternalIDs, desiredRow.ExternalIDs)
		if !containsString(router.Nat, keep.UUID) {
			attachOps, err := w.attachNATRule(router, keep.UUID)
			if err != nil {
				return nil, err
			}
			ops = append(ops, attachOps...)
		}
		if natRowChanged(keep, desiredRow, nextExternalIDs) {
			keep.Type = desiredRow.Type
			keep.ExternalIP = desiredRow.ExternalIP
			keep.LogicalIP = desiredRow.LogicalIP
			keep.ExternalPortRange = desiredRow.ExternalPortRange
			keep.Options = desiredRow.Options
			keep.LogicalPort = desiredRow.LogicalPort
			keep.ExternalMAC = desiredRow.ExternalMAC
			keep.AllowedExtIPs = desiredRow.AllowedExtIPs
			keep.ExemptedExtIPs = desiredRow.ExemptedExtIPs
			keep.GatewayPort = desiredRow.GatewayPort
			keep.Match = desiredRow.Match
			keep.Priority = desiredRow.Priority
			keep.ExternalIDs = nextExternalIDs
			updateOps, err := w.client.Where(&keep).Update(&keep, &keep.Type, &keep.ExternalIP, &keep.LogicalIP, &keep.ExternalPortRange, &keep.Options, &keep.LogicalPort, &keep.ExternalMAC, &keep.AllowedExtIPs, &keep.ExemptedExtIPs, &keep.GatewayPort, &keep.Match, &keep.Priority, &keep.ExternalIDs)
			if err != nil {
				return nil, fmt.Errorf("repair NAT rule %s/%s: %w", rule.VPC, rule.Name, err)
			}
			ops = append(ops, updateOps...)
		}
		for i := range existing {
			if i == keepIndex {
				continue
			}
			deleteOps, err := w.deleteNATRuleFromParents(&existing[i])
			if err != nil {
				return nil, err
			}
			ops = append(ops, deleteOps...)
		}
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) repairSteadyStateLoadBalancers(ctx context.Context, desired topology.State) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	for _, lb := range desired.LoadBalancers {
		router, ok, err := w.logicalRouterByName(ctx, logicalRouter(lb.VPC))
		if err != nil {
			return nil, err
		}
		if !ok || !isNetloomManaged(router.ExternalIDs) {
			continue
		}
		switches, err := w.logicalSwitchesForLoadBalancer(ctx, lb)
		if err != nil {
			return nil, err
		}
		frontendsByProtocol := loadBalancerFrontendsByProtocol(lb)
		for _, protocol := range sortedLoadBalancerProtocols(frontendsByProtocol) {
			desiredRow := desiredLoadBalancerRow(lb, protocol, frontendsByProtocol[protocol])
			existing, ok, err := w.loadBalancerByName(ctx, desiredRow.Name)
			if err != nil {
				return nil, err
			}
			if !ok || !isNetloomManaged(existing.ExternalIDs) {
				continue
			}
			parentOps, err := w.repairSteadyStateLoadBalancerParentRefs(ctx, existing.UUID, router, switches)
			if err != nil {
				return nil, err
			}
			ops = append(ops, parentOps...)
			nextExternalIDs := mergeManagedExternalIDs(existing.ExternalIDs, desiredRow.ExternalIDs)
			nextOptions := replaceManagedLoadBalancerOptions(existing.Options, desiredRow.Options)
			clearMappingOps, err := w.clearLoadBalancerIPPortMappings(existing)
			if err != nil {
				return nil, err
			}
			ops = append(ops, clearMappingOps...)
			if !reflect.DeepEqual(existing.Vips, desiredRow.Vips) ||
				!reflect.DeepEqual(existing.Protocol, desiredRow.Protocol) ||
				!reflect.DeepEqual(existing.SelectionFields, desiredRow.SelectionFields) ||
				!reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) ||
				!reflect.DeepEqual(existing.Options, nextOptions) {
				existing.Vips = desiredRow.Vips
				existing.Protocol = desiredRow.Protocol
				existing.SelectionFields = desiredRow.SelectionFields
				existing.ExternalIDs = nextExternalIDs
				existing.Options = nextOptions
				updateOps, err := w.client.Where(existing).Update(existing, &existing.Vips, &existing.Protocol, &existing.SelectionFields, &existing.ExternalIDs, &existing.Options)
				if err != nil {
					return nil, fmt.Errorf("repair load balancer %s columns: %w", existing.Name, err)
				}
				ops = append(ops, updateOps...)
			}
			hcOps, err := w.repairSteadyStateLoadBalancerHealthCheckRefs(ctx, existing, lb, protocol, frontendsByProtocol[protocol])
			if err != nil {
				return nil, err
			}
			ops = append(ops, hcOps...)
		}
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) repairSteadyStateLoadBalancerParentRefs(ctx context.Context, lbUUID string, router *ovnnb.LogicalRouter, desiredSwitches []ovnnb.LogicalSwitch) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	if !containsString(router.LoadBalancer, lbUUID) {
		attachOps, err := w.attachLoadBalancerToRouter(router, lbUUID)
		if err != nil {
			return nil, err
		}
		ops = append(ops, attachOps...)
	}
	var attachedRouters []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool {
		return isNetloomManaged(row.ExternalIDs) && containsString(row.LoadBalancer, lbUUID)
	}).List(ctx, &attachedRouters); err != nil {
		return nil, fmt.Errorf("list logical routers for load balancer attachment %s: %w", lbUUID, err)
	}
	sort.Slice(attachedRouters, func(i, j int) bool { return attachedRouters[i].UUID < attachedRouters[j].UUID })
	for i := range attachedRouters {
		if attachedRouters[i].UUID == router.UUID {
			continue
		}
		detachOps, err := w.detachLoadBalancerFromRouter(attachedRouters[i].UUID, lbUUID)
		if err != nil {
			return nil, err
		}
		ops = append(ops, detachOps...)
	}
	desiredSwitchUUIDs := make(map[string]struct{}, len(desiredSwitches))
	for i := range desiredSwitches {
		desiredSwitchUUIDs[desiredSwitches[i].UUID] = struct{}{}
		if containsString(desiredSwitches[i].LoadBalancer, lbUUID) {
			continue
		}
		attachOps, err := w.attachLoadBalancerToSwitch(&desiredSwitches[i], lbUUID)
		if err != nil {
			return nil, err
		}
		ops = append(ops, attachOps...)
	}
	var attachedSwitches []ovnnb.LogicalSwitch
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitch) bool {
		return isNetloomManaged(row.ExternalIDs) && containsString(row.LoadBalancer, lbUUID)
	}).List(ctx, &attachedSwitches); err != nil {
		return nil, fmt.Errorf("list logical switches for load balancer attachment %s: %w", lbUUID, err)
	}
	sort.Slice(attachedSwitches, func(i, j int) bool { return attachedSwitches[i].UUID < attachedSwitches[j].UUID })
	for i := range attachedSwitches {
		if _, ok := desiredSwitchUUIDs[attachedSwitches[i].UUID]; ok {
			continue
		}
		detachOps, err := w.detachLoadBalancerFromSwitch(attachedSwitches[i].UUID, lbUUID)
		if err != nil {
			return nil, err
		}
		ops = append(ops, detachOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) repairSteadyStateLoadBalancerHealthCheckRefs(ctx context.Context, lbRow *ovnnb.LoadBalancer, lb model.LoadBalancer, protocol model.Protocol, frontends []model.LoadBalancerFrontend) ([]ovsdb.Operation, error) {
	hcRows, err := w.healthChecksForLoadBalancerRow(ctx, lbRow)
	if err != nil {
		return nil, err
	}
	existingByVIP := make(map[string][]ovnnb.LoadBalancerHealthCheck, len(hcRows))
	for _, hc := range hcRows {
		existingByVIP[hc.Vip] = append(existingByVIP[hc.Vip], hc)
	}
	var ops []ovsdb.Operation
	lbRef := &ovnnb.LoadBalancer{UUID: lbRow.UUID}
	if lb.HealthCheck.Enabled {
		for _, frontend := range frontends {
			desired := desiredLoadBalancerHealthCheck(lb, frontend)
			rows := existingByVIP[desired.Vip]
			if len(rows) == 0 {
				desired.UUID = ovsdbNamedUUID("nl_lbhc_" + lb.VPC + "_" + lb.Name + "_" + desired.Vip)
				createOps, err := w.client.Create(&desired)
				if err != nil {
					return nil, fmt.Errorf("repair create load balancer health check %s: %w", desired.Vip, err)
				}
				ops = append(ops, createOps...)
				insertOps, err := w.client.Where(lbRef).Mutate(lbRef, ovsmodel.Mutation{
					Field:   &lbRef.HealthCheck,
					Mutator: ovsdb.MutateOperationInsert,
					Value:   []string{desired.UUID},
				})
				if err != nil {
					return nil, fmt.Errorf("repair attach load balancer health check %s: %w", desired.UUID, err)
				}
				ops = append(ops, insertOps...)
				continue
			}
			keepIndex := preferredReferencedRow(lbRow.HealthCheck, rows, func(row ovnnb.LoadBalancerHealthCheck) string { return row.UUID })
			keep := rows[keepIndex]
			nextExternalIDs := mergeManagedExternalIDs(keep.ExternalIDs, desired.ExternalIDs)
			if keep.Vip != desired.Vip || !reflect.DeepEqual(keep.Options, desired.Options) || !reflect.DeepEqual(keep.ExternalIDs, nextExternalIDs) {
				keep.Vip = desired.Vip
				keep.Options = desired.Options
				keep.ExternalIDs = nextExternalIDs
				updateOps, err := w.client.Where(&keep).Update(&keep, &keep.Vip, &keep.Options, &keep.ExternalIDs)
				if err != nil {
					return nil, fmt.Errorf("repair update load balancer health check %s: %w", keep.UUID, err)
				}
				ops = append(ops, updateOps...)
			}
			if !containsString(lbRow.HealthCheck, keep.UUID) {
				insertOps, err := w.client.Where(lbRef).Mutate(lbRef, ovsmodel.Mutation{
					Field:   &lbRef.HealthCheck,
					Mutator: ovsdb.MutateOperationInsert,
					Value:   []string{keep.UUID},
				})
				if err != nil {
					return nil, fmt.Errorf("repair load balancer %s health check attachment %s: %w", lbRow.Name, keep.UUID, err)
				}
				ops = append(ops, insertOps...)
			}
			for i := range rows {
				if i == keepIndex {
					continue
				}
				deleteOps, err := w.deleteLoadBalancerHealthCheckFromParents(&rows[i])
				if err != nil {
					return nil, err
				}
				ops = append(ops, deleteOps...)
			}
		}
	}
	desiredVIPs := make(map[string]struct{}, len(frontends))
	if lb.HealthCheck.Enabled {
		for _, frontend := range frontends {
			desiredVIPs[loadBalancerFrontendVIP(frontend)] = struct{}{}
		}
	}
	removedUUIDs := make(map[string]struct{})
	desiredUUIDs := make(map[string]struct{})
	for vip, rows := range existingByVIP {
		if _, ok := desiredVIPs[vip]; ok {
			if len(rows) > 0 {
				keepIndex := preferredReferencedRow(lbRow.HealthCheck, rows, func(row ovnnb.LoadBalancerHealthCheck) string { return row.UUID })
				desiredUUIDs[rows[keepIndex].UUID] = struct{}{}
			}
			continue
		}
		for i := range rows {
			deleteOps, err := w.deleteLoadBalancerHealthCheckFromParents(&rows[i])
			if err != nil {
				return nil, err
			}
			removedUUIDs[rows[i].UUID] = struct{}{}
			ops = append(ops, deleteOps...)
		}
	}
	for _, uuid := range lbRow.HealthCheck {
		if _, ok := desiredUUIDs[uuid]; ok {
			continue
		}
		if _, ok := removedUUIDs[uuid]; ok {
			continue
		}
		deleteOps, err := w.client.Where(lbRef).Mutate(lbRef, ovsmodel.Mutation{
			Field:   &lbRef.HealthCheck,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{uuid},
		})
		if err != nil {
			return nil, fmt.Errorf("repair load balancer %s stale health check attachment %s: %w", lbRow.Name, uuid, err)
		}
		ops = append(ops, deleteOps...)
	}
	return ops, nil
}

func (s *CleanupStats) add(other CleanupStats) {
	s.StaleVPCs += other.StaleVPCs
	s.StaleSubnets += other.StaleSubnets
	s.StaleEndpoints += other.StaleEndpoints
	s.StaleRoutes += other.StaleRoutes
	s.StaleBFDs += other.StaleBFDs
	s.ChangedRoutes += other.ChangedRoutes
	s.StalePolicyRoutes += other.StalePolicyRoutes
	s.ChangedPolicyRoutes += other.ChangedPolicyRoutes
	s.StaleGateways += other.StaleGateways
	s.StaleNATRules += other.StaleNATRules
	s.ChangedNATRules += other.ChangedNATRules
	s.StaleLoadBalancers += other.StaleLoadBalancers
	s.ChangedLoadBalancers += other.ChangedLoadBalancers
	s.StaleLoadBalancerSubnets += other.StaleLoadBalancerSubnets
	s.StaleLoadBalancerVIPs += other.StaleLoadBalancerVIPs
	s.StaleLogicalSwitchPorts += other.StaleLogicalSwitchPorts
	s.StaleLogicalRouterPorts += other.StaleLogicalRouterPorts
	s.StaleDHCPOptions += other.StaleDHCPOptions
	s.StaleLBHealthChecks += other.StaleLBHealthChecks
}

func (w *LibOVSDBTopologyWriter) deleteEndpointOperations(ctx context.Context, endpoint model.Endpoint) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	for _, family := range []int{4, 6} {
		rows, err := w.endpointDHCPOptionsByFamily(ctx, endpoint, family)
		if err != nil {
			return nil, err
		}
		for i := range rows {
			nextOps, err := w.deleteDHCPOptionsOperations(ctx, &rows[i])
			if err != nil {
				return nil, err
			}
			ops = append(ops, nextOps...)
		}
	}
	port, ok, err := w.logicalSwitchPortByName(ctx, logicalPort(endpoint.VPC, endpoint.ID))
	if err != nil || !ok {
		return ops, err
	}
	nextOps, err := w.deleteLogicalSwitchPortFromParents(port)
	if err != nil {
		return nil, err
	}
	return append(ops, nextOps...), nil
}

func (w *LibOVSDBTopologyWriter) deleteSubnetOperations(ctx context.Context, subnet model.Subnet) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	switchName := logicalSwitch(subnet.VPC, subnet.Name)
	for _, portName := range []string{
		localnetPortName(switchName, subnet.Name),
		switchRouterPortName(switchName, subnet.Name),
	} {
		port, ok, err := w.logicalSwitchPortByName(ctx, portName)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		nextOps, err := w.deleteLogicalSwitchPortFromParents(port)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	routerPort, ok, err := w.logicalRouterPortByName(ctx, routerPortName(logicalRouter(subnet.VPC), subnet.Name))
	if err != nil {
		return nil, err
	}
	if ok {
		nextOps, err := w.deleteLogicalRouterPortFromParents(routerPort)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	sw, ok, err := w.logicalSwitchByName(ctx, switchName)
	if err != nil {
		return nil, err
	}
	if ok {
		deleteOps, err := w.client.Where(sw).Delete()
		if err != nil {
			return nil, fmt.Errorf("delete logical switch %s: %w", sw.Name, err)
		}
		ops = append(ops, deleteOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) deleteVPCOperations(ctx context.Context, vpc string) ([]ovsdb.Operation, error) {
	router, ok, err := w.logicalRouterByName(ctx, logicalRouter(vpc))
	if err != nil || !ok {
		return nil, err
	}
	return w.client.Where(router).Delete()
}

func (w *LibOVSDBTopologyWriter) deleteStaticRouteDestinationOperations(ctx context.Context, record routeRecord) ([]ovsdb.Operation, error) {
	rows, err := w.staticRoutesByVPCAndDestination(ctx, record.VPC, record.Route.Destination.String())
	if err != nil {
		return nil, err
	}
	var ops []ovsdb.Operation
	for i := range rows {
		nextOps, err := w.deleteStaticRouteFromParents(&rows[i])
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) deletePolicyRouteByNameOperations(ctx context.Context, vpc, name string) ([]ovsdb.Operation, error) {
	rows, err := w.policyRoutesByName(ctx, vpc, name)
	if err != nil {
		return nil, err
	}
	var ops []ovsdb.Operation
	for i := range rows {
		nextOps, err := w.deletePolicyRouteFromParents(&rows[i])
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) deleteNATRuleByNameOperations(ctx context.Context, vpc, name string) ([]ovsdb.Operation, error) {
	rows, err := w.natRulesByName(ctx, vpc, name)
	if err != nil {
		return nil, err
	}
	var ops []ovsdb.Operation
	for i := range rows {
		nextOps, err := w.deleteNATRuleFromParents(&rows[i])
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) deleteLoadBalancerByIdentityOperations(ctx context.Context, vpc, name string) ([]ovsdb.Operation, error) {
	rows, err := w.loadBalancersByIdentity(ctx, vpc, name)
	if err != nil {
		return nil, err
	}
	var ops []ovsdb.Operation
	for i := range rows {
		nextOps, err := w.deleteLoadBalancerFromParents(ctx, &rows[i])
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) clearGatewayOperations(ctx context.Context, gateway model.Gateway) ([]ovsdb.Operation, error) {
	router, ok, err := w.logicalRouterByName(ctx, logicalRouter(gateway.VPC))
	if err != nil || !ok {
		return nil, err
	}
	return w.clearGatewayRouterOperations(router)
}

func (w *LibOVSDBTopologyWriter) clearGatewayRouterOperations(router *ovnnb.LogicalRouter) ([]ovsdb.Operation, error) {
	nextExternalIDs := clearGatewayExternalIDs(router.ExternalIDs)
	nextOptions := clearGatewayRouterOptions(router.Options)
	if equalStringMaps(router.ExternalIDs, nextExternalIDs) && equalStringMaps(router.Options, nextOptions) {
		return nil, nil
	}
	router.ExternalIDs = nextExternalIDs
	router.Options = nextOptions
	return w.client.Where(router).Update(router, &router.ExternalIDs, &router.Options)
}

func (w *LibOVSDBTopologyWriter) unexpectedGatewayMetadataOperations(ctx context.Context, desired topology.State) ([]ovsdb.Operation, int, error) {
	desiredVPCs := make(map[string]struct{}, len(desired.VPCs))
	for name := range desired.VPCs {
		desiredVPCs[name] = struct{}{}
	}
	desiredGatewayVPCs := make(map[string]struct{}, len(desired.Gateways))
	for _, gateway := range desired.Gateways {
		desiredGatewayVPCs[gateway.VPC] = struct{}{}
	}
	var routers []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool {
		return isNetloomManaged(row.ExternalIDs)
	}).List(ctx, &routers); err != nil {
		return nil, 0, fmt.Errorf("list logical routers for stale gateway metadata: %w", err)
	}
	sort.Slice(routers, func(i, j int) bool { return routers[i].UUID < routers[j].UUID })
	var ops []ovsdb.Operation
	var stale int
	for i := range routers {
		vpc := routers[i].ExternalIDs["netloom_vpc"]
		if _, ok := desiredVPCs[vpc]; !ok {
			continue
		}
		if _, ok := desiredGatewayVPCs[vpc]; ok || !hasGatewayRouterMetadata(routers[i]) {
			continue
		}
		nextOps, err := w.clearGatewayRouterOperations(&routers[i])
		if err != nil {
			return nil, 0, err
		}
		ops = append(ops, nextOps...)
		stale++
	}
	return ops, stale, nil
}

func hasGatewayRouterMetadata(router ovnnb.LogicalRouter) bool {
	for key := range router.ExternalIDs {
		if isGatewayExternalID(key) {
			return true
		}
	}
	_, ok := router.Options["chassis"]
	return ok
}

func (w *LibOVSDBTopologyWriter) deleteLogicalSwitchPortFromParents(port *ovnnb.LogicalSwitchPort) ([]ovsdb.Operation, error) {
	var switches []ovnnb.LogicalSwitch
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitch) bool {
		return containsString(row.Ports, port.UUID)
	}).List(context.Background(), &switches); err != nil {
		return nil, fmt.Errorf("list logical switches for port %s: %w", port.Name, err)
	}
	var ops []ovsdb.Operation
	for i := range switches {
		nextOps, err := w.client.Where(&switches[i]).Mutate(&switches[i], ovsmodel.Mutation{
			Field:   &switches[i].Ports,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{port.UUID},
		})
		if err != nil {
			return nil, fmt.Errorf("detach logical switch port %s from switch %s: %w", port.Name, switches[i].Name, err)
		}
		ops = append(ops, nextOps...)
	}
	deleteOps, err := w.client.Where(port).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete logical switch port %s: %w", port.Name, err)
	}
	return append(ops, deleteOps...), nil
}

func (w *LibOVSDBTopologyWriter) deleteLogicalRouterPortFromParents(port *ovnnb.LogicalRouterPort) ([]ovsdb.Operation, error) {
	var routers []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool {
		return containsString(row.Ports, port.UUID)
	}).List(context.Background(), &routers); err != nil {
		return nil, fmt.Errorf("list logical routers for port %s: %w", port.Name, err)
	}
	var ops []ovsdb.Operation
	for i := range routers {
		nextOps, err := w.client.Where(&routers[i]).Mutate(&routers[i], ovsmodel.Mutation{
			Field:   &routers[i].Ports,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{port.UUID},
		})
		if err != nil {
			return nil, fmt.Errorf("detach logical router port %s from router %s: %w", port.Name, routers[i].Name, err)
		}
		ops = append(ops, nextOps...)
	}
	deleteOps, err := w.client.Where(port).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete logical router port %s: %w", port.Name, err)
	}
	return append(ops, deleteOps...), nil
}

func (w *LibOVSDBTopologyWriter) deleteStaticRouteFromParents(route *ovnnb.LogicalRouterStaticRoute) ([]ovsdb.Operation, error) {
	var routers []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool {
		return containsString(row.StaticRoutes, route.UUID)
	}).List(context.Background(), &routers); err != nil {
		return nil, fmt.Errorf("list logical routers for static route %s: %w", route.UUID, err)
	}
	var ops []ovsdb.Operation
	for i := range routers {
		nextOps, err := w.client.Where(&routers[i]).Mutate(&routers[i], ovsmodel.Mutation{
			Field:   &routers[i].StaticRoutes,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{route.UUID},
		})
		if err != nil {
			return nil, fmt.Errorf("detach static route %s from router %s: %w", route.UUID, routers[i].Name, err)
		}
		ops = append(ops, nextOps...)
	}
	deleteOps, err := w.client.Where(route).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete static route %s: %w", route.UUID, err)
	}
	ops = append(ops, deleteOps...)
	if route.BFD != nil {
		bfdOps, err := w.deleteStaticRouteBFDByUUID(*route.BFD)
		if err != nil {
			return nil, err
		}
		ops = append(ops, bfdOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) deletePolicyRouteFromParents(route *ovnnb.LogicalRouterPolicy) ([]ovsdb.Operation, error) {
	var routers []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool {
		return containsString(row.Policies, route.UUID)
	}).List(context.Background(), &routers); err != nil {
		return nil, fmt.Errorf("list logical routers for policy route %s: %w", route.UUID, err)
	}
	var ops []ovsdb.Operation
	for i := range routers {
		nextOps, err := w.client.Where(&routers[i]).Mutate(&routers[i], ovsmodel.Mutation{
			Field:   &routers[i].Policies,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{route.UUID},
		})
		if err != nil {
			return nil, fmt.Errorf("detach policy route %s from router %s: %w", route.UUID, routers[i].Name, err)
		}
		ops = append(ops, nextOps...)
	}
	deleteOps, err := w.client.Where(route).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete policy route %s: %w", route.UUID, err)
	}
	return append(ops, deleteOps...), nil
}

func (w *LibOVSDBTopologyWriter) deleteNATRuleFromParents(nat *ovnnb.NAT) ([]ovsdb.Operation, error) {
	var routers []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool {
		return containsString(row.Nat, nat.UUID)
	}).List(context.Background(), &routers); err != nil {
		return nil, fmt.Errorf("list logical routers for NAT %s: %w", nat.UUID, err)
	}
	var ops []ovsdb.Operation
	for i := range routers {
		nextOps, err := w.client.Where(&routers[i]).Mutate(&routers[i], ovsmodel.Mutation{
			Field:   &routers[i].Nat,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{nat.UUID},
		})
		if err != nil {
			return nil, fmt.Errorf("detach NAT %s from router %s: %w", nat.UUID, routers[i].Name, err)
		}
		ops = append(ops, nextOps...)
	}
	deleteOps, err := w.client.Where(nat).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete NAT %s: %w", nat.UUID, err)
	}
	return append(ops, deleteOps...), nil
}

func (w *LibOVSDBTopologyWriter) deleteLoadBalancerHealthCheckFromParents(hc *ovnnb.LoadBalancerHealthCheck) ([]ovsdb.Operation, error) {
	var lbs []ovnnb.LoadBalancer
	if err := w.client.WhereCache(func(row *ovnnb.LoadBalancer) bool {
		return containsString(row.HealthCheck, hc.UUID)
	}).List(context.Background(), &lbs); err != nil {
		return nil, fmt.Errorf("list load balancers for health check %s: %w", hc.UUID, err)
	}
	var ops []ovsdb.Operation
	for i := range lbs {
		nextOps, err := w.client.Where(&lbs[i]).Mutate(&lbs[i], ovsmodel.Mutation{
			Field:   &lbs[i].HealthCheck,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{hc.UUID},
		})
		if err != nil {
			return nil, fmt.Errorf("detach load balancer health check %s from %s: %w", hc.UUID, lbs[i].Name, err)
		}
		ops = append(ops, nextOps...)
	}
	deleteOps, err := w.client.Where(hc).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete load balancer health check %s: %w", hc.UUID, err)
	}
	return append(ops, deleteOps...), nil
}

func (w *LibOVSDBTopologyWriter) deleteLoadBalancerFromParents(ctx context.Context, lb *ovnnb.LoadBalancer) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	hcRows, err := w.healthChecksForLoadBalancerRow(ctx, lb)
	if err != nil {
		return nil, err
	}
	for i := range hcRows {
		nextOps, err := w.deleteLoadBalancerHealthCheckFromParents(&hcRows[i])
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
	}
	var routers []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool {
		return containsString(row.LoadBalancer, lb.UUID)
	}).List(ctx, &routers); err != nil {
		return nil, fmt.Errorf("list logical routers for load balancer %s: %w", lb.Name, err)
	}
	for i := range routers {
		nextOps, err := w.client.Where(&routers[i]).Mutate(&routers[i], ovsmodel.Mutation{
			Field:   &routers[i].LoadBalancer,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{lb.UUID},
		})
		if err != nil {
			return nil, fmt.Errorf("detach load balancer %s from router %s: %w", lb.Name, routers[i].Name, err)
		}
		ops = append(ops, nextOps...)
	}
	var switches []ovnnb.LogicalSwitch
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitch) bool {
		return containsString(row.LoadBalancer, lb.UUID)
	}).List(ctx, &switches); err != nil {
		return nil, fmt.Errorf("list logical switches for load balancer %s: %w", lb.Name, err)
	}
	for i := range switches {
		nextOps, err := w.client.Where(&switches[i]).Mutate(&switches[i], ovsmodel.Mutation{
			Field:   &switches[i].LoadBalancer,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{lb.UUID},
		})
		if err != nil {
			return nil, fmt.Errorf("detach load balancer %s from switch %s: %w", lb.Name, switches[i].Name, err)
		}
		ops = append(ops, nextOps...)
	}
	deleteOps, err := w.client.Where(lb).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete load balancer %s: %w", lb.Name, err)
	}
	return append(ops, deleteOps...), nil
}

func (w *LibOVSDBTopologyWriter) deleteDHCPOptionsOperations(ctx context.Context, dhcp *ovnnb.DHCPOptions) ([]ovsdb.Operation, error) {
	var ports []ovnnb.LogicalSwitchPort
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool {
		return pointerStringValue(row.Dhcpv4Options) == dhcp.UUID || pointerStringValue(row.Dhcpv6Options) == dhcp.UUID
	}).List(ctx, &ports); err != nil {
		return nil, fmt.Errorf("list logical switch ports for DHCP options %s: %w", dhcp.UUID, err)
	}
	var ops []ovsdb.Operation
	for i := range ports {
		if pointerStringValue(ports[i].Dhcpv4Options) == dhcp.UUID {
			ports[i].Dhcpv4Options = nil
		}
		if pointerStringValue(ports[i].Dhcpv6Options) == dhcp.UUID {
			ports[i].Dhcpv6Options = nil
		}
		updateOps, err := w.client.Where(&ports[i]).Update(&ports[i], &ports[i].Dhcpv4Options, &ports[i].Dhcpv6Options)
		if err != nil {
			return nil, fmt.Errorf("clear DHCP options %s from port %s: %w", dhcp.UUID, ports[i].Name, err)
		}
		ops = append(ops, updateOps...)
	}
	deleteOps, err := w.client.Where(dhcp).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete DHCP options %s: %w", dhcp.UUID, err)
	}
	return append(ops, deleteOps...), nil
}

func (w *LibOVSDBTopologyWriter) transact(ctx context.Context, label string, ops []ovsdb.Operation) error {
	if len(ops) == 0 {
		return nil
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("%s operation errors=%+v: %w", label, opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) unexpectedLogicalSwitches(ctx context.Context, expected map[string]map[string]string, expectedNames map[string]struct{}) ([]ovnnb.LogicalSwitch, error) {
	var rows []ovnnb.LogicalSwitch
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitch) bool {
		if isNetloomManaged(row.ExternalIDs) {
			if _, ok := expectedNames[row.Name]; ok {
				return false
			}
		}
		return unexpectedManagedRow("Logical_Switch", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func expectedLogicalSwitchNames(desired topology.State) map[string]struct{} {
	out := make(map[string]struct{}, len(desired.Subnets))
	for _, subnet := range desired.Subnets {
		out[logicalSwitch(subnet.VPC, subnet.Name)] = struct{}{}
	}
	return out
}

func (w *LibOVSDBTopologyWriter) unexpectedLogicalRouters(ctx context.Context, expected map[string]map[string]string, expectedNames map[string]struct{}) ([]ovnnb.LogicalRouter, error) {
	var rows []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool {
		if isNetloomManaged(row.ExternalIDs) {
			if _, ok := expectedNames[row.Name]; ok {
				return false
			}
		}
		return unexpectedManagedRow("Logical_Router", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func expectedLogicalRouterNames(desired topology.State) map[string]struct{} {
	out := make(map[string]struct{}, len(desired.VPCs))
	for name := range desired.VPCs {
		out[logicalRouter(name)] = struct{}{}
	}
	return out
}

func desiredHasGatewayForVPC(desired topology.State, vpc string) bool {
	for _, gateway := range desired.Gateways {
		if gateway.VPC == vpc {
			return true
		}
	}
	return false
}

func (w *LibOVSDBTopologyWriter) unexpectedLogicalSwitchPorts(ctx context.Context, expected map[string]map[string]string) ([]ovnnb.LogicalSwitchPort, error) {
	var rows []ovnnb.LogicalSwitchPort
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool {
		return unexpectedManagedRow("Logical_Switch_Port", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) unexpectedLogicalRouterPorts(ctx context.Context, expected map[string]map[string]string) ([]ovnnb.LogicalRouterPort, error) {
	var rows []ovnnb.LogicalRouterPort
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool {
		return unexpectedManagedRow("Logical_Router_Port", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) unexpectedPolicyRoutes(ctx context.Context, expected map[string]map[string]string, desired []model.PolicyRoute) ([]ovnnb.LogicalRouterPolicy, error) {
	expectedRefs, err := w.expectedRouterPolicyRefs(ctx, expected, desired)
	if err != nil {
		return nil, err
	}
	var rows []ovnnb.LogicalRouterPolicy
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool {
		if _, ok := expectedRefs[row.UUID]; ok {
			return false
		}
		return unexpectedManagedRow("Logical_Router_Policy", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) expectedRouterPolicyRefs(ctx context.Context, expected map[string]map[string]string, desired []model.PolicyRoute) (map[string]struct{}, error) {
	var routers []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool {
		return !unexpectedManagedRow("Logical_Router", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &routers); err != nil {
		return nil, err
	}
	refs := make(map[string]struct{})
	for _, router := range routers {
		for _, route := range desired {
			if logicalRouter(route.VPC) != router.Name {
				continue
			}
			rows, err := w.referencedPolicyRoutesForDesired(ctx, router.Policies, desiredPolicyRouteRow(route))
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				refs[row.UUID] = struct{}{}
			}
		}
	}
	return refs, nil
}

func (w *LibOVSDBTopologyWriter) unexpectedNATRules(ctx context.Context, expected map[string]map[string]string, desired map[string]model.NATRule) ([]ovnnb.NAT, error) {
	expectedRefs, err := w.expectedRouterNATRefs(ctx, expected, desired)
	if err != nil {
		return nil, err
	}
	var rows []ovnnb.NAT
	if err := w.client.WhereCache(func(row *ovnnb.NAT) bool {
		if _, ok := expectedRefs[row.UUID]; ok {
			return false
		}
		return unexpectedManagedRow("NAT", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) expectedRouterNATRefs(ctx context.Context, expected map[string]map[string]string, desired map[string]model.NATRule) (map[string]struct{}, error) {
	var routers []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool {
		return !unexpectedManagedRow("Logical_Router", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &routers); err != nil {
		return nil, err
	}
	refs := make(map[string]struct{})
	for _, router := range routers {
		for _, rule := range desired {
			if logicalRouter(rule.VPC) != router.Name {
				continue
			}
			rows, err := w.referencedNATRulesForDesired(ctx, router.Nat, desiredNATRuleRow(rule))
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				refs[row.UUID] = struct{}{}
			}
		}
	}
	return refs, nil
}

func (w *LibOVSDBTopologyWriter) unexpectedLoadBalancers(ctx context.Context, expected map[string]map[string]string) ([]ovnnb.LoadBalancer, error) {
	var rows []ovnnb.LoadBalancer
	if err := w.client.WhereCache(func(row *ovnnb.LoadBalancer) bool {
		return unexpectedManagedRow("Load_Balancer", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) unexpectedLoadBalancerHealthChecks(ctx context.Context, expected map[string]map[string]string) ([]ovnnb.LoadBalancerHealthCheck, error) {
	expectedRefs, err := w.expectedLoadBalancerHealthCheckRefs(ctx, expected)
	if err != nil {
		return nil, err
	}
	var rows []ovnnb.LoadBalancerHealthCheck
	if err := w.client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool {
		if _, ok := expectedRefs[row.UUID]; ok {
			return false
		}
		return unexpectedManagedRow("Load_Balancer_Health_Check", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) expectedLoadBalancerHealthCheckRefs(ctx context.Context, expected map[string]map[string]string) (map[string]struct{}, error) {
	var lbs []ovnnb.LoadBalancer
	if err := w.client.WhereCache(func(row *ovnnb.LoadBalancer) bool {
		return !unexpectedManagedRow("Load_Balancer", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &lbs); err != nil {
		return nil, err
	}
	refs := make(map[string]struct{})
	for _, lb := range lbs {
		for _, uuid := range lb.HealthCheck {
			refs[uuid] = struct{}{}
		}
	}
	return refs, nil
}

func (w *LibOVSDBTopologyWriter) unexpectedDHCPOptions(ctx context.Context, expected map[string]map[string]string) ([]ovnnb.DHCPOptions, error) {
	expectedRefs, err := w.expectedLogicalSwitchPortDHCPRefs(ctx, expected)
	if err != nil {
		return nil, err
	}
	var rows []ovnnb.DHCPOptions
	if err := w.client.WhereCache(func(row *ovnnb.DHCPOptions) bool {
		if _, ok := expectedRefs[row.UUID]; ok {
			return false
		}
		return unexpectedManagedRow("DHCP_Options", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) expectedLogicalSwitchPortDHCPRefs(ctx context.Context, expected map[string]map[string]string) (map[string]struct{}, error) {
	var ports []ovnnb.LogicalSwitchPort
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool {
		return !unexpectedManagedRow("Logical_Switch_Port", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &ports); err != nil {
		return nil, err
	}
	refs := make(map[string]struct{})
	for _, port := range ports {
		if uuid := pointerStringValue(port.Dhcpv4Options); uuid != "" {
			refs[uuid] = struct{}{}
		}
		if uuid := pointerStringValue(port.Dhcpv6Options); uuid != "" {
			refs[uuid] = struct{}{}
		}
	}
	return refs, nil
}

func (w *LibOVSDBTopologyWriter) unexpectedStaticRoutes(ctx context.Context, managedExpected map[string]map[string]string, expected map[string]struct{}, desired map[string]model.RouteTable) ([]ovnnb.LogicalRouterStaticRoute, error) {
	expectedRefs, err := w.expectedRouterStaticRouteRefs(ctx, managedExpected, desired)
	if err != nil {
		return nil, err
	}
	var rows []ovnnb.LogicalRouterStaticRoute
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
		if _, ok := expectedRefs[row.UUID]; ok {
			return false
		}
		return isNetloomManaged(row.ExternalIDs) && !hasExpectedStaticRoute(row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) expectedRouterStaticRouteRefs(ctx context.Context, expected map[string]map[string]string, desired map[string]model.RouteTable) (map[string]struct{}, error) {
	var routers []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool {
		return !unexpectedManagedRow("Logical_Router", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &routers); err != nil {
		return nil, err
	}
	refs := make(map[string]struct{})
	for _, router := range routers {
		for _, table := range desired {
			if logicalRouter(table.VPC) != router.Name {
				continue
			}
			for _, route := range table.Routes {
				for _, desiredRow := range desiredStaticRouteRows(table, route) {
					rows, err := w.referencedStaticRoutesForDesired(ctx, router.StaticRoutes, desiredRow)
					if err != nil {
						return nil, err
					}
					for _, row := range rows {
						refs[row.UUID] = struct{}{}
					}
				}
			}
		}
	}
	return refs, nil
}

func (w *LibOVSDBTopologyWriter) unexpectedBFDs(ctx context.Context, expected map[string]struct{}) ([]ovnnb.BFD, error) {
	expectedRefs, err := w.expectedStaticRouteBFDRefs(ctx, expected)
	if err != nil {
		return nil, err
	}
	var rows []ovnnb.BFD
	if err := w.client.WhereCache(func(row *ovnnb.BFD) bool {
		if _, ok := expectedRefs[row.UUID]; ok {
			return false
		}
		return isNetloomManaged(row.ExternalIDs) && !hasExpectedStaticRoute(row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) expectedStaticRouteBFDRefs(ctx context.Context, expected map[string]struct{}) (map[string]struct{}, error) {
	var routes []ovnnb.LogicalRouterStaticRoute
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
		return hasExpectedStaticRoute(row.ExternalIDs, expected)
	}).List(ctx, &routes); err != nil {
		return nil, err
	}
	refs := make(map[string]struct{})
	for _, route := range routes {
		if uuid := pointerStringValue(route.BFD); uuid != "" {
			refs[uuid] = struct{}{}
		}
	}
	return refs, nil
}

func (w *LibOVSDBTopologyWriter) staticRoutesByVPCAndDestination(ctx context.Context, vpc, destination string) ([]ovnnb.LogicalRouterStaticRoute, error) {
	var rows []ovnnb.LogicalRouterStaticRoute
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom" &&
			row.ExternalIDs["netloom_vpc"] == vpc &&
			row.IPPrefix == destination
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list static routes for %s destination %s from libovsdb cache: %w", vpc, destination, err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func unexpectedManagedRow(table, uuid string, externalIDs map[string]string, expected map[string]map[string]string) bool {
	if !isNetloomManaged(externalIDs) {
		return false
	}
	identity, complete := managedAuditIdentity(table, uuid, externalIDs)
	if !complete {
		return true
	}
	if identity == "" {
		return false
	}
	_, ok := expected[identity]
	return !ok
}

func expectedStaticRouteRows(desired topology.State) map[string]struct{} {
	out := make(map[string]struct{})
	for _, table := range desired.RouteTables {
		for _, route := range table.Routes {
			for _, row := range desiredStaticRouteRows(table, route) {
				if key := staticRouteExpectedKey(row.ExternalIDs); key != "" {
					out[key] = struct{}{}
				}
			}
		}
	}
	return out
}

func expectedStaticRouteBFDRows(desired topology.State) map[string]struct{} {
	out := make(map[string]struct{})
	for _, table := range desired.RouteTables {
		for _, route := range table.Routes {
			if !route.BFD.Enabled {
				continue
			}
			for _, row := range desiredStaticRouteRows(table, route) {
				if key := staticRouteExpectedKey(row.ExternalIDs); key != "" {
					out[key] = struct{}{}
				}
			}
		}
	}
	return out
}

func hasExpectedStaticRoute(externalIDs map[string]string, expected map[string]struct{}) bool {
	key := staticRouteExpectedKey(externalIDs)
	if key == "" {
		return false
	}
	_, ok := expected[key]
	return ok
}

func staticRouteExpectedKey(externalIDs map[string]string) string {
	vpc := externalIDs["netloom_vpc"]
	table := externalIDs["netloom_route_table"]
	key := externalIDs["netloom_route_key"]
	if vpc == "" || table == "" || key == "" {
		return ""
	}
	return vpc + "|" + table + "|" + key
}

func equalStringMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}
