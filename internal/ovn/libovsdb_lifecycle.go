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
		repairOps, err := w.repairSteadyStateLoadBalancers(ctx, state)
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
	staticRoutes, err := w.unexpectedStaticRoutes(ctx, staticRouteExpected)
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
	policyRows, err := w.unexpectedPolicyRoutes(ctx, expected)
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
	natRows, err := w.unexpectedNATRules(ctx, expected)
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
	lsRows, err := w.unexpectedLogicalSwitches(ctx, expected)
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
	lrRows, err := w.unexpectedLogicalRouters(ctx, expected)
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

func (w *LibOVSDBTopologyWriter) repairSteadyStateLoadBalancers(ctx context.Context, desired topology.State) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	for _, lb := range desired.LoadBalancers {
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
			nextOptions := replaceManagedLoadBalancerOptions(existing.Options, desiredRow.Options)
			if !reflect.DeepEqual(existing.Options, nextOptions) {
				existing.Options = nextOptions
				updateOps, err := w.client.Where(existing).Update(existing, &existing.Options)
				if err != nil {
					return nil, fmt.Errorf("repair load balancer %s options: %w", existing.Name, err)
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

func (w *LibOVSDBTopologyWriter) repairSteadyStateLoadBalancerHealthCheckRefs(ctx context.Context, lbRow *ovnnb.LoadBalancer, lb model.LoadBalancer, protocol model.Protocol, frontends []model.LoadBalancerFrontend) ([]ovsdb.Operation, error) {
	hcRows, err := w.healthChecksByLoadBalancerName(ctx, lbRow.Name, lb.VPC, lb.Name)
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
			keep := rows[0]
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
			for i := 1; i < len(rows); i++ {
				deleteOps, err := w.deleteLoadBalancerHealthCheck(lbRow.UUID, &rows[i])
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
				desiredUUIDs[rows[0].UUID] = struct{}{}
			}
			continue
		}
		for i := range rows {
			deleteOps, err := w.deleteLoadBalancerHealthCheck(lbRow.UUID, &rows[i])
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
	nextExternalIDs := cloneStringMap(router.ExternalIDs)
	for _, key := range []string{"netloom_gateway", "netloom_external_if", "netloom_gateway_lan_ip", "netloom_gateway_distributed"} {
		delete(nextExternalIDs, key)
	}
	nextOptions := cloneStringMap(router.Options)
	delete(nextOptions, "chassis")
	if equalStringMaps(router.ExternalIDs, nextExternalIDs) && equalStringMaps(router.Options, nextOptions) {
		return nil, nil
	}
	router.ExternalIDs = nextExternalIDs
	router.Options = nextOptions
	return w.client.Where(router).Update(router, &router.ExternalIDs, &router.Options)
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
	return append(ops, deleteOps...), nil
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
	hcRows, err := w.healthChecksByLoadBalancerName(ctx, lb.Name, lb.ExternalIDs["netloom_vpc"], lb.ExternalIDs["netloom_load_balancer"])
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

func (w *LibOVSDBTopologyWriter) unexpectedLogicalSwitches(ctx context.Context, expected map[string]map[string]string) ([]ovnnb.LogicalSwitch, error) {
	var rows []ovnnb.LogicalSwitch
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitch) bool {
		return unexpectedManagedRow("Logical_Switch", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) unexpectedLogicalRouters(ctx context.Context, expected map[string]map[string]string) ([]ovnnb.LogicalRouter, error) {
	var rows []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool {
		return unexpectedManagedRow("Logical_Router", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
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

func (w *LibOVSDBTopologyWriter) unexpectedPolicyRoutes(ctx context.Context, expected map[string]map[string]string) ([]ovnnb.LogicalRouterPolicy, error) {
	var rows []ovnnb.LogicalRouterPolicy
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool {
		return unexpectedManagedRow("Logical_Router_Policy", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) unexpectedNATRules(ctx context.Context, expected map[string]map[string]string) ([]ovnnb.NAT, error) {
	var rows []ovnnb.NAT
	if err := w.client.WhereCache(func(row *ovnnb.NAT) bool {
		return unexpectedManagedRow("NAT", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
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
	var rows []ovnnb.LoadBalancerHealthCheck
	if err := w.client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool {
		return unexpectedManagedRow("Load_Balancer_Health_Check", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) unexpectedDHCPOptions(ctx context.Context, expected map[string]map[string]string) ([]ovnnb.DHCPOptions, error) {
	var rows []ovnnb.DHCPOptions
	if err := w.client.WhereCache(func(row *ovnnb.DHCPOptions) bool {
		return unexpectedManagedRow("DHCP_Options", row.UUID, row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) unexpectedStaticRoutes(ctx context.Context, expected map[string]struct{}) ([]ovnnb.LogicalRouterStaticRoute, error) {
	var rows []ovnnb.LogicalRouterStaticRoute
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
		return isNetloomManaged(row.ExternalIDs) && !hasExpectedStaticRoute(row.ExternalIDs, expected)
	}).List(ctx, &rows); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
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
