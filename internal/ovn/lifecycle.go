package ovn

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/topology"
)

type desiredSnapshot struct {
	VPCs          map[string]model.VPC
	Subnets       map[string]model.Subnet
	Endpoints     map[string]model.Endpoint
	Routes        map[string]routeRecord
	PolicyRoutes  map[string]policyRouteRecord
	Gateways      map[string]model.Gateway
	NATRules      map[string]model.NATRule
	LoadBalancers map[string]model.LoadBalancer
}

type routeRecord struct {
	VPC   string
	Route model.Route
}

type policyRouteRecord struct {
	Route model.PolicyRoute
	Match string
}

func snapshotDesired(state topology.State) desiredSnapshot {
	out := desiredSnapshot{
		VPCs:          make(map[string]model.VPC, len(state.VPCs)),
		Subnets:       make(map[string]model.Subnet, len(state.Subnets)),
		Endpoints:     make(map[string]model.Endpoint, len(state.Endpoints)),
		Routes:        make(map[string]routeRecord),
		PolicyRoutes:  make(map[string]policyRouteRecord, len(state.PolicyRoutes)),
		Gateways:      make(map[string]model.Gateway, len(state.Gateways)),
		NATRules:      make(map[string]model.NATRule, len(state.NATRules)),
		LoadBalancers: make(map[string]model.LoadBalancer, len(state.LoadBalancers)),
	}
	for name, vpc := range state.VPCs {
		out.VPCs[name] = vpc
	}
	for _, subnet := range state.Subnets {
		out.Subnets[subnetStateKey(subnet.VPC, subnet.Name)] = cloneSnapshotSubnet(subnet)
	}
	for _, endpoint := range state.Endpoints {
		out.Endpoints[model.EndpointKey(endpoint.VPC, endpoint.ID)] = cloneSnapshotEndpoint(endpoint)
	}
	for _, table := range state.RouteTables {
		for _, route := range table.Routes {
			route = cloneSnapshotRoute(route)
			out.Routes[routeKey(table.VPC, route)] = routeRecord{VPC: table.VPC, Route: route}
		}
	}
	for _, route := range state.PolicyRoutes {
		route = cloneSnapshotPolicyRoute(route)
		match := policyRouteMatch(route.Match)
		out.PolicyRoutes[policyRouteKey(route)] = policyRouteRecord{Route: route, Match: match}
	}
	for _, gateway := range state.Gateways {
		out.Gateways[gatewayStateKey(gateway.VPC, gateway.Name)] = gateway
	}
	for _, rule := range state.NATRules {
		out.NATRules[natRuleStateKey(rule.VPC, rule.Name)] = rule
	}
	for _, lb := range state.LoadBalancers {
		out.LoadBalancers[loadBalancerStateKey(lb)] = cloneSnapshotLoadBalancer(lb)
	}
	return out
}

func cloneSnapshotSubnet(subnet model.Subnet) model.Subnet {
	subnet.ExcludeCIDRs = append([]netip.Prefix(nil), subnet.ExcludeCIDRs...)
	subnet.DHCP.DNSServers = append([]netip.Addr(nil), subnet.DHCP.DNSServers...)
	subnet.DHCP.SearchDomains = append([]string(nil), subnet.DHCP.SearchDomains...)
	return subnet
}

func cloneSnapshotEndpoint(endpoint model.Endpoint) model.Endpoint {
	endpoint.SecurityGroups = append([]string(nil), endpoint.SecurityGroups...)
	endpoint.NamedPorts = append([]model.NamedPort(nil), endpoint.NamedPorts...)
	if endpoint.Labels != nil {
		labels := make(model.Labels, len(endpoint.Labels))
		for key, value := range endpoint.Labels {
			labels[key] = value
		}
		endpoint.Labels = labels
	}
	return endpoint
}

func cloneSnapshotRoute(route model.Route) model.Route {
	route.NextHops = append([]netip.Addr(nil), route.NextHops...)
	return route
}

func cloneSnapshotPolicyRoute(route model.PolicyRoute) model.PolicyRoute {
	route.Match.SrcPorts = append([]model.PortRange(nil), route.Match.SrcPorts...)
	route.Match.DstPorts = append([]model.PortRange(nil), route.Match.DstPorts...)
	route.Action.NextHops = append([]netip.Addr(nil), route.Action.NextHops...)
	return route
}

func cloneSnapshotLoadBalancer(lb model.LoadBalancer) model.LoadBalancer {
	lb.Ports = append([]model.LoadBalancerPort(nil), lb.Ports...)
	for i := range lb.Ports {
		lb.Ports[i].Backends = append([]model.LoadBalancerBackend(nil), lb.Ports[i].Backends...)
		for j := range lb.Ports[i].Backends {
			lb.Ports[i].Backends[j].Healthy = cloneBoolPtr(lb.Ports[i].Backends[j].Healthy)
		}
	}
	lb.Subnets = append([]string(nil), lb.Subnets...)
	lb.SelectionFields = append([]string(nil), lb.SelectionFields...)
	return lb
}

func cloneBoolPtr(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cleanupOperations(old, next desiredSnapshot) []Operation {
	var ops []Operation
	for _, key := range staleKeys(old.Endpoints, next.Endpoints) {
		oldEndpoint := old.Endpoints[key]
		port := logicalPort(oldEndpoint.VPC, oldEndpoint.ID)
		if subnet, ok := old.Subnets[subnetStateKey(oldEndpoint.VPC, oldEndpoint.Subnet)]; ok && subnet.DHCP.Enabled {
			ops = append(ops,
				Operation{Command: "lsp-set-dhcpv4-options", Args: []string{port}},
				Operation{Command: "lsp-set-dhcpv6-options", Args: []string{port}},
			)
			ops = append(ops, gcDHCPOptionsOperation(oldEndpoint))
		}
		ops = append(ops, Operation{Command: "lsp-del", Flags: []string{"--if-exists"}, Args: []string{port}})
	}
	for _, key := range staleKeys(old.Subnets, next.Subnets) {
		subnet := old.Subnets[key]
		router := logicalRouter(subnet.VPC)
		switchName := logicalSwitch(subnet.VPC, subnet.Name)
		ops = append(ops,
			Operation{Command: "lsp-del", Flags: []string{"--if-exists"}, Args: []string{localnetPortName(switchName, subnet.Name)}},
			Operation{Command: "lsp-del", Flags: []string{"--if-exists"}, Args: []string{switchRouterPortName(switchName, subnet.Name)}},
			Operation{Command: "lrp-del", Flags: []string{"--if-exists"}, Args: []string{routerPortName(router, subnet.Name)}},
			Operation{Command: "ls-del", Flags: []string{"--if-exists"}, Args: []string{switchName}},
		)
	}
	for _, key := range staleKeys(old.Routes, next.Routes) {
		record := old.Routes[key]
		ops = append(ops, deleteStaticRouteDestinationOperation(record))
	}
	for _, key := range commonKeys(old.Routes, next.Routes) {
		oldRecord := old.Routes[key]
		nextRecord := next.Routes[key]
		ops = append(ops, routeUpdateCleanupOperations(oldRecord, nextRecord)...)
	}
	for _, key := range staleKeys(old.PolicyRoutes, next.PolicyRoutes) {
		record := old.PolicyRoutes[key]
		ops = append(ops, Operation{Command: "lr-policy-del", Flags: []string{"--if-exists"}, Args: []string{
			logicalRouter(record.Route.VPC),
			fmt.Sprint(record.Route.Priority),
			record.Match,
		}})
	}
	for _, key := range commonKeys(old.PolicyRoutes, next.PolicyRoutes) {
		oldRecord := old.PolicyRoutes[key]
		nextRecord := next.PolicyRoutes[key]
		if policyRouteSignature(oldRecord.Route) == policyRouteSignature(nextRecord.Route) {
			continue
		}
		if op, ok := policyRouteNexthopSyncOperation(oldRecord, nextRecord); ok {
			ops = append(ops, op)
			continue
		}
		if op, ok := policyRouteNexthopsSyncOperation(oldRecord, nextRecord); ok {
			ops = append(ops, op)
			continue
		}
		ops = append(ops, Operation{Command: "lr-policy-del", Flags: []string{"--if-exists"}, Args: []string{
			logicalRouter(oldRecord.Route.VPC),
			fmt.Sprint(oldRecord.Route.Priority),
			oldRecord.Match,
		}})
	}
	for _, key := range staleKeys(old.NATRules, next.NATRules) {
		rule := old.NATRules[key]
		ops = append(ops, natDeleteOperations(rule)...)
	}
	for _, key := range commonKeys(old.NATRules, next.NATRules) {
		oldRule := old.NATRules[key]
		nextRule := next.NATRules[key]
		if natRuleSignature(oldRule) == natRuleSignature(nextRule) {
			continue
		}
		ops = append(ops, natDeleteOperations(oldRule)...)
	}
	for _, key := range staleKeys(old.LoadBalancers, next.LoadBalancers) {
		lb := old.LoadBalancers[key]
		names := loadBalancerProtocolNames(lb)
		for _, name := range names {
			ops = append(ops, Operation{Command: "clear", Args: []string{"load_balancer", name, "health_check"}})
		}
		ops = append(ops, gcLoadBalancerHealthChecksOperation(lb.Name, lb.VPC))
		for _, name := range names {
			ops = append(ops, Operation{Command: "lr-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalRouter(lb.VPC), name}})
			for _, subnet := range lb.Subnets {
				ops = append(ops, Operation{Command: "ls-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalSwitch(lb.VPC, subnet), name}})
			}
			ops = append(ops, Operation{Command: "lb-del", Flags: []string{"--if-exists"}, Args: []string{name}})
		}
	}
	for _, key := range commonKeys(old.LoadBalancers, next.LoadBalancers) {
		oldLB := old.LoadBalancers[key]
		nextLB := next.LoadBalancers[key]
		oldNames := loadBalancerProtocolNames(oldLB)
		nextNames := loadBalancerProtocolNames(nextLB)
		removedNames := removedStrings(oldNames, nextNames)
		for _, name := range removedNames {
			ops = append(ops, Operation{Command: "clear", Args: []string{"load_balancer", name, "health_check"}})
		}
		if len(removedNames) > 0 {
			ops = append(ops, gcLoadBalancerHealthChecksOperation(oldLB.Name, oldLB.VPC))
		}
		if oldLB.VPC != nextLB.VPC {
			for _, name := range oldNames {
				ops = append(ops, Operation{Command: "lr-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalRouter(oldLB.VPC), name}})
			}
		}
		oldVIPsByProtocol := loadBalancerVIPsByProtocol(oldLB)
		nextVIPsByProtocol := loadBalancerVIPsByProtocol(nextLB)
		for _, protocol := range sortedLoadBalancerProtocols(oldVIPsByProtocol) {
			if _, ok := nextVIPsByProtocol[protocol]; !ok {
				continue
			}
			name := loadBalancerProtocolName(oldLB.VPC, oldLB.Name, protocol)
			for _, vip := range removedStrings(oldVIPsByProtocol[protocol], nextVIPsByProtocol[protocol]) {
				ops = append(ops, Operation{Command: "lb-del", Flags: []string{"--if-exists"}, Args: []string{name, vip}})
			}
		}
		oldFrontendSignatures := loadBalancerFrontendSignaturesByProtocol(oldLB)
		nextFrontendSignatures := loadBalancerFrontendSignaturesByProtocol(nextLB)
		for _, protocol := range sortedProtocolKeys(oldFrontendSignatures) {
			if _, ok := nextFrontendSignatures[protocol]; !ok {
				continue
			}
			name := loadBalancerProtocolName(oldLB.VPC, oldLB.Name, protocol)
			for _, vip := range commonStringKeys(oldFrontendSignatures[protocol], nextFrontendSignatures[protocol]) {
				if oldFrontendSignatures[protocol][vip] != nextFrontendSignatures[protocol][vip] {
					ops = append(ops, Operation{Command: "lb-del", Flags: []string{"--if-exists"}, Args: []string{name, vip}})
				}
			}
		}
		removedSubnets := removedStrings(oldLB.Subnets, nextLB.Subnets)
		for _, subnet := range removedSubnets {
			for _, name := range oldNames {
				ops = append(ops, Operation{Command: "ls-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalSwitch(oldLB.VPC, subnet), name}})
			}
		}
		for _, name := range removedNames {
			if oldLB.VPC == nextLB.VPC {
				ops = append(ops, Operation{Command: "lr-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalRouter(oldLB.VPC), name}})
			}
			for _, subnet := range oldLB.Subnets {
				if stringInSlice(subnet, removedSubnets) {
					continue
				}
				ops = append(ops, Operation{Command: "ls-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalSwitch(oldLB.VPC, subnet), name}})
			}
			ops = append(ops, Operation{Command: "lb-del", Flags: []string{"--if-exists"}, Args: []string{name}})
		}
	}
	for _, key := range staleKeys(old.Gateways, next.Gateways) {
		gateway := old.Gateways[key]
		router := logicalRouter(gateway.VPC)
		ops = append(ops,
			Operation{Command: "remove", Args: []string{"logical_router", router, "external_ids", "netloom_gateway"}},
			Operation{Command: "remove", Args: []string{"logical_router", router, "external_ids", "netloom_external_if"}},
			Operation{Command: "remove", Args: []string{"logical_router", router, "external_ids", "netloom_gateway_lan_ip"}},
			Operation{Command: "remove", Args: []string{"logical_router", router, "external_ids", "netloom_gateway_distributed"}},
			Operation{Command: "remove", Args: []string{"logical_router", router, "options", "chassis"}},
		)
	}
	for _, key := range staleKeys(old.VPCs, next.VPCs) {
		ops = append(ops, Operation{Command: "lr-del", Flags: []string{"--if-exists"}, Args: []string{logicalRouter(key)}})
	}
	return ops
}

func unchangedNATRules(old, next desiredSnapshot) map[string]string {
	out := make(map[string]string)
	for _, key := range commonKeys(old.NATRules, next.NATRules) {
		oldRule := old.NATRules[key]
		nextRule := next.NATRules[key]
		signature := natRuleSignature(nextRule)
		if natRuleSignature(oldRule) == signature {
			out[natRuleStateKey(nextRule.VPC, nextRule.Name)] = signature
		}
	}
	return out
}

func unchangedLoadBalancers(old, next desiredSnapshot) map[string]string {
	out := make(map[string]string)
	for _, key := range commonKeys(old.LoadBalancers, next.LoadBalancers) {
		oldLB := old.LoadBalancers[key]
		nextLB := next.LoadBalancers[key]
		signature := loadBalancerSignature(nextLB)
		if loadBalancerSignature(oldLB) == signature {
			out[loadBalancerStateKey(nextLB)] = signature
		}
	}
	return out
}

func unchangedPolicyRoutes(old, next desiredSnapshot) map[string]string {
	out := make(map[string]string)
	for _, key := range commonKeys(old.PolicyRoutes, next.PolicyRoutes) {
		oldRoute := old.PolicyRoutes[key].Route
		nextRoute := next.PolicyRoutes[key].Route
		signature := policyRouteSignature(nextRoute)
		if policyRouteSignature(oldRoute) == signature ||
			policyRouteCanBeUpdatedByNexthop(oldRoute, nextRoute) ||
			policyRouteCanBeUpdatedByNexthops(oldRoute, nextRoute) {
			out[key] = signature
		}
	}
	return out
}

func unchangedRoutes(old, next desiredSnapshot) map[string]string {
	out := make(map[string]string)
	for key := range next.Routes {
		nextRecord, ok := next.Routes[key]
		if !ok {
			continue
		}
		oldRecord, ok := old.Routes[key]
		if !ok {
			continue
		}
		if routeSignature(oldRecord) != routeSignature(nextRecord) {
			continue
		}
		out[key] = routeSignature(nextRecord)
	}
	return out
}

func policyRouteCanBeUpdatedByNexthop(oldRoute, nextRoute model.PolicyRoute) bool {
	if oldRoute.VPC != nextRoute.VPC || oldRoute.Priority != nextRoute.Priority {
		return false
	}
	oldMatch := policyRouteMatch(oldRoute.Match)
	nextMatch := policyRouteMatch(nextRoute.Match)
	if oldMatch != nextMatch {
		return false
	}
	if oldRoute.Action.Type != model.ActionReroute || nextRoute.Action.Type != model.ActionReroute {
		return false
	}
	oldNextHops := oldRoute.Action.RerouteNextHops()
	nextNextHops := nextRoute.Action.RerouteNextHops()
	if len(oldNextHops) != 1 || len(nextNextHops) != 1 {
		return false
	}
	return policyRouteSignature(nextRoute) != policyRouteSignature(oldRoute)
}

func policyRouteNexthopSyncOperation(oldRecord, nextRecord policyRouteRecord) (Operation, bool) {
	if !policyRouteCanBeUpdatedByNexthop(oldRecord.Route, nextRecord.Route) {
		return Operation{}, false
	}
	return Operation{
		Command: "sync-policy-route-nexthop",
		Args: []string{
			nextRecord.Route.VPC,
			nextRecord.Route.Name,
			fmt.Sprint(nextRecord.Route.Priority),
			nextRecord.Match,
			nextRecord.Route.Action.RerouteNextHops()[0].String(),
		},
	}, true
}

func policyRouteCanBeUpdatedByNexthops(oldRoute, nextRoute model.PolicyRoute) bool {
	if oldRoute.VPC != nextRoute.VPC || oldRoute.Priority != nextRoute.Priority {
		return false
	}
	oldMatch := policyRouteMatch(oldRoute.Match)
	nextMatch := policyRouteMatch(nextRoute.Match)
	if oldMatch != nextMatch {
		return false
	}
	if oldRoute.Action.Type != model.ActionReroute || nextRoute.Action.Type != model.ActionReroute {
		return false
	}
	oldNextHops := oldRoute.Action.RerouteNextHops()
	nextNextHops := nextRoute.Action.RerouteNextHops()
	if len(oldNextHops) <= 1 || len(nextNextHops) <= 1 {
		return false
	}
	return policyRouteSignature(nextRoute) != policyRouteSignature(oldRoute)
}

func policyRouteNexthopsSyncOperation(oldRecord, nextRecord policyRouteRecord) (Operation, bool) {
	if !policyRouteCanBeUpdatedByNexthops(oldRecord.Route, nextRecord.Route) {
		return Operation{}, false
	}
	nextHops := make([]string, 0, len(nextRecord.Route.Action.RerouteNextHops()))
	for _, nextHop := range nextRecord.Route.Action.RerouteNextHops() {
		nextHops = append(nextHops, nextHop.String())
	}
	sort.Strings(nextHops)
	return Operation{
		Command: "sync-policy-route-nexthops",
		Args: []string{
			nextRecord.Route.VPC,
			nextRecord.Route.Name,
			fmt.Sprint(nextRecord.Route.Priority),
			nextRecord.Match,
			ovnStringSetValues(nextHops),
		},
	}, true
}

func unchangedEndpoints(old, next desiredSnapshot) map[string]string {
	out := make(map[string]string)
	for _, key := range commonKeys(old.Endpoints, next.Endpoints) {
		oldEndpoint := old.Endpoints[key]
		nextEndpoint := next.Endpoints[key]
		signature := endpointSignature(nextEndpoint, subnetForEndpoint(next.Subnets, nextEndpoint))
		if endpointSignature(oldEndpoint, subnetForEndpoint(old.Subnets, oldEndpoint)) == signature {
			out[key] = signature
		}
	}
	return out
}

func commonKeys[T any](old, next map[string]T) []string {
	keys := make([]string, 0)
	for key := range old {
		if _, ok := next[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func staleKeys[T any](old, next map[string]T) []string {
	keys := make([]string, 0)
	for key := range old {
		if _, ok := next[key]; !ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func removedStrings(old, next []string) []string {
	nextSet := make(map[string]struct{}, len(next))
	for _, value := range next {
		nextSet[value] = struct{}{}
	}
	var removed []string
	for _, value := range old {
		if _, ok := nextSet[value]; !ok {
			removed = append(removed, value)
		}
	}
	sort.Strings(removed)
	return removed
}

func stringInSlice(needle string, values []string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func loadBalancerProtocolNames(lb model.LoadBalancer) []string {
	return loadBalancerProtocolNamesFromFrontends(lb.VPC, lb.Name, loadBalancerFrontendsByProtocol(lb))
}

func loadBalancerVIPsByProtocol(lb model.LoadBalancer) map[model.Protocol][]string {
	out := make(map[model.Protocol][]string)
	for _, frontend := range lb.Frontends() {
		out[frontend.Protocol] = append(out[frontend.Protocol], loadBalancerFrontendVIP(frontend))
	}
	for protocol := range out {
		sort.Strings(out[protocol])
	}
	return out
}

func loadBalancerFrontendSignaturesByProtocol(lb model.LoadBalancer) map[model.Protocol]map[string]string {
	out := make(map[model.Protocol]map[string]string)
	for _, frontend := range lb.Frontends() {
		if _, ok := out[frontend.Protocol]; !ok {
			out[frontend.Protocol] = make(map[string]string)
		}
		out[frontend.Protocol][loadBalancerFrontendVIP(frontend)] = loadBalancerFrontendBackends(frontend)
	}
	return out
}

func sortedProtocolKeys[T any](values map[model.Protocol]T) []model.Protocol {
	protocols := make([]model.Protocol, 0, len(values))
	for protocol := range values {
		protocols = append(protocols, protocol)
	}
	sort.Slice(protocols, func(i, j int) bool {
		return protocols[i] < protocols[j]
	})
	return protocols
}

func commonStringKeys[T any](old, next map[string]T) []string {
	keys := make([]string, 0)
	for key := range old {
		if _, ok := next[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func routeKey(vpc string, route model.Route) string {
	return vpc + "|" + route.Destination.String()
}

func routeSignature(record routeRecord) string {
	route := record.Route
	if route.Blackhole {
		return routeKey(record.VPC, route) + "|discard"
	}
	nextHops := route.RouteNextHops()
	values := make([]string, 0, len(nextHops))
	for _, nextHop := range nextHops {
		values = append(values, nextHop.String())
	}
	sort.Strings(values)
	return routeKey(record.VPC, route) + "|" + strings.Join(values, ",")
}

func routeUpdateCleanupOperations(oldRecord, nextRecord routeRecord) []Operation {
	if routeSignature(oldRecord) == routeSignature(nextRecord) {
		return nil
	}
	if oldRecord.Route.Blackhole || nextRecord.Route.Blackhole {
		return []Operation{deleteStaticRouteDestinationOperation(oldRecord)}
	}
	oldNextHops := sortedRouteNextHops(oldRecord.Route)
	nextNextHops := sortedRouteNextHops(nextRecord.Route)
	if len(oldNextHops) == 1 && len(nextNextHops) > 1 {
		oldNextHop := oldNextHops[0]
		nextSet := make(map[string]struct{}, len(nextNextHops))
		for _, nextHop := range nextNextHops {
			nextSet[nextHop] = struct{}{}
		}
		if _, ok := nextSet[oldNextHop]; ok {
			return nil
		}
		return []Operation{deleteStaticRouteDestinationOperation(oldRecord)}
	}
	if len(oldNextHops) > 1 && len(nextNextHops) == 1 {
		nextSet := make(map[string]struct{}, len(nextNextHops))
		for _, nextHop := range nextNextHops {
			nextSet[nextHop] = struct{}{}
		}
		hasIntersection := false
		for _, oldNextHop := range oldNextHops {
			if _, ok := nextSet[oldNextHop]; ok {
				hasIntersection = true
				break
			}
		}
		if hasIntersection {
			// Keep the destination and remove only stale ECMP peers.
			var ops []Operation
			for _, oldNextHop := range oldNextHops {
				if _, keep := nextSet[oldNextHop]; keep {
					continue
				}
				ops = append(ops, deleteStaticRouteNextHopOperation(oldRecord, oldNextHop))
			}
			if len(ops) == 0 {
				return nil
			}
			return ops
		} else {
			return []Operation{deleteStaticRouteDestinationOperation(oldRecord)}
		}
	}
	if len(oldNextHops) == 1 && len(nextNextHops) == 1 {
		return nil
	}
	nextSet := make(map[string]struct{}, len(nextNextHops))
	for _, nextHop := range nextNextHops {
		nextSet[nextHop] = struct{}{}
	}
	var ops []Operation
	for _, nextHop := range oldNextHops {
		if _, ok := nextSet[nextHop]; ok {
			continue
		}
		ops = append(ops, deleteStaticRouteNextHopOperation(oldRecord, nextHop))
	}
	return ops
}

func sortedRouteNextHops(route model.Route) []string {
	nextHops := route.RouteNextHops()
	values := make([]string, 0, len(nextHops))
	for _, nextHop := range nextHops {
		values = append(values, nextHop.String())
	}
	sort.Strings(values)
	return values
}

func deleteStaticRouteDestinationOperation(record routeRecord) Operation {
	return Operation{Command: "lr-route-del", Flags: []string{"--if-exists"}, Args: []string{
		logicalRouter(record.VPC),
		record.Route.Destination.String(),
	}}
}

func deleteStaticRouteNextHopOperation(record routeRecord, nextHop string) Operation {
	return Operation{Command: "lr-route-del", Flags: []string{"--if-exists"}, Args: []string{
		logicalRouter(record.VPC),
		record.Route.Destination.String(),
		nextHop,
	}}
}

func policyRouteKey(route model.PolicyRoute) string {
	return route.VPC + "\x00" + route.Name
}

func policyRouteSignature(route model.PolicyRoute) string {
	return fmt.Sprintf("%s|%s|%d|%s|%s|%s",
		route.VPC,
		route.Name,
		route.Priority,
		policyRouteMatch(route.Match),
		route.Action.Type,
		policyRouteNextHops(route.Action),
	)
}

func subnetForEndpoint(subnets map[string]model.Subnet, endpoint model.Endpoint) model.Subnet {
	subnet := model.Subnet{}
	if subnetRef, ok := subnets[subnetStateKey(endpoint.VPC, endpoint.Subnet)]; ok {
		subnet = subnetRef
	}
	return subnet
}

func endpointSignature(endpoint model.Endpoint, subnet model.Subnet) string {
	securityGroups := append([]string(nil), endpoint.SecurityGroups...)
	sort.Strings(securityGroups)
	namedPorts := append([]model.NamedPort(nil), endpoint.NamedPorts...)
	sort.SliceStable(namedPorts, func(i, j int) bool {
		left := namedPorts[i]
		right := namedPorts[j]
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		return left.Port < right.Port
	})
	labels := make([]string, 0, len(endpoint.Labels))
	for key, value := range endpoint.Labels {
		labels = append(labels, key+"="+value)
	}
	sort.Strings(labels)

	hash := sha256.New()
	hash.Write([]byte(endpoint.ID))
	hash.Write([]byte("|"))
	hash.Write([]byte(endpoint.VPC))
	hash.Write([]byte("|"))
	hash.Write([]byte(endpoint.Subnet))
	hash.Write([]byte("|"))
	hash.Write([]byte(endpoint.IP.String()))
	hash.Write([]byte("|"))
	hash.Write([]byte(endpoint.MAC))
	hash.Write([]byte("|"))
	hash.Write([]byte(endpoint.Node))
	hash.Write([]byte("|"))
	hash.Write([]byte(subnet.Name))
	hash.Write([]byte("|"))
	hash.Write([]byte(subnet.CIDR.String()))
	hash.Write([]byte("|"))
	hash.Write([]byte(subnet.Gateway.String()))
	hash.Write([]byte("|"))
	hash.Write([]byte(fmt.Sprint(subnet.VLAN)))
	hash.Write([]byte("|"))
	hash.Write([]byte(subnet.ProviderNetwork))
	hash.Write([]byte("|"))
	hash.Write([]byte(fmt.Sprintf("%t", subnet.DHCP.Enabled)))
	hash.Write([]byte("|"))
	hash.Write([]byte(fmt.Sprintf("%d", subnet.DHCP.LeaseTime)))
	hash.Write([]byte("|"))
	hash.Write([]byte(fmt.Sprintf("%d", subnet.DHCP.MTU)))
	hash.Write([]byte("|"))
	dnsServers := make([]string, 0, len(subnet.DHCP.DNSServers))
	for _, dnsServer := range subnet.DHCP.DNSServers {
		dnsServers = append(dnsServers, dnsServer.String())
	}
	sort.Strings(dnsServers)
	hash.Write([]byte(strings.Join(dnsServers, ",")))
	hash.Write([]byte("|"))
	hash.Write([]byte(subnet.DHCP.DomainName))
	hash.Write([]byte("|"))
	searchDomains := append([]string(nil), subnet.DHCP.SearchDomains...)
	sort.Strings(searchDomains)
	hash.Write([]byte(strings.Join(searchDomains, ",")))
	hash.Write([]byte("|"))
	hash.Write([]byte(strings.Join(securityGroups, ",")))
	hash.Write([]byte("|"))
	for _, namedPort := range namedPorts {
		hash.Write([]byte(namedPort.Name))
		hash.Write([]byte("|"))
		hash.Write([]byte(namedPort.Protocol))
		hash.Write([]byte("|"))
		hash.Write([]byte(fmt.Sprint(namedPort.Port)))
		hash.Write([]byte("|"))
	}
	hash.Write([]byte("|"))
	hash.Write([]byte(strings.Join(labels, ",")))
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func policyRouteNextHops(action model.RouteAction) string {
	nextHops := action.RerouteNextHops()
	values := make([]string, 0, len(nextHops))
	for _, nextHop := range nextHops {
		values = append(values, nextHop.String())
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func loadBalancerSignature(lb model.LoadBalancer) string {
	frontends := lb.Frontends()
	frontendParts := make([]string, 0, len(frontends))
	for _, frontend := range frontends {
		frontendParts = append(frontendParts, strings.Join([]string{
			loadBalancerFrontendVIP(frontend),
			string(frontend.Protocol),
			loadBalancerFrontendBackends(frontend),
		}, "|"))
	}
	sort.Strings(frontendParts)
	subnets := append([]string(nil), lb.Subnets...)
	sort.Strings(subnets)
	return strings.Join([]string{
		lb.VPC,
		strings.Join(frontendParts, "||"),
		strings.Join(loadBalancerOptions(lb), "|"),
		loadBalancerHealthCheckSignature(lb),
		strings.Join(subnets, ","),
	}, "###")
}

func natType(action model.Action) string {
	switch action {
	case model.ActionSNAT:
		return "snat"
	case model.ActionDNAT:
		return "dnat"
	case model.ActionDNATSNAT:
		return "dnat_and_snat"
	default:
		return string(action)
	}
}

func natDeleteMatch(rule model.NATRule) string {
	if rule.Type == model.ActionSNAT {
		return rule.MatchCIDR.String()
	}
	return rule.ExternalIP.String()
}

func natDeleteKey(rule model.NATRule) string {
	return logicalRouter(rule.VPC) + "|" + natType(rule.Type) + "|" + natDeleteMatch(rule)
}

func natRuleSignature(rule model.NATRule) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%d|%s|%s",
		rule.VPC,
		rule.Type,
		rule.MatchCIDR,
		rule.ExternalIP,
		rule.TargetIP,
		rule.Protocol,
		rule.ExternalPort,
		rule.TargetPort,
		rule.LogicalPort,
		rule.ExternalMAC,
	)
}

func natDeleteOperations(rule model.NATRule) []Operation {
	if natUsesManagedRecord(rule) {
		return []Operation{gcNATRuleOperation(rule)}
	}
	return []Operation{{
		Command: "lr-nat-del",
		Flags:   []string{"--if-exists"},
		Args: []string{
			logicalRouter(rule.VPC),
			natType(rule.Type),
			natDeleteMatch(rule),
		},
	}}
}

func gcStaleNATRulesOperation(rules map[string]model.NATRule) Operation {
	keep := make([]string, 0, len(rules)*2)
	keys := make([]string, 0, len(rules))
	for key := range rules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		rule := rules[key]
		keep = append(keep, rule.VPC, rule.Name)
	}
	return Operation{Command: "gc-stale-nat-rules", Args: keep}
}

func gcStaleDHCPOptionsOperation(endpoints map[string]model.Endpoint, subnets map[string]model.Subnet) Operation {
	keep := make([]string, 0, len(endpoints)*2)
	keys := make([]string, 0, len(endpoints))
	for key := range endpoints {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		endpoint := endpoints[key]
		subnet, ok := subnets[subnetStateKey(endpoint.VPC, endpoint.Subnet)]
		if !ok || !subnet.DHCP.Enabled {
			continue
		}
		keep = append(keep, endpointExternalID(endpoint.VPC, endpoint.ID), endpoint.VPC)
	}
	return Operation{Command: "gc-stale-dhcp-options", Args: keep}
}

func gcNATRuleOperation(rule model.NATRule) Operation {
	return Operation{Command: "gc-nat-rule", Args: []string{rule.Name, rule.VPC}}
}

func tagPolicyRouteOperation(route model.PolicyRoute, match string) Operation {
	return Operation{Command: "tag-policy-route", Args: []string{
		route.VPC,
		route.Name,
		fmt.Sprint(route.Priority),
		match,
	}}
}

func gcStalePolicyRoutesOperation(routes map[string]policyRouteRecord) Operation {
	keep := make([]string, 0, len(routes)*2)
	keys := make([]string, 0, len(routes))
	for key := range routes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		route := routes[key].Route
		keep = append(keep, route.VPC, route.Name)
	}
	return Operation{Command: "gc-stale-policy-routes", Args: keep}
}
