package ovn

import (
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
	for name, subnet := range state.Subnets {
		out.Subnets[name] = cloneSnapshotSubnet(subnet)
	}
	for id, endpoint := range state.Endpoints {
		out.Endpoints[id] = cloneSnapshotEndpoint(endpoint)
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
	for name, gateway := range state.Gateways {
		out.Gateways[name] = gateway
	}
	for name, rule := range state.NATRules {
		out.NATRules[name] = rule
	}
	for name, lb := range state.LoadBalancers {
		out.LoadBalancers[name] = cloneSnapshotLoadBalancer(lb)
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
		port := logicalPort(key)
		if subnet, ok := old.Subnets[old.Endpoints[key].Subnet]; ok && subnet.DHCP.Enabled {
			ops = append(ops,
				Operation{Command: "lsp-set-dhcpv4-options", Args: []string{port}},
				Operation{Command: "lsp-set-dhcpv6-options", Args: []string{port}},
			)
			ops = append(ops, gcDHCPOptionsOperation(key))
		}
		ops = append(ops, Operation{Command: "lsp-del", Flags: []string{"--if-exists"}, Args: []string{port}})
	}
	for _, key := range staleKeys(old.Subnets, next.Subnets) {
		subnet := old.Subnets[key]
		router := logicalRouter(subnet.VPC)
		switchName := logicalSwitch(subnet.Name)
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
		ops = append(ops, gcLoadBalancerHealthChecksOperation(lb.Name))
		for _, name := range names {
			ops = append(ops, Operation{Command: "lr-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalRouter(lb.VPC), name}})
			for _, subnet := range lb.Subnets {
				ops = append(ops, Operation{Command: "ls-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalSwitch(subnet), name}})
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
			ops = append(ops, gcLoadBalancerHealthChecksOperation(oldLB.Name))
		}
		if oldLB.VPC != nextLB.VPC {
			for _, name := range oldNames {
				ops = append(ops, Operation{Command: "lr-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalRouter(oldLB.VPC), name}})
			}
		}
		oldVIPsByProtocol := loadBalancerVIPsByProtocol(oldLB)
		nextVIPsByProtocol := loadBalancerVIPsByProtocol(nextLB)
		for _, protocol := range sortedLoadBalancerProtocols(oldVIPsByProtocol) {
			name := loadBalancerProtocolName(oldLB.Name, protocol)
			for _, vip := range removedStrings(oldVIPsByProtocol[protocol], nextVIPsByProtocol[protocol]) {
				ops = append(ops, Operation{Command: "lb-del", Flags: []string{"--if-exists"}, Args: []string{name, vip}})
			}
		}
		oldFrontendSignatures := loadBalancerFrontendSignaturesByProtocol(oldLB)
		nextFrontendSignatures := loadBalancerFrontendSignaturesByProtocol(nextLB)
		for _, protocol := range sortedProtocolKeys(oldFrontendSignatures) {
			name := loadBalancerProtocolName(oldLB.Name, protocol)
			for _, vip := range commonStringKeys(oldFrontendSignatures[protocol], nextFrontendSignatures[protocol]) {
				if oldFrontendSignatures[protocol][vip] != nextFrontendSignatures[protocol][vip] {
					ops = append(ops, Operation{Command: "lb-del", Flags: []string{"--if-exists"}, Args: []string{name, vip}})
				}
			}
		}
		removedSubnets := removedStrings(oldLB.Subnets, nextLB.Subnets)
		for _, subnet := range removedSubnets {
			for _, name := range oldNames {
				ops = append(ops, Operation{Command: "ls-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalSwitch(subnet), name}})
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
				ops = append(ops, Operation{Command: "ls-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalSwitch(subnet), name}})
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
			out[nextRule.Name] = signature
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
			out[nextLB.Name] = signature
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
		if policyRouteSignature(oldRoute) == signature {
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
	return loadBalancerProtocolNamesFromFrontends(lb.Name, loadBalancerFrontendsByProtocol(lb))
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
	if len(oldNextHops) != len(nextNextHops) && (len(oldNextHops) == 1 || len(nextNextHops) == 1) {
		return []Operation{deleteStaticRouteDestinationOperation(oldRecord)}
	}
	if len(oldNextHops) == 1 && len(nextNextHops) == 1 {
		return []Operation{deleteStaticRouteDestinationOperation(oldRecord)}
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
			frontend.Name,
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
		return []Operation{{Command: "gc-nat-rule", Args: []string{rule.Name}}}
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
	keep := make([]string, 0, len(rules))
	for _, rule := range rules {
		if natUsesManagedRecord(rule) {
			keep = append(keep, rule.Name)
		}
	}
	sort.Strings(keep)
	return Operation{Command: "gc-stale-nat-rules", Args: keep}
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
