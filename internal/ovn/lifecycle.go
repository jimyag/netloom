package ovn

import (
	"fmt"
	"sort"

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
		out.Subnets[name] = subnet
	}
	for id, endpoint := range state.Endpoints {
		out.Endpoints[id] = endpoint
	}
	for _, table := range state.RouteTables {
		for _, route := range table.Routes {
			out.Routes[routeKey(table.VPC, route)] = routeRecord{VPC: table.VPC, Route: route}
		}
	}
	for _, route := range state.PolicyRoutes {
		match := policyRouteMatch(route.Match)
		out.PolicyRoutes[policyRouteKey(route.VPC, route.Priority, match)] = policyRouteRecord{Route: route, Match: match}
	}
	for name, gateway := range state.Gateways {
		out.Gateways[name] = gateway
	}
	for name, rule := range state.NATRules {
		out.NATRules[name] = rule
	}
	for name, lb := range state.LoadBalancers {
		out.LoadBalancers[name] = lb
	}
	return out
}

func cleanupOperations(old, next desiredSnapshot) []Operation {
	var ops []Operation
	for _, key := range staleKeys(old.Endpoints, next.Endpoints) {
		if subnet, ok := old.Subnets[old.Endpoints[key].Subnet]; ok && subnet.DHCP.Enabled {
			ops = append(ops, Operation{Command: "destroy", Flags: []string{"--if-exists"}, Args: []string{"DHCP_Options", logicalPort(key)}})
		}
		ops = append(ops, Operation{Command: "lsp-del", Flags: []string{"--if-exists"}, Args: []string{logicalPort(key)}})
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
		args := []string{logicalRouter(record.VPC), record.Route.Destination.String()}
		if !record.Route.Blackhole {
			args = append(args, record.Route.NextHop.String())
		}
		ops = append(ops, Operation{Command: "lr-route-del", Flags: []string{"--if-exists"}, Args: args})
	}
	for _, key := range staleKeys(old.PolicyRoutes, next.PolicyRoutes) {
		record := old.PolicyRoutes[key]
		ops = append(ops, Operation{Command: "lr-policy-del", Flags: []string{"--if-exists"}, Args: []string{
			logicalRouter(record.Route.VPC),
			fmt.Sprint(record.Route.Priority),
			record.Match,
		}})
	}
	for _, key := range staleKeys(old.NATRules, next.NATRules) {
		rule := old.NATRules[key]
		ops = append(ops, Operation{Command: "lr-nat-del", Flags: []string{"--if-exists"}, Args: []string{
			logicalRouter(rule.VPC),
			natType(rule.Type),
			natDeleteMatch(rule),
		}})
	}
	for _, key := range commonKeys(old.NATRules, next.NATRules) {
		oldRule := old.NATRules[key]
		nextRule := next.NATRules[key]
		if natRuleSignature(oldRule) == natRuleSignature(nextRule) {
			continue
		}
		if natDeleteKey(oldRule) == natDeleteKey(nextRule) {
			continue
		}
		ops = append(ops, Operation{Command: "lr-nat-del", Flags: []string{"--if-exists"}, Args: []string{
			logicalRouter(oldRule.VPC),
			natType(oldRule.Type),
			natDeleteMatch(oldRule),
		}})
	}
	for _, key := range staleKeys(old.LoadBalancers, next.LoadBalancers) {
		lb := old.LoadBalancers[key]
		name := loadBalancerName(lb.Name)
		ops = append(ops, Operation{Command: "lr-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalRouter(lb.VPC), name}})
		for _, subnet := range lb.Subnets {
			ops = append(ops, Operation{Command: "ls-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalSwitch(subnet), name}})
		}
		ops = append(ops, Operation{Command: "lb-del", Flags: []string{"--if-exists"}, Args: []string{name}})
	}
	for _, key := range commonKeys(old.LoadBalancers, next.LoadBalancers) {
		oldLB := old.LoadBalancers[key]
		nextLB := next.LoadBalancers[key]
		name := loadBalancerName(oldLB.Name)
		if oldLB.VPC != nextLB.VPC {
			ops = append(ops, Operation{Command: "lr-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalRouter(oldLB.VPC), name}})
		}
		if loadBalancerVIP(oldLB) != loadBalancerVIP(nextLB) {
			ops = append(ops, Operation{Command: "lb-del", Flags: []string{"--if-exists"}, Args: []string{name, loadBalancerVIP(oldLB)}})
		}
		for _, subnet := range removedStrings(oldLB.Subnets, nextLB.Subnets) {
			ops = append(ops, Operation{Command: "ls-lb-del", Flags: []string{"--if-exists"}, Args: []string{logicalSwitch(subnet), name}})
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

func routeKey(vpc string, route model.Route) string {
	nextHop := "discard"
	if !route.Blackhole {
		nextHop = route.NextHop.String()
	}
	return vpc + "|" + route.Destination.String() + "|" + nextHop
}

func policyRouteKey(vpc string, priority int, match string) string {
	return fmt.Sprintf("%s|%d|%s", vpc, priority, match)
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
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%d",
		rule.VPC,
		rule.Type,
		rule.MatchCIDR,
		rule.ExternalIP,
		rule.TargetIP,
		rule.Protocol,
		rule.ExternalPort,
		rule.TargetPort,
	)
}
