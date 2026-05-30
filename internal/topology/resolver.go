package topology

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/jimyag/netloom/internal/model"
)

type State struct {
	VPCs          map[string]model.VPC
	Subnets       map[string]model.Subnet
	Endpoints     map[string]model.Endpoint
	RouteTables   map[string]model.RouteTable
	PolicyRoutes  []model.PolicyRoute
	Gateways      map[string]model.Gateway
	NATRules      map[string]model.NATRule
	LoadBalancers map[string]model.LoadBalancer
}

type Packet struct {
	VPC      string
	Source   netip.Addr
	Dest     netip.Addr
	Protocol model.Protocol
	DestPort uint16
}

type Decision struct {
	Action         model.Action
	NextHop        netip.Addr
	Gateway        string
	Translated     netip.Addr
	TranslatedPort uint16
	MatchedBy      string
	Destination    string
}

func Resolve(state State, packet Packet) (Decision, error) {
	if packet.VPC == "" {
		return Decision{}, fmt.Errorf("packet vpc is required")
	}
	if !packet.Source.IsValid() || !packet.Dest.IsValid() {
		return Decision{}, fmt.Errorf("packet source and destination are required")
	}
	if packet.Protocol == "" {
		packet.Protocol = model.ProtocolAny
	}

	if endpointID := findEndpoint(state, packet.VPC, packet.Dest); endpointID != "" {
		return Decision{
			Action:      model.ActionAllow,
			MatchedBy:   "endpoint",
			Destination: endpointID,
		}, nil
	}

	if decision, ok := resolveLoadBalancer(state, packet); ok {
		return decision, nil
	}
	if decision, ok := resolvePolicyRoute(state.PolicyRoutes, packet); ok {
		return applyNATAndGateway(state, packet, decision), nil
	}
	if decision, ok := resolveRouteTables(state.RouteTables, packet); ok {
		return applyNATAndGateway(state, packet, decision), nil
	}
	return Decision{Action: model.ActionDrop, MatchedBy: "no-route"}, nil
}

func resolveLoadBalancer(state State, packet Packet) (Decision, bool) {
	sourceEndpoint := findEndpointByIP(state, packet.VPC, packet.Source)
	for _, lb := range state.LoadBalancers {
		protocol := lb.Protocol
		if protocol == "" {
			protocol = model.ProtocolTCP
		}
		if lb.VPC != packet.VPC || lb.VIP != packet.Dest || lb.Port != packet.DestPort || protocol != packet.Protocol {
			continue
		}
		if len(lb.Subnets) > 0 && !loadBalancerAllowsSourceSubnet(lb, sourceEndpoint) {
			continue
		}
		if len(lb.Backends) == 0 {
			continue
		}
		backend := firstLoadBalancerBackend(lb.Backends)
		return Decision{
			Action:         model.ActionAllow,
			Translated:     backend.IP,
			TranslatedPort: backend.Port,
			MatchedBy:      "load-balancer/" + lb.Name,
			Destination:    backend.IP.String(),
		}, true
	}
	return Decision{}, false
}

func findEndpointByIP(state State, vpc string, ip netip.Addr) model.Endpoint {
	for _, endpoint := range state.Endpoints {
		if endpoint.VPC == vpc && endpoint.IP == ip {
			return endpoint
		}
	}
	return model.Endpoint{}
}

func loadBalancerAllowsSourceSubnet(lb model.LoadBalancer, endpoint model.Endpoint) bool {
	if endpoint.ID == "" {
		return false
	}
	for _, subnet := range lb.Subnets {
		if endpoint.Subnet == subnet {
			return true
		}
	}
	return false
}

func firstLoadBalancerBackend(backends []model.LoadBalancerBackend) model.LoadBalancerBackend {
	selected := backends[0]
	for _, backend := range backends[1:] {
		if backend.IP.Compare(selected.IP) < 0 || (backend.IP == selected.IP && backend.Port < selected.Port) {
			selected = backend
		}
	}
	return selected
}

func findEndpoint(state State, vpc string, dest netip.Addr) string {
	for _, endpoint := range state.Endpoints {
		if endpoint.VPC == vpc && endpoint.IP == dest {
			return endpoint.ID
		}
	}
	return ""
}

func resolvePolicyRoute(routes []model.PolicyRoute, packet Packet) (Decision, bool) {
	candidates := append([]model.PolicyRoute(nil), routes...)
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Priority > candidates[j].Priority
	})
	for _, route := range candidates {
		if route.VPC != packet.VPC || !routeMatch(route.Match, packet) {
			continue
		}
		decision := Decision{
			Action:    route.Action.Type,
			NextHop:   route.Action.NextHop,
			MatchedBy: "policy-route/" + route.Name,
		}
		if route.Action.Type == model.ActionDrop {
			return decision, true
		}
		if route.Action.Type == model.ActionAllow {
			decision.Action = model.ActionAllow
		}
		return decision, true
	}
	return Decision{}, false
}

func routeMatch(match model.RouteMatch, packet Packet) bool {
	if match.Source.IsValid() && !match.Source.Contains(packet.Source) {
		return false
	}
	if match.Destination.IsValid() && !match.Destination.Contains(packet.Dest) {
		return false
	}
	if match.Protocol != "" && match.Protocol != model.ProtocolAny && match.Protocol != packet.Protocol {
		return false
	}
	if len(match.DstPorts) == 0 {
		return true
	}
	for _, p := range match.DstPorts {
		if packet.DestPort >= p.From && packet.DestPort <= p.To {
			return true
		}
	}
	return false
}

func resolveRouteTables(tables map[string]model.RouteTable, packet Packet) (Decision, bool) {
	var selected *model.Route
	selectedName := ""
	for tableName, table := range tables {
		if table.VPC != packet.VPC {
			continue
		}
		for i := range table.Routes {
			route := &table.Routes[i]
			if !route.Destination.Contains(packet.Dest) {
				continue
			}
			if selected == nil || route.Destination.Bits() > selected.Destination.Bits() {
				selected = route
				selectedName = tableName
			}
		}
	}
	if selected == nil {
		return Decision{}, false
	}
	if selected.Blackhole {
		return Decision{Action: model.ActionDrop, MatchedBy: "route-table/" + selectedName}, true
	}
	return Decision{
		Action:    model.ActionReroute,
		NextHop:   selected.NextHop,
		MatchedBy: "route-table/" + selectedName,
	}, true
}

func applyNATAndGateway(state State, packet Packet, decision Decision) Decision {
	if decision.Action == model.ActionDrop {
		return decision
	}
	if decision.Action == "" {
		decision.Action = model.ActionAllow
	}
	for _, rule := range state.NATRules {
		if rule.VPC != packet.VPC || rule.Type != model.ActionSNAT || !rule.MatchCIDR.Contains(packet.Source) {
			continue
		}
		decision.Translated = rule.ExternalIP
		break
	}
	for _, gateway := range state.Gateways {
		if gateway.VPC == packet.VPC {
			decision.Gateway = gateway.Name
			break
		}
	}
	return decision
}
