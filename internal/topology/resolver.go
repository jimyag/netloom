package topology

import (
	"fmt"
	"hash/fnv"
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
	SourcePort uint16
	VPC        string
	Source     netip.Addr
	Dest       netip.Addr
	Protocol   model.Protocol
	DestPort   uint16
}

type Decision struct {
	Action         model.Action
	NextHop        netip.Addr
	NextHops       []netip.Addr
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

	if decision, ok := resolveDNAT(state, packet); ok {
		return decision, nil
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

func resolveDNAT(state State, packet Packet) (Decision, bool) {
	for _, rule := range state.NATRules {
		if rule.VPC != packet.VPC || (rule.Type != model.ActionDNAT && rule.Type != model.ActionDNATSNAT) || rule.ExternalIP != packet.Dest {
			continue
		}
		if !dnatPortMatches(rule, packet) {
			continue
		}
		translatedPort := uint16(0)
		if rule.TargetPort != 0 {
			translatedPort = rule.TargetPort
		}
		destination := rule.TargetIP.String()
		if endpointID := findEndpoint(state, packet.VPC, rule.TargetIP); endpointID != "" {
			destination = endpointID
		}
		return Decision{
			Action:         model.ActionAllow,
			Translated:     rule.TargetIP,
			TranslatedPort: translatedPort,
			MatchedBy:      "nat/" + rule.Name,
			Destination:    destination,
		}, true
	}
	return Decision{}, false
}

func dnatPortMatches(rule model.NATRule, packet Packet) bool {
	if rule.ExternalPort == 0 {
		return true
	}
	protocol := rule.Protocol
	if protocol == "" {
		protocol = model.ProtocolAny
	}
	return protocol == packet.Protocol && packet.DestPort == rule.ExternalPort
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
		backends := healthyLoadBalancerBackends(lb)
		if len(backends) == 0 {
			continue
		}
		backend := selectLoadBalancerBackend(lb, backends, packet)
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

func healthyLoadBalancerBackends(lb model.LoadBalancer) []model.LoadBalancerBackend {
	backends := make([]model.LoadBalancerBackend, 0, len(lb.Backends))
	for _, backend := range lb.Backends {
		if backend.IsHealthy() {
			backends = append(backends, backend)
		}
	}
	return backends
}

func selectLoadBalancerBackend(lb model.LoadBalancer, backends []model.LoadBalancerBackend, packet Packet) model.LoadBalancerBackend {
	selected := backends[0]
	selectionFields := lb.EffectiveSelectionFields()
	selectedScore := loadBalancerBackendScore(selected, packet, selectionFields)
	for _, backend := range backends[1:] {
		score := loadBalancerBackendScore(backend, packet, selectionFields)
		if score > selectedScore || (score == selectedScore && compareLoadBalancerBackend(backend, selected) < 0) {
			selected = backend
			selectedScore = score
		}
	}
	return selected
}

func loadBalancerBackendScore(backend model.LoadBalancerBackend, packet Packet, selectionFields []string) uint32 {
	hash := fnv.New32a()
	if len(selectionFields) > 0 {
		_, _ = fmt.Fprintf(hash, "%s|%s|%d", packet.VPC, backend.IP, backend.Port)
		for _, field := range selectionFields {
			_, _ = fmt.Fprintf(hash, "|%s=%s", field, loadBalancerSelectionValue(field, packet))
		}
		return hash.Sum32()
	}
	_, _ = fmt.Fprintf(hash, "%s|%s|%d|%s|%s|%d|%s|%d",
		packet.VPC,
		packet.Source,
		packet.SourcePort,
		packet.Dest,
		packet.Protocol,
		packet.DestPort,
		backend.IP,
		backend.Port,
	)
	return hash.Sum32()
}

func loadBalancerSelectionValue(field string, packet Packet) string {
	switch field {
	case "ip_src", "ipv6_src":
		return packet.Source.String()
	case "ip_dst", "ipv6_dst":
		return packet.Dest.String()
	case "tp_src":
		return fmt.Sprint(packet.SourcePort)
	case "tp_dst":
		return fmt.Sprint(packet.DestPort)
	default:
		return ""
	}
}

func compareLoadBalancerBackend(a, b model.LoadBalancerBackend) int {
	if cmp := a.IP.Compare(b.IP); cmp != 0 {
		return cmp
	}
	if a.Port < b.Port {
		return -1
	}
	if a.Port > b.Port {
		return 1
	}
	return 0
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
			NextHops:  route.Action.RerouteNextHops(),
			MatchedBy: "policy-route/" + route.Name,
		}
		if len(decision.NextHops) > 0 {
			decision.NextHop = decision.NextHops[0]
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
	nextHops := selected.RouteNextHops()
	decision := Decision{
		Action:    model.ActionReroute,
		NextHops:  nextHops,
		MatchedBy: "route-table/" + selectedName,
	}
	if len(nextHops) > 0 {
		decision.NextHop = nextHops[0]
	}
	return decision, true
}

func applyNATAndGateway(state State, packet Packet, decision Decision) Decision {
	if decision.Action == model.ActionDrop {
		return decision
	}
	if decision.Action == "" {
		decision.Action = model.ActionAllow
	}
	for _, rule := range sortedNATRules(state.NATRules) {
		if rule.VPC != packet.VPC || rule.Type != model.ActionSNAT || !rule.MatchCIDR.Contains(packet.Source) {
			continue
		}
		decision.Translated = rule.ExternalIP
		break
	}
	for _, gateway := range sortedGateways(state.Gateways) {
		if gateway.VPC != packet.VPC {
			continue
		}
		if decision.NextHop.IsValid() && gateway.LANIP != decision.NextHop {
			continue
		}
		decision.Gateway = gateway.Name
		return decision
	}
	for _, gateway := range sortedGateways(state.Gateways) {
		if gateway.VPC == packet.VPC {
			decision.Gateway = gateway.Name
			return decision
		}
	}
	return decision
}

func sortedNATRules(rules map[string]model.NATRule) []model.NATRule {
	names := make([]string, 0, len(rules))
	for name := range rules {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]model.NATRule, 0, len(names))
	for _, name := range names {
		out = append(out, rules[name])
	}
	return out
}

func sortedGateways(gateways map[string]model.Gateway) []model.Gateway {
	names := make([]string, 0, len(gateways))
	for name := range gateways {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]model.Gateway, 0, len(names))
	for _, name := range names {
		out = append(out, gateways[name])
	}
	return out
}
