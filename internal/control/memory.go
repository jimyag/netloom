package control

import (
	"context"
	"net/netip"
	"sync"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
	"github.com/jimyag/netloom/internal/topology"
)

type MemoryBackend struct {
	mu            sync.Mutex
	VPCs          map[string]model.VPC
	Subnets       map[string]model.Subnet
	Endpoints     map[string]model.Endpoint
	RouteTables   map[string]model.RouteTable
	PolicyRoutes  []model.PolicyRoute
	Gateways      map[string]model.Gateway
	NATRules      map[string]model.NATRule
	LoadBalancers map[string]model.LoadBalancer
	PolicyProgram map[string]policy.Program
}

func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{
		VPCs:          make(map[string]model.VPC),
		Subnets:       make(map[string]model.Subnet),
		Endpoints:     make(map[string]model.Endpoint),
		RouteTables:   make(map[string]model.RouteTable),
		Gateways:      make(map[string]model.Gateway),
		NATRules:      make(map[string]model.NATRule),
		LoadBalancers: make(map[string]model.LoadBalancer),
		PolicyProgram: make(map[string]policy.Program),
	}
}

func (m *MemoryBackend) EnsureVPC(_ context.Context, vpc model.VPC) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.VPCs[vpc.Name] = vpc
	return nil
}

func (m *MemoryBackend) EnsureSubnet(_ context.Context, subnet model.Subnet) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Subnets[subnetKey(subnet.VPC, subnet.Name)] = cloneSubnet(subnet)
	return nil
}

func (m *MemoryBackend) EnsureEndpoint(_ context.Context, endpoint model.Endpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Endpoints[endpoint.ID] = cloneEndpoint(endpoint)
	return nil
}

func (m *MemoryBackend) EnsureRouteTable(_ context.Context, table model.RouteTable) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RouteTables[routeTableKey(table.VPC, table.Name)] = cloneRouteTable(table)
	return nil
}

func (m *MemoryBackend) EnsurePolicyRoute(_ context.Context, route model.PolicyRoute) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PolicyRoutes = append(m.PolicyRoutes, clonePolicyRoute(route))
	return nil
}

func (m *MemoryBackend) EnsureGateway(_ context.Context, gateway model.Gateway) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Gateways[gateway.Name] = gateway
	return nil
}

func (m *MemoryBackend) EnsureNATRule(_ context.Context, rule model.NATRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.NATRules[natRuleKey(rule.VPC, rule.Name)] = rule
	return nil
}

func (m *MemoryBackend) EnsureLoadBalancer(_ context.Context, lb model.LoadBalancer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.LoadBalancers[loadBalancerKey(lb.VPC, lb.Name)] = cloneLoadBalancer(lb)
	return nil
}

func (m *MemoryBackend) BeginTopologyReconcile(context.Context, topology.State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PolicyRoutes = nil
	return nil
}

func (m *MemoryBackend) CleanupTopology(_ context.Context, state topology.State) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.VPCs = cloneMap(state.VPCs)
	m.Subnets = cloneMapValues(state.Subnets, cloneSubnet)
	m.Endpoints = cloneMapValues(state.Endpoints, cloneEndpoint)
	m.RouteTables = cloneMapValues(state.RouteTables, cloneRouteTable)
	m.Gateways = cloneMap(state.Gateways)
	m.NATRules = cloneMap(state.NATRules)
	m.LoadBalancers = cloneMapValues(state.LoadBalancers, cloneLoadBalancer)
	return nil
}

func (m *MemoryBackend) ApplyEndpointProgram(_ context.Context, program policy.Program) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PolicyProgram[program.EndpointID] = clonePolicyProgram(program)
	return nil
}

func (m *MemoryBackend) CleanupPolicy(_ context.Context, state DesiredState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	keep := make(map[string]struct{}, len(state.Endpoints))
	for _, endpoint := range state.Endpoints {
		keep[endpoint.ID] = struct{}{}
	}
	for endpointID := range m.PolicyProgram {
		if _, ok := keep[endpointID]; !ok {
			delete(m.PolicyProgram, endpointID)
		}
	}
	return nil
}

func (m *MemoryBackend) TopologyState() topology.State {
	m.mu.Lock()
	defer m.mu.Unlock()

	return topology.State{
		VPCs:          cloneMap(m.VPCs),
		Subnets:       cloneMapValues(m.Subnets, cloneSubnet),
		Endpoints:     cloneMapValues(m.Endpoints, cloneEndpoint),
		RouteTables:   cloneMapValues(m.RouteTables, cloneRouteTable),
		PolicyRoutes:  clonePolicyRoutes(m.PolicyRoutes),
		Gateways:      cloneMap(m.Gateways),
		NATRules:      cloneMap(m.NATRules),
		LoadBalancers: cloneMapValues(m.LoadBalancers, cloneLoadBalancer),
	}
}

func cloneMap[K comparable, V any](in map[K]V) map[K]V {
	out := make(map[K]V, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneMapValues[K comparable, V any](in map[K]V, clone func(V) V) map[K]V {
	out := make(map[K]V, len(in))
	for k, v := range in {
		out[k] = clone(v)
	}
	return out
}

func cloneSubnet(subnet model.Subnet) model.Subnet {
	subnet.ExcludeCIDRs = append([]netip.Prefix(nil), subnet.ExcludeCIDRs...)
	subnet.DHCP.DNSServers = append([]netip.Addr(nil), subnet.DHCP.DNSServers...)
	subnet.DHCP.SearchDomains = append([]string(nil), subnet.DHCP.SearchDomains...)
	return subnet
}

func cloneEndpoint(endpoint model.Endpoint) model.Endpoint {
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

func cloneRouteTable(table model.RouteTable) model.RouteTable {
	table.Routes = append([]model.Route(nil), table.Routes...)
	for i := range table.Routes {
		table.Routes[i] = cloneRoute(table.Routes[i])
	}
	return table
}

func cloneRoute(route model.Route) model.Route {
	route.NextHops = append([]netip.Addr(nil), route.NextHops...)
	return route
}

func clonePolicyRoutes(routes []model.PolicyRoute) []model.PolicyRoute {
	out := make([]model.PolicyRoute, len(routes))
	for i := range routes {
		out[i] = clonePolicyRoute(routes[i])
	}
	return out
}

func clonePolicyRoute(route model.PolicyRoute) model.PolicyRoute {
	route.Match.SrcPorts = append([]model.PortRange(nil), route.Match.SrcPorts...)
	route.Match.DstPorts = append([]model.PortRange(nil), route.Match.DstPorts...)
	route.Action.NextHops = append([]netip.Addr(nil), route.Action.NextHops...)
	return route
}

func cloneLoadBalancer(lb model.LoadBalancer) model.LoadBalancer {
	lb.Ports = append([]model.LoadBalancerPort(nil), lb.Ports...)
	for i := range lb.Ports {
		lb.Ports[i].Backends = append([]model.LoadBalancerBackend(nil), lb.Ports[i].Backends...)
	}
	lb.Subnets = append([]string(nil), lb.Subnets...)
	lb.SelectionFields = append([]string(nil), lb.SelectionFields...)
	return lb
}

func clonePolicyProgram(program policy.Program) policy.Program {
	program.MapEntries = append([]policy.MapEntry(nil), program.MapEntries...)
	program.Rules = append([]policy.Rule(nil), program.Rules...)
	for i := range program.Rules {
		program.Rules[i].Ports = append([]model.PortRange(nil), program.Rules[i].Ports...)
		program.Rules[i].NamedPorts = append([]string(nil), program.Rules[i].NamedPorts...)
		if program.Rules[i].ICMPType != nil {
			value := *program.Rules[i].ICMPType
			program.Rules[i].ICMPType = &value
		}
		if program.Rules[i].ICMPCode != nil {
			value := *program.Rules[i].ICMPCode
			program.Rules[i].ICMPCode = &value
		}
	}
	return program
}
