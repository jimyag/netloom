package control

import (
	"context"
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
	m.Subnets[subnet.Name] = subnet
	return nil
}

func (m *MemoryBackend) EnsureEndpoint(_ context.Context, endpoint model.Endpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Endpoints[endpoint.ID] = endpoint
	return nil
}

func (m *MemoryBackend) EnsureRouteTable(_ context.Context, table model.RouteTable) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RouteTables[table.Name] = table
	return nil
}

func (m *MemoryBackend) EnsurePolicyRoute(_ context.Context, route model.PolicyRoute) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PolicyRoutes = append(m.PolicyRoutes, route)
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
	m.NATRules[rule.Name] = rule
	return nil
}

func (m *MemoryBackend) EnsureLoadBalancer(_ context.Context, lb model.LoadBalancer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.LoadBalancers[lb.Name] = lb
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
	m.Subnets = cloneMap(state.Subnets)
	m.Endpoints = cloneMap(state.Endpoints)
	m.RouteTables = cloneMap(state.RouteTables)
	m.Gateways = cloneMap(state.Gateways)
	m.NATRules = cloneMap(state.NATRules)
	m.LoadBalancers = cloneMap(state.LoadBalancers)
	return nil
}

func (m *MemoryBackend) ApplyEndpointProgram(_ context.Context, program policy.Program) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PolicyProgram[program.EndpointID] = program
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
		Subnets:       cloneMap(m.Subnets),
		Endpoints:     cloneMap(m.Endpoints),
		RouteTables:   cloneMap(m.RouteTables),
		PolicyRoutes:  append([]model.PolicyRoute(nil), m.PolicyRoutes...),
		Gateways:      cloneMap(m.Gateways),
		NATRules:      cloneMap(m.NATRules),
		LoadBalancers: cloneMap(m.LoadBalancers),
	}
}

func cloneMap[K comparable, V any](in map[K]V) map[K]V {
	out := make(map[K]V, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
