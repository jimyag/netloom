package control

import (
	"context"
	"fmt"
	"sort"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
	"github.com/jimyag/netloom/internal/topology"
)

type TopologyBackend interface {
	EnsureVPC(context.Context, model.VPC) error
	EnsureSubnet(context.Context, model.Subnet) error
	EnsureEndpoint(context.Context, model.Endpoint) error
	EnsureRouteTable(context.Context, model.RouteTable) error
	EnsurePolicyRoute(context.Context, model.PolicyRoute) error
	EnsureGateway(context.Context, model.Gateway) error
	EnsureNATRule(context.Context, model.NATRule) error
}

type TopologyLifecycleBackend interface {
	BeginTopologyReconcile(context.Context, topology.State) error
	CleanupTopology(context.Context, topology.State) error
}

type MultiTopologyBackend []TopologyBackend

func (m MultiTopologyBackend) BeginTopologyReconcile(ctx context.Context, state topology.State) error {
	for _, backend := range m {
		if lifecycle, ok := backend.(TopologyLifecycleBackend); ok {
			if err := lifecycle.BeginTopologyReconcile(ctx, state); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m MultiTopologyBackend) CleanupTopology(ctx context.Context, state topology.State) error {
	for _, backend := range m {
		if lifecycle, ok := backend.(TopologyLifecycleBackend); ok {
			if err := lifecycle.CleanupTopology(ctx, state); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsureVPC(ctx context.Context, vpc model.VPC) error {
	for _, backend := range m {
		if err := backend.EnsureVPC(ctx, vpc); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsureSubnet(ctx context.Context, subnet model.Subnet) error {
	for _, backend := range m {
		if err := backend.EnsureSubnet(ctx, subnet); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsureEndpoint(ctx context.Context, endpoint model.Endpoint) error {
	for _, backend := range m {
		if err := backend.EnsureEndpoint(ctx, endpoint); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsureRouteTable(ctx context.Context, table model.RouteTable) error {
	for _, backend := range m {
		if err := backend.EnsureRouteTable(ctx, table); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsurePolicyRoute(ctx context.Context, route model.PolicyRoute) error {
	for _, backend := range m {
		if err := backend.EnsurePolicyRoute(ctx, route); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsureGateway(ctx context.Context, gateway model.Gateway) error {
	for _, backend := range m {
		if err := backend.EnsureGateway(ctx, gateway); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsureNATRule(ctx context.Context, rule model.NATRule) error {
	for _, backend := range m {
		if err := backend.EnsureNATRule(ctx, rule); err != nil {
			return err
		}
	}
	return nil
}

type PolicyBackend interface {
	ApplyEndpointProgram(context.Context, policy.Program) error
}

type PolicyLifecycleBackend interface {
	CleanupPolicy(context.Context, DesiredState) error
}

type DesiredState struct {
	VPCs           []model.VPC           `json:"vpcs"`
	Subnets        []model.Subnet        `json:"subnets"`
	Endpoints      []model.Endpoint      `json:"endpoints"`
	RouteTables    []model.RouteTable    `json:"route_tables"`
	PolicyRoutes   []model.PolicyRoute   `json:"policy_routes"`
	Gateways       []model.Gateway       `json:"gateways"`
	NATRules       []model.NATRule       `json:"nat_rules"`
	SecurityGroups []model.SecurityGroup `json:"security_groups"`
}

type Controller struct {
	topology TopologyBackend
	policy   PolicyBackend
}

func NewController(topology TopologyBackend, policy PolicyBackend) *Controller {
	return &Controller{topology: topology, policy: policy}
}

func (c *Controller) Reconcile(ctx context.Context, state DesiredState) error {
	groups := make(map[string]model.SecurityGroup, len(state.SecurityGroups))
	for _, group := range state.SecurityGroups {
		if err := group.Validate(); err != nil {
			return err
		}
		groups[group.Name] = group
	}
	topologyState := desiredTopologyState(state)
	if lifecycle, ok := c.topology.(TopologyLifecycleBackend); ok {
		if err := lifecycle.BeginTopologyReconcile(ctx, topologyState); err != nil {
			return fmt.Errorf("begin topology reconcile: %w", err)
		}
	}

	for _, vpc := range state.VPCs {
		if err := vpc.Validate(); err != nil {
			return err
		}
		if err := c.topology.EnsureVPC(ctx, vpc); err != nil {
			return fmt.Errorf("ensure vpc %s: %w", vpc.Name, err)
		}
	}
	for _, subnet := range state.Subnets {
		if err := subnet.Validate(); err != nil {
			return err
		}
		if err := c.topology.EnsureSubnet(ctx, subnet); err != nil {
			return fmt.Errorf("ensure subnet %s: %w", subnet.Name, err)
		}
	}
	for _, rt := range state.RouteTables {
		if err := rt.Validate(); err != nil {
			return err
		}
		if err := c.topology.EnsureRouteTable(ctx, rt); err != nil {
			return fmt.Errorf("ensure route table %s: %w", rt.Name, err)
		}
	}
	policyRoutes := append([]model.PolicyRoute(nil), state.PolicyRoutes...)
	sort.SliceStable(policyRoutes, func(i, j int) bool {
		return policyRoutes[i].Priority > policyRoutes[j].Priority
	})
	for _, route := range policyRoutes {
		if err := route.Validate(); err != nil {
			return err
		}
		if err := c.topology.EnsurePolicyRoute(ctx, route); err != nil {
			return fmt.Errorf("ensure policy route %s: %w", route.Name, err)
		}
	}
	for _, gateway := range state.Gateways {
		if err := gateway.Validate(); err != nil {
			return err
		}
		if err := c.topology.EnsureGateway(ctx, gateway); err != nil {
			return fmt.Errorf("ensure gateway %s: %w", gateway.Name, err)
		}
	}
	for _, rule := range state.NATRules {
		if err := rule.Validate(); err != nil {
			return err
		}
		if err := c.topology.EnsureNATRule(ctx, rule); err != nil {
			return fmt.Errorf("ensure nat rule %s: %w", rule.Name, err)
		}
	}
	for _, endpoint := range state.Endpoints {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		if err := c.topology.EnsureEndpoint(ctx, endpoint); err != nil {
			return fmt.Errorf("ensure endpoint %s: %w", endpoint.ID, err)
		}
		program, err := policy.CompileForEndpointWithState(endpoint, groups, state.Endpoints)
		if err != nil {
			return err
		}
		if err := c.policy.ApplyEndpointProgram(ctx, program); err != nil {
			return fmt.Errorf("apply policy program for endpoint %s: %w", endpoint.ID, err)
		}
	}
	if lifecycle, ok := c.topology.(TopologyLifecycleBackend); ok {
		if err := lifecycle.CleanupTopology(ctx, topologyState); err != nil {
			return fmt.Errorf("cleanup topology: %w", err)
		}
	}
	if lifecycle, ok := c.policy.(PolicyLifecycleBackend); ok {
		if err := lifecycle.CleanupPolicy(ctx, state); err != nil {
			return fmt.Errorf("cleanup policy: %w", err)
		}
	}
	return nil
}

func desiredTopologyState(state DesiredState) topology.State {
	vpcs := make(map[string]model.VPC, len(state.VPCs))
	for _, vpc := range state.VPCs {
		vpcs[vpc.Name] = vpc
	}
	subnets := make(map[string]model.Subnet, len(state.Subnets))
	for _, subnet := range state.Subnets {
		subnets[subnet.Name] = subnet
	}
	endpoints := make(map[string]model.Endpoint, len(state.Endpoints))
	for _, endpoint := range state.Endpoints {
		endpoints[endpoint.ID] = endpoint
	}
	routeTables := make(map[string]model.RouteTable, len(state.RouteTables))
	for _, table := range state.RouteTables {
		routeTables[table.Name] = table
	}
	gateways := make(map[string]model.Gateway, len(state.Gateways))
	for _, gateway := range state.Gateways {
		gateways[gateway.Name] = gateway
	}
	natRules := make(map[string]model.NATRule, len(state.NATRules))
	for _, rule := range state.NATRules {
		natRules[rule.Name] = rule
	}
	return topology.State{
		VPCs:         vpcs,
		Subnets:      subnets,
		Endpoints:    endpoints,
		RouteTables:  routeTables,
		PolicyRoutes: append([]model.PolicyRoute(nil), state.PolicyRoutes...),
		Gateways:     gateways,
		NATRules:     natRules,
	}
}
