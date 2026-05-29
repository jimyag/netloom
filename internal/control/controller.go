package control

import (
	"context"
	"fmt"
	"sort"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
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

type MultiTopologyBackend []TopologyBackend

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
		program, err := policy.CompileForEndpoint(endpoint, groups)
		if err != nil {
			return err
		}
		if err := c.policy.ApplyEndpointProgram(ctx, program); err != nil {
			return fmt.Errorf("apply policy program for endpoint %s: %w", endpoint.ID, err)
		}
	}
	return nil
}
