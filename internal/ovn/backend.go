package ovn

import (
	"context"

	"github.com/jimyag/netloom/internal/model"
)

type Backend struct {
	planner  *Planner
	executor Executor
}

func NewBackend(executor Executor) *Backend {
	return &Backend{planner: NewPlanner(), executor: executor}
}

func (b *Backend) EnsureVPC(ctx context.Context, vpc model.VPC) error {
	return b.apply(ctx, func() error { return b.planner.EnsureVPC(ctx, vpc) })
}

func (b *Backend) EnsureSubnet(ctx context.Context, subnet model.Subnet) error {
	return b.apply(ctx, func() error { return b.planner.EnsureSubnet(ctx, subnet) })
}

func (b *Backend) EnsureEndpoint(ctx context.Context, endpoint model.Endpoint) error {
	return b.apply(ctx, func() error { return b.planner.EnsureEndpoint(ctx, endpoint) })
}

func (b *Backend) EnsureRouteTable(ctx context.Context, table model.RouteTable) error {
	return b.apply(ctx, func() error { return b.planner.EnsureRouteTable(ctx, table) })
}

func (b *Backend) EnsurePolicyRoute(ctx context.Context, route model.PolicyRoute) error {
	return b.apply(ctx, func() error { return b.planner.EnsurePolicyRoute(ctx, route) })
}

func (b *Backend) EnsureGateway(ctx context.Context, gateway model.Gateway) error {
	return b.apply(ctx, func() error { return b.planner.EnsureGateway(ctx, gateway) })
}

func (b *Backend) EnsureNATRule(ctx context.Context, rule model.NATRule) error {
	return b.apply(ctx, func() error { return b.planner.EnsureNATRule(ctx, rule) })
}

func (b *Backend) Operations() []Operation {
	return b.planner.Operations()
}

func (b *Backend) apply(ctx context.Context, plan func() error) error {
	before := len(b.planner.Operations())
	if err := plan(); err != nil {
		return err
	}
	planned := b.planner.Operations()
	next := planned[before:]
	if len(next) == 0 || b.executor == nil {
		return nil
	}
	return b.executor.Execute(ctx, next)
}
