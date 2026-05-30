package ovn

import (
	"context"
	"sync"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/topology"
)

type Backend struct {
	planner  *Planner
	executor Executor
	mu       sync.Mutex
	last     desiredSnapshot
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

func (b *Backend) EnsureLoadBalancer(ctx context.Context, lb model.LoadBalancer) error {
	return b.apply(ctx, func() error { return b.planner.EnsureLoadBalancer(ctx, lb) })
}

func (b *Backend) BeginTopologyReconcile(context.Context, topology.State) error {
	return nil
}

func (b *Backend) CleanupTopology(ctx context.Context, state topology.State) error {
	next := snapshotDesired(state)
	b.mu.Lock()
	ops := cleanupOperations(b.last, next)
	b.last = next
	b.mu.Unlock()
	b.planner.SyncLoadBalancerHealthChecks(next.LoadBalancers)

	if len(ops) == 0 {
		return nil
	}
	b.planner.Append(ops...)
	if b.executor == nil {
		return nil
	}
	return b.executor.Execute(ctx, ops)
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
