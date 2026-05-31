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
	history  []Operation
	skipNAT  map[string]string
}

const operationHistoryLimit = 4096

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
	return b.apply(ctx, func() error {
		if b.skipUnchangedNATRuleLocked(rule) {
			return nil
		}
		return b.planner.EnsureNATRule(ctx, rule)
	})
}

func (b *Backend) EnsureLoadBalancer(ctx context.Context, lb model.LoadBalancer) error {
	return b.apply(ctx, func() error { return b.planner.EnsureLoadBalancer(ctx, lb) })
}

func (b *Backend) BeginTopologyReconcile(context.Context, topology.State) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.skipNAT = nil
	return nil
}

func (b *Backend) CleanupTopology(ctx context.Context, state topology.State) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	next := snapshotDesired(state)
	ops := cleanupOperations(b.last, next)
	b.skipNAT = unchangedNATRules(b.last, next)
	b.last = next
	b.planner.SyncLoadBalancerHealthChecks(next.LoadBalancers)

	if len(ops) == 0 {
		return nil
	}
	b.planner.Append(ops...)
	if b.executor == nil {
		return nil
	}
	if err := b.executor.Execute(ctx, ops); err != nil {
		return err
	}
	b.recordOperationsLocked(ops)
	b.planner.DiscardOperations(len(b.planner.Operations()))
	return nil
}

func (b *Backend) skipUnchangedNATRuleLocked(rule model.NATRule) bool {
	if len(b.skipNAT) == 0 {
		return false
	}
	signature, ok := b.skipNAT[rule.Name]
	return ok && signature == natRuleSignature(rule)
}

func (b *Backend) Operations() []Operation {
	b.mu.Lock()
	defer b.mu.Unlock()
	ops := cloneOperations(b.history)
	ops = append(ops, b.planner.Operations()...)
	return ops
}

func (b *Backend) apply(ctx context.Context, plan func() error) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	before := len(b.planner.Operations())
	if err := plan(); err != nil {
		return err
	}
	planned := b.planner.Operations()
	next := planned[before:]
	if len(next) == 0 || b.executor == nil {
		return nil
	}
	if err := b.executor.Execute(ctx, next); err != nil {
		return err
	}
	b.recordOperationsLocked(next)
	b.planner.DiscardOperations(len(planned))
	return nil
}

func (b *Backend) recordOperationsLocked(ops []Operation) {
	if len(ops) == 0 {
		return
	}
	b.history = append(b.history, cloneOperations(ops)...)
	if len(b.history) > operationHistoryLimit {
		b.history = append([]Operation(nil), b.history[len(b.history)-operationHistoryLimit:]...)
	}
}
