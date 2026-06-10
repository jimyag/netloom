package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/ovn"
)

func main() {
	ctx := context.Background()
	if stateFile := os.Getenv("NETLOOM_STATE_FILE"); stateFile != "" {
		if err := runStateFile(ctx, stateFile); err != nil {
			log.Fatal(err)
		}
		return
	}

	result, err := control.RunSelfTest(ctx)
	if db := os.Getenv("NETLOOM_OVN_NBCTL_DB"); db != "" {
		executor, executorErr := newNBCTLExecutorFromEnv(db)
		if executorErr != nil {
			log.Fatal(executorErr)
		}
		result, err = control.RunOVNSelfTest(ctx, executor)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("netloom-controller reconciled bootstrap state policy_next_hop=%s snat=%s gateway=%s service_backend=%s:%d dnat=%s floating_ip=%s ovn_ops=%d ovn_executed=%d\n", result.PolicyRouteNextHop, result.SNATAddress, result.Gateway, result.ServiceBackend, result.ServiceBackendPort, result.DNATTarget, result.FloatingIPTarget, result.OVNOperations, result.OVNExecuted)
}

func runStateFile(ctx context.Context, path string) error {
	interval, err := reconcileInterval()
	if err != nil {
		return err
	}
	reconciler, err := newStateFileReconciler()
	if err != nil {
		return err
	}
	reconcile := func() error {
		return reconciler.reconcile(ctx, path)
	}
	if interval == 0 {
		return reconcile()
	}
	for {
		if err := reconcile(); err != nil {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

type stateFileReconciler struct {
	memory        *control.MemoryBackend
	executor      ovn.Executor
	ovnBackend    *ovn.Backend
	controller    *control.Controller
	healthTracker *control.LoadBalancerHealthTracker
}

func newStateFileReconciler() (*stateFileReconciler, error) {
	memory := control.NewMemoryBackend()
	var executor ovn.Executor = ovn.NewRecorderExecutor()
	if db := os.Getenv("NETLOOM_OVN_NBCTL_DB"); db != "" {
		nbctl, err := newNBCTLExecutorFromEnv(db)
		if err != nil {
			return nil, err
		}
		executor = nbctl
	}
	ovnBackend := ovn.NewBackend(executor)
	return &stateFileReconciler{
		memory:        memory,
		executor:      executor,
		ovnBackend:    ovnBackend,
		controller:    control.NewController(control.MultiTopologyBackend{memory, ovnBackend}, memory),
		healthTracker: control.NewLoadBalancerHealthTracker(),
	}, nil
}

func (r *stateFileReconciler) reconcile(ctx context.Context, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	state, err := control.LoadDesiredStateJSON(file)
	if err != nil {
		return err
	}
	healthSummary, err := r.applyLoadBalancerHealthChecks(ctx, &state)
	if err != nil {
		return err
	}

	opsBefore := len(r.ovnBackend.Operations())
	executedBefore := r.executedOperations()
	if err := r.controller.Reconcile(ctx, state); err != nil {
		return err
	}

	ovnOps := len(r.ovnBackend.Operations()) - opsBefore
	executed := r.executedOperations() - executedBefore
	fmt.Printf(
		"netloom-controller reconciled desired state vpcs=%d subnets=%d endpoints=%d route_tables=%d policy_routes=%d gateways=%d nat_rules=%d load_balancers=%d security_groups=%d policy_entries=%d lb_health_checked=%d lb_health_healthy=%d lb_health_unhealthy=%d ovn_ops=%d ovn_executed=%d\n",
		len(state.VPCs),
		len(state.Subnets),
		len(state.Endpoints),
		len(state.RouteTables),
		len(state.PolicyRoutes),
		len(state.Gateways),
		len(state.NATRules),
		len(state.LoadBalancers),
		len(state.SecurityGroups),
		countPolicyEntries(r.memory),
		healthSummary.Checked,
		healthSummary.Healthy,
		healthSummary.Unhealthy,
		ovnOps,
		executed,
	)
	return nil
}

func (r *stateFileReconciler) applyLoadBalancerHealthChecks(ctx context.Context, state *control.DesiredState) (control.LoadBalancerHealthSummary, error) {
	if os.Getenv("NETLOOM_LB_HEALTH_PROBE") != "1" {
		return control.LoadBalancerHealthSummary{}, nil
	}
	next, summary, err := control.ApplyLoadBalancerHealthChecksWithTracker(ctx, *state, nil, r.healthTracker)
	if err != nil {
		return summary, err
	}
	*state = next
	return summary, nil
}

func (r *stateFileReconciler) executedOperations() int {
	if recorder, ok := r.executor.(*ovn.RecorderExecutor); ok {
		return len(recorder.Operations())
	}
	return len(r.ovnBackend.Operations())
}

func reconcileInterval() (time.Duration, error) {
	raw := os.Getenv("NETLOOM_RECONCILE_INTERVAL_MS")
	if raw == "" {
		return 0, nil
	}
	ms, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NETLOOM_RECONCILE_INTERVAL_MS: %w", err)
	}
	if ms <= 0 {
		return 0, nil
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func newNBCTLExecutorFromEnv(db string) (*ovn.NBCTLExecutor, error) {
	executor := ovn.NewNBCTLExecutor("ovn-nbctl", "--db="+db)
	timeout, err := nbctlTimeout()
	if err != nil {
		return nil, err
	}
	executor.Timeout = timeout
	retryAttempts, err := nbctlRetryAttempts()
	if err != nil {
		return nil, err
	}
	executor.RetryPolicy.Attempts = retryAttempts
	return executor, nil
}

func nbctlTimeout() (time.Duration, error) {
	raw := os.Getenv("NETLOOM_OVN_NBCTL_TIMEOUT_MS")
	if raw == "" {
		return ovn.DefaultNBCTLTimeout, nil
	}
	ms, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NETLOOM_OVN_NBCTL_TIMEOUT_MS: %w", err)
	}
	if ms <= 0 {
		return 0, nil
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func nbctlRetryAttempts() (int, error) {
	raw := os.Getenv("NETLOOM_OVN_NBCTL_RETRY_ATTEMPTS")
	if raw == "" {
		return ovn.DefaultNBCTLRetryAttempts, nil
	}
	attempts, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NETLOOM_OVN_NBCTL_RETRY_ATTEMPTS: %w", err)
	}
	if attempts <= 0 {
		return 1, nil
	}
	return attempts, nil
}

func countPolicyEntries(memory *control.MemoryBackend) int {
	total := 0
	for _, program := range memory.PolicyProgram {
		total += len(program.MapEntries)
	}
	return total
}
