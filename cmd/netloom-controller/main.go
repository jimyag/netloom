package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn"
	"github.com/jimyag/netloom/internal/policy"
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
	failureBackoff, err := reconcileFailureBackoff(interval)
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
	metrics := newControllerMetrics()
	reconciler.metrics = metrics
	if closeMetrics, err := startControllerMetricsServer(ctx, os.Getenv("NETLOOM_CONTROLLER_METRICS_ADDR"), metrics); err != nil {
		return err
	} else {
		defer closeMetrics()
	}
	return runReconcileLoop(ctx, interval, failureBackoff, reconcile, func(err error) {
		log.Printf("netloom-controller reconcile failed: %v", err)
	})
}

type stateFileReconciler struct {
	memory        *control.MemoryBackend
	executor      ovn.Executor
	ovnBackend    *ovn.Backend
	controller    *control.Controller
	healthTracker *control.LoadBalancerHealthTracker
	healthChecker ovnHealthChecker
	ovnHealth     ovnHealthTracker
	metrics       *controllerMetrics
}

type ovnHealthChecker interface {
	HealthCheck(context.Context) (time.Duration, error)
}

type ovnAuditor interface {
	AuditManagedObjects(context.Context) (ovn.AuditStats, error)
}

type ovnHealthSnapshot struct {
	Status               string
	Latency              time.Duration
	ConsecutiveFailures  int
	ConsecutiveSuccesses int
	Recovering           bool
}

type ovnHealthTracker struct {
	consecutiveFailures  int
	consecutiveSuccesses int
	recovering           bool
}

func (t *ovnHealthTracker) recordSuccess(latency time.Duration) ovnHealthSnapshot {
	wasFailing := t.consecutiveFailures > 0
	t.consecutiveFailures = 0
	t.consecutiveSuccesses++
	t.recovering = wasFailing
	status := "ok"
	if t.recovering {
		status = "recovering"
	}
	return t.snapshot(status, latency)
}

func (t *ovnHealthTracker) recordFailure(latency time.Duration) ovnHealthSnapshot {
	t.consecutiveFailures++
	t.consecutiveSuccesses = 0
	t.recovering = false
	return t.snapshot("error", latency)
}

func (t ovnHealthTracker) disabled() ovnHealthSnapshot {
	return ovnHealthSnapshot{Status: "disabled"}
}

func (t ovnHealthTracker) snapshot(status string, latency time.Duration) ovnHealthSnapshot {
	if status == "" {
		status = "disabled"
	}
	return ovnHealthSnapshot{
		Status:               status,
		Latency:              latency,
		ConsecutiveFailures:  t.consecutiveFailures,
		ConsecutiveSuccesses: t.consecutiveSuccesses,
		Recovering:           t.recovering,
	}
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
		healthChecker: executorHealthChecker(executor),
	}, nil
}

func (r *stateFileReconciler) reconcile(ctx context.Context, path string) error {
	start := time.Now()
	ovnHealth := r.probeOVNHealth(ctx)
	var state control.DesiredState
	if ovnHealth.Snapshot.Status == "error" {
		reconcileErr := fmt.Errorf("ovn health check: %w", ovnHealth.err)
		duration := time.Since(start)
		printControllerReconcileFailure("ovn_health", state, control.LoadBalancerHealthSummary{}, ovnHealth.Snapshot, 0, 0, reconcileErr, duration)
		r.observeReconcileFailure("ovn_health", state, control.LoadBalancerHealthSummary{}, ovnHealth.Snapshot, 0, 0, reconcileErr, duration)
		return reconcileErr
	}
	file, err := os.Open(path)
	if err != nil {
		duration := time.Since(start)
		printControllerReconcileFailure("load_state", state, control.LoadBalancerHealthSummary{}, ovnHealth.Snapshot, 0, 0, err, duration)
		r.observeReconcileFailure("load_state", state, control.LoadBalancerHealthSummary{}, ovnHealth.Snapshot, 0, 0, err, duration)
		return err
	}
	defer file.Close()

	state, err = control.LoadDesiredStateJSON(file)
	if err != nil {
		duration := time.Since(start)
		printControllerReconcileFailure("load_state", state, control.LoadBalancerHealthSummary{}, ovnHealth.Snapshot, 0, 0, err, duration)
		r.observeReconcileFailure("load_state", state, control.LoadBalancerHealthSummary{}, ovnHealth.Snapshot, 0, 0, err, duration)
		return err
	}
	healthSummary, err := r.applyLoadBalancerHealthChecks(ctx, &state)
	if err != nil {
		duration := time.Since(start)
		printControllerReconcileFailure("lb_health", state, healthSummary, ovnHealth.Snapshot, 0, 0, err, duration)
		r.observeReconcileFailure("lb_health", state, healthSummary, ovnHealth.Snapshot, 0, 0, err, duration)
		return err
	}

	opsBefore := len(r.ovnBackend.Operations())
	executedBefore := r.executedOperations()
	if err := r.controller.Reconcile(ctx, state); err != nil {
		ovnOps := len(r.ovnBackend.Operations()) - opsBefore
		executed := r.executedOperations() - executedBefore
		duration := time.Since(start)
		printControllerReconcileFailure("apply", state, healthSummary, ovnHealth.Snapshot, ovnOps, executed, err, duration)
		r.observeReconcileFailure("apply", state, healthSummary, ovnHealth.Snapshot, ovnOps, executed, err, duration)
		return err
	}

	ovnOps := len(r.ovnBackend.Operations()) - opsBefore
	executed := r.executedOperations() - executedBefore
	ovnAudit, ovnAuditStatus, ovnAuditError := r.auditOVN(ctx)
	duration := time.Since(start)
	fmt.Printf(
		"netloom-controller reconciled desired state vpcs=%d subnets=%d endpoints=%d route_tables=%d policy_routes=%d gateways=%d nat_rules=%d load_balancers=%d security_groups=%d policy_entries=%d lb_health_checked=%d lb_health_healthy=%d lb_health_unhealthy=%d ovn_health=%s ovn_health_latency_ms=%d ovn_health_consecutive_failures=%d ovn_health_consecutive_successes=%d ovn_health_recovering=%d ovn_ops=%d ovn_executed=%d ovn_audit=%s ovn_live_managed=%d ovn_live_duplicates=%d ovn_live_incomplete=%d ovn_audit_error=%s reconcile_duration_ms=%d\n",
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
		ovnHealth.Snapshot.Status,
		ovnHealth.Snapshot.Latency.Milliseconds(),
		ovnHealth.Snapshot.ConsecutiveFailures,
		ovnHealth.Snapshot.ConsecutiveSuccesses,
		boolMetric(ovnHealth.Snapshot.Recovering),
		ovnOps,
		executed,
		ovnAuditStatus,
		ovnAudit.TotalManagedObjects(),
		ovnAudit.DuplicateManagedRows,
		ovnAudit.IncompleteManagedRows,
		formatResultError(ovnAuditError),
		duration.Milliseconds(),
	)
	r.observeReconcileSuccess(state, healthSummary, ovnHealth.Snapshot, ovnOps, executed, ovnAuditStatus, ovnAuditError, ovnAudit, duration)
	return nil
}

type ovnHealthProbe struct {
	Snapshot ovnHealthSnapshot
	err      error
}

func (r *stateFileReconciler) probeOVNHealth(ctx context.Context) ovnHealthProbe {
	if r == nil {
		return ovnHealthProbe{Snapshot: ovnHealthTracker{}.disabled()}
	}
	if r.healthChecker == nil {
		return ovnHealthProbe{Snapshot: r.ovnHealth.disabled()}
	}
	latency, err := r.healthChecker.HealthCheck(ctx)
	if err != nil {
		return ovnHealthProbe{Snapshot: r.ovnHealth.recordFailure(latency), err: err}
	}
	return ovnHealthProbe{Snapshot: r.ovnHealth.recordSuccess(latency)}
}

func printControllerReconcileFailure(phase string, state control.DesiredState, healthSummary control.LoadBalancerHealthSummary, ovnHealth ovnHealthSnapshot, ovnOps, executed int, err error, duration time.Duration) {
	if phase == "" {
		phase = "unknown"
	}
	fmt.Printf(
		"netloom-controller reconcile failed reconcile_phase=%s vpcs=%d subnets=%d endpoints=%d route_tables=%d policy_routes=%d gateways=%d nat_rules=%d load_balancers=%d security_groups=%d policy_entries=%d lb_health_checked=%d lb_health_healthy=%d lb_health_unhealthy=%d ovn_health=%s ovn_health_latency_ms=%d ovn_health_consecutive_failures=%d ovn_health_consecutive_successes=%d ovn_health_recovering=%d ovn_ops=%d ovn_executed=%d err=%q reconcile_duration_ms=%d\n",
		phase,
		len(state.VPCs),
		len(state.Subnets),
		len(state.Endpoints),
		len(state.RouteTables),
		len(state.PolicyRoutes),
		len(state.Gateways),
		len(state.NATRules),
		len(state.LoadBalancers),
		len(state.SecurityGroups),
		countDesiredPolicyEntries(state),
		healthSummary.Checked,
		healthSummary.Healthy,
		healthSummary.Unhealthy,
		fallbackMetricsLabel(ovnHealth.Status, "disabled"),
		ovnHealth.Latency.Milliseconds(),
		ovnHealth.ConsecutiveFailures,
		ovnHealth.ConsecutiveSuccesses,
		boolMetric(ovnHealth.Recovering),
		ovnOps,
		executed,
		err.Error(),
		duration.Milliseconds(),
	)
}

func (r *stateFileReconciler) observeReconcileSuccess(state control.DesiredState, healthSummary control.LoadBalancerHealthSummary, ovnHealth ovnHealthSnapshot, ovnOps, executed int, ovnAuditStatus, ovnAuditError string, ovnAudit ovn.AuditStats, duration time.Duration) {
	if r == nil || r.metrics == nil {
		return
	}
	r.metrics.observe(controllerMetricsSnapshot{
		State:                         state,
		PolicyEntries:                 countPolicyEntries(r.memory),
		HealthSummary:                 healthSummary,
		OVNHealthStatus:               ovnHealth.Status,
		OVNHealthLatency:              ovnHealth.Latency,
		OVNHealthConsecutiveFailures:  ovnHealth.ConsecutiveFailures,
		OVNHealthConsecutiveSuccesses: ovnHealth.ConsecutiveSuccesses,
		OVNHealthRecovering:           ovnHealth.Recovering,
		OVNOps:                        ovnOps,
		OVNExecuted:                   executed,
		OVNCleanup:                    r.lastOVNCleanupStats(),
		OVNAuditStatus:                fallbackMetricsLabel(ovnAuditStatus, "disabled"),
		OVNAuditError:                 ovnAuditError,
		OVNAudit:                      ovnAudit,
		Duration:                      duration,
		Success:                       true,
	})
}

func (r *stateFileReconciler) observeReconcileFailure(phase string, state control.DesiredState, healthSummary control.LoadBalancerHealthSummary, ovnHealth ovnHealthSnapshot, ovnOps, executed int, err error, duration time.Duration) {
	if r == nil || r.metrics == nil {
		return
	}
	if phase == "" {
		phase = "unknown"
	}
	message := ""
	if err != nil {
		message = err.Error()
	}
	r.metrics.observe(controllerMetricsSnapshot{
		State:                         state,
		PolicyEntries:                 countDesiredPolicyEntries(state),
		HealthSummary:                 healthSummary,
		OVNHealthStatus:               ovnHealth.Status,
		OVNHealthLatency:              ovnHealth.Latency,
		OVNHealthConsecutiveFailures:  ovnHealth.ConsecutiveFailures,
		OVNHealthConsecutiveSuccesses: ovnHealth.ConsecutiveSuccesses,
		OVNHealthRecovering:           ovnHealth.Recovering,
		OVNOps:                        ovnOps,
		OVNExecuted:                   executed,
		OVNCleanup:                    r.lastOVNCleanupStats(),
		OVNAuditStatus:                "disabled",
		Duration:                      duration,
		Success:                       false,
		Phase:                         phase,
		Error:                         message,
	})
}

func (r *stateFileReconciler) lastOVNCleanupStats() ovn.CleanupStats {
	if r == nil || r.ovnBackend == nil {
		return ovn.CleanupStats{}
	}
	return r.ovnBackend.LastCleanupStats()
}

func (r *stateFileReconciler) auditOVN(ctx context.Context) (ovn.AuditStats, string, string) {
	if r == nil || r.executor == nil {
		return ovn.AuditStats{}, "disabled", ""
	}
	auditor, ok := r.executor.(ovnAuditor)
	if !ok {
		return ovn.AuditStats{}, "disabled", ""
	}
	stats, err := auditor.AuditManagedObjects(ctx)
	if err != nil {
		return ovn.AuditStats{}, "error", err.Error()
	}
	return stats, "ok", ""
}

type controllerMetrics struct {
	mu       sync.RWMutex
	snapshot controllerMetricsSnapshot
	totals   controllerMetricsTotals
	ready    bool
}

type controllerMetricsSnapshot struct {
	State                         control.DesiredState
	PolicyEntries                 int
	HealthSummary                 control.LoadBalancerHealthSummary
	OVNHealthStatus               string
	OVNHealthLatency              time.Duration
	OVNHealthConsecutiveFailures  int
	OVNHealthConsecutiveSuccesses int
	OVNHealthRecovering           bool
	OVNOps                        int
	OVNExecuted                   int
	OVNCleanup                    ovn.CleanupStats
	OVNAuditStatus                string
	OVNAuditError                 string
	OVNAudit                      ovn.AuditStats
	Duration                      time.Duration
	Success                       bool
	Phase                         string
	Error                         string
}

type controllerMetricsTotals struct {
	Attempts              uint64
	Successes             uint64
	Failures              uint64
	DurationSum           time.Duration
	DurationBuckets       []uint64
	FailurePhases         map[string]uint64
	OVNOpsPlanned         uint64
	OVNOpsExecuted        uint64
	OVNCleanupOperations  uint64
	OVNCleanupStale       uint64
	OVNCleanupChanged     uint64
	LBHealthChecked       uint64
	LBHealthHealthy       uint64
	LBHealthUnhealthy     uint64
	OVNHealthChecks       uint64
	OVNHealthFailures     uint64
	OVNHealthLatencyTotal time.Duration
	OVNAuditChecks        uint64
	OVNAuditFailures      uint64
}

var controllerReconcileDurationBuckets = []time.Duration{
	10 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	2500 * time.Millisecond,
	5 * time.Second,
	10 * time.Second,
	30 * time.Second,
}

func newControllerMetrics() *controllerMetrics {
	return &controllerMetrics{totals: controllerMetricsTotals{
		DurationBuckets: make([]uint64, len(controllerReconcileDurationBuckets)),
		FailurePhases:   make(map[string]uint64),
	}}
}

func (m *controllerMetrics) observe(snapshot controllerMetricsSnapshot) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshot = snapshot
	m.totals.observe(snapshot)
	m.ready = true
}

func (t *controllerMetricsTotals) observe(snapshot controllerMetricsSnapshot) {
	t.Attempts++
	if snapshot.Success {
		t.Successes++
	} else {
		t.Failures++
		phase := fallbackMetricsLabel(snapshot.Phase, "unknown")
		if t.FailurePhases == nil {
			t.FailurePhases = make(map[string]uint64)
		}
		t.FailurePhases[phase]++
	}
	t.DurationSum += snapshot.Duration
	for i, bucket := range controllerReconcileDurationBuckets {
		if snapshot.Duration <= bucket {
			t.DurationBuckets[i]++
		}
	}
	t.OVNOpsPlanned += uint64(nonNegative(snapshot.OVNOps))
	t.OVNOpsExecuted += uint64(nonNegative(snapshot.OVNExecuted))
	t.OVNCleanupOperations += uint64(nonNegative(snapshot.OVNCleanup.Operations))
	t.OVNCleanupStale += uint64(nonNegative(snapshot.OVNCleanup.TotalStaleObjects()))
	t.OVNCleanupChanged += uint64(nonNegative(snapshot.OVNCleanup.TotalChangedObjects()))
	t.LBHealthChecked += uint64(nonNegative(snapshot.HealthSummary.Checked))
	t.LBHealthHealthy += uint64(nonNegative(snapshot.HealthSummary.Healthy))
	t.LBHealthUnhealthy += uint64(nonNegative(snapshot.HealthSummary.Unhealthy))
	if snapshot.OVNHealthStatus != "" && snapshot.OVNHealthStatus != "disabled" {
		t.OVNHealthChecks++
		t.OVNHealthLatencyTotal += snapshot.OVNHealthLatency
		if snapshot.OVNHealthStatus == "error" {
			t.OVNHealthFailures++
		}
	}
	if snapshot.OVNAuditStatus != "" && snapshot.OVNAuditStatus != "disabled" {
		t.OVNAuditChecks++
		if snapshot.OVNAuditStatus == "error" {
			t.OVNAuditFailures++
		}
	}
}

func (m *controllerMetrics) snapshotValue() (controllerMetricsSnapshot, controllerMetricsTotals, bool) {
	if m == nil {
		return controllerMetricsSnapshot{}, controllerMetricsTotals{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshot, cloneControllerMetricsTotals(m.totals), m.ready
}

func cloneControllerMetricsTotals(totals controllerMetricsTotals) controllerMetricsTotals {
	totals.DurationBuckets = append([]uint64(nil), totals.DurationBuckets...)
	if totals.FailurePhases != nil {
		cloned := make(map[string]uint64, len(totals.FailurePhases))
		for key, value := range totals.FailurePhases {
			cloned[key] = value
		}
		totals.FailurePhases = cloned
	}
	return totals
}

func startControllerMetricsServer(ctx context.Context, addr string, metrics *controllerMetrics) (func(), error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return func() {}, nil
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen controller metrics endpoint %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", metrics.handleMetrics)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	server := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("netloom-controller metrics endpoint stopped: %v", err)
		}
	}()
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}, nil
}

func (m *controllerMetrics) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	snapshot, totals, ready := m.snapshotValue()
	if !ready {
		writeMetricHelp(w, "netloom_controller_reconcile_ready", "Whether the controller has completed at least one reconcile attempt.")
		writeMetricType(w, "netloom_controller_reconcile_ready", "gauge")
		fmt.Fprintln(w, "netloom_controller_reconcile_ready 0")
		return
	}
	writeControllerMetrics(w, snapshot, totals)
}

func writeControllerMetrics(w metricWriter, snapshot controllerMetricsSnapshot, totals controllerMetricsTotals) {
	success := 0
	if snapshot.Success {
		success = 1
	}
	baseLabels := prometheusLabels(map[string]string{
		"ovn_health": fallbackMetricsLabel(snapshot.OVNHealthStatus, "disabled"),
	})
	auditLabels := prometheusLabels(map[string]string{
		"ovn_audit":  fallbackMetricsLabel(snapshot.OVNAuditStatus, "disabled"),
		"ovn_health": fallbackMetricsLabel(snapshot.OVNHealthStatus, "disabled"),
	})
	writeMetricHelp(w, "netloom_controller_reconcile_ready", "Whether the controller has completed at least one reconcile attempt.")
	writeMetricType(w, "netloom_controller_reconcile_ready", "gauge")
	fmt.Fprintln(w, "netloom_controller_reconcile_ready 1")
	writeMetricHelp(w, "netloom_controller_reconcile_success", "Whether the last controller reconcile attempt succeeded.")
	writeMetricType(w, "netloom_controller_reconcile_success", "gauge")
	fmt.Fprintf(w, "netloom_controller_reconcile_success%s %d\n", baseLabels, success)
	writeMetricHelp(w, "netloom_controller_reconcile_duration_milliseconds", "Duration of the last controller reconcile attempt in milliseconds.")
	writeMetricType(w, "netloom_controller_reconcile_duration_milliseconds", "gauge")
	fmt.Fprintf(w, "netloom_controller_reconcile_duration_milliseconds%s %d\n", baseLabels, snapshot.Duration.Milliseconds())
	writeControllerCounter(w, "netloom_controller_reconcile_attempts_total", baseLabels, totals.Attempts)
	writeControllerCounter(w, "netloom_controller_reconcile_success_total", baseLabels, totals.Successes)
	writeControllerCounter(w, "netloom_controller_reconcile_failure_total", baseLabels, totals.Failures)
	writeControllerDurationHistogram(w, fallbackMetricsLabel(snapshot.OVNHealthStatus, "disabled"), baseLabels, totals)
	writeControllerFailurePhaseCounters(w, totals)
	if !snapshot.Success {
		fmt.Fprintf(w, "netloom_controller_reconcile_failure%s 1\n", prometheusLabels(map[string]string{
			"phase": fallbackMetricsLabel(snapshot.Phase, "unknown"),
			"error": snapshot.Error,
		}))
	}

	writeMetricType(w, "netloom_controller_desired_vpcs", "gauge")
	fmt.Fprintf(w, "netloom_controller_desired_vpcs %d\n", len(snapshot.State.VPCs))
	writeMetricType(w, "netloom_controller_desired_subnets", "gauge")
	fmt.Fprintf(w, "netloom_controller_desired_subnets %d\n", len(snapshot.State.Subnets))
	writeMetricType(w, "netloom_controller_desired_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_controller_desired_endpoints %d\n", len(snapshot.State.Endpoints))
	writeMetricType(w, "netloom_controller_desired_policy_routes", "gauge")
	fmt.Fprintf(w, "netloom_controller_desired_policy_routes %d\n", len(snapshot.State.PolicyRoutes))
	writeMetricType(w, "netloom_controller_desired_load_balancers", "gauge")
	fmt.Fprintf(w, "netloom_controller_desired_load_balancers %d\n", len(snapshot.State.LoadBalancers))
	writeMetricType(w, "netloom_controller_policy_entries", "gauge")
	fmt.Fprintf(w, "netloom_controller_policy_entries %d\n", snapshot.PolicyEntries)

	writeMetricType(w, "netloom_controller_lb_health_checked", "gauge")
	fmt.Fprintf(w, "netloom_controller_lb_health_checked %d\n", snapshot.HealthSummary.Checked)
	writeMetricType(w, "netloom_controller_lb_health_healthy", "gauge")
	fmt.Fprintf(w, "netloom_controller_lb_health_healthy %d\n", snapshot.HealthSummary.Healthy)
	writeMetricType(w, "netloom_controller_lb_health_unhealthy", "gauge")
	fmt.Fprintf(w, "netloom_controller_lb_health_unhealthy %d\n", snapshot.HealthSummary.Unhealthy)
	writeMetricType(w, "netloom_controller_ovn_health_latency_milliseconds", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_health_latency_milliseconds%s %d\n", baseLabels, snapshot.OVNHealthLatency.Milliseconds())
	writeMetricType(w, "netloom_controller_ovn_health_consecutive_failures", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_health_consecutive_failures%s %d\n", baseLabels, snapshot.OVNHealthConsecutiveFailures)
	writeMetricType(w, "netloom_controller_ovn_health_consecutive_successes", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_health_consecutive_successes%s %d\n", baseLabels, snapshot.OVNHealthConsecutiveSuccesses)
	writeMetricType(w, "netloom_controller_ovn_health_recovering", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_health_recovering%s %d\n", baseLabels, boolMetric(snapshot.OVNHealthRecovering))
	writeMetricType(w, "netloom_controller_ovn_operations_planned", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_operations_planned%s %d\n", baseLabels, snapshot.OVNOps)
	writeMetricType(w, "netloom_controller_ovn_operations_executed", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_operations_executed%s %d\n", baseLabels, snapshot.OVNExecuted)
	writeControllerCounter(w, "netloom_controller_ovn_operations_planned_total", baseLabels, totals.OVNOpsPlanned)
	writeControllerCounter(w, "netloom_controller_ovn_operations_executed_total", baseLabels, totals.OVNOpsExecuted)
	writeControllerCounter(w, "netloom_controller_lb_health_checked_total", baseLabels, totals.LBHealthChecked)
	writeControllerCounter(w, "netloom_controller_lb_health_healthy_total", baseLabels, totals.LBHealthHealthy)
	writeControllerCounter(w, "netloom_controller_lb_health_unhealthy_total", baseLabels, totals.LBHealthUnhealthy)
	writeControllerCounter(w, "netloom_controller_ovn_health_checks_total", baseLabels, totals.OVNHealthChecks)
	writeControllerCounter(w, "netloom_controller_ovn_health_failures_total", baseLabels, totals.OVNHealthFailures)
	writeControllerCounter(w, "netloom_controller_ovn_health_latency_milliseconds_total", baseLabels, uint64(totals.OVNHealthLatencyTotal.Milliseconds()))
	writeMetricType(w, "netloom_controller_ovn_cleanup_operations", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_operations%s %d\n", baseLabels, snapshot.OVNCleanup.Operations)
	writeControllerCounter(w, "netloom_controller_ovn_cleanup_operations_total", baseLabels, totals.OVNCleanupOperations)
	writeControllerCounter(w, "netloom_controller_ovn_cleanup_stale_objects_total", baseLabels, totals.OVNCleanupStale)
	writeControllerCounter(w, "netloom_controller_ovn_cleanup_changed_objects_total", baseLabels, totals.OVNCleanupChanged)
	writeMetricType(w, "netloom_controller_ovn_cleanup_first_reconcile_gc", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_first_reconcile_gc%s %d\n", baseLabels, boolMetric(snapshot.OVNCleanup.FirstReconcileGC))
	writeMetricType(w, "netloom_controller_ovn_cleanup_stale_objects", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_stale_objects%s %d\n", baseLabels, snapshot.OVNCleanup.TotalStaleObjects())
	writeMetricType(w, "netloom_controller_ovn_cleanup_changed_objects", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_changed_objects%s %d\n", baseLabels, snapshot.OVNCleanup.TotalChangedObjects())
	writeMetricType(w, "netloom_controller_ovn_cleanup_stale_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_stale_endpoints%s %d\n", baseLabels, snapshot.OVNCleanup.StaleEndpoints)
	writeMetricType(w, "netloom_controller_ovn_cleanup_stale_subnets", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_stale_subnets%s %d\n", baseLabels, snapshot.OVNCleanup.StaleSubnets)
	writeMetricType(w, "netloom_controller_ovn_cleanup_stale_routes", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_stale_routes%s %d\n", baseLabels, snapshot.OVNCleanup.StaleRoutes)
	writeMetricType(w, "netloom_controller_ovn_cleanup_changed_routes", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_changed_routes%s %d\n", baseLabels, snapshot.OVNCleanup.ChangedRoutes)
	writeMetricType(w, "netloom_controller_ovn_cleanup_stale_policy_routes", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_stale_policy_routes%s %d\n", baseLabels, snapshot.OVNCleanup.StalePolicyRoutes)
	writeMetricType(w, "netloom_controller_ovn_cleanup_changed_policy_routes", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_changed_policy_routes%s %d\n", baseLabels, snapshot.OVNCleanup.ChangedPolicyRoutes)
	writeMetricType(w, "netloom_controller_ovn_cleanup_stale_nat_rules", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_stale_nat_rules%s %d\n", baseLabels, snapshot.OVNCleanup.StaleNATRules)
	writeMetricType(w, "netloom_controller_ovn_cleanup_changed_nat_rules", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_changed_nat_rules%s %d\n", baseLabels, snapshot.OVNCleanup.ChangedNATRules)
	writeMetricType(w, "netloom_controller_ovn_cleanup_stale_load_balancers", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_stale_load_balancers%s %d\n", baseLabels, snapshot.OVNCleanup.StaleLoadBalancers)
	writeMetricType(w, "netloom_controller_ovn_cleanup_changed_load_balancers", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_changed_load_balancers%s %d\n", baseLabels, snapshot.OVNCleanup.ChangedLoadBalancers)
	writeMetricType(w, "netloom_controller_ovn_live_managed_objects", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_managed_objects%s %d\n", auditLabels, snapshot.OVNAudit.TotalManagedObjects())
	writeMetricType(w, "netloom_controller_ovn_live_logical_switches", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_logical_switches%s %d\n", auditLabels, snapshot.OVNAudit.ManagedLogicalSwitches)
	writeMetricType(w, "netloom_controller_ovn_live_logical_routers", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_logical_routers%s %d\n", auditLabels, snapshot.OVNAudit.ManagedLogicalRouters)
	writeMetricType(w, "netloom_controller_ovn_live_logical_switch_ports", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_logical_switch_ports%s %d\n", auditLabels, snapshot.OVNAudit.ManagedLogicalSwitchPorts)
	writeMetricType(w, "netloom_controller_ovn_live_logical_router_ports", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_logical_router_ports%s %d\n", auditLabels, snapshot.OVNAudit.ManagedLogicalRouterPorts)
	writeMetricType(w, "netloom_controller_ovn_live_logical_router_policies", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_logical_router_policies%s %d\n", auditLabels, snapshot.OVNAudit.ManagedLogicalRouterPolicies)
	writeMetricType(w, "netloom_controller_ovn_live_nat_rules", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_nat_rules%s %d\n", auditLabels, snapshot.OVNAudit.ManagedNATRules)
	writeMetricType(w, "netloom_controller_ovn_live_load_balancers", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_load_balancers%s %d\n", auditLabels, snapshot.OVNAudit.ManagedLoadBalancers)
	writeMetricType(w, "netloom_controller_ovn_live_load_balancer_health_checks", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_load_balancer_health_checks%s %d\n", auditLabels, snapshot.OVNAudit.ManagedLoadBalancerHealthChecks)
	writeMetricType(w, "netloom_controller_ovn_live_dhcp_options", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_dhcp_options%s %d\n", auditLabels, snapshot.OVNAudit.ManagedDHCPOptions)
	writeMetricType(w, "netloom_controller_ovn_live_duplicate_managed_rows", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_duplicate_managed_rows%s %d\n", auditLabels, snapshot.OVNAudit.DuplicateManagedRows)
	writeMetricType(w, "netloom_controller_ovn_live_incomplete_managed_rows", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_incomplete_managed_rows%s %d\n", auditLabels, snapshot.OVNAudit.IncompleteManagedRows)
	writeControllerCounter(w, "netloom_controller_ovn_audit_checks_total", auditLabels, totals.OVNAuditChecks)
	writeControllerCounter(w, "netloom_controller_ovn_audit_failures_total", auditLabels, totals.OVNAuditFailures)
	if snapshot.OVNAuditStatus == "error" {
		fmt.Fprintf(w, "netloom_controller_ovn_audit_error%s 1\n", prometheusLabels(map[string]string{
			"error":      snapshot.OVNAuditError,
			"ovn_health": fallbackMetricsLabel(snapshot.OVNHealthStatus, "disabled"),
		}))
	}
}

func writeControllerCounter(w metricWriter, name, labels string, value uint64) {
	writeMetricType(w, name, "counter")
	fmt.Fprintf(w, "%s%s %d\n", name, labels, value)
}

func writeControllerDurationHistogram(w metricWriter, ovnHealth, baseLabels string, totals controllerMetricsTotals) {
	name := "netloom_controller_reconcile_duration_milliseconds_histogram"
	writeMetricType(w, name, "histogram")
	for i, bucket := range controllerReconcileDurationBuckets {
		labels := prometheusLabels(map[string]string{
			"le":         strconv.FormatInt(bucket.Milliseconds(), 10),
			"ovn_health": ovnHealth,
		})
		fmt.Fprintf(w, "%s_bucket%s %d\n", name, labels, totals.DurationBuckets[i])
	}
	fmt.Fprintf(w, "%s_bucket%s %d\n", name, prometheusLabels(map[string]string{"le": "+Inf", "ovn_health": ovnHealth}), totals.Attempts)
	fmt.Fprintf(w, "%s_sum%s %d\n", name, baseLabels, totals.DurationSum.Milliseconds())
	fmt.Fprintf(w, "%s_count%s %d\n", name, baseLabels, totals.Attempts)
}

func writeControllerFailurePhaseCounters(w metricWriter, totals controllerMetricsTotals) {
	phases := make([]string, 0, len(totals.FailurePhases))
	for phase := range totals.FailurePhases {
		phases = append(phases, phase)
	}
	sort.Strings(phases)
	for _, phase := range phases {
		writeControllerCounter(w, "netloom_controller_reconcile_failures_by_phase_total", prometheusLabels(map[string]string{"phase": phase}), totals.FailurePhases[phase])
	}
}

type metricWriter interface {
	Write([]byte) (int, error)
}

func writeMetricHelp(w metricWriter, name, help string) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
}

func writeMetricType(w metricWriter, name, typ string) {
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
}

func prometheusLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strconv.Quote(labels[key]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func fallbackMetricsLabel(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func formatResultError(value string) string {
	if value == "" {
		return "none"
	}
	return strconv.Quote(value)
}

func boolMetric(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
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

func reconcileFailureBackoff(interval time.Duration) (time.Duration, error) {
	raw := os.Getenv("NETLOOM_RECONCILE_FAILURE_BACKOFF_MS")
	if raw == "" {
		if interval > 0 {
			return interval, nil
		}
		return time.Second, nil
	}
	ms, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NETLOOM_RECONCILE_FAILURE_BACKOFF_MS: %w", err)
	}
	if ms <= 0 {
		if interval > 0 {
			return interval, nil
		}
		return time.Second, nil
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func runReconcileLoop(ctx context.Context, interval, failureBackoff time.Duration, reconcile func() error, reportFailure func(error)) error {
	if interval <= 0 {
		return reconcile()
	}
	if failureBackoff <= 0 {
		failureBackoff = interval
		if failureBackoff <= 0 {
			failureBackoff = time.Second
		}
	}
	for {
		if err := reconcile(); err != nil {
			if reportFailure != nil {
				reportFailure(err)
			}
			if err := waitForNextAttempt(ctx, failureBackoff); err != nil {
				return err
			}
			continue
		}
		if err := waitForNextAttempt(ctx, interval); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return err
		}
	}
}

func waitForNextAttempt(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func executorHealthChecker(executor ovn.Executor) ovnHealthChecker {
	checker, _ := executor.(ovnHealthChecker)
	return checker
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
	initialBackoff, err := nbctlRetryInitialBackoff()
	if err != nil {
		return nil, err
	}
	maxBackoff, err := nbctlRetryMaxBackoff()
	if err != nil {
		return nil, err
	}
	executor.RetryPolicy.InitialBackoff = initialBackoff
	executor.RetryPolicy.MaxBackoff = maxBackoff
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

func nbctlRetryInitialBackoff() (time.Duration, error) {
	raw := os.Getenv("NETLOOM_OVN_NBCTL_RETRY_INITIAL_BACKOFF_MS")
	if raw == "" {
		return ovn.DefaultNBCTLRetryInitialBackoff, nil
	}
	ms, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NETLOOM_OVN_NBCTL_RETRY_INITIAL_BACKOFF_MS: %w", err)
	}
	if ms <= 0 {
		return 0, nil
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func nbctlRetryMaxBackoff() (time.Duration, error) {
	raw := os.Getenv("NETLOOM_OVN_NBCTL_RETRY_MAX_BACKOFF_MS")
	if raw == "" {
		return ovn.DefaultNBCTLRetryMaxBackoff, nil
	}
	ms, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NETLOOM_OVN_NBCTL_RETRY_MAX_BACKOFF_MS: %w", err)
	}
	if ms <= 0 {
		return 0, nil
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func countPolicyEntries(memory *control.MemoryBackend) int {
	total := 0
	for _, program := range memory.PolicyProgram {
		total += len(program.MapEntries)
	}
	return total
}

func countDesiredPolicyEntries(state control.DesiredState) int {
	total := 0
	groups := make(map[string]model.SecurityGroup, len(state.SecurityGroups))
	for _, group := range state.SecurityGroups {
		groups[group.VPC+"\x00"+group.Name] = group
	}
	resolver := policy.NewIdentityCache()
	for _, endpoint := range state.Endpoints {
		if err := endpoint.Validate(); err != nil {
			continue
		}
		endpointGroups := make(map[string]model.SecurityGroup)
		for _, groupName := range endpoint.SecurityGroups {
			if group, ok := groups[endpoint.VPC+"\x00"+groupName]; ok {
				endpointGroups[group.Name] = group
			}
		}
		program, err := policy.CompileForEndpointWithContext(endpoint, endpointGroups, policy.CompileContext{
			Endpoints:        state.Endpoints,
			Subnets:          state.Subnets,
			Gateways:         state.Gateways,
			Services:         state.LoadBalancers,
			DNSRecords:       state.DNSRecords,
			CIDRGroups:       state.CIDRGroups,
			IdentityResolver: resolver,
		})
		if err != nil {
			continue
		}
		total += len(program.MapEntries)
	}
	return total
}
