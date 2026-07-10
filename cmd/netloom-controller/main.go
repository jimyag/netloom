package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/linuxdatapath"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/ovnnb"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/vswitch"
	"github.com/jimyag/netloom/internal/policy"
	"github.com/jimyag/netloom/internal/topology"
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
	reconciler, err := newStateFileReconciler(ctx)
	if err != nil {
		return err
	}
	defer reconciler.Close()
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
	memory                 *control.MemoryBackend
	executor               ovn.Executor
	ovnBackend             *ovn.Backend
	ovnCleanup             ovnCleanupStatsReporter
	ovnCloser              func()
	controller             *control.Controller
	healthTracker          *control.LoadBalancerHealthTracker
	healthChecker          ovnHealthChecker
	ovnHealth              ovnHealthTracker
	maintenance            ovnMaintenanceRunner
	auditReader            ovn.ManagedOVNReader
	auditCloser            func()
	ovsStatus              ovsdbControlStatusWriter
	ovsStatusClose         func()
	metrics                *controllerMetrics
	identityGroupFeedCache *control.IdentityGroupObservationCache
}

type ovnTopologyRuntime struct {
	backend    control.TopologyBackend
	executor   ovn.Executor
	ovnBackend *ovn.Backend
	cleanup    ovnCleanupStatsReporter
	health     ovnHealthChecker
	close      func()
}

type libovsdbDialFunc func(context.Context, string, string) (libovsdbclient.Client, func(), error)
type ovnLeaderProbe func(context.Context, []string) (string, error)

type libovsdbClusterConnector struct {
	mu           sync.Mutex
	owner        string
	endpoints    []string
	dial         libovsdbDialFunc
	leaderProbe  ovnLeaderProbe
	leader       string
	leaderStatus string
	leaderError  string
	current      string
	currentIndex int
	failovers    int
}

type ovnCleanupStatsReporter interface {
	LastCleanupStats() ovn.CleanupStats
}

type ovnHealthChecker interface {
	HealthCheck(context.Context) (time.Duration, error)
}

type ovnAuditor interface {
	AuditManagedObjects(context.Context) (ovn.AuditStats, error)
}

type ovnMaintenanceRunner interface {
	RunMaintenance(context.Context) ovnMaintenanceResult
}

type ovsdbControlStatusWriter interface {
	SetOpenVSwitchExternalID(context.Context, string, string) error
}

type ovnMaintenanceResult struct {
	Status    string        `json:"status"`
	Attempted int           `json:"attempted"`
	Succeeded int           `json:"succeeded"`
	Failed    int           `json:"failed"`
	Latency   time.Duration `json:"latency"`
	Error     string        `json:"error,omitempty"`
}

type ovnHealthSnapshot struct {
	Status               string                   `json:"status"`
	Latency              time.Duration            `json:"latency"`
	ConsecutiveFailures  int                      `json:"consecutive_failures"`
	ConsecutiveSuccesses int                      `json:"consecutive_successes"`
	Recovering           bool                     `json:"recovering"`
	Cluster              ovnClusterHealthSnapshot `json:"cluster"`
}

type ovnClusterHealthSnapshot struct {
	ActiveEndpoint      string `json:"active_endpoint,omitempty"`
	LeaderEndpoint      string `json:"leader_endpoint,omitempty"`
	LeaderProbeStatus   string `json:"leader_probe_status,omitempty"`
	LeaderProbeError    string `json:"leader_probe_error,omitempty"`
	ConfiguredEndpoints int    `json:"configured_endpoints"`
	Failovers           int    `json:"failovers"`
	LeaderPreferred     bool   `json:"leader_preferred"`
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

type ovnClusterHealthReporter interface {
	OVNClusterHealth() ovnClusterHealthSnapshot
}

func newStateFileReconciler(ctx context.Context) (*stateFileReconciler, error) {
	memory := control.NewMemoryBackend()
	ovnRuntime, err := newOVNTopologyRuntimeFromEnv()
	if err != nil {
		return nil, err
	}
	auditReader, auditCloser, err := newOVNAuditReaderFromEnv()
	if err != nil {
		if ovnRuntime.close != nil {
			ovnRuntime.close()
		}
		return nil, err
	}
	ovsStatus, ovsStatusClose, err := newOVSDBControlStatusWriterFromEnv(ctx)
	if err != nil {
		if auditCloser != nil {
			auditCloser()
		}
		if ovnRuntime.close != nil {
			ovnRuntime.close()
		}
		return nil, err
	}
	return &stateFileReconciler{
		memory:                 memory,
		executor:               ovnRuntime.executor,
		ovnBackend:             ovnRuntime.ovnBackend,
		ovnCleanup:             ovnRuntime.cleanup,
		ovnCloser:              ovnRuntime.close,
		controller:             control.NewController(control.MultiTopologyBackend{memory, ovnRuntime.backend}, memory),
		healthTracker:          control.NewLoadBalancerHealthTracker(),
		healthChecker:          ovnRuntime.health,
		maintenance:            newOVNMaintenanceFromEnv(),
		auditReader:            auditReader,
		auditCloser:            auditCloser,
		ovsStatus:              ovsStatus,
		ovsStatusClose:         ovsStatusClose,
		identityGroupFeedCache: &control.IdentityGroupObservationCache{},
	}, nil
}

func (r *stateFileReconciler) Close() {
	if r == nil {
		return
	}
	if r.ovsStatusClose != nil {
		r.ovsStatusClose()
		r.ovsStatusClose = nil
	}
	if r.auditCloser != nil {
		r.auditCloser()
		r.auditCloser = nil
	}
	if r.ovnCloser != nil {
		r.ovnCloser()
		r.ovnCloser = nil
	}
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
	state, err = r.withIdentityGroupObservationsContext(ctx, state)
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

	opsBefore := r.plannedOVNOperations()
	executedBefore := r.executedOperations()
	if err := r.controller.Reconcile(ctx, state); err != nil {
		ovnOps := r.plannedOVNOperations() - opsBefore
		executed := r.executedOperations() - executedBefore
		duration := time.Since(start)
		printControllerReconcileFailure("apply", state, healthSummary, ovnHealth.Snapshot, ovnOps, executed, err, duration)
		r.observeReconcileFailure("apply", state, healthSummary, ovnHealth.Snapshot, ovnOps, executed, err, duration)
		return err
	}

	ovnOps := r.plannedOVNOperations() - opsBefore
	executed := r.executedOperations() - executedBefore
	ovnAudit, ovnAuditStatus, ovnAuditError := r.auditOVN(ctx, r.memory.TopologyState())
	ovnStaleAdvisory := ovnStaleAdvisoryFromAudit(ovnAudit, ovnStaleAdvisoryThresholdFromEnv())
	ovnMaintenance := r.runOVNMaintenance(ctx)
	duration := time.Since(start)
	if err := r.syncOVSDBControlStatus(ctx, state, healthSummary, ovnHealth.Snapshot, ovnOps, executed, ovnAuditStatus, ovnAuditError, ovnAudit, ovnStaleAdvisory, ovnMaintenance, duration); err != nil {
		log.Printf("netloom-controller failed to sync Open_vSwitch control status: %v", err)
	}
	fmt.Printf(
		"netloom-controller reconciled desired state vpcs=%d subnets=%d endpoints=%d route_tables=%d policy_routes=%d gateways=%d nat_rules=%d load_balancers=%d security_groups=%d policy_entries=%d lb_health_checked=%d lb_health_healthy=%d lb_health_unhealthy=%d ovn_health=%s ovn_health_latency_ms=%d ovn_health_consecutive_failures=%d ovn_health_consecutive_successes=%d ovn_health_recovering=%d ovn_cluster_active_endpoint=%s ovn_cluster_leader_endpoint=%s ovn_cluster_leader_probe_status=%s ovn_cluster_leader_probe_error=%s ovn_cluster_leader_preferred=%d ovn_cluster_endpoints=%d ovn_cluster_failovers=%d ovn_ops=%d ovn_executed=%d ovn_audit=%s ovn_live_managed=%d ovn_live_duplicates=%d ovn_live_incomplete=%d ovn_live_missing=%d ovn_live_unexpected=%d ovn_live_drifted_rows=%d ovn_live_drifted_fields=%d ovn_audit_error=%s ovn_stale_advisory=%s ovn_stale_burden=%d ovn_stale_threshold=%d ovn_maintenance=%s ovn_maintenance_attempted=%d ovn_maintenance_succeeded=%d ovn_maintenance_failed=%d ovn_maintenance_latency_ms=%d ovn_maintenance_error=%s reconcile_duration_ms=%d\n",
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
		formatResultValue(ovnHealth.Snapshot.Cluster.ActiveEndpoint),
		formatResultValue(ovnHealth.Snapshot.Cluster.LeaderEndpoint),
		formatResultValue(ovnHealth.Snapshot.Cluster.LeaderProbeStatus),
		formatResultError(ovnHealth.Snapshot.Cluster.LeaderProbeError),
		boolMetric(ovnHealth.Snapshot.Cluster.LeaderPreferred),
		ovnHealth.Snapshot.Cluster.ConfiguredEndpoints,
		ovnHealth.Snapshot.Cluster.Failovers,
		ovnOps,
		executed,
		ovnAuditStatus,
		ovnAudit.TotalManagedObjects(),
		ovnAudit.DuplicateManagedRows,
		ovnAudit.IncompleteManagedRows,
		ovnAudit.MissingManagedRows,
		ovnAudit.UnexpectedManagedRows,
		ovnAudit.DriftedManagedRows,
		ovnAudit.DriftedManagedFields,
		formatResultError(ovnAuditError),
		ovnStaleAdvisory.Status,
		ovnStaleAdvisory.Burden,
		ovnStaleAdvisory.Threshold,
		fallbackMetricsLabel(ovnMaintenance.Status, "disabled"),
		ovnMaintenance.Attempted,
		ovnMaintenance.Succeeded,
		ovnMaintenance.Failed,
		ovnMaintenance.Latency.Milliseconds(),
		formatResultError(ovnMaintenance.Error),
		duration.Milliseconds(),
	)
	r.observeReconcileSuccess(state, healthSummary, ovnHealth.Snapshot, ovnOps, executed, ovnAuditStatus, ovnAuditError, ovnAudit, ovnStaleAdvisory, ovnMaintenance, duration)
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
	cluster := ovnClusterHealth(r.healthChecker)
	latency, err := r.healthChecker.HealthCheck(ctx)
	if err != nil {
		snapshot := r.ovnHealth.recordFailure(latency)
		snapshot.Cluster = cluster
		return ovnHealthProbe{Snapshot: snapshot, err: err}
	}
	snapshot := r.ovnHealth.recordSuccess(latency)
	snapshot.Cluster = ovnClusterHealth(r.healthChecker)
	return ovnHealthProbe{Snapshot: snapshot}
}

func ovnClusterHealth(checker ovnHealthChecker) ovnClusterHealthSnapshot {
	reporter, ok := checker.(ovnClusterHealthReporter)
	if !ok {
		return ovnClusterHealthSnapshot{}
	}
	return reporter.OVNClusterHealth()
}

func printControllerReconcileFailure(phase string, state control.DesiredState, healthSummary control.LoadBalancerHealthSummary, ovnHealth ovnHealthSnapshot, ovnOps, executed int, err error, duration time.Duration) {
	if phase == "" {
		phase = "unknown"
	}
	fmt.Printf(
		"netloom-controller reconcile failed reconcile_phase=%s vpcs=%d subnets=%d endpoints=%d route_tables=%d policy_routes=%d gateways=%d nat_rules=%d load_balancers=%d security_groups=%d policy_entries=%d lb_health_checked=%d lb_health_healthy=%d lb_health_unhealthy=%d ovn_health=%s ovn_health_latency_ms=%d ovn_health_consecutive_failures=%d ovn_health_consecutive_successes=%d ovn_health_recovering=%d ovn_cluster_active_endpoint=%s ovn_cluster_leader_endpoint=%s ovn_cluster_leader_probe_status=%s ovn_cluster_leader_probe_error=%s ovn_cluster_leader_preferred=%d ovn_cluster_endpoints=%d ovn_cluster_failovers=%d ovn_ops=%d ovn_executed=%d err=%q reconcile_duration_ms=%d\n",
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
		formatResultValue(ovnHealth.Cluster.ActiveEndpoint),
		formatResultValue(ovnHealth.Cluster.LeaderEndpoint),
		formatResultValue(ovnHealth.Cluster.LeaderProbeStatus),
		formatResultError(ovnHealth.Cluster.LeaderProbeError),
		boolMetric(ovnHealth.Cluster.LeaderPreferred),
		ovnHealth.Cluster.ConfiguredEndpoints,
		ovnHealth.Cluster.Failovers,
		ovnOps,
		executed,
		err.Error(),
		duration.Milliseconds(),
	)
}

func (r *stateFileReconciler) observeReconcileSuccess(state control.DesiredState, healthSummary control.LoadBalancerHealthSummary, ovnHealth ovnHealthSnapshot, ovnOps, executed int, ovnAuditStatus, ovnAuditError string, ovnAudit ovn.AuditStats, ovnStaleAdvisory ovnStaleAdvisory, ovnMaintenance ovnMaintenanceResult, duration time.Duration) {
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
		OVNCluster:                    ovnHealth.Cluster,
		OVNOps:                        ovnOps,
		OVNExecuted:                   executed,
		OVNCleanup:                    r.lastOVNCleanupStats(),
		OVNAuditStatus:                fallbackMetricsLabel(ovnAuditStatus, "disabled"),
		OVNAuditError:                 ovnAuditError,
		OVNAudit:                      ovnAudit,
		OVNStaleAdvisory:              ovnStaleAdvisory,
		OVNMaintenance:                ovnMaintenance,
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
		OVNCluster:                    ovnHealth.Cluster,
		OVNOps:                        ovnOps,
		OVNExecuted:                   executed,
		OVNCleanup:                    r.lastOVNCleanupStats(),
		OVNAuditStatus:                "disabled",
		OVNMaintenance:                ovnMaintenanceResult{Status: "disabled"},
		Duration:                      duration,
		Success:                       false,
		Phase:                         phase,
		Error:                         message,
	})
}

func (r *stateFileReconciler) lastOVNCleanupStats() ovn.CleanupStats {
	if r == nil || r.ovnCleanup == nil {
		return ovn.CleanupStats{}
	}
	return r.ovnCleanup.LastCleanupStats()
}

func (r *stateFileReconciler) auditOVN(ctx context.Context, desired topology.State) (ovn.AuditStats, string, string) {
	if r == nil {
		return ovn.AuditStats{}, "disabled", ""
	}
	if r.auditReader != nil {
		stats, err := ovn.AuditManagedObjectsFromReaderWithDesired(ctx, r.auditReader, desired)
		if err != nil {
			return ovn.AuditStats{}, "error", err.Error()
		}
		return stats, "ok", ""
	}
	if r.executor == nil {
		return ovn.AuditStats{}, "disabled", ""
	}
	if reader, ok := r.executor.(ovn.ManagedOVNReader); ok {
		stats, err := ovn.AuditManagedObjectsFromReaderWithDesired(ctx, reader, desired)
		if err != nil {
			return ovn.AuditStats{}, "error", err.Error()
		}
		return stats, "ok", ""
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

func (r *stateFileReconciler) runOVNMaintenance(ctx context.Context) ovnMaintenanceResult {
	if r == nil || r.maintenance == nil {
		return ovnMaintenanceResult{Status: "disabled"}
	}
	return r.maintenance.RunMaintenance(ctx)
}

type controllerOVSDBStatus struct {
	SchemaVersion       int                               `json:"schema_version"`
	UpdatedAt           string                            `json:"updated_at"`
	VPCs                int                               `json:"vpcs"`
	Subnets             int                               `json:"subnets"`
	Endpoints           int                               `json:"endpoints"`
	RouteTables         int                               `json:"route_tables"`
	PolicyRoutes        int                               `json:"policy_routes"`
	Gateways            int                               `json:"gateways"`
	NATRules            int                               `json:"nat_rules"`
	LoadBalancers       int                               `json:"load_balancers"`
	SecurityGroups      int                               `json:"security_groups"`
	PolicyEntries       int                               `json:"policy_entries"`
	LBHealth            control.LoadBalancerHealthSummary `json:"lb_health"`
	OVNHealth           ovnHealthSnapshot                 `json:"ovn_health"`
	OVNOps              int                               `json:"ovn_ops"`
	OVNExecuted         int                               `json:"ovn_executed"`
	OVNAuditStatus      string                            `json:"ovn_audit_status"`
	OVNAuditError       string                            `json:"ovn_audit_error,omitempty"`
	OVNAudit            ovn.AuditStats                    `json:"ovn_audit"`
	OVNStaleAdvisory    ovnStaleAdvisory                  `json:"ovn_stale_advisory"`
	OVNMaintenance      ovnMaintenanceResult              `json:"ovn_maintenance"`
	ReconcileDurationMS int64                             `json:"reconcile_duration_ms"`
}

const controllerOVSDBStatusKey = "netloom_controller_status"

func (r *stateFileReconciler) syncOVSDBControlStatus(ctx context.Context, state control.DesiredState, healthSummary control.LoadBalancerHealthSummary, ovnHealth ovnHealthSnapshot, ovnOps, executed int, ovnAuditStatus, ovnAuditError string, ovnAudit ovn.AuditStats, ovnStaleAdvisory ovnStaleAdvisory, ovnMaintenance ovnMaintenanceResult, duration time.Duration) error {
	if r == nil || r.ovsStatus == nil {
		return nil
	}
	status := controllerOVSDBStatus{
		SchemaVersion:       1,
		UpdatedAt:           time.Now().UTC().Format(time.RFC3339Nano),
		VPCs:                len(state.VPCs),
		Subnets:             len(state.Subnets),
		Endpoints:           len(state.Endpoints),
		RouteTables:         len(state.RouteTables),
		PolicyRoutes:        len(state.PolicyRoutes),
		Gateways:            len(state.Gateways),
		NATRules:            len(state.NATRules),
		LoadBalancers:       len(state.LoadBalancers),
		SecurityGroups:      len(state.SecurityGroups),
		PolicyEntries:       countPolicyEntries(r.memory),
		LBHealth:            healthSummary,
		OVNHealth:           ovnHealth,
		OVNOps:              ovnOps,
		OVNExecuted:         executed,
		OVNAuditStatus:      fallbackMetricsLabel(ovnAuditStatus, "disabled"),
		OVNAuditError:       ovnAuditError,
		OVNAudit:            ovnAudit,
		OVNStaleAdvisory:    ovnStaleAdvisory,
		OVNMaintenance:      ovnMaintenance,
		ReconcileDurationMS: duration.Milliseconds(),
	}
	raw, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("encode Open_vSwitch controller status: %w", err)
	}
	if err := r.ovsStatus.SetOpenVSwitchExternalID(ctx, "netloom_owner", "netloom"); err != nil {
		return err
	}
	return r.ovsStatus.SetOpenVSwitchExternalID(ctx, controllerOVSDBStatusKey, string(raw))
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
	OVNCluster                    ovnClusterHealthSnapshot
	OVNOps                        int
	OVNExecuted                   int
	OVNCleanup                    ovn.CleanupStats
	OVNAuditStatus                string
	OVNAuditError                 string
	OVNAudit                      ovn.AuditStats
	OVNStaleAdvisory              ovnStaleAdvisory
	OVNMaintenance                ovnMaintenanceResult
	Duration                      time.Duration
	Success                       bool
	Phase                         string
	Error                         string
}

type ovnStaleAdvisory struct {
	Status    string `json:"status"`
	Burden    int    `json:"burden"`
	Threshold int    `json:"threshold"`
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
	OVNMaintenanceRuns    uint64
	OVNMaintenanceTargets uint64
	OVNMaintenanceSuccess uint64
	OVNMaintenanceFailure uint64
}

func ovnStaleAdvisoryThresholdFromEnv() int {
	raw := strings.TrimSpace(os.Getenv("NETLOOM_OVN_STALE_ADVISORY_THRESHOLD"))
	if raw == "" {
		return 0
	}
	threshold, err := strconv.Atoi(raw)
	if err != nil || threshold < 0 {
		return 0
	}
	return threshold
}

func ovnStaleAdvisoryFromAudit(stats ovn.AuditStats, threshold int) ovnStaleAdvisory {
	burden := ovnStaleBurden(stats)
	if threshold <= 0 {
		return ovnStaleAdvisory{Status: "disabled", Burden: burden}
	}
	status := "ok"
	if burden >= threshold {
		status = "warning"
	}
	return ovnStaleAdvisory{Status: status, Burden: burden, Threshold: threshold}
}

func ovnStaleBurden(stats ovn.AuditStats) int {
	return stats.MissingManagedRows +
		stats.UnexpectedManagedRows +
		stats.DriftedManagedRows +
		stats.DuplicateManagedRows +
		stats.IncompleteManagedRows
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
	if snapshot.OVNMaintenance.Status != "" && snapshot.OVNMaintenance.Status != "disabled" {
		t.OVNMaintenanceRuns++
		t.OVNMaintenanceTargets += uint64(nonNegative(snapshot.OVNMaintenance.Attempted))
		t.OVNMaintenanceSuccess += uint64(nonNegative(snapshot.OVNMaintenance.Succeeded))
		t.OVNMaintenanceFailure += uint64(nonNegative(snapshot.OVNMaintenance.Failed))
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
	staleAdvisoryLabels := prometheusLabels(map[string]string{
		"ovn_health":         fallbackMetricsLabel(snapshot.OVNHealthStatus, "disabled"),
		"ovn_stale_advisory": fallbackMetricsLabel(snapshot.OVNStaleAdvisory.Status, "disabled"),
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
	writeMetricType(w, "netloom_controller_ovn_cluster_active_endpoint", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cluster_active_endpoint%s %d\n", prometheusLabels(map[string]string{
		"endpoint":   fallbackMetricsLabel(snapshot.OVNCluster.ActiveEndpoint, "none"),
		"ovn_health": fallbackMetricsLabel(snapshot.OVNHealthStatus, "disabled"),
	}), boolMetric(snapshot.OVNCluster.ActiveEndpoint != ""))
	writeMetricType(w, "netloom_controller_ovn_cluster_leader_endpoint", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cluster_leader_endpoint%s %d\n", prometheusLabels(map[string]string{
		"endpoint":   fallbackMetricsLabel(snapshot.OVNCluster.LeaderEndpoint, "none"),
		"ovn_health": fallbackMetricsLabel(snapshot.OVNHealthStatus, "disabled"),
	}), boolMetric(snapshot.OVNCluster.LeaderEndpoint != ""))
	writeMetricType(w, "netloom_controller_ovn_cluster_leader_probe_status", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cluster_leader_probe_status%s 1\n", prometheusLabels(map[string]string{
		"ovn_health": fallbackMetricsLabel(snapshot.OVNHealthStatus, "disabled"),
		"status":     fallbackMetricsLabel(snapshot.OVNCluster.LeaderProbeStatus, "disabled"),
	}))
	writeMetricType(w, "netloom_controller_ovn_cluster_leader_preferred", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cluster_leader_preferred%s %d\n", baseLabels, boolMetric(snapshot.OVNCluster.LeaderPreferred))
	writeMetricType(w, "netloom_controller_ovn_cluster_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cluster_endpoints%s %d\n", baseLabels, snapshot.OVNCluster.ConfiguredEndpoints)
	writeMetricType(w, "netloom_controller_ovn_cluster_failovers", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cluster_failovers%s %d\n", baseLabels, snapshot.OVNCluster.Failovers)
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
	maintenanceLabels := prometheusLabels(map[string]string{
		"ovn_health":      fallbackMetricsLabel(snapshot.OVNHealthStatus, "disabled"),
		"ovn_maintenance": fallbackMetricsLabel(snapshot.OVNMaintenance.Status, "disabled"),
	})
	writeMetricType(w, "netloom_controller_ovn_maintenance_attempted", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_maintenance_attempted%s %d\n", maintenanceLabels, snapshot.OVNMaintenance.Attempted)
	writeMetricType(w, "netloom_controller_ovn_maintenance_succeeded", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_maintenance_succeeded%s %d\n", maintenanceLabels, snapshot.OVNMaintenance.Succeeded)
	writeMetricType(w, "netloom_controller_ovn_maintenance_failed", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_maintenance_failed%s %d\n", maintenanceLabels, snapshot.OVNMaintenance.Failed)
	writeMetricType(w, "netloom_controller_ovn_maintenance_latency_milliseconds", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_maintenance_latency_milliseconds%s %d\n", maintenanceLabels, snapshot.OVNMaintenance.Latency.Milliseconds())
	writeControllerCounter(w, "netloom_controller_ovn_maintenance_runs_total", maintenanceLabels, totals.OVNMaintenanceRuns)
	writeControllerCounter(w, "netloom_controller_ovn_maintenance_targets_total", maintenanceLabels, totals.OVNMaintenanceTargets)
	writeControllerCounter(w, "netloom_controller_ovn_maintenance_succeeded_total", maintenanceLabels, totals.OVNMaintenanceSuccess)
	writeControllerCounter(w, "netloom_controller_ovn_maintenance_failed_total", maintenanceLabels, totals.OVNMaintenanceFailure)
	if snapshot.OVNMaintenance.Error != "" {
		fmt.Fprintf(w, "netloom_controller_ovn_maintenance_error%s 1\n", prometheusLabels(map[string]string{
			"error":           snapshot.OVNMaintenance.Error,
			"ovn_health":      fallbackMetricsLabel(snapshot.OVNHealthStatus, "disabled"),
			"ovn_maintenance": fallbackMetricsLabel(snapshot.OVNMaintenance.Status, "disabled"),
		}))
	}
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
	writeMetricType(w, "netloom_controller_ovn_cleanup_stale_logical_switch_ports", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_stale_logical_switch_ports%s %d\n", baseLabels, snapshot.OVNCleanup.StaleLogicalSwitchPorts)
	writeMetricType(w, "netloom_controller_ovn_cleanup_stale_logical_router_ports", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_stale_logical_router_ports%s %d\n", baseLabels, snapshot.OVNCleanup.StaleLogicalRouterPorts)
	writeMetricType(w, "netloom_controller_ovn_cleanup_stale_dhcp_options", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_stale_dhcp_options%s %d\n", baseLabels, snapshot.OVNCleanup.StaleDHCPOptions)
	writeMetricType(w, "netloom_controller_ovn_cleanup_stale_load_balancer_health_checks", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_cleanup_stale_load_balancer_health_checks%s %d\n", baseLabels, snapshot.OVNCleanup.StaleLBHealthChecks)
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
	writeMetricType(w, "netloom_controller_ovn_live_logical_router_static_routes", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_logical_router_static_routes%s %d\n", auditLabels, snapshot.OVNAudit.ManagedLogicalRouterStaticRoutes)
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
	writeMetricType(w, "netloom_controller_ovn_live_missing_managed_rows", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_missing_managed_rows%s %d\n", auditLabels, snapshot.OVNAudit.MissingManagedRows)
	writeMetricType(w, "netloom_controller_ovn_live_unexpected_managed_rows", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_unexpected_managed_rows%s %d\n", auditLabels, snapshot.OVNAudit.UnexpectedManagedRows)
	writeMetricType(w, "netloom_controller_ovn_live_drifted_managed_rows", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_drifted_managed_rows%s %d\n", auditLabels, snapshot.OVNAudit.DriftedManagedRows)
	writeMetricType(w, "netloom_controller_ovn_live_drifted_managed_fields", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_live_drifted_managed_fields%s %d\n", auditLabels, snapshot.OVNAudit.DriftedManagedFields)
	writeMetricType(w, "netloom_controller_ovn_stale_advisory_active", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_stale_advisory_active%s %d\n", staleAdvisoryLabels, boolMetric(snapshot.OVNStaleAdvisory.Status == "warning"))
	writeMetricType(w, "netloom_controller_ovn_stale_advisory_burden", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_stale_advisory_burden%s %d\n", staleAdvisoryLabels, snapshot.OVNStaleAdvisory.Burden)
	writeMetricType(w, "netloom_controller_ovn_stale_advisory_threshold", "gauge")
	fmt.Fprintf(w, "netloom_controller_ovn_stale_advisory_threshold%s %d\n", staleAdvisoryLabels, snapshot.OVNStaleAdvisory.Threshold)
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

func formatResultValue(value string) string {
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

func withIdentityGroupObservations(state control.DesiredState) (control.DesiredState, error) {
	return withIdentityGroupObservationsAt(state, time.Now().UTC())
}

func withIdentityGroupObservationsContext(ctx context.Context, state control.DesiredState) (control.DesiredState, error) {
	return withIdentityGroupObservationsAtContext(ctx, state, time.Now().UTC())
}

func withIdentityGroupObservationsAt(state control.DesiredState, now time.Time) (control.DesiredState, error) {
	return withIdentityGroupObservationsAtContext(context.Background(), state, now)
}

func withIdentityGroupObservationsAtContext(ctx context.Context, state control.DesiredState, now time.Time) (control.DesiredState, error) {
	return mergeIdentityGroupObservationsAtContext(ctx, state, now, nil)
}

func (r *stateFileReconciler) withIdentityGroupObservationsContext(ctx context.Context, state control.DesiredState) (control.DesiredState, error) {
	var cache *control.IdentityGroupObservationCache
	if r != nil {
		cache = r.identityGroupFeedCache
	}
	return mergeIdentityGroupObservationsAtContext(ctx, state, time.Now().UTC(), cache)
}

func mergeIdentityGroupObservationsAtContext(ctx context.Context, state control.DesiredState, now time.Time, cache *control.IdentityGroupObservationCache) (control.DesiredState, error) {
	return control.MergeIdentityGroupObservations(ctx, state, control.IdentityGroupObservationOptions{
		FilePath:    os.Getenv("NETLOOM_IDENTITY_GROUPS_FILE"),
		URL:         os.Getenv("NETLOOM_IDENTITY_GROUPS_URL"),
		BearerToken: os.Getenv("NETLOOM_IDENTITY_GROUPS_BEARER_TOKEN"),
		Timeout:     identityGroupFeedTimeout(),
		Now:         now,
		BackoffBase: identityGroupFeedBackoffInitial(),
		BackoffMax:  identityGroupFeedBackoffMax(),
		Cache:       cache,
	})
}

func identityGroupFeedTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("NETLOOM_IDENTITY_GROUPS_TIMEOUT_MS"))
	if raw == "" {
		return 5 * time.Second
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms < 0 {
		return 5 * time.Second
	}
	return time.Duration(ms) * time.Millisecond
}

func identityGroupFeedBackoffInitial() time.Duration {
	return identityGroupFeedBackoffDuration("NETLOOM_IDENTITY_GROUPS_BACKOFF_INITIAL_MS", time.Second)
}

func identityGroupFeedBackoffMax() time.Duration {
	return identityGroupFeedBackoffDuration("NETLOOM_IDENTITY_GROUPS_BACKOFF_MAX_MS", time.Minute)
}

func identityGroupFeedBackoffDuration(env string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(env))
	if raw == "" {
		return fallback
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms < 0 {
		return fallback
	}
	return time.Duration(ms) * time.Millisecond
}

func (r *stateFileReconciler) executedOperations() int {
	if r == nil {
		return 0
	}
	if recorder, ok := r.executor.(*ovn.RecorderExecutor); ok {
		return len(recorder.Operations())
	}
	if r.ovnBackend == nil {
		return 0
	}
	return len(r.ovnBackend.Operations())
}

func (r *stateFileReconciler) plannedOVNOperations() int {
	if r == nil || r.ovnBackend == nil {
		return 0
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

type clusteredOVNHealthChecker struct {
	checker ovnHealthChecker
	cluster *libovsdbClusterConnector
}

func (c clusteredOVNHealthChecker) HealthCheck(ctx context.Context) (time.Duration, error) {
	if c.checker == nil {
		return 0, nil
	}
	return c.checker.HealthCheck(ctx)
}

func (c clusteredOVNHealthChecker) OVNClusterHealth() ovnClusterHealthSnapshot {
	if c.cluster == nil {
		return ovnClusterHealthSnapshot{}
	}
	return c.cluster.Snapshot()
}

func newOVNTopologyRuntimeFromEnv() (ovnTopologyRuntime, error) {
	backend := ovnTopologyBackendFromEnv()
	if backend == "nbctl" {
		var executor ovn.Executor = ovn.NewRecorderExecutor()
		if db := os.Getenv("NETLOOM_OVN_NBCTL_DB"); db != "" {
			nbctl, err := newNBCTLExecutorFromEnv(db)
			if err != nil {
				return ovnTopologyRuntime{}, err
			}
			executor = nbctl
		}
		ovnBackend := ovn.NewBackend(executor)
		return ovnTopologyRuntime{
			backend:    ovnBackend,
			executor:   executor,
			ovnBackend: ovnBackend,
			cleanup:    ovnBackend,
			health:     executorHealthChecker(executor),
		}, nil
	}
	if backend != "libovsdb" {
		return ovnTopologyRuntime{}, fmt.Errorf("invalid NETLOOM_OVN_TOPOLOGY_BACKEND %q", backend)
	}
	cluster, client, closeFn, err := newLibOVSDBClusterConnectorFromEnv("NETLOOM_OVN_TOPOLOGY_BACKEND=libovsdb")
	if err != nil {
		return ovnTopologyRuntime{}, err
	}
	writer := ovn.NewLibOVSDBTopologyWriter(client)
	initialBackoff, err := libovsdbReconnectInitialBackoff()
	if err != nil {
		closeFn()
		return ovnTopologyRuntime{}, err
	}
	maxBackoff, err := libovsdbReconnectMaxBackoff()
	if err != nil {
		closeFn()
		return ovnTopologyRuntime{}, err
	}
	writer.EnableHealthReconnect(initialBackoff, maxBackoff)
	writer.SetHealthReconnectClientFactory(closeFn, func(ctx context.Context) (libovsdbclient.Client, func(), error) {
		return cluster.Connect(ctx)
	})
	return ovnTopologyRuntime{
		backend: writer,
		cleanup: writer,
		health:  clusteredOVNHealthChecker{checker: writer, cluster: cluster},
		close:   writer.Close,
	}, nil
}

func newOVNAuditReaderFromEnv() (ovn.ManagedOVNReader, func(), error) {
	backend := ovnAuditBackendFromEnv()
	if backend == "nbctl" {
		return nil, nil, nil
	}
	if backend != "libovsdb" {
		return nil, nil, fmt.Errorf("invalid NETLOOM_OVN_AUDIT_BACKEND %q", backend)
	}
	client, closeFn, err := newOVNNBClientFromEnv("NETLOOM_OVN_AUDIT_BACKEND=libovsdb")
	if err != nil {
		return nil, nil, err
	}
	return ovn.NewLibOVSDBManagedReader(client), closeFn, nil
}

func newOVSDBControlStatusWriterFromEnv(ctx context.Context) (ovsdbControlStatusWriter, func(), error) {
	endpoint := strings.TrimSpace(os.Getenv("NETLOOM_OVSDB_ENDPOINT"))
	if endpoint == "" {
		return nil, func() {}, nil
	}
	client, closeFn, err := newOpenVSwitchClient(ctx, endpoint)
	if err != nil {
		return nil, nil, err
	}
	return linuxdatapath.NewLibOVSDBProviderSyncer(client), closeFn, nil
}

func newOpenVSwitchClient(ctx context.Context, endpoint string) (libovsdbclient.Client, func(), error) {
	dbModel, err := vswitch.FullDatabaseModel()
	if err != nil {
		return nil, nil, fmt.Errorf("build Open_vSwitch libovsdb model: %w", err)
	}
	client, err := libovsdbclient.NewOVSDBClient(dbModel, libovsdbclient.WithEndpoint(endpoint))
	if err != nil {
		return nil, nil, fmt.Errorf("create Open_vSwitch libovsdb client: %w", err)
	}
	if err := client.Connect(ctx); err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("connect Open_vSwitch libovsdb endpoint %s: %w", endpoint, err)
	}
	if _, err := client.MonitorAll(ctx); err != nil {
		client.Disconnect()
		client.Close()
		return nil, nil, fmt.Errorf("monitor Open_vSwitch libovsdb endpoint %s: %w", endpoint, err)
	}
	return client, func() {
		client.Disconnect()
		client.Close()
	}, nil
}

func ovnTopologyBackendFromEnv() string {
	backend := strings.TrimSpace(os.Getenv("NETLOOM_OVN_TOPOLOGY_BACKEND"))
	if backend != "" {
		return backend
	}
	if len(ovnLibOVSDBEndpointsFromEnv()) > 0 {
		return "libovsdb"
	}
	return "nbctl"
}

func ovnAuditBackendFromEnv() string {
	backend := strings.TrimSpace(os.Getenv("NETLOOM_OVN_AUDIT_BACKEND"))
	if backend != "" {
		return backend
	}
	if len(ovnLibOVSDBEndpointsFromEnv()) > 0 {
		return "libovsdb"
	}
	return "nbctl"
}

func newOVNNBClientFromEnv(owner string) (libovsdbclient.Client, func(), error) {
	endpoints := ovnLibOVSDBEndpointsFromEnv()
	if len(endpoints) == 0 {
		return nil, nil, fmt.Errorf("%s requires NETLOOM_OVN_LIBOVSDB_ENDPOINT or NETLOOM_OVN_NBCTL_DB", owner)
	}
	return newOVNNBClientFromEndpoints(context.Background(), owner, endpoints)
}

func newLibOVSDBClusterConnectorFromEnv(owner string) (*libovsdbClusterConnector, libovsdbclient.Client, func(), error) {
	endpoints := ovnLibOVSDBEndpointsFromEnv()
	if len(endpoints) == 0 {
		return nil, nil, nil, fmt.Errorf("%s requires NETLOOM_OVN_LIBOVSDB_ENDPOINT or NETLOOM_OVN_NBCTL_DB", owner)
	}
	cluster := newLibOVSDBClusterConnector(owner, endpoints, newOVNNBClientForEndpoint, ovnLeaderProbeFromEnv())
	client, closeFn, err := cluster.Connect(context.Background())
	if err != nil {
		return nil, nil, nil, err
	}
	return cluster, client, closeFn, nil
}

func ovnLibOVSDBEndpointsFromEnv() []string {
	raw := strings.TrimSpace(os.Getenv("NETLOOM_OVN_LIBOVSDB_ENDPOINT"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("NETLOOM_OVN_NBCTL_DB"))
	}
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	})
	endpoints := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		endpoint := strings.TrimSpace(part)
		if endpoint == "" {
			continue
		}
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

func newLibOVSDBClusterConnector(owner string, endpoints []string, dial libovsdbDialFunc, leaderProbe ovnLeaderProbe) *libovsdbClusterConnector {
	if dial == nil {
		dial = newOVNNBClientForEndpoint
	}
	return &libovsdbClusterConnector{
		owner:        owner,
		endpoints:    append([]string(nil), endpoints...),
		dial:         dial,
		leaderProbe:  leaderProbe,
		currentIndex: -1,
	}
}

func (c *libovsdbClusterConnector) Connect(ctx context.Context) (libovsdbclient.Client, func(), error) {
	if c == nil || len(c.endpoints) == 0 {
		return nil, nil, fmt.Errorf("OVN northbound libovsdb endpoints are not configured")
	}
	c.mu.Lock()
	start := 0
	previous := c.current
	if c.currentIndex >= 0 {
		start = (c.currentIndex + 1) % len(c.endpoints)
	}
	c.mu.Unlock()
	if leader := c.probeLeader(ctx); leader != "" {
		if index := indexString(c.endpoints, leader); index >= 0 {
			start = index
		}
	}

	var errs []string
	for offset := 0; offset < len(c.endpoints); offset++ {
		index := (start + offset) % len(c.endpoints)
		endpoint := c.endpoints[index]
		client, closeFn, err := c.dial(ctx, c.owner, endpoint)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", endpoint, err))
			continue
		}
		c.mu.Lock()
		if previous != "" && endpoint != previous {
			c.failovers++
		}
		c.current = endpoint
		c.currentIndex = index
		c.mu.Unlock()
		return client, closeFn, nil
	}
	return nil, nil, fmt.Errorf("connect OVN northbound libovsdb endpoints: %s", strings.Join(errs, "; "))
}

func (c *libovsdbClusterConnector) probeLeader(ctx context.Context) string {
	if c == nil || c.leaderProbe == nil {
		return ""
	}
	leader, err := c.leaderProbe(ctx, append([]string(nil), c.endpoints...))
	if err != nil {
		c.mu.Lock()
		c.leaderStatus = "error"
		c.leaderError = err.Error()
		c.mu.Unlock()
		return ""
	}
	leader = strings.TrimSpace(leader)
	if leader == "" {
		c.mu.Lock()
		c.leaderStatus = "unknown"
		c.leaderError = ""
		c.mu.Unlock()
		return ""
	}
	c.mu.Lock()
	c.leader = leader
	c.leaderStatus = "ok"
	c.leaderError = ""
	c.mu.Unlock()
	return leader
}

func (c *libovsdbClusterConnector) Snapshot() ovnClusterHealthSnapshot {
	if c == nil {
		return ovnClusterHealthSnapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	leaderStatus := c.leaderStatus
	if c.leaderProbe == nil {
		leaderStatus = "disabled"
	} else if leaderStatus == "" {
		leaderStatus = "unknown"
	}
	return ovnClusterHealthSnapshot{
		ActiveEndpoint:      c.current,
		LeaderEndpoint:      c.leader,
		LeaderProbeStatus:   leaderStatus,
		LeaderProbeError:    c.leaderError,
		ConfiguredEndpoints: len(c.endpoints),
		Failovers:           c.failovers,
		LeaderPreferred:     c.leader != "" && c.current == c.leader,
	}
}

func newOVNNBClientFromEndpoints(ctx context.Context, owner string, endpoints []string) (libovsdbclient.Client, func(), error) {
	cluster := newLibOVSDBClusterConnector(owner, endpoints, newOVNNBClientForEndpoint, nil)
	return cluster.Connect(ctx)
}

func newOVNNBClientForEndpoint(ctx context.Context, owner, endpoint string) (libovsdbclient.Client, func(), error) {
	if endpoint == "" {
		return nil, nil, fmt.Errorf("%s requires OVN northbound libovsdb endpoint", owner)
	}
	dbModel, err := ovnnb.FullDatabaseModel()
	if err != nil {
		return nil, nil, fmt.Errorf("build OVN northbound libovsdb model: %w", err)
	}
	client, err := libovsdbclient.NewOVSDBClient(dbModel, libovsdbclient.WithEndpoint(endpoint))
	if err != nil {
		return nil, nil, fmt.Errorf("create OVN northbound libovsdb client: %w", err)
	}
	timeout, err := nbctlTimeout()
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	connectCtx := ctx
	cancel := func() {}
	if _, ok := connectCtx.Deadline(); !ok && timeout > 0 {
		var cancelCtx context.CancelFunc
		connectCtx, cancelCtx = context.WithTimeout(connectCtx, timeout)
		cancel = cancelCtx
	}
	defer cancel()
	if err := client.Connect(connectCtx); err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("connect OVN northbound libovsdb endpoint %s: %w", endpoint, err)
	}
	if _, err := client.MonitorAll(connectCtx); err != nil {
		client.Disconnect()
		client.Close()
		return nil, nil, fmt.Errorf("monitor OVN northbound libovsdb endpoint %s: %w", endpoint, err)
	}
	return client, func() {
		client.Disconnect()
		client.Close()
	}, nil
}

func ovnLeaderProbeFromEnv() ovnLeaderProbe {
	command := strings.TrimSpace(os.Getenv("NETLOOM_OVN_LEADER_STATUS_CMD"))
	if command != "" {
		return ovnLeaderCommandProbe(command)
	}
	targets := ovnClusterStatusTargetsFromEnv()
	if len(targets) == 0 {
		return nil
	}
	appctl := strings.TrimSpace(os.Getenv("NETLOOM_OVN_APPCTL_BIN"))
	if appctl == "" {
		appctl = "ovn-appctl"
	}
	db := strings.TrimSpace(os.Getenv("NETLOOM_OVN_CLUSTER_STATUS_DB"))
	if db == "" {
		db = ovnnb.DatabaseName
	}
	return ovnClusterStatusLeaderProbe(appctl, db, targets)
}

func ovnLeaderCommandProbe(command string) ovnLeaderProbe {
	return func(ctx context.Context, endpoints []string) (string, error) {
		output, err := exec.CommandContext(ctx, "sh", "-c", command).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("probe OVN leader endpoint: %w: %s", err, strings.TrimSpace(string(output)))
		}
		leader := parseOVNLeaderEndpoint(string(output), endpoints)
		if leader == "" {
			return "", fmt.Errorf("probe OVN leader endpoint: no configured endpoint found in output")
		}
		return leader, nil
	}
}

func ovnClusterStatusLeaderProbe(appctl, db string, targets map[string]string) ovnLeaderProbe {
	return func(ctx context.Context, endpoints []string) (string, error) {
		var errs []string
		for _, endpoint := range endpoints {
			target := strings.TrimSpace(targets[endpoint])
			if target == "" {
				continue
			}
			output, err := exec.CommandContext(ctx, appctl, "-t", target, "cluster/status", db).CombinedOutput()
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v: %s", endpoint, err, strings.TrimSpace(string(output))))
				continue
			}
			if ovnClusterStatusIsLeader(string(output)) {
				return endpoint, nil
			}
		}
		if len(errs) > 0 {
			return "", fmt.Errorf("probe OVN cluster/status leader endpoint: %s", strings.Join(errs, "; "))
		}
		return "", fmt.Errorf("probe OVN cluster/status leader endpoint: no configured endpoint target reported leader")
	}
}

func ovnClusterStatusTargetsFromEnv() map[string]string {
	raw := strings.TrimSpace(os.Getenv("NETLOOM_OVN_CLUSTER_STATUS_TARGETS"))
	if raw == "" {
		return nil
	}
	out := make(map[string]string)
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	}) {
		endpoint, target, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok {
			continue
		}
		endpoint = strings.TrimSpace(endpoint)
		target = strings.TrimSpace(target)
		if endpoint == "" || target == "" {
			continue
		}
		out[endpoint] = target
	}
	return out
}

func parseOVNLeaderEndpoint(output string, endpoints []string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		key, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "leader") {
			continue
		}
		candidate := strings.TrimSpace(value)
		if indexString(endpoints, candidate) >= 0 {
			return candidate
		}
	}
	for _, endpoint := range endpoints {
		if endpoint != "" && strings.Contains(output, endpoint) {
			return endpoint
		}
	}
	return ""
}

func ovnClusterStatusIsLeader(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if strings.EqualFold(key, "Role") && strings.EqualFold(value, "leader") {
			return true
		}
		if strings.EqualFold(key, "Leader") && strings.EqualFold(value, "self") {
			return true
		}
	}
	return false
}

func ovnLeaderProbeModeFromEnv() string {
	if strings.TrimSpace(os.Getenv("NETLOOM_OVN_LEADER_STATUS_CMD")) != "" {
		return "command"
	}
	if len(ovnClusterStatusTargetsFromEnv()) > 0 {
		return "cluster-status"
	}
	return "disabled"
}

type ovnDBMaintenanceTarget struct {
	Target string
	DB     string
}

type ovnDBMaintenance struct {
	appctl  string
	targets []ovnDBMaintenanceTarget
}

func newOVNMaintenanceFromEnv() ovnMaintenanceRunner {
	targets := ovnDBMaintenanceTargetsFromEnv()
	if len(targets) == 0 {
		return nil
	}
	appctl := strings.TrimSpace(os.Getenv("NETLOOM_OVN_APPCTL_BIN"))
	if appctl == "" {
		appctl = "ovn-appctl"
	}
	return ovnDBMaintenance{appctl: appctl, targets: targets}
}

func ovnDBMaintenanceTargetsFromEnv() []ovnDBMaintenanceTarget {
	raw := strings.TrimSpace(os.Getenv("NETLOOM_OVN_DB_COMPACT_TARGETS"))
	if raw == "" {
		return nil
	}
	items := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	})
	targets := make([]ovnDBMaintenanceTarget, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		target, db, _ := strings.Cut(strings.TrimSpace(item), "=")
		target = strings.TrimSpace(target)
		db = strings.TrimSpace(db)
		if target == "" {
			continue
		}
		if db == "" {
			db = ovnnb.DatabaseName
		}
		key := target + "|" + db
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, ovnDBMaintenanceTarget{Target: target, DB: db})
	}
	return targets
}

func (m ovnDBMaintenance) RunMaintenance(ctx context.Context) ovnMaintenanceResult {
	if len(m.targets) == 0 {
		return ovnMaintenanceResult{Status: "disabled"}
	}
	appctl := strings.TrimSpace(m.appctl)
	if appctl == "" {
		appctl = "ovn-appctl"
	}
	start := time.Now()
	result := ovnMaintenanceResult{Status: "ok", Attempted: len(m.targets)}
	var errs []string
	for _, target := range m.targets {
		args := []string{"-t", target.Target, "ovsdb-server/compact"}
		if target.DB != "" {
			args = append(args, target.DB)
		}
		output, err := exec.CommandContext(ctx, appctl, args...).CombinedOutput()
		if err != nil && !ovnCompactDuplicateSnapshot(string(output)) {
			result.Failed++
			errs = append(errs, fmt.Sprintf("%s(%s): %v: %s", target.Target, target.DB, err, strings.TrimSpace(string(output))))
			continue
		}
		result.Succeeded++
	}
	result.Latency = time.Since(start)
	if result.Failed > 0 {
		result.Status = "error"
		result.Error = strings.Join(errs, "; ")
	}
	return result
}

func ovnCompactDuplicateSnapshot(output string) bool {
	return strings.Contains(output, "not storing a duplicate snapshot")
}

func indexString(values []string, value string) int {
	for i, candidate := range values {
		if candidate == value {
			return i
		}
	}
	return -1
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

func libovsdbReconnectInitialBackoff() (time.Duration, error) {
	raw := os.Getenv("NETLOOM_OVN_LIBOVSDB_RECONNECT_INITIAL_BACKOFF_MS")
	if raw == "" {
		return ovn.DefaultLibOVSDBReconnectInitialBackoff, nil
	}
	ms, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NETLOOM_OVN_LIBOVSDB_RECONNECT_INITIAL_BACKOFF_MS: %w", err)
	}
	if ms <= 0 {
		return 0, nil
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func libovsdbReconnectMaxBackoff() (time.Duration, error) {
	raw := os.Getenv("NETLOOM_OVN_LIBOVSDB_RECONNECT_MAX_BACKOFF_MS")
	if raw == "" {
		return ovn.DefaultLibOVSDBReconnectMaxBackoff, nil
	}
	ms, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NETLOOM_OVN_LIBOVSDB_RECONNECT_MAX_BACKOFF_MS: %w", err)
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
