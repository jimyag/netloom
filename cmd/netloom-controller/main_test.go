package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn"
	"github.com/jimyag/netloom/internal/topology"
)

func TestReconcileIntervalParsesMilliseconds(t *testing.T) {
	t.Setenv("NETLOOM_RECONCILE_INTERVAL_MS", "500")
	interval, err := reconcileInterval()
	if err != nil {
		t.Fatal(err)
	}
	if interval != 500*time.Millisecond {
		t.Fatalf("interval = %s, want 500ms", interval)
	}
}

func TestReconcileIntervalRejectsInvalidValue(t *testing.T) {
	t.Setenv("NETLOOM_RECONCILE_INTERVAL_MS", "often")
	_, err := reconcileInterval()
	if err == nil {
		t.Fatal("expected invalid interval to fail")
	}
}

func TestNBCTLTimeoutParsesMilliseconds(t *testing.T) {
	t.Setenv("NETLOOM_OVN_NBCTL_TIMEOUT_MS", "250")
	timeout, err := nbctlTimeout()
	if err != nil {
		t.Fatal(err)
	}
	if timeout != 250*time.Millisecond {
		t.Fatalf("timeout = %s, want 250ms", timeout)
	}
}

func TestNBCTLTimeoutRejectsInvalidValue(t *testing.T) {
	t.Setenv("NETLOOM_OVN_NBCTL_TIMEOUT_MS", "slow")
	_, err := nbctlTimeout()
	if err == nil {
		t.Fatal("expected invalid nbctl timeout to fail")
	}
}

func TestNBCTLRetryAttemptsParsesValue(t *testing.T) {
	t.Setenv("NETLOOM_OVN_NBCTL_RETRY_ATTEMPTS", "5")
	attempts, err := nbctlRetryAttempts()
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 5 {
		t.Fatalf("retry attempts = %d, want 5", attempts)
	}
}

func TestNBCTLRetryAttemptsRejectsInvalidValue(t *testing.T) {
	t.Setenv("NETLOOM_OVN_NBCTL_RETRY_ATTEMPTS", "often")
	_, err := nbctlRetryAttempts()
	if err == nil {
		t.Fatal("expected invalid nbctl retry attempts to fail")
	}
}

func TestNBCTLRetryInitialBackoffParsesMilliseconds(t *testing.T) {
	t.Setenv("NETLOOM_OVN_NBCTL_RETRY_INITIAL_BACKOFF_MS", "75")
	backoff, err := nbctlRetryInitialBackoff()
	if err != nil {
		t.Fatal(err)
	}
	if backoff != 75*time.Millisecond {
		t.Fatalf("initial backoff = %s, want 75ms", backoff)
	}
}

func TestNBCTLRetryInitialBackoffRejectsInvalidValue(t *testing.T) {
	t.Setenv("NETLOOM_OVN_NBCTL_RETRY_INITIAL_BACKOFF_MS", "soon")
	_, err := nbctlRetryInitialBackoff()
	if err == nil {
		t.Fatal("expected invalid initial backoff to fail")
	}
}

func TestNBCTLRetryMaxBackoffParsesMilliseconds(t *testing.T) {
	t.Setenv("NETLOOM_OVN_NBCTL_RETRY_MAX_BACKOFF_MS", "900")
	backoff, err := nbctlRetryMaxBackoff()
	if err != nil {
		t.Fatal(err)
	}
	if backoff != 900*time.Millisecond {
		t.Fatalf("max backoff = %s, want 900ms", backoff)
	}
}

func TestNBCTLRetryMaxBackoffRejectsInvalidValue(t *testing.T) {
	t.Setenv("NETLOOM_OVN_NBCTL_RETRY_MAX_BACKOFF_MS", "later")
	_, err := nbctlRetryMaxBackoff()
	if err == nil {
		t.Fatal("expected invalid max backoff to fail")
	}
}

func TestLibOVSDBReconnectBackoffParsesMilliseconds(t *testing.T) {
	t.Setenv("NETLOOM_OVN_LIBOVSDB_RECONNECT_INITIAL_BACKOFF_MS", "125")
	initial, err := libovsdbReconnectInitialBackoff()
	if err != nil {
		t.Fatal(err)
	}
	if initial != 125*time.Millisecond {
		t.Fatalf("initial reconnect backoff = %s, want 125ms", initial)
	}

	t.Setenv("NETLOOM_OVN_LIBOVSDB_RECONNECT_MAX_BACKOFF_MS", "750")
	maxBackoff, err := libovsdbReconnectMaxBackoff()
	if err != nil {
		t.Fatal(err)
	}
	if maxBackoff != 750*time.Millisecond {
		t.Fatalf("max reconnect backoff = %s, want 750ms", maxBackoff)
	}
}

func TestLibOVSDBReconnectBackoffRejectsInvalidValue(t *testing.T) {
	t.Setenv("NETLOOM_OVN_LIBOVSDB_RECONNECT_INITIAL_BACKOFF_MS", "soon")
	if _, err := libovsdbReconnectInitialBackoff(); err == nil {
		t.Fatal("expected invalid libovsdb initial reconnect backoff to fail")
	}
	t.Setenv("NETLOOM_OVN_LIBOVSDB_RECONNECT_MAX_BACKOFF_MS", "later")
	if _, err := libovsdbReconnectMaxBackoff(); err == nil {
		t.Fatal("expected invalid libovsdb max reconnect backoff to fail")
	}
}

func TestOVNLibOVSDBEndpointsFromEnvParsesClusterList(t *testing.T) {
	t.Setenv("NETLOOM_OVN_LIBOVSDB_ENDPOINT", "tcp:10.0.0.1:6641, tcp:10.0.0.2:6641 tcp:10.0.0.1:6641")
	endpoints := ovnLibOVSDBEndpointsFromEnv()
	want := []string{"tcp:10.0.0.1:6641", "tcp:10.0.0.2:6641"}
	if strings.Join(endpoints, ",") != strings.Join(want, ",") {
		t.Fatalf("endpoints = %+v, want %+v", endpoints, want)
	}
}

func TestParseOVNLeaderEndpointFindsConfiguredEndpoint(t *testing.T) {
	endpoints := []string{"tcp:a:6641", "tcp:b:6641"}
	if got := parseOVNLeaderEndpoint("cluster status\nleader: tcp:b:6641\n", endpoints); got != "tcp:b:6641" {
		t.Fatalf("leader endpoint = %q, want tcp:b:6641", got)
	}
	if got := parseOVNLeaderEndpoint("leader: tcp:c:6641\n", endpoints); got != "" {
		t.Fatalf("leader endpoint = %q, want empty for unconfigured endpoint", got)
	}
}

func TestParseOVNLeaderEndpointPrefersLeaderLineOverOtherEndpointMentions(t *testing.T) {
	endpoints := []string{"tcp:a:6641", "tcp:b:6641"}
	output := "connections: tcp:a:6641 tcp:b:6641\nleader: tcp:b:6641\n"
	if got := parseOVNLeaderEndpoint(output, endpoints); got != "tcp:b:6641" {
		t.Fatalf("leader endpoint = %q, want tcp:b:6641", got)
	}
}

func TestOVNClusterStatusTargetsFromEnvParsesEndpointMappings(t *testing.T) {
	t.Setenv("NETLOOM_OVN_CLUSTER_STATUS_TARGETS", "tcp:a:6641=/run/ovn/a.ctl, tcp:b:6641=ovnnb_db.ctl")
	targets := ovnClusterStatusTargetsFromEnv()
	if targets["tcp:a:6641"] != "/run/ovn/a.ctl" || targets["tcp:b:6641"] != "ovnnb_db.ctl" {
		t.Fatalf("targets = %#v", targets)
	}
}

func TestOVNClusterStatusIsLeader(t *testing.T) {
	for _, output := range []string{
		"Cluster ID: x\nRole: leader\n",
		"Cluster ID: x\nLeader: self\n",
	} {
		if !ovnClusterStatusIsLeader(output) {
			t.Fatalf("cluster status %q should be leader", output)
		}
	}
	if ovnClusterStatusIsLeader("Cluster ID: x\nRole: follower\nLeader: 1234\n") {
		t.Fatal("follower cluster status should not be leader")
	}
}

func TestOVNClusterStatusLeaderProbePrefersLeaderEndpoint(t *testing.T) {
	dir := t.TempDir()
	appctl := filepath.Join(dir, "ovn-appctl")
	script := `#!/bin/sh
case "$2" in
  target-b) printf 'Cluster ID: test\nRole: leader\n' ;;
  *) printf 'Cluster ID: test\nRole: follower\n' ;;
esac
`
	if err := os.WriteFile(appctl, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	probe := ovnClusterStatusLeaderProbe(appctl, "OVN_Northbound", map[string]string{
		"tcp:a:6641": "target-a",
		"tcp:b:6641": "target-b",
	})
	leader, err := probe(context.Background(), []string{"tcp:a:6641", "tcp:b:6641"})
	if err != nil {
		t.Fatal(err)
	}
	if leader != "tcp:b:6641" {
		t.Fatalf("leader = %q, want tcp:b:6641", leader)
	}
}

func TestOVNLeaderProbeFromEnvUsesClusterStatusTargets(t *testing.T) {
	dir := t.TempDir()
	appctl := filepath.Join(dir, "ovn-appctl")
	script := `#!/bin/sh
case "$2" in
  target-a) printf 'Cluster ID: test\nLeader: self\n' ;;
  *) printf 'Cluster ID: test\nRole: follower\n' ;;
esac
`
	if err := os.WriteFile(appctl, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETLOOM_OVN_APPCTL_BIN", appctl)
	t.Setenv("NETLOOM_OVN_CLUSTER_STATUS_TARGETS", "tcp:a:6641=target-a,tcp:b:6641=target-b")
	probe := ovnLeaderProbeFromEnv()
	if probe == nil {
		t.Fatal("expected cluster/status leader probe")
	}
	leader, err := probe(context.Background(), []string{"tcp:a:6641", "tcp:b:6641"})
	if err != nil {
		t.Fatal(err)
	}
	if leader != "tcp:a:6641" {
		t.Fatalf("leader = %q, want tcp:a:6641", leader)
	}
	if mode := ovnLeaderProbeModeFromEnv(); mode != "cluster-status" {
		t.Fatalf("leader probe mode = %q, want cluster-status", mode)
	}
}

func TestOVNDBMaintenanceTargetsFromEnvParsesTargets(t *testing.T) {
	t.Setenv("NETLOOM_OVN_DB_COMPACT_TARGETS", "/run/ovn/ovnnb_db.ctl=OVN_Northbound,/run/ovn/ovnsb_db.ctl=OVN_Southbound,/run/ovn/ovnnb_db.ctl=OVN_Northbound")
	targets := ovnDBMaintenanceTargetsFromEnv()
	if len(targets) != 2 {
		t.Fatalf("targets = %#v, want 2 unique targets", targets)
	}
	if targets[0].Target != "/run/ovn/ovnnb_db.ctl" || targets[0].DB != "OVN_Northbound" {
		t.Fatalf("target[0] = %#v", targets[0])
	}
	if targets[1].Target != "/run/ovn/ovnsb_db.ctl" || targets[1].DB != "OVN_Southbound" {
		t.Fatalf("target[1] = %#v", targets[1])
	}
}

func TestOVNDBMaintenanceRunsCompactTargets(t *testing.T) {
	dir := t.TempDir()
	appctl := filepath.Join(dir, "ovn-appctl")
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
printf '%s %s %s %s\n' "$1" "$2" "$3" "$4" >> "$NETLOOM_TEST_CALLS"
exit 0
`
	if err := os.WriteFile(appctl, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETLOOM_TEST_CALLS", logPath)
	result := ovnDBMaintenance{
		appctl: appctl,
		targets: []ovnDBMaintenanceTarget{
			{Target: "target-a", DB: "OVN_Northbound"},
			{Target: "target-b", DB: "OVN_Southbound"},
		},
	}.RunMaintenance(context.Background())
	if result.Status != "ok" || result.Attempted != 2 || result.Succeeded != 2 || result.Failed != 0 {
		t.Fatalf("maintenance result = %+v, want two successful compactions", result)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(raw)), "-t target-a ovsdb-server/compact OVN_Northbound\n-t target-b ovsdb-server/compact OVN_Southbound"; got != want {
		t.Fatalf("appctl calls = %q, want %q", got, want)
	}
}

func TestOVNDBMaintenanceTreatsDuplicateSnapshotAsSuccess(t *testing.T) {
	dir := t.TempDir()
	appctl := filepath.Join(dir, "ovn-appctl")
	script := `#!/bin/sh
printf 'not storing a duplicate snapshot\n'
exit 1
`
	if err := os.WriteFile(appctl, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	result := ovnDBMaintenance{
		appctl:  appctl,
		targets: []ovnDBMaintenanceTarget{{Target: "target-a", DB: "OVN_Northbound"}},
	}.RunMaintenance(context.Background())
	if result.Status != "ok" || result.Succeeded != 1 || result.Failed != 0 {
		t.Fatalf("maintenance result = %+v, want duplicate snapshot as success", result)
	}
}

func TestOVNDBMaintenanceReportsFailures(t *testing.T) {
	dir := t.TempDir()
	appctl := filepath.Join(dir, "ovn-appctl")
	script := `#!/bin/sh
printf 'locked\n'
exit 2
`
	if err := os.WriteFile(appctl, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	result := ovnDBMaintenance{
		appctl:  appctl,
		targets: []ovnDBMaintenanceTarget{{Target: "target-a", DB: "OVN_Northbound"}},
	}.RunMaintenance(context.Background())
	if result.Status != "error" || result.Succeeded != 0 || result.Failed != 1 || !strings.Contains(result.Error, "locked") {
		t.Fatalf("maintenance result = %+v, want failed compaction with error output", result)
	}
}

func TestLibOVSDBClusterConnectorPrefersProbedLeaderEndpoint(t *testing.T) {
	attempts := make([]string, 0)
	cluster := newLibOVSDBClusterConnector("test", []string{"tcp:a:6641", "tcp:b:6641"}, func(_ context.Context, _ string, endpoint string) (libovsdbclient.Client, func(), error) {
		attempts = append(attempts, endpoint)
		return nil, func() {}, nil
	}, func(context.Context, []string) (string, error) {
		return "tcp:b:6641", nil
	})
	if _, _, err := cluster.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(attempts, ",") != "tcp:b:6641" {
		t.Fatalf("attempts = %+v, want leader endpoint first", attempts)
	}
	snapshot := cluster.Snapshot()
	if snapshot.ActiveEndpoint != "tcp:b:6641" || snapshot.LeaderEndpoint != "tcp:b:6641" || !snapshot.LeaderPreferred {
		t.Fatalf("cluster snapshot = %+v, want active leader preferred", snapshot)
	}
	if snapshot.LeaderProbeStatus != "ok" || snapshot.LeaderProbeError != "" {
		t.Fatalf("leader probe snapshot = %+v, want ok without error", snapshot)
	}
}

func TestLibOVSDBClusterConnectorReportsLeaderProbeFailure(t *testing.T) {
	attempts := make([]string, 0)
	cluster := newLibOVSDBClusterConnector("test", []string{"tcp:a:6641", "tcp:b:6641"}, func(_ context.Context, _ string, endpoint string) (libovsdbclient.Client, func(), error) {
		attempts = append(attempts, endpoint)
		return nil, func() {}, nil
	}, func(context.Context, []string) (string, error) {
		return "", errors.New("cluster status unavailable")
	})
	if _, _, err := cluster.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(attempts, ",") != "tcp:a:6641" {
		t.Fatalf("attempts = %+v, want fallback to first configured endpoint", attempts)
	}
	snapshot := cluster.Snapshot()
	if snapshot.ActiveEndpoint != "tcp:a:6641" || snapshot.LeaderEndpoint != "" || snapshot.LeaderPreferred {
		t.Fatalf("cluster snapshot = %+v, want active fallback without leader", snapshot)
	}
	if snapshot.LeaderProbeStatus != "error" || !strings.Contains(snapshot.LeaderProbeError, "cluster status unavailable") {
		t.Fatalf("leader probe snapshot = %+v, want recorded probe error", snapshot)
	}
}

func TestLibOVSDBClusterConnectorFailsOverEndpoints(t *testing.T) {
	attempts := make([]string, 0)
	cluster := newLibOVSDBClusterConnector("test", []string{"tcp:a:6641", "tcp:b:6641"}, func(_ context.Context, _ string, endpoint string) (libovsdbclient.Client, func(), error) {
		attempts = append(attempts, endpoint)
		if endpoint == "tcp:a:6641" {
			return nil, nil, errors.New("down")
		}
		return nil, func() {}, nil
	}, nil)
	if _, _, err := cluster.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(attempts, ",") != "tcp:a:6641,tcp:b:6641" {
		t.Fatalf("attempts = %+v, want first endpoint then failover endpoint", attempts)
	}
	snapshot := cluster.Snapshot()
	if snapshot.ActiveEndpoint != "tcp:b:6641" || snapshot.ConfiguredEndpoints != 2 || snapshot.Failovers != 0 {
		t.Fatalf("initial cluster snapshot = %+v, want active b without counted failover", snapshot)
	}
	attempts = attempts[:0]
	cluster.dial = func(_ context.Context, _ string, endpoint string) (libovsdbclient.Client, func(), error) {
		attempts = append(attempts, endpoint)
		if endpoint == "tcp:a:6641" {
			return nil, func() {}, nil
		}
		return nil, nil, errors.New("down")
	}
	if _, _, err := cluster.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot = cluster.Snapshot()
	if snapshot.ActiveEndpoint != "tcp:a:6641" || snapshot.Failovers != 1 {
		t.Fatalf("failover cluster snapshot = %+v, want active a with one failover", snapshot)
	}
}

func TestReconcileFailureBackoffDefaultsToInterval(t *testing.T) {
	backoff, err := reconcileFailureBackoff(750 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if backoff != 750*time.Millisecond {
		t.Fatalf("backoff = %s, want 750ms", backoff)
	}
}

func TestReconcileFailureBackoffParsesMilliseconds(t *testing.T) {
	t.Setenv("NETLOOM_RECONCILE_FAILURE_BACKOFF_MS", "125")
	backoff, err := reconcileFailureBackoff(500 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if backoff != 125*time.Millisecond {
		t.Fatalf("backoff = %s, want 125ms", backoff)
	}
}

func TestReconcileFailureBackoffRejectsInvalidValue(t *testing.T) {
	t.Setenv("NETLOOM_RECONCILE_FAILURE_BACKOFF_MS", "slow")
	_, err := reconcileFailureBackoff(500 * time.Millisecond)
	if err == nil {
		t.Fatal("expected invalid reconcile failure backoff to fail")
	}
}

func TestRunReconcileLoopRetriesAfterFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	attempts := 0
	failures := 0
	errBoom := errors.New("boom")
	err := runReconcileLoop(ctx, 20*time.Millisecond, 2*time.Millisecond, func() error {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts < 3 {
			return errBoom
		}
		cancel()
		return nil
	}, func(err error) {
		if !errors.Is(err, errBoom) {
			t.Fatalf("reported error = %v, want boom", err)
		}
		mu.Lock()
		failures++
		mu.Unlock()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runReconcileLoop error = %v, want context canceled", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
	if failures != 2 {
		t.Fatalf("failures = %d, want 2", failures)
	}
}

func TestPrintControllerReconcileFailureIncludesPhase(t *testing.T) {
	state := control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		SecurityGroups: []model.SecurityGroup{{
			Name: "web",
			Rules: []model.SecurityGroupRule{{
				Direction: model.DirectionIngress,
				Action:    model.ActionAllow,
			}},
		}},
	}
	summary := control.LoadBalancerHealthSummary{Checked: 2, Healthy: 1, Unhealthy: 1}
	ovnHealth := ovnHealthSnapshot{Status: "error", Latency: 25 * time.Millisecond, ConsecutiveFailures: 2}
	output := captureStdout(t, func() {
		printControllerReconcileFailure("ovn_health", state, summary, ovnHealth, 3, 2, errors.New("boom"), 125*time.Millisecond)
	})

	expected := []string{
		"netloom-controller reconcile failed",
		"reconcile_phase=ovn_health",
		"vpcs=1",
		"security_groups=1",
		"policy_entries=0",
		"lb_health_checked=2",
		"lb_health_healthy=1",
		"lb_health_unhealthy=1",
		"ovn_health=error",
		"ovn_health_latency_ms=25",
		"ovn_health_consecutive_failures=2",
		"ovn_health_consecutive_successes=0",
		"ovn_health_recovering=0",
		"ovn_ops=3",
		"ovn_executed=2",
		"err=\"boom\"",
		"reconcile_duration_ms=125",
	}
	for _, want := range expected {
		if !strings.Contains(output, want) {
			t.Fatalf("failure output missing %q:\n%s", want, output)
		}
	}
}

func TestStateFileReconcilerReportsLoadStateOpenFailure(t *testing.T) {
	reconciler := &stateFileReconciler{healthTracker: control.NewLoadBalancerHealthTracker()}
	missingPath := filepath.Join(t.TempDir(), "missing.json")
	var err error
	output := captureStdout(t, func() {
		err = reconciler.reconcile(context.Background(), missingPath)
	})

	if err == nil {
		t.Fatal("expected missing state file to fail")
	}
	if !strings.Contains(output, "reconcile_phase=load_state") {
		t.Fatalf("failure output missing load_state phase:\n%s", output)
	}
	if !strings.Contains(output, "err=\"open "+missingPath) {
		t.Fatalf("failure output missing open error:\n%s", output)
	}
}

func TestApplyLoadBalancerHealthChecksDisabledByDefault(t *testing.T) {
	state := control.DesiredState{LoadBalancers: []model.LoadBalancer{{
		Name:        "web",
		VPC:         "prod",
		VIP:         netip.MustParseAddr("10.96.0.10"),
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
		Ports: []model.LoadBalancerPort{{
			Port:     80,
			Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("127.0.0.1"), Port: 1}},
		}},
	}}}
	reconciler := &stateFileReconciler{healthTracker: control.NewLoadBalancerHealthTracker()}
	summary, err := reconciler.applyLoadBalancerHealthChecks(context.Background(), &state)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Checked != 0 || state.LoadBalancers[0].Ports[0].Backends[0].Healthy != nil {
		t.Fatalf("summary/state = %+v/%+v, want no active probe by default", summary, state.LoadBalancers[0].Ports[0].Backends[0])
	}
}

func TestControllerMetricsReportsNotReadyBeforeFirstReconcile(t *testing.T) {
	metrics := newControllerMetrics()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)

	metrics.handleMetrics(recorder, request)

	output := recorder.Body.String()
	if !strings.Contains(output, "netloom_controller_reconcile_ready 0") {
		t.Fatalf("metrics output missing not-ready gauge:\n%s", output)
	}
}

func TestControllerMetricsExportsLatestSuccess(t *testing.T) {
	metrics := newControllerMetrics()
	metrics.observe(controllerMetricsSnapshot{
		State: control.DesiredState{
			VPCs:         []model.VPC{{Name: "prod"}},
			Subnets:      []model.Subnet{{Name: "apps", VPC: "prod"}},
			Endpoints:    []model.Endpoint{{ID: "pod-a", VPC: "prod", Subnet: "apps", IP: netip.MustParseAddr("10.10.0.10")}},
			PolicyRoutes: []model.PolicyRoute{{Name: "via-fw", VPC: "prod"}},
			LoadBalancers: []model.LoadBalancer{{
				Name: "web",
				VPC:  "prod",
				VIP:  netip.MustParseAddr("10.96.0.10"),
			}},
		},
		PolicyEntries:                 2,
		HealthSummary:                 control.LoadBalancerHealthSummary{Checked: 2, Healthy: 1, Unhealthy: 1},
		OVNHealthStatus:               "ok",
		OVNHealthLatency:              25 * time.Millisecond,
		OVNHealthConsecutiveSuccesses: 1,
		OVNCluster: ovnClusterHealthSnapshot{
			ActiveEndpoint:      "tcp:10.0.0.2:6641",
			LeaderEndpoint:      "tcp:10.0.0.2:6641",
			LeaderProbeStatus:   "ok",
			ConfiguredEndpoints: 3,
			Failovers:           1,
			LeaderPreferred:     true,
		},
		OVNOps:      7,
		OVNExecuted: 6,
		OVNCleanup: ovn.CleanupStats{
			Operations:           3,
			StaleEndpoints:       1,
			ChangedRoutes:        1,
			ChangedPolicyRoutes:  1,
			ChangedLoadBalancers: 1,
		},
		OVNAuditStatus: "ok",
		OVNAudit: ovn.AuditStats{
			ManagedLogicalSwitches:           1,
			ManagedLogicalRouters:            1,
			ManagedLogicalSwitchPorts:        2,
			ManagedLogicalRouterPorts:        1,
			ManagedLogicalRouterPolicies:     1,
			ManagedLogicalRouterStaticRoutes: 1,
			ManagedNATRules:                  1,
			ManagedLoadBalancers:             1,
			ManagedLoadBalancerHealthChecks:  1,
			ManagedDHCPOptions:               1,
			DuplicateManagedRows:             1,
			IncompleteManagedRows:            2,
			MissingManagedRows:               3,
			UnexpectedManagedRows:            4,
			DriftedManagedRows:               5,
			DriftedManagedFields:             6,
		},
		OVNMaintenance: ovnMaintenanceResult{
			Status:    "ok",
			Attempted: 2,
			Succeeded: 2,
			Latency:   15 * time.Millisecond,
		},
		Duration: 125 * time.Millisecond,
		Success:  true,
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metrics.handleMetrics(recorder, request)

	output := recorder.Body.String()
	for _, expected := range []string{
		"netloom_controller_reconcile_ready 1",
		`netloom_controller_reconcile_success{ovn_health="ok"} 1`,
		`netloom_controller_reconcile_duration_milliseconds{ovn_health="ok"} 125`,
		"netloom_controller_desired_vpcs 1",
		"netloom_controller_desired_subnets 1",
		"netloom_controller_desired_endpoints 1",
		"netloom_controller_desired_policy_routes 1",
		"netloom_controller_desired_load_balancers 1",
		"netloom_controller_policy_entries 2",
		"netloom_controller_lb_health_checked 2",
		"netloom_controller_lb_health_healthy 1",
		"netloom_controller_lb_health_unhealthy 1",
		`netloom_controller_ovn_health_latency_milliseconds{ovn_health="ok"} 25`,
		`netloom_controller_ovn_health_consecutive_failures{ovn_health="ok"} 0`,
		`netloom_controller_ovn_health_consecutive_successes{ovn_health="ok"} 1`,
		`netloom_controller_ovn_health_recovering{ovn_health="ok"} 0`,
		`netloom_controller_ovn_cluster_active_endpoint{endpoint="tcp:10.0.0.2:6641",ovn_health="ok"} 1`,
		`netloom_controller_ovn_cluster_leader_endpoint{endpoint="tcp:10.0.0.2:6641",ovn_health="ok"} 1`,
		`netloom_controller_ovn_cluster_leader_probe_status{ovn_health="ok",status="ok"} 1`,
		`netloom_controller_ovn_cluster_leader_preferred{ovn_health="ok"} 1`,
		`netloom_controller_ovn_cluster_endpoints{ovn_health="ok"} 3`,
		`netloom_controller_ovn_cluster_failovers{ovn_health="ok"} 1`,
		`netloom_controller_ovn_operations_planned{ovn_health="ok"} 7`,
		`netloom_controller_ovn_operations_executed{ovn_health="ok"} 6`,
		`netloom_controller_ovn_maintenance_attempted{ovn_health="ok",ovn_maintenance="ok"} 2`,
		`netloom_controller_ovn_maintenance_succeeded{ovn_health="ok",ovn_maintenance="ok"} 2`,
		`netloom_controller_ovn_maintenance_failed{ovn_health="ok",ovn_maintenance="ok"} 0`,
		`netloom_controller_ovn_maintenance_latency_milliseconds{ovn_health="ok",ovn_maintenance="ok"} 15`,
		`netloom_controller_ovn_maintenance_runs_total{ovn_health="ok",ovn_maintenance="ok"} 1`,
		`netloom_controller_ovn_cleanup_operations{ovn_health="ok"} 3`,
		`netloom_controller_ovn_cleanup_stale_objects{ovn_health="ok"} 1`,
		`netloom_controller_ovn_cleanup_changed_objects{ovn_health="ok"} 3`,
		`netloom_controller_ovn_cleanup_stale_endpoints{ovn_health="ok"} 1`,
		`netloom_controller_ovn_cleanup_changed_routes{ovn_health="ok"} 1`,
		`netloom_controller_ovn_cleanup_changed_policy_routes{ovn_health="ok"} 1`,
		`netloom_controller_ovn_cleanup_changed_load_balancers{ovn_health="ok"} 1`,
		`netloom_controller_ovn_live_managed_objects{ovn_audit="ok",ovn_health="ok"} 11`,
		`netloom_controller_ovn_live_logical_switches{ovn_audit="ok",ovn_health="ok"} 1`,
		`netloom_controller_ovn_live_logical_switch_ports{ovn_audit="ok",ovn_health="ok"} 2`,
		`netloom_controller_ovn_live_logical_router_policies{ovn_audit="ok",ovn_health="ok"} 1`,
		`netloom_controller_ovn_live_logical_router_static_routes{ovn_audit="ok",ovn_health="ok"} 1`,
		`netloom_controller_ovn_live_nat_rules{ovn_audit="ok",ovn_health="ok"} 1`,
		`netloom_controller_ovn_live_load_balancer_health_checks{ovn_audit="ok",ovn_health="ok"} 1`,
		`netloom_controller_ovn_live_duplicate_managed_rows{ovn_audit="ok",ovn_health="ok"} 1`,
		`netloom_controller_ovn_live_incomplete_managed_rows{ovn_audit="ok",ovn_health="ok"} 2`,
		`netloom_controller_ovn_live_missing_managed_rows{ovn_audit="ok",ovn_health="ok"} 3`,
		`netloom_controller_ovn_live_unexpected_managed_rows{ovn_audit="ok",ovn_health="ok"} 4`,
		`netloom_controller_ovn_live_drifted_managed_rows{ovn_audit="ok",ovn_health="ok"} 5`,
		`netloom_controller_ovn_live_drifted_managed_fields{ovn_audit="ok",ovn_health="ok"} 6`,
		`netloom_controller_ovn_audit_checks_total{ovn_audit="ok",ovn_health="ok"} 1`,
		`netloom_controller_ovn_audit_failures_total{ovn_audit="ok",ovn_health="ok"} 0`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("metrics output missing %q:\n%s", expected, output)
		}
	}
}

func TestControllerMetricsReportsOVNAuditErrorWithoutFailingReconcile(t *testing.T) {
	metrics := newControllerMetrics()
	metrics.observe(controllerMetricsSnapshot{
		OVNHealthStatus: "ok",
		OVNAuditStatus:  "error",
		OVNAuditError:   "audit managed NAT: database is busy",
		Duration:        25 * time.Millisecond,
		Success:         true,
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metrics.handleMetrics(recorder, request)

	output := recorder.Body.String()
	for _, expected := range []string{
		`netloom_controller_reconcile_success{ovn_health="ok"} 1`,
		`netloom_controller_ovn_live_managed_objects{ovn_audit="error",ovn_health="ok"} 0`,
		`netloom_controller_ovn_audit_checks_total{ovn_audit="error",ovn_health="ok"} 1`,
		`netloom_controller_ovn_audit_failures_total{ovn_audit="error",ovn_health="ok"} 1`,
		`netloom_controller_ovn_audit_error{error="audit managed NAT: database is busy",ovn_health="ok"} 1`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("metrics output missing %q:\n%s", expected, output)
		}
	}
}

func TestAuditOVNUsesManagedReaderWhenConfigured(t *testing.T) {
	reconciler := &stateFileReconciler{
		auditReader: fakeControllerManagedOVNReader{rows: map[string][]ovn.ManagedOVNRow{
			"Logical_Switch": {
				{
					Table: "Logical_Switch",
					UUID:  "ls-a",
					ExternalIDs: map[string]string{
						"netloom_owner":  "netloom",
						"netloom_vpc":    "prod",
						"netloom_subnet": "apps",
					},
				},
				{
					Table: "Logical_Switch",
					UUID:  "ls-stale",
					ExternalIDs: map[string]string{
						"netloom_owner":  "netloom",
						"netloom_vpc":    "prod",
						"netloom_subnet": "old",
					},
				},
			},
		}},
	}

	stats, status, message := reconciler.auditOVN(context.Background(), topology.State{
		VPCs: map[string]model.VPC{"prod": {Name: "prod"}},
		Subnets: map[string]model.Subnet{
			"prod/apps": {Name: "apps", VPC: "prod"},
		},
	})
	if status != "ok" || message != "" {
		t.Fatalf("audit status/message = %q/%q, want ok", status, message)
	}
	if stats.ManagedLogicalSwitches != 2 || stats.UnexpectedManagedRows != 1 || stats.MissingManagedRows != 3 {
		t.Fatalf("audit stats = %+v, want live row drift from managed reader", stats)
	}
}

func TestNewOVNAuditReaderRejectsInvalidBackend(t *testing.T) {
	t.Setenv("NETLOOM_OVN_AUDIT_BACKEND", "shell")
	_, _, err := newOVNAuditReaderFromEnv()
	if err == nil {
		t.Fatal("expected invalid audit backend to fail")
	}
}

func TestNewOVNAuditReaderRequiresEndpointForLibOVSDB(t *testing.T) {
	t.Setenv("NETLOOM_OVN_AUDIT_BACKEND", "libovsdb")
	t.Setenv("NETLOOM_OVN_LIBOVSDB_ENDPOINT", "")
	t.Setenv("NETLOOM_OVN_NBCTL_DB", "")
	_, _, err := newOVNAuditReaderFromEnv()
	if err == nil {
		t.Fatal("expected libovsdb audit backend without endpoint to fail")
	}
}

func TestNewOVNTopologyRuntimeRejectsInvalidBackend(t *testing.T) {
	t.Setenv("NETLOOM_OVN_TOPOLOGY_BACKEND", "shell")
	_, err := newOVNTopologyRuntimeFromEnv()
	if err == nil {
		t.Fatal("expected invalid topology backend to fail")
	}
}

func TestOVNTopologyBackendDefaultsToLibOVSDBWhenEndpointConfigured(t *testing.T) {
	t.Setenv("NETLOOM_OVN_TOPOLOGY_BACKEND", "")
	t.Setenv("NETLOOM_OVN_LIBOVSDB_ENDPOINT", "unix:/run/ovn/ovnnb_db.sock")
	t.Setenv("NETLOOM_OVN_NBCTL_DB", "")
	if got := ovnTopologyBackendFromEnv(); got != "libovsdb" {
		t.Fatalf("topology backend = %q, want libovsdb", got)
	}
}

func TestOVNTopologyBackendDefaultsToRecorderWithoutEndpoint(t *testing.T) {
	t.Setenv("NETLOOM_OVN_TOPOLOGY_BACKEND", "")
	t.Setenv("NETLOOM_OVN_LIBOVSDB_ENDPOINT", "")
	t.Setenv("NETLOOM_OVN_NBCTL_DB", "")
	if got := ovnTopologyBackendFromEnv(); got != "nbctl" {
		t.Fatalf("topology backend = %q, want nbctl recorder", got)
	}
}

func TestOVNTopologyBackendAllowsExplicitNBCTL(t *testing.T) {
	t.Setenv("NETLOOM_OVN_TOPOLOGY_BACKEND", "nbctl")
	t.Setenv("NETLOOM_OVN_LIBOVSDB_ENDPOINT", "unix:/run/ovn/ovnnb_db.sock")
	if got := ovnTopologyBackendFromEnv(); got != "nbctl" {
		t.Fatalf("topology backend = %q, want explicit nbctl", got)
	}
}

func TestNewOVNTopologyRuntimeRequiresEndpointForLibOVSDB(t *testing.T) {
	t.Setenv("NETLOOM_OVN_TOPOLOGY_BACKEND", "libovsdb")
	t.Setenv("NETLOOM_OVN_LIBOVSDB_ENDPOINT", "")
	t.Setenv("NETLOOM_OVN_NBCTL_DB", "")
	_, err := newOVNTopologyRuntimeFromEnv()
	if err == nil {
		t.Fatal("expected libovsdb topology backend without endpoint to fail")
	}
}

func TestOVNAuditBackendDefaultsToLibOVSDBWhenEndpointConfigured(t *testing.T) {
	t.Setenv("NETLOOM_OVN_AUDIT_BACKEND", "")
	t.Setenv("NETLOOM_OVN_LIBOVSDB_ENDPOINT", "unix:/run/ovn/ovnnb_db.sock")
	t.Setenv("NETLOOM_OVN_NBCTL_DB", "")
	if got := ovnAuditBackendFromEnv(); got != "libovsdb" {
		t.Fatalf("audit backend = %q, want libovsdb", got)
	}
}

func TestOVNAuditBackendAllowsExplicitNBCTL(t *testing.T) {
	t.Setenv("NETLOOM_OVN_AUDIT_BACKEND", "nbctl")
	t.Setenv("NETLOOM_OVN_LIBOVSDB_ENDPOINT", "unix:/run/ovn/ovnnb_db.sock")
	if got := ovnAuditBackendFromEnv(); got != "nbctl" {
		t.Fatalf("audit backend = %q, want explicit nbctl", got)
	}
}

func TestStateFileReconcilerSupportsTopologyBackendWithoutOVNPlanner(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(statePath, []byte(`{"vpcs":[{"name":"prod"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	memory := control.NewMemoryBackend()
	reconciler := &stateFileReconciler{
		memory:        memory,
		healthTracker: control.NewLoadBalancerHealthTracker(),
		controller:    control.NewController(memory, memory),
		metrics:       newControllerMetrics(),
	}

	if err := reconciler.reconcile(context.Background(), statePath); err != nil {
		t.Fatalf("reconcile with non-planner topology backend failed: %v", err)
	}
	snapshot, _, ready := reconciler.metrics.snapshotValue()
	if !ready {
		t.Fatal("expected metrics after reconcile")
	}
	if snapshot.OVNOps != 0 || snapshot.OVNExecuted != 0 {
		t.Fatalf("ovn operation metrics = %d/%d, want 0/0", snapshot.OVNOps, snapshot.OVNExecuted)
	}
}

func TestControllerMetricsExportsLatestFailure(t *testing.T) {
	metrics := newControllerMetrics()
	metrics.observe(controllerMetricsSnapshot{
		OVNHealthStatus:              "error",
		OVNHealthLatency:             30 * time.Millisecond,
		OVNHealthConsecutiveFailures: 1,
		Duration:                     40 * time.Millisecond,
		Success:                      false,
		Phase:                        "ovn_health",
		Error:                        "ovn health check: failed",
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metrics.handleMetrics(recorder, request)

	output := recorder.Body.String()
	for _, expected := range []string{
		`netloom_controller_reconcile_success{ovn_health="error"} 0`,
		`netloom_controller_reconcile_duration_milliseconds{ovn_health="error"} 40`,
		`netloom_controller_reconcile_failure{error="ovn health check: failed",phase="ovn_health"} 1`,
		`netloom_controller_ovn_health_latency_milliseconds{ovn_health="error"} 30`,
		`netloom_controller_ovn_health_consecutive_failures{ovn_health="error"} 1`,
		`netloom_controller_ovn_health_consecutive_successes{ovn_health="error"} 0`,
		`netloom_controller_ovn_health_recovering{ovn_health="error"} 0`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("failure metrics output missing %q:\n%s", expected, output)
		}
	}
}

func TestStateFileReconcilerTracksOVNHealthRecovery(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(statePath, []byte(`{"vpcs":[{"name":"prod"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	checker := &sequenceHealthChecker{
		results: []healthCheckResult{
			{latency: 10 * time.Millisecond, err: errors.New("database unavailable")},
			{latency: 15 * time.Millisecond},
			{latency: 20 * time.Millisecond},
		},
	}
	reconciler := &stateFileReconciler{
		memory:        control.NewMemoryBackend(),
		executor:      ovn.NewRecorderExecutor(),
		ovnBackend:    ovn.NewBackend(ovn.NewRecorderExecutor()),
		healthTracker: control.NewLoadBalancerHealthTracker(),
		healthChecker: checker,
		metrics:       newControllerMetrics(),
	}
	reconciler.controller = control.NewController(control.MultiTopologyBackend{reconciler.memory, reconciler.ovnBackend}, reconciler.memory)

	if err := reconciler.reconcile(context.Background(), statePath); err == nil {
		t.Fatal("expected first reconcile to fail health check")
	}
	snapshot, _, ready := reconciler.metrics.snapshotValue()
	if !ready {
		t.Fatal("expected metrics after failed reconcile")
	}
	if snapshot.OVNHealthStatus != "error" || snapshot.OVNHealthConsecutiveFailures != 1 || snapshot.OVNHealthRecovering {
		t.Fatalf("first health snapshot = %+v, want one failure", snapshot)
	}

	if err := reconciler.reconcile(context.Background(), statePath); err != nil {
		t.Fatalf("second reconcile should recover: %v", err)
	}
	snapshot, _, _ = reconciler.metrics.snapshotValue()
	if snapshot.OVNHealthStatus != "recovering" || !snapshot.OVNHealthRecovering || snapshot.OVNHealthConsecutiveSuccesses != 1 {
		t.Fatalf("second health snapshot = %+v, want recovering first success", snapshot)
	}

	if err := reconciler.reconcile(context.Background(), statePath); err != nil {
		t.Fatalf("third reconcile should stay healthy: %v", err)
	}
	snapshot, _, _ = reconciler.metrics.snapshotValue()
	if snapshot.OVNHealthStatus != "ok" || snapshot.OVNHealthRecovering || snapshot.OVNHealthConsecutiveSuccesses != 2 {
		t.Fatalf("third health snapshot = %+v, want stable ok", snapshot)
	}
}

func TestControllerMetricsAccumulatesReconcileCountersAndBuckets(t *testing.T) {
	metrics := newControllerMetrics()
	metrics.observe(controllerMetricsSnapshot{
		OVNHealthStatus:  "ok",
		OVNHealthLatency: 20 * time.Millisecond,
		OVNOps:           5,
		OVNExecuted:      4,
		OVNCleanup:       ovn.CleanupStats{Operations: 2, StaleEndpoints: 1, ChangedRoutes: 1},
		HealthSummary:    control.LoadBalancerHealthSummary{Checked: 2, Healthy: 1, Unhealthy: 1},
		Duration:         250 * time.Millisecond,
		Success:          true,
	})
	metrics.observe(controllerMetricsSnapshot{
		OVNHealthStatus:  "error",
		OVNHealthLatency: 30 * time.Millisecond,
		OVNOps:           3,
		OVNExecuted:      1,
		OVNCleanup:       ovn.CleanupStats{Operations: 1, StaleNATRules: 1},
		Duration:         750 * time.Millisecond,
		Success:          false,
		Phase:            "ovn_health",
		Error:            "ovn health check: failed",
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metrics.handleMetrics(recorder, request)

	output := recorder.Body.String()
	for _, expected := range []string{
		`netloom_controller_reconcile_attempts_total{ovn_health="error"} 2`,
		`netloom_controller_reconcile_success_total{ovn_health="error"} 1`,
		`netloom_controller_reconcile_failure_total{ovn_health="error"} 1`,
		`netloom_controller_reconcile_failures_by_phase_total{phase="ovn_health"} 1`,
		`netloom_controller_reconcile_duration_milliseconds_histogram_bucket{le="250",ovn_health="error"} 1`,
		`netloom_controller_reconcile_duration_milliseconds_histogram_bucket{le="1000",ovn_health="error"} 2`,
		`netloom_controller_reconcile_duration_milliseconds_histogram_bucket{le="+Inf",ovn_health="error"} 2`,
		`netloom_controller_reconcile_duration_milliseconds_histogram_sum{ovn_health="error"} 1000`,
		`netloom_controller_reconcile_duration_milliseconds_histogram_count{ovn_health="error"} 2`,
		`netloom_controller_ovn_operations_planned_total{ovn_health="error"} 8`,
		`netloom_controller_ovn_operations_executed_total{ovn_health="error"} 5`,
		`netloom_controller_lb_health_checked_total{ovn_health="error"} 2`,
		`netloom_controller_lb_health_healthy_total{ovn_health="error"} 1`,
		`netloom_controller_lb_health_unhealthy_total{ovn_health="error"} 1`,
		`netloom_controller_ovn_health_checks_total{ovn_health="error"} 2`,
		`netloom_controller_ovn_health_failures_total{ovn_health="error"} 1`,
		`netloom_controller_ovn_health_latency_milliseconds_total{ovn_health="error"} 50`,
		`netloom_controller_ovn_cleanup_operations_total{ovn_health="error"} 3`,
		`netloom_controller_ovn_cleanup_stale_objects_total{ovn_health="error"} 2`,
		`netloom_controller_ovn_cleanup_changed_objects_total{ovn_health="error"} 1`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("cumulative metrics output missing %q:\n%s", expected, output)
		}
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = original
	}()

	fn()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := io.Copy(&output, reader); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

type healthCheckResult struct {
	latency time.Duration
	err     error
}

type sequenceHealthChecker struct {
	results []healthCheckResult
	next    int
}

func (c *sequenceHealthChecker) HealthCheck(context.Context) (time.Duration, error) {
	if c.next >= len(c.results) {
		return 0, nil
	}
	result := c.results[c.next]
	c.next++
	return result.latency, result.err
}

type fakeControllerManagedOVNReader struct {
	rows map[string][]ovn.ManagedOVNRow
}

func (r fakeControllerManagedOVNReader) ManagedOVNRows(_ context.Context, table string) ([]ovn.ManagedOVNRow, error) {
	return append([]ovn.ManagedOVNRow(nil), r.rows[table]...), nil
}
