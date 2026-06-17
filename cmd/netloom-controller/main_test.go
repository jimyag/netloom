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

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn"
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
	output := captureStdout(t, func() {
		printControllerReconcileFailure("ovn_health", state, summary, "error", 25*time.Millisecond, 3, 2, errors.New("boom"), 125*time.Millisecond)
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
		PolicyEntries:    2,
		HealthSummary:    control.LoadBalancerHealthSummary{Checked: 2, Healthy: 1, Unhealthy: 1},
		OVNHealthStatus:  "ok",
		OVNHealthLatency: 25 * time.Millisecond,
		OVNOps:           7,
		OVNExecuted:      6,
		OVNCleanup: ovn.CleanupStats{
			Operations:           3,
			StaleEndpoints:       1,
			ChangedRoutes:        1,
			ChangedPolicyRoutes:  1,
			ChangedLoadBalancers: 1,
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
		`netloom_controller_ovn_operations_planned{ovn_health="ok"} 7`,
		`netloom_controller_ovn_operations_executed{ovn_health="ok"} 6`,
		`netloom_controller_ovn_cleanup_operations{ovn_health="ok"} 3`,
		`netloom_controller_ovn_cleanup_stale_objects{ovn_health="ok"} 1`,
		`netloom_controller_ovn_cleanup_changed_objects{ovn_health="ok"} 3`,
		`netloom_controller_ovn_cleanup_stale_endpoints{ovn_health="ok"} 1`,
		`netloom_controller_ovn_cleanup_changed_routes{ovn_health="ok"} 1`,
		`netloom_controller_ovn_cleanup_changed_policy_routes{ovn_health="ok"} 1`,
		`netloom_controller_ovn_cleanup_changed_load_balancers{ovn_health="ok"} 1`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("metrics output missing %q:\n%s", expected, output)
		}
	}
}

func TestControllerMetricsExportsLatestFailure(t *testing.T) {
	metrics := newControllerMetrics()
	metrics.observe(controllerMetricsSnapshot{
		OVNHealthStatus:  "error",
		OVNHealthLatency: 30 * time.Millisecond,
		Duration:         40 * time.Millisecond,
		Success:          false,
		Phase:            "ovn_health",
		Error:            "ovn health check: failed",
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
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("failure metrics output missing %q:\n%s", expected, output)
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
