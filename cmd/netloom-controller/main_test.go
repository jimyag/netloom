package main

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/model"
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
