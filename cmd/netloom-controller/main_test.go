package main

import (
	"context"
	"net/netip"
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
