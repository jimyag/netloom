package control

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jimyag/netloom/internal/model"
)

func TestApplyLoadBalancerHealthChecksMarksTCPBackends(t *testing.T) {
	state := DesiredState{LoadBalancers: []model.LoadBalancer{{
		Name:        "web",
		VPC:         "prod",
		VIP:         netip.MustParseAddr("10.96.0.10"),
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true, Timeout: 7},
		Ports: []model.LoadBalancerPort{{
			Port: 80,
			Backends: []model.LoadBalancerBackend{
				{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080},
				{IP: netip.MustParseAddr("10.10.0.11"), Port: 8080},
			},
		}},
	}}}
	probed := make(map[netip.Addr]time.Duration)
	next, summary, err := ApplyLoadBalancerHealthChecks(context.Background(), state, func(_ context.Context, backend model.LoadBalancerBackend, timeout time.Duration) error {
		probed[backend.IP] = timeout
		if backend.IP == netip.MustParseAddr("10.10.0.11") {
			return errors.New("closed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Checked != 2 || summary.Healthy != 1 || summary.Unhealthy != 1 {
		t.Fatalf("summary = %+v, want checked=2 healthy=1 unhealthy=1", summary)
	}
	if probed[netip.MustParseAddr("10.10.0.10")] != 7*time.Second {
		t.Fatalf("probe timeout = %s, want 7s", probed[netip.MustParseAddr("10.10.0.10")])
	}
	if state.LoadBalancers[0].Ports[0].Backends[0].Healthy != nil {
		t.Fatal("original desired state should not be mutated")
	}
	if !next.LoadBalancers[0].Ports[0].Backends[0].IsHealthy() || next.LoadBalancers[0].Ports[0].Backends[1].IsHealthy() {
		t.Fatalf("backend health = %+v, want first healthy and second unhealthy", next.LoadBalancers[0].Ports[0].Backends)
	}
}

func TestApplyLoadBalancerHealthChecksKeepsManualDrainAndSkipsUDP(t *testing.T) {
	drained := false
	state := DesiredState{LoadBalancers: []model.LoadBalancer{
		{
			Name:        "web",
			VPC:         "prod",
			VIP:         netip.MustParseAddr("10.96.0.10"),
			HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
			Ports: []model.LoadBalancerPort{{
				Port: 80,
				Backends: []model.LoadBalancerBackend{
					{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080, Healthy: &drained},
					{IP: netip.MustParseAddr("10.10.0.11"), Port: 8080},
				},
			}},
		},
		{
			Name:        "dns",
			VPC:         "prod",
			VIP:         netip.MustParseAddr("10.96.0.53"),
			HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
			Ports: []model.LoadBalancerPort{{
				Port:     53,
				Protocol: model.ProtocolUDP,
				Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.53"), Port: 5353}},
			}},
		},
	}}
	probes := 0
	next, summary, err := ApplyLoadBalancerHealthChecks(context.Background(), state, func(context.Context, model.LoadBalancerBackend, time.Duration) error {
		probes++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if probes != 1 || summary.Checked != 1 || summary.Healthy != 1 || summary.Unhealthy != 1 {
		t.Fatalf("probes/summary = %d/%+v, want only non-drained TCP backend checked", probes, summary)
	}
	if next.LoadBalancers[0].Ports[0].Backends[0].IsHealthy() {
		t.Fatal("manual drained backend should stay unhealthy")
	}
	if next.LoadBalancers[1].Ports[0].Backends[0].Healthy != nil {
		t.Fatal("UDP load balancer should not be actively TCP-probed")
	}
}

func TestApplyLoadBalancerHealthChecksMarksMultiPortBackends(t *testing.T) {
	state := DesiredState{LoadBalancers: []model.LoadBalancer{{
		Name:        "web",
		VPC:         "prod",
		VIP:         netip.MustParseAddr("10.96.0.10"),
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
		Ports: []model.LoadBalancerPort{
			{
				Name:     "http",
				Port:     80,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080}},
			},
			{
				Name:     "dns",
				Port:     53,
				Protocol: model.ProtocolUDP,
				Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.53"), Port: 5353}},
			},
		},
	}}}
	next, summary, err := ApplyLoadBalancerHealthChecks(context.Background(), state, func(context.Context, model.LoadBalancerBackend, time.Duration) error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Checked != 1 || summary.Healthy != 1 || summary.Unhealthy != 0 {
		t.Fatalf("summary = %+v, want only TCP frontend checked", summary)
	}
	if !next.LoadBalancers[0].Ports[0].Backends[0].IsHealthy() {
		t.Fatalf("tcp frontend backend health = %+v, want healthy", next.LoadBalancers[0].Ports[0].Backends)
	}
	if next.LoadBalancers[0].Ports[1].Backends[0].Healthy != nil {
		t.Fatal("UDP frontend should not be actively TCP-probed")
	}
}

func TestApplyLoadBalancerHealthChecksRejectsAllFailedBackends(t *testing.T) {
	state := DesiredState{LoadBalancers: []model.LoadBalancer{{
		Name:        "web",
		VPC:         "prod",
		VIP:         netip.MustParseAddr("10.96.0.10"),
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
		Ports: []model.LoadBalancerPort{{
			Port:     80,
			Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080}},
		}},
	}}}
	_, summary, err := ApplyLoadBalancerHealthChecks(context.Background(), state, func(context.Context, model.LoadBalancerBackend, time.Duration) error {
		return errors.New("refused")
	})
	if err == nil {
		t.Fatal("expected all-failed health check to fail")
	}
	if summary.Checked != 1 || summary.Healthy != 0 || summary.Unhealthy != 1 {
		t.Fatalf("summary = %+v, want one unhealthy probe", summary)
	}
}

func TestApplyLoadBalancerHealthChecksWithTrackerHonorsFailureThreshold(t *testing.T) {
	state := DesiredState{LoadBalancers: []model.LoadBalancer{{
		Name:        "web",
		VPC:         "prod",
		VIP:         netip.MustParseAddr("10.96.0.10"),
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true, FailureCount: 3},
		Ports: []model.LoadBalancerPort{{
			Port: 80,
			Backends: []model.LoadBalancerBackend{
				{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080},
				{IP: netip.MustParseAddr("10.10.0.11"), Port: 8080},
			},
		}},
	}}}
	tracker := NewLoadBalancerHealthTracker()
	probe := func(_ context.Context, backend model.LoadBalancerBackend, _ time.Duration) error {
		if backend.IP == netip.MustParseAddr("10.10.0.10") {
			return errors.New("timeout")
		}
		return nil
	}

	first, _, err := ApplyLoadBalancerHealthChecksWithTracker(context.Background(), state, probe, tracker)
	if err != nil {
		t.Fatal(err)
	}
	if !first.LoadBalancers[0].Ports[0].Backends[0].IsHealthy() {
		t.Fatalf("first failed probe should stay healthy until failure threshold: %+v", first.LoadBalancers[0].Ports[0].Backends)
	}
	second, _, err := ApplyLoadBalancerHealthChecksWithTracker(context.Background(), state, probe, tracker)
	if err != nil {
		t.Fatal(err)
	}
	if !second.LoadBalancers[0].Ports[0].Backends[0].IsHealthy() {
		t.Fatalf("second failed probe should stay healthy until failure threshold: %+v", second.LoadBalancers[0].Ports[0].Backends)
	}
	third, _, err := ApplyLoadBalancerHealthChecksWithTracker(context.Background(), state, probe, tracker)
	if err != nil {
		t.Fatal(err)
	}
	if third.LoadBalancers[0].Ports[0].Backends[0].IsHealthy() || !third.LoadBalancers[0].Ports[0].Backends[1].IsHealthy() {
		t.Fatalf("third failed probe should mark only failing backend unhealthy: %+v", third.LoadBalancers[0].Ports[0].Backends)
	}
}

func TestApplyLoadBalancerHealthChecksWithTrackerHonorsSuccessThreshold(t *testing.T) {
	state := DesiredState{LoadBalancers: []model.LoadBalancer{{
		Name:        "web",
		VPC:         "prod",
		VIP:         netip.MustParseAddr("10.96.0.10"),
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true, SuccessCount: 2, FailureCount: 1},
		Ports: []model.LoadBalancerPort{{
			Port: 80,
			Backends: []model.LoadBalancerBackend{
				{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080},
				{IP: netip.MustParseAddr("10.10.0.11"), Port: 8080},
			},
		}},
	}}}
	tracker := NewLoadBalancerHealthTracker()
	failPrimary := true
	probe := func(_ context.Context, backend model.LoadBalancerBackend, _ time.Duration) error {
		if backend.IP == netip.MustParseAddr("10.10.0.10") && failPrimary {
			return errors.New("timeout")
		}
		return nil
	}
	failed, _, err := ApplyLoadBalancerHealthChecksWithTracker(context.Background(), state, probe, tracker)
	if err != nil {
		t.Fatal(err)
	}
	if failed.LoadBalancers[0].Ports[0].Backends[0].IsHealthy() {
		t.Fatalf("failure_count=1 should mark primary unhealthy: %+v", failed.LoadBalancers[0].Ports[0].Backends)
	}

	failPrimary = false
	firstRecovery, _, err := ApplyLoadBalancerHealthChecksWithTracker(context.Background(), state, probe, tracker)
	if err != nil {
		t.Fatal(err)
	}
	if firstRecovery.LoadBalancers[0].Ports[0].Backends[0].IsHealthy() {
		t.Fatalf("first successful probe should not recover before success threshold: %+v", firstRecovery.LoadBalancers[0].Ports[0].Backends)
	}
	secondRecovery, _, err := ApplyLoadBalancerHealthChecksWithTracker(context.Background(), state, probe, tracker)
	if err != nil {
		t.Fatal(err)
	}
	if !secondRecovery.LoadBalancers[0].Ports[0].Backends[0].IsHealthy() {
		t.Fatalf("second successful probe should recover backend: %+v", secondRecovery.LoadBalancers[0].Ports[0].Backends)
	}
}

func TestApplyLoadBalancerHealthChecksWithTrackerPrunesRemovedBackends(t *testing.T) {
	state := DesiredState{LoadBalancers: []model.LoadBalancer{{
		Name:        "web",
		VPC:         "prod",
		VIP:         netip.MustParseAddr("10.96.0.10"),
		HealthCheck: model.LoadBalancerHealthCheck{Enabled: true},
		Ports: []model.LoadBalancerPort{{
			Port: 80,
			Backends: []model.LoadBalancerBackend{
				{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080},
				{IP: netip.MustParseAddr("10.10.0.11"), Port: 8080},
			},
		}},
	}}}
	tracker := NewLoadBalancerHealthTracker()
	if _, _, err := ApplyLoadBalancerHealthChecksWithTracker(context.Background(), state, func(context.Context, model.LoadBalancerBackend, time.Duration) error {
		return nil
	}, tracker); err != nil {
		t.Fatal(err)
	}
	if len(tracker.backends) != 2 {
		t.Fatalf("tracked backends = %d, want 2", len(tracker.backends))
	}

	state.LoadBalancers[0].Ports[0].Backends = state.LoadBalancers[0].Ports[0].Backends[:1]
	if _, _, err := ApplyLoadBalancerHealthChecksWithTracker(context.Background(), state, func(context.Context, model.LoadBalancerBackend, time.Duration) error {
		return nil
	}, tracker); err != nil {
		t.Fatal(err)
	}
	if len(tracker.backends) != 1 {
		t.Fatalf("tracked backends after removal = %d, want 1", len(tracker.backends))
	}
}
