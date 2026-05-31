package control

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/jimyag/netloom/internal/model"
)

type LoadBalancerHealthSummary struct {
	Checked   int
	Healthy   int
	Unhealthy int
}

type LoadBalancerBackendProbe func(context.Context, model.LoadBalancerBackend, time.Duration) error

type LoadBalancerHealthTracker struct {
	backends map[string]trackedLoadBalancerBackendHealth
}

type trackedLoadBalancerBackendHealth struct {
	Healthy   bool
	Successes uint32
	Failures  uint32
}

func NewLoadBalancerHealthTracker() *LoadBalancerHealthTracker {
	return &LoadBalancerHealthTracker{backends: make(map[string]trackedLoadBalancerBackendHealth)}
}

func ApplyLoadBalancerHealthChecks(ctx context.Context, state DesiredState, probe LoadBalancerBackendProbe) (DesiredState, LoadBalancerHealthSummary, error) {
	return ApplyLoadBalancerHealthChecksWithTracker(ctx, state, probe, nil)
}

func ApplyLoadBalancerHealthChecksWithTracker(ctx context.Context, state DesiredState, probe LoadBalancerBackendProbe, tracker *LoadBalancerHealthTracker) (DesiredState, LoadBalancerHealthSummary, error) {
	if probe == nil {
		probe = TCPBackendProbe
	}
	next := state
	next.LoadBalancers = append([]model.LoadBalancer(nil), state.LoadBalancers...)
	var summary LoadBalancerHealthSummary
	var desiredHealthKeys map[string]struct{}
	if tracker != nil {
		desiredHealthKeys = make(map[string]struct{})
	}
	for i, lb := range next.LoadBalancers {
		if !lb.HealthCheck.Enabled {
			continue
		}
		lb.Ports = append([]model.LoadBalancerPort(nil), lb.Ports...)
		for j, port := range lb.Ports {
			if normalizedLoadBalancerProtocol(port.Protocol) != model.ProtocolTCP {
				continue
			}
			backends, healthyBackends := probeLoadBalancerBackends(ctx, lb, port, probe, tracker, desiredHealthKeys, &summary)
			if healthyBackends == 0 {
				return DesiredState{}, summary, fmt.Errorf("load balancer %q port %d has no healthy probed backends", lb.Name, port.Port)
			}
			lb.Ports[j].Backends = backends
		}
		next.LoadBalancers[i] = lb
	}
	if tracker != nil {
		tracker.prune(desiredHealthKeys)
	}
	return next, summary, nil
}

func probeLoadBalancerBackends(ctx context.Context, lb model.LoadBalancer, port model.LoadBalancerPort, probe LoadBalancerBackendProbe, tracker *LoadBalancerHealthTracker, desiredHealthKeys map[string]struct{}, summary *LoadBalancerHealthSummary) ([]model.LoadBalancerBackend, int) {
	healthCheck := lb.HealthCheck
	next := append([]model.LoadBalancerBackend(nil), port.Backends...)
	healthyBackends := 0
	for j, backend := range next {
		key := loadBalancerBackendHealthKey(lb, port, backend)
		if backend.Healthy != nil && !*backend.Healthy {
			if tracker != nil {
				tracker.delete(key)
			}
			summary.Unhealthy++
			continue
		}
		if desiredHealthKeys != nil {
			desiredHealthKeys[key] = struct{}{}
		}
		ok := probe(ctx, backend, loadBalancerHealthProbeTimeout(healthCheck)) == nil
		next[j].Healthy = boolPtr(ok)
		if tracker != nil {
			next[j].Healthy = boolPtr(tracker.update(key, backend, healthCheck, ok))
		}
		summary.Checked++
		if ok {
			summary.Healthy++
		} else {
			summary.Unhealthy++
		}
		if next[j].IsHealthy() {
			healthyBackends++
		}
	}
	return next, healthyBackends
}

func loadBalancerBackendHealthKey(lb model.LoadBalancer, port model.LoadBalancerPort, backend model.LoadBalancerBackend) string {
	return lb.VPC + "/" + lb.Name + "/" + string(normalizedLoadBalancerProtocol(port.Protocol)) + "/" + strconv.Itoa(int(port.Port)) + "/" + net.JoinHostPort(backend.IP.String(), strconv.Itoa(int(backend.Port)))
}

func (t *LoadBalancerHealthTracker) update(key string, backend model.LoadBalancerBackend, healthCheck model.LoadBalancerHealthCheck, probeHealthy bool) bool {
	if t.backends == nil {
		t.backends = make(map[string]trackedLoadBalancerBackendHealth)
	}
	current, ok := t.backends[key]
	if !ok {
		current.Healthy = backend.IsHealthy()
	}
	if probeHealthy {
		current.Successes++
		current.Failures = 0
		if current.Healthy || current.Successes >= loadBalancerHealthSuccessThreshold(healthCheck) {
			current.Healthy = true
		}
	} else {
		current.Failures++
		current.Successes = 0
		if current.Failures >= loadBalancerHealthFailureThreshold(healthCheck) {
			current.Healthy = false
		}
	}
	t.backends[key] = current
	return current.Healthy
}

func (t *LoadBalancerHealthTracker) delete(key string) {
	if t == nil || t.backends == nil {
		return
	}
	delete(t.backends, key)
}

func (t *LoadBalancerHealthTracker) prune(desired map[string]struct{}) {
	if t == nil || t.backends == nil {
		return
	}
	for key := range t.backends {
		if _, ok := desired[key]; !ok {
			delete(t.backends, key)
		}
	}
}

func TCPBackendProbe(ctx context.Context, backend model.LoadBalancerBackend, timeout time.Duration) error {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(backend.IP.String(), strconv.Itoa(int(backend.Port))))
	if err != nil {
		return err
	}
	return conn.Close()
}

func loadBalancerHealthProbeTimeout(healthCheck model.LoadBalancerHealthCheck) time.Duration {
	if healthCheck.Timeout == 0 {
		return 20 * time.Second
	}
	return time.Duration(healthCheck.Timeout) * time.Second
}

func loadBalancerHealthSuccessThreshold(healthCheck model.LoadBalancerHealthCheck) uint32 {
	if healthCheck.SuccessCount == 0 {
		return 3
	}
	return healthCheck.SuccessCount
}

func loadBalancerHealthFailureThreshold(healthCheck model.LoadBalancerHealthCheck) uint32 {
	if healthCheck.FailureCount == 0 {
		return 3
	}
	return healthCheck.FailureCount
}

func normalizedLoadBalancerProtocol(protocol model.Protocol) model.Protocol {
	if protocol == "" {
		return model.ProtocolTCP
	}
	return protocol
}

func boolPtr(v bool) *bool {
	return &v
}
