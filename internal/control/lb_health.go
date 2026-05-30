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

func ApplyLoadBalancerHealthChecks(ctx context.Context, state DesiredState, probe LoadBalancerBackendProbe) (DesiredState, LoadBalancerHealthSummary, error) {
	if probe == nil {
		probe = TCPBackendProbe
	}
	next := state
	next.LoadBalancers = append([]model.LoadBalancer(nil), state.LoadBalancers...)
	var summary LoadBalancerHealthSummary
	for i, lb := range next.LoadBalancers {
		if !lb.HealthCheck.Enabled {
			continue
		}
		if len(lb.Ports) == 0 {
			if normalizedLoadBalancerProtocol(lb.Protocol) != model.ProtocolTCP {
				continue
			}
			backends, healthyBackends := probeLoadBalancerBackends(ctx, lb.Backends, lb.HealthCheck, probe, &summary)
			if healthyBackends == 0 {
				return DesiredState{}, summary, fmt.Errorf("load balancer %q has no healthy probed backends", lb.Name)
			}
			lb.Backends = backends
			next.LoadBalancers[i] = lb
			continue
		}
		lb.Ports = append([]model.LoadBalancerPort(nil), lb.Ports...)
		for j, port := range lb.Ports {
			if normalizedLoadBalancerProtocol(port.Protocol) != model.ProtocolTCP {
				continue
			}
			backends := port.Backends
			if len(backends) == 0 {
				backends = lb.Backends
			}
			backends, healthyBackends := probeLoadBalancerBackends(ctx, backends, lb.HealthCheck, probe, &summary)
			if healthyBackends == 0 {
				return DesiredState{}, summary, fmt.Errorf("load balancer %q port %d has no healthy probed backends", lb.Name, port.Port)
			}
			lb.Ports[j].Backends = backends
		}
		next.LoadBalancers[i] = lb
	}
	return next, summary, nil
}

func probeLoadBalancerBackends(ctx context.Context, backends []model.LoadBalancerBackend, healthCheck model.LoadBalancerHealthCheck, probe LoadBalancerBackendProbe, summary *LoadBalancerHealthSummary) ([]model.LoadBalancerBackend, int) {
	next := append([]model.LoadBalancerBackend(nil), backends...)
	healthyBackends := 0
	for j, backend := range next {
		if backend.Healthy != nil && !*backend.Healthy {
			summary.Unhealthy++
			continue
		}
		ok := probe(ctx, backend, loadBalancerHealthProbeTimeout(healthCheck)) == nil
		next[j].Healthy = boolPtr(ok)
		summary.Checked++
		if ok {
			summary.Healthy++
			healthyBackends++
		} else {
			summary.Unhealthy++
		}
	}
	return next, healthyBackends
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

func normalizedLoadBalancerProtocol(protocol model.Protocol) model.Protocol {
	if protocol == "" {
		return model.ProtocolTCP
	}
	return protocol
}

func boolPtr(v bool) *bool {
	return &v
}
