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
		if !lb.HealthCheck.Enabled || normalizedLoadBalancerProtocol(lb.Protocol) != model.ProtocolTCP {
			continue
		}
		lb.Backends = append([]model.LoadBalancerBackend(nil), lb.Backends...)
		healthyBackends := 0
		for j, backend := range lb.Backends {
			if backend.Healthy != nil && !*backend.Healthy {
				summary.Unhealthy++
				continue
			}
			ok := probe(ctx, backend, loadBalancerHealthProbeTimeout(lb.HealthCheck)) == nil
			lb.Backends[j].Healthy = boolPtr(ok)
			summary.Checked++
			if ok {
				summary.Healthy++
				healthyBackends++
			} else {
				summary.Unhealthy++
			}
		}
		if healthyBackends == 0 {
			return DesiredState{}, summary, fmt.Errorf("load balancer %q has no healthy probed backends", lb.Name)
		}
		next.LoadBalancers[i] = lb
	}
	return next, summary, nil
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
