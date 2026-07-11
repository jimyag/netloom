package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerControllerActiveLBHealthProbeConvergesOVNBackends(t *testing.T) {
	requireDockerE2E(t)

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	startComposeLab(t, ctx, composeFile)
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), time.Minute)
		defer downCancel()
		run(t, downCtx, "docker", "compose", "-f", composeFile, "down", "-v")
	})
	waitForOVN(t, ctx, composeFile)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "command -v ncat >/dev/null 2>&1")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "pid=$(cat /tmp/netloom-lb-probe-a.pid 2>/dev/null || true); [ -n \"$pid\" ] && kill \"$pid\" >/dev/null 2>&1 || true; nohup sh -c 'exec ncat -k -l 127.0.0.1 18080 >/dev/null 2>&1' >/tmp/netloom-lb-probe-a.log 2>&1 </dev/null & echo $! >/tmp/netloom-lb-probe-a.pid; sleep 1; kill -0 $(cat /tmp/netloom-lb-probe-a.pid)")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		runAllowFailure(t, cleanupCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "pid=$(cat /tmp/netloom-lb-probe-a.pid 2>/dev/null || true); [ -n \"$pid\" ] && kill \"$pid\" >/dev/null 2>&1 || true; rm -f /tmp/netloom-lb-probe-a.pid")
		runAllowFailure(t, cleanupCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "pid=$(cat /tmp/netloom-lb-probe-b.pid 2>/dev/null || true); [ -n \"$pid\" ] && kill \"$pid\" >/dev/null 2>&1 || true; rm -f /tmp/netloom-lb-probe-b.pid")
	})
	runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "pid=$(cat /tmp/netloom-lb-probe-b.pid 2>/dev/null || true); [ -n \"$pid\" ] && kill \"$pid\" >/dev/null 2>&1 || true; rm -f /tmp/netloom-lb-probe-b.pid")

	statePath := "/tmp/netloom-lb-health-probe-state.json"
	applyState := func() string {
		return run(
			t,
			ctx,
			"docker",
			"compose",
			"-f",
			composeFile,
			"exec",
			"-T",
			"ovn-central",
			"sh",
			"-c",
			"cat >"+statePath+" <<'EOF'\n"+desiredStateLBHealthProbeJSON()+"\nEOF\nNETLOOM_STATE_FILE="+statePath+" NETLOOM_LB_HEALTH_PROBE=1 NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller",
		)
	}

	firstOutput := applyState()
	for _, expected := range []string{"reconciled desired state", "lb_health_checked=2", "lb_health_healthy=1", "lb_health_unhealthy=1"} {
		if !strings.Contains(firstOutput, expected) {
			t.Fatalf("first active health-probe reconcile missing %q:\n%s", expected, firstOutput)
		}
	}

	lb := findLoadBalancerForVIP(t, ctx, composeFile, "probe", "probe-web", "10.96.0.55:80")
	if lb == "" {
		t.Fatal("expected load balancer row for probe-web VIP 10.96.0.55:80")
	}
	lbState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lb-list", lb)
	if !strings.Contains(lbState, "127.0.0.1:18080") || strings.Contains(lbState, "127.0.0.2:18080") {
		t.Fatalf("OVN VIPs after first health probe = %s, want only first loopback backend", lbState)
	}
	if got := activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=probe", "external_ids:netloom_load_balancer=probe-web"); len(got) != 1 {
		t.Fatalf("expected one managed LB health-check row for probe-web, got %v", got)
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "pid=$(cat /tmp/netloom-lb-probe-b.pid 2>/dev/null || true); [ -n \"$pid\" ] && kill \"$pid\" >/dev/null 2>&1 || true; nohup sh -c 'exec ncat -k -l 127.0.0.2 18080 >/dev/null 2>&1' >/tmp/netloom-lb-probe-b.log 2>&1 </dev/null & echo $! >/tmp/netloom-lb-probe-b.pid; sleep 1; kill -0 $(cat /tmp/netloom-lb-probe-b.pid)")

	secondOutput := applyState()
	for _, expected := range []string{"reconciled desired state", "lb_health_checked=2", "lb_health_healthy=2", "lb_health_unhealthy=0"} {
		if !strings.Contains(secondOutput, expected) {
			t.Fatalf("second active health-probe reconcile missing %q:\n%s", expected, secondOutput)
		}
	}

	lbState = run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lb-list", lb)
	if !strings.Contains(lbState, "127.0.0.1:18080") || !strings.Contains(lbState, "127.0.0.2:18080") {
		t.Fatalf("OVN VIPs after backend recovery = %s, want both backends restored", lbState)
	}
}

func desiredStateLBHealthProbeJSON() string {
	return `{
  "vpcs": [{"name": "probe"}],
  "subnets": [{"name": "apps", "vpc": "probe", "cidr": "127.0.0.0/24", "gateway": "127.0.0.1"}],
  "load_balancers": [{
    "name": "probe-web",
    "vpc": "probe",
    "vip": "10.96.0.55",
    "ports": [{
      "name": "http",
      "port": 80,
      "protocol": "tcp",
      "backends": [
        {"ip": "127.0.0.1", "port": 18080},
        {"ip": "127.0.0.2", "port": 18080}
      ]
    }],
    "subnets": ["apps"],
    "health_check": {"enabled": true, "interval": 5, "timeout": 1, "success_count": 1, "failure_count": 1}
  }]
}`
}
