package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerControllerProgramsLoadBalancerSessionAffinity(t *testing.T) {
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

	statePath := "/tmp/netloom-lb-affinity-state.json"
	output := run(
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
		"cat >"+statePath+" <<'EOF'\n"+desiredStateWithSessionAffinityJSON()+"\nEOF\nNETLOOM_STATE_FILE="+statePath+" NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller",
	)
	if !strings.Contains(output, "reconciled desired state") {
		t.Fatalf("session affinity reconcile did not succeed:\n%s", output)
	}

	v4LB := findLoadBalancerForVIP(t, ctx, composeFile, "affinity", "web-v4", "10.96.0.60:80")
	if v4LB == "" {
		t.Fatal("expected IPv4 affinity load balancer row for VIP 10.96.0.60:80")
	}
	v6LB := findLoadBalancerForVIP(t, ctx, composeFile, "affinity", "web-v6", "[fd00:96::60]:80")
	if v6LB == "" {
		t.Fatal("expected IPv6 affinity load balancer row for VIP [fd00:96::60]:80")
	}

	v4Selection := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "get", "load_balancer", v4LB, "selection_fields")
	if !strings.Contains(v4Selection, `[ip_src, tp_src]`) {
		t.Fatalf("IPv4 selection_fields = %s, want [ip_src, tp_src]", v4Selection)
	}
	v4Options := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "get", "load_balancer", v4LB, "options")
	if !strings.Contains(v4Options, `affinity_timeout="7200"`) {
		t.Fatalf("IPv4 load balancer options missing affinity_timeout=7200:\n%s", v4Options)
	}
	v4ExternalIDs := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "get", "load_balancer", v4LB, "external_ids")
	if !strings.Contains(v4ExternalIDs, `netloom_session_affinity="true"`) {
		t.Fatalf("IPv4 load balancer external_ids missing netloom_session_affinity=true:\n%s", v4ExternalIDs)
	}

	v6Selection := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "get", "load_balancer", v6LB, "selection_fields")
	if !strings.Contains(v6Selection, `[ipv6_src]`) {
		t.Fatalf("IPv6 selection_fields = %s, want [ipv6_src]", v6Selection)
	}
	v6Options := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "get", "load_balancer", v6LB, "options")
	if !strings.Contains(v6Options, `affinity_timeout="10800"`) {
		t.Fatalf("IPv6 load balancer options missing default affinity_timeout=10800:\n%s", v6Options)
	}
	v6ExternalIDs := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "get", "load_balancer", v6LB, "external_ids")
	if !strings.Contains(v6ExternalIDs, `netloom_session_affinity="true"`) {
		t.Fatalf("IPv6 load balancer external_ids missing netloom_session_affinity=true:\n%s", v6ExternalIDs)
	}
}

func desiredStateWithSessionAffinityJSON() string {
	return `{
  "vpcs": [{"name": "affinity"}],
  "subnets": [
    {"name": "apps-v4", "vpc": "affinity", "cidr": "10.247.0.0/24", "gateway": "10.247.0.1"},
    {"name": "apps-v6", "vpc": "affinity", "cidr": "fd00:47::/64", "gateway": "fd00:47::1"}
  ],
  "load_balancers": [
    {"name": "web-v4", "vpc": "affinity", "vip": "10.96.0.60", "session_affinity": true, "affinity_timeout": 7200, "selection_fields": ["tp_src", "ip_src"], "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.247.0.10", "port": 8080}]}], "subnets": ["apps-v4"]},
    {"name": "web-v6", "vpc": "affinity", "vip": "fd00:96::60", "session_affinity": true, "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "fd00:47::10", "port": 8080}]}], "subnets": ["apps-v6"]}
  ]
}`
}
