package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerSharedInterfaceSelectorExpressionsFilterEndpoints(t *testing.T) {
	requireDockerE2E(t)

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.135/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.136/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf good | nc -l -s 172.30.0.135 -p 9093 >/dev/null; done >/tmp/netloom-selector-expr-good.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf bad | nc -l -s 172.30.0.136 -p 9093 >/dev/null; done >/tmp/netloom-selector-expr-bad.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf drop | nc -l -s 172.30.0.135 -p 9094 >/dev/null; done >/tmp/netloom-selector-expr-drop.log 2>&1 &")

	statePath := "/tmp/netloom-selector-expr-state.json"
	agentScript := "cat >" + statePath + " <<'EOF'\n" + desiredSharedInterfaceSelectorExpressionStateJSON() + "\nEOF\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_NODE_NAME=node-a" +
		" NETLOOM_POLICY_STORE=ebpf" +
		" NETLOOM_TCX_IFACE=eth0" +
		" NETLOOM_TCX_HOLD_MS=2500" +
		" /netloom/bin/netloom-agent >/tmp/netloom-agent-selector-expr.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", agentScript)
	time.Sleep(700 * time.Millisecond)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.135 9093")

	badDrop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -w 1 172.30.0.136 9093 >/tmp/netloom-selector-expr-bad-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-selector-expr-bad-probe.log; exit 1")
	if badDrop.exitCode == 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "cat", "/tmp/netloom-agent-selector-expr.log")
		t.Fatalf("expected selector expressions to exclude endpoint 172.30.0.136 while TCX policy is attached, output:\n%s\nagent log:\n%s", badDrop.output, agentLog)
	}

	portDrop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -w 1 172.30.0.135 9094 >/tmp/netloom-selector-expr-port-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-selector-expr-port-probe.log; exit 1")
	if portDrop.exitCode == 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "cat", "/tmp/netloom-agent-selector-expr.log")
		t.Fatalf("expected explicit drop on tcp/9094 while TCX policy is attached, output:\n%s\nagent log:\n%s", portDrop.output, agentLog)
	}

	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.136 9093")

	agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "cat", "/tmp/netloom-agent-selector-expr.log")
	for _, expected := range []string{
		"reconciled node policy",
		"node=node-a",
		"store=ebpf",
		"endpoints=1",
		"tcx=attached:eth0:egress:policy-l4",
	} {
		if !strings.Contains(agentLog, expected) {
			t.Fatalf("selector expression agent output missing %q:\n%s", expected, agentLog)
		}
	}
}

func desiredSharedInterfaceSelectorExpressionStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [{"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}],
  "endpoints": [
    {"id": "host-client", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.134", "node": "node-a", "security_groups": ["selector-egress"], "labels": {"app": "client", "env": "prod"}},
    {"id": "host-good", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.135", "node": "node-b", "labels": {"app": "server", "env": "prod", "track": "stable"}},
    {"id": "host-bad", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.136", "node": "node-b", "labels": {"app": "server", "env": "dev", "track": "stable", "deprecated": "true"}}
  ],
  "security_groups": [
    {"name": "selector-egress", "vpc": "fabric", "rules": [
      {"id": "allow-selector-expressions", "priority": 100, "direction": "egress", "protocol": "tcp", "remote_endpoint_selector": {"app": "server"}, "remote_endpoint_expressions": [{"key": "track", "operator": "Exists"}, {"key": "deprecated", "operator": "DoesNotExist"}, {"key": "env", "operator": "NotIn", "values": ["dev"]}], "ports": [{"from": 9093, "to": 9093}], "action": "allow"},
      {"id": "drop-selector-port", "priority": 110, "direction": "egress", "protocol": "tcp", "remote_cidr": "172.30.0.0/24", "ports": [{"from": 9094, "to": 9094}], "action": "drop"}
    ]}
  ]
}`
}
