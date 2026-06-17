package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerSharedInterfaceDefaultAllowEgressKeepsWildcardPermit(t *testing.T) {
	requireDockerE2E(t)

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ip", "addr", "add", "172.30.0.134/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.12 -p 8087 >/dev/null; done >/tmp/netloom-default-allow-egress-8087.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.12 -p 8088 >/dev/null; done >/tmp/netloom-default-allow-egress-8088.log 2>&1 &")

	statePath := "/tmp/netloom-default-allow-egress-state.json"
	agentScript := "cat >" + statePath + " <<'EOF'\n" + desiredSharedInterfaceDefaultAllowEgressStateJSON() + "\nEOF\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_NODE_NAME=node-a" +
		" NETLOOM_POLICY_STORE=ebpf" +
		" NETLOOM_TCX_IFACE=eth0" +
		" NETLOOM_TCX_HOLD_MS=2500" +
		" /netloom/bin/netloom-agent >/tmp/netloom-agent-default-allow-egress.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", agentScript)
	time.Sleep(700 * time.Millisecond)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -s 172.30.0.134 -w 1 172.30.0.12 8087")

	adminDrop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -s 172.30.0.134 -w 1 172.30.0.12 8088 >/tmp/netloom-default-allow-egress-drop.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-default-allow-egress-drop.log; exit 1")
	if adminDrop.exitCode == 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "cat /tmp/netloom-agent-default-allow-egress.log 2>/dev/null || true")
		t.Fatalf("expected explicit tcp/8088 drop to override default-allow egress wildcard, output:\n%s\nagent log:\n%s", adminDrop.output, agentLog)
	}

	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -s 172.30.0.134 -w 1 172.30.0.12 8088")

	agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "cat", "/tmp/netloom-agent-default-allow-egress.log")
	for _, expected := range []string{"reconciled node policy", "node=node-a", "store=ebpf", "endpoints=1", "tcx=attached:eth0:egress:policy-l4"} {
		if !strings.Contains(agentLog, expected) {
			t.Fatalf("default-allow egress agent output missing %q:\n%s", expected, agentLog)
		}
	}
}

func desiredSharedInterfaceDefaultAllowEgressStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [{"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}],
  "endpoints": [
    {"id": "host-134", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.134", "node": "node-a", "security_groups": ["default-allow-egress"]}
  ],
  "security_groups": [
    {"name": "default-allow-egress", "vpc": "fabric", "default_deny_egress": false, "rules": [
      {"id": "drop-node-b-admin", "priority": 100, "direction": "egress", "protocol": "tcp", "remote_cidr": "172.30.0.12/32", "ports": [{"from": 8088, "to": 8088}], "action": "drop"}
    ]}
  ]
}`
}
