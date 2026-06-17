package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerSharedInterfaceDefaultAllowModeKeepsWildcardPermit(t *testing.T) {
	requireDockerE2E(t)

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.126/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.126 -p 8087 >/dev/null; done >/tmp/netloom-default-allow-8087.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.126 -p 8088 >/dev/null; done >/tmp/netloom-default-allow-8088.log 2>&1 &")

	statePath := "/tmp/netloom-default-allow-state.json"
	agentScript := "cat >" + statePath + " <<'EOF'\n" + desiredSharedInterfaceDefaultAllowStateJSON() + "\nEOF\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_NODE_NAME=node-b" +
		" NETLOOM_POLICY_STORE=ebpf" +
		" NETLOOM_TCX_IFACE=eth0" +
		" NETLOOM_TCX_HOLD_MS=2500" +
		" /netloom/bin/netloom-agent >/tmp/netloom-agent-default-allow.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentScript)
	time.Sleep(700 * time.Millisecond)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.126 8087")

	adminDrop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -w 1 172.30.0.126 8088 >/tmp/netloom-default-allow-drop-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-default-allow-drop-probe.log; exit 1")
	if adminDrop.exitCode == 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-default-allow.log 2>/dev/null || true")
		t.Fatalf("expected explicit tcp/8088 drop to override default-allow wildcard, output:\n%s\nagent log:\n%s", adminDrop.output, agentLog)
	}

	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.126 8088")

	agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-default-allow.log")
	for _, expected := range []string{"reconciled node policy", "node=node-b", "store=ebpf", "endpoints=1", "tcx=attached:eth0:ingress:policy-l4"} {
		if !strings.Contains(agentLog, expected) {
			t.Fatalf("default-allow agent output missing %q:\n%s", expected, agentLog)
		}
	}
}

func desiredSharedInterfaceDefaultAllowStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [{"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}],
  "endpoints": [
    {"id": "host-126", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.126", "node": "node-b", "security_groups": ["default-allow-ingress"]}
  ],
  "security_groups": [
    {"name": "default-allow-ingress", "vpc": "fabric", "default_deny_ingress": false, "rules": [
      {"id": "drop-node-a-admin", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8088, "to": 8088}], "action": "drop"}
    ]}
  ]
}`
}
