package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerSharedInterfaceTierPrecedenceHonorsPlatformAllow(t *testing.T) {
	requireDockerE2E(t)

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.138/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf tier-allow | nc -l -s 172.30.0.138 -p 9553 >/dev/null; done >/tmp/netloom-tier-9553.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf tier-drop | nc -l -s 172.30.0.138 -p 9554 >/dev/null; done >/tmp/netloom-tier-9554.log 2>&1 &")

	statePath := "/tmp/netloom-tier-precedence-state.json"
	agentScript := "cat >" + statePath + " <<'EOF'\n" + desiredSharedInterfaceTierPrecedenceStateJSON() + "\nEOF\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_NODE_NAME=node-b" +
		" NETLOOM_POLICY_STORE=ebpf" +
		" NETLOOM_TCX_IFACE=eth0" +
		" NETLOOM_TCX_HOLD_MS=2500" +
		" /netloom/bin/netloom-agent >/tmp/netloom-agent-tier.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentScript)
	time.Sleep(700 * time.Millisecond)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.138 9553")

	dropProbe := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -w 1 172.30.0.138 9554 >/tmp/netloom-tier-drop-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-tier-drop-probe.log; exit 1")
	if dropProbe.exitCode == 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-tier.log")
		t.Fatalf("expected tenant-tier drop to block tcp/9554 while tcx policy is attached, output:\n%s\nagent log:\n%s", dropProbe.output, agentLog)
	}

	agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-tier.log")
	for _, expected := range []string{
		"reconciled node policy",
		"node=node-b",
		"store=ebpf",
		"endpoints=1",
		"tcx=attached:eth0:ingress:policy-l4",
	} {
		if !strings.Contains(agentLog, expected) {
			t.Fatalf("tier precedence agent output missing %q:\n%s", expected, agentLog)
		}
	}
}

func desiredSharedInterfaceTierPrecedenceStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [{"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}],
  "endpoints": [
    {"id": "host-138", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.138", "node": "node-b", "security_groups": ["platform-guard", "tenant-guard"]}
  ],
  "security_groups": [
    {"name": "platform-guard", "vpc": "fabric", "tier": 0, "rules": [
      {"id": "platform-allow-dns", "priority": 10, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 9553, "to": 9553}], "action": "allow"}
    ]},
    {"name": "tenant-guard", "vpc": "fabric", "tier": 1, "rules": [
      {"id": "tenant-drop-dns", "priority": 1000, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 9553, "to": 9553}], "action": "drop"},
      {"id": "tenant-drop-admin", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 9554, "to": 9554}], "action": "drop"}
    ]}
  ]
}`
}
