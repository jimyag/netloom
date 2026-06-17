package e2e

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerSharedInterfaceRejectPolicyBlocksTraffic(t *testing.T) {
	requireDockerE2E(t)
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	cmdPattern := filepath.ToSlash(filepath.Join("..", "..", "cmd")) + "/..."
	run(t, ctx, "env", "CGO_ENABLED=0", "go", "build", "-trimpath", "-o", filepath.Join("..", "..", "bin")+"/", cmdPattern)
	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.139/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf reject-should-not-pass | nc -l -s 172.30.0.139 -p 9555 >/dev/null; done >/tmp/netloom-reject-9555.log 2>&1 &")

	statePath := "/tmp/netloom-reject-policy-state.json"
	agentLogPath := "/tmp/netloom-agent-reject.log"
	agentScript := "cat >" + statePath + " <<'EOF'\n" + desiredSharedInterfaceRejectStateJSON() + "\nEOF\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_NODE_NAME=node-b" +
		" NETLOOM_POLICY_STORE=ebpf" +
		" NETLOOM_TCX_IFACE=eth0" +
		" NETLOOM_TCX_HOLD_MS=2500" +
		" /netloom/bin/netloom-agent >" + agentLogPath + " 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 20); do grep -q 'tcx=attached:eth0:ingress:policy-l4' "+agentLogPath+" 2>/dev/null && exit 0; sleep 1; done; cat "+agentLogPath+"; exit 1")

	rejectProbe := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -w 1 172.30.0.139 9555 >/tmp/netloom-reject-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-reject-probe.log; exit 1")
	if rejectProbe.exitCode == 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", agentLogPath)
		t.Fatalf("expected reject policy to block tcp/9555 while TCX policy is attached, output:\n%s\nagent log:\n%s", rejectProbe.output, agentLog)
	}

	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.139 9555")

	agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", agentLogPath)
	for _, expected := range []string{
		"reconciled node policy",
		"node=node-b",
		"store=ebpf",
		"endpoints=1",
		"tcx=attached:eth0:ingress:policy-l4",
	} {
		if !strings.Contains(agentLog, expected) {
			t.Fatalf("reject policy agent output missing %q:\n%s", expected, agentLog)
		}
	}
}

func desiredSharedInterfaceRejectStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [{"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}],
  "endpoints": [
    {"id": "host-139", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.139", "node": "node-b", "security_groups": ["reject-ingress"]}
  ],
  "security_groups": [
    {"name": "reject-ingress", "vpc": "fabric", "rules": [
      {"id": "reject-node-a-admin", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 9555, "to": 9555}], "action": "reject"}
    ]}
  ]
}`
}
