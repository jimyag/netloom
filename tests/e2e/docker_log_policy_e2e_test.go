package e2e

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerSharedInterfaceLogPolicyDoesNotBlockTraffic(t *testing.T) {
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

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.140/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf log-ok | nc -l -s 172.30.0.140 -p 9556 >/dev/null; done >/tmp/netloom-log-9556.log 2>&1 &")

	statePath := "/tmp/netloom-log-policy-state.json"
	agentLogPath := "/tmp/netloom-agent-log-policy.log"
	agentScript := "cat >" + statePath + " <<'EOF'\n" + desiredSharedInterfaceLogStateJSON() + "\nEOF\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_NODE_NAME=node-b" +
		" NETLOOM_POLICY_STORE=ebpf" +
		" NETLOOM_TCX_IFACE=eth0" +
		" /netloom/bin/netloom-agent >" + agentLogPath + " 2>&1"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentScript)

	output := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do out=$(printf hi | nc -w 1 172.30.0.140 9556) && [ \"$out\" = \"log-ok\" ] && exit 0; sleep 1; done; exit 1")
	if output != "" {
		t.Fatalf("unexpected log-policy probe output:\n%s", output)
	}

	agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", agentLogPath)
	for _, expected := range []string{
		"reconciled node policy",
		"node=node-b",
		"store=ebpf",
		"endpoints=1",
		"programs=1",
		"entries=1",
		"tcx_eligible=0",
	} {
		if !strings.Contains(agentLog, expected) {
			t.Fatalf("log policy agent output missing %q:\n%s", expected, agentLog)
		}
	}
	if strings.Contains(agentLog, "tcx=attached") {
		t.Fatalf("log-only policy should not attach an enforcing TCX program:\n%s", agentLog)
	}
}

func desiredSharedInterfaceLogStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [{"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}],
  "endpoints": [
    {"id": "host-140", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.140", "node": "node-b", "security_groups": ["log-ingress"]}
  ],
  "security_groups": [
    {"name": "log-ingress", "vpc": "fabric", "rules": [
      {"id": "log-node-a-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 9556, "to": 9556}], "action": "log"}
    ]}
  ]
}`
}
