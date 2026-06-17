package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerSharedInterfaceStatefulIngressAllowsRepliesViaConntrack(t *testing.T) {
	requireDockerE2E(t)

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.133/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf reply-ok | nc -l -s 172.30.0.133 -p 8084 >/dev/null; done >/tmp/netloom-stateful-8084.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf reject-me | nc -l -s 172.30.0.133 -p 8085 >/dev/null; done >/tmp/netloom-stateful-8085.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "while true; do printf upstream-ok | nc -l -s 172.30.0.11 -p 9099 >/dev/null; done >/tmp/netloom-stateful-9099.log 2>&1 &")

	statePath := "/tmp/netloom-stateful-conntrack-state.json"
	agentScript := "cat >" + statePath + " <<'EOF'\n" + desiredSharedInterfaceStatefulConntrackStateJSON() + "\nEOF\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_NODE_NAME=node-b" +
		" NETLOOM_POLICY_STORE=ebpf" +
		" NETLOOM_TCX_IFACE=eth0" +
		" NETLOOM_TCX_HOLD_MS=2500" +
		" /netloom/bin/netloom-agent >/tmp/netloom-agent-stateful-conntrack.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentScript)
	time.Sleep(700 * time.Millisecond)

	replyProbe := runAllowFailure(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"node-a",
		"sh",
		"-c",
		"for i in $(seq 1 20); do out=$(printf hi | nc -w 1 172.30.0.133 8084 2>/tmp/netloom-stateful-reply.err) && [ \"$out\" = \"reply-ok\" ] && exit 0; sleep 1; done; cat /tmp/netloom-stateful-reply.err; exit 1",
	)
	if replyProbe.exitCode != 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-stateful-conntrack.log")
		t.Fatalf("expected stateful ingress allow to permit reply traffic via conntrack, output:\n%s\nagent log:\n%s", replyProbe.output, agentLog)
	}

	ingressDrop := runAllowFailure(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"node-a",
		"sh",
		"-c",
		"for i in $(seq 1 15); do printf hi | nc -w 1 172.30.0.133 8085 >/tmp/netloom-stateful-ingress-drop.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-stateful-ingress-drop.log; exit 1",
	)
	if ingressDrop.exitCode == 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-stateful-conntrack.log")
		t.Fatalf("expected explicit ingress drop on tcp/8085 while tcx policy is attached, output:\n%s\nagent log:\n%s", ingressDrop.output, agentLog)
	}

	egressDrop := runAllowFailure(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"node-b",
		"sh",
		"-c",
		"for i in $(seq 1 15); do printf hi | nc -s 172.30.0.133 -w 1 172.30.0.11 9099 >/tmp/netloom-stateful-egress-drop.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-stateful-egress-drop.log; exit 1",
	)
	if egressDrop.exitCode == 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-stateful-conntrack.log")
		t.Fatalf("expected explicit egress drop on tcp/9099 while tcx policy is attached, output:\n%s\nagent log:\n%s", egressDrop.output, agentLog)
	}

	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "printf hi | nc -s 172.30.0.133 -w 1 172.30.0.11 9099")

	agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-stateful-conntrack.log")
	for _, expected := range []string{
		"reconciled node policy",
		"node=node-b",
		"store=ebpf",
		"endpoints=1",
		"tcx=attached:eth0:mixed:policy-l4",
	} {
		if !strings.Contains(agentLog, expected) {
			t.Fatalf("stateful conntrack agent output missing %q:\n%s", expected, agentLog)
		}
	}
}

func desiredSharedInterfaceStatefulConntrackStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [{"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}],
  "endpoints": [
    {"id": "host-133", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.133", "node": "node-b", "security_groups": ["stateful-web"]}
  ],
  "security_groups": [
    {"name": "stateful-web", "vpc": "fabric", "rules": [
      {"id": "allow-node-a-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8084, "to": 8084}], "action": "allow", "stateful": true},
      {"id": "drop-node-a-admin", "priority": 110, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8085, "to": 8085}], "action": "drop"},
      {"id": "drop-node-a-upstream", "priority": 120, "direction": "egress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 9099, "to": 9099}], "action": "drop"}
    ]}
  ]
}`
}
