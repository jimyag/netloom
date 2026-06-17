package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerSharedInterfaceRemoteEntitiesRespectHostAndRemoteNode(t *testing.T) {
	requireDockerE2E(t)

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.124/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.125/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.124 -p 8085 >/dev/null; done >/tmp/netloom-remote-entity-host.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.125 -p 8086 >/dev/null; done >/tmp/netloom-remote-entity-remote-node.log 2>&1 &")

	statePath := "/tmp/netloom-remote-entities-state.json"
	agentScript := "cat >" + statePath + " <<'EOF'\n" + desiredSharedInterfaceRemoteEntitiesStateJSON() + "\nEOF\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_NODE_NAME=node-b" +
		" NETLOOM_POLICY_STORE=ebpf" +
		" NETLOOM_TCX_IFACE=eth0" +
		" NETLOOM_TCX_HOLD_MS=2500" +
		" /netloom/bin/netloom-agent >/tmp/netloom-agent-remote-entities.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentScript)
	time.Sleep(700 * time.Millisecond)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.124 8085")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.125 8086")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "printf hi | nc -s 172.30.0.12 -w 1 172.30.0.124 8085")

	remoteNodeLocalDrop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -s 172.30.0.12 -w 1 172.30.0.125 8086 >/tmp/netloom-remote-entity-local-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-remote-entity-local-probe.log; exit 1")
	if remoteNodeLocalDrop.exitCode == 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-remote-entities.log 2>/dev/null || true")
		t.Fatalf("expected remote-node entity to exclude local gateway 172.30.0.12 while TCX policy is attached, output:\n%s\nagent log:\n%s", remoteNodeLocalDrop.output, agentLog)
	}

	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "printf hi | nc -s 172.30.0.12 -w 1 172.30.0.125 8086")

	agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-remote-entities.log")
	for _, expected := range []string{"reconciled node policy", "node=node-b", "store=ebpf", "endpoints=2", "tcx_eligible=2", "tcx=attached:eth0:ingress:policy-l4"} {
		if !strings.Contains(agentLog, expected) {
			t.Fatalf("remote-entities agent output missing %q:\n%s", expected, agentLog)
		}
	}
}

func desiredSharedInterfaceRemoteEntitiesStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [{"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}],
  "gateways": [
    {"name": "gw-node-a", "vpc": "fabric", "node": "node-a", "external_if": "eth0", "lan_ip": "172.30.0.11"},
    {"name": "gw-node-b", "vpc": "fabric", "node": "node-b", "external_if": "eth0", "lan_ip": "172.30.0.12"}
  ],
  "endpoints": [
    {"id": "host-124", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.124", "node": "node-b", "security_groups": ["allow-host"]},
    {"id": "host-125", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.125", "node": "node-b", "security_groups": ["allow-remote-node"]}
  ],
  "security_groups": [
    {"name": "allow-host", "vpc": "fabric", "rules": [
      {"id": "allow-host-entity", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_entities": ["host"], "ports": [{"from": 8085, "to": 8085}], "action": "allow"},
      {"id": "drop-hostnet-8085", "priority": 200, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.0/24", "ports": [{"from": 8085, "to": 8085}], "action": "drop"}
    ]},
    {"name": "allow-remote-node", "vpc": "fabric", "rules": [
      {"id": "allow-remote-node-entity", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_entities": ["remote-node"], "ports": [{"from": 8086, "to": 8086}], "action": "allow"},
      {"id": "drop-hostnet-8086", "priority": 200, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.0/24", "ports": [{"from": 8086, "to": 8086}], "action": "drop"}
    ]}
  ]
}`
}
