package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerSharedInterfaceClusterPrivateAndAllEntities(t *testing.T) {
	requireDockerE2E(t)

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.128/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.129/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.130/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ip", "addr", "add", "10.200.0.11/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ip", "addr", "add", "198.51.100.11/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "route", "add", "10.200.0.0/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "route", "add", "198.51.100.0/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.128 -p 8091 >/dev/null; done >/tmp/netloom-cluster-entity.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.129 -p 8092 >/dev/null; done >/tmp/netloom-private-entity.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.130 -p 8093 >/dev/null; done >/tmp/netloom-all-entity.log 2>&1 &")

	statePath := "/tmp/netloom-common-entities-state.json"
	agentScript := "cat >" + statePath + " <<'EOF'\n" + desiredSharedInterfaceCommonEntitiesStateJSON() + "\nEOF\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_NODE_NAME=node-b" +
		" NETLOOM_POLICY_STORE=ebpf" +
		" NETLOOM_TCX_IFACE=eth0" +
		" NETLOOM_TCX_HOLD_MS=2500" +
		" /netloom/bin/netloom-agent >/tmp/netloom-agent-common-entities.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentScript)
	time.Sleep(700 * time.Millisecond)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.128 8091")
	clusterPublicDrop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -s 198.51.100.11 -w 1 172.30.0.128 8091 >/tmp/netloom-cluster-public-drop.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-cluster-public-drop.log; exit 1")
	if clusterPublicDrop.exitCode == 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-common-entities.log 2>/dev/null || true")
		t.Fatalf("expected public source to stay outside cluster entity while TCX policy is attached, output:\n%s\nagent log:\n%s", clusterPublicDrop.output, agentLog)
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -s 10.200.0.11 -w 1 172.30.0.129 8092")
	privatePublicDrop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -s 198.51.100.11 -w 1 172.30.0.129 8092 >/tmp/netloom-private-public-drop.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-private-public-drop.log; exit 1")
	if privatePublicDrop.exitCode == 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-common-entities.log 2>/dev/null || true")
		t.Fatalf("expected public source to stay outside private entity while TCX policy is attached, output:\n%s\nagent log:\n%s", privatePublicDrop.output, agentLog)
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.130 8093")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -s 198.51.100.11 -w 1 172.30.0.130 8093")

	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -s 198.51.100.11 -w 1 172.30.0.128 8091")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -s 198.51.100.11 -w 1 172.30.0.129 8092")

	agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-common-entities.log")
	for _, expected := range []string{"reconciled node policy", "node=node-b", "store=ebpf", "endpoints=3", "tcx_eligible=2", "tcx=attached:eth0:ingress:policy-l4"} {
		if !strings.Contains(agentLog, expected) {
			t.Fatalf("common-entities agent output missing %q:\n%s", expected, agentLog)
		}
	}
}

func desiredSharedInterfaceCommonEntitiesStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [{"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}],
  "endpoints": [
    {"id": "host-128", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.128", "node": "node-b", "security_groups": ["allow-cluster"]},
    {"id": "host-129", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.129", "node": "node-b", "security_groups": ["allow-private"]},
    {"id": "host-130", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.130", "node": "node-b", "security_groups": ["allow-all"]}
  ],
  "security_groups": [
    {"name": "allow-cluster", "vpc": "fabric", "rules": [
      {"id": "allow-cluster-entity", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_entities": ["cluster"], "ports": [{"from": 8091, "to": 8091}], "action": "allow"},
      {"id": "drop-public-8091", "priority": 200, "direction": "ingress", "protocol": "tcp", "remote_cidr": "198.51.100.0/24", "ports": [{"from": 8091, "to": 8091}], "action": "drop"}
    ]},
    {"name": "allow-private", "vpc": "fabric", "rules": [
      {"id": "allow-private-entity", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_entities": ["private"], "ports": [{"from": 8092, "to": 8092}], "action": "allow"},
      {"id": "drop-public-8092", "priority": 200, "direction": "ingress", "protocol": "tcp", "remote_cidr": "198.51.100.0/24", "ports": [{"from": 8092, "to": 8092}], "action": "drop"}
    ]},
    {"name": "allow-all", "vpc": "fabric", "rules": [
      {"id": "allow-all-entity", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_entities": ["all"], "ports": [{"from": 8093, "to": 8093}], "action": "allow"}
    ]}
  ]
}`
}
