package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerSharedInterfaceWorldEntitiesExcludeClusterPrefixes(t *testing.T) {
	requireDockerE2E(t)

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.127/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "-6", "addr", "add", "fd00:30::127/64", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ip", "addr", "add", "198.51.100.11/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ip", "-6", "addr", "add", "2001:db8::11/64", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "route", "add", "198.51.100.0/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "-6", "route", "add", "2001:db8::/64", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.127 -p 8089 >/dev/null; done >/tmp/netloom-world-ipv4.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s fd00:30::127 -p 8090 >/dev/null; done >/tmp/netloom-world-ipv6.log 2>&1 &")

	statePath := "/tmp/netloom-world-entities-state.json"
	agentScript := "cat >" + statePath + " <<'EOF'\n" + desiredSharedInterfaceWorldEntitiesStateJSON() + "\nEOF\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_NODE_NAME=node-b" +
		" NETLOOM_POLICY_STORE=ebpf" +
		" NETLOOM_TCX_IFACE=eth0" +
		" NETLOOM_TCX_HOLD_MS=2500" +
		" /netloom/bin/netloom-agent >/tmp/netloom-agent-world-entities.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentScript)
	time.Sleep(700 * time.Millisecond)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -s 198.51.100.11 -w 1 172.30.0.127 8089")
	clusterIPv4Drop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -w 1 172.30.0.127 8089 >/tmp/netloom-world-ipv4-drop.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-world-ipv4-drop.log; exit 1")
	if clusterIPv4Drop.exitCode == 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-world-entities.log 2>/dev/null || true")
		t.Fatalf("expected cluster IPv4 source to stay outside world-ipv4 entity while TCX policy is attached, output:\n%s\nagent log:\n%s", clusterIPv4Drop.output, agentLog)
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -s 2001:db8::11 -w 1 fd00:30::127 8090")
	clusterIPv6Drop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -w 1 fd00:30::127 8090 >/tmp/netloom-world-ipv6-drop.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-world-ipv6-drop.log; exit 1")
	if clusterIPv6Drop.exitCode == 0 {
		agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-world-entities.log 2>/dev/null || true")
		t.Fatalf("expected cluster IPv6 source to stay outside world-ipv6 entity while TCX policy is attached, output:\n%s\nagent log:\n%s", clusterIPv6Drop.output, agentLog)
	}

	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.127 8089")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 fd00:30::127 8090")

	agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-world-entities.log")
	for _, expected := range []string{"reconciled node policy", "node=node-b", "store=ebpf", "endpoints=2", "tcx_eligible=2", "tcx=attached:eth0:ingress:policy-l4"} {
		if !strings.Contains(agentLog, expected) {
			t.Fatalf("world-entities agent output missing %q:\n%s", expected, agentLog)
		}
	}
}

func desiredSharedInterfaceWorldEntitiesStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [
    {"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"},
    {"name": "hostnet-v6", "vpc": "fabric", "cidr": "fd00:30::/64", "gateway": "fd00:30::1"}
  ],
  "endpoints": [
    {"id": "host-127", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.127", "node": "node-b", "security_groups": ["allow-world-ipv4"]},
    {"id": "host-v6-127", "vpc": "fabric", "subnet": "hostnet-v6", "ip": "fd00:30::127", "node": "node-b", "security_groups": ["allow-world-ipv6"]}
  ],
  "security_groups": [
    {"name": "allow-world-ipv4", "vpc": "fabric", "rules": [
      {"id": "allow-world-ipv4-entity", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_entities": ["world-ipv4"], "ports": [{"from": 8089, "to": 8089}], "action": "allow"},
      {"id": "drop-cluster-ipv4", "priority": 200, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.0/24", "ports": [{"from": 8089, "to": 8089}], "action": "drop"}
    ]},
    {"name": "allow-world-ipv6", "vpc": "fabric", "rules": [
      {"id": "allow-world-ipv6-entity", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_entities": ["world-ipv6"], "ports": [{"from": 8090, "to": 8090}], "action": "allow"},
      {"id": "drop-cluster-ipv6", "priority": 200, "direction": "ingress", "protocol": "tcp", "remote_cidr": "fd00:30::/64", "ports": [{"from": 8090, "to": 8090}], "action": "drop"}
    ]}
  ]
}`
}
