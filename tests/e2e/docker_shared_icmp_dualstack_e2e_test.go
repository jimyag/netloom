package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerSharedInterfaceDualStackICMPPolicy(t *testing.T) {
	requireDockerE2E(t)

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	ipv6Check := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip -6 -o addr show dev eth0 | grep -q 'fd00:30::12'")
	if ipv6Check.exitCode != 0 {
		dump := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "-6", "addr", "show", "dev", "eth0")
		t.Skipf("node-b does not have IPv6 fabric address:\n%s", strings.TrimSpace(dump.output))
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.137/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "-6", "addr", "add", "fd00:30::137/64", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ping -c 1 -W 1 172.30.0.137 >/tmp/netloom-shared-icmp-v4-allow.log 2>&1 && exit 0; sleep 1; done; cat /tmp/netloom-shared-icmp-v4-allow.log; exit 1")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ping -6 -c 1 -W 1 fd00:30::137 >/tmp/netloom-shared-icmp-v6-allow.log 2>&1 && exit 0; sleep 1; done; cat /tmp/netloom-shared-icmp-v6-allow.log; exit 1")

	statePath := "/tmp/netloom-shared-icmp-dual-state.json"
	agentScript := "cat >" + statePath + " <<'EOF'\n" + desiredSharedInterfaceDualStackICMPDropStateJSON() + "\nEOF\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_NODE_NAME=node-b" +
		" NETLOOM_POLICY_STORE=ebpf" +
		" NETLOOM_TCX_IFACE=eth0" +
		" NETLOOM_TCX_HOLD_MS=2500" +
		" /netloom/bin/netloom-agent >/tmp/netloom-agent-shared-icmp-dual.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do grep -q 'tcx=attached:eth0:ingress:policy-l4-dual' /tmp/netloom-agent-shared-icmp-dual.log 2>/dev/null && exit 0; sleep 1; done; cat /tmp/netloom-agent-shared-icmp-dual.log; exit 1")

	v4Drop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ping -c 1 -W 1 172.30.0.137 >/tmp/netloom-shared-icmp-v4-drop.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-shared-icmp-v4-drop.log; exit 1")
	if v4Drop.exitCode == 0 {
		log := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-shared-icmp-dual.log")
		t.Fatalf("expected IPv4 ICMP echo to fail while dual-stack shared-interface ICMP policy is attached, output:\n%s\nagent log:\n%s", v4Drop.output, log)
	}
	v6Drop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ping -6 -c 1 -W 1 fd00:30::137 >/tmp/netloom-shared-icmp-v6-drop.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-shared-icmp-v6-drop.log; exit 1")
	if v6Drop.exitCode == 0 {
		log := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-shared-icmp-dual.log")
		t.Fatalf("expected IPv6 ICMP echo to fail while dual-stack shared-interface ICMP policy is attached, output:\n%s\nagent log:\n%s", v6Drop.output, log)
	}

	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "ping -c 1 -W 1 172.30.0.137")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "ping -6 -c 1 -W 1 fd00:30::137")

	dualLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-shared-icmp-dual.log")
	for _, expected := range []string{"reconciled node policy", "node=node-b", "store=ebpf", "endpoints=2", "tcx_eligible=2", "tcx=attached:eth0:ingress:policy-l4-dual"} {
		if !strings.Contains(dualLog, expected) {
			t.Fatalf("shared dual-stack ICMP agent output missing %q:\n%s", expected, dualLog)
		}
	}
}

func desiredSharedInterfaceDualStackICMPDropStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [
    {"name": "hostnet-v4", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"},
    {"name": "hostnet-v6", "vpc": "fabric", "cidr": "fd00:30::/64", "gateway": "fd00:30::1"}
  ],
  "endpoints": [
    {"id": "host-v4-137", "vpc": "fabric", "subnet": "hostnet-v4", "ip": "172.30.0.137", "node": "node-b", "security_groups": ["drop-icmp-v4"]},
    {"id": "host-v6-137", "vpc": "fabric", "subnet": "hostnet-v6", "ip": "fd00:30::137", "node": "node-b", "security_groups": ["drop-icmp-v6"]}
  ],
  "security_groups": [
    {"name": "drop-icmp-v4", "vpc": "fabric", "rules": [{"id": "drop-icmpv4-from-node-a", "priority": 100, "direction": "ingress", "protocol": "icmp", "remote_cidr": "172.30.0.11/32", "action": "drop"}]},
    {"name": "drop-icmp-v6", "vpc": "fabric", "rules": [{"id": "drop-icmpv6-from-node-a", "priority": 100, "direction": "ingress", "protocol": "icmp", "remote_cidr": "fd00:30::11/128", "action": "drop"}]}
  ]
}`
}
