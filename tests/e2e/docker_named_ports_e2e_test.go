package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerLinuxNamedPortsResolveAcrossIngressAndEgressPolicies(t *testing.T) {
	requireDockerE2E(t)

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	for _, service := range []string{"node-a", "node-b"} {
		netns := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "netns", "list")
		if netns.exitCode == 0 {
			continue
		}
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "apk add --no-cache iproute2")
	}

	statePath := "/tmp/netloom-workload-named-ports-state.json"
	stateForNode := func(node string) string {
		return "cat >" + statePath + " <<'EOF'\n" + desiredWorkloadNamedPortsStateJSON() + "\nEOF\n" +
			"NETLOOM_STATE_FILE=" + statePath +
			" NETLOOM_NODE_NAME=" + node +
			" NETLOOM_POLICY_STORE=ebpf" +
			" NETLOOM_LINUX_DATAPATH=1" +
			" NETLOOM_LINUX_DATAPATH_MODE=netns" +
			" NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth0" +
			" NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-b=172.30.0.12 " +
			"/netloom/bin/netloom-agent"
	}
	startTCXWorkloadAgent := func(service string) {
		logPath := "/tmp/netloom-named-ports-" + service + ".log"
		command := "cat >" + statePath + " <<'EOF'\n" + desiredWorkloadNamedPortsStateJSON() + "\nEOF\n" +
			"pkill -f '/netloom/bin/netloom-agent' 2>/dev/null || true\n" +
			": >" + logPath + "\n" +
			"NETLOOM_STATE_FILE=" + statePath +
			" NETLOOM_NODE_NAME=" + service +
			" NETLOOM_POLICY_STORE=ebpf" +
			" NETLOOM_LINUX_DATAPATH=1" +
			" NETLOOM_LINUX_DATAPATH_MODE=netns" +
			" NETLOOM_LINUX_DATAPATH_CLEANUP=1" +
			" NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth0" +
			" NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-b=172.30.0.12" +
			" NETLOOM_TCX_WORKLOAD=1" +
			" NETLOOM_RECONCILE_INTERVAL_MS=500" +
			" /netloom/bin/netloom-agent >" + logPath + " 2>&1 &"
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", command)
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "for i in $(seq 1 20); do grep -q 'tcx=attached-workloads' "+logPath+" 2>/dev/null && exit 0; sleep 1; done; cat "+logPath+"; exit 1")
	}

	nodeAOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", stateForNode("node-a"))
	if !strings.Contains(nodeAOutput, "reconciled node policy") {
		t.Fatalf("node-a named-port reconcile did not succeed:\n%s", nodeAOutput)
	}
	if !strings.Contains(nodeAOutput, "policy_added=2") {
		t.Fatalf("node-a named-port reconcile did not add the expected egress rules:\n%s", nodeAOutput)
	}
	nodeBOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", stateForNode("node-b"))
	if !strings.Contains(nodeBOutput, "reconciled node policy") {
		t.Fatalf("node-b named-port reconcile did not succeed:\n%s", nodeBOutput)
	}
	startTCXWorkloadAgent("node-b")

	clientNS := workloadNamespace("file", "file-pod-a")
	serverNS := workloadNamespace("file", "file-pod-b")

	run(
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
		"ip netns exec "+serverNS+" sh -c 'while true; do printf http | nc -l -p 8080 >/dev/null; done' >/tmp/netloom-named-port-http.log 2>&1 & "+
			"ip netns exec "+serverNS+" sh -c 'while true; do printf admin | nc -l -p 9090 >/dev/null; done' >/tmp/netloom-named-port-admin.log 2>&1 &",
	)
	time.Sleep(700 * time.Millisecond)

	allowProbe := runAllowFailure(
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
		"for i in $(seq 1 20); do ip netns exec "+clientNS+" sh -c 'printf hi | nc -w 1 10.245.0.11 8080' >/tmp/netloom-named-port-allow.log 2>&1 && exit 0; sleep 1; done; cat /tmp/netloom-named-port-allow.log; exit 1",
	)
	if allowProbe.exitCode != 0 {
		t.Fatalf("named port allow probe to tcp/8080 failed:\n%s", allowProbe.output)
	}

	denyProbe := runAllowFailure(
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
		"for i in $(seq 1 20); do ip netns exec "+clientNS+" sh -c 'printf hi | nc -w 1 10.245.0.11 9090' >/tmp/netloom-named-port-deny.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-named-port-deny.log; exit 1",
	)
	if denyProbe.exitCode != 0 {
		t.Fatalf("named port deny probe to tcp/9090 unexpectedly succeeded:\n%s", denyProbe.output)
	}
}

func desiredWorkloadNamedPortsStateJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "provider_networks": [{"name": "physnet-a", "nodes": [{"node": "node-a", "interface": "eth0"}, {"node": "node-b", "interface": "eth0"}]}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100}],
  "endpoints": [
    {"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["clients", "client-egress"]},
    {"id": "file-pod-b", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.11", "node": "node-b", "security_groups": ["servers", "server-ingress"], "named_ports": [{"name": "http", "protocol": "tcp", "port": 8080}, {"name": "admin", "protocol": "tcp", "port": 9090}]},
    {"id": "file-pod-c", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.12", "node": "node-b", "security_groups": ["shadow-ingress"], "named_ports": [{"name": "http", "protocol": "tcp", "port": 8082}, {"name": "admin", "protocol": "tcp", "port": 9091}]}
  ],
  "security_groups": [
    {"name": "clients", "vpc": "file", "rules": []},
    {"name": "servers", "vpc": "file", "rules": []},
    {"name": "shadow-ingress", "vpc": "file", "rules": [{"id": "allow-client-shadow-http-ingress", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_group": "clients", "named_ports": ["http"], "action": "allow"}, {"id": "drop-client-shadow-admin-ingress", "priority": 110, "direction": "ingress", "protocol": "tcp", "remote_group": "clients", "ports": [{"from": 9091, "to": 9091}], "action": "drop"}]},
    {"name": "client-egress", "vpc": "file", "rules": [{"id": "allow-server-http-egress", "priority": 100, "direction": "egress", "protocol": "tcp", "remote_group": "servers", "named_ports": ["http"], "action": "allow"}, {"id": "drop-server-admin-egress", "priority": 110, "direction": "egress", "protocol": "tcp", "remote_group": "servers", "ports": [{"from": 9090, "to": 9090}], "action": "drop"}]},
    {"name": "server-ingress", "vpc": "file", "rules": [{"id": "allow-client-http-ingress", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_group": "clients", "named_ports": ["http"], "action": "allow"}, {"id": "drop-client-admin-ingress", "priority": 110, "direction": "ingress", "protocol": "tcp", "remote_group": "clients", "ports": [{"from": 9090, "to": 9090}], "action": "drop"}]}
  ]
}`
}
