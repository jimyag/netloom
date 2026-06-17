package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerSharedInterfaceExpandsSelectorServiceFQDNAndCIDRGroupPolicies(t *testing.T) {
	requireDockerE2E(t)

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	for _, cmd := range []string{
		"ip addr add 172.30.0.131/24 dev eth0",
		"ip route replace 198.51.100.0/24 dev eth0",
		"ip route replace 10.200.0.0/16 dev eth0",
	} {
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", cmd)
	}
	for _, cmd := range []string{
		"ip addr add 172.30.0.132/24 dev eth0",
		"ip addr add 172.30.0.200/24 dev eth0",
		"ip addr add 198.51.100.20/24 dev eth0",
		"ip addr add 198.51.100.30/24 dev eth0",
		"ip addr add 10.200.1.20/16 dev eth0",
		"ip addr add 10.200.200.20/16 dev eth0",
	} {
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", cmd)
	}
	for _, listener := range []string{
		"while true; do printf selector-ok | nc -l -s 172.30.0.132 -p 9091 >/dev/null; done >/tmp/netloom-selector-9091.log 2>&1 &",
		"while true; do printf selector-drop | nc -l -s 172.30.0.132 -p 9092 >/dev/null; done >/tmp/netloom-selector-9092.log 2>&1 &",
		"while true; do printf service-ok | nc -l -s 172.30.0.200 -p 8080 >/dev/null; done >/tmp/netloom-service-8080.log 2>&1 &",
		"while true; do printf service-drop | nc -l -s 172.30.0.200 -p 8081 >/dev/null; done >/tmp/netloom-service-8081.log 2>&1 &",
		"while true; do printf fqdn-ok | nc -l -s 198.51.100.20 -p 443 >/dev/null; done >/tmp/netloom-fqdn-443.log 2>&1 &",
		"while true; do printf fqdn-drop | nc -l -s 198.51.100.30 -p 443 >/dev/null; done >/tmp/netloom-fqdn-drop-443.log 2>&1 &",
		"while true; do printf corp-ok | nc -l -s 10.200.1.20 -p 8443 >/dev/null; done >/tmp/netloom-corp-8443.log 2>&1 &",
		"while true; do printf corp-drop | nc -l -s 10.200.200.20 -p 8443 >/dev/null; done >/tmp/netloom-corp-drop-8443.log 2>&1 &",
	} {
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", listener)
	}

	statePath := "/tmp/netloom-policy-sources-state.json"
	observationsPath := "/tmp/netloom-policy-sources-dns.json"
	agentLogPath := "/tmp/netloom-policy-sources-agent.log"
	agentScript := "cat >" + statePath + " <<'EOF'\n" + desiredSharedInterfacePolicySourcesStateJSON() + "\nEOF\n" +
		"cat >" + observationsPath + " <<'EOF'\n" + policySourcesDNSObservationJSON() + "\nEOF\n" +
		"pkill -f '/netloom/bin/netloom-agent' 2>/dev/null || true\n" +
		": >" + agentLogPath + "\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_DNS_OBSERVATIONS_FILE=" + observationsPath +
		" NETLOOM_NODE_NAME=node-a" +
		" NETLOOM_POLICY_STORE=ebpf" +
		" NETLOOM_TCX_IFACE=eth0" +
		" NETLOOM_TCX_HOLD_MS=4000" +
		" /netloom/bin/netloom-agent >" + agentLogPath + " 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", agentScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 20); do grep -q 'tcx=attached:eth0:egress:policy-l4' "+agentLogPath+" 2>/dev/null && exit 0; sleep 1; done; cat "+agentLogPath+"; exit 1")

	for _, allow := range []string{
		"printf hi | nc -s 172.30.0.131 -w 1 172.30.0.132 9091",
		"printf hi | nc -s 172.30.0.131 -w 1 172.30.0.200 8080",
		"printf hi | nc -s 172.30.0.131 -w 1 198.51.100.20 443",
		"printf hi | nc -s 172.30.0.131 -w 1 10.200.1.20 8443",
	} {
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", allow)
	}

	for _, probe := range []struct {
		name string
		cmd  string
	}{
		{
			name: "selector alternate port",
			cmd:  "for i in $(seq 1 20); do printf hi | nc -s 172.30.0.131 -w 1 172.30.0.132 9092 >/tmp/netloom-selector-drop-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-selector-drop-probe.log; exit 1",
		},
		{
			name: "service alternate port",
			cmd:  "for i in $(seq 1 20); do printf hi | nc -s 172.30.0.131 -w 1 172.30.0.200 8081 >/tmp/netloom-service-drop-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-service-drop-probe.log; exit 1",
		},
		{
			name: "unobserved fqdn address",
			cmd:  "for i in $(seq 1 20); do printf hi | nc -s 172.30.0.131 -w 1 198.51.100.30 443 >/tmp/netloom-fqdn-drop-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-fqdn-drop-probe.log; exit 1",
		},
		{
			name: "cidr-group except range",
			cmd:  "for i in $(seq 1 20); do printf hi | nc -s 172.30.0.131 -w 1 10.200.200.20 8443 >/tmp/netloom-corp-drop-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-corp-drop-probe.log; exit 1",
		},
	} {
		result := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", probe.cmd)
		if result.exitCode == 0 {
			agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "cat", agentLogPath)
			t.Fatalf("expected %s probe to be blocked while tcx policy is attached, output:\n%s\nagent log:\n%s", probe.name, result.output, agentLog)
		}
	}

	agentLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "cat", agentLogPath)
	for _, expected := range []string{
		"reconciled node policy",
		"node=node-a",
		"store=ebpf",
		"endpoints=1",
		"tcx=attached:eth0:egress:policy-l4",
	} {
		if !strings.Contains(agentLog, expected) {
			t.Fatalf("policy-source agent output missing %q:\n%s", expected, agentLog)
		}
	}
}

func desiredSharedInterfacePolicySourcesStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [{"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}],
  "endpoints": [
    {"id": "host-client", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.131", "node": "node-a", "security_groups": ["policy-sources"], "labels": {"app": "client", "env": "prod"}},
    {"id": "host-server", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.132", "node": "node-b", "labels": {"app": "server", "env": "prod"}}
  ],
  "load_balancers": [
    {"name": "svc-web", "vpc": "fabric", "vip": "172.30.0.200", "ports": [{"name": "http", "port": 8080, "protocol": "tcp", "backends": [{"ip": "172.30.0.132", "port": 8080}]}]}
  ],
  "cidr_groups": [
    {"name": "corp", "vpc": "fabric", "entries": [{"cidr": "10.200.0.0/16", "except_cidrs": ["10.200.128.0/17"]}]}
  ],
  "security_groups": [
    {"name": "policy-sources", "vpc": "fabric", "rules": [
      {"id": "allow-selector-server", "priority": 100, "direction": "egress", "protocol": "tcp", "remote_endpoint_selector": {"app": "server"}, "remote_endpoint_expressions": [{"key": "env", "operator": "In", "values": ["prod"]}], "ports": [{"from": 9091, "to": 9091}], "action": "allow"},
      {"id": "drop-selector-server-alt", "priority": 110, "direction": "egress", "protocol": "tcp", "remote_endpoint_selector": {"app": "server"}, "remote_endpoint_expressions": [{"key": "env", "operator": "In", "values": ["prod"]}], "ports": [{"from": 9092, "to": 9092}], "action": "drop"},
      {"id": "allow-service-vip", "priority": 120, "direction": "egress", "protocol": "any", "remote_service": "svc-web", "ports": [{"from": 8080, "to": 8080}], "action": "allow"},
      {"id": "drop-service-vip-alt", "priority": 130, "direction": "egress", "protocol": "tcp", "remote_cidr": "172.30.0.200/32", "ports": [{"from": 8081, "to": 8081}], "action": "drop"},
      {"id": "allow-observed-api", "priority": 140, "direction": "egress", "protocol": "tcp", "remote_fqdns": [{"match_name": "api.example.com"}], "ports": [{"from": 443, "to": 443}], "action": "allow"},
      {"id": "drop-unobserved-public", "priority": 150, "direction": "egress", "protocol": "tcp", "remote_cidr": "198.51.100.0/24", "except_cidrs": ["198.51.100.20/32"], "ports": [{"from": 443, "to": 443}], "action": "drop"},
      {"id": "allow-corp-group", "priority": 160, "direction": "egress", "protocol": "tcp", "remote_cidr_group": "corp", "ports": [{"from": 8443, "to": 8443}], "action": "allow"},
      {"id": "drop-corp-except", "priority": 170, "direction": "egress", "protocol": "tcp", "remote_cidr": "10.200.128.0/17", "ports": [{"from": 8443, "to": 8443}], "action": "drop"}
    ]}
  ]
}`
}

func policySourcesDNSObservationJSON() string {
	return `{
  "dns_records": [{"name": "api.example.com", "ips": ["198.51.100.20"]}]
}`
}
