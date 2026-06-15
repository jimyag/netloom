package e2e

import (
	"context"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestDockerLinuxPolicyRoutingProgramsAndCleansRuntimeState(t *testing.T) {
	requireDockerE2E(t)
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cmdPattern := filepath.ToSlash(filepath.Join("..", "..", "cmd")) + "/..."
	run(t, ctx, "env", "CGO_ENABLED=0", "go", "build", "-trimpath", "-o", filepath.Join("..", "..", "bin")+"/", cmdPattern)
	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	ipVersion := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "apk add --no-cache iproute2 >/dev/null && ip -V")
	if !strings.Contains(ipVersion, "iproute2") {
		t.Fatalf("node-b did not install iproute2:\n%s", ipVersion)
	}

	statePath := "/tmp/netloom-policy-route-state.json"
	applyState := func(stateJSON string) string {
		script := "cat >" + statePath + " <<'EOF'\n" + stateJSON + "\nEOF\n" +
			"NETLOOM_STATE_FILE=" + statePath +
			" NETLOOM_NODE_NAME=node-b" +
			" NETLOOM_LINUX_DATAPATH=1" +
			" NETLOOM_LINUX_DATAPATH_BACKEND=netlink" +
			" NETLOOM_LINUX_DATAPATH_CLEANUP=1" +
			" /netloom/bin/netloom-agent"
		return run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", script)
	}

	applyOutput := applyState(desiredLinuxPolicyRoutingStateJSON())
	if !strings.Contains(applyOutput, "policy_routes=2") {
		t.Fatalf("initial policy-route reconcile did not program two routes:\n%s", applyOutput)
	}

	rules := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "rule", "show")
	for _, expected := range []string{
		"from 10.10.0.0/24 to 198.51.100.10 ipproto tcp dport 443",
		"from 10.10.0.0/24 to 203.0.113.0/24",
	} {
		if !strings.Contains(rules, expected) {
			t.Fatalf("policy rules missing %q:\n%s", expected, rules)
		}
	}

	rerouteTable := mustLookupTableForDestination(t, rules, "198.51.100.10")
	dropTable := mustLookupTableForDestination(t, rules, "203.0.113.0/24")

	rerouteTableState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "route", "show", "table", rerouteTable)
	if !strings.Contains(rerouteTableState, "198.51.100.10 via 172.30.0.11 dev eth0") {
		t.Fatalf("reroute table %s missing nexthop route:\n%s", rerouteTable, rerouteTableState)
	}
	dropTableState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "route", "show", "table", dropTable)
	if !strings.Contains(dropTableState, "blackhole 203.0.113.0/24") {
		t.Fatalf("drop table %s missing blackhole route:\n%s", dropTable, dropTableState)
	}

	rerouteLookup := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip route get 198.51.100.10 from 10.10.0.11 ipproto tcp dport 443")
	if !strings.Contains(rerouteLookup, "table "+rerouteTable) || !strings.Contains(rerouteLookup, "via 172.30.0.11 dev eth0") {
		t.Fatalf("policy route lookup did not use reroute table %s:\n%s", rerouteTable, rerouteLookup)
	}
	missLookup := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip route get 198.51.100.10 from 10.10.0.11 ipproto tcp dport 8443")
	if strings.Contains(missLookup, "table "+rerouteTable) {
		t.Fatalf("policy route lookup unexpectedly matched reroute table %s on dport miss:\n%s", rerouteTable, missLookup)
	}

	cleanupOutput := applyState(desiredLinuxPolicyRoutingStateWithoutPoliciesJSON())
	if !strings.Contains(cleanupOutput, "policy_routes=0") {
		t.Fatalf("cleanup policy-route reconcile did not remove routes:\n%s", cleanupOutput)
	}
	waitForNodeBPolicyRouteCleanup(t, ctx, composeFile, rerouteTable, dropTable)
}

func waitForNodeBPolicyRouteCleanup(t *testing.T, ctx context.Context, composeFile, rerouteTable, dropTable string) {
	t.Helper()
	cmd := "for i in $(seq 1 20); do " +
		"! ip rule show | grep -q '198.51.100.10' && " +
		"! ip rule show | grep -q '203.0.113.0/24' && " +
		"[ -z \"$(ip route show table " + rerouteTable + ")\" ] && " +
		"[ -z \"$(ip route show table " + dropTable + ")\" ] && exit 0; " +
		"sleep 1; done; " +
		"echo 'rules:'; ip rule show; " +
		"echo 'reroute:'; ip route show table " + rerouteTable + "; " +
		"echo 'drop:'; ip route show table " + dropTable + "; " +
		"exit 1"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", cmd)
}

func mustLookupTableForDestination(t *testing.T, rules, destination string) string {
	t.Helper()
	pattern := regexp.MustCompile(`lookup ([0-9]+)`)
	for _, line := range strings.Split(strings.TrimSpace(rules), "\n") {
		if !strings.Contains(line, destination) {
			continue
		}
		match := pattern.FindStringSubmatch(line)
		if len(match) == 2 {
			return match[1]
		}
	}
	t.Fatalf("did not find lookup table for %q in rules:\n%s", destination, rules)
	return ""
}

func desiredLinuxPolicyRoutingStateJSON() string {
	return `{
  "vpcs": [{"name": "prod"}],
  "subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1"}],
  "endpoints": [{"id": "pod-b", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.11", "node": "node-b", "security_groups": []}],
  "policy_routes": [
    {"name": "https-via-fw", "vpc": "prod", "priority": 200, "match": {"source": "10.10.0.0/24", "destination": "198.51.100.10/32", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["172.30.0.11"]}},
    {"name": "deny-test", "vpc": "prod", "priority": 100, "match": {"source": "10.10.0.0/24", "destination": "203.0.113.0/24"}, "action": {"type": "drop"}}
  ],
  "security_groups": []
}`
}

func desiredLinuxPolicyRoutingStateWithoutPoliciesJSON() string {
	return `{
  "vpcs": [{"name": "prod"}],
  "subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1"}],
  "endpoints": [{"id": "pod-b", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.11", "node": "node-b", "security_groups": []}],
  "security_groups": []
}`
}
