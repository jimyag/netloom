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

func TestDockerLinuxPolicyRoutingProgramsAndCleansECMPRuntimeState(t *testing.T) {
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

	statePath := "/tmp/netloom-policy-route-ecmp-state.json"
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

	applyOutput := applyState(desiredLinuxPolicyRoutingECMPStateJSON())
	if !strings.Contains(applyOutput, "policy_routes=1") {
		t.Fatalf("ECMP policy-route reconcile did not program one route:\n%s", applyOutput)
	}

	rules := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "rule", "show")
	if !strings.Contains(rules, "from 10.10.0.0/24 to 198.51.100.10 ipproto tcp dport 443") {
		t.Fatalf("ECMP policy rule missing expected match:\n%s", rules)
	}
	rerouteTable := mustLookupTableForDestination(t, rules, "198.51.100.10")
	rerouteTableState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "route", "show", "table", rerouteTable)
	for _, expected := range []string{
		"198.51.100.10",
		"nexthop via 172.30.0.11 dev eth0",
		"nexthop via 172.30.0.12 dev eth0",
	} {
		if !strings.Contains(rerouteTableState, expected) {
			t.Fatalf("ECMP reroute table %s missing %q:\n%s", rerouteTable, expected, rerouteTableState)
		}
	}

	rerouteLookup := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip route get 198.51.100.10 from 10.10.0.11 ipproto tcp dport 443")
	if !strings.Contains(rerouteLookup, "table "+rerouteTable) {
		t.Fatalf("ECMP policy route lookup did not use reroute table %s:\n%s", rerouteTable, rerouteLookup)
	}

	cleanupOutput := applyState(desiredLinuxPolicyRoutingStateWithoutPoliciesJSON())
	if !strings.Contains(cleanupOutput, "policy_routes=0") {
		t.Fatalf("cleanup ECMP policy-route reconcile did not remove route:\n%s", cleanupOutput)
	}
	waitForNodeBPolicyRouteCleanup(t, ctx, composeFile, rerouteTable, rerouteTable)
}

func TestDockerLinuxPolicyRoutingAllowUsesMainTable(t *testing.T) {
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

	statePath := "/tmp/netloom-policy-route-allow-state.json"
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

	applyOutput := applyState(desiredLinuxPolicyRoutingAllowStateJSON())
	if !strings.Contains(applyOutput, "policy_routes=2") {
		t.Fatalf("allow policy-route reconcile did not program two routes:\n%s", applyOutput)
	}

	rules := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "rule", "show")
	if !strings.Contains(rules, "from 10.10.0.0/24 to 198.51.100.10 ipproto tcp dport 443 lookup main") {
		t.Fatalf("allow policy rule missing lookup main:\n%s", rules)
	}
	if !strings.Contains(rules, "from 10.10.0.0/24 to 203.0.113.0/24") {
		t.Fatalf("drop policy rule missing expected match:\n%s", rules)
	}

	dropTable := mustLookupTableForDestination(t, rules, "203.0.113.0/24")
	managedRouteState := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip route show table all | grep '198.51.100.10' || true")
	if strings.Contains(managedRouteState.output, "table "+dropTable) || strings.Contains(managedRouteState.output, "198.51.100.10/32") {
		t.Fatalf("allow policy route unexpectedly programmed managed route state:\n%s", managedRouteState.output)
	}

	allowLookup := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip route get 198.51.100.10 from 10.10.0.11 ipproto tcp dport 443")
	if strings.Contains(allowLookup, "table "+dropTable) || strings.Contains(strings.ToLower(allowLookup), "unreachable") {
		t.Fatalf("allow policy route lookup did not stay on main table:\n%s", allowLookup)
	}

	cleanupOutput := applyState(desiredLinuxPolicyRoutingStateWithoutPoliciesJSON())
	if !strings.Contains(cleanupOutput, "policy_routes=0") {
		t.Fatalf("cleanup allow policy-route reconcile did not remove routes:\n%s", cleanupOutput)
	}
	waitForNodeBPolicyRouteCleanup(t, ctx, composeFile, dropTable, dropTable)
}

func TestDockerLinuxPolicyRoutingRejectUsesUnreachableRoute(t *testing.T) {
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

	statePath := "/tmp/netloom-policy-route-reject-state.json"
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

	applyOutput := applyState(desiredLinuxPolicyRoutingRejectStateJSON())
	if !strings.Contains(applyOutput, "policy_routes=1") {
		t.Fatalf("reject policy-route reconcile did not program one route:\n%s", applyOutput)
	}

	rules := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "rule", "show")
	if !strings.Contains(rules, "from 10.10.0.0/24 to 203.0.113.0/24 ipproto tcp dport 443") {
		t.Fatalf("reject policy rule missing expected match:\n%s", rules)
	}
	rejectTable := mustLookupTableForDestination(t, rules, "203.0.113.0/24")
	rejectTableState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "route", "show", "table", rejectTable)
	if !strings.Contains(rejectTableState, "unreachable 203.0.113.0/24") {
		t.Fatalf("reject table %s missing unreachable route:\n%s", rejectTable, rejectTableState)
	}
	rejectLookup := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip route get 203.0.113.10 from 10.10.0.11 ipproto tcp dport 443 2>&1")
	if rejectLookup.exitCode == 0 || !strings.Contains(strings.ToLower(rejectLookup.output), "unreachable") {
		t.Fatalf("reject policy route lookup should fail as unreachable, exit=%d output:\n%s", rejectLookup.exitCode, rejectLookup.output)
	}

	cleanupOutput := applyState(desiredLinuxPolicyRoutingStateWithoutPoliciesJSON())
	if !strings.Contains(cleanupOutput, "policy_routes=0") {
		t.Fatalf("cleanup reject policy-route reconcile did not remove route:\n%s", cleanupOutput)
	}
	waitForNodeBPolicyRouteCleanup(t, ctx, composeFile, rejectTable, rejectTable)
}

func TestDockerLinuxPolicyRoutingProgramsIPv6RuntimeState(t *testing.T) {
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
	ipv6Check := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip -6 -o addr show dev eth0 | grep -q 'fd00:30::12'")
	if ipv6Check.exitCode != 0 {
		t.Fatalf("node-b does not have expected IPv6 underlay address:\n%s", ipv6Check.output)
	}

	statePath := "/tmp/netloom-policy-route-ipv6-state.json"
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

	applyOutput := applyState(desiredLinuxIPv6PolicyRoutingStateJSON())
	if !strings.Contains(applyOutput, "policy_routes=1") {
		t.Fatalf("IPv6 policy-route reconcile did not program one route:\n%s", applyOutput)
	}

	rules := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "-6", "rule", "show")
	for _, expected := range []string{
		"from fd00:10::/64 to fd00:40::/64 ipproto tcp dport 8443",
		"proto bgp",
	} {
		if !strings.Contains(rules, expected) {
			t.Fatalf("IPv6 policy rules missing %q:\n%s", expected, rules)
		}
	}

	rerouteTable := mustLookupTableForDestination(t, rules, "fd00:40::/64")
	rerouteTableState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "-6", "route", "show", "table", rerouteTable)
	if !strings.Contains(rerouteTableState, "fd00:40::/64 via fd00:30::11 dev eth0") {
		t.Fatalf("IPv6 reroute table %s missing nexthop route:\n%s", rerouteTable, rerouteTableState)
	}

	rerouteLookup := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip -6 route get fd00:40::10 from fd00:10::11 ipproto tcp dport 8443")
	if !strings.Contains(rerouteLookup, "table "+rerouteTable) || !strings.Contains(rerouteLookup, "via fd00:30::11 dev eth0") {
		t.Fatalf("IPv6 policy route lookup did not use reroute table %s:\n%s", rerouteTable, rerouteLookup)
	}
	missLookup := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip -6 route get fd00:40::10 from fd00:10::11 ipproto tcp dport 443")
	if strings.Contains(missLookup, "table "+rerouteTable) {
		t.Fatalf("IPv6 policy route lookup unexpectedly matched reroute table %s on dport miss:\n%s", rerouteTable, missLookup)
	}

	cleanupOutput := applyState(desiredLinuxIPv6PolicyRoutingStateWithoutPoliciesJSON())
	if !strings.Contains(cleanupOutput, "policy_routes=0") {
		t.Fatalf("cleanup IPv6 policy-route reconcile did not remove route:\n%s", cleanupOutput)
	}
	waitForNodeBIPv6PolicyRouteCleanup(t, ctx, composeFile, rerouteTable)
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

func waitForNodeBIPv6PolicyRouteCleanup(t *testing.T, ctx context.Context, composeFile, table string) {
	t.Helper()
	cmd := "for i in $(seq 1 20); do " +
		"! ip -6 rule show | grep -q 'fd00:40::/64' && " +
		"[ -z \"$(ip -6 route show table " + table + ")\" ] && exit 0; " +
		"sleep 1; done; " +
		"echo 'ipv6 rules:'; ip -6 rule show; " +
		"echo 'ipv6 reroute:'; ip -6 route show table " + table + "; " +
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

func desiredLinuxPolicyRoutingECMPStateJSON() string {
	return `{
  "vpcs": [{"name": "prod"}],
  "subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1"}],
  "endpoints": [{"id": "pod-b", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.11", "node": "node-b", "security_groups": []}],
  "policy_routes": [
    {"name": "https-via-fw", "vpc": "prod", "priority": 200, "match": {"source": "10.10.0.0/24", "destination": "198.51.100.10/32", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["172.30.0.11", "172.30.0.12"]}}
  ],
  "security_groups": []
}`
}

func desiredLinuxPolicyRoutingAllowStateJSON() string {
	return `{
  "vpcs": [{"name": "prod"}],
  "subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1"}],
  "endpoints": [{"id": "pod-b", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.11", "node": "node-b", "security_groups": []}],
  "policy_routes": [
    {"name": "allow-https", "vpc": "prod", "priority": 300, "match": {"source": "10.10.0.0/24", "destination": "198.51.100.10/32", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "allow"}},
    {"name": "deny-test", "vpc": "prod", "priority": 100, "match": {"source": "10.10.0.0/24", "destination": "203.0.113.0/24"}, "action": {"type": "drop"}}
  ],
  "security_groups": []
}`
}

func desiredLinuxPolicyRoutingRejectStateJSON() string {
	return `{
  "vpcs": [{"name": "prod"}],
  "subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1"}],
  "endpoints": [{"id": "pod-b", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.11", "node": "node-b", "security_groups": []}],
  "policy_routes": [
    {"name": "reject-test", "vpc": "prod", "priority": 150, "match": {"source": "10.10.0.0/24", "destination": "203.0.113.0/24", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reject"}}
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

func desiredLinuxIPv6PolicyRoutingStateJSON() string {
	return `{
  "vpcs": [{"name": "prod6"}],
  "subnets": [{"name": "apps6", "vpc": "prod6", "cidr": "fd00:10::/64", "gateway": "fd00:10::1"}],
  "endpoints": [{"id": "pod-b6", "vpc": "prod6", "subnet": "apps6", "ip": "fd00:10::11", "node": "node-b", "security_groups": []}],
  "policy_routes": [
    {"name": "ipv6-via-fw", "vpc": "prod6", "priority": 200, "match": {"source": "fd00:10::/64", "destination": "fd00:40::/64", "protocol": "tcp", "dst_ports": [{"from": 8443, "to": 8443}]}, "action": {"type": "reroute", "next_hops": ["fd00:30::11"]}}
  ],
  "security_groups": []
}`
}

func desiredLinuxIPv6PolicyRoutingStateWithoutPoliciesJSON() string {
	return `{
  "vpcs": [{"name": "prod6"}],
  "subnets": [{"name": "apps6", "vpc": "prod6", "cidr": "fd00:10::/64", "gateway": "fd00:10::1"}],
  "endpoints": [{"id": "pod-b6", "vpc": "prod6", "subnet": "apps6", "ip": "fd00:10::11", "node": "node-b", "security_groups": []}],
  "security_groups": []
}`
}
