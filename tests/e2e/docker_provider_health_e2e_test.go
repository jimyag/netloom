package e2e

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerProviderHealthStrictFailsForDegradedLink(t *testing.T) {
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

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-c", "sh", "-c", "command -v ip >/dev/null 2>&1 || apk add --no-cache iproute2")

	workloadStateNodeCScript := "cat >/tmp/netloom-workload-node-c-state.json <<'EOF'\n" + desiredProviderOnlyStateWithMappedNodeCJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-workload-node-c-state.json NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth0 NETLOOM_LINUX_DATAPATH_CLEANUP=1 NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-b=172.30.0.12 "
	initialOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-c", "sh", "-c", workloadStateNodeCScript+"NETLOOM_NODE_NAME=node-c /netloom/bin/netloom-agent")
	for _, expected := range []string{"datapath=linux:netns", "provider_networks=1", "provider_links=1", "provider_status=physnet-a:eth0:100:"} {
		if !strings.Contains(initialOutput, expected) {
			t.Fatalf("initial provider link reconcile missing %q:\n%s", expected, initialOutput)
		}
	}
	waitForManagedLinkCount(t, ctx, composeFile, "node-c", "nlv", 1)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-c", "sh", "-c", "ip link set eth0 down; for i in $(seq 1 10); do [ \"$(cat /sys/class/net/eth0/operstate 2>/dev/null)\" = down ] && exit 0; sleep 1; done; ip -o link show dev eth0; exit 1")
	t.Cleanup(func() {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer restoreCancel()
		runAllowFailure(t, restoreCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-c", "ip", "link", "set", "eth0", "up")
	})

	strictOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-c", "sh", "-c", workloadStateNodeCScript+"NETLOOM_PROVIDER_HEALTH_STRICT=1 NETLOOM_NODE_NAME=node-c /netloom/bin/netloom-agent")
	if strictOutput.exitCode == 0 {
		t.Fatalf("expected strict provider health reconcile to fail while parent link is down:\n%s", strictOutput.output)
	}
	for _, expected := range []string{"provider health degraded", "ready=0 degraded=1", "physnet-a:eth0:100:"} {
		if !strings.Contains(strictOutput.output, expected) {
			t.Fatalf("strict provider health failure missing %q:\n%s", expected, strictOutput.output)
		}
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-c", "sh", "-c", "ip link set eth0 up; for i in $(seq 1 10); do [ \"$(cat /sys/class/net/eth0/operstate 2>/dev/null)\" = up ] && exit 0; sleep 1; done; ip -o link show dev eth0; exit 1")
	recoveredOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-c", "sh", "-c", workloadStateNodeCScript+"NETLOOM_PROVIDER_HEALTH_STRICT=1 NETLOOM_NODE_NAME=node-c /netloom/bin/netloom-agent")
	for _, expected := range []string{"provider_ready=1", "provider_degraded=0", "provider_status=physnet-a:eth0:100:"} {
		if !strings.Contains(recoveredOutput, expected) {
			t.Fatalf("recovered strict provider health reconcile missing %q:\n%s", expected, recoveredOutput)
		}
	}
}

func TestDockerProviderHealthAutoDiscoversCandidateInterface(t *testing.T) {
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

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-c", "sh", "-c", "command -v ip >/dev/null 2>&1 || apk add --no-cache iproute2")

	workloadStateNodeCScript := "cat >/tmp/netloom-workload-node-c-state.json <<'EOF'\n" + desiredProviderOnlyStateWithCandidateNodeCJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-workload-node-c-state.json NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_LINUX_DATAPATH_CLEANUP=1 NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-b=172.30.0.12 "
	output := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-c", "sh", "-c", workloadStateNodeCScript+"NETLOOM_NODE_NAME=node-c /netloom/bin/netloom-agent")
	for _, expected := range []string{"datapath=linux:netns", "provider_networks=1", "provider_links=1", "provider_ready=1", "provider_status=physnet-a:eth0:100:"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("candidate provider interface reconcile missing %q:\n%s", expected, output)
		}
	}
	waitForManagedLinkCount(t, ctx, composeFile, "node-c", "nlv", 1)
}

func desiredProviderOnlyStateWithMappedNodeCJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "provider_networks": [{"name": "physnet-a", "nodes": [{"node": "node-c", "interface": "eth0"}]}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100}],
  "endpoints": [],
  "security_groups": []
}`
}

func desiredProviderOnlyStateWithCandidateNodeCJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "provider_networks": [{"name": "physnet-a", "nodes": [{"node": "node-c", "interfaces": ["ens9", "eth0"]}]}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100}],
  "endpoints": [],
  "security_groups": []
}`
}
