package e2e

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerControllerProgramsDistributedGatewayAndFloatingIPs(t *testing.T) {
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

	statePath := "/tmp/netloom-distributed-gateway-nat-state.json"
	stateScript := "cat >" + statePath + " <<'EOF'\n" + desiredStateWithDistributedGatewayAndFloatingIPsJSON() + "\nEOF\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock" +
		" /netloom/bin/netloom-controller"
	controllerOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateScript)
	for _, expected := range []string{"reconciled desired state", "gateways=1", "nat_rules=1", "ovn_ops=", "ovn_executed="} {
		if !strings.Contains(controllerOutput, expected) {
			t.Fatalf("distributed gateway/fip controller output missing %q:\n%s", expected, controllerOutput)
		}
	}

	routerExternalIDs := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "get", "logical_router", "nl_lr_dist", "external_ids")
	for _, expected := range []string{"netloom_gateway=gw-dist", "netloom_external_if=eth0", `netloom_gateway_lan_ip="10.245.0.254"`, `netloom_gateway_distributed="true"`} {
		if !strings.Contains(routerExternalIDs, expected) {
			t.Fatalf("distributed gateway external IDs missing %q:\n%s", expected, routerExternalIDs)
		}
	}
	routerOptions := strings.TrimSpace(run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "get", "logical_router", "nl_lr_dist", "options"))
	if strings.Contains(routerOptions, "chassis=") {
		t.Fatalf("distributed gateway must not pin chassis:\n%s", routerOptions)
	}

	webRows := activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dist", "external_ids:netloom_nat=web-fip")
	if len(webRows) != 1 {
		t.Fatalf("expected one managed distributed fip nat row, got %v", webRows)
	}
	webNAT := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "list", "NAT", webRows[0])
	for _, expected := range []string{
		"type                : dnat_and_snat",
		"external_ip         : \"198.51.100.31\"",
		"logical_ip          : \"10.245.0.10\"",
		"logical_port        : nl_lp_dist_dist-pod-a",
		"external_mac        : \"0a:58:0a:f5:00:0a\"",
	} {
		if !strings.Contains(webNAT, expected) {
			t.Fatalf("distributed fip nat row missing %q:\n%s", expected, webNAT)
		}
	}

	if got := activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dist", "external_ids:netloom_nat=dns-fip"); len(got) != 0 {
		t.Fatalf("unexpected translated distributed fip nat rows in plain e2e scenario: %v", got)
	}
}

func desiredStateWithDistributedGatewayAndFloatingIPsJSON() string {
	return `{
  "vpcs": [{"name": "dist"}],
  "subnets": [{"name": "apps", "vpc": "dist", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1"}],
  "endpoints": [
    {"id": "dist-pod-a", "vpc": "dist", "subnet": "apps", "ip": "10.245.0.10", "mac": "0A:58:0A:F5:00:0A", "node": "node-a"}
  ],
  "gateways": [{"name": "gw-dist", "vpc": "dist", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254", "distributed": true}],
  "nat_rules": [
    {"name": "web-fip", "vpc": "dist", "type": "dnat_and_snat", "external_ip": "198.51.100.31", "target_ip": "10.245.0.10", "logical_port": "nl_lp_dist_dist-pod-a", "external_mac": "0a:58:0a:f5:00:0a"}
  ]
}`
}
