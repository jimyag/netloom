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
		" NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock" +
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

func TestDockerControllerTransitionsDistributedGatewayAndCleansDistributedFloatingIP(t *testing.T) {
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

	applyState := func(path, stateJSON string) string {
		script := "cat >" + path + " <<'EOF'\n" + stateJSON + "\nEOF\n" +
			"NETLOOM_STATE_FILE=" + path +
			" NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock" +
			" /netloom/bin/netloom-controller"
		return run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", script)
	}

	initialOutput := applyState("/tmp/netloom-distributed-gateway-initial.json", desiredStateWithDistributedGatewayAndFloatingIPsJSON())
	if !strings.Contains(initialOutput, "reconciled desired state") {
		t.Fatalf("initial distributed state reconcile failed:\n%s", initialOutput)
	}
	if got := activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dist", "external_ids:netloom_nat=web-fip"); len(got) != 1 {
		t.Fatalf("expected one distributed fip row after initial reconcile, got %v", got)
	}

	updatedOutput := applyState("/tmp/netloom-distributed-gateway-updated.json", desiredStateWithCentralizedGatewayWithoutFloatingIPsJSON())
	if !strings.Contains(updatedOutput, "reconciled desired state") {
		t.Fatalf("updated centralized state reconcile failed:\n%s", updatedOutput)
	}

	routerExternalIDs := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "get", "logical_router", "nl_lr_dist", "external_ids")
	if !strings.Contains(routerExternalIDs, `netloom_gateway_distributed="false"`) {
		t.Fatalf("expected centralized gateway external_ids after update:\n%s", routerExternalIDs)
	}
	routerOptions := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "get", "logical_router", "nl_lr_dist", "options")
	if !strings.Contains(routerOptions, "chassis=node-a") {
		t.Fatalf("expected centralized gateway chassis pin after update:\n%s", routerOptions)
	}
	if got := activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dist", "external_ids:netloom_nat=web-fip"); len(got) != 0 {
		t.Fatalf("expected distributed fip row to be cleaned after update, got %v", got)
	}
}

func TestDockerControllerClearsStaleNATPortMetadata(t *testing.T) {
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

	applyState := func(path, stateJSON string) string {
		script := "cat >" + path + " <<'EOF'\n" + stateJSON + "\nEOF\n" +
			"NETLOOM_STATE_FILE=" + path +
			" NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock" +
			" /netloom/bin/netloom-controller"
		return run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", script)
	}

	initialOutput := applyState("/tmp/netloom-nat-port-initial.json", desiredStateWithPortMappedDNATJSON())
	if !strings.Contains(initialOutput, "reconciled desired state") {
		t.Fatalf("initial port-mapped NAT reconcile failed:\n%s", initialOutput)
	}
	rows := activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=natmeta", "external_ids:netloom_nat=ssh-port")
	if len(rows) != 1 {
		t.Fatalf("expected one managed ssh-port NAT row after initial reconcile, got %v", rows)
	}
	initialNAT := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "list", "NAT", rows[0])
	for _, expected := range []string{
		"external_port_range : \"2222\"",
		"netloom_logical_port_range=\"2222\"",
		"netloom_protocol=tcp",
		"netloom_external_port=\"2222\"",
		"netloom_target_port=\"2222\"",
	} {
		if !strings.Contains(initialNAT, expected) {
			t.Fatalf("initial NAT row missing %q:\n%s", expected, initialNAT)
		}
	}

	updatedOutput := applyState("/tmp/netloom-nat-port-updated.json", desiredStateWithPlainDNATJSON())
	if !strings.Contains(updatedOutput, "reconciled desired state") {
		t.Fatalf("updated plain NAT reconcile failed:\n%s", updatedOutput)
	}
	rows = activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=natmeta", "external_ids:netloom_nat=ssh-port")
	if len(rows) != 1 {
		t.Fatalf("expected one managed ssh-port NAT row after update, got %v", rows)
	}
	updatedNAT := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "list", "NAT", rows[0])
	for _, stale := range []string{
		"external_port_range : \"2222\"",
		"netloom_logical_port_range",
		"netloom_protocol",
		"netloom_external_port",
		"netloom_target_port",
	} {
		if strings.Contains(updatedNAT, stale) {
			t.Fatalf("updated NAT row retained stale %q:\n%s", stale, updatedNAT)
		}
	}
	if !strings.Contains(updatedNAT, "logical_ip          : \"10.245.0.10\"") {
		t.Fatalf("updated NAT row lost DNAT target:\n%s", updatedNAT)
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

func desiredStateWithPortMappedDNATJSON() string {
	return `{
  "vpcs": [{"name": "natmeta"}],
  "subnets": [{"name": "apps", "vpc": "natmeta", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1"}],
  "endpoints": [
    {"id": "pod-a", "vpc": "natmeta", "subnet": "apps", "ip": "10.245.0.10", "mac": "0A:58:0A:F5:00:0A", "node": "node-a"}
  ],
  "gateways": [{"name": "gw-natmeta", "vpc": "natmeta", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [
    {"name": "ssh-port", "vpc": "natmeta", "type": "dnat", "external_ip": "198.51.100.23", "target_ip": "10.245.0.10", "protocol": "tcp", "external_port": 2222, "target_port": 2222}
  ]
}`
}

func desiredStateWithPlainDNATJSON() string {
	return `{
  "vpcs": [{"name": "natmeta"}],
  "subnets": [{"name": "apps", "vpc": "natmeta", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1"}],
  "endpoints": [
    {"id": "pod-a", "vpc": "natmeta", "subnet": "apps", "ip": "10.245.0.10", "mac": "0A:58:0A:F5:00:0A", "node": "node-a"}
  ],
  "gateways": [{"name": "gw-natmeta", "vpc": "natmeta", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [
    {"name": "ssh-port", "vpc": "natmeta", "type": "dnat", "external_ip": "198.51.100.23", "target_ip": "10.245.0.10"}
  ]
}`
}

func desiredStateWithCentralizedGatewayWithoutFloatingIPsJSON() string {
	return `{
  "vpcs": [{"name": "dist"}],
  "subnets": [{"name": "apps", "vpc": "dist", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1"}],
  "endpoints": [
    {"id": "dist-pod-a", "vpc": "dist", "subnet": "apps", "ip": "10.245.0.10", "mac": "0A:58:0A:F5:00:0A", "node": "node-a"}
  ],
  "gateways": [{"name": "gw-dist", "vpc": "dist", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254", "distributed": false}]
}`
}
