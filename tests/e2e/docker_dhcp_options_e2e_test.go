package e2e

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerControllerProgramsDHCPDNSAndSearchDomains(t *testing.T) {
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

	statePath := "/tmp/netloom-dhcp-options-state.json"
	stateScript := "cat >" + statePath + " <<'EOF'\n" + desiredStateWithDHCPDNSAndSearchDomainsJSON() + "\nEOF\n" +
		"NETLOOM_STATE_FILE=" + statePath +
		" NETLOOM_OVN_LIBOVSDB_ENDPOINT=unix:/var/run/ovn/ovnnb_db.sock" +
		" /netloom/bin/netloom-controller"
	controllerOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateScript)
	for _, expected := range []string{"reconciled desired state", "subnets=1", "endpoints=1", "ovn_ops=", "ovn_executed="} {
		if !strings.Contains(controllerOutput, expected) {
			t.Fatalf("dhcp state controller output missing %q:\n%s", expected, controllerOutput)
		}
	}

	dhcpOptionsID := strings.TrimSpace(run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lsp-get-dhcpv4-options", "nl_lp_file_file-pod-a"))
	if dhcpOptionsID == "" || dhcpOptionsID == "[]" {
		t.Fatalf("OVN endpoint DHCP options were not bound: %q", dhcpOptionsID)
	}
	dhcpOptionsID = strings.Fields(dhcpOptionsID)[0]
	dhcpOptions := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "dhcp-options-get-options", dhcpOptionsID)
	for _, expected := range []string{
		`dns_server=["10.96.0.10"]`,
		`domain_name=svc.cluster.local`,
		`domain_search_list=["cluster.local","svc.cluster.local"]`,
		"lease_time=7200",
		"mtu=1400",
	} {
		if !strings.Contains(dhcpOptions, expected) {
			t.Fatalf("OVN DHCP options missing %q:\n%s", expected, dhcpOptions)
		}
	}
}

func desiredStateWithDHCPDNSAndSearchDomainsJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "provider_networks": [{"name": "physnet-a", "nodes": [{"node": "node-a", "interface": "eth0"}, {"node": "node-b", "interface": "eth0"}]}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400, "dns_servers": ["10.96.0.10"], "domain_name": "svc.cluster.local", "search_domains": ["cluster.local", "svc.cluster.local"]}}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a"}]
}`
}
