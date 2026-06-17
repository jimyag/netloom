package e2e

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerControllerClearsLocalnetTagWhenProviderVLANIsRemoved(t *testing.T) {
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
			" NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock" +
			" /netloom/bin/netloom-controller"
		return run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", script)
	}

	initialOutput := applyState("/tmp/netloom-provider-vlan-initial.json", desiredStateWithProviderNetworkVLANJSON())
	if !strings.Contains(initialOutput, "reconciled desired state") {
		t.Fatalf("initial provider vlan reconcile failed:\n%s", initialOutput)
	}

	localnetTag := strings.TrimSpace(run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lsp-get-tag", "nl_ls_file_fileapps_to_fileapps_localnet"))
	if localnetTag != "100" {
		t.Fatalf("initial OVN localnet tag = %q, want 100", localnetTag)
	}

	updatedOutput := applyState("/tmp/netloom-provider-vlan-cleared.json", desiredStateWithProviderNetworkWithoutVLANJSON())
	if !strings.Contains(updatedOutput, "reconciled desired state") {
		t.Fatalf("updated provider vlan reconcile failed:\n%s", updatedOutput)
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do list=$(ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-list nl_ls_file_fileapps 2>/dev/null || true); opts=$(ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-get-options nl_ls_file_fileapps_to_fileapps_localnet 2>/dev/null || true); tag=$(ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-get-tag nl_ls_file_fileapps_to_fileapps_localnet 2>/dev/null || true); echo \"$list\" | grep -q nl_ls_file_fileapps_to_fileapps_localnet || { sleep 1; continue; }; echo \"$opts\" | grep -q 'network_name=physnet-a' || { sleep 1; continue; }; [ -z \"$tag\" ] || [ \"$tag\" = \"[]\" ] && exit 0; sleep 1; done; echo 'localnet-port:'; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-list nl_ls_file_fileapps; echo 'localnet-options:'; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-get-options nl_ls_file_fileapps_to_fileapps_localnet; echo 'localnet-tag:'; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-get-tag nl_ls_file_fileapps_to_fileapps_localnet; exit 1")
}

func desiredStateWithProviderNetworkVLANJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "provider_networks": [{"name": "physnet-a", "nodes": [{"node": "node-a", "interface": "eth0"}]}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "mac": "0A:58:0A:F5:00:0A", "node": "node-a"}]
}`
}

func desiredStateWithProviderNetworkWithoutVLANJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "provider_networks": [{"name": "physnet-a", "nodes": [{"node": "node-a", "interface": "eth0"}]}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a"}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "mac": "0A:58:0A:F5:00:0A", "node": "node-a"}]
}`
}
