package e2e

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"
)

func requireDockerE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("NETLOOM_E2E") != "1" {
		t.Skip("set NETLOOM_E2E=1 to run docker e2e tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
}

func tcxSelftestInterface(t *testing.T, ctx context.Context, composeFile, service string) (string, string) {
	t.Helper()
	for _, iface := range []string{"lo", "eth0", "eth1"} {
		result := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "link", "show", "dev", iface)
		if result.exitCode != 0 || strings.TrimSpace(result.output) == "" {
			continue
		}
		return iface, defaultIPv4ForInterface(t, ctx, composeFile, service, iface)
	}
	exists := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "link")
	t.Fatalf("no tcx selftest interface found on %s. links:\n%s", service, strings.TrimSpace(exists.output))
	return "", ""
}

func defaultIPv4ForInterface(t *testing.T, ctx context.Context, composeFile, service, iface string) string {
	t.Helper()
	result := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "-4", "-o", "addr", "show", "dev", iface)
	if result.exitCode != 0 {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(result.output), "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "inet" {
				parts := strings.Split(fields[i+1], "/")
				if len(parts) == 2 && parts[0] != "" {
					return parts[0]
				}
			}
		}
	}
	return ""
}

type netloomOVNInventory struct {
	logicalRouters []string
	logicalSwitch  []string
	endpoints      []string
	loadBalancers  []string
}

func endpointExternalIDForOVN(vpc, endpoint string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(vpc + "\x00" + endpoint))
}

func describeNetloomOVNInventory(t *testing.T, ctx context.Context, composeFile, endpointID string) netloomOVNInventory {
	t.Helper()
	return netloomOVNInventory{
		logicalRouters: listNetloomOVNNames(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file"),
		logicalSwitch:  listNetloomOVNNames(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file"),
		endpoints: listNetloomOVNNames(t, ctx, composeFile, "logical_switch_port",
			"external_ids:netloom_owner=netloom",
			"external_ids:netloom_vpc=file",
			"external_ids:netloom_endpoint="+endpointID),
		loadBalancers: listNetloomOVNNames(t, ctx, composeFile, "load_balancer",
			"external_ids:netloom_owner=netloom",
			"external_ids:netloom_vpc=file"),
	}
}

func listNetloomOVNNames(t *testing.T, ctx context.Context, composeFile, table string, filters ...string) []string {
	t.Helper()
	args := []string{"docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=name", "find", table}
	args = append(args, filters...)
	output := run(t, ctx, args[0], args[1:]...)
	names := strings.Fields(strings.TrimSpace(output))
	sort.Strings(names)
	return names
}

func runInNetworkNamespace(t *testing.T, ctx context.Context, composeFile, service, namespace string, nsArgs ...string) string {
	t.Helper()
	waitForNetworkNamespace(t, ctx, composeFile, service, namespace)
	args := append([]string{"docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "netns", "exec", namespace}, nsArgs...)
	return run(t, ctx, args[0], args[1:]...)
}

func runInNetworkNamespaceAllowFailure(t *testing.T, ctx context.Context, composeFile, service, namespace string, nsArgs ...string) commandResult {
	t.Helper()
	waitForNetworkNamespace(t, ctx, composeFile, service, namespace)
	args := append([]string{"docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "netns", "exec", namespace}, nsArgs...)
	return runAllowFailure(t, ctx, args[0], args[1:]...)
}

func waitForNetworkNamespace(t *testing.T, ctx context.Context, composeFile, service, namespace string) {
	t.Helper()
	var lastOutput string
	for i := 0; i < 120; i++ {
		result := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "netns", "list")
		lastOutput = result.output
		if result.exitCode == 0 {
			for _, line := range strings.Split(strings.TrimSpace(result.output), "\n") {
				fields := strings.Fields(line)
				if len(fields) > 0 && fields[0] == namespace {
					return
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("namespace %q was not found in %s on node %s, namespaces now: %s", namespace, composeFile, service, strings.TrimSpace(lastOutput))
}

func workloadNamespace(vpc, endpointID string) string {
	return "nl-" + sanitizeForNetNS(vpc+"\x00"+endpointID)
}

func sanitizeForNetNS(value string) string {
	var out strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-':
			out.WriteRune(r)
		case r == '_':
			out.WriteString("__")
		case r == '.':
			out.WriteString("_d")
		case r == '/':
			out.WriteString("_s")
		case r == ':':
			out.WriteString("_c")
		case r == '@':
			out.WriteString("_a")
		case r == ' ':
			out.WriteString("_w")
		default:
			out.WriteString("_x")
			out.WriteString(fmt.Sprintf("%06x", r))
		}
	}
	return out.String()
}

func findLogicalPortByEndpointID(t *testing.T, ctx context.Context, composeFile, endpointID string) string {
	t.Helper()
	result := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=name", "find", "logical_switch_port", "external_ids:netloom_endpoint="+endpointID)
	return strings.TrimSpace(result.output)
}

func detectDefaultEBPFPolicyMapRoot(t *testing.T, ctx context.Context, composeFile, service string) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "for dir in /sys/fs/bpf/netloom/policy /var/run/netloom-ebpf/policy; do if [ -d \"$dir\" ] && ls \"$dir\"/nlp* >/dev/null 2>&1; then echo \"$dir\"; exit 0; fi; done; exit 1")
		if output.exitCode == 0 {
			return strings.TrimSpace(output.output)
		}
		time.Sleep(500 * time.Millisecond)
	}
	debug := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "ls -la /sys/fs/bpf/netloom 2>/dev/null || true; ls -la /var/run/netloom-ebpf 2>/dev/null || true")
	t.Fatalf("default eBPF policy map root did not appear on %s:\n%s", service, debug)
	return ""
}

func waitForEBPFPolicyMapCount(t *testing.T, ctx context.Context, composeFile, service, root string, want int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "count=$(find "+root+" -maxdepth 1 -type f | wc -l); [ \"$count\" = \""+fmt.Sprint(want)+"\" ] && exit 0 || { echo \"$count\"; exit 1; }")
		if output.exitCode == 0 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	debug := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "find "+root+" -maxdepth 1 -type f | sort")
	t.Fatalf("eBPF policy map count under %s did not converge to %d:\n%s", root, want, debug)
}

func waitForEBPFPolicyMetadataCount(t *testing.T, ctx context.Context, composeFile, service, root string, want int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "count=$(find "+root+" -maxdepth 1 -name '*.meta' | wc -l); [ \"$count\" = \""+fmt.Sprint(want)+"\" ] && exit 0 || { echo \"$count\"; exit 1; }")
		if output.exitCode == 0 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	debug := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "find "+root+" -maxdepth 1 -name '*.meta' | sort")
	t.Fatalf("eBPF policy metadata count under %s did not converge to %d:\n%s", root, want, debug)
}

func waitForManagedLinkCount(t *testing.T, ctx context.Context, composeFile, service, prefix string, want int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "count=$(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep '^"+prefix+"' | wc -l); [ \"$count\" = \""+fmt.Sprint(want)+"\" ] && exit 0 || { echo \"$count\"; exit 1; }")
		if output.exitCode == 0 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	debug := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | sort")
	t.Fatalf("managed link prefix %s count on %s did not converge to %d:\n%s", prefix, service, want, debug)
}

func findLoadBalancerForVIP(t *testing.T, ctx context.Context, composeFile, vpc, name, vip string) string {
	t.Helper()
	result := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=name", "find", "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc, "external_ids:netloom_load_balancer="+name)
	if result.exitCode != 0 {
		return ""
	}
	loadBalancers := strings.Fields(strings.TrimSpace(result.output))
	for _, lb := range loadBalancers {
		vips := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "get", "load_balancer", lb, "vips")
		if vips.exitCode == 0 && strings.Contains(vips.output, vip) {
			return lb
		}
	}
	return ""
}
