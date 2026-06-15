package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerMultiNodeLab(t *testing.T) {
	requireDockerE2E(t)
	if os.Getenv("NETLOOM_E2E") != "1" {
		t.Skip("set NETLOOM_E2E=1 to run docker e2e tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	cmdPattern := filepath.ToSlash(filepath.Join("..", "..", "cmd")) + "/..."
	run(t, ctx, "env", "CGO_ENABLED=0", "go", "build", "-trimpath", "-o", filepath.Join("..", "..", "bin")+"/", cmdPattern)
	startComposeLab(t, ctx, composeFile)
	waitForOVN(t, ctx, composeFile)

	for _, service := range []string{"node-a", "node-b", "node-c"} {
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "command -v ip >/dev/null 2>&1 || for i in $(seq 1 5); do apk add --no-cache iproute2 && exit 0; sleep 2; done; apk add --no-cache iproute2")
		ipVersion := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "-V")
		if !strings.Contains(ipVersion, "iproute2") {
			t.Fatalf("%s does not have iproute2 installed, output:\n%s", service, ipVersion)
		}
		output := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "addr")
		if !strings.Contains(output, "172.30.0.") {
			t.Fatalf("%s did not receive fabric ip, output:\n%s", service, output)
		}
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ping", "-c", "1", "172.30.0.12")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ping", "-c", "1", "172.30.0.13")

	controllerOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "/netloom/bin/netloom-controller")
	if !strings.Contains(controllerOutput, "reconciled bootstrap state") {
		t.Fatalf("controller output did not show reconcile success:\n%s", controllerOutput)
	}
	for _, expected := range []string{"policy_next_hop=10.244.0.253", "snat=198.51.100.10", "gateway=gw-a", "service_backend=10.244.0.10:8080", "dnat=10.244.0.10", "floating_ip=10.244.0.10", "ovn_ops=", "ovn_executed="} {
		if !strings.Contains(controllerOutput, expected) {
			t.Fatalf("controller output missing %q:\n%s", expected, controllerOutput)
		}
	}
	liveControllerOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "-e", "NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock", "ovn-central", "/netloom/bin/netloom-controller")
	for _, expected := range []string{"ovn_ops=", "ovn_executed="} {
		if !strings.Contains(liveControllerOutput, expected) {
			t.Fatalf("live controller output missing %q:\n%s", expected, liveControllerOutput)
		}
	}
	stateScript := "cat >/tmp/netloom-state.json <<'EOF'\n" + desiredStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-state.json /netloom/bin/netloom-controller"
	stateOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", stateScript)
	for _, expected := range []string{"reconciled desired state", "vpcs=1", "policy_routes=1", "policy_entries=", "ovn_ops=", "ovn_executed="} {
		if !strings.Contains(stateOutput, expected) {
			t.Fatalf("state-file controller output missing %q:\n%s", expected, stateOutput)
		}
	}
	liveStateScript := "cat >/tmp/netloom-state.json <<'EOF'\n" + desiredStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-state.json NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
	liveStateOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", liveStateScript)
	for _, expected := range []string{"reconciled desired state", "policy_routes=1", "nat_rules=4", "load_balancers=1", "security_groups=1"} {
		if !strings.Contains(liveStateOutput, expected) {
			t.Fatalf("live state-file controller output missing %q:\n%s", expected, liveStateOutput)
		}
	}
	policyState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-policy-list", "nl_lr_file")
	for _, expected := range []string{"tcp.src == 32000", "tcp.dst == 443", "10.245.0.253"} {
		if !strings.Contains(policyState, expected) {
			t.Fatalf("OVN policy route state missing %q:\n%s", expected, policyState)
		}
	}
	nbState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "show")
	for _, expected := range []string{"nl_lr_default", "nl_ls_default_apps", "nl_lr_file", "nl_ls_file_fileapps"} {
		if !strings.Contains(nbState, expected) {
			t.Fatalf("OVN NB state missing %q:\n%s", expected, nbState)
		}
	}
	gatewayExternalIDs := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "get", "logical_router", "nl_lr_file", "external_ids")
	for _, expected := range []string{"netloom_gateway=gw-file", "netloom_external_if=eth0", `netloom_gateway_lan_ip="10.245.0.254"`, `netloom_gateway_distributed="false"`} {
		if !strings.Contains(gatewayExternalIDs, expected) {
			t.Fatalf("OVN gateway external IDs missing %q:\n%s", expected, gatewayExternalIDs)
		}
	}
	gatewayOptions := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "get", "logical_router", "nl_lr_file", "options")
	if !strings.Contains(gatewayOptions, "chassis=node-a") {
		t.Fatalf("OVN centralized gateway options missing chassis pin:\n%s", gatewayOptions)
	}
	localnetOptions := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lsp-get-options", "nl_ls_file_fileapps_to_fileapps_localnet")
	if !strings.Contains(localnetOptions, "network_name=physnet-a") {
		t.Fatalf("OVN localnet options missing provider network:\n%s", localnetOptions)
	}
	localnetTag := strings.TrimSpace(run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lsp-get-tag", "nl_ls_file_fileapps_to_fileapps_localnet"))
	if localnetTag != "100" {
		t.Fatalf("OVN localnet tag = %q, want 100", localnetTag)
	}
	dhcpOptionsID := strings.TrimSpace(run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lsp-get-dhcpv4-options", "nl_lp_file_file-pod-a"))
	if dhcpOptionsID == "" || dhcpOptionsID == "[]" {
		t.Fatalf("OVN endpoint DHCP options were not bound: %q", dhcpOptionsID)
	}
	dhcpOptionsID = strings.Fields(dhcpOptionsID)[0]
	dhcpOptions := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "dhcp-options-get-options", dhcpOptionsID)
	for _, expected := range []string{"lease_time=7200", "mtu=1400", "router=10.245.0.1", "server_id=10.245.0.1"} {
		if !strings.Contains(dhcpOptions, expected) {
			t.Fatalf("OVN DHCP options missing %q:\n%s", expected, dhcpOptions)
		}
	}
	natState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-nat-list", "nl_lr_file")
	for _, expected := range []string{"snat", "198.51.100.20", "dnat", "198.51.100.21", "dnat_and_snat", "198.51.100.22", "2222"} {
		if !strings.Contains(natState, expected) {
			t.Fatalf("OVN NAT state missing %q:\n%s", expected, natState)
		}
	}
	tcpLB := findLoadBalancerForVIP(t, ctx, composeFile, "file", "file-web", "10.96.0.10:80")
	if tcpLB == "" {
		t.Fatal("expected tcp load balancer row for file-web vip 10.96.0.10:80")
	}
	lbState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lb-list", tcpLB)
	for _, expected := range []string{"10.96.0.10:80", "10.245.0.10:8080"} {
		if !strings.Contains(lbState, expected) {
			t.Fatalf("OVN LB state missing %q:\n%s", expected, lbState)
		}
	}
	udpLB := findLoadBalancerForVIP(t, ctx, composeFile, "file", "file-web", "10.96.0.10:53")
	if udpLB == "" {
		t.Fatal("expected udp load balancer row for file-web vip 10.96.0.10:53")
	}
	udpLBState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lb-list", udpLB)
	for _, expected := range []string{"10.96.0.10:53", "10.245.0.10:5353"} {
		if !strings.Contains(udpLBState, expected) {
			t.Fatalf("OVN UDP LB state missing %q:\n%s", expected, udpLBState)
		}
	}
	controllerWatchPath := "/tmp/netloom-controller-watch-state.json"
	controllerWatchTmpTemplate := "/tmp/netloom-controller-watch-state-XXXXXXXXXXXX.tmp"
	atomicControllerWatchState := func(stateJSON string) string {
		return "tmp=$(mktemp " + controllerWatchTmpTemplate + ") && cat >\"$tmp\" <<'EOF'\n" + stateJSON + "\nEOF\nmv \"$tmp\" " + controllerWatchPath
	}
	startControllerWatch := atomicControllerWatchState(desiredStateJSON()) + "\nNETLOOM_STATE_FILE=" + controllerWatchPath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock NETLOOM_RECONCILE_INTERVAL_MS=500 /netloom/bin/netloom-controller >/tmp/netloom-controller-watch.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", startControllerWatch)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do grep -q 'reconciled desired state' /tmp/netloom-controller-watch.log 2>/dev/null && exit 0; sleep 1; done; cat /tmp/netloom-controller-watch.log; exit 1")
	updateControllerWatch := atomicControllerWatchState(desiredStateWithUpdatedLoadBalancerJSON())
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", updateControllerWatch)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do vips=$(ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock get load_balancer nl_lb_file_file-web_tcp vips); echo \"$vips\" | grep -q '10.96.0.20:80' && echo \"$vips\" | grep -q '10.245.0.11:8080' && ! echo \"$vips\" | grep -q '10.96.0.10:80' && exit 0; sleep 1; done; cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock get load_balancer nl_lb_file_file-web_tcp vips; exit 1")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lb-list | grep -q nl_lb_file_file-web_udp || exit 0; sleep 1; done; cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lb-list; exit 1")
	updateControllerWatch = atomicControllerWatchState(desiredStateWithUpdatedNATJSON())
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", updateControllerWatch)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do nat=$(ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-nat-list nl_lr_file); echo \"$nat\" | grep -q '198.51.100.50' && ! echo \"$nat\" | grep -q '198.51.100.20' && exit 0; sleep 1; done; cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-nat-list nl_lr_file; exit 1")
	updateControllerWatch = atomicControllerWatchState(desiredStateWithUpdatedPolicyRouteJSON())
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", updateControllerWatch)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do policies=$(ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-policy-list nl_lr_file); echo \"$policies\" | grep -q '10.245.0.252' && ! echo \"$policies\" | grep -q '10.245.0.253' && exit 0; sleep 1; done; cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-policy-list nl_lr_file; exit 1")
	updateControllerWatch = atomicControllerWatchState(desiredStateWithUpdatedStaticRouteJSON())
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", updateControllerWatch)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do routes=$(ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-route-list nl_lr_file); echo \"$routes\" | grep -q '10.245.0.251' && ! echo \"$routes\" | grep -q '10.245.0.254' && exit 0; sleep 1; done; cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-route-list nl_lr_file; exit 1")
	updateControllerWatch = atomicControllerWatchState(desiredStateWithStaticRouteToECMPJSON())
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", updateControllerWatch)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do routes=$(ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-route-list nl_lr_file); echo \"$routes\" | grep -q '10.245.0.251' && echo \"$routes\" | grep -q '10.245.0.252' && exit 0; sleep 1; done; cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-route-list nl_lr_file; exit 1")
	updateControllerWatch = atomicControllerWatchState(desiredStateWithStaticRouteFromECMPToSingleJSON())
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", updateControllerWatch)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do routes=$(ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-route-list nl_lr_file); echo \"$routes\" | grep -q '10.245.0.252' && ! echo \"$routes\" | grep -q '10.245.0.251' && exit 0; sleep 1; done; cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-route-list nl_lr_file; exit 1")
	updateControllerWatch = atomicControllerWatchState(desiredStateWithoutProviderNetworkJSON())
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", updateControllerWatch)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-list nl_ls_file_fileapps | grep -q nl_ls_file_fileapps_to_fileapps_localnet || exit 0; sleep 1; done; cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-list nl_ls_file_fileapps; exit 1")
	updateControllerWatch = atomicControllerWatchState(desiredStateWithoutDHCPJSON())
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", updateControllerWatch)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do options=$(ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-get-dhcpv4-options nl_lp_file_file-pod-a); [ -z \"$options\" ] || [ \"$options\" = \"[]\" ] && exit 0; sleep 1; done; cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-get-dhcpv4-options nl_lp_file_file-pod-a; exit 1")
	updateControllerWatch = atomicControllerWatchState(desiredStateWithoutEndpointNATJSON())
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", updateControllerWatch)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-list nl_ls_file_fileapps | grep -q nl_lp_file_file-pod-a || exit 0; sleep 1; done; cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-list nl_ls_file_fileapps; exit 1")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-list nl_ls_file_fileapps | grep -q nl_ls_file_fileapps_to_fileapps_localnet || { cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-list nl_ls_file_fileapps; exit 1; }")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock dhcp-options-list | grep -q netloom_endpoint=file-pod-a && { cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock dhcp-options-list; exit 1; } || exit 0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-nat-list nl_lr_file | grep -q 198.51.100.20 && { cat /tmp/netloom-controller-watch.log; exit 1; } || exit 0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lb-list | grep -q nl_lb_file_file-web_tcp && { cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lb-list; exit 1; } || exit 0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "pkill", "-f", "netloom-controller")
	agentOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "-e", "NETLOOM_TCX_SELFTEST_IFACE=lo", "node-b", "/netloom/bin/netloom-agent")
	if !strings.Contains(agentOutput, "ready for node policy") {
		t.Fatalf("agent output did not show ready state:\n%s", agentOutput)
	}
	for _, expected := range []string{"endpoint=default\x00selftest-pod", "entries=", "allow=allow", "deny=drop", "policy_allowed=3", "policy_dropped=1", "policy_conntrack=1", "policy_established=1", "policy_logged=3", "rule_stats=", "0:p=1,b=64,a=1,d=0,r=0,nm=0,ct=1,est=0,log=0", "drop_events=1", "policy_events=3", "trace_events=4", "tcx=attached:lo:ingress:verdict:pass"} {
		if !strings.Contains(agentOutput, expected) {
			t.Fatalf("agent output missing %q:\n%s", expected, agentOutput)
		}
	}
	agentStateScript := "cat >/tmp/netloom-state.json <<'EOF'\n" + desiredStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-state.json NETLOOM_NODE_NAME=node-a /netloom/bin/netloom-agent"
	agentStateOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", agentStateScript)
	for _, expected := range []string{"reconciled node policy", "node=node-a", "endpoints=1", "programs=1", "entries=1", "policy_added=1", "policy_events=1", "policy_revision_max=1", "tcx_eligible=0"} {
		if !strings.Contains(agentStateOutput, expected) {
			t.Fatalf("state-file agent output missing %q:\n%s", expected, agentStateOutput)
		}
	}
	dnsObservationScript := "cat >/tmp/netloom-dns-state.json <<'EOF'\n" + desiredDNSObservationStateJSON() + "\nEOF\ncat >/tmp/netloom-dns-observations.json <<'EOF'\n" + dnsObservationJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-dns-state.json NETLOOM_DNS_OBSERVATIONS_FILE=/tmp/netloom-dns-observations.json NETLOOM_NODE_NAME=node-a /netloom/bin/netloom-agent"
	dnsObservationOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", dnsObservationScript)
	for _, expected := range []string{"reconciled node policy", "node=node-a", "endpoints=1", "programs=1", "entries=1", "policy_added=1", "policy_events=1", "policy_revision_max=1", "tcx_eligible=0"} {
		if !strings.Contains(dnsObservationOutput, expected) {
			t.Fatalf("DNS observation state-file agent output missing %q:\n%s", expected, dnsObservationOutput)
		}
	}
	agentOtherNodeScript := "cat >/tmp/netloom-state.json <<'EOF'\n" + desiredStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-state.json NETLOOM_NODE_NAME=node-b /netloom/bin/netloom-agent"
	agentOtherNodeOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentOtherNodeScript)
	for _, expected := range []string{"reconciled node policy", "node=node-b", "endpoints=0", "programs=0", "entries=0", "policy_events=0", "policy_revision_max=0"} {
		if !strings.Contains(agentOtherNodeOutput, expected) {
			t.Fatalf("other-node state-file agent output missing %q:\n%s", expected, agentOtherNodeOutput)
		}
	}
	workloadStateScript := "cat >/tmp/netloom-workload-state.json <<'EOF'\n" + desiredWorkloadStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-workload-state.json NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth0 NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-b=172.30.0.12 "
	nodeAWorkloadOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", workloadStateScript+"NETLOOM_NODE_NAME=node-a /netloom/bin/netloom-agent")
	for _, expected := range []string{"datapath=linux:netns", "local_ips=1", "remote_routes=1", "policy_added=1", "policy_events=1", "policy_revision_max=1"} {
		if !strings.Contains(nodeAWorkloadOutput, expected) {
			t.Fatalf("node-a workload datapath output missing %q:\n%s", expected, nodeAWorkloadOutput)
		}
	}
	nodeBWorkloadOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", workloadStateScript+"NETLOOM_NODE_NAME=node-b /netloom/bin/netloom-agent")
	for _, expected := range []string{"datapath=linux:netns", "local_ips=1", "remote_routes=1", "policy_added=1", "policy_events=1", "policy_revision_max=1"} {
		if !strings.Contains(nodeBWorkloadOutput, expected) {
			t.Fatalf("node-b workload datapath output missing %q:\n%s", expected, nodeBWorkloadOutput)
		}
	}
	filePodA := workloadNamespace("file", "file-pod-a")
	filePodB := workloadNamespace("file", "file-pod-b")
	filePodC := workloadNamespace("file", "file-pod-c")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ip", "netns", "exec", filePodA, "ping", "-c", "1", "-W", "1", "10.245.0.11")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip netns exec "+filePodB+" sh -c 'while true; do printf ok | nc -l -p 8080 >/dev/null; done' >/tmp/netloom-ns-nc.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ip", "netns", "exec", filePodA, "sh", "-c", "printf hi | nc -w 1 10.245.0.11 8080")
	watchStatePath := "/tmp/netloom-workload-watch-state.json"
	metadataRoot := "/var/run/netloom-ebpf-meta/policy"
	startWatchScript := "cat >" + watchStatePath + " <<'EOF'\n" + desiredWorkloadStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=" + watchStatePath + " NETLOOM_NODE_NAME=node-b NETLOOM_POLICY_STORE=ebpf NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth0 NETLOOM_LINUX_DATAPATH_CLEANUP=1 NETLOOM_RECONCILE_INTERVAL_MS=500 NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-b=172.30.0.12 NETLOOM_TCX_WORKLOAD=1 /netloom/bin/netloom-agent >/tmp/netloom-agent-watch.log 2>&1 &"
	restartWatchScript := "cat /dev/null >/tmp/netloom-agent-watch.log\nNETLOOM_STATE_FILE=" + watchStatePath + " NETLOOM_NODE_NAME=node-b NETLOOM_POLICY_STORE=ebpf NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth0 NETLOOM_LINUX_DATAPATH_CLEANUP=1 NETLOOM_RECONCILE_INTERVAL_MS=500 NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-b=172.30.0.12 NETLOOM_TCX_WORKLOAD=1 /netloom/bin/netloom-agent >/tmp/netloom-agent-watch.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", startWatchScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do grep -q 'reconciled node policy' /tmp/netloom-agent-watch.log 2>/dev/null && grep -q 'tcx=not-attached' /tmp/netloom-agent-watch.log 2>/dev/null && exit 0; sleep 1; done; cat /tmp/netloom-agent-watch.log; exit 1")
	waitForManagedLinkCount(t, ctx, composeFile, "node-b", "nlv", 1)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ip", "netns", "exec", filePodA, "sh", "-c", "printf hi | nc -w 1 10.245.0.11 8080")
	updateWatchScript := "cat >" + watchStatePath + " <<'EOF'\n" + desiredWorkloadPolicyDropStateJSON() + "\nEOF"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", updateWatchScript)
	nodeAWorkloadPolicyOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "cat >/tmp/netloom-workload-policy-state.json <<'EOF'\n"+desiredWorkloadPolicyDropStateJSON()+"\nEOF\n"+workloadStateScript+"NETLOOM_STATE_FILE=/tmp/netloom-workload-policy-state.json NETLOOM_NODE_NAME=node-a /netloom/bin/netloom-agent")
	for _, expected := range []string{"datapath=linux:netns", "local_ips=1", "remote_routes=2", "policy_added=1", "policy_events=1", "policy_revision_max=1"} {
		if !strings.Contains(nodeAWorkloadPolicyOutput, expected) {
			t.Fatalf("node-a workload policy datapath output missing %q:\n%s", expected, nodeAWorkloadPolicyOutput)
		}
	}
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ip", "netns", "exec", filePodA, "ping", "-c", "1", "-W", "1", "10.245.0.11")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+filePodA+" sh -c 'printf hi | nc -w 1 10.245.0.11 8080' >/tmp/netloom-workload-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-workload-probe.log; exit 1")
	workloadDropLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-watch.log")
	for _, expected := range []string{"reconciled node policy", "node=node-b", "store=ebpf", "datapath=linux:netns", "local_ips=2", "policy_added=3", "policy_deleted=1", "policy_events=2", "policy_revision_max=2", "tcx=attached-workloads:2:egress:policy-l4"} {
		if !strings.Contains(workloadDropLog, expected) {
			t.Fatalf("workload L4 drop agent output missing %q:\n%s", expected, workloadDropLog)
		}
	}
	pinRoot := detectDefaultEBPFPolicyMapRoot(t, ctx, composeFile, "node-b")
	waitForEBPFPolicyMapCount(t, ctx, composeFile, "node-b", pinRoot, 2)
	waitForEBPFPolicyMetadataCount(t, ctx, composeFile, "node-b", metadataRoot, 2)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "pkill", "-f", "/netloom/bin/netloom-agent")
	waitForEBPFPolicyMapCount(t, ctx, composeFile, "node-b", pinRoot, 2)
	waitForEBPFPolicyMetadataCount(t, ctx, composeFile, "node-b", metadataRoot, 2)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", restartWatchScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do grep -q 'tcx=attached-workloads:2:egress:policy-l4' /tmp/netloom-agent-watch.log 2>/dev/null && grep -q 'endpoints=2' /tmp/netloom-agent-watch.log 2>/dev/null && exit 0; sleep 1; done; cat /tmp/netloom-agent-watch.log; exit 1")
	waitForEBPFPolicyMapCount(t, ctx, composeFile, "node-b", pinRoot, 2)
	waitForEBPFPolicyMetadataCount(t, ctx, composeFile, "node-b", metadataRoot, 2)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+filePodA+" sh -c 'printf hi | nc -w 1 10.245.0.11 8080' >/tmp/netloom-workload-restart-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-workload-restart-probe.log; exit 1")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "netns", "exec", filePodC, "ip", "addr")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip netns exec "+filePodC+" sh -c 'while true; do printf ok | nc -l -p 8081 >/dev/null; done' >/tmp/netloom-ns-c-nc.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+filePodA+" sh -c 'printf hi | nc -w 1 10.245.0.12 8081' >/tmp/netloom-workload-cidr-allow-probe.log 2>&1 && exit 0; sleep 1; done; cat /tmp/netloom-workload-cidr-allow-probe.log; exit 1")
	updateWatchScript = ": >/tmp/netloom-agent-watch.log\ncat >" + watchStatePath + " <<'EOF'\n" + desiredWorkloadICMPDropStateJSON() + "\nEOF"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", updateWatchScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do grep -q 'policy_added=1' /tmp/netloom-agent-watch.log 2>/dev/null && grep -q 'policy_deleted=1' /tmp/netloom-agent-watch.log 2>/dev/null && exit 0; sleep 1; done; cat /tmp/netloom-agent-watch.log; exit 1")
	icmpDrop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+filePodA+" ping -c 1 -W 1 10.245.0.11 >/tmp/netloom-workload-icmp-drop-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-workload-icmp-drop-probe.log; exit 1")
	if icmpDrop.exitCode != 0 {
		icmpDropLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-watch.log")
		t.Fatalf("expected TCX ICMP policy to drop pod-a ping to pod-b, probe:\n%s\nagent log:\n%s", icmpDrop.output, icmpDropLog)
	}
	updateWatchScript = "cat >" + watchStatePath + " <<'EOF'\n" + desiredWorkloadCleanupStateJSON() + "\nEOF"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", updateWatchScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+filePodA+" sh -c 'printf hi | nc -w 1 10.245.0.11 8080' >/tmp/netloom-workload-probe.log 2>&1 && exit 0; sleep 1; done; cat /tmp/netloom-workload-probe.log; exit 1")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+filePodC+" ip addr >/dev/null 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-agent-watch.log; exit 1")
	waitForManagedLinkCount(t, ctx, composeFile, "node-b", "nlv", 0)
	watchLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-watch.log")
	for _, expected := range []string{"datapath=linux:netns", "local_ips=1", "cleanup=true"} {
		if !strings.Contains(watchLog, expected) {
			t.Fatalf("watch cleanup log missing %q:\n%s", expected, watchLog)
		}
	}
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "pkill", "-f", "netloom-agent")
	podBAddr := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "netns", "exec", filePodB, "ip", "addr", "show", "eth0")
	if !strings.Contains(podBAddr, "10.245.0.11") {
		t.Fatalf("pod-b namespace was not preserved:\n%s", podBAddr)
	}
	stalePodC := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "netns", "exec", filePodC, "ip", "addr")
	if stalePodC.exitCode == 0 {
		t.Fatalf("expected stale pod-c namespace to be deleted, output:\n%s", stalePodC.output)
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "NETLOOM_TCX_SELFTEST_IFACE=eth0 NETLOOM_TCX_VERDICT=drop NETLOOM_TCX_SRC4=172.30.0.11 NETLOOM_TCX_HOLD_MS=2500 /netloom/bin/netloom-agent >/tmp/netloom-agent-drop.log 2>&1 &")
	time.Sleep(700 * time.Millisecond)
	dropOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ping", "-c", "1", "-W", "1", "172.30.0.12")
	if dropOutput.exitCode == 0 {
		dropLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-drop.log 2>/dev/null || true")
		t.Fatalf("expected ping to node-b to fail while TCX drop is attached, output:\n%s\nagent log:\n%s", dropOutput.output, dropLog)
	}
	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ping", "-c", "1", "-W", "1", "172.30.0.12")
	dropLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-drop.log")
	if !strings.Contains(dropLog, "tcx=attached:eth0:ingress:src4:drop") {
		t.Fatalf("drop agent output missing TCX drop status:\n%s", dropLog)
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -p 8080 >/dev/null; done >/tmp/netloom-nc.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.12 8080")
	agentPolicyDropScript := "cat >/tmp/netloom-policy-drop-state.json <<'EOF'\n" + desiredPolicyDropStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-policy-drop-state.json NETLOOM_NODE_NAME=node-b NETLOOM_POLICY_STORE=ebpf NETLOOM_TCX_IFACE=eth0 NETLOOM_TCX_HOLD_MS=2500 /netloom/bin/netloom-agent >/tmp/netloom-agent-l4-drop.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentPolicyDropScript)
	time.Sleep(700 * time.Millisecond)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ping", "-c", "1", "-W", "1", "172.30.0.12")
	l4DropOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.12 8080")
	if l4DropOutput.exitCode == 0 {
		l4DropLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-l4-drop.log 2>/dev/null || true")
		t.Fatalf("expected TCP/8080 to fail while L4 TCX drop is attached, output:\n%s\nagent log:\n%s", l4DropOutput.output, l4DropLog)
	}
	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.12 8080")
	l4DropLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-l4-drop.log")
	for _, expected := range []string{"reconciled node policy", "node=node-b", "store=ebpf", "endpoints=1", "tcx=attached:eth0:ingress:policy-l4"} {
		if !strings.Contains(l4DropLog, expected) {
			t.Fatalf("L4 drop agent output missing %q:\n%s", expected, l4DropLog)
		}
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.120/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.121/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.120 -p 8080 >/dev/null; done >/tmp/netloom-multi-local-120-8080.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.121 -p 8080 >/dev/null; done >/tmp/netloom-multi-local-121-8080.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.121 -p 8081 >/dev/null; done >/tmp/netloom-multi-local-121-8081.log 2>&1 &")
	agentMultiLocalScript := "cat >/tmp/netloom-multi-local-state.json <<'EOF'\n" + desiredSharedInterfaceMultiEndpointStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-multi-local-state.json NETLOOM_NODE_NAME=node-b NETLOOM_POLICY_STORE=ebpf NETLOOM_TCX_IFACE=eth0 NETLOOM_TCX_HOLD_MS=2500 /netloom/bin/netloom-agent >/tmp/netloom-agent-multi-local.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentMultiLocalScript)
	time.Sleep(700 * time.Millisecond)
	multiLocalDrop120 := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.120 8080")
	if multiLocalDrop120.exitCode == 0 {
		multiLocalLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-multi-local.log 2>/dev/null || true")
		t.Fatalf("expected TCP/8080 to 172.30.0.120 to fail while multi-endpoint TCX policy is attached, output:\n%s\nagent log:\n%s", multiLocalDrop120.output, multiLocalLog)
	}
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.121 8080")
	multiLocalDrop121 := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.121 8081")
	if multiLocalDrop121.exitCode == 0 {
		multiLocalLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-multi-local.log 2>/dev/null || true")
		t.Fatalf("expected TCP/8081 to 172.30.0.121 to fail while multi-endpoint TCX policy is attached, output:\n%s\nagent log:\n%s", multiLocalDrop121.output, multiLocalLog)
	}
	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.120 8080")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.121 8081")
	multiLocalLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-multi-local.log")
	for _, expected := range []string{"reconciled node policy", "node=node-b", "store=ebpf", "endpoints=2", "tcx_eligible=2", "tcx=attached:eth0:ingress:policy-l4"} {
		if !strings.Contains(multiLocalLog, expected) {
			t.Fatalf("multi-endpoint shared-interface agent output missing %q:\n%s", expected, multiLocalLog)
		}
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.122/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "addr", "add", "172.30.0.123/24", "dev", "eth0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.122 -p 8082 >/dev/null; done >/tmp/netloom-mixed-local-122-8082.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "while true; do printf ok | nc -l -p 9090 >/dev/null; done >/tmp/netloom-mixed-egress-9090.log 2>&1 &")
	agentMixedLocalScript := "cat >/tmp/netloom-mixed-local-state.json <<'EOF'\n" + desiredSharedInterfaceBidirectionalStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-mixed-local-state.json NETLOOM_NODE_NAME=node-b NETLOOM_POLICY_STORE=ebpf NETLOOM_TCX_IFACE=eth0 NETLOOM_TCX_HOLD_MS=2500 /netloom/bin/netloom-agent >/tmp/netloom-agent-mixed-local.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentMixedLocalScript)
	mixedIngressDrop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -w 1 172.30.0.122 8082 >/tmp/netloom-mixed-ingress-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-mixed-ingress-probe.log; exit 1")
	if mixedIngressDrop.exitCode == 0 {
		mixedLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-mixed-local.log 2>/dev/null || true")
		t.Fatalf("expected TCP/8082 to 172.30.0.122 to fail while mixed-direction TCX policy is attached, output:\n%s\nagent log:\n%s", mixedIngressDrop.output, mixedLog)
	}
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "printf hi | nc -s 172.30.0.122 -w 1 172.30.0.11 9090")
	mixedEgressDrop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -s 172.30.0.123 -w 1 172.30.0.11 9090 >/tmp/netloom-mixed-egress-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-mixed-egress-probe.log; exit 1")
	if mixedEgressDrop.exitCode == 0 {
		mixedLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-mixed-local.log 2>/dev/null || true")
		t.Fatalf("expected egress TCP/9090 from 172.30.0.123 to fail while mixed-direction TCX policy is attached, output:\n%s\nagent log:\n%s", mixedEgressDrop.output, mixedLog)
	}
	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.122 8082")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "printf hi | nc -s 172.30.0.123 -w 1 172.30.0.11 9090")
	mixedLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-mixed-local.log")
	for _, expected := range []string{"reconciled node policy", "node=node-b", "store=ebpf", "endpoints=2", "tcx_eligible=2", "tcx=attached:eth0:mixed:policy-l4"} {
		if !strings.Contains(mixedLog, expected) {
			t.Fatalf("mixed-direction shared-interface agent output missing %q:\n%s", expected, mixedLog)
		}
	}
}

func TestDockerIPv6WorkloadPolicyTCX(t *testing.T) {
	requireDockerE2E(t)
	if testing.Short() {
		t.Skip("skip long e2e test in short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	cmdPattern := filepath.ToSlash(filepath.Join("..", "..", "cmd")) + "/..."
	run(t, ctx, "env", "CGO_ENABLED=0", "go", "build", "-trimpath", "-o", filepath.Join("..", "..", "bin")+"/", cmdPattern)
	startComposeLab(t, ctx, composeFile)
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), time.Minute)
		defer downCancel()
		run(t, downCtx, "docker", "compose", "-f", composeFile, "down", "-v")
	})
	waitForOVN(t, ctx, composeFile)
	ensureIPNetNS := func(service string) {
		hasNetNS := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "netns", "list")
		if hasNetNS.exitCode == 0 {
			return
		}
		installOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "apk add --no-cache iproute2")
		if installOutput.exitCode != 0 {
			t.Skipf("node %s does not support ip netns and iproute2 install failed:\n%s", service, strings.TrimSpace(installOutput.output))
		}
		hasNetNS = runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "netns", "list")
		if hasNetNS.exitCode != 0 {
			t.Skipf("node %s still does not support ip netns after install:\n%s", service, strings.TrimSpace(hasNetNS.output))
		}
	}
	ensureIPNetNS("node-b")

	stateScript := "cat >/tmp/netloom-workload-ipv6-state.json <<'EOF'\n" + desiredWorkloadIPv6StateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-workload-ipv6-state.json NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns "
	nodeBOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", stateScript+"NETLOOM_NODE_NAME=node-b /netloom/bin/netloom-agent")
	if !strings.Contains(nodeBOutput, "datapath=linux:netns") {
		t.Fatalf("node-b ipv6 workload datapath did not succeed:\n%s", nodeBOutput)
	}

	podA := workloadNamespace("ipv6", "ipv6-pod-a")
	podB := workloadNamespace("ipv6", "ipv6-pod-b")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+podA+" ping -6 -c 1 -W 1 fd00:10:10::11 >/tmp/netloom-workload-ipv6-allow-probe.log 2>&1 && exit 0; sleep 1; done; cat /tmp/netloom-workload-ipv6-allow-probe.log; exit 1")

	watchStatePath := "/tmp/netloom-workload-ipv6-watch.json"
	startWatchScript := "cat >" + watchStatePath + " <<'EOF'\n" + desiredWorkloadIPv6ICMPDropStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=" + watchStatePath + " NETLOOM_NODE_NAME=node-b NETLOOM_POLICY_STORE=ebpf NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_LINUX_DATAPATH_CLEANUP=1 NETLOOM_RECONCILE_INTERVAL_MS=500 NETLOOM_TCX_WORKLOAD=1 /netloom/bin/netloom-agent >/tmp/netloom-agent-ipv6-watch.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", startWatchScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do grep -q 'tcx=attached' /tmp/netloom-agent-ipv6-watch.log 2>/dev/null && grep -q 'tcx_eligible=1' /tmp/netloom-agent-ipv6-watch.log 2>/dev/null && exit 0; sleep 1; done; cat /tmp/netloom-agent-ipv6-watch.log; exit 1")

	icmpDrop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+podA+" ping -6 -c 1 -W 1 fd00:10:10::11 >/tmp/netloom-workload-ipv6-drop-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-workload-ipv6-drop-probe.log; exit 1")
	if icmpDrop.exitCode != 0 {
		dropLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-ipv6-watch.log")
		t.Fatalf("expected IPv6 TCX policy to drop pod-a ping to pod-b, probe:\n%s\nagent log:\n%s", icmpDrop.output, dropLog)
	}
	runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "pkill", "-f", "/netloom/bin/netloom-agent")
	_ = podB
}

func TestDockerIPv6CrossNodeWorkloadPolicyTCX(t *testing.T) {
	requireDockerE2E(t)
	if testing.Short() {
		t.Skip("skip long e2e test in short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	cmdPattern := filepath.ToSlash(filepath.Join("..", "..", "cmd")) + "/..."
	run(t, ctx, "env", "CGO_ENABLED=0", "go", "build", "-trimpath", "-o", filepath.Join("..", "..", "bin")+"/", cmdPattern)
	startComposeLab(t, ctx, composeFile)
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), time.Minute)
		defer downCancel()
		run(t, downCtx, "docker", "compose", "-f", composeFile, "down", "-v")
	})
	waitForOVN(t, ctx, composeFile)

	ensureIPNetNS := func(service string) {
		hasNetNS := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "netns", "list")
		if hasNetNS.exitCode == 0 {
			return
		}
		installOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "apk add --no-cache iproute2")
		if installOutput.exitCode != 0 {
			t.Skipf("node %s does not support ip netns and iproute2 install failed:\n%s", service, strings.TrimSpace(installOutput.output))
		}
		hasNetNS = runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "netns", "list")
		if hasNetNS.exitCode != 0 {
			t.Skipf("node %s still does not support ip netns after install:\n%s", service, strings.TrimSpace(hasNetNS.output))
		}
	}
	ensureIPv6Fabric := func(service string) {
		check := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "ip -6 -o addr show dev eth0 | grep -q 'fd00:30::'")
		if check.exitCode != 0 {
			dump := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "-6", "addr", "show", "dev", "eth0")
			t.Skipf("node %s does not have IPv6 fabric address:\n%s", service, strings.TrimSpace(dump.output))
		}
	}
	for _, service := range []string{"node-a", "node-b"} {
		ensureIPNetNS(service)
		ensureIPv6Fabric(service)
	}

	stateScript := "cat >/tmp/netloom-workload-ipv6-cross-state.json <<'EOF'\n" + desiredWorkloadIPv6CrossNodeStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-workload-ipv6-cross-state.json NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-a=fd00:30::11,node-b=172.30.0.12,node-b=fd00:30::12 "
	nodeAOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", stateScript+"NETLOOM_NODE_NAME=node-a /netloom/bin/netloom-agent")
	if !strings.Contains(nodeAOutput, "datapath=linux:netns") || !strings.Contains(nodeAOutput, "remote_routes=1") {
		t.Fatalf("node-a cross-node ipv6 workload datapath did not succeed:\n%s", nodeAOutput)
	}
	nodeBOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", stateScript+"NETLOOM_NODE_NAME=node-b /netloom/bin/netloom-agent")
	if !strings.Contains(nodeBOutput, "datapath=linux:netns") || !strings.Contains(nodeBOutput, "remote_routes=1") {
		t.Fatalf("node-b cross-node ipv6 workload datapath did not succeed:\n%s", nodeBOutput)
	}

	podA := workloadNamespace("ipv6", "ipv6-pod-a")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+podA+" ping -6 -c 1 -W 1 fd00:10:20::11 >/tmp/netloom-workload-ipv6-cross-allow-probe.log 2>&1 && exit 0; sleep 1; done; cat /tmp/netloom-workload-ipv6-cross-allow-probe.log; ip -6 route show; exit 1")

	watchStatePath := "/tmp/netloom-workload-ipv6-cross-watch.json"
	startWatchScript := "cat >" + watchStatePath + " <<'EOF'\n" + desiredWorkloadIPv6CrossNodeICMPDropStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=" + watchStatePath + " NETLOOM_NODE_NAME=node-b NETLOOM_POLICY_STORE=ebpf NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_LINUX_DATAPATH_CLEANUP=1 NETLOOM_RECONCILE_INTERVAL_MS=500 NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-a=fd00:30::11,node-b=172.30.0.12,node-b=fd00:30::12 NETLOOM_TCX_WORKLOAD=1 /netloom/bin/netloom-agent >/tmp/netloom-agent-ipv6-cross-watch.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", startWatchScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do grep -q 'tcx=attached' /tmp/netloom-agent-ipv6-cross-watch.log 2>/dev/null && grep -q 'tcx_eligible=1' /tmp/netloom-agent-ipv6-cross-watch.log 2>/dev/null && exit 0; sleep 1; done; cat /tmp/netloom-agent-ipv6-cross-watch.log; exit 1")

	icmpDrop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+podA+" ping -6 -c 1 -W 1 fd00:10:20::11 >/tmp/netloom-workload-ipv6-cross-drop-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-workload-ipv6-cross-drop-probe.log; exit 1")
	if icmpDrop.exitCode != 0 {
		dropLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-ipv6-cross-watch.log")
		t.Fatalf("expected cross-node IPv6 TCX policy to drop pod-a ping to pod-b, probe:\n%s\nagent log:\n%s", icmpDrop.output, dropLog)
	}
	runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "pkill", "-f", "/netloom/bin/netloom-agent")
}

func TestDockerIPv6CrossNodeWorkloadL4PolicyTCX(t *testing.T) {
	requireDockerE2E(t)
	if testing.Short() {
		t.Skip("skip long e2e test in short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	cmdPattern := filepath.ToSlash(filepath.Join("..", "..", "cmd")) + "/..."
	run(t, ctx, "env", "CGO_ENABLED=0", "go", "build", "-trimpath", "-o", filepath.Join("..", "..", "bin")+"/", cmdPattern)
	startComposeLab(t, ctx, composeFile)
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), time.Minute)
		defer downCancel()
		run(t, downCtx, "docker", "compose", "-f", composeFile, "down", "-v")
	})
	waitForOVN(t, ctx, composeFile)

	ensureIPNetNS := func(service string) {
		hasNetNS := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "netns", "list")
		if hasNetNS.exitCode == 0 {
			return
		}
		installOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "apk add --no-cache iproute2")
		if installOutput.exitCode != 0 {
			t.Skipf("node %s does not support ip netns and iproute2 install failed:\n%s", service, strings.TrimSpace(installOutput.output))
		}
		hasNetNS = runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "netns", "list")
		if hasNetNS.exitCode != 0 {
			t.Skipf("node %s still does not support ip netns after install:\n%s", service, strings.TrimSpace(hasNetNS.output))
		}
	}
	ensureIPv6Fabric := func(service string) {
		check := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "ip -6 -o addr show dev eth0 | grep -q 'fd00:30::'")
		if check.exitCode != 0 {
			dump := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "-6", "addr", "show", "dev", "eth0")
			t.Skipf("node %s does not have IPv6 fabric address:\n%s", service, strings.TrimSpace(dump.output))
		}
	}
	for _, service := range []string{"node-a", "node-b"} {
		ensureIPNetNS(service)
		ensureIPv6Fabric(service)
	}

	stateScript := "cat >/tmp/netloom-workload-ipv6-cross-l4-state.json <<'EOF'\n" + desiredWorkloadIPv6CrossNodeL4StateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-workload-ipv6-cross-l4-state.json NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-a=fd00:30::11,node-b=172.30.0.12,node-b=fd00:30::12 "
	nodeAOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", stateScript+"NETLOOM_NODE_NAME=node-a /netloom/bin/netloom-agent")
	if !strings.Contains(nodeAOutput, "datapath=linux:netns") || !strings.Contains(nodeAOutput, "remote_routes=1") {
		t.Fatalf("node-a cross-node ipv6 l4 workload datapath did not succeed:\n%s", nodeAOutput)
	}
	nodeBOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", stateScript+"NETLOOM_NODE_NAME=node-b /netloom/bin/netloom-agent")
	if !strings.Contains(nodeBOutput, "datapath=linux:netns") || !strings.Contains(nodeBOutput, "remote_routes=1") {
		t.Fatalf("node-b cross-node ipv6 l4 workload datapath did not succeed:\n%s", nodeBOutput)
	}

	podA := workloadNamespace("ipv6", "ipv6-pod-a")
	podB := workloadNamespace("ipv6", "ipv6-pod-b")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip netns exec "+podB+" sh -c 'while true; do printf ok | nc -l -p 8080 >/dev/null; done' >/tmp/netloom-ipv6-cross-l4-nc.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+podA+" sh -c 'printf hi | nc -w 1 fd00:10:20::11 8080' >/tmp/netloom-workload-ipv6-cross-l4-allow-probe.log 2>&1 && exit 0; sleep 1; done; cat /tmp/netloom-workload-ipv6-cross-l4-allow-probe.log; exit 1")

	watchStatePath := "/tmp/netloom-workload-ipv6-cross-l4-watch.json"
	startWatchScript := "cat >" + watchStatePath + " <<'EOF'\n" + desiredWorkloadIPv6CrossNodeL4DropStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=" + watchStatePath + " NETLOOM_NODE_NAME=node-b NETLOOM_POLICY_STORE=ebpf NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_LINUX_DATAPATH_CLEANUP=1 NETLOOM_RECONCILE_INTERVAL_MS=500 NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-a=fd00:30::11,node-b=172.30.0.12,node-b=fd00:30::12 NETLOOM_TCX_WORKLOAD=1 /netloom/bin/netloom-agent >/tmp/netloom-agent-ipv6-cross-l4-watch.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", startWatchScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do grep -q 'tcx=attached' /tmp/netloom-agent-ipv6-cross-l4-watch.log 2>/dev/null && grep -q 'tcx_eligible=1' /tmp/netloom-agent-ipv6-cross-l4-watch.log 2>/dev/null && exit 0; sleep 1; done; cat /tmp/netloom-agent-ipv6-cross-l4-watch.log; exit 1")

	l4Drop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+podA+" sh -c 'printf hi | nc -w 1 fd00:10:20::11 8080' >/tmp/netloom-workload-ipv6-cross-l4-drop-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-workload-ipv6-cross-l4-drop-probe.log; exit 1")
	if l4Drop.exitCode != 0 {
		dropLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-ipv6-cross-l4-watch.log")
		t.Fatalf("expected cross-node IPv6 TCX L4 policy to drop pod-a tcp/8080 to pod-b, probe:\n%s\nagent log:\n%s", l4Drop.output, dropLog)
	}
	runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "pkill", "-f", "/netloom/bin/netloom-agent")
}

func TestDockerDualStackInterfaceL4PolicyTCX(t *testing.T) {
	requireDockerE2E(t)
	if testing.Short() {
		t.Skip("skip long e2e test in short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	cmdPattern := filepath.ToSlash(filepath.Join("..", "..", "cmd")) + "/..."
	run(t, ctx, "env", "CGO_ENABLED=0", "go", "build", "-trimpath", "-o", filepath.Join("..", "..", "bin")+"/", cmdPattern)
	startComposeLab(t, ctx, composeFile)
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), time.Minute)
		defer downCancel()
		run(t, downCtx, "docker", "compose", "-f", composeFile, "down", "-v")
	})
	waitForOVN(t, ctx, composeFile)

	ipv6Check := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip -6 -o addr show dev eth0 | grep -q 'fd00:30::12'")
	if ipv6Check.exitCode != 0 {
		dump := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "-6", "addr", "show", "dev", "eth0")
		t.Skipf("node-b does not have IPv6 fabric address:\n%s", strings.TrimSpace(dump.output))
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s 172.30.0.12 -p 8084 >/dev/null; done >/tmp/netloom-dual-v4-nc.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "while true; do printf ok | nc -l -s fd00:30::12 -p 8084 >/dev/null; done >/tmp/netloom-dual-v6-nc.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -w 1 172.30.0.12 8084 >/tmp/netloom-dual-v4-allow.log 2>&1 && exit 0; sleep 1; done; cat /tmp/netloom-dual-v4-allow.log; exit 1")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -w 1 fd00:30::12 8084 >/tmp/netloom-dual-v6-allow.log 2>&1 && exit 0; sleep 1; done; cat /tmp/netloom-dual-v6-allow.log; exit 1")

	agentStateScript := "cat >/tmp/netloom-dual-l4-state.json <<'EOF'\n" + desiredDualStackInterfaceDropStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-dual-l4-state.json NETLOOM_NODE_NAME=node-b NETLOOM_POLICY_STORE=ebpf NETLOOM_TCX_IFACE=eth0 NETLOOM_TCX_HOLD_MS=2500 /netloom/bin/netloom-agent >/tmp/netloom-agent-dual-l4.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentStateScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do grep -q 'tcx=attached:eth0:ingress:policy-l4-dual' /tmp/netloom-agent-dual-l4.log 2>/dev/null && exit 0; sleep 1; done; cat /tmp/netloom-agent-dual-l4.log; exit 1")

	v4Drop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -w 1 172.30.0.12 8084 >/tmp/netloom-dual-v4-drop.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-dual-v4-drop.log; exit 1")
	if v4Drop.exitCode == 0 {
		log := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-dual-l4.log 2>/dev/null || true")
		t.Fatalf("expected IPv4 TCP/8084 to fail while dual-stack TCX policy is attached, output:\n%s\nagent log:\n%s", v4Drop.output, log)
	}
	v6Drop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do printf hi | nc -w 1 fd00:30::12 8084 >/tmp/netloom-dual-v6-drop.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-dual-v6-drop.log; exit 1")
	if v6Drop.exitCode == 0 {
		log := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /tmp/netloom-agent-dual-l4.log 2>/dev/null || true")
		t.Fatalf("expected IPv6 TCP/8084 to fail while dual-stack TCX policy is attached, output:\n%s\nagent log:\n%s", v6Drop.output, log)
	}

	time.Sleep(3 * time.Second)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 172.30.0.12 8084")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "printf hi | nc -w 1 fd00:30::12 8084")
	dualLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-dual-l4.log")
	for _, expected := range []string{"reconciled node policy", "node=node-b", "store=ebpf", "endpoints=1", "tcx_eligible=1", "tcx=attached:eth0:ingress:policy-l4-dual"} {
		if !strings.Contains(dualLog, expected) {
			t.Fatalf("dual-stack interface agent output missing %q:\n%s", expected, dualLog)
		}
	}
}

func TestDockerIPv6CrossNodeWorkloadEgressL4PolicyTCX(t *testing.T) {
	requireDockerE2E(t)
	if testing.Short() {
		t.Skip("skip long e2e test in short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	cmdPattern := filepath.ToSlash(filepath.Join("..", "..", "cmd")) + "/..."
	run(t, ctx, "env", "CGO_ENABLED=0", "go", "build", "-trimpath", "-o", filepath.Join("..", "..", "bin")+"/", cmdPattern)
	startComposeLab(t, ctx, composeFile)
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), time.Minute)
		defer downCancel()
		run(t, downCtx, "docker", "compose", "-f", composeFile, "down", "-v")
	})
	waitForOVN(t, ctx, composeFile)

	ensureIPNetNS := func(service string) {
		hasNetNS := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "netns", "list")
		if hasNetNS.exitCode == 0 {
			return
		}
		installOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "apk add --no-cache iproute2")
		if installOutput.exitCode != 0 {
			t.Skipf("node %s does not support ip netns and iproute2 install failed:\n%s", service, strings.TrimSpace(installOutput.output))
		}
		hasNetNS = runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "netns", "list")
		if hasNetNS.exitCode != 0 {
			t.Skipf("node %s still does not support ip netns after install:\n%s", service, strings.TrimSpace(hasNetNS.output))
		}
	}
	ensureIPv6Fabric := func(service string) {
		check := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "sh", "-c", "ip -6 -o addr show dev eth0 | grep -q 'fd00:30::'")
		if check.exitCode != 0 {
			dump := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", service, "ip", "-6", "addr", "show", "dev", "eth0")
			t.Skipf("node %s does not have IPv6 fabric address:\n%s", service, strings.TrimSpace(dump.output))
		}
	}
	for _, service := range []string{"node-a", "node-b"} {
		ensureIPNetNS(service)
		ensureIPv6Fabric(service)
	}

	stateScript := "cat >/tmp/netloom-workload-ipv6-cross-egress-state.json <<'EOF'\n" + desiredWorkloadIPv6CrossNodeEgressL4StateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-workload-ipv6-cross-egress-state.json NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-a=fd00:30::11,node-b=172.30.0.12,node-b=fd00:30::12 "
	nodeAOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", stateScript+"NETLOOM_NODE_NAME=node-a /netloom/bin/netloom-agent")
	if !strings.Contains(nodeAOutput, "datapath=linux:netns") || !strings.Contains(nodeAOutput, "remote_routes=1") {
		t.Fatalf("node-a cross-node ipv6 egress workload datapath did not succeed:\n%s", nodeAOutput)
	}
	nodeBOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", stateScript+"NETLOOM_NODE_NAME=node-b /netloom/bin/netloom-agent")
	if !strings.Contains(nodeBOutput, "datapath=linux:netns") || !strings.Contains(nodeBOutput, "remote_routes=1") {
		t.Fatalf("node-b cross-node ipv6 egress workload datapath did not succeed:\n%s", nodeBOutput)
	}

	podA := workloadNamespace("ipv6", "ipv6-pod-a")
	podB := workloadNamespace("ipv6", "ipv6-pod-b")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "ip netns exec "+podA+" sh -c 'while true; do printf ok | nc -l -p 9090 >/dev/null; done' >/tmp/netloom-ipv6-cross-egress-nc.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+podB+" sh -c 'printf hi | nc -w 1 fd00:10:30::10 9090' >/tmp/netloom-workload-ipv6-cross-egress-allow-probe.log 2>&1 && exit 0; sleep 1; done; cat /tmp/netloom-workload-ipv6-cross-egress-allow-probe.log; exit 1")

	watchStatePath := "/tmp/netloom-workload-ipv6-cross-egress-watch.json"
	startWatchScript := "cat >" + watchStatePath + " <<'EOF'\n" + desiredWorkloadIPv6CrossNodeEgressL4DropStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=" + watchStatePath + " NETLOOM_NODE_NAME=node-b NETLOOM_POLICY_STORE=ebpf NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_LINUX_DATAPATH_CLEANUP=1 NETLOOM_RECONCILE_INTERVAL_MS=500 NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-a=fd00:30::11,node-b=172.30.0.12,node-b=fd00:30::12 NETLOOM_TCX_WORKLOAD=1 /netloom/bin/netloom-agent >/tmp/netloom-agent-ipv6-cross-egress-watch.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", startWatchScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do grep -q 'tcx=attached' /tmp/netloom-agent-ipv6-cross-egress-watch.log 2>/dev/null && grep -q 'tcx_eligible=1' /tmp/netloom-agent-ipv6-cross-egress-watch.log 2>/dev/null && exit 0; sleep 1; done; cat /tmp/netloom-agent-ipv6-cross-egress-watch.log; exit 1")

	l4Drop := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do ip netns exec "+podB+" sh -c 'printf hi | nc -w 1 fd00:10:30::10 9090' >/tmp/netloom-workload-ipv6-cross-egress-drop-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-workload-ipv6-cross-egress-drop-probe.log; exit 1")
	if l4Drop.exitCode != 0 {
		dropLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-ipv6-cross-egress-watch.log")
		t.Fatalf("expected cross-node IPv6 TCX egress policy to drop pod-b tcp/9090 to pod-a, probe:\n%s\nagent log:\n%s", l4Drop.output, dropLog)
	}
	runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "pkill", "-f", "/netloom/bin/netloom-agent")
}

func desiredPolicyDropStateJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400, "dns_servers": ["10.96.0.10"], "domain_name": "svc.cluster.local", "search_domains": ["cluster.local", "svc.cluster.local"]}}],
  "endpoints": [{"id": "file-pod-b", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.11", "node": "node-b", "security_groups": ["drop-web"]}],
  "security_groups": [{"name": "drop-web", "vpc": "file", "rules": [{"id": "drop-web-from-node-a", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "drop"}]}]
}`
}

func desiredSharedInterfaceMultiEndpointStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [{"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}],
  "endpoints": [
    {"id": "host-120", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.120", "node": "node-b", "security_groups": ["drop-8080"]},
    {"id": "host-121", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.121", "node": "node-b", "security_groups": ["drop-8081"]}
  ],
  "security_groups": [
    {"name": "drop-8080", "vpc": "fabric", "rules": [{"id": "drop-from-node-a-8080", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "drop"}]},
    {"name": "drop-8081", "vpc": "fabric", "rules": [{"id": "drop-from-node-a-8081", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8081, "to": 8081}], "action": "drop"}]}
  ]
}`
}

func desiredSharedInterfaceBidirectionalStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [{"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}],
  "endpoints": [
    {"id": "host-122", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.122", "node": "node-b", "security_groups": ["drop-8082-ingress"]},
    {"id": "host-123", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.123", "node": "node-b", "security_groups": ["drop-9090-egress"]}
  ],
  "security_groups": [
    {"name": "drop-8082-ingress", "vpc": "fabric", "rules": [{"id": "drop-from-node-a-8082", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8082, "to": 8082}], "action": "drop"}]},
    {"name": "drop-9090-egress", "vpc": "fabric", "rules": [{"id": "drop-to-node-a-9090", "priority": 100, "direction": "egress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 9090, "to": 9090}], "action": "drop"}]}
  ]
}`
}

func desiredWorkloadPolicyPriorityDenyWinsStateJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400, "dns_servers": ["10.96.0.10"], "domain_name": "svc.cluster.local", "search_domains": ["cluster.local", "svc.cluster.local"]}}],
  "endpoints": [
    {"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["client"]},
    {"id": "file-pod-b", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.11", "node": "node-b", "security_groups": ["policy-conflict"]}
  ],
  "security_groups": [
    {"name": "client", "vpc": "file", "rules": []},
    {
      "name": "policy-conflict",
      "vpc": "file",
      "rules": [
        {"id": "allow-tcp", "priority": 200, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.10/32", "ports": [{"from": 8081, "to": 8081}], "action": "allow"},
        {"id": "deny-tcp", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.10/32", "ports": [{"from": 8081, "to": 8081}], "action": "drop"}
      ]
    }
  ]
}`
}

func desiredWorkloadPolicyPriorityAllowWinsStateJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400, "dns_servers": ["10.96.0.10"], "domain_name": "svc.cluster.local", "search_domains": ["cluster.local", "svc.cluster.local"]}}],
  "endpoints": [
    {"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["client"]},
    {"id": "file-pod-b", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.11", "node": "node-b", "security_groups": ["policy-conflict"]}
  ],
  "security_groups": [
    {"name": "client", "vpc": "file", "rules": []},
    {
      "name": "policy-conflict",
      "vpc": "file",
      "rules": [
        {"id": "allow-tcp", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.10/32", "ports": [{"from": 8081, "to": 8081}], "action": "allow"},
        {"id": "deny-tcp", "priority": 200, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.10/32", "ports": [{"from": 8081, "to": 8081}], "action": "drop"}
      ]
    }
  ]
}`
}

func desiredDNSObservationStateJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1"}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["dns-client"]}],
  "security_groups": [{"name": "dns-client", "vpc": "file", "rules": [{"id": "allow-observed-api", "priority": 100, "direction": "egress", "protocol": "tcp", "remote_fqdns": [{"match_name": "api.example.com"}], "ports": [{"from": 443, "to": 443}], "action": "allow"}]}]
}`
}

func dnsObservationJSON() string {
	return `{
  "dns_records": [{"name": "api.example.com", "ips": ["203.0.113.10"]}]
}`
}

func desiredWorkloadPolicyDropStateJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400, "dns_servers": ["10.96.0.10"], "domain_name": "svc.cluster.local", "search_domains": ["cluster.local", "svc.cluster.local"]}}],
  "endpoints": [
    {"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["allow-web", "clients"]},
    {"id": "file-pod-b", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.11", "node": "node-b", "security_groups": ["drop-web"]},
    {"id": "file-pod-c", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.12", "node": "node-b", "security_groups": ["drop-alt-web"]}
  ],
  "security_groups": [
    {"name": "allow-web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow"}]},
    {"name": "clients", "vpc": "file", "rules": []},
    {"name": "drop-web", "vpc": "file", "rules": [{"id": "drop-web-from-clients", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_group": "clients", "ports": [{"from": 8080, "to": 8080}], "action": "drop"}]},
    {"name": "drop-alt-web", "vpc": "file", "rules": [
      {"id": "allow-alt-web-from-pod-a", "priority": 50, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.10/32", "ports": [{"from": 8081, "to": 8081}], "action": "allow"},
      {"id": "drop-alt-web-from-local-subnet", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.0/24", "ports": [{"from": 8081, "to": 8081}], "action": "drop"}
    ]}
  ]
}`
}

func desiredWorkloadICMPDropStateJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400}}],
  "endpoints": [
    {"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["clients"]},
    {"id": "file-pod-b", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.11", "node": "node-b", "security_groups": ["drop-icmp"]},
    {"id": "file-pod-c", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.12", "node": "node-b", "security_groups": ["drop-alt-web"]}
  ],
  "security_groups": [
    {"name": "clients", "vpc": "file", "rules": []},
    {"name": "drop-icmp", "vpc": "file", "rules": [{"id": "drop-icmp-from-clients", "priority": 100, "direction": "ingress", "protocol": "icmp", "remote_group": "clients", "action": "drop"}]},
    {"name": "drop-alt-web", "vpc": "file", "rules": [
      {"id": "allow-alt-web-from-pod-a", "priority": 50, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.10/32", "ports": [{"from": 8081, "to": 8081}], "action": "allow"},
      {"id": "drop-alt-web-from-local-subnet", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.0/24", "ports": [{"from": 8081, "to": 8081}], "action": "drop"}
    ]}
  ]
}`
}

func desiredWorkloadCleanupStateJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1"}],
  "endpoints": [
    {"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["allow-web"]},
    {"id": "file-pod-b", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.11", "node": "node-b", "security_groups": ["allow-web"]}
  ],
  "security_groups": [{"name": "allow-web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.10/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow"}]}]
}`
}

func desiredWorkloadStateJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100}],
  "endpoints": [
    {"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["web"]},
    {"id": "file-pod-b", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.11", "node": "node-b", "security_groups": ["web"]}
  ],
  "security_groups": [{"name": "web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow", "stateful": true}]}]
}`
}

func desiredStateJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400}}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["web"]}],
  "route_tables": [{"name": "main", "vpc": "file", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.245.0.254"]}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "file", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "src_ports": [{"from": 32000, "to": 32000}], "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.245.0.253"]}}],
  "gateways": [{"name": "gw-file", "vpc": "file", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [
    {"name": "egress", "vpc": "file", "type": "snat", "match_cidr": "10.245.0.0/24", "external_ip": "198.51.100.20"},
    {"name": "web-dnat", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.21", "target_ip": "10.245.0.10"},
    {"name": "web-fip", "vpc": "file", "type": "dnat_and_snat", "external_ip": "198.51.100.22", "target_ip": "10.245.0.10"},
    {"name": "ssh-port", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.23", "target_ip": "10.245.0.10", "protocol": "tcp", "external_port": 2222, "target_port": 2222}
  ],
  "load_balancers": [{"name": "file-web", "vpc": "file", "vip": "10.96.0.10", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.245.0.10", "port": 8080}]}, {"name": "dns", "port": 53, "protocol": "udp", "backends": [{"ip": "10.245.0.10", "port": 5353}]}], "subnets": ["fileapps"]}],
  "security_groups": [{"name": "web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow", "stateful": true}]}]
}`
}

func desiredStateWithoutDHCPJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["web"]}],
  "route_tables": [{"name": "main", "vpc": "file", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.245.0.254"]}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "file", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.245.0.253"]}}],
  "gateways": [{"name": "gw-file", "vpc": "file", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [
    {"name": "egress", "vpc": "file", "type": "snat", "match_cidr": "10.245.0.0/24", "external_ip": "198.51.100.20"},
    {"name": "web-dnat", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.21", "target_ip": "10.245.0.10"},
    {"name": "web-fip", "vpc": "file", "type": "dnat_and_snat", "external_ip": "198.51.100.22", "target_ip": "10.245.0.10"},
    {"name": "ssh-port", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.23", "target_ip": "10.245.0.10", "protocol": "tcp", "external_port": 2222, "target_port": 2222}
  ],
  "load_balancers": [{"name": "file-web", "vpc": "file", "vip": "10.96.0.10", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.245.0.10", "port": 8080}]}], "subnets": ["fileapps"]}],
  "security_groups": [{"name": "web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow", "stateful": true}]}]
}`
}

func desiredStateWithUpdatedLoadBalancerJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400}}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["web"]}],
  "route_tables": [{"name": "main", "vpc": "file", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.245.0.254"]}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "file", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.245.0.253"]}}],
  "gateways": [{"name": "gw-file", "vpc": "file", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [
    {"name": "egress", "vpc": "file", "type": "snat", "match_cidr": "10.245.0.0/24", "external_ip": "198.51.100.20"},
    {"name": "web-dnat", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.21", "target_ip": "10.245.0.10"},
    {"name": "web-fip", "vpc": "file", "type": "dnat_and_snat", "external_ip": "198.51.100.22", "target_ip": "10.245.0.10"},
    {"name": "ssh-port", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.23", "target_ip": "10.245.0.10", "protocol": "tcp", "external_port": 2222, "target_port": 2222}
  ],
  "load_balancers": [{"name": "file-web", "vpc": "file", "vip": "10.96.0.20", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.245.0.11", "port": 8080}]}], "subnets": ["fileapps"]}],
  "security_groups": [{"name": "web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow", "stateful": true}]}]
}`
}

func desiredStateWithUpdatedNATJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400}}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["web"]}],
  "route_tables": [{"name": "main", "vpc": "file", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.245.0.254"]}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "file", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.245.0.253"]}}],
  "gateways": [{"name": "gw-file", "vpc": "file", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [
    {"name": "egress", "vpc": "file", "type": "snat", "match_cidr": "10.245.0.0/24", "external_ip": "198.51.100.50"},
    {"name": "web-dnat", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.21", "target_ip": "10.245.0.10"},
    {"name": "web-fip", "vpc": "file", "type": "dnat_and_snat", "external_ip": "198.51.100.22", "target_ip": "10.245.0.10"},
    {"name": "ssh-port", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.23", "target_ip": "10.245.0.10", "protocol": "tcp", "external_port": 2222, "target_port": 2222}
  ],
  "load_balancers": [{"name": "file-web", "vpc": "file", "vip": "10.96.0.20", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.245.0.11", "port": 8080}]}], "subnets": ["fileapps"]}],
  "security_groups": [{"name": "web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow", "stateful": true}]}]
}`
}

func desiredStateWithUpdatedPolicyRouteJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400}}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["web"]}],
  "route_tables": [{"name": "main", "vpc": "file", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.245.0.254"]}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "file", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.245.0.252"]}}],
  "gateways": [{"name": "gw-file", "vpc": "file", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [
    {"name": "egress", "vpc": "file", "type": "snat", "match_cidr": "10.245.0.0/24", "external_ip": "198.51.100.50"},
    {"name": "web-dnat", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.21", "target_ip": "10.245.0.10"},
    {"name": "web-fip", "vpc": "file", "type": "dnat_and_snat", "external_ip": "198.51.100.22", "target_ip": "10.245.0.10"},
    {"name": "ssh-port", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.23", "target_ip": "10.245.0.10", "protocol": "tcp", "external_port": 2222, "target_port": 2222}
  ],
  "load_balancers": [{"name": "file-web", "vpc": "file", "vip": "10.96.0.20", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.245.0.11", "port": 8080}]}], "subnets": ["fileapps"]}],
  "security_groups": [{"name": "web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow", "stateful": true}]}]
}`
}

func desiredStateWithUpdatedStaticRouteJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400}}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["web"]}],
  "route_tables": [{"name": "main", "vpc": "file", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.245.0.251"]}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "file", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.245.0.252"]}}],
  "gateways": [{"name": "gw-file", "vpc": "file", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [
    {"name": "egress", "vpc": "file", "type": "snat", "match_cidr": "10.245.0.0/24", "external_ip": "198.51.100.50"},
    {"name": "web-dnat", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.21", "target_ip": "10.245.0.10"},
    {"name": "web-fip", "vpc": "file", "type": "dnat_and_snat", "external_ip": "198.51.100.22", "target_ip": "10.245.0.10"},
    {"name": "ssh-port", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.23", "target_ip": "10.245.0.10", "protocol": "tcp", "external_port": 2222, "target_port": 2222}
  ],
  "load_balancers": [{"name": "file-web", "vpc": "file", "vip": "10.96.0.20", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.245.0.11", "port": 8080}]}], "subnets": ["fileapps"]}],
  "security_groups": [{"name": "web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow", "stateful": true}]}]
}`
}

func desiredStateWithStaticRouteToECMPJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400}}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["web"]}],
  "route_tables": [{"name": "main", "vpc": "file", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.245.0.251", "10.245.0.252"]}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "file", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.245.0.252"]}}],
  "gateways": [{"name": "gw-file", "vpc": "file", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [
    {"name": "egress", "vpc": "file", "type": "snat", "match_cidr": "10.245.0.0/24", "external_ip": "198.51.100.50"},
    {"name": "web-dnat", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.21", "target_ip": "10.245.0.10"},
    {"name": "web-fip", "vpc": "file", "type": "dnat_and_snat", "external_ip": "198.51.100.22", "target_ip": "10.245.0.10"},
    {"name": "ssh-port", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.23", "target_ip": "10.245.0.10", "protocol": "tcp", "external_port": 2222, "target_port": 2222}
  ],
  "load_balancers": [{"name": "file-web", "vpc": "file", "vip": "10.96.0.20", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.245.0.11", "port": 8080}]}], "subnets": ["fileapps"]}],
  "security_groups": [{"name": "web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow", "stateful": true}]}]
}`
}

func desiredStateWithStaticRouteToECMPIPv6JSON() string {
	return `{
  "vpcs": [{"name": "ipv6"}],
  "subnets": [{"name": "appsv6", "vpc": "ipv6", "cidr": "fd00:10:10::/64", "gateway": "fd00:10:10::1"}],
  "endpoints": [{"id": "ipv6-pod-a", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:10::10", "node": "node-a", "security_groups": ["ipv6-allow"]}],
  "route_tables": [{"name": "main", "vpc": "ipv6", "routes": [{"destination": "::/0", "next_hops": ["fd00:10:10::252", "fd00:10:10::251"]}]}],
  "security_groups": [{"name": "ipv6-allow", "vpc": "ipv6", "rules": [{"id": "allow-all", "priority": 100, "direction": "ingress", "protocol": "any", "remote_cidr": "::/0", "action": "allow"}]}]
}`
}

func desiredWorkloadIPv6StateJSON() string {
	return `{
  "vpcs": [{"name": "ipv6"}],
  "subnets": [{"name": "appsv6", "vpc": "ipv6", "cidr": "fd00:10:10::/64", "gateway": "fd00:10:10::1"}],
  "endpoints": [
    {"id": "ipv6-pod-a", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:10::10", "node": "node-b", "security_groups": ["clients"]},
    {"id": "ipv6-pod-b", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:10::11", "node": "node-b", "security_groups": ["servers"]}
  ],
  "security_groups": [
    {"name": "clients", "vpc": "ipv6", "rules": []},
    {"name": "servers", "vpc": "ipv6", "rules": []}
  ]
}`
}

func desiredWorkloadIPv6ICMPDropStateJSON() string {
	return `{
  "vpcs": [{"name": "ipv6"}],
  "subnets": [{"name": "appsv6", "vpc": "ipv6", "cidr": "fd00:10:10::/64", "gateway": "fd00:10:10::1"}],
  "endpoints": [
    {"id": "ipv6-pod-a", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:10::10", "node": "node-b", "security_groups": ["clients"]},
    {"id": "ipv6-pod-b", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:10::11", "node": "node-b", "security_groups": ["drop-icmpv6"]}
  ],
  "security_groups": [
    {"name": "clients", "vpc": "ipv6", "rules": []},
    {"name": "drop-icmpv6", "vpc": "ipv6", "rules": [{"id": "drop-icmpv6-from-clients", "priority": 100, "direction": "ingress", "protocol": "icmp", "remote_group": "clients", "action": "drop"}]}
  ]
}`
}

func desiredWorkloadIPv6CrossNodeStateJSON() string {
	return `{
  "vpcs": [{"name": "ipv6"}],
  "subnets": [{"name": "appsv6", "vpc": "ipv6", "cidr": "fd00:10:20::/64", "gateway": "fd00:10:20::1"}],
  "endpoints": [
    {"id": "ipv6-pod-a", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:20::10", "node": "node-a", "security_groups": ["clients"]},
    {"id": "ipv6-pod-b", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:20::11", "node": "node-b", "security_groups": ["servers"]}
  ],
  "security_groups": [
    {"name": "clients", "vpc": "ipv6", "rules": []},
    {"name": "servers", "vpc": "ipv6", "rules": []}
  ]
}`
}

func desiredWorkloadIPv6CrossNodeICMPDropStateJSON() string {
	return `{
  "vpcs": [{"name": "ipv6"}],
  "subnets": [{"name": "appsv6", "vpc": "ipv6", "cidr": "fd00:10:20::/64", "gateway": "fd00:10:20::1"}],
  "endpoints": [
    {"id": "ipv6-pod-a", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:20::10", "node": "node-a", "security_groups": ["clients"]},
    {"id": "ipv6-pod-b", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:20::11", "node": "node-b", "security_groups": ["drop-icmpv6"]}
  ],
  "security_groups": [
    {"name": "clients", "vpc": "ipv6", "rules": []},
    {"name": "drop-icmpv6", "vpc": "ipv6", "rules": [{"id": "drop-icmpv6-from-clients", "priority": 100, "direction": "ingress", "protocol": "icmp", "remote_group": "clients", "action": "drop"}]}
  ]
}`
}

func desiredWorkloadIPv6CrossNodeL4StateJSON() string {
	return `{
  "vpcs": [{"name": "ipv6"}],
  "subnets": [{"name": "appsv6", "vpc": "ipv6", "cidr": "fd00:10:20::/64", "gateway": "fd00:10:20::1"}],
  "endpoints": [
    {"id": "ipv6-pod-a", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:20::10", "node": "node-a", "security_groups": ["clients"]},
    {"id": "ipv6-pod-b", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:20::11", "node": "node-b", "security_groups": ["servers"]}
  ],
  "security_groups": [
    {"name": "clients", "vpc": "ipv6", "rules": []},
    {"name": "servers", "vpc": "ipv6", "rules": []}
  ]
}`
}

func desiredWorkloadIPv6CrossNodeL4DropStateJSON() string {
	return `{
  "vpcs": [{"name": "ipv6"}],
  "subnets": [{"name": "appsv6", "vpc": "ipv6", "cidr": "fd00:10:20::/64", "gateway": "fd00:10:20::1"}],
  "endpoints": [
    {"id": "ipv6-pod-a", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:20::10", "node": "node-a", "security_groups": ["clients"]},
    {"id": "ipv6-pod-b", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:20::11", "node": "node-b", "security_groups": ["drop-web"]}
  ],
  "security_groups": [
    {"name": "clients", "vpc": "ipv6", "rules": []},
    {"name": "drop-web", "vpc": "ipv6", "rules": [{"id": "drop-web-from-clients", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_group": "clients", "ports": [{"from": 8080, "to": 8080}], "action": "drop"}]}
  ]
}`
}

func desiredDualStackInterfaceDropStateJSON() string {
	return `{
  "vpcs": [{"name": "fabric"}],
  "subnets": [{"name": "hostnet", "vpc": "fabric", "cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}],
  "endpoints": [{"id": "host-b", "vpc": "fabric", "subnet": "hostnet", "ip": "172.30.0.12", "node": "node-b", "security_groups": ["dual-drop"]}],
  "security_groups": [{"name": "dual-drop", "vpc": "fabric", "rules": [
    {"id": "drop-v4-from-node-a", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8084, "to": 8084}], "action": "drop"},
    {"id": "drop-v6-from-node-a", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "fd00:30::11/128", "ports": [{"from": 8084, "to": 8084}], "action": "drop"}
  ]}]
}`
}

func desiredWorkloadIPv6CrossNodeEgressL4StateJSON() string {
	return `{
  "vpcs": [{"name": "ipv6"}],
  "subnets": [{"name": "appsv6", "vpc": "ipv6", "cidr": "fd00:10:30::/64", "gateway": "fd00:10:30::1"}],
  "endpoints": [
    {"id": "ipv6-pod-a", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:30::10", "node": "node-a", "security_groups": ["servers"]},
    {"id": "ipv6-pod-b", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:30::11", "node": "node-b", "security_groups": ["clients"]}
  ],
  "security_groups": [
    {"name": "servers", "vpc": "ipv6", "rules": []},
    {"name": "clients", "vpc": "ipv6", "rules": []}
  ]
}`
}

func desiredWorkloadIPv6CrossNodeEgressL4DropStateJSON() string {
	return `{
  "vpcs": [{"name": "ipv6"}],
  "subnets": [{"name": "appsv6", "vpc": "ipv6", "cidr": "fd00:10:30::/64", "gateway": "fd00:10:30::1"}],
  "endpoints": [
    {"id": "ipv6-pod-a", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:30::10", "node": "node-a", "security_groups": ["servers"]},
    {"id": "ipv6-pod-b", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:30::11", "node": "node-b", "security_groups": ["drop-egress"]}
  ],
  "security_groups": [
    {"name": "servers", "vpc": "ipv6", "rules": []},
    {"name": "drop-egress", "vpc": "ipv6", "rules": [{"id": "drop-9090-to-servers", "priority": 100, "direction": "egress", "protocol": "tcp", "remote_group": "servers", "ports": [{"from": 9090, "to": 9090}], "action": "drop"}]}
  ]
}`
}

func desiredStateWithStaticRouteFromECMPToSingleJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400}}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["web"]}],
  "route_tables": [{"name": "main", "vpc": "file", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.245.0.252"]}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "file", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.245.0.252"]}}],
  "gateways": [{"name": "gw-file", "vpc": "file", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [
    {"name": "egress", "vpc": "file", "type": "snat", "match_cidr": "10.245.0.0/24", "external_ip": "198.51.100.50"},
    {"name": "web-dnat", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.21", "target_ip": "10.245.0.10"},
    {"name": "web-fip", "vpc": "file", "type": "dnat_and_snat", "external_ip": "198.51.100.22", "target_ip": "10.245.0.10"},
    {"name": "ssh-port", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.23", "target_ip": "10.245.0.10", "protocol": "tcp", "external_port": 2222, "target_port": 2222}
  ],
  "load_balancers": [{"name": "file-web", "vpc": "file", "vip": "10.96.0.20", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.245.0.11", "port": 8080}]}], "subnets": ["fileapps"]}],
  "security_groups": [{"name": "web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow", "stateful": true}]}]
}`
}

func desiredStateWithoutProviderNetworkJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400}}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["web"]}],
  "route_tables": [{"name": "main", "vpc": "file", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.245.0.251"]}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "file", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.245.0.252"]}}],
  "gateways": [{"name": "gw-file", "vpc": "file", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [
    {"name": "egress", "vpc": "file", "type": "snat", "match_cidr": "10.245.0.0/24", "external_ip": "198.51.100.50"},
    {"name": "web-dnat", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.21", "target_ip": "10.245.0.10"},
    {"name": "web-fip", "vpc": "file", "type": "dnat_and_snat", "external_ip": "198.51.100.22", "target_ip": "10.245.0.10"},
    {"name": "ssh-port", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.23", "target_ip": "10.245.0.10", "protocol": "tcp", "external_port": 2222, "target_port": 2222}
  ],
  "load_balancers": [{"name": "file-web", "vpc": "file", "vip": "10.96.0.20", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.245.0.11", "port": 8080}]}], "subnets": ["fileapps"]}],
  "security_groups": [{"name": "web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow", "stateful": true}]}]
}`
}

func desiredStateWithoutEndpointNATJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400}}],
  "endpoints": [],
  "route_tables": [{"name": "main", "vpc": "file", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.245.0.254"]}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "file", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.245.0.253"]}}],
  "gateways": [{"name": "gw-file", "vpc": "file", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [],
  "load_balancers": [],
  "security_groups": [{"name": "web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow", "stateful": true}]}]
}`
}

func waitForOVN(t *testing.T, ctx context.Context, composeFile string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "show")
		output, err := cmd.CombinedOutput()
		last = string(output)
		if err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("OVN NB DB did not become ready:\n%s", last)
}

func startComposeLab(t *testing.T, ctx context.Context, composeFile string) {
	t.Helper()
	composeDown(t, composeFile)
	deadline := time.Now().Add(45 * time.Second)
	var last commandResult
	for {
		last = runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "up", "-d", "--quiet-pull", "--force-recreate", "--remove-orphans")
		if last.exitCode == 0 && composeServicesRunning(t, composeFile, "ovn-central", "node-a", "node-b", "node-c") {
			break
		}
		if last.exitCode != 0 && !dockerComposeStartupRetryable(last.output) {
			t.Fatalf("docker compose -f %s up -d --quiet-pull --force-recreate --remove-orphans failed:\n%s", composeFile, last.output)
		}
		if time.Now().After(deadline) {
			t.Fatalf("docker compose -f %s up -d --quiet-pull --force-recreate --remove-orphans failed:\n%s", composeFile, last.output)
		}
		time.Sleep(2 * time.Second)
		composeDown(t, composeFile)
	}
	t.Cleanup(func() {
		composeDown(t, composeFile)
	})
}

func composeDown(t *testing.T, composeFile string) {
	t.Helper()
	downCtx, downCancel := context.WithTimeout(context.Background(), time.Minute)
	defer downCancel()
	runAllowFailure(t, downCtx, "docker", "compose", "-f", composeFile, "down", "-v", "--remove-orphans")
	waitForComposeProjectRemoval(t, composeFile)
}

func dockerComposeStartupRetryable(output string) bool {
	return (strings.Contains(output, "removal of container") && strings.Contains(output, "already in progress")) ||
		(strings.Contains(output, "container name") && strings.Contains(output, "is already in use")) ||
		strings.Contains(output, "marked for removal and cannot be started") ||
		(strings.Contains(output, "network") && strings.Contains(output, "not found"))
}

func waitForComposeProjectRemoval(t *testing.T, composeFile string) {
	t.Helper()
	project := filepath.Base(filepath.Dir(composeFile))
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		result := runAllowFailure(t, context.Background(), "docker", "ps", "-a", "--filter", "label=com.docker.compose.project="+project, "--format", "{{.Names}}")
		if result.exitCode == 0 && strings.TrimSpace(result.output) == "" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	result := runAllowFailure(t, context.Background(), "docker", "ps", "-a", "--filter", "label=com.docker.compose.project="+project, "--format", "{{.Names}} {{.Status}}")
	t.Fatalf("docker compose project %s did not finish removing containers:\n%s", project, result.output)
}

func composeServicesRunning(t *testing.T, composeFile string, services ...string) bool {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		allRunning := true
		for _, service := range services {
			result := runAllowFailure(t, context.Background(), "docker", "compose", "-f", composeFile, "ps", "-q", service)
			containerID := strings.TrimSpace(result.output)
			if result.exitCode != 0 || containerID == "" {
				allRunning = false
				break
			}
			inspect := runAllowFailure(t, context.Background(), "docker", "inspect", "-f", "{{.State.Running}}", containerID)
			if inspect.exitCode != 0 || strings.TrimSpace(inspect.output) != "true" {
				allRunning = false
				break
			}
		}
		if allRunning {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func run(t *testing.T, ctx context.Context, name string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}

type commandResult struct {
	output   string
	exitCode int
}

func runAllowFailure(t *testing.T, ctx context.Context, name string, args ...string) commandResult {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return commandResult{output: string(output)}
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return commandResult{output: string(output), exitCode: exitErr.ExitCode()}
	}
	t.Fatalf("%s %s failed unexpectedly: %v\n%s", name, strings.Join(args, " "), err, output)
	return commandResult{}
}
