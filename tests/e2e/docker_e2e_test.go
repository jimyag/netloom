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
	if os.Getenv("NETLOOM_E2E") != "1" {
		t.Skip("set NETLOOM_E2E=1 to run docker e2e tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	composeFile := filepath.Join("testdata", "..", "docker-compose.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmdPattern := filepath.ToSlash(filepath.Join("..", "..", "cmd")) + "/..."
	run(t, ctx, "env", "CGO_ENABLED=0", "go", "build", "-trimpath", "-o", filepath.Join("..", "..", "bin")+"/", cmdPattern)
	run(t, ctx, "docker", "compose", "-f", composeFile, "up", "-d", "--quiet-pull", "--force-recreate")
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), time.Minute)
		defer downCancel()
		run(t, downCtx, "docker", "compose", "-f", composeFile, "down", "-v")
	})
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
	for _, expected := range []string{"policy_next_hop=10.244.0.253", "snat=198.51.100.10", "gateway=gw-a", "ovn_ops=", "ovn_executed="} {
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
	for _, expected := range []string{"reconciled desired state", "policy_routes=1", "nat_rules=4", "security_groups=1"} {
		if !strings.Contains(liveStateOutput, expected) {
			t.Fatalf("live state-file controller output missing %q:\n%s", expected, liveStateOutput)
		}
	}
	nbState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "show")
	for _, expected := range []string{"nl_lr_default", "nl_ls_apps", "nl_lr_file", "nl_ls_fileapps"} {
		if !strings.Contains(nbState, expected) {
			t.Fatalf("OVN NB state missing %q:\n%s", expected, nbState)
		}
	}
	natState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-nat-list", "nl_lr_file")
	for _, expected := range []string{"snat", "198.51.100.20", "dnat", "198.51.100.21", "dnat_and_snat", "198.51.100.22", "2222"} {
		if !strings.Contains(natState, expected) {
			t.Fatalf("OVN NAT state missing %q:\n%s", expected, natState)
		}
	}
	controllerWatchPath := "/tmp/netloom-controller-watch-state.json"
	startControllerWatch := "cat >" + controllerWatchPath + " <<'EOF'\n" + desiredStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=" + controllerWatchPath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock NETLOOM_RECONCILE_INTERVAL_MS=500 /netloom/bin/netloom-controller >/tmp/netloom-controller-watch.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", startControllerWatch)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do grep -q 'reconciled desired state' /tmp/netloom-controller-watch.log 2>/dev/null && exit 0; sleep 1; done; cat /tmp/netloom-controller-watch.log; exit 1")
	updateControllerWatch := "cat >" + controllerWatchPath + " <<'EOF'\n" + desiredStateWithoutEndpointNATJSON() + "\nEOF"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", updateControllerWatch)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 15); do ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-list nl_ls_fileapps | grep -q nl_lp_file-pod-a || exit 0; sleep 1; done; cat /tmp/netloom-controller-watch.log; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lsp-list nl_ls_fileapps; exit 1")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-nat-list nl_lr_file | grep -q 198.51.100.20 && { cat /tmp/netloom-controller-watch.log; exit 1; } || exit 0")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "pkill", "-f", "netloom-controller")
	agentOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "-e", "NETLOOM_TCX_SELFTEST_IFACE=lo", "node-b", "/netloom/bin/netloom-agent")
	if !strings.Contains(agentOutput, "ready for node policy") {
		t.Fatalf("agent output did not show ready state:\n%s", agentOutput)
	}
	for _, expected := range []string{"endpoint=selftest-pod", "entries=", "allow=allow", "deny=drop", "policy_allowed=1", "policy_dropped=1", "drop_events=1", "tcx=attached:lo:ingress:verdict:pass"} {
		if !strings.Contains(agentOutput, expected) {
			t.Fatalf("agent output missing %q:\n%s", expected, agentOutput)
		}
	}
	agentStateScript := "cat >/tmp/netloom-state.json <<'EOF'\n" + desiredStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-state.json NETLOOM_NODE_NAME=node-a /netloom/bin/netloom-agent"
	agentStateOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", agentStateScript)
	for _, expected := range []string{"reconciled node policy", "node=node-a", "endpoints=1", "programs=1", "entries=1", "tcx_eligible=1"} {
		if !strings.Contains(agentStateOutput, expected) {
			t.Fatalf("state-file agent output missing %q:\n%s", expected, agentStateOutput)
		}
	}
	agentOtherNodeScript := "cat >/tmp/netloom-state.json <<'EOF'\n" + desiredStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-state.json NETLOOM_NODE_NAME=node-b /netloom/bin/netloom-agent"
	agentOtherNodeOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", agentOtherNodeScript)
	for _, expected := range []string{"reconciled node policy", "node=node-b", "endpoints=0", "programs=0", "entries=0"} {
		if !strings.Contains(agentOtherNodeOutput, expected) {
			t.Fatalf("other-node state-file agent output missing %q:\n%s", expected, agentOtherNodeOutput)
		}
	}
	workloadStateScript := "cat >/tmp/netloom-workload-state.json <<'EOF'\n" + desiredWorkloadStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-workload-state.json NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_LINUX_DATAPATH_BACKEND=netlink NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-b=172.30.0.12 "
	nodeAWorkloadOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", workloadStateScript+"NETLOOM_NODE_NAME=node-a /netloom/bin/netloom-agent")
	for _, expected := range []string{"datapath=linux:netns", "local_ips=1", "remote_routes=1"} {
		if !strings.Contains(nodeAWorkloadOutput, expected) {
			t.Fatalf("node-a workload datapath output missing %q:\n%s", expected, nodeAWorkloadOutput)
		}
	}
	nodeBWorkloadOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", workloadStateScript+"NETLOOM_NODE_NAME=node-b /netloom/bin/netloom-agent")
	for _, expected := range []string{"datapath=linux:netns", "local_ips=1", "remote_routes=1"} {
		if !strings.Contains(nodeBWorkloadOutput, expected) {
			t.Fatalf("node-b workload datapath output missing %q:\n%s", expected, nodeBWorkloadOutput)
		}
	}
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ip", "netns", "exec", "nl-file-pod-a", "ping", "-c", "1", "-W", "1", "10.245.0.11")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ip netns exec nl-file-pod-b sh -c 'while true; do printf ok | nc -l -p 8080 >/dev/null; done' >/tmp/netloom-ns-nc.log 2>&1 &")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ip", "netns", "exec", "nl-file-pod-a", "sh", "-c", "printf hi | nc -w 1 10.245.0.11 8080")
	watchStatePath := "/tmp/netloom-workload-watch-state.json"
	startWatchScript := "cat >" + watchStatePath + " <<'EOF'\n" + desiredWorkloadStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=" + watchStatePath + " NETLOOM_NODE_NAME=node-b NETLOOM_POLICY_STORE=ebpf NETLOOM_LINUX_DATAPATH=1 NETLOOM_LINUX_DATAPATH_MODE=netns NETLOOM_LINUX_DATAPATH_BACKEND=netlink NETLOOM_LINUX_DATAPATH_CLEANUP=1 NETLOOM_RECONCILE_INTERVAL_MS=500 NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-b=172.30.0.12 NETLOOM_TCX_WORKLOAD=1 /netloom/bin/netloom-agent >/tmp/netloom-agent-watch.log 2>&1 &"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", startWatchScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do grep -q 'tcx=attached' /tmp/netloom-agent-watch.log 2>/dev/null && exit 0; sleep 1; done; cat /tmp/netloom-agent-watch.log; exit 1")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ip", "netns", "exec", "nl-file-pod-a", "sh", "-c", "printf hi | nc -w 1 10.245.0.11 8080")
	updateWatchScript := "cat >" + watchStatePath + " <<'EOF'\n" + desiredWorkloadPolicyDropStateJSON() + "\nEOF"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", updateWatchScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "ip", "netns", "exec", "nl-file-pod-a", "ping", "-c", "1", "-W", "1", "10.245.0.11")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ip netns exec nl-file-pod-a sh -c 'printf hi | nc -w 1 10.245.0.11 8080' >/tmp/netloom-workload-probe.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-workload-probe.log; exit 1")
	workloadDropLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-watch.log")
	for _, expected := range []string{"reconciled node policy", "node=node-b", "store=ebpf", "datapath=linux:netns", "local_ips=2", "tcx=attached-workloads:2:egress:policy-l4"} {
		if !strings.Contains(workloadDropLog, expected) {
			t.Fatalf("workload L4 drop agent output missing %q:\n%s", expected, workloadDropLog)
		}
	}
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "netns", "exec", "nl-file-pod-c", "ip", "addr")
	updateWatchScript = "cat >" + watchStatePath + " <<'EOF'\n" + desiredWorkloadCleanupStateJSON() + "\nEOF"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", updateWatchScript)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", "for i in $(seq 1 15); do ip netns exec nl-file-pod-a sh -c 'printf hi | nc -w 1 10.245.0.11 8080' >/tmp/netloom-workload-probe.log 2>&1 && exit 0; sleep 1; done; cat /tmp/netloom-workload-probe.log; exit 1")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 15); do ip netns exec nl-file-pod-c ip addr >/dev/null 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-agent-watch.log; exit 1")
	watchLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", "/tmp/netloom-agent-watch.log")
	for _, expected := range []string{"datapath=linux:netns", "local_ips=1", "cleanup=true"} {
		if !strings.Contains(watchLog, expected) {
			t.Fatalf("watch cleanup log missing %q:\n%s", expected, watchLog)
		}
	}
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "pkill", "-f", "netloom-agent")
	podBAddr := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "netns", "exec", "nl-file-pod-b", "ip", "addr", "show", "eth0")
	if !strings.Contains(podBAddr, "10.245.0.11") {
		t.Fatalf("pod-b namespace was not preserved:\n%s", podBAddr)
	}
	stalePodC := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "ip", "netns", "exec", "nl-file-pod-c", "ip", "addr")
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
}

func desiredPolicyDropStateJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1"}],
  "endpoints": [{"id": "file-pod-b", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.11", "node": "node-b", "security_groups": ["drop-web"]}],
  "security_groups": [{"name": "drop-web", "vpc": "file", "rules": [{"id": "drop-web-from-node-a", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "drop"}]}]
}`
}

func desiredWorkloadPolicyDropStateJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1"}],
  "endpoints": [
    {"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["allow-web", "clients"]},
    {"id": "file-pod-b", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.11", "node": "node-b", "security_groups": ["drop-web"]},
    {"id": "file-pod-c", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.12", "node": "node-b", "security_groups": ["drop-alt-web"]}
  ],
  "security_groups": [
    {"name": "allow-web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow"}]},
    {"name": "clients", "vpc": "file", "rules": []},
    {"name": "drop-web", "vpc": "file", "rules": [{"id": "drop-web-from-clients", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_group": "clients", "ports": [{"from": 8080, "to": 8080}], "action": "drop"}]},
    {"name": "drop-alt-web", "vpc": "file", "rules": [{"id": "drop-alt-web-from-pod-a", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.245.0.10/32", "ports": [{"from": 8081, "to": 8081}], "action": "drop"}]}
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
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1"}],
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
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1"}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["web"]}],
  "route_tables": [{"name": "main", "vpc": "file", "routes": [{"destination": "0.0.0.0/0", "next_hop": "10.245.0.254"}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "file", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hop": "10.245.0.253"}}],
  "gateways": [{"name": "gw-file", "vpc": "file", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [
    {"name": "egress", "vpc": "file", "type": "snat", "match_cidr": "10.245.0.0/24", "external_ip": "198.51.100.20"},
    {"name": "web-dnat", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.21", "target_ip": "10.245.0.10"},
    {"name": "web-fip", "vpc": "file", "type": "dnat_and_snat", "external_ip": "198.51.100.22", "target_ip": "10.245.0.10"},
    {"name": "ssh-port", "vpc": "file", "type": "dnat", "external_ip": "198.51.100.23", "target_ip": "10.245.0.10", "protocol": "tcp", "external_port": 2222, "target_port": 2222}
  ],
  "security_groups": [{"name": "web", "vpc": "file", "rules": [{"id": "allow-web", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "172.30.0.11/32", "ports": [{"from": 8080, "to": 8080}], "action": "allow", "stateful": true}]}]
}`
}

func desiredStateWithoutEndpointNATJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1"}],
  "endpoints": [],
  "route_tables": [{"name": "main", "vpc": "file", "routes": [{"destination": "0.0.0.0/0", "next_hop": "10.245.0.254"}]}],
  "policy_routes": [{"name": "https-via-fw", "vpc": "file", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hop": "10.245.0.253"}}],
  "gateways": [{"name": "gw-file", "vpc": "file", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"}],
  "nat_rules": [],
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
