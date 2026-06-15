package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestDockerControllerReconcileIdempotent(t *testing.T) {
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

	waitForOVN(t, ctx, composeFile)

	applyState := func() string {
		stateScript := "cat >/tmp/netloom-state.json <<'EOF'\n" + desiredStateJSON() + "\nEOF\nNETLOOM_STATE_FILE=/tmp/netloom-state.json NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
		return run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateScript)
	}

	firstOutput := applyState()
	for _, expected := range []string{"reconciled desired state", "policy_routes=1", "nat_rules=4", "load_balancers=1"} {
		if !strings.Contains(firstOutput, expected) {
			t.Fatalf("initial desired-state reconcile missing %q:\n%s", expected, firstOutput)
		}
	}
	endpointID := endpointExternalIDForOVN("file", "file-pod-a")
	initial := describeNetloomOVNInventory(t, ctx, composeFile, endpointID)
	if len(initial.logicalRouters) == 0 || len(initial.logicalSwitch) == 0 || len(initial.endpoints) == 0 {
		t.Fatalf("initial inventory was incomplete: %+v", initial)
	}

	secondOutput := applyState()
	for _, expected := range []string{"reconciled desired state", "policy_routes=1", "nat_rules=4", "load_balancers=1"} {
		if !strings.Contains(secondOutput, expected) {
			t.Fatalf("second desired-state reconcile missing %q:\n%s", expected, secondOutput)
		}
	}
	after := describeNetloomOVNInventory(t, ctx, composeFile, endpointID)
	if !reflect.DeepEqual(initial, after) {
		t.Fatalf("idempotent reconcile changed OVN inventory.\ninitial=%+v\nafter=%+v", initial, after)
	}
}

func TestDockerControllerReplayDoesNotChangeOVNState(t *testing.T) {
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
	waitForOVN(t, ctx, composeFile)

	statePath := "/tmp/netloom-state-replay.json"
	prepareStateScript := "cat >" + statePath + " <<'EOF'\n" + desiredStateJSON() + "\nEOF\n"
	applyState := "NETLOOM_STATE_FILE=" + statePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", prepareStateScript+applyState)

	endpointID := endpointExternalIDForOVN("file", "file-pod-a")
	base := describeNetloomOVNInventory(t, ctx, composeFile, endpointID)
	baseManaged := map[string]int{
		"load_balancer":  len(activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"logical_router": len(activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"logical_switch": len(activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"nat":            len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
	}

	for i := 0; i < 12; i++ {
		output := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", prepareStateScript+applyState)
		if !strings.Contains(output, "reconciled desired state") {
			t.Fatalf("replay iteration %d failed:\n%s", i, output)
		}
		current := describeNetloomOVNInventory(t, ctx, composeFile, endpointID)
		if !reflect.DeepEqual(base, current) {
			t.Fatalf("OVN inventory changed on replay iteration %d.\nbefore=%+v\nafter=%+v", i, base, current)
		}
		currentManaged := map[string]int{
			"load_balancer":  len(activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
			"logical_router": len(activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
			"logical_switch": len(activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
			"nat":            len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		}
		for table, beforeCount := range baseManaged {
			if currentManaged[table] != beforeCount {
				t.Fatalf("managed resource count changed at iteration %d for %s: before=%d after=%d", i, table, beforeCount, currentManaged[table])
			}
		}
	}
}

func TestDockerControllerConcurrentReconcilesAreStable(t *testing.T) {
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
	waitForOVN(t, ctx, composeFile)

	stateScript := "cat >/tmp/netloom-state.json <<'EOF'\n" + desiredStateJSON() + "\nEOF\n"
	stateCommand := stateScript + "NETLOOM_STATE_FILE=/tmp/netloom-state.json NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	endpointID := endpointExternalIDForOVN("file", "file-pod-a")
	beforeInventory := describeNetloomOVNInventory(t, ctx, composeFile, endpointID)
	beforeManagedRows := map[string]int{
		"load_balancer":  len(activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"logical_router": len(activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"logical_switch": len(activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"nat":            len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
	}

	reconcilerCount := runtime.NumCPU() * 3
	if reconcilerCount < 6 {
		reconcilerCount = 6
	}
	baseStatePath := "/tmp/netloom-state-concurrent-base.json"
	reconcileStatePath := "/tmp/netloom-state-concurrent.json"
	baseWriteScript := "cat >" + baseStatePath + " <<'EOF'\n" + desiredStateJSON() + "\nEOF\n"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", baseWriteScript)
	atomicallyRefreshState := "tmp=$(mktemp /tmp/netloom-state-concurrent-XXXXXXXXXXXX.tmp) && cp " + baseStatePath + " \"$tmp\" && mv \"$tmp\" " + reconcileStatePath

	watchLog := "/tmp/netloom-controller-concurrent-watch.log"
	watchCommand := atomicallyRefreshState + "\n" + "NETLOOM_STATE_FILE=" + reconcileStatePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock NETLOOM_RECONCILE_INTERVAL_MS=300 /netloom/bin/netloom-controller >" + watchLog + " 2>&1"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", watchCommand+" &")
	waitForControllerWatch := func(expected string) {
		for i := 0; i < 20; i++ {
			output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "grep -Fq '"+expected+"' "+watchLog+" && exit 0 || exit 1")
			if output.exitCode == 0 {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		logOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cat", watchLog)
		t.Fatalf("controller watch did not emit %q in time:\n%s", expected, logOutput)
	}
	waitForControllerWatch("reconciled desired state")

	writerErrors := make(chan error, reconcilerCount)
	for i := 0; i < reconcilerCount; i++ {
		reconcileDelay := time.Duration(i%3) * 100 * time.Millisecond
		go func(delay time.Duration) {
			time.Sleep(delay)
			for j := 0; j < 4; j++ {
				output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", atomicallyRefreshState)
				if output.exitCode != 0 {
					writerErrors <- fmt.Errorf("state refresh failed: %s", output.output)
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			writerErrors <- nil
		}(reconcileDelay)
	}
	for i := 0; i < reconcilerCount; i++ {
		if err := <-writerErrors; err != nil {
			t.Fatalf("concurrent reconcile trigger failed: %v", err)
		}
	}
	waitForControllerWatch("reconciled desired state")

	afterInventory := describeNetloomOVNInventory(t, ctx, composeFile, endpointID)
	if !reflect.DeepEqual(beforeInventory, afterInventory) {
		t.Fatalf("OVN inventory changed after concurrent reconcile triggers.\nbefore=%+v\nafter=%+v", beforeInventory, afterInventory)
	}

	afterManagedRows := map[string]int{
		"load_balancer":  len(activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"logical_router": len(activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"logical_switch": len(activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"nat":            len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
	}

	for table, beforeCount := range beforeManagedRows {
		if afterManagedRows[table] != beforeCount {
			t.Fatalf("managed resource count changed for %s: before=%d after=%d", table, beforeCount, afterManagedRows[table])
		}
	}
}

func TestDockerControllerConcurrentReconcilesAreStableAcrossVPCs(t *testing.T) {
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

	baseStatePath := "/tmp/netloom-state-dual-concurrent-base.json"
	reconcileStatePath := "/tmp/netloom-state-dual-concurrent.json"
	baseWriteScript := "cat >" + baseStatePath + " <<'EOF'\n" + desiredDualVPCStateJSON() + "\nEOF\n"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", baseWriteScript)
	atomicallyRefreshState := "tmp=$(mktemp /tmp/netloom-state-dual-concurrent-XXXXXXXXXXXX.tmp) && cp " + baseStatePath + " \"$tmp\" && mv \"$tmp\" " + reconcileStatePath
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cp "+baseStatePath+" "+reconcileStatePath)
	watchLog := "/tmp/netloom-controller-dual-vpc-concurrent-watch.log"
	watchCommand := atomicallyRefreshState + "\n" + "NETLOOM_STATE_FILE=" + reconcileStatePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock NETLOOM_RECONCILE_INTERVAL_MS=300 /netloom/bin/netloom-controller >" + watchLog + " 2>&1"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", watchCommand+" &")
	waitForControllerWatch := func(expected string) {
		for i := 0; i < 20; i++ {
			output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "grep -Fq '"+expected+"' "+watchLog+" && exit 0 || exit 1")
			if output.exitCode == 0 {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		logOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cat", watchLog)
		t.Fatalf("controller watch did not emit %q in time:\n%s", expected, logOutput)
	}
	waitForControllerWatch("reconciled desired state")

	fileEndpoint := endpointExternalIDForOVN("file", "shared-pod")
	blueEndpoint := endpointExternalIDForOVN("blue", "shared-pod")
	snapshot := func() map[string]map[string]int {
		return map[string]map[string]int{
			"file": {
				"logical_router":        len(activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"logical_switch":        len(activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"logical_switch_port":   len(activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_endpoint="+fileEndpoint)),
				"nat":                   len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"load_balancer":         len(activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"logical_router_policy": len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
			},
			"blue": {
				"logical_router":        len(activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"logical_switch":        len(activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"logical_switch_port":   len(activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue", "external_ids:netloom_endpoint="+blueEndpoint)),
				"nat":                   len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"load_balancer":         len(activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"logical_router_policy": len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
			},
		}
	}

	before := snapshot()
	reconcilerCount := runtime.NumCPU() * 3
	if reconcilerCount < 6 {
		reconcilerCount = 6
	}
	writerErrors := make(chan error, reconcilerCount)
	for i := 0; i < reconcilerCount; i++ {
		reconcileDelay := time.Duration(i%3) * 100 * time.Millisecond
		go func(delay time.Duration) {
			time.Sleep(delay)
			for j := 0; j < 4; j++ {
				output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", atomicallyRefreshState)
				if output.exitCode != 0 {
					writerErrors <- fmt.Errorf("state refresh failed: %s", output.output)
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			writerErrors <- nil
		}(reconcileDelay)
	}

	for i := 0; i < reconcilerCount; i++ {
		if err := <-writerErrors; err != nil {
			t.Fatalf("concurrent reconcile trigger failed: %v", err)
		}
	}
	waitForControllerWatch("reconciled desired state")

	after := snapshot()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("OVN snapshot changed after concurrent dual-vpc reconcile triggers.\nbefore=%+v\nafter=%+v", before, after)
	}
	filePorts := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_endpoint="+fileEndpoint)
	bluePorts := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue", "external_ids:netloom_endpoint="+blueEndpoint)
	if len(filePorts) != 1 || len(bluePorts) != 1 {
		t.Fatalf("expected one endpoint port per vpc after concurrent reconcile, got file=%v blue=%v", filePorts, bluePorts)
	}

}

func TestDockerControllerWatchRecoversFromRestart(t *testing.T) {
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

	statePath := "/tmp/netloom-state-restart.json"
	controllerPIDFile := "/tmp/netloom-controller-watch-restart.pid"
	stateScript := "cat >" + statePath + " <<'EOF'\n" + desiredStateJSON() + "\nEOF\n"
	stateCommand := stateScript + "NETLOOM_STATE_FILE=" + statePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	endpointID := endpointExternalIDForOVN("file", "file-pod-a")
	initialPort := strings.TrimSpace(findLogicalPortByEndpointID(t, ctx, composeFile, endpointID))
	if initialPort == "" {
		t.Fatalf("missing logical_switch_port for initial endpoint %s", endpointID)
	}

	watchLog := "/tmp/netloom-controller-watch-restart.log"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat /dev/null > "+watchLog+" && "+stateScript+"\n"+"NETLOOM_STATE_FILE="+statePath+" NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock NETLOOM_RECONCILE_INTERVAL_MS=300 /netloom/bin/netloom-controller >"+watchLog+" 2>&1 &")
	waitForControllerWatch := func(expected string) {
		for i := 0; i < 20; i++ {
			output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "grep -Fq '"+expected+"' "+watchLog+" && exit 0 || exit 1")
			if output.exitCode == 0 {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		logOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cat", watchLog)
		t.Fatalf("controller watch did not emit %q in time:\n%s", expected, logOutput)
	}
	startControllerWatch := func() {
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat /dev/null > "+watchLog+"; (NETLOOM_STATE_FILE="+statePath+" NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock NETLOOM_RECONCILE_INTERVAL_MS=300 /netloom/bin/netloom-controller >"+watchLog+" 2>&1 &) ; echo $! > "+controllerPIDFile)
	}
	stopControllerWatch := func() {
		runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "pid=$(cat "+controllerPIDFile+" 2>/dev/null || true); [ -n \"$pid\" ] && kill -9 \"$pid\" || true; rm -f "+controllerPIDFile)
	}

	startControllerWatch()
	waitForControllerWatch("reconciled desired state")

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock destroy logical_switch_port "+initialPort)
	stopControllerWatch()
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat /dev/null > "+watchLog)
	startControllerWatch()
	waitForControllerWatch("reconciled desired state")

	recoveredPort := strings.TrimSpace(findLogicalPortByEndpointID(t, ctx, composeFile, endpointID))
	if recoveredPort == "" {
		recoveredWatchLog := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cat", watchLog)
		t.Fatalf("endpoint port not recovered after restart.\nwatch log:\n%s", recoveredWatchLog)
	}

	stopControllerWatch()
}

func TestDockerControllerWatchRecoversFromOVNDBRestart(t *testing.T) {
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
	waitForOVN(t, ctx, composeFile)

	statePath := "/tmp/netloom-state-ovn-health-restart.json"
	controllerPIDPath := "/tmp/netloom-controller-ovn-health-restart.pid"
	controllerLogPath := "/tmp/netloom-controller-ovn-health-restart.log"
	baseStatePath := "/tmp/netloom-state-ovn-health-restart-base.json"
	updatedStatePath := "/tmp/netloom-state-ovn-health-restart-updated.json"

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat >"+baseStatePath+" <<'EOF'\n"+desiredStateJSON()+"\nEOF")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat >"+updatedStatePath+" <<'EOF'\n"+desiredStateWithUpdatedStaticRouteJSON()+"\nEOF")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cp", baseStatePath, statePath)

	startControllerWatch := "cat /dev/null > " + controllerLogPath + "; (NETLOOM_STATE_FILE=" + statePath + " NETLOOM_RECONCILE_INTERVAL_MS=250 NETLOOM_RECONCILE_FAILURE_BACKOFF_MS=100 NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller >" + controllerLogPath + " 2>&1 &) ; echo $! > " + controllerPIDPath
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", startControllerWatch)
	t.Cleanup(func() {
		runAllowFailure(t, context.Background(), "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "pid=$(cat "+controllerPIDPath+" 2>/dev/null || true); [ -n \"$pid\" ] && kill -9 \"$pid\" || true; rm -f "+controllerPIDPath)
	})

	waitForControllerWatchLog := func(expected string) {
		for i := 0; i < 30; i++ {
			output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "grep -Fq '"+expected+"' "+controllerLogPath+" && exit 0 || exit 1")
			if output.exitCode == 0 {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		logOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cat", controllerLogPath)
		t.Fatalf("controller watch did not emit %q in time:\n%s", expected, logOutput)
	}

	waitForControllerWatchLog("reconciled desired state")
	waitForControllerWatchLog("ovn_health=ok")

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "pid=$(cat /var/run/ovn/ovnnb_db.pid); kill \"$pid\"")
	waitForControllerWatchLog("netloom-controller reconcile failed: ovn health check:")

	restartOVN := "mkdir -p /var/run/ovn /var/lib/ovn\n" +
		"ovsdb-server --detach --pidfile=/var/run/ovn/ovnnb_db.pid --remote=punix:/var/run/ovn/ovnnb_db.sock /var/lib/ovn/ovnnb_db.db\n" +
		"ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock init"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", restartOVN)
	waitForOVN(t, ctx, composeFile)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cp", updatedStatePath, statePath)
	waitForControllerWatchLog("ovn_health=ok")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "for i in $(seq 1 20); do routes=$(ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-route-list nl_lr_file); echo \"$routes\" | grep -q '10.245.0.251' && ! echo \"$routes\" | grep -q '10.245.0.254' && exit 0; sleep 1; done; cat "+controllerLogPath+"; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock lr-route-list nl_lr_file; exit 1")
}

func TestDockerControllerReconcileSupportsSameEndpointIDAcrossVPCs(t *testing.T) {
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

	statePath := "/tmp/netloom-state-dual-vpc.json"
	stateScript := "cat >" + statePath + " <<'EOF'\n" + desiredDualVPCStateJSON() + "\nEOF\n"
	stateCommand := stateScript + "NETLOOM_STATE_FILE=" + statePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	fileEndpoint := endpointExternalIDForOVN("file", "shared-pod")
	blueEndpoint := endpointExternalIDForOVN("blue", "shared-pod")
	filePorts := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_endpoint="+fileEndpoint)
	bluePorts := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue", "external_ids:netloom_endpoint="+blueEndpoint)
	if len(filePorts) != 1 {
		t.Fatalf("expected one logical switch port for file shared-pod, got %d (%v)", len(filePorts), filePorts)
	}
	if len(bluePorts) != 1 {
		t.Fatalf("expected one logical switch port for blue shared-pod, got %d (%v)", len(bluePorts), bluePorts)
	}
	if filePorts[0] == bluePorts[0] {
		t.Fatalf("expected VPC-scoped endpoints to produce distinct logical switch port names: %s", filePorts[0])
	}
}

func TestDockerControllerSupportsSameResourceNamesAcrossVPCs(t *testing.T) {
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

	statePath := "/tmp/netloom-state-dual-vpc-same-name.json"
	stateScript := "cat >" + statePath + " <<'EOF'\n" + desiredDualVPCSameNameStateJSON() + "\nEOF\n"
	stateCommand := stateScript + "NETLOOM_STATE_FILE=" + statePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	fileEndpoint := endpointExternalIDForOVN("file", "shared-pod")
	blueEndpoint := endpointExternalIDForOVN("blue", "shared-pod")
	filePorts := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_endpoint="+fileEndpoint)
	bluePorts := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue", "external_ids:netloom_endpoint="+blueEndpoint)
	if len(filePorts) != 1 {
		t.Fatalf("expected one logical switch port for file shared-pod, got %d (%v)", len(filePorts), filePorts)
	}
	if len(bluePorts) != 1 {
		t.Fatalf("expected one logical switch port for blue shared-pod, got %d (%v)", len(bluePorts), bluePorts)
	}
	if filePorts[0] == bluePorts[0] {
		t.Fatalf("expected VPC-scoped resources to produce distinct logical switch port names: %s", filePorts[0])
	}

	fileRouters := activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")
	blueRouters := activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")
	if len(fileRouters) != 1 {
		t.Fatalf("expected one file logical_router, got %d (%v)", len(fileRouters), fileRouters)
	}
	if len(blueRouters) != 1 {
		t.Fatalf("expected one blue logical_router, got %d (%v)", len(blueRouters), blueRouters)
	}
	if fileRouters[0] == blueRouters[0] {
		t.Fatalf("expected VPC-scoped logical_router names to differ, both=%s", fileRouters[0])
	}

	fileSwitches := activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")
	blueSwitches := activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")
	if len(fileSwitches) != 1 {
		t.Fatalf("expected one file logical_switch, got %d (%v)", len(fileSwitches), fileSwitches)
	}
	if len(blueSwitches) != 1 {
		t.Fatalf("expected one blue logical_switch, got %d (%v)", len(blueSwitches), blueSwitches)
	}
	if fileSwitches[0] == blueSwitches[0] {
		t.Fatalf("expected VPC-scoped logical_switch names to differ, both=%s", fileSwitches[0])
	}

	fileL4lb := findLoadBalancerForVIP(t, ctx, composeFile, "file", "cross-vpc-web", "10.96.0.20")
	blueL4lb := findLoadBalancerForVIP(t, ctx, composeFile, "blue", "cross-vpc-web", "10.96.0.20")
	if fileL4lb == "" || blueL4lb == "" {
		t.Fatalf("expected VPC-specific load balancers for shared VIP, file=%s blue=%s", fileL4lb, blueL4lb)
	}
	if fileL4lb == blueL4lb {
		t.Fatalf("expected VPC-scoped load balancer names to differ, both=%s", fileL4lb)
	}

	fileNAT := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-nat-list", "nl_lr_file")
	blueNAT := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-nat-list", "nl_lr_blue")
	if !strings.Contains(fileNAT, "198.51.100.50") {
		t.Fatalf("file router NAT should include 198.51.100.50, output:\n%s", fileNAT)
	}
	if !strings.Contains(blueNAT, "198.51.101.50") {
		t.Fatalf("blue router NAT should include 198.51.101.50, output:\n%s", blueNAT)
	}
	if strings.Contains(fileNAT, "198.51.101.50") {
		t.Fatalf("file router NAT should not include blue NAT external IP, output:\n%s", fileNAT)
	}
	if strings.Contains(blueNAT, "198.51.100.50") {
		t.Fatalf("blue router NAT should not include file NAT external IP, output:\n%s", blueNAT)
	}

	fileRoutes := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_file")
	blueRoutes := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_blue")
	fileHops := parseRouteNextHopsFromList(t, fileRoutes, "0.0.0.0/0")
	blueHops := parseRouteNextHopsFromList(t, blueRoutes, "0.0.0.0/0")
	if !routeListContainsHops(fileHops, []string{"10.245.0.254"}) {
		t.Fatalf("file route table missing expected default nexthop 10.245.0.254: %v\n%s", fileHops, fileRoutes)
	}
	if !routeListContainsHops(blueHops, []string{"10.246.0.254"}) {
		t.Fatalf("blue route table missing expected default nexthop 10.246.0.254: %v\n%s", blueHops, blueRoutes)
	}
	if routeListContainsHops(fileHops, []string{"10.246.0.254"}) {
		t.Fatalf("file route table should not contain blue default nexthop, got %v", fileHops)
	}
	if routeListContainsHops(blueHops, []string{"10.245.0.254"}) {
		t.Fatalf("blue route table should not contain file default nexthop, got %v", blueHops)
	}
}

func TestDockerControllerReplaySameResourceNamesAcrossVPCs(t *testing.T) {
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

	statePath := "/tmp/netloom-state-dual-vpc-same-name-replay.json"
	stateScript := "cat >" + statePath + " <<'EOF'\n" + desiredDualVPCSameNameStateJSON() + "\nEOF\n"
	stateCommand := stateScript + "NETLOOM_STATE_FILE=" + statePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	fileEndpoint := endpointExternalIDForOVN("file", "shared-pod")
	blueEndpoint := endpointExternalIDForOVN("blue", "shared-pod")
	snapshot := func() map[string]map[string]int {
		return map[string]map[string]int{
			"file": {
				"logical_router":        len(activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"logical_switch":        len(activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"logical_switch_port":   len(activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_endpoint="+fileEndpoint)),
				"nat":                   len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"load_balancer":         len(activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"logical_router_policy": len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
			},
			"blue": {
				"logical_router":        len(activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"logical_switch":        len(activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"logical_switch_port":   len(activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue", "external_ids:netloom_endpoint="+blueEndpoint)),
				"nat":                   len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"load_balancer":         len(activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"logical_router_policy": len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
			},
		}
	}
	base := snapshot()

	fileL4lb := findLoadBalancerForVIP(t, ctx, composeFile, "file", "cross-vpc-web", "10.96.0.20")
	blueL4lb := findLoadBalancerForVIP(t, ctx, composeFile, "blue", "cross-vpc-web", "10.96.0.20")
	if fileL4lb == "" || blueL4lb == "" {
		t.Fatalf("expected initial VPC-specific LB for shared VIP, file=%s blue=%s", fileL4lb, blueL4lb)
	}
	if fileL4lb == blueL4lb {
		t.Fatalf("expected VPC-specific LB names to differ during replay, both=%s", fileL4lb)
	}
	checkNATIsolation := func() {
		fileNAT := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-nat-list", "nl_lr_file")
		blueNAT := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-nat-list", "nl_lr_blue")
		if !strings.Contains(fileNAT, "198.51.100.50") {
			t.Fatalf("file router NAT should include 198.51.100.50, output:\n%s", fileNAT)
		}
		if !strings.Contains(blueNAT, "198.51.101.50") {
			t.Fatalf("blue router NAT should include 198.51.101.50, output:\n%s", blueNAT)
		}
		if strings.Contains(fileNAT, "198.51.101.50") {
			t.Fatalf("file router NAT should not include blue NAT external IP, output:\n%s", fileNAT)
		}
		if strings.Contains(blueNAT, "198.51.100.50") {
			t.Fatalf("blue router NAT should not include file NAT external IP, output:\n%s", blueNAT)
		}
	}
	checkNATIsolation()

	reconcile := func() {
		output := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)
		if !strings.Contains(output, "reconciled desired state") {
			t.Fatalf("reconcile failed:\n%s", output)
		}
	}

	for i := 0; i < 8; i++ {
		reconcile()
		current := snapshot()
		if !reflect.DeepEqual(base, current) {
			t.Fatalf("resource counts drift on same-name replay iteration %d.\nbase=%+v\ncurrent=%+v", i, base, current)
		}
		currentFilePorts := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_endpoint="+fileEndpoint)
		currentBluePorts := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue", "external_ids:netloom_endpoint="+blueEndpoint)
		if len(currentFilePorts) != 1 || len(currentBluePorts) != 1 {
			t.Fatalf("expected one endpoint port per vpc after iteration %d: file=%v blue=%v", i, currentFilePorts, currentBluePorts)
		}
		if currentFilePorts[0] == currentBluePorts[0] {
			t.Fatalf("endpoint port names should remain VPC-scoped and distinct at iteration %d: %s", i, currentFilePorts[0])
		}
		checkNATIsolation()
	}
}

func TestDockerControllerSameResourceNamesAcrossVPCsIncludeRoutes(t *testing.T) {
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

	statePath := "/tmp/netloom-state-dual-vpc-same-name-routes.json"
	stateScript := "cat >" + statePath + " <<'EOF'\n" + desiredDualVPCSameNameStateJSON() + "\nEOF\n"
	stateCommand := stateScript + "NETLOOM_STATE_FILE=" + statePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	fileRoutes := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_file")
	blueRoutes := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_blue")

	fileHops := parseRouteNextHopsFromList(t, fileRoutes, "0.0.0.0/0")
	blueHops := parseRouteNextHopsFromList(t, blueRoutes, "0.0.0.0/0")
	if !routeListContainsHops(fileHops, []string{"10.245.0.254"}) {
		t.Fatalf("file route table missing expected nexthop for default route: %v\n%s", fileHops, fileRoutes)
	}
	if !routeListContainsHops(blueHops, []string{"10.246.0.254"}) {
		t.Fatalf("blue route table missing expected nexthop for default route: %v\n%s", blueHops, blueRoutes)
	}
	if routeListContainsHops(fileHops, []string{"10.246.0.254"}) {
		t.Fatalf("file route table should not contain blue default nexthop, got %v", fileHops)
	}
	if routeListContainsHops(blueHops, []string{"10.245.0.254"}) {
		t.Fatalf("blue route table should not contain file default nexthop, got %v", blueHops)
	}
}

func TestDockerControllerStateReplayDetectsManagedOVNLeaks(t *testing.T) {
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

	statePath := "/tmp/netloom-state-leak.json"
	stateScript := "cat >" + statePath + " <<'EOF'\n" + desiredStateJSON() + "\nEOF\n"
	stateCommand := stateScript + "NETLOOM_STATE_FILE=" + statePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	beforeManagedRows := map[string]int{
		"NAT":                        len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Logical_Router_Policy":      len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"DHCP_Options":               len(activeManagedRows(t, ctx, composeFile, "DHCP_Options", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Load_Balancer_Health_Check": len(activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_load_balancer=file-web")),
	}
	staleManagedNAT := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_nat create NAT type=snat external_ip=198.51.100.220 logical_ip=10.10.0.220 external_ids:netloom_owner=netloom external_ids:netloom_nat=stale-leak external_ids:netloom_vpc=file -- add logical_router nl_lr_file nat @stale_managed_nat"
	staleManagedPolicy := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_policy create Logical_Router_Policy priority=250 match='ip' action=drop external_ids:netloom_owner=netloom external_ids:netloom_policy_route=stale-leak external_ids:netloom_vpc=file -- add logical_router nl_lr_file policies @stale_managed_policy"
	staleManagedDHCP := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock create DHCP_Options cidr=10.245.0.0/24 options:server_id=10.245.0.1 options:server_mac=0a:58:0a:f5:00:01 options:router=10.245.0.1 options:lease_time=7200 external_ids:netloom_owner=netloom external_ids:netloom_subnet=fileapps external_ids:netloom_endpoint=" + endpointExternalIDForOVN("file", "stale-pod") + " external_ids:netloom_vpc=file"
	unmanagedNAT := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_unmanaged_nat create NAT type=snat external_ip=198.51.100.221 logical_ip=10.10.0.221 external_ids:notes=netloom-unmanaged-leak external_ids:owner=manual -- add logical_router nl_lr_file nat @stale_unmanaged_nat"
	staleManagedLBHC := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_lbhc create Load_Balancer_Health_Check vip=10.96.0.99 options:interval=5 options:timeout=20 options:success_count=3 options:failure_count=3 external_ids:netloom_owner=netloom external_ids:netloom_load_balancer=file-web external_ids:netloom_vpc=file"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedNAT)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedPolicy)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedDHCP)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", unmanagedNAT)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedLBHC)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	afterManagedRows := map[string]int{
		"NAT":                        len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Logical_Router_Policy":      len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"DHCP_Options":               len(activeManagedRows(t, ctx, composeFile, "DHCP_Options", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Load_Balancer_Health_Check": len(activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_load_balancer=file-web")),
	}
	if beforeManagedRows["NAT"] != afterManagedRows["NAT"] {
		t.Fatalf("managed NAT count changed after leak cleanup: before=%d after=%d", beforeManagedRows["NAT"], afterManagedRows["NAT"])
	}
	if beforeManagedRows["Logical_Router_Policy"] != afterManagedRows["Logical_Router_Policy"] {
		t.Fatalf("managed policy route count changed after leak cleanup: before=%d after=%d", beforeManagedRows["Logical_Router_Policy"], afterManagedRows["Logical_Router_Policy"])
	}
	if beforeManagedRows["DHCP_Options"] != afterManagedRows["DHCP_Options"] {
		t.Fatalf("managed DHCP option count changed after leak cleanup: before=%d after=%d", beforeManagedRows["DHCP_Options"], afterManagedRows["DHCP_Options"])
	}
	if beforeManagedRows["Load_Balancer_Health_Check"] != afterManagedRows["Load_Balancer_Health_Check"] {
		t.Fatalf("managed LB health check count changed after leak cleanup: before=%d after=%d", beforeManagedRows["Load_Balancer_Health_Check"], afterManagedRows["Load_Balancer_Health_Check"])
	}

	staleManagedNATRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_nat=stale-leak", "external_ids:netloom_vpc=file")
	if strings.TrimSpace(staleManagedNATRows.output) != "" {
		t.Fatalf("stale managed NAT row should be cleaned: %s", staleManagedNATRows.output)
	}
	staleManagedPolicyRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_policy_route=stale-leak", "external_ids:netloom_vpc=file")
	if strings.TrimSpace(staleManagedPolicyRows.output) != "" {
		t.Fatalf("stale managed policy row should be cleaned: %s", staleManagedPolicyRows.output)
	}
	staleManagedDHCPRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "DHCP_Options", "external_ids:netloom_owner=netloom", "external_ids:netloom_endpoint="+endpointExternalIDForOVN("file", "stale-pod"), "external_ids:netloom_vpc=file")
	if strings.TrimSpace(staleManagedDHCPRows.output) != "" {
		t.Fatalf("stale managed DHCP option row should be cleaned: %s", staleManagedDHCPRows.output)
	}
	staleManagedLBHCRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_load_balancer=file-web", "external_ids:netloom_vpc=file", "vip=10.96.0.99")
	if strings.TrimSpace(staleManagedLBHCRows.output) != "" {
		t.Fatalf("stale managed LB health check row should be cleaned: %s", staleManagedLBHCRows.output)
	}

	unmanagedNATRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "NAT", "external_ids:notes=netloom-unmanaged-leak", "external_ids:owner=manual")
	if strings.TrimSpace(unmanagedNATRows.output) == "" {
		t.Fatalf("expected unmanaged leak row to remain for leakage validation")
	}

	for i := 0; i < 3; i++ {
		replayOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)
		if !strings.Contains(replayOutput, "reconciled desired state") {
			t.Fatalf("managed leak cleanup replay iteration %d failed:\n%s", i, replayOutput)
		}
		afterReplayManagedRows := map[string]int{
			"NAT":                        len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
			"Logical_Router_Policy":      len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
			"DHCP_Options":               len(activeManagedRows(t, ctx, composeFile, "DHCP_Options", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
			"Load_Balancer_Health_Check": len(activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_load_balancer=file-web")),
		}
		for table, beforeCount := range beforeManagedRows {
			if afterReplayManagedRows[table] != beforeCount {
				t.Fatalf("managed resource count changed after replay iteration %d for table %s: before=%d after=%d", i, table, beforeCount, afterReplayManagedRows[table])
			}
		}
		replayedManagedNATRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_nat=stale-leak", "external_ids:netloom_vpc=file")
		if strings.TrimSpace(replayedManagedNATRows.output) != "" {
			t.Fatalf("stale managed NAT row should be cleaned after replay iteration %d: %s", i, replayedManagedNATRows.output)
		}
		replayedManagedPolicyRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_policy_route=stale-leak", "external_ids:netloom_vpc=file")
		if strings.TrimSpace(replayedManagedPolicyRows.output) != "" {
			t.Fatalf("stale managed policy row should be cleaned after replay iteration %d: %s", i, replayedManagedPolicyRows.output)
		}
		replayedManagedDHCPRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "DHCP_Options", "external_ids:netloom_owner=netloom", "external_ids:netloom_endpoint="+endpointExternalIDForOVN("file", "stale-pod"), "external_ids:netloom_vpc=file")
		if strings.TrimSpace(replayedManagedDHCPRows.output) != "" {
			t.Fatalf("stale managed DHCP option row should be cleaned after replay iteration %d: %s", i, replayedManagedDHCPRows.output)
		}
		replayedManagedLBHCRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_load_balancer=file-web", "external_ids:netloom_vpc=file", "vip=10.96.0.99")
		if strings.TrimSpace(replayedManagedLBHCRows.output) != "" {
			t.Fatalf("stale managed LB health check row should be cleaned after replay iteration %d: %s", i, replayedManagedLBHCRows.output)
		}
		replayedUnmanagedNATRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "NAT", "external_ids:notes=netloom-unmanaged-leak", "external_ids:owner=manual")
		if strings.TrimSpace(replayedUnmanagedNATRows.output) == "" {
			t.Fatalf("unmanaged leak row should remain after replay iteration %d", i)
		}
	}
}

func TestDockerControllerRestartRecoversManagedOVNLeakCleanup(t *testing.T) {
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

	statePath := "/tmp/netloom-state-leak-restart.json"
	stateWrite := "cat >" + statePath + " <<'EOF'\n" + desiredStateJSON() + "\nEOF\n"
	stateCommand := stateWrite + "NETLOOM_STATE_FILE=" + statePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	before := map[string]int{
		"NAT":                        len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Logical_Router_Policy":      len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Load_Balancer_Health_Check": len(activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_load_balancer=file-web")),
	}

	controllerLog := "/tmp/netloom-controller-leak-restart.log"
	controllerPID := "/tmp/netloom-controller-leak-restart.pid"
	routerName := "nl_lr_file"
	controllerRun := "cat /dev/null > " + controllerLog + "; (NETLOOM_STATE_FILE=" + statePath + " NETLOOM_RECONCILE_INTERVAL_MS=300 NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller >" + controllerLog + " 2>&1 &) ; echo $! > " + controllerPID
	startController := func() {
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", controllerRun)
	}
	stopController := func() {
		runAllowFailure(t, context.Background(), "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "pid=$(cat "+controllerPID+" 2>/dev/null || true); [ -n \"$pid\" ] && kill -9 \"$pid\" || true; rm -f "+controllerPID)
	}
	waitForControllerWatch := func(expected string) {
		for i := 0; i < 30; i++ {
			output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "grep -Fq '"+expected+"' "+controllerLog+" && exit 0 || exit 1")
			if output.exitCode == 0 {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		logOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cat", controllerLog)
		t.Fatalf("controller watch did not emit %q in time:\n%s", expected, logOutput)
	}

	startController()
	waitForControllerWatch("reconciled desired state")
	stopController()

	staleManagedNAT := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_nat_restart create NAT type=snat external_ip=198.51.100.230 logical_ip=10.10.0.230 external_ids:netloom_owner=netloom external_ids:netloom_nat=stale-restart-leak external_ids:netloom_vpc=file -- add logical_router " + routerName + " nat @stale_managed_nat_restart"
	staleManagedPolicy := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_policy_restart create Logical_Router_Policy priority=280 match='ip' action=drop external_ids:netloom_owner=netloom external_ids:netloom_policy_route=stale-restart-leak external_ids:netloom_vpc=file -- add logical_router " + routerName + " policies @stale_managed_policy_restart"
	staleManagedLBHC := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_lbhc_restart create Load_Balancer_Health_Check vip=10.96.0.90 options:interval=5 options:timeout=20 options:success_count=3 options:failure_count=3 external_ids:netloom_owner=netloom external_ids:netloom_load_balancer=file-web external_ids:netloom_vpc=file external_ids:netloom_lbhc=stale-restart-leak"
	unmanagedNAT := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_unmanaged_nat_restart create NAT type=snat external_ip=198.51.100.223 logical_ip=10.10.0.223 external_ids:notes=netloom-unmanaged-leak external_ids:owner=manual -- add logical_router " + routerName + " nat @stale_unmanaged_nat_restart"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedNAT)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedPolicy)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedLBHC)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", unmanagedNAT)

	startController()
	waitForControllerWatch("reconciled desired state")

	after := map[string]int{
		"NAT":                        len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Logical_Router_Policy":      len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Load_Balancer_Health_Check": len(activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_load_balancer=file-web")),
	}
	for table, beforeCount := range before {
		if after[table] != beforeCount {
			t.Fatalf("managed resource count changed after restart cleanup: table=%s before=%d after=%d", table, beforeCount, after[table])
		}
	}

	staleManagedNATRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_nat=stale-restart-leak", "external_ids:netloom_vpc=file")
	if strings.TrimSpace(staleManagedNATRows.output) != "" {
		t.Fatalf("stale managed NAT row should be cleaned after restart: %s", staleManagedNATRows.output)
	}
	staleManagedPolicyRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_policy_route=stale-restart-leak", "external_ids:netloom_vpc=file")
	if strings.TrimSpace(staleManagedPolicyRows.output) != "" {
		t.Fatalf("stale managed policy row should be cleaned after restart: %s", staleManagedPolicyRows.output)
	}
	staleManagedLBHCRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_load_balancer=file-web", "external_ids:netloom_vpc=file", "external_ids:netloom_lbhc=stale-restart-leak")
	if strings.TrimSpace(staleManagedLBHCRows.output) != "" {
		t.Fatalf("stale managed LB health check row should be cleaned after restart: %s", staleManagedLBHCRows.output)
	}
	unmanagedNATRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "NAT", "external_ids:notes=netloom-unmanaged-leak", "external_ids:owner=manual")
	if strings.TrimSpace(unmanagedNATRows.output) == "" {
		t.Fatalf("expected unmanaged leak row to remain after restart")
	}

	stopController()
	t.Cleanup(func() {
		stopController()
	})
}

func TestDockerControllerStateReplayDetectsManagedOVNLeaksAcrossVPCs(t *testing.T) {
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

	statePath := "/tmp/netloom-state-leak-dual.json"
	stateScript := "cat >" + statePath + " <<'EOF'\n" + desiredDualVPCStateJSON() + "\nEOF\n"
	stateCommand := stateScript + "NETLOOM_STATE_FILE=" + statePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	beforeManagedRows := map[string]map[string]int{
		"file": {},
		"blue": {},
	}
	for _, vpc := range []string{"file", "blue"} {
		beforeManagedRows[vpc]["NAT"] = len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc))
		beforeManagedRows[vpc]["Logical_Router_Policy"] = len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc))
		beforeManagedRows[vpc]["Load_Balancer_Health_Check"] = len(activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc, "external_ids:netloom_load_balancer=cross-vpc-web"))
	}

	for _, vpc := range []string{"file", "blue"} {
		routerName := "nl_lr_" + vpc
		staleManagedNAT := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_nat_" + vpc + " create NAT type=snat external_ip=198.51.100.220 logical_ip=10.10.0.22" + map[string]string{"file": "0", "blue": "1"}[vpc] + " external_ids:netloom_owner=netloom external_ids:netloom_nat=stale-leak-" + vpc + " external_ids:netloom_vpc=" + vpc + " -- add logical_router " + routerName + " nat @stale_managed_nat_" + vpc
		staleManagedPolicy := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_policy_" + vpc + " create Logical_Router_Policy priority=250 match='ip' action=drop external_ids:netloom_owner=netloom external_ids:netloom_policy_route=stale-leak-" + vpc + " external_ids:netloom_vpc=" + vpc + " -- add logical_router " + routerName + " policies @stale_managed_policy_" + vpc
		staleManagedLBHC := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_lbhc_" + vpc + " create Load_Balancer_Health_Check vip=10.96.0.9" + map[string]string{"file": "9", "blue": "8"}[vpc] + " options:interval=5 options:timeout=20 options:success_count=3 options:failure_count=3 external_ids:netloom_owner=netloom external_ids:netloom_load_balancer=cross-vpc-web external_ids:netloom_vpc=" + vpc + " external_ids:netloom_lbhc=stale-leak-" + vpc
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedNAT)
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedPolicy)
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedLBHC)
	}
	unmanagedNAT := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_unmanaged_nat create NAT type=snat external_ip=198.51.100.222 logical_ip=10.10.0.222 external_ids:notes=netloom-unmanaged-leak external_ids:owner=manual -- add logical_router nl_lr_file nat @stale_unmanaged_nat"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", unmanagedNAT)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	for _, vpc := range []string{"file", "blue"} {
		afterManagedRows := map[string]int{
			"NAT":                        len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc)),
			"Logical_Router_Policy":      len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc)),
			"Load_Balancer_Health_Check": len(activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc, "external_ids:netloom_load_balancer=cross-vpc-web")),
		}
		for table, beforeCount := range beforeManagedRows[vpc] {
			if afterManagedRows[table] != beforeCount {
				t.Fatalf("managed resource count changed for vpc=%s table=%s: before=%d after=%d", vpc, table, beforeCount, afterManagedRows[table])
			}
		}
	}

	for _, vpc := range []string{"file", "blue"} {
		staleManagedNATRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_nat=stale-leak-"+vpc, "external_ids:netloom_vpc="+vpc)
		if strings.TrimSpace(staleManagedNATRows.output) != "" {
			t.Fatalf("stale managed NAT row should be cleaned for vpc=%s: %s", vpc, staleManagedNATRows.output)
		}
		staleManagedPolicyRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_policy_route=stale-leak-"+vpc, "external_ids:netloom_vpc="+vpc)
		if strings.TrimSpace(staleManagedPolicyRows.output) != "" {
			t.Fatalf("stale managed policy row should be cleaned for vpc=%s: %s", vpc, staleManagedPolicyRows.output)
		}
		staleManagedLBHCRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_load_balancer=cross-vpc-web", "external_ids:netloom_vpc="+vpc, "external_ids:netloom_lbhc=stale-leak-"+vpc)
		if strings.TrimSpace(staleManagedLBHCRows.output) != "" {
			t.Fatalf("stale managed LB health check row should be cleaned for vpc=%s: %s", vpc, staleManagedLBHCRows.output)
		}
	}

	unmanagedNATRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "NAT", "external_ids:notes=netloom-unmanaged-leak", "external_ids:owner=manual")
	if strings.TrimSpace(unmanagedNATRows.output) == "" {
		t.Fatalf("expected unmanaged leak row to remain for leakage validation")
	}
}

func TestDockerControllerReplayDetectsManagedOVNLeaksAcrossVPCsIdempotent(t *testing.T) {
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

	statePath := "/tmp/netloom-state-leak-dual-replay-idempotent.json"
	stateScript := "cat >" + statePath + " <<'EOF'\n" + desiredDualVPCStateJSON() + "\nEOF\n"
	stateCommand := stateScript + "NETLOOM_STATE_FILE=" + statePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	beforeManagedRows := map[string]map[string]int{
		"file": {},
		"blue": {},
	}
	for _, vpc := range []string{"file", "blue"} {
		beforeManagedRows[vpc]["NAT"] = len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc))
		beforeManagedRows[vpc]["Logical_Router_Policy"] = len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc))
		beforeManagedRows[vpc]["Load_Balancer_Health_Check"] = len(activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc, "external_ids:netloom_load_balancer=cross-vpc-web"))
	}

	for _, vpc := range []string{"file", "blue"} {
		staleManagedNAT := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_nat_" + vpc + " create NAT type=snat external_ip=198.51.100.23" + map[string]string{"file": "0", "blue": "1"}[vpc] + " logical_ip=10.10.0.23" + map[string]string{"file": "0", "blue": "1"}[vpc] + " external_ids:netloom_owner=netloom external_ids:netloom_nat=stale-replay-leak-" + vpc + " external_ids:netloom_vpc=" + vpc + " -- add logical_router nl_lr_" + vpc + " nat @stale_managed_nat_" + vpc
		staleManagedPolicy := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_policy_" + vpc + " create Logical_Router_Policy priority=251 match='ip' action=drop external_ids:netloom_owner=netloom external_ids:netloom_policy_route=stale-replay-leak-" + vpc + " external_ids:netloom_vpc=" + vpc + " -- add logical_router nl_lr_" + vpc + " policies @stale_managed_policy_" + vpc
		staleManagedLBHC := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_lbhc_" + vpc + " create Load_Balancer_Health_Check vip=10.96.0.8" + map[string]string{"file": "0", "blue": "1"}[vpc] + " options:interval=5 options:timeout=20 options:success_count=3 options:failure_count=3 external_ids:netloom_owner=netloom external_ids:netloom_load_balancer=cross-vpc-web external_ids:netloom_vpc=" + vpc + " external_ids:netloom_lbhc=stale-replay-leak-" + vpc
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedNAT)
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedPolicy)
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedLBHC)
	}

	for i := 0; i < 4; i++ {
		replayOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)
		if !strings.Contains(replayOutput, "reconciled desired state") {
			t.Fatalf("replay iteration %d failed:\n%s", i, replayOutput)
		}

		for _, vpc := range []string{"file", "blue"} {
			afterManagedRows := map[string]int{
				"NAT":                        len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc)),
				"Logical_Router_Policy":      len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc)),
				"Load_Balancer_Health_Check": len(activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc, "external_ids:netloom_load_balancer=cross-vpc-web")),
			}
			for table, beforeCount := range beforeManagedRows[vpc] {
				if afterManagedRows[table] != beforeCount {
					t.Fatalf("managed resource count changed at replay iteration %d for vpc=%s table=%s: before=%d after=%d", i, vpc, table, beforeCount, afterManagedRows[table])
				}
			}

			staleNAT := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_nat=stale-replay-leak-"+vpc, "external_ids:netloom_vpc="+vpc)
			if strings.TrimSpace(staleNAT.output) != "" {
				t.Fatalf("stale managed NAT row should be cleaned at iteration %d for vpc=%s: %s", i, vpc, staleNAT.output)
			}
			stalePolicy := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_policy_route=stale-replay-leak-"+vpc, "external_ids:netloom_vpc="+vpc)
			if strings.TrimSpace(stalePolicy.output) != "" {
				t.Fatalf("stale managed policy row should be cleaned at iteration %d for vpc=%s: %s", i, vpc, stalePolicy.output)
			}
			staleLBHC := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_load_balancer=cross-vpc-web", "external_ids:netloom_vpc="+vpc, "external_ids:netloom_lbhc=stale-replay-leak-"+vpc)
			if strings.TrimSpace(staleLBHC.output) != "" {
				t.Fatalf("stale managed LBHC row should be cleaned at iteration %d for vpc=%s: %s", i, vpc, staleLBHC.output)
			}
		}
	}
}

func TestDockerControllerReplayDoesNotChangeOVNStateAcrossVPCs(t *testing.T) {
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

	stateScript := "cat >/tmp/netloom-state-replay-dual-vpc.json <<'EOF'\n" + desiredDualVPCStateJSON() + "\nEOF\n"
	runCommand := stateScript + "NETLOOM_STATE_FILE=/tmp/netloom-state-replay-dual-vpc.json NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", runCommand)

	fileEndpoint := endpointExternalIDForOVN("file", "shared-pod")
	blueEndpoint := endpointExternalIDForOVN("blue", "shared-pod")

	snapshot := func() map[string]map[string]int {
		return map[string]map[string]int{
			"file": {
				"logical_router":      len(activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"logical_switch":      len(activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"logical_switch_port": len(activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_endpoint="+fileEndpoint)),
				"nat":                 len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"load_balancer":       len(activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"policy_routes":       len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
			},
			"blue": {
				"logical_router":      len(activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"logical_switch":      len(activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"logical_switch_port": len(activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue", "external_ids:netloom_endpoint="+blueEndpoint)),
				"nat":                 len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"load_balancer":       len(activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"policy_routes":       len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
			},
		}
	}
	baseSnapshot := snapshot()

	for i := 0; i < 8; i++ {
		output := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", runCommand)
		if !strings.Contains(output, "reconciled desired state") {
			t.Fatalf("replay iteration %d failed:\n%s", i, output)
		}

		current := snapshot()
		if !reflect.DeepEqual(baseSnapshot, current) {
			t.Fatalf("OVN state changed on replay iteration %d.\nbase=%+v\ncurrent=%+v", i, baseSnapshot, current)
		}
	}
}

func TestDockerControllerReplaysRecoverOnDualVPCRestart(t *testing.T) {
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

	statePath := "/tmp/netloom-state-dual-vpc-watch.json"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat >"+statePath+" <<'EOF'\n"+desiredDualVPCStateJSON()+"\nEOF")

	controllerLogPath := "/tmp/netloom-controller-dual-vpc-watch.log"
	controllerPIDPath := "/tmp/netloom-controller-dual-vpc-watch.pid"
	controllerRun := "cat /dev/null > " + controllerLogPath + "; (NETLOOM_STATE_FILE=" + statePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock NETLOOM_RECONCILE_INTERVAL_MS=250 /netloom/bin/netloom-controller >" + controllerLogPath + " 2>&1 &) ; echo $! > " + controllerPIDPath
	startControllerWatch := func() {
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", controllerRun)
	}
	stopControllerWatch := func() {
		runAllowFailure(t, context.Background(), "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "pid=$(cat "+controllerPIDPath+" 2>/dev/null || true); [ -n \"$pid\" ] && kill -9 \"$pid\" || true; rm -f "+controllerPIDPath)
	}
	waitForControllerWatch := func(expected string) {
		for i := 0; i < 20; i++ {
			output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "grep -Fq '"+expected+"' "+controllerLogPath+" && exit 0 || exit 1")
			if output.exitCode == 0 {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		logOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cat", controllerLogPath)
		t.Fatalf("controller watch did not emit %q in time:\n%s", expected, logOutput)
	}
	snapshot := func() map[string]map[string]int {
		return map[string]map[string]int{
			"file": {
				"logical_router":      len(activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"logical_switch":      len(activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"logical_switch_port": len(activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"nat":                 len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
				"load_balancer":       len(activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
			},
			"blue": {
				"logical_router":      len(activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"logical_switch":      len(activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"logical_switch_port": len(activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"nat":                 len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
				"load_balancer":       len(activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue")),
			},
		}
	}

	startControllerWatch()
	waitForControllerWatch("reconciled desired state")
	baseSnapshot := snapshot()

	fileEndpoint := endpointExternalIDForOVN("file", "shared-pod")
	blueEndpoint := endpointExternalIDForOVN("blue", "shared-pod")
	filePorts := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_endpoint="+fileEndpoint)
	bluePorts := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue", "external_ids:netloom_endpoint="+blueEndpoint)
	if len(filePorts) != 1 || len(bluePorts) != 1 {
		t.Fatalf("expected both endpoints before churn, got filePorts=%v bluePorts=%v", filePorts, bluePorts)
	}

	stopControllerWatch()

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --if-exists lsp-del "+filePorts[0])
	waitForNoRows := func(vpc string) {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			ports := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc, "external_ids:netloom_endpoint="+map[string]string{"file": fileEndpoint, "blue": blueEndpoint}[vpc])
			if len(ports) == 0 {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("expected file endpoint port to disappear before restart; current=%v", activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_endpoint="+fileEndpoint))
	}
	waitForNoRows("file")

	startControllerWatch()
	waitForControllerWatch("reconciled desired state")

	afterWatchPorts := map[string][]string{
		"file": activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_endpoint="+fileEndpoint),
		"blue": activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=blue", "external_ids:netloom_endpoint="+blueEndpoint),
	}
	if len(afterWatchPorts["file"]) != 1 {
		t.Fatalf("file endpoint port should be recreated after restart: %v", afterWatchPorts["file"])
	}
	if len(afterWatchPorts["blue"]) != 1 {
		t.Fatalf("blue endpoint port should remain after restart: %v", afterWatchPorts["blue"])
	}

	current := snapshot()
	if !reflect.DeepEqual(baseSnapshot, current) {
		t.Fatalf("OVN snapshot changed after restart recovery.\nbase=%+v\ncurrent=%+v", baseSnapshot, current)
	}

	t.Cleanup(func() {
		stopControllerWatch()
	})
}

func TestDockerControllerRouteTableECMPDeltaIsIncremental(t *testing.T) {
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

	baseState := "/tmp/netloom-state-route-base.json"
	toECMPState := "/tmp/netloom-state-route-ecmp.json"
	backToSingleState := "/tmp/netloom-state-route-single.json"
	controllerStatePath := "/tmp/netloom-state-route-current.json"
	controllerLogPath := "/tmp/netloom-controller-route-watch.log"
	controllerPIDPath := "/tmp/netloom-controller-route-watch.pid"
	writeFile := func(path, contents string) {
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat >"+path+" <<'EOF'\n"+contents+"\nEOF")
	}
	writeFile(baseState, desiredStateWithStaticRouteFromECMPToSingleJSON())
	writeFile(toECMPState, desiredStateWithStaticRouteToECMPJSON())
	writeFile(backToSingleState, desiredStateWithStaticRouteFromECMPToSingleJSON())
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cp", baseState, controllerStatePath)

	startControllerWatch := "cat /dev/null > " + controllerLogPath + "; (NETLOOM_STATE_FILE=" + controllerStatePath + " NETLOOM_RECONCILE_INTERVAL_MS=250 NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller >" + controllerLogPath + " 2>&1 &) ; echo $! > " + controllerPIDPath
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", startControllerWatch)
	waitForControllerWatch := func(expected string) {
		for i := 0; i < 20; i++ {
			output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "grep -Fq '"+expected+"' "+controllerLogPath+" && exit 0 || exit 1")
			if output.exitCode == 0 {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		logOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cat", controllerLogPath)
		t.Fatalf("controller watch did not emit %q in time:\n%s", expected, logOutput)
	}
	waitForControllerWatch("reconciled desired state")

	waitForRouteNextHops := func(expected, forbidden []string) string {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			listOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_file")
			nextHops := parseRouteNextHopsFromList(t, listOutput, "0.0.0.0/0")
			if routeListHasOnlyHops(nextHops, expected) && !routeListContainsAnyHops(nextHops, forbidden) {
				return listOutput
			}
			time.Sleep(500 * time.Millisecond)
		}
		currentRouteOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_file")
		t.Fatalf("route state did not converge to expected next hops %v with no stale hops %v:\n%s", expected, forbidden, currentRouteOutput.output)
		return ""
	}

	baseRouteOutput := waitForRouteNextHops([]string{"10.245.0.252"}, nil)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cp", toECMPState, controllerStatePath)
	ecmpRouteOutput := waitForRouteNextHops([]string{"10.245.0.251", "10.245.0.252"}, nil)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cp", backToSingleState, controllerStatePath)
	afterSingleRouteOutput := waitForRouteNextHops([]string{"10.245.0.252"}, []string{"10.245.0.251", "10.245.0.253"})

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		runAllowFailure(t, cleanupCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "pid=$(cat "+controllerPIDPath+" 2>/dev/null || true); [ -n \"$pid\" ] && kill -9 \"$pid\" || true; rm -f "+controllerPIDPath)
	})

	baseNextHops := parseRouteNextHopsFromList(t, baseRouteOutput, "0.0.0.0/0")
	if len(baseNextHops) != 1 || baseNextHops[0] != "10.245.0.252" {
		t.Fatalf("base state expected single next hop 10.245.0.252 for 0.0.0.0/0, got %#v", baseNextHops)
	}

	afterAddNextHops := parseRouteNextHopsFromList(t, ecmpRouteOutput, "0.0.0.0/0")
	if len(afterAddNextHops) != 2 {
		t.Fatalf("ECMP state expected two nexthops for 0.0.0.0/0, got %#v", afterAddNextHops)
	}
	if !routeListContainsHops(afterAddNextHops, []string{"10.245.0.251", "10.245.0.252"}) {
		t.Fatalf("route ECMP state should contain both nexthops, got:\n%s", ecmpRouteOutput)
	}

	afterSingleNextHops := parseRouteNextHopsFromList(t, afterSingleRouteOutput, "0.0.0.0/0")
	if len(afterSingleNextHops) != 1 || afterSingleNextHops[0] != "10.245.0.252" {
		t.Fatalf("single state expected one nexthop 10.245.0.252 for 0.0.0.0/0, got %#v", afterSingleNextHops)
	}
	if !routeListContainsHops(afterSingleNextHops, []string{"10.245.0.252"}) {
		t.Fatalf("route single-hop state should contain 10.245.0.252, got:\n%s", afterSingleRouteOutput)
	}
	if routeListContainsHops(afterSingleNextHops, []string{"10.245.0.251", "10.245.0.253"}) {
		t.Fatalf("route single-hop state should not contain stale nexthops, got:\n%s", afterSingleRouteOutput)
	}
}

func TestDockerControllerRouteTableECMPDeltaSurvivesRestart(t *testing.T) {
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

	baseState := "/tmp/netloom-state-route-base.json"
	ecmpState := "/tmp/netloom-state-route-ecmp.json"
	singleState := "/tmp/netloom-state-route-single.json"
	controllerStatePath := "/tmp/netloom-controller-route-watch-restart.json"
	controllerLogPath := "/tmp/netloom-controller-route-watch-restart.log"
	controllerPIDPath := "/tmp/netloom-controller-route-watch-restart.pid"

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat >"+baseState+" <<'EOF'\n"+desiredStateWithStaticRouteFromECMPToSingleJSON()+"\nEOF")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat >"+ecmpState+" <<'EOF'\n"+desiredStateWithStaticRouteToECMPJSON()+"\nEOF")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat >"+singleState+" <<'EOF'\n"+desiredStateWithStaticRouteFromECMPToSingleJSON()+"\nEOF")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cp "+baseState+" "+controllerStatePath)

	controllerStateTemplate := "NETLOOM_STATE_FILE=" + controllerStatePath + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock NETLOOM_RECONCILE_INTERVAL_MS=300 /netloom/bin/netloom-controller >" + controllerLogPath + " 2>&1"
	startWatch := func() {
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat /dev/null > "+controllerLogPath+"; ("+controllerStateTemplate+" &) ; echo $! > "+controllerPIDPath)
	}
	stopWatch := func() {
		runAllowFailure(t, context.Background(), "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "pid=$(cat "+controllerPIDPath+" 2>/dev/null || true); [ -n \"$pid\" ] && kill -9 \"$pid\" || true; rm -f "+controllerPIDPath)
	}
	waitForWatch := func(expected string) {
		for i := 0; i < 20; i++ {
			output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "grep -Fq '"+expected+"' "+controllerLogPath+" && exit 0 || exit 1")
			if output.exitCode == 0 {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		logOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cat", controllerLogPath)
		t.Fatalf("controller watch did not emit %q in time:\n%s", expected, logOutput)
	}
	waitForRouteState := func(expected, forbidden []string) []string {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			listOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_file")
			nextHops := parseRouteNextHopsFromList(t, listOutput, "0.0.0.0/0")
			if routeListHasOnlyHops(nextHops, expected) && !routeListContainsAnyHops(nextHops, forbidden) {
				return nextHops
			}
			time.Sleep(500 * time.Millisecond)
		}
		currentRouteOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_file")
		t.Fatalf("route state did not converge to expected next hops %v with no stale hops %v:\n%s", expected, forbidden, currentRouteOutput.output)
		return nil
	}
	waitForRouteStaticRowUUID := func(destination, nextHop string) string {
		for i := 0; i < 20; i++ {
			routeUUID := staticRouteUUIDForPrefixAndNexthop(t, ctx, composeFile, destination, nextHop)
			if routeUUID != "" {
				return routeUUID
			}
			time.Sleep(500 * time.Millisecond)
		}
		current := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "find", "Logical_Router_Static_Route")
		t.Fatalf("expected static route row for %s via %s after reconcile; output:\n%s", destination, nextHop, current.output)
		return ""
	}

	startWatch()
	waitForWatch("reconciled desired state")
	waitForRouteState([]string{"10.245.0.252"}, nil)
	baseRouteUUIDFor252 := waitForRouteStaticRowUUID("0.0.0.0/0", "10.245.0.252")

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cp", ecmpState, controllerStatePath)
	ecmpNextHops := waitForRouteState([]string{"10.245.0.251", "10.245.0.252"}, nil)
	if len(ecmpNextHops) != 2 {
		t.Fatalf("expected two next hops in ECMP state, got %#v", ecmpNextHops)
	}
	ecmpRowUUIDFor252 := waitForRouteStaticRowUUID("0.0.0.0/0", "10.245.0.252")
	if ecmpRowUUIDFor252 != baseRouteUUIDFor252 {
		t.Fatalf("route row for 10.245.0.252 should be preserved across ECMP expansion: before=%q after=%q", baseRouteUUIDFor252, ecmpRowUUIDFor252)
	}
	ecmpRowUUIDFor251 := waitForRouteStaticRowUUID("0.0.0.0/0", "10.245.0.251")
	if ecmpRowUUIDFor251 == "" {
		t.Fatalf("expected ECMP route row for 10.245.0.251")
	}

	stopWatch()
	startWatch()
	waitForWatch("reconciled desired state")
	waitForRouteState([]string{"10.245.0.251", "10.245.0.252"}, nil)
	restartedRowUUIDFor252 := waitForRouteStaticRowUUID("0.0.0.0/0", "10.245.0.252")
	if restartedRowUUIDFor252 != ecmpRowUUIDFor252 {
		t.Fatalf("route row for 10.245.0.252 changed across restart: before=%q after=%q", ecmpRowUUIDFor252, restartedRowUUIDFor252)
	}
	restartedRowUUIDFor251 := waitForRouteStaticRowUUID("0.0.0.0/0", "10.245.0.251")
	if restartedRowUUIDFor251 != ecmpRowUUIDFor251 {
		t.Fatalf("route row for 10.245.0.251 changed across restart: before=%q after=%q", ecmpRowUUIDFor251, restartedRowUUIDFor251)
	}

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "cp", singleState, controllerStatePath)
	afterSingle := waitForRouteState([]string{"10.245.0.252"}, []string{"10.245.0.251", "10.245.0.253"})
	if len(afterSingle) != 1 || afterSingle[0] != "10.245.0.252" {
		t.Fatalf("expected only single-hop 10.245.0.252 after ECMP collapse, got %#v", afterSingle)
	}
	singleRouteUUID := waitForRouteStaticRowUUID("0.0.0.0/0", "10.245.0.252")
	extraRouteUUID := staticRouteUUIDForPrefixAndNexthop(t, ctx, composeFile, "0.0.0.0/0", "10.245.0.251")
	if extraRouteUUID != "" {
		t.Fatalf("stale ECMP route row for 10.245.0.251 remained: %q", extraRouteUUID)
	}
	if singleRouteUUID != baseRouteUUIDFor252 {
		t.Fatalf("route row for 10.245.0.252 should be preserved when collapsing ECMP: expected=%q got=%q", baseRouteUUIDFor252, singleRouteUUID)
	}

	t.Cleanup(func() {
		stopWatch()
	})
}

func TestDockerControllerRouteTableECMPDeltaIsIdempotentForOneShotReconcile(t *testing.T) {
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

	baseState := "/tmp/netloom-state-route-baseline.json"
	ecmpState := "/tmp/netloom-state-route-ecmp-replay.json"
	singleState := "/tmp/netloom-state-route-single.json"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat >"+baseState+" <<'EOF'\n"+desiredStateWithStaticRouteFromECMPToSingleJSON()+"\nEOF")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat >"+ecmpState+" <<'EOF'\n"+desiredStateWithStaticRouteToECMPJSON()+"\nEOF")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat >"+singleState+" <<'EOF'\n"+desiredStateWithStaticRouteFromECMPToSingleJSON()+"\nEOF")

	runRouteReconcile := func(path string) {
		command := "NETLOOM_STATE_FILE=" + path + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
		output := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", command)
		if !strings.Contains(output, "reconciled desired state") {
			t.Fatalf("controller reconcile on %s did not succeed: %s", path, output)
		}
	}

	waitForNexthops := func(expected []string) []string {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			listOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_file")
			nextHops := parseRouteNextHopsFromList(t, listOutput, "0.0.0.0/0")
			if routeListHasOnlyHops(nextHops, expected) {
				return nextHops
			}
			time.Sleep(500 * time.Millisecond)
		}
		currentRouteOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_file")
		t.Fatalf("route state did not converge to %v: %s", expected, currentRouteOutput.output)
		return nil
	}
	waitForStaticRow := func(destination, nextHop string) string {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			uuid := staticRouteUUIDForPrefixAndNexthop(t, ctx, composeFile, destination, nextHop)
			if uuid != "" {
				return uuid
			}
			time.Sleep(200 * time.Millisecond)
		}
		return ""
	}

	waitForInitialRoute := func() []string {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			listOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_file")
			nextHops := parseRouteNextHopsFromList(t, listOutput, "0.0.0.0/0")
			if len(nextHops) == 1 && nextHops[0] == "10.245.0.252" {
				return nextHops
			}
			if routeListHasOnlyHops(nextHops, []string{"10.245.0.251", "10.245.0.252"}) {
				return nextHops
			}
			time.Sleep(500 * time.Millisecond)
		}
		currentRouteOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_file")
		t.Fatalf("route state did not converge to base single/ecmp state for 0.0.0.0/0: %s", currentRouteOutput.output)
		return nil
	}

	runRouteReconcile(baseState)
	baseRouteState := waitForInitialRoute()
	if !routeListContainsHops(baseRouteState, []string{"10.245.0.252"}) {
		t.Fatalf("base route state missing next hop 10.245.0.252: %v", baseRouteState)
	}
	base252 := waitForStaticRow("0.0.0.0/0", "10.245.0.252")
	if base252 == "" {
		t.Fatalf("missing base route row for 10.245.0.252")
	}

	runRouteReconcile(ecmpState)
	waitForNexthops([]string{"10.245.0.251", "10.245.0.252"})
	ecmp252 := waitForStaticRow("0.0.0.0/0", "10.245.0.252")
	if ecmp252 != base252 {
		t.Fatalf("10.245.0.252 static route row changed on ECMP reconcile: before=%q after=%q", base252, ecmp252)
	}

	runRouteReconcile(ecmpState)
	replay252 := waitForStaticRow("0.0.0.0/0", "10.245.0.252")
	if replay252 != ecmp252 {
		t.Fatalf("ECMP one-shot reconcile is not idempotent: before=%q after=%q", ecmp252, replay252)
	}

	runRouteReconcile(singleState)
	finalRouteState := waitForInitialRoute()
	if !routeListContainsHops(finalRouteState, []string{"10.245.0.252"}) {
		t.Fatalf("single-state reconcile lost required next hop 10.245.0.252: %v", finalRouteState)
	}
	single252 := waitForStaticRow("0.0.0.0/0", "10.245.0.252")
	if single252 == "" {
		t.Fatalf("missing single route row for 10.245.0.252")
	}

	runRouteReconcile(singleState)
	replayedSingle252 := waitForStaticRow("0.0.0.0/0", "10.245.0.252")
	if replayedSingle252 != single252 {
		t.Fatalf("single-state one-shot reconcile is not idempotent: before=%q after=%q", single252, replayedSingle252)
	}
}

func TestDockerControllerRouteTableECMPDeltaIsOrderInsensitive(t *testing.T) {
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

	ecmpState := "/tmp/netloom-state-route-ecmp.json"
	reorderedECMPState := "/tmp/netloom-state-route-ecmp-reordered.json"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat >"+ecmpState+" <<'EOF'\n"+desiredStateWithStaticRouteToECMPJSON()+"\nEOF")
	run(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"ovn-central",
		"sh",
		"-c",
		"cat >"+reorderedECMPState+" <<'EOF'\n"+
			strings.Replace(
				desiredStateWithStaticRouteToECMPJSON(),
				"\"next_hops\": [\"10.245.0.251\", \"10.245.0.252\"]",
				"\"next_hops\": [\"10.245.0.252\", \"10.245.0.251\"]",
				1,
			)+"\nEOF",
	)

	runRouteReconcile := func(path string) {
		command := "NETLOOM_STATE_FILE=" + path + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
		output := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", command)
		if !strings.Contains(output, "reconciled desired state") {
			t.Fatalf("controller reconcile on %s did not succeed: %s", path, output)
		}
	}

	waitForNexthops := func(expected []string) []string {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			listOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_file")
			nextHops := parseRouteNextHopsFromList(t, listOutput, "0.0.0.0/0")
			if routeListHasOnlyHops(nextHops, expected) {
				return nextHops
			}
			time.Sleep(500 * time.Millisecond)
		}
		currentRouteOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_file")
		t.Fatalf("route state did not converge to %v: %s", expected, currentRouteOutput.output)
		return nil
	}
	waitForStaticRow := func(destination, nextHop string) string {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			uuid := staticRouteUUIDForPrefixAndNexthop(t, ctx, composeFile, destination, nextHop)
			if uuid != "" {
				return uuid
			}
			time.Sleep(200 * time.Millisecond)
		}
		return ""
	}

	runRouteReconcile(ecmpState)
	baseHops := waitForNexthops([]string{"10.245.0.251", "10.245.0.252"})
	base252 := waitForStaticRow("0.0.0.0/0", "10.245.0.252")
	base251 := waitForStaticRow("0.0.0.0/0", "10.245.0.251")
	if base252 == "" || base251 == "" {
		t.Fatalf("missing baseline ECMP rows: hops=%v", baseHops)
	}

	runRouteReconcile(reorderedECMPState)
	reorderedHops := waitForNexthops([]string{"10.245.0.251", "10.245.0.252"})
	reordered252 := waitForStaticRow("0.0.0.0/0", "10.245.0.252")
	reordered251 := waitForStaticRow("0.0.0.0/0", "10.245.0.251")
	if reordered252 == "" || reordered251 == "" {
		t.Fatalf("missing reordered ECMP rows: hops=%v", reorderedHops)
	}
	if reordered252 != base252 {
		t.Fatalf("10.245.0.252 static route row changed after reorder: before=%q after=%q", base252, reordered252)
	}
	if reordered251 != base251 {
		t.Fatalf("10.245.0.251 static route row changed after reorder: before=%q after=%q", base251, reordered251)
	}
}

func TestDockerControllerRouteTableECMPDeltaIsOrderInsensitiveIPv6(t *testing.T) {
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

	ecmpState := "/tmp/netloom-state-route-ecmp-v6.json"
	reorderedECMPState := "/tmp/netloom-state-route-ecmp-v6-reordered.json"
	baseState := desiredStateWithStaticRouteToECMPIPv6JSON()
	reorderedState := strings.Replace(
		baseState,
		"\"next_hops\": [\"fd00:10:10::252\", \"fd00:10:10::251\"]",
		"\"next_hops\": [\"fd00:10:10::251\", \"fd00:10:10::252\"]",
		1,
	)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat >"+ecmpState+" <<'EOF'\n"+baseState+"\nEOF")
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", "cat >"+reorderedECMPState+" <<'EOF'\n"+reorderedState+"\nEOF")

	runRouteReconcile := func(path string) {
		command := "NETLOOM_STATE_FILE=" + path + " NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller"
		output := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", command)
		if !strings.Contains(output, "reconciled desired state") {
			t.Fatalf("controller reconcile on %s did not succeed: %s", path, output)
		}
	}

	waitForNexthops := func(expected []string) []string {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			listOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_ipv6")
			nextHops := parseRouteNextHopsFromList(t, listOutput, "::/0")
			if routeListHasOnlyHops(nextHops, expected) {
				return nextHops
			}
			time.Sleep(500 * time.Millisecond)
		}
		currentRouteOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", "nl_lr_ipv6")
		t.Fatalf("route state did not converge to %v: %s", expected, currentRouteOutput.output)
		return nil
	}
	waitForStaticRow := func(destination, nextHop string) string {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			uuid := staticRouteUUIDForPrefixAndNexthop(t, ctx, composeFile, destination, nextHop)
			if uuid != "" {
				return uuid
			}
			time.Sleep(200 * time.Millisecond)
		}
		return ""
	}

	runRouteReconcile(ecmpState)
	baseHops := waitForNexthops([]string{"fd00:10:10::251", "fd00:10:10::252"})
	base252 := waitForStaticRow("::/0", "fd00:10:10::252")
	base251 := waitForStaticRow("::/0", "fd00:10:10::251")
	if base252 == "" || base251 == "" {
		t.Fatalf("missing baseline ECMP rows: hops=%v", baseHops)
	}

	runRouteReconcile(reorderedECMPState)
	reorderedHops := waitForNexthops([]string{"fd00:10:10::251", "fd00:10:10::252"})
	reordered252 := waitForStaticRow("::/0", "fd00:10:10::252")
	reordered251 := waitForStaticRow("::/0", "fd00:10:10::251")
	if reordered252 == "" || reordered251 == "" {
		t.Fatalf("missing reordered ECMP rows: hops=%v", reorderedHops)
	}
	if reordered252 != base252 {
		t.Fatalf("fd00:10:10::252 static route row changed after reorder: before=%q after=%q", base252, reordered252)
	}
	if reordered251 != base251 {
		t.Fatalf("fd00:10:10::251 static route row changed after reorder: before=%q after=%q", base251, reordered251)
	}
}

func TestDockerWorkloadPolicyPriorityConflict(t *testing.T) {
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
	for _, service := range []string{"node-a", "node-b"} {
		ensureIPNetNS(service)
	}

	statePath := "/tmp/netloom-workload-priority-state.json"
	stateForNode := func(stateJSON, node string) string {
		return "cat >" + statePath + " <<'EOF'\n" + stateJSON + "\nEOF\n" +
			"NETLOOM_STATE_FILE=" + statePath +
			" NETLOOM_NODE_NAME=" + node +
			" NETLOOM_POLICY_STORE=ebpf" +
			" NETLOOM_LINUX_DATAPATH=1" +
			" NETLOOM_LINUX_DATAPATH_MODE=netns" +
			" NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth0" +
			" NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-b=172.30.0.12 " +
			"/netloom/bin/netloom-agent"
	}
	startTCXWorkloadAgent := func(stateJSON string, wantAttached bool) {
		logPath := "/tmp/netloom-workload-priority-agent.log"
		command := "cat >" + statePath + " <<'EOF'\n" + stateJSON + "\nEOF\n" +
			"pkill -f '/netloom/bin/netloom-agent' 2>/dev/null || true\n" +
			": >" + logPath + "\n" +
			"NETLOOM_STATE_FILE=" + statePath +
			" NETLOOM_NODE_NAME=node-b" +
			" NETLOOM_POLICY_STORE=ebpf" +
			" NETLOOM_LINUX_DATAPATH=1" +
			" NETLOOM_LINUX_DATAPATH_MODE=netns" +
			" NETLOOM_PROVIDER_NETWORK_LINKS=physnet-a=eth0" +
			" NETLOOM_NODE_UNDERLAYS=node-a=172.30.0.11,node-b=172.30.0.12" +
			" NETLOOM_TCX_WORKLOAD=1" +
			" NETLOOM_RECONCILE_INTERVAL_MS=500" +
			" /netloom/bin/netloom-agent >" + logPath + " 2>&1 &"
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", command)
		expected := "tcx=not-attached"
		if wantAttached {
			expected = "tcx=attached"
		}
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for i in $(seq 1 20); do grep -q '"+expected+"' "+logPath+" 2>/dev/null && exit 0; sleep 1; done; cat "+logPath+"; exit 1")
	}

	nodeAWorkloadDenyOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", stateForNode(desiredWorkloadPolicyPriorityDenyWinsStateJSON(), "node-a"))
	if !strings.Contains(nodeAWorkloadDenyOutput, "reconciled node policy") {
		t.Fatalf("node-a deny-state reconcile did not succeed:\n%s", nodeAWorkloadDenyOutput)
	}
	nodeBWorkloadDenyOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", stateForNode(desiredWorkloadPolicyPriorityDenyWinsStateJSON(), "node-b"))
	if !strings.Contains(nodeBWorkloadDenyOutput, "reconciled node policy") {
		t.Fatalf("node-b deny-state reconcile did not succeed:\n%s", nodeBWorkloadDenyOutput)
	}
	startTCXWorkloadAgent(desiredWorkloadPolicyPriorityDenyWinsStateJSON(), true)

	resolveWorkloadNamespace := func(node, endpointID string) string {
		expected := workloadNamespace("file", endpointID)
		legacy := "nl-" + endpointID
		var lastOutput string
		for i := 0; i < 120; i++ {
			result := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", node, "ip", "netns", "list")
			lastOutput = result.output
			if result.exitCode == 0 {
				for _, line := range strings.Split(strings.TrimSpace(result.output), "\n") {
					fields := strings.Fields(line)
					if len(fields) == 0 {
						continue
					}
					namespace := fields[0]
					if namespace == expected || namespace == legacy || (strings.HasPrefix(namespace, "nl-") && strings.HasSuffix(namespace, endpointID)) {
						return namespace
					}
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("namespace for endpoint %q was not found on %s, namespaces now:\n%s", endpointID, node, strings.TrimSpace(lastOutput))
		return ""
	}

	srcNS := resolveWorkloadNamespace("node-a", "file-pod-a")
	dstNS := resolveWorkloadNamespace("node-b", "file-pod-b")

	run(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"node-b",
		"sh",
		"-c",
		"ip netns exec "+dstNS+" sh -c 'while true; do printf ok | nc -l -p 8081 >/tmp/netloom-workload-priority-server.log 2>&1; done >/dev/null 2>&1 &'",
	)
	time.Sleep(700 * time.Millisecond)

	denyProbe := runAllowFailure(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"node-a",
		"sh",
		"-c",
		"for i in $(seq 1 20); do ip netns exec "+srcNS+" sh -c 'printf hi | nc -w 1 10.245.0.11 8081' >/tmp/netloom-workload-priority-deny.log 2>&1 || exit 0; sleep 1; done; cat /tmp/netloom-workload-priority-deny.log; exit 1",
	)
	if denyProbe.exitCode != 0 {
		t.Fatalf("policy priority expected deny state to block traffic, but probe succeeded: %s", denyProbe.output)
	}

	nodeAWorkloadAllowOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-a", "sh", "-c", stateForNode(desiredWorkloadPolicyPriorityAllowWinsStateJSON(), "node-a"))
	if !strings.Contains(nodeAWorkloadAllowOutput, "reconciled node policy") {
		t.Fatalf("node-a allow-state reconcile did not succeed:\n%s", nodeAWorkloadAllowOutput)
	}
	nodeBWorkloadAllowOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", stateForNode(desiredWorkloadPolicyPriorityAllowWinsStateJSON(), "node-b"))
	if !strings.Contains(nodeBWorkloadAllowOutput, "reconciled node policy") {
		t.Fatalf("node-b allow-state reconcile did not succeed:\n%s", nodeBWorkloadAllowOutput)
	}
	startTCXWorkloadAgent(desiredWorkloadPolicyPriorityAllowWinsStateJSON(), false)

	allowProbe := runAllowFailure(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"node-a",
		"sh",
		"-c",
		"for i in $(seq 1 20); do ip netns exec "+srcNS+" sh -c 'printf hi | nc -w 1 10.245.0.11 8081' >/tmp/netloom-workload-priority-allow.log 2>&1 && exit 0; sleep 1; done; cat /tmp/netloom-workload-priority-allow.log; exit 1",
	)
	if allowProbe.exitCode != 0 {
		t.Fatalf("policy priority expected allow state to pass traffic, probe output: %s", allowProbe.output)
	}
	runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "pkill", "-f", "/netloom/bin/netloom-agent")
}

func TestDockerControllerReconcileIPv6VPC(t *testing.T) {
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

	statePath := "/tmp/netloom-state-ipv6.json"
	stateCommand := "cat >/tmp/netloom-state-ipv6.json <<'EOF'\n" + desiredStateIPv6JSON() + "\nEOF\n"
	reconcileOutput := run(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"ovn-central",
		"sh",
		"-c",
		stateCommand+"NETLOOM_STATE_FILE="+statePath+" NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller",
	)
	if !strings.Contains(reconcileOutput, "reconciled desired state") {
		t.Fatalf("ipv6 desired-state reconcile did not succeed:\n%s", reconcileOutput)
	}

	endpointID := endpointExternalIDForOVN("ipv6", "ipv6-pod-a")
	ports := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=ipv6", "external_ids:netloom_endpoint="+endpointID)
	if len(ports) != 1 {
		t.Fatalf("expected one IPv6 logical switch port for endpoint %q, got %v", endpointID, ports)
	}
	addressOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lsp-get-addresses", ports[0])
	if !strings.Contains(addressOutput, "fd00:10:10::10") {
		t.Fatalf("lsp address output missing expected IPv6 endpoint address:\n%s", addressOutput)
	}
	if strings.Contains(addressOutput, "10.") {
		t.Fatalf("lsp address output should be IPv6-only:\n%s", addressOutput)
	}

	routers := activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=ipv6")
	if len(routers) != 1 {
		t.Fatalf("expected one ipv6 logical router for vpc ipv6, got %v", routers)
	}
	switches := activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=ipv6")
	if len(switches) != 1 {
		t.Fatalf("expected one ipv6 logical switch for vpc ipv6, got %v", switches)
	}

	routeOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", routers[0])
	if strings.Contains(routeOutput, "0.0.0.0/0") {
		t.Fatalf("unexpected IPv4 default route leaked into IPv6-only VPC:\n%s", routeOutput)
	}
	natOutput := activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=ipv6")
	if len(natOutput) != 0 {
		t.Fatalf("unexpected managed NAT rows found for ipv6-only VPC: %v", natOutput)
	}
	lbOutput := activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=ipv6")
	if len(lbOutput) != 0 {
		t.Fatalf("unexpected managed load_balancer rows found for ipv6-only VPC: %v", lbOutput)
	}
}

func TestDockerControllerReconcileSubnetExcludeCIDRs(t *testing.T) {
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

	statePath := "/tmp/netloom-state-exclude-cidrs.json"
	reconcileOutput := run(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"ovn-central",
		"sh",
		"-c",
		"cat >"+statePath+" <<'EOF'\n"+desiredStateWithExcludeCIDRsJSON()+"\nEOF\nNETLOOM_STATE_FILE="+statePath+" NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller",
	)
	if !strings.Contains(reconcileOutput, "reconciled desired state") {
		t.Fatalf("exclude-cidr desired-state reconcile did not succeed:\n%s", reconcileOutput)
	}

	otherConfig := run(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"ovn-central",
		"ovn-nbctl",
		"--db=unix:/var/run/ovn/ovnnb_db.sock",
		"get",
		"logical_switch",
		"nl_ls_file_fileapps",
		"other_config",
	)
	for _, expected := range []string{
		`subnet="10.245.0.0/24"`,
		`exclude_ips="10.245.0.1 10.245.0.16..10.245.0.31"`,
	} {
		if !strings.Contains(otherConfig, expected) {
			t.Fatalf("logical switch other_config missing %q:\n%s", expected, otherConfig)
		}
	}
}

func TestDockerControllerReconcileDualStackVPC(t *testing.T) {
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

	statePath := "/tmp/netloom-state-dual-stack.json"
	reconcileOutput := run(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"ovn-central",
		"sh",
		"-c",
		"cat >"+statePath+" <<'EOF'\n"+desiredStateDualStackJSON()+"\nEOF\nNETLOOM_STATE_FILE="+statePath+" NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller",
	)
	if !strings.Contains(reconcileOutput, "reconciled desired state") {
		t.Fatalf("dual-stack desired-state reconcile did not succeed:\n%s", reconcileOutput)
	}
	for _, expected := range []string{"policy_routes=2", "load_balancers=2"} {
		if !strings.Contains(reconcileOutput, expected) {
			t.Fatalf("dual-stack reconcile output missing %q:\n%s", expected, reconcileOutput)
		}
	}

	v4EndpointID := endpointExternalIDForOVN("dual", "dual-pod-v4")
	v6EndpointID := endpointExternalIDForOVN("dual", "dual-pod-v6")
	v4Ports := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dual", "external_ids:netloom_endpoint="+v4EndpointID)
	v6Ports := activeManagedRows(t, ctx, composeFile, "logical_switch_port", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dual", "external_ids:netloom_endpoint="+v6EndpointID)
	if len(v4Ports) != 1 {
		t.Fatalf("expected one IPv4 logical switch port for dual-v4 endpoint %q, got %v", v4EndpointID, v4Ports)
	}
	if len(v6Ports) != 1 {
		t.Fatalf("expected one IPv6 logical switch port for dual-v6 endpoint %q, got %v", v6EndpointID, v6Ports)
	}

	v4AddressOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lsp-get-addresses", v4Ports[0])
	if !strings.Contains(v4AddressOutput, "10.245.0.10") {
		t.Fatalf("expected IPv4 endpoint address 10.245.0.10, output:\n%s", v4AddressOutput)
	}
	if strings.Contains(v4AddressOutput, "fd00:") {
		t.Fatalf("unexpected IPv6 address on IPv4 endpoint logical port:\n%s", v4AddressOutput)
	}

	v6AddressOutput := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lsp-get-addresses", v6Ports[0])
	if !strings.Contains(v6AddressOutput, "fd00:20:20::10") {
		t.Fatalf("expected IPv6 endpoint address fd00:20:20::10, output:\n%s", v6AddressOutput)
	}
	if strings.Contains(v6AddressOutput, "10.") {
		t.Fatalf("unexpected IPv4 address on IPv6 endpoint logical port:\n%s", v6AddressOutput)
	}

	v4DHCPOptionsID := strings.TrimSpace(run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lsp-get-dhcpv4-options", v4Ports[0]))
	if v4DHCPOptionsID == "" || v4DHCPOptionsID == "[]" {
		t.Fatalf("dual-stack IPv4 endpoint DHCP options were not bound: %q", v4DHCPOptionsID)
	}
	v4DHCPOptionsID = strings.Fields(v4DHCPOptionsID)[0]
	v4DHCPOptions := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "dhcp-options-get-options", v4DHCPOptionsID)
	for _, expected := range []string{"lease_time=3600", "router=10.245.0.1", "server_id=10.245.0.1", "dns_server=[\"10.96.0.10\"]"} {
		if !strings.Contains(v4DHCPOptions, expected) {
			t.Fatalf("dual-stack IPv4 DHCP options missing %q:\n%s", expected, v4DHCPOptions)
		}
	}

	v6DHCPOptionsID := strings.TrimSpace(run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lsp-get-dhcpv6-options", v6Ports[0]))
	if v6DHCPOptionsID == "" || v6DHCPOptionsID == "[]" {
		t.Fatalf("dual-stack IPv6 endpoint DHCP options were not bound: %q", v6DHCPOptionsID)
	}
	v6DHCPOptionsID = strings.Fields(v6DHCPOptionsID)[0]
	v6DHCPOptions := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "dhcp-options-get-options", v6DHCPOptionsID)
	for _, expected := range []string{"dns_server=[\"fd00:96::10\"]", "domain_name=dual.internal"} {
		if !strings.Contains(v6DHCPOptions, expected) {
			t.Fatalf("dual-stack IPv6 DHCP options missing %q:\n%s", expected, v6DHCPOptions)
		}
	}

	v4LB := findLoadBalancerForVIP(t, ctx, composeFile, "dual", "dual-web-v4", "10.96.0.40:80")
	if v4LB == "" {
		t.Fatal("expected IPv4 dual-stack load balancer row for VIP 10.96.0.40:80")
	}
	v4LBState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lb-list", v4LB)
	for _, expected := range []string{"10.96.0.40:80", "10.245.0.10:8080"} {
		if !strings.Contains(v4LBState, expected) {
			t.Fatalf("dual-stack IPv4 LB state missing %q:\n%s", expected, v4LBState)
		}
	}
	v4LBHC := activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dual", "external_ids:netloom_load_balancer=dual-web-v4")
	if len(v4LBHC) != 1 {
		t.Fatalf("expected one IPv4 dual-stack load balancer health check row, got %v", v4LBHC)
	}

	v6LB := findLoadBalancerForVIP(t, ctx, composeFile, "dual", "dual-web-v6", "[fd00:96::40]:80")
	if v6LB == "" {
		t.Fatal("expected IPv6 dual-stack load balancer row for VIP [fd00:96::40]:80")
	}
	v6LBState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lb-list", v6LB)
	for _, expected := range []string{"[fd00:96::40]:80", "[fd00:20:20::10]:8080"} {
		if !strings.Contains(v6LBState, expected) {
			t.Fatalf("dual-stack IPv6 LB state missing %q:\n%s", expected, v6LBState)
		}
	}
	v6LBHC := activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dual", "external_ids:netloom_load_balancer=dual-web-v6")
	if len(v6LBHC) != 1 {
		t.Fatalf("expected one IPv6 dual-stack load balancer health check row, got %v", v6LBHC)
	}

	routers := activeManagedRows(t, ctx, composeFile, "logical_router", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dual")
	if len(routers) != 1 {
		t.Fatalf("expected one dual-stack logical router, got %v", routers)
	}
	policyState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-policy-list", routers[0])
	for _, expected := range []string{"ip4.src == 10.245.0.0/24", "ip4.dst == 198.51.100.0/24", "10.245.0.254", "ip6.src == fd00:20:20::/64", "ip6.dst == 2001:db8:100::/64", "fd00:20:20::fe"} {
		if !strings.Contains(policyState, expected) {
			t.Fatalf("dual-stack OVN policy route state missing %q:\n%s", expected, policyState)
		}
	}
	switches := activeManagedRows(t, ctx, composeFile, "logical_switch", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dual")
	if len(switches) != 2 {
		t.Fatalf("expected two dual-stack logical switches (v4/v6), got %v", switches)
	}
	loadBalancers := activeManagedRows(t, ctx, composeFile, "load_balancer", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dual")
	if len(loadBalancers) != 2 {
		t.Fatalf("expected two dual-stack load balancer rows (v4/v6), got %v", loadBalancers)
	}
	nat := activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dual")
	if len(nat) != 3 {
		t.Fatalf("expected three managed dual-stack NAT rows (v4 snat, v6 snat, v6 dnat), got %v", nat)
	}
	var natDetails []string
	for _, uuid := range nat {
		detail := strings.TrimSpace(run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "get", "NAT", uuid, "type", "external_ip", "logical_ip"))
		natDetails = append(natDetails, detail)
	}
	joinedNATDetails := strings.ReplaceAll(strings.Join(natDetails, "\n"), "\"", "")
	for _, expected := range []string{"snat\n198.51.100.40\n10.245.0.0/24", "snat\n2001:db8:ffff::40\nfd00:20:20::/64", "dnat\n2001:db8:ffff::41\nfd00:20:20::10"} {
		if !strings.Contains(joinedNATDetails, expected) {
			t.Fatalf("dual-stack NAT detail missing %q:\n%s", expected, joinedNATDetails)
		}
	}
}

func TestDockerControllerToggleDualStackLoadBalancerHealthChecks(t *testing.T) {
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

	statePath := "/tmp/netloom-state-dual-stack-health-toggle.json"
	applyState := func(stateJSON string) string {
		return run(
			t,
			ctx,
			"docker",
			"compose",
			"-f",
			composeFile,
			"exec",
			"-T",
			"ovn-central",
			"sh",
			"-c",
			"cat >"+statePath+" <<'EOF'\n"+stateJSON+"\nEOF\nNETLOOM_STATE_FILE="+statePath+" NETLOOM_OVN_NBCTL_DB=unix:/var/run/ovn/ovnnb_db.sock /netloom/bin/netloom-controller",
		)
	}

	enableOutput := applyState(desiredStateDualStackJSON())
	if !strings.Contains(enableOutput, "reconciled desired state") {
		t.Fatalf("dual-stack health-check enable reconcile did not succeed:\n%s", enableOutput)
	}

	v4LB := findLoadBalancerForVIP(t, ctx, composeFile, "dual", "dual-web-v4", "10.96.0.40:80")
	if v4LB == "" {
		t.Fatal("expected IPv4 dual-stack load balancer row for VIP 10.96.0.40:80")
	}
	v6LB := findLoadBalancerForVIP(t, ctx, composeFile, "dual", "dual-web-v6", "[fd00:96::40]:80")
	if v6LB == "" {
		t.Fatal("expected IPv6 dual-stack load balancer row for VIP [fd00:96::40]:80")
	}

	if got := activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dual", "external_ids:netloom_load_balancer=dual-web-v4"); len(got) != 1 {
		t.Fatalf("expected one IPv4 health-check row before toggle, got %v", got)
	}
	if got := activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=dual", "external_ids:netloom_load_balancer=dual-web-v6"); len(got) != 1 {
		t.Fatalf("expected one IPv6 health-check row before toggle, got %v", got)
	}

	disableOutput := applyState(desiredStateDualStackWithoutHealthChecksJSON())
	if !strings.Contains(disableOutput, "reconciled desired state") {
		t.Fatalf("dual-stack health-check disable reconcile did not succeed:\n%s", disableOutput)
	}

	waitForNoLBHealthChecks := func(lbName, ovnName string) {
		t.Helper()
		cmd := "for i in $(seq 1 20); do " +
			"[ -z \"$(ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock get load_balancer " + ovnName + " health_check | tr -d '[][:space:]')\" ] && " +
			"[ -z \"$(ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --bare --no-heading --columns=_uuid find Load_Balancer_Health_Check external_ids:netloom_owner=netloom external_ids:netloom_vpc=dual external_ids:netloom_load_balancer=" + lbName + ")\" ] && exit 0; " +
			"sleep 1; done; " +
			"echo 'lb health_check:'; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock get load_balancer " + ovnName + " health_check; " +
			"echo 'table rows:'; ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --bare --no-heading --columns=_uuid,vip find Load_Balancer_Health_Check external_ids:netloom_owner=netloom external_ids:netloom_vpc=dual external_ids:netloom_load_balancer=" + lbName + "; " +
			"exit 1"
		run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", cmd)
	}

	waitForNoLBHealthChecks("dual-web-v4", v4LB)
	waitForNoLBHealthChecks("dual-web-v6", v6LB)

	v4LBState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lb-list", v4LB)
	if !strings.Contains(v4LBState, "10.96.0.40:80") || !strings.Contains(v4LBState, "10.245.0.10:8080") {
		t.Fatalf("dual-stack IPv4 LB state changed after disabling health checks:\n%s", v4LBState)
	}
	v6LBState := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lb-list", v6LB)
	if !strings.Contains(v6LBState, "[fd00:96::40]:80") || !strings.Contains(v6LBState, "[fd00:20:20::10]:8080") {
		t.Fatalf("dual-stack IPv6 LB state changed after disabling health checks:\n%s", v6LBState)
	}
}

func routeListHasOnlyHops(got []string, expected []string) bool {
	if len(got) != len(expected) {
		return false
	}
	for _, hop := range expected {
		if !routeListContainsHops(got, []string{hop}) {
			return false
		}
	}
	return true
}

func activeManagedRows(t *testing.T, ctx context.Context, composeFile, table string, filters ...string) []string {
	t.Helper()
	column := "name"
	switch table {
	case "NAT", "Logical_Router_Policy", "Load_Balancer_Health_Check", "DHCP_Options":
		column = "_uuid"
	default:
		column = "name"
	}
	args := []string{"docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=" + column, "find", table}
	args = append(args, filters...)
	result := runAllowFailure(t, ctx, args[0], args[1:]...)
	if result.exitCode != 0 {
		t.Fatalf("failed to list managed %s rows: %s", table, result.output)
	}
	return strings.Fields(strings.TrimSpace(result.output))
}

func staticRouteUUIDForPrefixAndNexthop(t *testing.T, ctx context.Context, composeFile, ipPrefix, nextHop string) string {
	t.Helper()
	result := runAllowFailure(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"ovn-central",
		"ovn-nbctl",
		"--db=unix:/var/run/ovn/ovnnb_db.sock",
		"--bare",
		"--no-heading",
		"--columns=_uuid",
		"find",
		"Logical_Router_Static_Route",
		fmt.Sprintf("ip_prefix=%q", ipPrefix),
		fmt.Sprintf("nexthop=%q", nextHop),
	)
	if result.exitCode != 0 {
		t.Fatalf("failed to get static route row uuid for prefix %q via %q: %s", ipPrefix, nextHop, result.output)
	}
	for _, line := range strings.Split(strings.TrimSpace(result.output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[0]) == "_uuid" {
				line = strings.TrimSpace(parts[1])
			}
		}
		fields := strings.Fields(line)
		if len(fields) >= 1 && fields[0] != "" {
			return fields[0]
		}
	}
	return ""
}

func staticRouteNextHopsForPrefix(t *testing.T, ctx context.Context, composeFile, router, destination string) []string {
	t.Helper()
	listOutput := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-route-list", router)
	if listOutput.exitCode != 0 {
		t.Fatalf("failed to list routes for router %q: %s", router, listOutput.output)
	}
	return parseRouteNextHopsFromList(t, listOutput.output, destination)
}

func parseRouteNextHopsFromList(t *testing.T, routeListOutput, destination string) []string {
	t.Helper()
	lines := strings.Split(routeListOutput, "\n")
	nextSet := make(map[string]struct{})
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || fields[0] != destination {
			continue
		}
		nextSet[fields[1]] = struct{}{}
	}
	nextHops := make([]string, 0, len(nextSet))
	for nextHop := range nextSet {
		nextHops = append(nextHops, nextHop)
	}
	sort.Strings(nextHops)
	return nextHops
}

func routeListContainsHops(nextHops []string, expected []string) bool {
	for _, expectedHop := range expected {
		found := false
		for _, nextHop := range nextHops {
			if nextHop == expectedHop {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func routeListContainsAnyHops(nextHops []string, expected []string) bool {
	for _, hop := range expected {
		if routeListContainsHops(nextHops, []string{hop}) {
			return true
		}
	}
	return false
}

func desiredStateWithExcludeCIDRsJSON() string {
	return `{
  "vpcs": [{"name": "file"}],
  "provider_networks": [{"name": "physnet-a", "nodes": [{"node": "node-a", "interface": "eth0"}, {"node": "node-b", "interface": "eth0"}]}],
  "subnets": [{"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "exclude_cidrs": ["10.245.0.16/28"], "provider_network": "physnet-a", "vlan": 100, "dhcp": {"enabled": true, "lease_time": 7200, "mtu": 1400}}],
  "endpoints": [{"id": "file-pod-a", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["file-allow"]}],
  "security_groups": [{"name": "file-allow", "vpc": "file", "rules": [{"id": "allow-all", "priority": 100, "direction": "ingress", "protocol": "any", "remote_cidr": "0.0.0.0/0", "action": "allow"}]}]
}`
}

func desiredDualVPCStateJSON() string {
	return `{
  "vpcs": [
    {"name": "file"},
    {"name": "blue"}
  ],
  "subnets": [
    {"name": "fileapps", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1"},
    {"name": "blueapps", "vpc": "blue", "cidr": "10.246.0.0/24", "gateway": "10.246.0.1"}
  ],
  "endpoints": [
    {"id": "shared-pod", "vpc": "file", "subnet": "fileapps", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["file-allow"]},
    {"id": "shared-pod", "vpc": "blue", "subnet": "blueapps", "ip": "10.246.0.10", "node": "node-a", "security_groups": ["blue-allow"]}
  ],
  "security_groups": [
    {"name": "file-allow", "vpc": "file", "rules": [{"id": "allow", "priority": 100, "direction": "ingress", "protocol": "any", "remote_cidr": "0.0.0.0/0", "action": "allow"}]},
    {"name": "blue-allow", "vpc": "blue", "rules": [{"id": "allow", "priority": 100, "direction": "ingress", "protocol": "any", "remote_cidr": "0.0.0.0/0", "action": "allow"}]}
  ]
}`
}

func desiredDualVPCSameNameStateJSON() string {
	return `{
  "vpcs": [
    {"name": "file"},
    {"name": "blue"}
  ],
  "subnets": [
    {"name": "shared", "vpc": "file", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1"},
    {"name": "shared", "vpc": "blue", "cidr": "10.246.0.0/24", "gateway": "10.246.0.1"}
  ],
  "endpoints": [
    {"id": "shared-pod", "vpc": "file", "subnet": "shared", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["shared-allow"]},
    {"id": "shared-pod", "vpc": "blue", "subnet": "shared", "ip": "10.246.0.10", "node": "node-a", "security_groups": ["shared-allow"]}
  ],
  "route_tables": [
    {"name": "main", "vpc": "file", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.245.0.254"]}]},
    {"name": "main", "vpc": "blue", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.246.0.254"]}]}
  ],
  "gateways": [
    {"name": "shared-gw", "vpc": "file", "node": "node-a", "external_if": "eth0", "lan_ip": "10.245.0.254"},
    {"name": "shared-gw", "vpc": "blue", "node": "node-b", "external_if": "eth0", "lan_ip": "10.246.0.254"}
  ],
  "nat_rules": [
    {"name": "egress", "vpc": "file", "type": "snat", "match_cidr": "10.245.0.0/24", "external_ip": "198.51.100.50"},
    {"name": "egress", "vpc": "blue", "type": "snat", "match_cidr": "10.246.0.0/24", "external_ip": "198.51.101.50"}
  ],
  "load_balancers": [
    {"name": "cross-vpc-web", "vpc": "file", "vip": "10.96.0.20", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.245.0.10", "port": 80}]}], "subnets": ["shared"]},
    {"name": "cross-vpc-web", "vpc": "blue", "vip": "10.96.0.20", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.246.0.10", "port": 80}]}], "subnets": ["shared"]}
  ],
  "security_groups": [
    {"name": "shared-allow", "vpc": "file", "rules": [{"id": "allow-http", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "0.0.0.0/0", "ports": [{"from": 80, "to": 80}], "action": "allow"}]},
    {"name": "shared-allow", "vpc": "blue", "rules": [{"id": "allow-http", "priority": 100, "direction": "ingress", "protocol": "tcp", "remote_cidr": "0.0.0.0/0", "ports": [{"from": 80, "to": 80}], "action": "allow"}]}
  ]
}`
}

func desiredStateIPv6JSON() string {
	return `{
  "vpcs": [{"name": "ipv6"}],
  "subnets": [{"name": "appsv6", "vpc": "ipv6", "cidr": "fd00:10:10::/64", "gateway": "fd00:10:10::1"}],
  "endpoints": [{"id": "ipv6-pod-a", "vpc": "ipv6", "subnet": "appsv6", "ip": "fd00:10:10::10", "node": "node-a", "security_groups": ["ipv6-allow"]}],
  "security_groups": [{"name": "ipv6-allow", "vpc": "ipv6", "rules": [{"id": "allow-all", "priority": 100, "direction": "ingress", "protocol": "any", "remote_cidr": "::/0", "action": "allow"}]}]
}`
}

func desiredStateDualStackJSON() string {
	return `{
  "vpcs": [{"name": "dual"}],
  "subnets": [
    {"name": "apps-v4", "vpc": "dual", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "dhcp": {"enabled": true, "dns_servers": ["10.96.0.10"], "domain_name": "dual.internal"}},
    {"name": "apps-v6", "vpc": "dual", "cidr": "fd00:20:20::/64", "gateway": "fd00:20:20::1", "dhcp": {"enabled": true, "dns_servers": ["fd00:96::10"], "domain_name": "dual.internal"}}
  ],
  "endpoints": [
    {"id": "dual-pod-v4", "vpc": "dual", "subnet": "apps-v4", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["dual-allow"]},
    {"id": "dual-pod-v6", "vpc": "dual", "subnet": "apps-v6", "ip": "fd00:20:20::10", "node": "node-a", "security_groups": ["dual-allow"]}
  ],
  "policy_routes": [
    {"name": "v4-fw", "vpc": "dual", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "198.51.100.0/24", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.245.0.254"]}},
    {"name": "v6-fw", "vpc": "dual", "priority": 110, "match": {"source": "fd00:20:20::/64", "destination": "2001:db8:100::/64", "protocol": "tcp", "dst_ports": [{"from": 8443, "to": 8443}]}, "action": {"type": "reroute", "next_hops": ["fd00:20:20::fe"]}}
  ],
  "load_balancers": [
    {"name": "dual-web-v4", "vpc": "dual", "vip": "10.96.0.40", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.245.0.10", "port": 8080}]}], "subnets": ["apps-v4"], "health_check": {"enabled": true, "interval": 5, "timeout": 20, "success_count": 2, "failure_count": 3}},
    {"name": "dual-web-v6", "vpc": "dual", "vip": "fd00:96::40", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "fd00:20:20::10", "port": 8080}]}], "subnets": ["apps-v6"], "health_check": {"enabled": true, "interval": 5, "timeout": 20, "success_count": 2, "failure_count": 3}}
  ],
  "nat_rules": [
    {"name": "v4-egress", "vpc": "dual", "type": "snat", "match_cidr": "10.245.0.0/24", "external_ip": "198.51.100.40"},
    {"name": "v6-egress", "vpc": "dual", "type": "snat", "match_cidr": "fd00:20:20::/64", "external_ip": "2001:db8:ffff::40"},
    {"name": "v6-api", "vpc": "dual", "type": "dnat", "external_ip": "2001:db8:ffff::41", "target_ip": "fd00:20:20::10"}
  ],
  "security_groups": [{"name": "dual-allow", "vpc": "dual", "rules": [{"id": "allow-all", "priority": 100, "direction": "ingress", "protocol": "any", "remote_cidr": "0.0.0.0/0", "action": "allow"}, {"id": "allow-all-v6", "priority": 100, "direction": "ingress", "protocol": "any", "remote_cidr": "::/0", "action": "allow"}]}]
}`
}

func desiredStateDualStackWithoutHealthChecksJSON() string {
	return `{
  "vpcs": [{"name": "dual"}],
  "subnets": [
    {"name": "apps-v4", "vpc": "dual", "cidr": "10.245.0.0/24", "gateway": "10.245.0.1", "dhcp": {"enabled": true, "dns_servers": ["10.96.0.10"], "domain_name": "dual.internal"}},
    {"name": "apps-v6", "vpc": "dual", "cidr": "fd00:20:20::/64", "gateway": "fd00:20:20::1", "dhcp": {"enabled": true, "dns_servers": ["fd00:96::10"], "domain_name": "dual.internal"}}
  ],
  "endpoints": [
    {"id": "dual-pod-v4", "vpc": "dual", "subnet": "apps-v4", "ip": "10.245.0.10", "node": "node-a", "security_groups": ["dual-allow"]},
    {"id": "dual-pod-v6", "vpc": "dual", "subnet": "apps-v6", "ip": "fd00:20:20::10", "node": "node-a", "security_groups": ["dual-allow"]}
  ],
  "policy_routes": [
    {"name": "v4-fw", "vpc": "dual", "priority": 100, "match": {"source": "10.245.0.0/24", "destination": "198.51.100.0/24", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.245.0.254"]}},
    {"name": "v6-fw", "vpc": "dual", "priority": 110, "match": {"source": "fd00:20:20::/64", "destination": "2001:db8:100::/64", "protocol": "tcp", "dst_ports": [{"from": 8443, "to": 8443}]}, "action": {"type": "reroute", "next_hops": ["fd00:20:20::fe"]}}
  ],
  "load_balancers": [
    {"name": "dual-web-v4", "vpc": "dual", "vip": "10.96.0.40", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.245.0.10", "port": 8080}]}], "subnets": ["apps-v4"]},
    {"name": "dual-web-v6", "vpc": "dual", "vip": "fd00:96::40", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "fd00:20:20::10", "port": 8080}]}], "subnets": ["apps-v6"]}
  ],
  "nat_rules": [
    {"name": "v4-egress", "vpc": "dual", "type": "snat", "match_cidr": "10.245.0.0/24", "external_ip": "198.51.100.40"},
    {"name": "v6-egress", "vpc": "dual", "type": "snat", "match_cidr": "fd00:20:20::/64", "external_ip": "2001:db8:ffff::40"},
    {"name": "v6-api", "vpc": "dual", "type": "dnat", "external_ip": "2001:db8:ffff::41", "target_ip": "fd00:20:20::10"}
  ],
  "security_groups": [{"name": "dual-allow", "vpc": "dual", "rules": [{"id": "allow-all", "priority": 100, "direction": "ingress", "protocol": "any", "remote_cidr": "0.0.0.0/0", "action": "allow"}, {"id": "allow-all-v6", "priority": 100, "direction": "ingress", "protocol": "any", "remote_cidr": "::/0", "action": "allow"}]}]
}`
}
