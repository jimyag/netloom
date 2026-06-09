package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDockerControllerReconcileIdempotent(t *testing.T) {
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
	run(t, ctx, "docker", "compose", "-f", composeFile, "up", "-d", "--quiet-pull", "--force-recreate")
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), time.Minute)
		defer downCancel()
		run(t, downCtx, "docker", "compose", "-f", composeFile, "down", "-v")
	})

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
	run(t, ctx, "docker", "compose", "-f", composeFile, "up", "-d", "--quiet-pull", "--force-recreate")
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), time.Minute)
		defer downCancel()
		run(t, downCtx, "docker", "compose", "-f", composeFile, "down", "-v")
	})
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
	run(t, ctx, "docker", "compose", "-f", composeFile, "up", "-d", "--quiet-pull", "--force-recreate")
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), time.Minute)
		defer downCancel()
		run(t, downCtx, "docker", "compose", "-f", composeFile, "down", "-v")
	})
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

func TestDockerControllerWatchRecoversFromRestart(t *testing.T) {
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
	run(t, ctx, "docker", "compose", "-f", composeFile, "up", "-d", "--quiet-pull", "--force-recreate")
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

func TestDockerControllerReconcileSupportsSameEndpointIDAcrossVPCs(t *testing.T) {
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
	run(t, ctx, "docker", "compose", "-f", composeFile, "up", "-d", "--quiet-pull", "--force-recreate")
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
	run(t, ctx, "docker", "compose", "-f", composeFile, "up", "-d", "--quiet-pull", "--force-recreate")
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
}

func TestDockerControllerStateReplayDetectsManagedOVNLeaks(t *testing.T) {
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
	run(t, ctx, "docker", "compose", "-f", composeFile, "up", "-d", "--quiet-pull", "--force-recreate")
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
		"NAT":                   len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Logical_Router_Policy": len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Load_Balancer_Health_Check": len(activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_load_balancer=file-web")),
	}
	staleManagedNAT := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_nat create NAT type=snat external_ip=198.51.100.220 logical_ip=10.10.0.220 external_ids:netloom_owner=netloom external_ids:netloom_nat=stale-leak external_ids:netloom_vpc=file -- add logical_router nl_lr_file nat @stale_managed_nat"
	staleManagedPolicy := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_policy create Logical_Router_Policy priority=250 match='ip' action=drop external_ids:netloom_owner=netloom external_ids:netloom_policy_route=stale-leak external_ids:netloom_vpc=file -- add logical_router nl_lr_file policies @stale_managed_policy"
	unmanagedNAT := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_unmanaged_nat create NAT type=snat external_ip=198.51.100.221 logical_ip=10.10.0.221 external_ids:notes=netloom-unmanaged-leak external_ids:owner=manual -- add logical_router nl_lr_file nat @stale_unmanaged_nat"
	staleManagedLBHC := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_lbhc create Load_Balancer_Health_Check vip=10.96.0.99 options:interval=5 options:timeout=20 options:success_count=3 options:failure_count=3 external_ids:netloom_owner=netloom external_ids:netloom_load_balancer=file-web external_ids:netloom_vpc=file"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedNAT)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedPolicy)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", unmanagedNAT)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedLBHC)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	afterManagedRows := map[string]int{
		"NAT":                   len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Logical_Router_Policy": len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Load_Balancer_Health_Check": len(activeManagedRows(t, ctx, composeFile, "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file", "external_ids:netloom_load_balancer=file-web")),
	}
	if beforeManagedRows["NAT"] != afterManagedRows["NAT"] {
		t.Fatalf("managed NAT count changed after leak cleanup: before=%d after=%d", beforeManagedRows["NAT"], afterManagedRows["NAT"])
	}
	if beforeManagedRows["Logical_Router_Policy"] != afterManagedRows["Logical_Router_Policy"] {
		t.Fatalf("managed policy route count changed after leak cleanup: before=%d after=%d", beforeManagedRows["Logical_Router_Policy"], afterManagedRows["Logical_Router_Policy"])
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
	staleManagedLBHCRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "Load_Balancer_Health_Check", "external_ids:netloom_owner=netloom", "external_ids:netloom_load_balancer=file-web", "external_ids:netloom_vpc=file", "vip=10.96.0.99")
	if strings.TrimSpace(staleManagedLBHCRows.output) != "" {
		t.Fatalf("stale managed LB health check row should be cleaned: %s", staleManagedLBHCRows.output)
	}

	unmanagedNATRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "NAT", "external_ids:notes=netloom-unmanaged-leak", "external_ids:owner=manual")
	if strings.TrimSpace(unmanagedNATRows.output) == "" {
		t.Fatalf("expected unmanaged leak row to remain for leakage validation")
	}
}

func TestDockerControllerRouteTableECMPDeltaIsIncremental(t *testing.T) {
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
	run(t, ctx, "docker", "compose", "-f", composeFile, "up", "-d", "--quiet-pull", "--force-recreate")
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
	run(t, ctx, "docker", "compose", "-f", composeFile, "up", "-d", "--quiet-pull", "--force-recreate")
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
	run(t, ctx, "docker", "compose", "-f", composeFile, "up", "-d", "--quiet-pull", "--force-recreate")
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
	case "NAT", "Logical_Router_Policy", "Load_Balancer_Health_Check":
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
	result := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "Logical_Router_Static_Route", "ip_prefix="+ipPrefix, "nexthop="+nextHop)
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
