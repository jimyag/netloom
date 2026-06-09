package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"reflect"
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
		"NAT":                 len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Logical_Router_Policy": len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
	}
	staleManagedNAT := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_nat create NAT type=snat external_ip=198.51.100.220 logical_ip=10.10.0.220 external_ids:netloom_owner=netloom external_ids:netloom_nat=stale-leak external_ids:netloom_vpc=file -- add logical_router nl_lr_file nat @stale_managed_nat"
	staleManagedPolicy := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_managed_policy create Logical_Router_Policy priority=250 match='ip' action=drop external_ids:netloom_owner=netloom external_ids:netloom_policy_route=stale-leak external_ids:netloom_vpc=file -- add logical_router nl_lr_file policies @stale_managed_policy"
	unmanagedNAT := "ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --id=@stale_unmanaged_nat create NAT type=snat external_ip=198.51.100.221 logical_ip=10.10.0.221 external_ids:notes=netloom-unmanaged-leak external_ids:owner=manual -- add logical_router nl_lr_file nat @stale_unmanaged_nat"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedNAT)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", staleManagedPolicy)
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", unmanagedNAT)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "sh", "-c", stateCommand)

	afterManagedRows := map[string]int{
		"NAT":                 len(activeManagedRows(t, ctx, composeFile, "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
		"Logical_Router_Policy": len(activeManagedRows(t, ctx, composeFile, "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc=file")),
	}
	if beforeManagedRows["NAT"] != afterManagedRows["NAT"] {
		t.Fatalf("managed NAT count changed after leak cleanup: before=%d after=%d", beforeManagedRows["NAT"], afterManagedRows["NAT"])
	}
	if beforeManagedRows["Logical_Router_Policy"] != afterManagedRows["Logical_Router_Policy"] {
		t.Fatalf("managed policy route count changed after leak cleanup: before=%d after=%d", beforeManagedRows["Logical_Router_Policy"], afterManagedRows["Logical_Router_Policy"])
	}

	staleManagedNATRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "NAT", "external_ids:netloom_owner=netloom", "external_ids:netloom_nat=stale-leak", "external_ids:netloom_vpc=file")
	if strings.TrimSpace(staleManagedNATRows.output) != "" {
		t.Fatalf("stale managed NAT row should be cleaned: %s", staleManagedNATRows.output)
	}
	staleManagedPolicyRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "Logical_Router_Policy", "external_ids:netloom_owner=netloom", "external_ids:netloom_policy_route=stale-leak", "external_ids:netloom_vpc=file")
	if strings.TrimSpace(staleManagedPolicyRows.output) != "" {
		t.Fatalf("stale managed policy row should be cleaned: %s", staleManagedPolicyRows.output)
	}

	unmanagedNATRows := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "ovn-central", "ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "--bare", "--no-heading", "--columns=_uuid", "find", "NAT", "external_ids:notes=netloom-unmanaged-leak", "external_ids:owner=manual")
	if strings.TrimSpace(unmanagedNATRows.output) == "" {
		t.Fatalf("expected unmanaged leak row to remain for leakage validation")
	}
}

func activeManagedRows(t *testing.T, ctx context.Context, composeFile, table string, filters ...string) []string {
	t.Helper()
	column := "name"
	switch table {
	case "NAT", "Logical_Router_Policy":
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
