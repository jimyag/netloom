package e2e

import (
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDockerAgentSelftestSupportsCustomVpc(t *testing.T) {
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

	tcxIface, _ := tcxSelftestInterface(t, ctx, composeFile, "node-b")
	output := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T",
		"-e", "NETLOOM_TCX_SELFTEST_IFACE="+tcxIface,
		"-e", "NETLOOM_SELFTEST_VPC=blue",
		"node-b",
		"/netloom/bin/netloom-agent")
	if !strings.Contains(output, "ready for node policy") {
		t.Fatalf("agent selftest output did not show ready state:\n%s", output)
	}
	if !strings.Contains(output, "endpoint=blue") {
		t.Fatalf("agent selftest output did not include blue scoped endpoint id:\n%s", output)
	}
}

func TestDockerAgentSelftestCapturesStatefulPolicyAndTraceMetrics(t *testing.T) {
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

	output := run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "-e", "NETLOOM_SELFTEST_VPC=blue", "node-b", "/netloom/bin/netloom-agent")
	for _, expected := range []string{
		"ready for node policy",
		"endpoint=blue\x00selftest-pod",
		"allow=allow",
		"deny=drop",
		"policy_allowed=3",
		"policy_dropped=1",
		"policy_conntrack=1",
		"policy_established=1",
		"policy_logged=3",
		"policy_events=3",
		"trace_events=4",
		"drop_events=1",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("agent selftest output missing %q:\n%s", expected, output)
		}
	}
}

func TestDockerAgentSelftestTCXAttachFailureIsSurfaceable(t *testing.T) {
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

	output := runAllowFailure(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T",
		"-e", "NETLOOM_TCX_SELFTEST_IFACE=not-a-real-interface",
		"node-b",
		"/netloom/bin/netloom-agent")
	if output.exitCode == 0 {
		t.Fatalf("expected tcx selftest to fail, output:\n%s", output.output)
	}
	if !strings.Contains(output.output, "tcx selftest:") {
		t.Fatalf("tcx attach failure output missing tcx selftest context:\n%s", output.output)
	}
}

func TestDockerAgentSelftestTCXAttachFailureAndRecovery(t *testing.T) {
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

	failureOutput := runAllowFailure(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"-e",
		"NETLOOM_TCX_SELFTEST_IFACE=not-a-real-interface",
		"node-b",
		"/netloom/bin/netloom-agent",
	)
	if failureOutput.exitCode == 0 {
		t.Fatalf("expected tcx selftest to fail with bad interface, output:\n%s", failureOutput.output)
	}
	if !strings.Contains(failureOutput.output, "tcx selftest:") {
		t.Fatalf("tcx attach failure output missing tcx selftest context:\n%s", failureOutput.output)
	}

	tcxIface, _ := tcxSelftestInterface(t, ctx, composeFile, "node-b")
	recoveredOutput := run(
		t,
		ctx,
		"docker",
		"compose",
		"-f",
		composeFile,
		"exec",
		"-T",
		"-e",
		"NETLOOM_TCX_SELFTEST_IFACE="+tcxIface,
		"-e",
		"NETLOOM_SELFTEST_VPC=blue",
		"node-b",
		"/netloom/bin/netloom-agent",
	)
	if !strings.Contains(recoveredOutput, "ready for node policy") {
		t.Fatalf("agent selftest did not recover after attach failure: %s", recoveredOutput)
	}
	if !strings.Contains(recoveredOutput, "endpoint=blue") {
		t.Fatalf("agent selftest recovered output did not include expected vpc endpoint:\n%s", recoveredOutput)
	}
}

func TestDockerAgentStateWatchRecoversFromRestart(t *testing.T) {
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

	statePath := "/tmp/netloom-agent-restart-watch-state.json"
	stateAWrite := "cat >" + statePath + " <<'EOF'\n" + desiredWorkloadPolicyDropStateJSON() + "\nEOF\n"
	stateBWrite := "cat >" + statePath + " <<'EOF'\n" + desiredWorkloadCleanupStateJSON() + "\nEOF\n"
	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", stateAWrite)

	agentWatchLog := "/tmp/netloom-agent-watch-restart.log"
	agentPIDFile := "/tmp/netloom-agent-watch-restart.pid"
	metadataRoot := "/var/run/netloom-ebpf-meta/policy"
	agentWatchCommand := "NETLOOM_STATE_FILE=" + statePath + " NETLOOM_NODE_NAME=node-b NETLOOM_POLICY_STORE=ebpf NETLOOM_RECONCILE_INTERVAL_MS=500 /netloom/bin/netloom-agent >" + agentWatchLog + " 2>&1"
	shortCtx := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 30*time.Second)
	}
	startWatch := func() {
		opCtx, cancel := shortCtx()
		run(t, opCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /dev/null > "+agentWatchLog+"; ("+agentWatchCommand+" &) ; echo $! > "+agentPIDFile)
		cancel()
	}
	stopWatch := func() {
		opCtx, cancel := shortCtx()
		runAllowFailure(t, opCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "pid=$(cat "+agentPIDFile+" 2>/dev/null || true); [ -n \"$pid\" ] && kill -9 \"$pid\" || true; rm -f "+agentPIDFile)
		cancel()
	}
	waitForWatch := func(expected string) {
		for i := 0; i < 30; i++ {
			opCtx, cancel := shortCtx()
			output := runAllowFailure(t, opCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "grep -Fq '"+expected+"' "+agentWatchLog+" && exit 0 || exit 1")
			cancel()
			if output.exitCode == 0 {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		opCtx, cancel := shortCtx()
		logOutput := run(t, opCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "cat", agentWatchLog)
		cancel()
		t.Fatalf("agent watch did not emit %q in time:\n%s", expected, logOutput)
	}
	detectPinnedPolicyRoot := func() string {
		for i := 0; i < 30; i++ {
			opCtx, cancel := shortCtx()
			output := runAllowFailure(t, opCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "for dir in /sys/fs/bpf/netloom/policy /var/run/netloom-ebpf/policy; do if [ -d \"$dir\" ] && ls \"$dir\"/nlp* >/dev/null 2>&1; then echo \"$dir\"; exit 0; fi; done; exit 1")
			cancel()
			if output.exitCode == 0 {
				return strings.TrimSpace(output.output)
			}
			time.Sleep(500 * time.Millisecond)
		}
		opCtx, cancel := shortCtx()
		logOutput := run(t, opCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "ls -la /sys/fs/bpf/netloom 2>/dev/null || true; ls -la /var/run/netloom-ebpf 2>/dev/null || true; cat "+agentWatchLog+" 2>/dev/null || true")
		cancel()
		t.Fatalf("default eBPF pin root was not populated in time:\n%s", logOutput)
		return ""
	}
	waitForPinnedArtifacts := func(root string, want int) {
		for i := 0; i < 30; i++ {
			opCtx, cancel := shortCtx()
			output := runAllowFailure(t, opCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "count=$(find "+root+" -maxdepth 1 -type f | wc -l); [ \"$count\" = \""+strconv.Itoa(want)+"\" ] && exit 0 || { echo \"$count\"; exit 1; }")
			cancel()
			if output.exitCode == 0 {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		opCtx, cancel := shortCtx()
		logOutput := run(t, opCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "find "+root+" -maxdepth 1 -type f | sort; cat "+agentWatchLog+" 2>/dev/null || true")
		cancel()
		t.Fatalf("pinned artifact count under %s did not converge to %d:\n%s", root, want, logOutput)
	}
	waitForMetadataArtifacts := func(root string, want int) {
		for i := 0; i < 30; i++ {
			opCtx, cancel := shortCtx()
			output := runAllowFailure(t, opCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "count=$(find "+root+" -maxdepth 1 -name '*.meta' | wc -l); [ \"$count\" = \""+strconv.Itoa(want)+"\" ] && exit 0 || { echo \"$count\"; exit 1; }")
			cancel()
			if output.exitCode == 0 {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		opCtx, cancel := shortCtx()
		logOutput := run(t, opCtx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "find "+root+" -maxdepth 1 -name '*.meta' | sort; cat "+agentWatchLog+" 2>/dev/null || true")
		cancel()
		t.Fatalf("metadata artifact count under %s did not converge to %d:\n%s", root, want, logOutput)
	}

	startWatch()
	t.Cleanup(stopWatch)
	waitForWatch("reconciled node policy")
	waitForWatch("store=ebpf")
	waitForWatch("endpoints=2")
	pinRoot := detectPinnedPolicyRoot()
	waitForPinnedArtifacts(pinRoot, 2)
	waitForMetadataArtifacts(metadataRoot, 2)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", stateBWrite)
	waitForWatch("endpoints=1")
	waitForPinnedArtifacts(pinRoot, 1)
	waitForMetadataArtifacts(metadataRoot, 1)

	run(t, ctx, "docker", "compose", "-f", composeFile, "exec", "-T", "node-b", "sh", "-c", "cat /dev/null > "+agentWatchLog)
	stopWatch()
	waitForPinnedArtifacts(pinRoot, 1)
	waitForMetadataArtifacts(metadataRoot, 1)
	startWatch()
	waitForWatch("reconciled node policy")
	waitForWatch("endpoints=1")
	waitForPinnedArtifacts(pinRoot, 1)
	waitForMetadataArtifacts(metadataRoot, 1)
}
