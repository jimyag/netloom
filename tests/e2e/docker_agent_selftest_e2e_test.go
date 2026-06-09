package e2e

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerAgentSelftestSupportsCustomVpc(t *testing.T) {
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
