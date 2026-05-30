package ovn_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn"
)

func TestRecorderExecutorRecordsDeepCopies(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	ops := []ovn.Operation{{Command: "lr-add", Args: []string{"lr0"}}}
	if err := recorder.Execute(context.Background(), ops); err != nil {
		t.Fatal(err)
	}
	ops[0].Args[0] = "mutated"

	recorded := recorder.Operations()
	if recorded[0].Args[0] != "lr0" {
		t.Fatalf("recorded op was mutated: %+v", recorded[0])
	}
}

func TestBackendExecutesPlannedOperations(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	if err := backend.EnsureVPC(context.Background(), model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	recorded := recorder.Operations()
	if len(recorded) != 2 {
		t.Fatalf("recorded ops = %d, want 2", len(recorded))
	}
	if recorded[0].Command != "lr-add" || recorded[0].Flags[0] != "--may-exist" || recorded[0].Args[0] != "nl_lr_prod" {
		t.Fatalf("recorded op = %+v, want --may-exist lr-add nl_lr_prod", recorded[0])
	}
	if recorded[1].Command != "set" || recorded[1].Args[2] != "external_ids:netloom_owner=netloom" {
		t.Fatalf("recorded ownership op = %+v", recorded[1])
	}
}

func TestBackendPropagatesExecutorFailure(t *testing.T) {
	backend := ovn.NewBackend(failingExecutor{})
	err := backend.EnsureVPC(context.Background(), model.VPC{Name: "prod"})
	if err == nil {
		t.Fatal("expected executor failure")
	}
}

func TestBackendCleanupEmitsDeletesForStaleDesiredObjects(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.Endpoints = nil
	second.NATRules = nil
	second.LoadBalancers = nil
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--if-exists lsp-del nl_lp_pod-a",
		"--if-exists lr-nat-del nl_lr_prod snat 10.10.0.0/24",
		"--if-exists lr-lb-del nl_lr_prod nl_lb_web",
		"--if-exists ls-lb-del nl_ls_apps nl_lb_web",
		"--if-exists lb-del nl_lb_web",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("cleanup operations missing %q:\n%s", expected, joined)
		}
	}
}

func TestNBCTLExecutorBatchesOperationsIntoTransaction(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{
		{Command: "lr-add", Flags: []string{"--may-exist"}, Args: []string{"nl_lr_prod"}},
		{Command: "set", Args: []string{"logical_router", "nl_lr_prod", "external_ids:netloom_owner=netloom"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(raw)), "\n")
	want := []string{
		"--db=unix:/tmp/ovnnb.sock",
		"--may-exist",
		"lr-add",
		"nl_lr_prod",
		"--",
		"set",
		"logical_router",
		"nl_lr_prod",
		"external_ids:netloom_owner=netloom",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

type failingExecutor struct{}

func (failingExecutor) Execute(context.Context, []ovn.Operation) error {
	return errors.New("boom")
}

func controlStateWithEndpoint(endpointID string) control.DesiredState {
	return control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
		Endpoints: []model.Endpoint{{
			ID:     endpointID,
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
		NATRules: []model.NATRule{{
			Name:       "egress",
			VPC:        "prod",
			Type:       model.ActionSNAT,
			MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
			ExternalIP: netip.MustParseAddr("198.51.100.10"),
		}},
		LoadBalancers: []model.LoadBalancer{{
			Name:     "web",
			VPC:      "prod",
			VIP:      netip.MustParseAddr("10.96.0.10"),
			Port:     80,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{
				IP:   netip.MustParseAddr("10.10.0.10"),
				Port: 8080,
			}},
			Subnets: []string{"apps"},
		}},
	}
}

func stringifyOVNOps(ops []ovn.Operation) string {
	lines := make([]string, 0, len(ops))
	for _, op := range ops {
		lines = append(lines, op.String())
	}
	return strings.Join(lines, "\n")
}
