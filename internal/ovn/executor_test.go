package ovn_test

import (
	"context"
	"errors"
	"testing"

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
	if len(recorded) != 1 {
		t.Fatalf("recorded ops = %d, want 1", len(recorded))
	}
	if recorded[0].Command != "lr-add" || recorded[0].Args[0] != "nl_lr_prod" {
		t.Fatalf("recorded op = %+v, want lr-add nl_lr_prod", recorded[0])
	}
}

func TestBackendPropagatesExecutorFailure(t *testing.T) {
	backend := ovn.NewBackend(failingExecutor{})
	err := backend.EnsureVPC(context.Background(), model.VPC{Name: "prod"})
	if err == nil {
		t.Fatal("expected executor failure")
	}
}

type failingExecutor struct{}

func (failingExecutor) Execute(context.Context, []ovn.Operation) error {
	return errors.New("boom")
}
