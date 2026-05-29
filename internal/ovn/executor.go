package ovn

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sync"
)

type Executor interface {
	Execute(context.Context, []Operation) error
}

type RecorderExecutor struct {
	mu  sync.Mutex
	ops []Operation
}

func NewRecorderExecutor() *RecorderExecutor {
	return &RecorderExecutor{}
}

func (r *RecorderExecutor) Execute(_ context.Context, ops []Operation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, cloneOperations(ops)...)
	return nil
}

func (r *RecorderExecutor) Operations() []Operation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneOperations(r.ops)
}

type NBCTLExecutor struct {
	Binary   string
	BaseArgs []string
}

func NewNBCTLExecutor(binary string, baseArgs ...string) *NBCTLExecutor {
	if binary == "" {
		binary = "ovn-nbctl"
	}
	return &NBCTLExecutor{Binary: binary, BaseArgs: append([]string(nil), baseArgs...)}
}

func (e *NBCTLExecutor) Execute(ctx context.Context, ops []Operation) error {
	for _, op := range ops {
		if err := validateOperation(op); err != nil {
			return err
		}
		args := append(append([]string(nil), e.BaseArgs...), op.Command)
		args = append(args, op.Args...)
		cmd := exec.CommandContext(ctx, e.Binary, args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s %v failed: %w: %s", e.Binary, args, err, stderr.String())
		}
	}
	return nil
}

func validateOperation(op Operation) error {
	if op.Command == "" {
		return fmt.Errorf("operation command is required")
	}
	for _, arg := range append([]string{op.Command}, op.Args...) {
		if arg == "" {
			return fmt.Errorf("operation %q contains empty argument", op.Command)
		}
	}
	return nil
}

func cloneOperations(ops []Operation) []Operation {
	out := make([]Operation, 0, len(ops))
	for _, op := range ops {
		out = append(out, Operation{
			Command: op.Command,
			Args:    append([]string(nil), op.Args...),
		})
	}
	return out
}
