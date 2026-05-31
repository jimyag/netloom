package ovn

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const DefaultNBCTLTimeout = 30 * time.Second

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
	Binary      string
	BaseArgs    []string
	Transaction bool
	Timeout     time.Duration
}

func NewNBCTLExecutor(binary string, baseArgs ...string) *NBCTLExecutor {
	if binary == "" {
		binary = "ovn-nbctl"
	}
	return &NBCTLExecutor{Binary: binary, BaseArgs: append([]string(nil), baseArgs...), Transaction: true, Timeout: DefaultNBCTLTimeout}
}

func (e *NBCTLExecutor) Execute(ctx context.Context, ops []Operation) error {
	if e.Transaction {
		return e.executeTransaction(ctx, ops)
	}
	for _, op := range ops {
		if isSpecialOperation(op) {
			if err := e.executeSpecial(ctx, op); err != nil {
				return err
			}
			continue
		}
		if err := validateOperation(op); err != nil {
			return err
		}
		args := append([]string(nil), e.BaseArgs...)
		args = append(args, op.Flags...)
		args = append(args, op.Command)
		args = append(args, op.Args...)
		if err := e.runCommand(ctx, args); err != nil {
			return err
		}
	}
	return nil
}

func (e *NBCTLExecutor) executeTransaction(ctx context.Context, ops []Operation) error {
	if len(ops) == 0 {
		return nil
	}
	for len(ops) > 0 {
		if isSpecialOperation(ops[0]) {
			if err := e.executeSpecial(ctx, ops[0]); err != nil {
				return err
			}
			ops = ops[1:]
			continue
		}
		special := firstSpecialOperation(ops)
		regular := ops
		if special >= 0 {
			regular = ops[:special]
		}
		batchEnd := nextTransactionBatchEnd(regular)
		if err := e.executeTransactionBatch(ctx, ops[:batchEnd]); err != nil {
			return err
		}
		ops = ops[batchEnd:]
	}
	return nil
}

func (e *NBCTLExecutor) executeTransactionBatch(ctx context.Context, ops []Operation) error {
	args := append([]string(nil), e.BaseArgs...)
	for i, op := range ops {
		if err := validateOperation(op); err != nil {
			return err
		}
		if i > 0 {
			args = append(args, "--")
		}
		args = append(args, op.Flags...)
		args = append(args, op.Command)
		args = append(args, op.Args...)
	}
	return e.runCommand(ctx, args)
}

func nextTransactionBatchEnd(ops []Operation) int {
	if len(ops) <= 1 {
		return len(ops)
	}
	for i := 1; i < len(ops); i++ {
		if ops[i].Command == "lr-nat-add" {
			return i
		}
	}
	return len(ops)
}

func firstSpecialOperation(ops []Operation) int {
	for i, op := range ops {
		if isSpecialOperation(op) {
			return i
		}
	}
	return -1
}

func isSpecialOperation(op Operation) bool {
	switch op.Command {
	case "gc-dhcp-options", "gc-load-balancer-health-checks", "gc-nat-rule", "gc-stale-nat-rules", "tag-policy-route", "gc-stale-policy-routes":
		return true
	default:
		return false
	}
}

func (e *NBCTLExecutor) executeSpecial(ctx context.Context, op Operation) error {
	if err := validateSpecialOperation(op); err != nil {
		return err
	}
	switch op.Command {
	case "gc-dhcp-options":
		return e.destroyMatchingRecords(ctx, "DHCP_Options",
			"external_ids:netloom_owner=netloom",
			"external_ids:netloom_endpoint="+op.Args[0],
		)
	case "gc-load-balancer-health-checks":
		return e.destroyMatchingRecords(ctx, "Load_Balancer_Health_Check",
			"external_ids:netloom_owner=netloom",
			"external_ids:netloom_load_balancer="+op.Args[0],
		)
	case "gc-nat-rule":
		return e.destroyMatchingRecords(ctx, "NAT",
			"external_ids:netloom_owner=netloom",
			"external_ids:netloom_nat="+op.Args[0],
		)
	case "gc-stale-nat-rules":
		return e.destroyStaleNATRules(ctx, op.Args)
	case "tag-policy-route":
		return e.tagPolicyRoute(ctx, op.Args[0], op.Args[1], op.Args[2], op.Args[3])
	case "gc-stale-policy-routes":
		return e.destroyStalePolicyRoutes(ctx, op.Args)
	default:
		return fmt.Errorf("unsupported special operation %q", op.Command)
	}
}

func (e *NBCTLExecutor) tagPolicyRoute(ctx context.Context, vpc, name, priority, match string) error {
	router := logicalRouter(vpc)
	uuids, err := e.routerPolicyUUIDs(ctx, router)
	if err != nil {
		return err
	}
	for _, uuid := range uuids {
		policyPriority, policyMatch, err := e.logicalRouterPolicyIdentity(ctx, uuid)
		if err != nil {
			return err
		}
		if policyPriority != priority || policyMatch != match {
			continue
		}
		args := append([]string(nil), e.BaseArgs...)
		args = append(args, "set", "Logical_Router_Policy", uuid,
			"external_ids:netloom_owner=netloom",
			"external_ids:netloom_policy_route="+name,
			"external_ids:netloom_vpc="+vpc,
		)
		if err := e.runCommand(ctx, args); err != nil {
			return err
		}
	}
	return nil
}

func (e *NBCTLExecutor) routerPolicyUUIDs(ctx context.Context, router string) ([]string, error) {
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "--if-exists", "get", "logical_router", router, "policies")
	output, err := e.outputCommand(ctx, args)
	if err != nil {
		return nil, err
	}
	return parseOVNSet(string(output)), nil
}

func (e *NBCTLExecutor) logicalRouterPolicyIdentity(ctx context.Context, uuid string) (string, string, error) {
	priorityArgs := append([]string(nil), e.BaseArgs...)
	priorityArgs = append(priorityArgs, "--if-exists", "get", "Logical_Router_Policy", uuid, "priority")
	priorityOutput, err := e.outputCommand(ctx, priorityArgs)
	if err != nil {
		return "", "", err
	}
	matchArgs := append([]string(nil), e.BaseArgs...)
	matchArgs = append(matchArgs, "--if-exists", "get", "Logical_Router_Policy", uuid, "match")
	matchOutput, err := e.outputCommand(ctx, matchArgs)
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(string(priorityOutput)), trimOVNString(string(matchOutput)), nil
}

func (e *NBCTLExecutor) destroyStalePolicyRoutes(ctx context.Context, keep []string) error {
	keepSet := make(map[string]struct{}, len(keep)/2)
	for i := 0; i+1 < len(keep); i += 2 {
		keepSet[keep[i]+"\x00"+keep[i+1]] = struct{}{}
	}
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "--format=csv", "--data=bare", "--no-headings", "--columns=_uuid,external_ids", "find", "Logical_Router_Policy", "external_ids:netloom_owner=netloom")
	output, err := e.outputCommand(ctx, args)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		uuid, externalIDs, ok := parseExternalIDsCSVRow(line)
		if !ok {
			continue
		}
		vpc := externalIDs["netloom_vpc"]
		name := externalIDs["netloom_policy_route"]
		if vpc == "" || name == "" {
			continue
		}
		if _, keep := keepSet[vpc+"\x00"+name]; keep {
			continue
		}
		removeArgs := append([]string(nil), e.BaseArgs...)
		removeArgs = append(removeArgs, "remove", "logical_router", logicalRouter(vpc), "policies", uuid)
		if err := e.runCommand(ctx, removeArgs); err != nil {
			return err
		}
		destroyArgs := append([]string(nil), e.BaseArgs...)
		destroyArgs = append(destroyArgs, "--if-exists", "destroy", "Logical_Router_Policy", uuid)
		if err := e.runCommand(ctx, destroyArgs); err != nil {
			return err
		}
	}
	return nil
}

func (e *NBCTLExecutor) destroyStaleNATRules(ctx context.Context, keep []string) error {
	keepSet := make(map[string]struct{}, len(keep))
	for _, name := range keep {
		keepSet[name] = struct{}{}
	}
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "--format=csv", "--data=bare", "--no-headings", "--columns=_uuid,external_ids", "find", "NAT", "external_ids:netloom_owner=netloom")
	output, err := e.outputCommand(ctx, args)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		uuid, natName, ok := parseNATGCRow(line)
		if !ok {
			continue
		}
		if _, keep := keepSet[natName]; keep {
			continue
		}
		destroyArgs := append([]string(nil), e.BaseArgs...)
		destroyArgs = append(destroyArgs, "--if-exists", "destroy", "NAT", uuid)
		if err := e.runCommand(ctx, destroyArgs); err != nil {
			return err
		}
	}
	return nil
}

func parseNATGCRow(line string) (string, string, bool) {
	uuid, externalIDs, ok := parseExternalIDsCSVRow(line)
	if !ok {
		return "", "", false
	}
	natName := externalIDs["netloom_nat"]
	return uuid, natName, uuid != "" && natName != ""
}

func parseExternalIDsCSVRow(line string) (string, map[string]string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", nil, false
	}
	uuid, externalIDs, ok := strings.Cut(line, ",")
	if !ok {
		return "", nil, false
	}
	uuid = strings.Trim(strings.TrimSpace(uuid), `"`)
	externalIDs = strings.TrimSpace(externalIDs)
	externalIDs = strings.Trim(externalIDs, `"{} `)
	out := make(map[string]string)
	for _, field := range strings.Split(externalIDs, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		key = strings.Trim(key, `"{} `)
		value = strings.Trim(value, `"{} `)
		if key != "" {
			out[key] = value
		}
	}
	return uuid, out, uuid != ""
}

func parseOVNSet(value string) []string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "[]")
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(strings.TrimSpace(part), `"`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func trimOVNString(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = strings.Trim(value, `"`)
		value = strings.ReplaceAll(value, `\"`, `"`)
	}
	return value
}

func (e *NBCTLExecutor) destroyMatchingRecords(ctx context.Context, table string, matches ...string) error {
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "--bare", "--columns=_uuid", "find", table)
	args = append(args, matches...)
	output, err := e.outputCommand(ctx, args)
	if err != nil {
		return err
	}
	for _, uuid := range strings.Fields(string(output)) {
		destroyArgs := append([]string(nil), e.BaseArgs...)
		destroyArgs = append(destroyArgs, "--if-exists", "destroy", table, uuid)
		if err := e.runCommand(ctx, destroyArgs); err != nil {
			return err
		}
	}
	return nil
}

func (e *NBCTLExecutor) runCommand(ctx context.Context, args []string) error {
	cmdCtx, cancel := e.commandContext(ctx)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, e.Binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if cmdCtx.Err() != nil {
			return fmt.Errorf("%s %v timed out or was canceled: %w", e.Binary, args, cmdCtx.Err())
		}
		return fmt.Errorf("%s %v failed: %w: %s", e.Binary, args, err, stderr.String())
	}
	return nil
}

func (e *NBCTLExecutor) outputCommand(ctx context.Context, args []string) ([]byte, error) {
	cmdCtx, cancel := e.commandContext(ctx)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, e.Binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		if cmdCtx.Err() != nil {
			return nil, fmt.Errorf("%s %v timed out or was canceled: %w", e.Binary, args, cmdCtx.Err())
		}
		return nil, fmt.Errorf("%s %v failed: %w: %s", e.Binary, args, err, stderr.String())
	}
	return output, nil
}

func (e *NBCTLExecutor) commandContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e.Timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, e.Timeout)
}

func validateOperation(op Operation) error {
	if op.Command == "" {
		return fmt.Errorf("operation command is required")
	}
	fields := append([]string(nil), op.Flags...)
	fields = append(fields, op.Command)
	fields = append(fields, op.Args...)
	for _, arg := range fields {
		if arg == "" {
			return fmt.Errorf("operation %q contains empty argument", op.Command)
		}
	}
	return nil
}

func validateSpecialOperation(op Operation) error {
	if len(op.Flags) != 0 {
		return fmt.Errorf("special operation %q must not set flags", op.Command)
	}
	if op.Command == "gc-stale-nat-rules" {
		for _, arg := range op.Args {
			if arg == "" {
				return fmt.Errorf("special operation %q contains empty keep name", op.Command)
			}
		}
		return nil
	}
	if op.Command == "tag-policy-route" {
		if len(op.Args) != 4 {
			return fmt.Errorf("special operation %q requires vpc, name, priority, and match", op.Command)
		}
		for _, arg := range op.Args {
			if arg == "" {
				return fmt.Errorf("special operation %q contains empty argument", op.Command)
			}
		}
		return nil
	}
	if op.Command == "gc-stale-policy-routes" {
		if len(op.Args)%2 != 0 {
			return fmt.Errorf("special operation %q requires vpc/name keep pairs", op.Command)
		}
		for _, arg := range op.Args {
			if arg == "" {
				return fmt.Errorf("special operation %q contains empty keep argument", op.Command)
			}
		}
		return nil
	}
	if len(op.Args) != 1 || op.Args[0] == "" {
		return fmt.Errorf("special operation %q requires one non-empty argument", op.Command)
	}
	return nil
}

func cloneOperations(ops []Operation) []Operation {
	out := make([]Operation, 0, len(ops))
	for _, op := range ops {
		out = append(out, Operation{
			Command: op.Command,
			Flags:   append([]string(nil), op.Flags...),
			Args:    append([]string(nil), op.Args...),
		})
	}
	return out
}
