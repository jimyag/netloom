package ovn

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode"
)

const DefaultNBCTLTimeout = 30 * time.Second
const (
	DefaultNBCTLRetryAttempts       = 3
	DefaultNBCTLRetryInitialBackoff = 50 * time.Millisecond
	DefaultNBCTLRetryMaxBackoff     = 500 * time.Millisecond
)

type NBCTLRetryPolicy struct {
	Attempts       int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

func NewNBCTLRetryPolicy() NBCTLRetryPolicy {
	return NBCTLRetryPolicy{
		Attempts:       DefaultNBCTLRetryAttempts,
		InitialBackoff: DefaultNBCTLRetryInitialBackoff,
		MaxBackoff:     DefaultNBCTLRetryMaxBackoff,
	}
}

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
	RetryPolicy NBCTLRetryPolicy
}

func NewNBCTLExecutor(binary string, baseArgs ...string) *NBCTLExecutor {
	if binary == "" {
		binary = "ovn-nbctl"
	}
	return &NBCTLExecutor{
		Binary:      binary,
		BaseArgs:    append([]string(nil), baseArgs...),
		Transaction: true,
		Timeout:     DefaultNBCTLTimeout,
		RetryPolicy: NewNBCTLRetryPolicy(),
	}
}

func (e *NBCTLExecutor) HealthCheck(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "show")
	if _, err := e.outputCommand(ctx, args); err != nil {
		return 0, err
	}
	return time.Since(start), nil
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
	case "gc-dhcp-options", "gc-stale-dhcp-options", "gc-load-balancer-health-checks", "ensure-load-balancer-health-check", "gc-stale-load-balancer-health-checks", "gc-nat-rule", "gc-stale-nat-rules", "tag-nat-rule", "tag-policy-route", "gc-stale-policy-routes", "sync-policy-route-nexthop", "sync-policy-route-nexthops", "ensure-policy-route-nexthops":
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
			"external_ids:netloom_vpc="+op.Args[1],
		)
	case "gc-stale-dhcp-options":
		return e.destroyStaleDHCPOptions(ctx, op.Args)
	case "gc-load-balancer-health-checks":
		return e.destroyMatchingRecords(ctx, "Load_Balancer_Health_Check",
			"external_ids:netloom_owner=netloom",
			"external_ids:netloom_load_balancer="+op.Args[0],
			"external_ids:netloom_vpc="+op.Args[1],
		)
	case "ensure-load-balancer-health-check":
		return e.ensureLoadBalancerHealthCheck(ctx, op.Args)
	case "gc-stale-load-balancer-health-checks":
		return e.destroyStaleLoadBalancerHealthChecks(ctx, op.Args)
	case "gc-nat-rule":
		uuids, err := e.findUUIDs(ctx, "NAT",
			"external_ids:netloom_owner=netloom",
			"external_ids:netloom_nat="+op.Args[0],
			"external_ids:netloom_vpc="+op.Args[1],
		)
		if err != nil {
			return err
		}
		for _, uuid := range uuids {
			if err := e.destroyManagedNAT(ctx, op.Args[1], uuid); err != nil {
				return err
			}
		}
		return nil
	case "gc-stale-nat-rules":
		return e.destroyStaleNATRules(ctx, op.Args)
	case "tag-nat-rule":
		return e.tagNATRule(ctx, op.Args[0], op.Args[1], op.Args[2], op.Args[3], op.Args[4])
	case "tag-policy-route":
		return e.tagPolicyRoute(ctx, op.Args[0], op.Args[1], op.Args[2], op.Args[3])
	case "gc-stale-policy-routes":
		return e.destroyStalePolicyRoutes(ctx, op.Args)
	case "sync-policy-route-nexthop":
		return e.syncPolicyRouteNexthop(ctx, op.Args[0], op.Args[1], op.Args[2], op.Args[3], op.Args[4])
	case "sync-policy-route-nexthops":
		return e.syncPolicyRouteNexthops(ctx, op.Args[0], op.Args[1], op.Args[2], op.Args[3], op.Args[4])
	case "ensure-policy-route-nexthops":
		return e.ensurePolicyRouteNexthops(ctx, op.Args[0], op.Args[1], op.Args[2], op.Args[3], op.Args[4])
	default:
		return fmt.Errorf("unsupported special operation %q", op.Command)
	}
}

func (e *NBCTLExecutor) ensureLoadBalancerHealthCheck(ctx context.Context, fields []string) error {
	ovnLoadBalancer, _, _, vip := fields[0], fields[1], fields[2], loadBalancerHealthCheckVIP(fields[3:])
	uuids, err := e.loadBalancerHealthCheckUUIDs(ctx, fields[1], fields[2], vip)
	if err != nil {
		return err
	}
	var uuid string
	if len(uuids) == 0 {
		return e.createAndAttachLoadBalancerHealthCheck(ctx, ovnLoadBalancer, fields[3:])
	} else {
		uuid = uuids[0]
		if err := e.setLoadBalancerHealthCheck(ctx, uuid, fields[3:]); err != nil {
			return err
		}
	}
	if len(uuids) > 1 {
		for _, duplicate := range uuids[1:] {
			if err := e.destroyLoadBalancerHealthCheck(ctx, duplicate); err != nil {
				return err
			}
		}
	}
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "add", "load_balancer", ovnLoadBalancer, "health_check", uuid)
	return e.runCommand(ctx, args)
}

func (e *NBCTLExecutor) loadBalancerHealthCheckUUIDs(ctx context.Context, loadBalancer, vpc, vip string) ([]string, error) {
	return e.findLoadBalancerHealthChecks(ctx,
		"external_ids:netloom_owner=netloom",
		"external_ids:netloom_load_balancer="+loadBalancer,
		"external_ids:netloom_vpc="+vpc,
		"vip="+vip,
	)
}

func (e *NBCTLExecutor) createAndAttachLoadBalancerHealthCheck(ctx context.Context, ovnLoadBalancer string, fields []string) error {
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "--id=@netloom_lbhc", "create", "Load_Balancer_Health_Check")
	args = append(args, fields...)
	args = append(args, "--", "add", "load_balancer", ovnLoadBalancer, "health_check", "@netloom_lbhc")
	return e.runCommand(ctx, args)
}

func (e *NBCTLExecutor) setLoadBalancerHealthCheck(ctx context.Context, uuid string, fields []string) error {
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "set", "Load_Balancer_Health_Check", uuid)
	args = append(args, fields...)
	return e.runCommand(ctx, args)
}

func (e *NBCTLExecutor) destroyLoadBalancerHealthCheck(ctx context.Context, uuid string) error {
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "--if-exists", "destroy", "Load_Balancer_Health_Check", uuid)
	return e.runCommand(ctx, args)
}

func (e *NBCTLExecutor) destroyStaleLoadBalancerHealthChecks(ctx context.Context, args []string) error {
	loadBalancer := args[0]
	vpc := args[1]
	keep := make(map[string]struct{}, len(args)-2)
	for _, vip := range args[2:] {
		keep[vip] = struct{}{}
	}
	rows, err := e.loadBalancerHealthCheckRows(ctx, loadBalancer, vpc)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if _, ok := keep[row.vip]; ok {
			continue
		}
		if err := e.destroyLoadBalancerHealthCheck(ctx, row.uuid); err != nil {
			return err
		}
	}
	return nil
}

type loadBalancerHealthCheckRow struct {
	uuid string
	vip  string
}

func (e *NBCTLExecutor) loadBalancerHealthCheckRows(ctx context.Context, loadBalancer, vpc string) ([]loadBalancerHealthCheckRow, error) {
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "--format=csv", "--data=bare", "--no-headings", "--columns=_uuid,vip", "find", "Load_Balancer_Health_Check",
		"external_ids:netloom_owner=netloom",
		"external_ids:netloom_load_balancer="+loadBalancer,
		"external_ids:netloom_vpc="+vpc,
	)
	output, err := e.outputCommand(ctx, args)
	if err != nil {
		return nil, err
	}
	var rows []loadBalancerHealthCheckRow
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		uuid, vip, ok := parseLoadBalancerHealthCheckRow(line)
		if ok {
			rows = append(rows, loadBalancerHealthCheckRow{uuid: uuid, vip: vip})
		}
	}
	return rows, nil
}

func (e *NBCTLExecutor) findLoadBalancerHealthChecks(ctx context.Context, matches ...string) ([]string, error) {
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "--bare", "--columns=_uuid", "find", "Load_Balancer_Health_Check")
	args = append(args, matches...)
	output, err := e.outputCommand(ctx, args)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(output)), nil
}

func loadBalancerHealthCheckVIP(fields []string) string {
	for _, field := range fields {
		if vip, ok := strings.CutPrefix(field, "vip="); ok {
			return strings.Trim(vip, `"`)
		}
	}
	return ""
}

func parseLoadBalancerHealthCheckRow(line string) (string, string, bool) {
	uuid, vip, ok := strings.Cut(strings.TrimSpace(line), ",")
	if !ok {
		return "", "", false
	}
	uuid = strings.Trim(strings.TrimSpace(uuid), `"`)
	vip = strings.Trim(strings.TrimSpace(vip), `"`)
	return uuid, vip, uuid != "" && vip != ""
}

func (e *NBCTLExecutor) tagPolicyRoute(ctx context.Context, vpc, name, priority, match string) error {
	router := logicalRouter(vpc)
	uuids, err := e.routerPolicyUUIDs(ctx, router)
	if err != nil {
		return err
	}
	tagged := false
	for _, uuid := range uuids {
		policyPriority, policyMatch, err := e.logicalRouterPolicyIdentity(ctx, uuid)
		if err != nil {
			return err
		}
		if policyPriority != priority || policyMatch != match {
			continue
		}
		if tagged {
			if err := e.removeAndDestroyPolicyRoute(ctx, router, uuid); err != nil {
				return err
			}
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
		tagged = true
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
	seenKeep := make(map[string]struct{}, len(keepSet))
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
		key := vpc + "\x00" + name
		if _, keep := keepSet[key]; keep {
			if _, duplicate := seenKeep[key]; !duplicate {
				seenKeep[key] = struct{}{}
				continue
			}
		}
		if err := e.removeAndDestroyPolicyRoute(ctx, logicalRouter(vpc), uuid); err != nil {
			return err
		}
	}
	return nil
}

func (e *NBCTLExecutor) syncPolicyRouteNexthops(ctx context.Context, vpc, name, priority, match, nextHops string) error {
	policyUUIDs, err := e.policyRouteUUIDsByName(ctx, vpc, name)
	if err != nil {
		return err
	}
	router := logicalRouter(vpc)
	updated := false
	for _, uuid := range policyUUIDs {
		policyPriority, policyMatch, err := e.logicalRouterPolicyIdentity(ctx, uuid)
		if err != nil {
			return err
		}
		if policyPriority != priority || policyMatch != match {
			continue
		}
		if updated {
			if err := e.removeAndDestroyPolicyRoute(ctx, router, uuid); err != nil {
				return err
			}
			continue
		}
		args := append([]string(nil), e.BaseArgs...)
		args = append(args, "set", "Logical_Router_Policy", uuid, "nexthops="+nextHops)
		if err := e.runCommand(ctx, args); err != nil {
			return err
		}
		updated = true
	}
	return nil
}

func (e *NBCTLExecutor) ensurePolicyRouteNexthops(ctx context.Context, vpc, name, priority, match, nextHops string) error {
	if err := e.tagPolicyRoute(ctx, vpc, name, priority, match); err != nil {
		return err
	}
	if err := e.syncPolicyRouteNexthops(ctx, vpc, name, priority, match, nextHops); err != nil {
		return err
	}
	exists, err := e.managedPolicyRouteExists(ctx, vpc, name, priority, match)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return e.createPolicyRouteWithNexthops(ctx, vpc, name, priority, match, nextHops)
}

func (e *NBCTLExecutor) syncPolicyRouteNexthop(ctx context.Context, vpc, name, priority, match, nextHop string) error {
	policyUUIDs, err := e.policyRouteUUIDsByName(ctx, vpc, name)
	if err != nil {
		return err
	}
	router := logicalRouter(vpc)
	updated := false
	singleNextHop := ovnStringSetValues([]string{nextHop})
	for _, uuid := range policyUUIDs {
		policyPriority, policyMatch, err := e.logicalRouterPolicyIdentity(ctx, uuid)
		if err != nil {
			return err
		}
		if policyPriority != priority || policyMatch != match {
			continue
		}
		if updated {
			if err := e.removeAndDestroyPolicyRoute(ctx, router, uuid); err != nil {
				return err
			}
			continue
		}
		args := append([]string(nil), e.BaseArgs...)
		args = append(args, "set", "Logical_Router_Policy", uuid, "nexthops="+singleNextHop)
		if err := e.runCommand(ctx, args); err != nil {
			return err
		}
		updated = true
	}
	return nil
}

func (e *NBCTLExecutor) managedPolicyRouteExists(ctx context.Context, vpc, name, priority, match string) (bool, error) {
	policyUUIDs, err := e.policyRouteUUIDsByName(ctx, vpc, name)
	if err != nil {
		return false, err
	}
	for _, uuid := range policyUUIDs {
		policyPriority, policyMatch, err := e.logicalRouterPolicyIdentity(ctx, uuid)
		if err != nil {
			return false, err
		}
		if policyPriority == priority && policyMatch == match {
			return true, nil
		}
	}
	return false, nil
}

func (e *NBCTLExecutor) createPolicyRouteWithNexthops(ctx context.Context, vpc, name, priority, match, nextHops string) error {
	args := append([]string(nil), e.BaseArgs...)
	args = append(args,
		"--id=@netloom_lrp",
		"create",
		"Logical_Router_Policy",
		"priority="+priority,
		"match="+ovnStringValue(match),
		"action=reroute",
		"nexthops="+nextHops,
		"external_ids:netloom_owner=netloom",
		"external_ids:netloom_policy_route="+name,
		"external_ids:netloom_vpc="+vpc,
		"--",
		"add",
		"logical_router",
		logicalRouter(vpc),
		"policies",
		"@netloom_lrp",
	)
	return e.runCommand(ctx, args)
}

func (e *NBCTLExecutor) removeAndDestroyPolicyRoute(ctx context.Context, router, uuid string) error {
	removeArgs := append([]string(nil), e.BaseArgs...)
	removeArgs = append(removeArgs, "remove", "logical_router", router, "policies", uuid)
	if err := e.runCommand(ctx, removeArgs); err != nil {
		return err
	}
	destroyArgs := append([]string(nil), e.BaseArgs...)
	destroyArgs = append(destroyArgs, "--if-exists", "destroy", "Logical_Router_Policy", uuid)
	return e.runCommand(ctx, destroyArgs)
}

func (e *NBCTLExecutor) policyRouteUUIDsByName(ctx context.Context, vpc, name string) ([]string, error) {
	args := append([]string(nil), e.BaseArgs...)
	args = append(args,
		"--bare",
		"--columns=_uuid",
		"find",
		"Logical_Router_Policy",
		"external_ids:netloom_owner=netloom",
		"external_ids:netloom_vpc="+vpc,
		"external_ids:netloom_policy_route="+name,
	)
	output, err := e.outputCommand(ctx, args)
	if err != nil {
		return nil, err
	}
	return strings.Fields(strings.TrimSpace(string(output))), nil
}

func (e *NBCTLExecutor) destroyStaleNATRules(ctx context.Context, keep []string) error {
	keepSet := make(map[string]struct{}, len(keep)/2)
	for i := 0; i+1 < len(keep); i += 2 {
		keepSet[managedNATKey(keep[i], keep[i+1])] = struct{}{}
	}
	seenKeep := make(map[string]struct{}, len(keepSet))
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "--format=csv", "--data=bare", "--no-headings", "--columns=_uuid,external_ids", "find", "NAT", "external_ids:netloom_owner=netloom")
	output, err := e.outputCommand(ctx, args)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		uuid, natKey, ok := parseNATGCRow(line)
		if !ok {
			continue
		}
		if _, keep := keepSet[natKey]; keep {
			if _, duplicate := seenKeep[natKey]; !duplicate {
				seenKeep[natKey] = struct{}{}
				continue
			}
		}
		parts := strings.SplitN(natKey, "\x00", 2)
		if len(parts) != 2 {
			continue
		}
		if err := e.destroyManagedNAT(ctx, parts[0], uuid); err != nil {
			return err
		}
	}
	return nil
}

func (e *NBCTLExecutor) tagNATRule(ctx context.Context, name, vpc, natTypeValue, externalIP, logicalIP string) error {
	uuids, err := e.findUUIDs(ctx, "NAT",
		"type="+natTypeValue,
		"external_ip="+externalIP,
		"logical_ip="+logicalIP,
	)
	if err != nil {
		return err
	}
	if len(uuids) == 0 {
		return nil
	}
	args := append([]string(nil), e.BaseArgs...)
	args = append(args,
		"set", "NAT", uuids[0],
		"external_ids:netloom_owner=netloom",
		"external_ids:netloom_nat="+name,
		"external_ids:netloom_vpc="+vpc,
	)
	if err := e.runCommand(ctx, args); err != nil {
		return err
	}
	for _, duplicate := range uuids[1:] {
		if err := e.destroyManagedNAT(ctx, vpc, duplicate); err != nil {
			return err
		}
	}
	return nil
}

func (e *NBCTLExecutor) destroyStaleDHCPOptions(ctx context.Context, keep []string) error {
	keepSet := make(map[string]struct{}, len(keep)/2)
	for i := 0; i+1 < len(keep); i += 2 {
		keepSet[managedDHCPOptionKey(keep[i], keep[i+1])] = struct{}{}
	}
	seenKeep := make(map[string]struct{}, len(keepSet))
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "--format=csv", "--data=bare", "--no-headings", "--columns=_uuid,external_ids", "find", "DHCP_Options", "external_ids:netloom_owner=netloom")
	output, err := e.outputCommand(ctx, args)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		uuid, dhcpKey, ok := parseDHCPGCRow(line)
		if !ok {
			continue
		}
		if _, keep := keepSet[dhcpKey]; keep {
			if _, duplicate := seenKeep[dhcpKey]; !duplicate {
				seenKeep[dhcpKey] = struct{}{}
				continue
			}
		}
		if err := e.destroyDHCPOptionsByUUID(ctx, uuid); err != nil {
			return err
		}
	}
	return nil
}

func (e *NBCTLExecutor) detachNATFromRouter(ctx context.Context, router, uuid string) error {
	removeArgs := append([]string(nil), e.BaseArgs...)
	removeArgs = append(removeArgs, "remove", "logical_router", router, "nat", uuid)
	return e.runCommand(ctx, removeArgs)
}

func (e *NBCTLExecutor) destroyNATByUUID(ctx context.Context, uuid string) error {
	destroyArgs := append([]string(nil), e.BaseArgs...)
	destroyArgs = append(destroyArgs, "--if-exists", "destroy", "NAT", uuid)
	return e.runCommand(ctx, destroyArgs)
}

func (e *NBCTLExecutor) destroyDHCPOptionsByUUID(ctx context.Context, uuid string) error {
	destroyArgs := append([]string(nil), e.BaseArgs...)
	destroyArgs = append(destroyArgs, "--if-exists", "destroy", "DHCP_Options", uuid)
	return e.runCommand(ctx, destroyArgs)
}

func (e *NBCTLExecutor) destroyManagedNAT(ctx context.Context, vpc, uuid string) error {
	if err := e.detachNATFromRouter(ctx, logicalRouter(vpc), uuid); err != nil {
		return err
	}
	return e.destroyNATByUUID(ctx, uuid)
}

func parseNATGCRow(line string) (string, string, bool) {
	uuid, externalIDs, ok := parseExternalIDsCSVRow(line)
	if !ok {
		return "", "", false
	}
	natName := externalIDs["netloom_nat"]
	vpc := externalIDs["netloom_vpc"]
	return uuid, managedNATKey(vpc, natName), uuid != "" && vpc != "" && natName != ""
}

func parseDHCPGCRow(line string) (string, string, bool) {
	uuid, externalIDs, ok := parseExternalIDsCSVRow(line)
	if !ok {
		return "", "", false
	}
	endpointID := externalIDs["netloom_endpoint"]
	vpc := externalIDs["netloom_vpc"]
	return uuid, managedDHCPOptionKey(endpointID, vpc), uuid != "" && endpointID != "" && vpc != ""
}

func managedNATKey(vpc, name string) string {
	return vpc + "\x00" + name
}

func managedDHCPOptionKey(endpointID, vpc string) string {
	return endpointID + "\x00" + vpc
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
	for _, field := range strings.FieldsFunc(externalIDs, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	}) {
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
	uuids, err := e.findUUIDs(ctx, table, matches...)
	if err != nil {
		return err
	}
	for _, uuid := range uuids {
		destroyArgs := append([]string(nil), e.BaseArgs...)
		destroyArgs = append(destroyArgs, "--if-exists", "destroy", table, uuid)
		if err := e.runCommand(ctx, destroyArgs); err != nil {
			return err
		}
	}
	return nil
}

func (e *NBCTLExecutor) findUUIDs(ctx context.Context, table string, matches ...string) ([]string, error) {
	args := append([]string(nil), e.BaseArgs...)
	args = append(args, "--bare", "--columns=_uuid", "find", table)
	for _, match := range matches {
		args = append(args, ovnMatchField(match))
	}
	output, err := e.outputCommand(ctx, args)
	if err != nil {
		return nil, err
	}
	return strings.Fields(strings.TrimSpace(string(output))), nil
}

func ovnMatchField(match string) string {
	key, value, ok := strings.Cut(match, "=")
	if !ok || key == "" || value == "" {
		return match
	}
	value = trimOVNString(value)
	if strings.Contains(value, ":") {
		return key + "=" + ovnStringValue(value)
	}
	return key + "=" + value
}

func (e *NBCTLExecutor) runCommand(ctx context.Context, args []string) error {
	_, err := e.executeWithRetry(ctx, func(ctx context.Context, candidate []string) ([]byte, error) {
		return nil, e.runCommandRaw(ctx, candidate)
	}, args)
	if err != nil {
		return err
	}
	return nil
}

func (e *NBCTLExecutor) runCommandRaw(ctx context.Context, args []string) error {
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
	return e.executeWithRetry(ctx, e.outputCommandRaw, args)
}

func (e *NBCTLExecutor) outputCommandRaw(ctx context.Context, args []string) ([]byte, error) {
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

func (e *NBCTLExecutor) executeWithRetry(ctx context.Context, command func(context.Context, []string) ([]byte, error), args []string) ([]byte, error) {
	policy := e.retryPolicy()
	candidates := natFallbackArgs(append([]string(nil), args...))
	var lastErr error
	for _, candidate := range candidates {
		for attempt := 0; attempt < policy.Attempts; attempt++ {
			output, err := command(ctx, candidate)
			if err == nil {
				return output, nil
			}
			lastErr = err
			if isNATFallbackableError(err) {
				break
			}
			if !isRetryableNBCTLCommandError(err) || attempt == policy.Attempts-1 {
				return nil, err
			}
			if delay := policy.backoff(attempt + 1); delay > 0 {
				if err := sleepWithContext(ctx, delay); err != nil {
					return nil, err
				}
			}
		}
		if !isNATFallbackableError(lastErr) {
			return nil, lastErr
		}
	}
	return nil, lastErr
}

func (e *NBCTLExecutor) retryPolicy() NBCTLRetryPolicy {
	policy := e.RetryPolicy
	if policy.Attempts <= 0 {
		policy.Attempts = 1
	}
	if policy.InitialBackoff <= 0 {
		policy.InitialBackoff = DefaultNBCTLRetryInitialBackoff
	}
	if policy.MaxBackoff <= 0 {
		policy.MaxBackoff = DefaultNBCTLRetryMaxBackoff
	}
	return policy
}

func (p NBCTLRetryPolicy) backoff(attempt int) time.Duration {
	if attempt <= 0 || p.InitialBackoff <= 0 {
		return 0
	}
	if p.Attempts <= 1 {
		return 0
	}
	delay := p.InitialBackoff
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay > p.MaxBackoff {
			return p.MaxBackoff
		}
	}
	return delay
}

func isRetryableNBCTLCommandError(err error) bool {
	if err == nil {
		return false
	}
	errorText := err.Error()
	return strings.Contains(errorText, "database is busy") ||
		strings.Contains(errorText, "database is locked") ||
		strings.Contains(errorText, "transaction is already committed") ||
		strings.Contains(errorText, "Transaction in progress") ||
		strings.Contains(errorText, "another transaction") ||
		strings.Contains(errorText, "connection refused")
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func isNATFallbackableError(err error) bool {
	if err == nil {
		return false
	}
	errorText := err.Error()
	return strings.Contains(errorText, "logical_port_range") ||
		strings.Contains(errorText, "external_port_range") ||
		strings.Contains(errorText, "column whose name matches \"protocol\"") ||
		strings.Contains(errorText, "column \"protocol\"")
}

func natFallbackArgs(args []string) [][]string {
	candidates := [][]string{append([]string(nil), args...)}
	if hasNATRangeArgs(args) {
		rangeArgs := legacyNATRangeArgs(args)
		if !equalStringSlices(rangeArgs, args) {
			candidates = append(candidates, rangeArgs)
		}
		if hasNATProtocolArg(rangeArgs) {
			protocolRangeArgs := removeNATProtocolArg(rangeArgs)
			if !containsStringSlice(candidates, protocolRangeArgs) {
				candidates = append(candidates, protocolRangeArgs)
			}
		}
		return candidates
	}
	if hasNATProtocolArg(args) {
		protocolArgs := removeNATProtocolArg(args)
		if !equalStringSlices(protocolArgs, args) {
			candidates = append(candidates, protocolArgs)
		}
	}
	return candidates
}

func hasNATRangeArgs(args []string) bool {
	return hasAnyNATArgPrefix(args, "external_port_range=", "logical_port_range=")
}

func hasNATProtocolArg(args []string) bool {
	return hasAnyNATArgPrefix(args, "protocol=")
}

func hasAnyNATArgPrefix(args []string, prefixes ...string) bool {
	for _, arg := range args {
		for _, prefix := range prefixes {
			if strings.HasPrefix(arg, prefix) {
				return true
			}
		}
	}
	return false
}

func containsStringSlice(list [][]string, target []string) bool {
	for _, item := range list {
		if equalStringSlices(item, target) {
			return true
		}
	}
	return false
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func legacyNATRangeArgs(args []string) []string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "external_port_range=") || strings.HasPrefix(arg, "logical_port_range=") {
			break
		}
	}
	out := make([]string, len(args))
	for i, arg := range args {
		arg = strings.ReplaceAll(arg, "external_port_range=", "external_port=")
		arg = strings.ReplaceAll(arg, "logical_port_range=", "logical_port=")
		out[i] = arg
	}
	return out
}

func removeNATProtocolArg(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.HasPrefix(arg, "protocol=") {
			continue
		}
		out = append(out, arg)
	}
	return out
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
	if op.Command == "gc-stale-dhcp-options" {
		if len(op.Args)%2 != 0 {
			return fmt.Errorf("special operation %q requires endpoint/vpc keep pairs", op.Command)
		}
		for _, arg := range op.Args {
			if arg == "" {
				return fmt.Errorf("special operation %q contains empty keep argument", op.Command)
			}
		}
		return nil
	}
	if op.Command == "gc-nat-rule" {
		if len(op.Args) != 2 || op.Args[0] == "" || op.Args[1] == "" {
			return fmt.Errorf("special operation %q requires nat rule name and vpc", op.Command)
		}
		return nil
	}
	if op.Command == "tag-nat-rule" {
		if len(op.Args) != 5 {
			return fmt.Errorf("special operation %q requires nat rule name, vpc, type, external ip, and logical ip", op.Command)
		}
		for _, arg := range op.Args {
			if arg == "" {
				return fmt.Errorf("special operation %q contains empty argument", op.Command)
			}
		}
		return nil
	}
	if op.Command == "gc-dhcp-options" {
		if len(op.Args) != 2 || op.Args[0] == "" || op.Args[1] == "" {
			return fmt.Errorf("special operation %q requires endpoint id and vpc", op.Command)
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
	if op.Command == "sync-policy-route-nexthop" {
		if len(op.Args) != 5 {
			return fmt.Errorf("special operation %q requires vpc, name, priority, match, and nexthop", op.Command)
		}
		for _, arg := range op.Args {
			if arg == "" {
				return fmt.Errorf("special operation %q contains empty argument", op.Command)
			}
		}
		return nil
	}
	if op.Command == "sync-policy-route-nexthops" {
		if len(op.Args) != 5 {
			return fmt.Errorf("special operation %q requires vpc, name, priority, match, and nexthops", op.Command)
		}
		for _, arg := range op.Args {
			if arg == "" {
				return fmt.Errorf("special operation %q contains empty argument", op.Command)
			}
		}
		return nil
	}
	if op.Command == "ensure-policy-route-nexthops" {
		if len(op.Args) != 5 {
			return fmt.Errorf("special operation %q requires vpc, name, priority, match, and nexthops", op.Command)
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
	if op.Command == "ensure-load-balancer-health-check" {
		if len(op.Args) < 9 {
			return fmt.Errorf("special operation %q requires load balancer, identity, vip, options, and external ids", op.Command)
		}
		if loadBalancerHealthCheckVIP(op.Args[3:]) == "" {
			return fmt.Errorf("special operation %q requires vip field", op.Command)
		}
		for _, arg := range op.Args {
			if arg == "" {
				return fmt.Errorf("special operation %q contains empty argument", op.Command)
			}
		}
		return nil
	}
	if op.Command == "gc-stale-load-balancer-health-checks" {
		if len(op.Args) < 2 || op.Args[0] == "" || op.Args[1] == "" {
			return fmt.Errorf("special operation %q requires load balancer name and vpc", op.Command)
		}
		for _, arg := range op.Args[2:] {
			if arg == "" {
				return fmt.Errorf("special operation %q contains empty keep vip", op.Command)
			}
		}
		return nil
	}
	if op.Command == "gc-load-balancer-health-checks" {
		if len(op.Args) != 2 || op.Args[0] == "" || op.Args[1] == "" {
			return fmt.Errorf("special operation %q requires load balancer name and vpc", op.Command)
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
