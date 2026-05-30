package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/linuxdatapath"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
)

type ReconcileResult struct {
	Node         string
	Endpoints    int
	Programs     int
	Entries      int
	TCXEligible  int
	TCX          string
	Datapath     string
	LocalIPs     int
	RemoteRoutes int
	Cleanup      bool
}

type PolicyStore interface {
	ReplaceEndpoint(ctx context.Context, endpointID string, entries []dataplane.PolicyMapEntry) error
}

type ReconcileOptions struct {
	Node          string
	Store         PolicyStore
	TCXInterface  string
	TCXWorkload   bool
	TCXHold       time.Duration
	LinuxDatapath *linuxdatapath.Options
}

type tcxTarget struct {
	ifName   string
	attach   ebpf.AttachType
	programs []policy.Program
}

type tcxAttachmentHandle struct {
	result    dataplane.TCXSelfTestResult
	close     func() error
	signature string
}

type tcxAttachFunc func(context.Context, tcxTarget) (tcxAttachmentHandle, error)

type Reconciler struct {
	store               PolicyStore
	attachments         map[string]tcxAttachmentHandle
	attach              tcxAttachFunc
	conntrack           *dataplane.InMemoryConntrackStore
	conntrackSignatures map[string]string
}

func NewReconciler(store PolicyStore) *Reconciler {
	return &Reconciler{
		store:               store,
		attachments:         make(map[string]tcxAttachmentHandle),
		attach:              attachTCXTarget,
		conntrack:           dataplane.NewInMemoryConntrackStore(),
		conntrackSignatures: make(map[string]string),
	}
}

func ReconcileNode(ctx context.Context, state control.DesiredState, node string, store PolicyStore) (ReconcileResult, error) {
	return ReconcileNodeWithOptions(ctx, state, ReconcileOptions{Node: node, Store: store})
}

func ReconcileNodeWithOptions(ctx context.Context, state control.DesiredState, options ReconcileOptions) (ReconcileResult, error) {
	result, targets, _, err := prepareReconcile(ctx, state, options)
	if err != nil {
		return ReconcileResult{}, err
	}
	if options.TCXInterface != "" || options.TCXWorkload {
		tcxResult, err := attachTCXTargets(ctx, targets, options.TCXHold)
		if err != nil {
			return ReconcileResult{}, fmt.Errorf("attach tcx policy for node %s: %w", options.Node, err)
		}
		result.TCX = tcxResult
	}
	return result, nil
}

func (r *Reconciler) Reconcile(ctx context.Context, state control.DesiredState, options ReconcileOptions) (ReconcileResult, error) {
	if r == nil {
		return ReconcileResult{}, fmt.Errorf("reconciler is required")
	}
	if options.Store == nil {
		options.Store = r.store
	}
	result, targets, programs, err := prepareReconcile(ctx, state, options)
	if err != nil {
		return ReconcileResult{}, err
	}
	r.syncConntrackPrograms(programs)
	if options.TCXInterface != "" || options.TCXWorkload {
		tcxResult, err := r.syncTCXTargets(ctx, targets)
		if err != nil {
			return ReconcileResult{}, fmt.Errorf("attach tcx policy for node %s: %w", options.Node, err)
		}
		result.TCX = tcxResult
	}
	return result, nil
}

func (r *Reconciler) Close() error {
	if r == nil {
		return nil
	}
	var firstErr error
	for key, attachment := range r.attachments {
		if err := attachment.close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(r.attachments, key)
	}
	return firstErr
}

func (r *Reconciler) ConntrackStore() *dataplane.InMemoryConntrackStore {
	if r == nil {
		return nil
	}
	return r.conntrack
}

func (r *Reconciler) syncConntrackPrograms(programs []policy.Program) {
	if r == nil || r.conntrack == nil {
		return
	}
	desired := make(map[string]string, len(programs))
	for _, program := range programs {
		desired[program.EndpointID] = fmt.Sprintf("%#v/%#v", program.Rules, program.MapEntries)
	}
	for endpointID, oldSignature := range r.conntrackSignatures {
		signature, ok := desired[endpointID]
		if !ok || signature != oldSignature {
			r.conntrack.DeleteEndpoint(endpointID)
			delete(r.conntrackSignatures, endpointID)
		}
	}
	for endpointID, signature := range desired {
		r.conntrackSignatures[endpointID] = signature
	}
}

func prepareReconcile(ctx context.Context, state control.DesiredState, options ReconcileOptions) (ReconcileResult, []tcxTarget, []policy.Program, error) {
	if options.Node == "" {
		return ReconcileResult{}, nil, nil, fmt.Errorf("node name is required")
	}
	if options.Store == nil {
		return ReconcileResult{}, nil, nil, fmt.Errorf("policy store is required")
	}

	groups := make(map[string]model.SecurityGroup, len(state.SecurityGroups))
	for _, group := range state.SecurityGroups {
		if err := group.Validate(); err != nil {
			return ReconcileResult{}, nil, nil, err
		}
		groups[group.Name] = group
	}

	backend := dataplane.NewPolicyBackend(options.Store)
	result := ReconcileResult{Node: options.Node, TCX: "not-requested", Datapath: "not-requested"}
	var localPrograms []policy.Program
	for _, endpoint := range state.Endpoints {
		if endpoint.Node != options.Node {
			continue
		}
		if err := endpoint.Validate(); err != nil {
			return ReconcileResult{}, nil, nil, err
		}
		program, err := policy.CompileForEndpointWithState(endpoint, groups, state.Endpoints)
		if err != nil {
			return ReconcileResult{}, nil, nil, err
		}
		if err := backend.ApplyEndpointProgram(ctx, program); err != nil {
			return ReconcileResult{}, nil, nil, fmt.Errorf("apply policy program for endpoint %s: %w", endpoint.ID, err)
		}
		result.Endpoints++
		result.Programs++
		result.Entries += len(program.MapEntries)
		if _, err := dataplane.IPv4L4ACLRulesFromProgram(program); err == nil {
			result.TCXEligible++
			localPrograms = append(localPrograms, program)
		}
	}
	if options.LinuxDatapath != nil {
		linuxOptions := *options.LinuxDatapath
		linuxOptions.Node = options.Node
		linuxResult, err := linuxdatapath.Apply(ctx, state, linuxOptions)
		if err != nil {
			return ReconcileResult{}, nil, nil, fmt.Errorf("apply linux datapath for node %s: %w", options.Node, err)
		}
		result.Datapath = "linux:" + linuxResult.Device
		result.LocalIPs = linuxResult.LocalAddresses
		result.RemoteRoutes = linuxResult.RemoteRoutes
		result.Cleanup = linuxResult.CleanupPlanned
	}
	var targets []tcxTarget
	if options.TCXInterface != "" || options.TCXWorkload {
		targets = tcxTargets(options, localPrograms)
	}
	return result, targets, localPrograms, nil
}

func tcxTargets(options ReconcileOptions, programs []policy.Program) []tcxTarget {
	if options.TCXWorkload {
		targets := make([]tcxTarget, 0, len(programs))
		for _, program := range programs {
			targets = append(targets, tcxTarget{
				ifName:   linuxdatapath.HostVethName(program.EndpointID),
				attach:   ebpf.AttachTCXEgress,
				programs: []policy.Program{program},
			})
		}
		return targets
	}
	if options.TCXInterface == "" {
		return nil
	}
	return []tcxTarget{{
		ifName:   options.TCXInterface,
		attach:   ebpf.AttachTCXIngress,
		programs: programs,
	}}
}

func attachTCXTargets(ctx context.Context, targets []tcxTarget, hold time.Duration) (string, error) {
	if len(targets) == 0 {
		return "", fmt.Errorf("no TCX policy targets")
	}
	attachments := make([]tcxAttachmentHandle, 0, len(targets))
	defer func() {
		for i := len(attachments) - 1; i >= 0; i-- {
			_ = attachments[i].close()
		}
	}()
	for _, target := range targets {
		attachment, err := attachTCXTarget(ctx, target)
		if err != nil {
			return "", err
		}
		attachments = append(attachments, attachment)
	}
	if hold > 0 {
		timer := time.NewTimer(hold)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	return formatTCXResult(attachments), nil
}

func (r *Reconciler) syncTCXTargets(ctx context.Context, targets []tcxTarget) (string, error) {
	if len(targets) == 0 {
		return "", fmt.Errorf("no TCX policy targets")
	}
	desired := make(map[string]tcxTarget, len(targets))
	for _, target := range targets {
		desired[tcxTargetKey(target)] = target
	}
	for key, attachment := range r.attachments {
		if _, ok := desired[key]; !ok {
			if err := attachment.close(); err != nil {
				return "", err
			}
			delete(r.attachments, key)
		}
	}
	for key, target := range desired {
		signature := tcxTargetSignature(target)
		if old, ok := r.attachments[key]; ok && old.signature == signature {
			continue
		}
		if old, ok := r.attachments[key]; ok {
			if err := old.close(); err != nil {
				return "", err
			}
			delete(r.attachments, key)
		}
		attachment, err := r.attach(ctx, target)
		if err != nil {
			return "", err
		}
		attachment.signature = signature
		r.attachments[key] = attachment
	}
	attachments := make([]tcxAttachmentHandle, 0, len(targets))
	for _, target := range targets {
		attachments = append(attachments, r.attachments[tcxTargetKey(target)])
	}
	return formatTCXResult(attachments), nil
}

func attachTCXTarget(ctx context.Context, target tcxTarget) (tcxAttachmentHandle, error) {
	attachment, err := dataplane.AttachTCXIPv4L4Programs(ctx, target.ifName, target.programs, target.attach)
	if err != nil {
		return tcxAttachmentHandle{}, err
	}
	return tcxAttachmentHandle{
		result: attachment.Result,
		close:  attachment.Close,
	}, nil
}

func tcxTargetKey(target tcxTarget) string {
	return fmt.Sprintf("%s/%d", target.ifName, target.attach)
}

func tcxTargetSignature(target tcxTarget) string {
	return fmt.Sprintf("%s/%#v", tcxTargetKey(target), target.programs)
}

func formatTCXResult(attachments []tcxAttachmentHandle) string {
	first := attachments[0].result
	if len(attachments) == 1 {
		return fmt.Sprintf("attached:%s:%s:%s", first.Interface, first.Direction, first.Mode)
	}
	return fmt.Sprintf("attached-workloads:%d:%s:%s", len(attachments), first.Direction, first.Mode)
}
