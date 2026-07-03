package agent

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/linuxdatapath"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
)

type ReconcileResult struct {
	Node                             string
	Endpoints                        int
	Programs                         int
	Entries                          int
	PolicyMapEntries                 uint32
	PolicyMapCapacity                uint32
	PolicyMapPressureMax             uint32
	PolicyMapPressureEndpoint        string
	PolicyMapPressureEndpoints       int
	PolicyPressureMitigated          int
	PolicyPressureQuarantined        int
	PolicyPressureQuarantineEndpoint string
	PolicyMapDriftEndpoints          int
	PolicyMapDriftMissing            int
	PolicyMapDriftExtra              int
	PolicyMapDriftChanged            int
	PolicyEndpointStatus             []dataplane.PolicyEndpointStatus
	PolicyGCEndpoints                int
	PolicyAdded                      int
	PolicyUpdated                    int
	PolicyDeleted                    int
	PolicyUnchanged                  int
	PolicyEvents                     int
	PolicyFailed                     int
	PolicyRollbacks                  int
	PolicyFailedEndpoint             string
	PolicyFailedRevision             uint64
	PolicyRevisionMax                uint64
	PolicyLastError                  string
	PolicyRulePackets                uint64
	PolicyRuleBytes                  uint64
	PolicyRuleAllowed                uint64
	PolicyRuleDropped                uint64
	PolicyRuleRejected               uint64
	PolicyRuleLogged                 uint64
	PolicyRuleStats                  []dataplane.RuleMetrics
	TCXFailed                        int
	TCXRollbacks                     int
	TCXFailedTarget                  string
	TCXLastError                     string
	ConntrackExpired                 int
	TCXEligible                      int
	TCX                              string
	Datapath                         string
	LocalIPs                         int
	RemoteRoutes                     int
	PolicyRoutes                     int
	ProviderNetworks                 int
	ProviderLinks                    int
	ProviderReady                    int
	ProviderDegraded                 int
	ProviderStatus                   []linuxdatapath.ProviderLinkStatus
	ProviderIssues                   []linuxdatapath.ProviderIssue
	ProviderNetworkStatus            []linuxdatapath.ProviderNetworkStatus
	ProviderInventoryTotal           int
	ProviderInventoryReady           int
	ProviderInventoryDegraded        int
	ProviderInventoryStatus          []linuxdatapath.ProviderInterface
	Cleanup                          bool
}

type PolicyStore interface {
	ReplaceEndpoint(ctx context.Context, endpointID string, entries []dataplane.PolicyMapEntry) error
	DeleteEndpoint(ctx context.Context, endpointID string) error
}

type PolicyStatsStore interface {
	LastStats(endpointID string) dataplane.PolicyUpdateStats
}

type PolicyEventStore interface {
	Events() []dataplane.PolicyUpdateEvent
}

type PolicyEndpointInventory interface {
	EndpointIDs(context.Context) ([]string, error)
}

type PolicyUsageStore interface {
	PolicyMapUsage(context.Context) ([]dataplane.PolicyMapUsage, error)
}

type PolicyDriftStore interface {
	PolicyMapDrift(context.Context) ([]dataplane.PolicyMapDrift, error)
}

type PolicyEndpointStatusStore interface {
	PolicyEndpointStatuses(context.Context) ([]dataplane.PolicyEndpointStatus, error)
}

type PolicyEndpointEntryStore interface {
	Entries(endpointID string) []dataplane.PolicyMapEntry
}

type PolicyEndpointSweeper interface {
	SweepPolicyEndpoints(context.Context, []string, time.Duration) (int, error)
}

type PolicyRuleMetricsStore interface {
	PolicyRuleMetrics(context.Context) ([]dataplane.RuleMetrics, error)
}

type ReconcileOptions struct {
	Node                              string
	Store                             PolicyStore
	PolicyTelemetry                   PolicyRuleMetricsStore
	IdentityResolver                  policy.IdentityResolver
	TCXInterface                      string
	TCXWorkload                       bool
	TCXHold                           time.Duration
	ConntrackIdle                     time.Duration
	PolicyGCMaxIdle                   time.Duration
	PolicyPressureMitigationThreshold uint32
	PolicyPressureQuarantine          bool
	LinuxDatapath                     *linuxdatapath.Options
}

type PolicyEndpointPlan struct {
	EndpointID     string                      `json:"endpoint_id"`
	CurrentEntries int                         `json:"current_entries"`
	DesiredEntries int                         `json:"desired_entries"`
	Stats          dataplane.PolicyUpdateStats `json:"stats"`
	Changed        bool                        `json:"changed"`
}

type tcxTarget struct {
	ifName          string
	attach          ebpf.AttachType
	policyDirection model.Direction
	programs        []policy.Program
}

type tcxAttachmentHandle struct {
	result    dataplane.TCXSelfTestResult
	close     func() error
	metrics   func(context.Context) ([]dataplane.RuleMetrics, error)
	signature string
}

type tcxUpdateStats struct {
	Failed    int
	Rollbacks int
	Target    string
	LastError string
	Attempted int
	Reused    int
	Detached  int
}

type tcxAttachFunc func(context.Context, tcxTarget) (tcxAttachmentHandle, error)

type Reconciler struct {
	store               PolicyStore
	mu                  sync.Mutex
	attachments         map[string]tcxAttachmentHandle
	attach              tcxAttachFunc
	conntrack           *dataplane.InMemoryConntrackStore
	conntrackSignatures map[string]string
	policyEndpoints     map[string]struct{}
}

func NewReconciler(store PolicyStore) *Reconciler {
	return &Reconciler{
		store:               store,
		attachments:         make(map[string]tcxAttachmentHandle),
		attach:              attachTCXTarget,
		conntrack:           dataplane.NewInMemoryConntrackStore(),
		conntrackSignatures: make(map[string]string),
		policyEndpoints:     make(map[string]struct{}),
	}
}

func ReconcileNode(ctx context.Context, state control.DesiredState, node string, store PolicyStore) (ReconcileResult, error) {
	return ReconcileNodeWithOptions(ctx, state, ReconcileOptions{Node: node, Store: store})
}

func ReconcileNodeWithOptions(ctx context.Context, state control.DesiredState, options ReconcileOptions) (ReconcileResult, error) {
	result, targets, _, err := prepareReconcile(ctx, state, options)
	if err != nil {
		return result, err
	}
	if options.TCXInterface != "" || options.TCXWorkload {
		tcxResult, tcxStats, tcxMetrics, err := attachTCXTargets(ctx, targets, options.TCXHold)
		applyTCXUpdateStats(&result, tcxStats)
		if err != nil {
			return result, fmt.Errorf("attach tcx policy for node %s: %w", options.Node, err)
		}
		addPolicyRuleMetricsResult(&result, tcxMetrics)
		result.TCX = tcxResult
	}
	return result, nil
}

func RegeneratePolicyEndpoint(ctx context.Context, state control.DesiredState, options ReconcileOptions, endpointID string) (dataplane.PolicyEndpointStatus, error) {
	program, err := compileEndpointPolicyProgram(state, options, endpointID)
	if err != nil {
		return dataplane.PolicyEndpointStatus{}, err
	}
	if err := dataplane.NewPolicyBackend(options.Store).ApplyEndpointProgram(ctx, program); err != nil {
		return dataplane.PolicyEndpointStatus{}, fmt.Errorf("regenerate policy endpoint %s: %w", endpointID, err)
	}
	status := dataplane.PolicyEndpointStatus{
		EndpointID: program.EndpointID,
		Entries:    uint32(len(program.MapEntries)),
	}
	if statusStore, ok := options.Store.(PolicyEndpointStatusStore); ok {
		statuses, err := statusStore.PolicyEndpointStatuses(ctx)
		if err != nil {
			return dataplane.PolicyEndpointStatus{}, fmt.Errorf("read regenerated policy endpoint status: %w", err)
		}
		for _, candidate := range statuses {
			if candidate.EndpointID == program.EndpointID {
				return candidate, nil
			}
		}
	}
	return status, nil
}

func PlanPolicyEndpoint(ctx context.Context, state control.DesiredState, options ReconcileOptions, endpointID string) (PolicyEndpointPlan, error) {
	if options.Store == nil {
		return PolicyEndpointPlan{}, fmt.Errorf("policy store is required")
	}
	program, err := compileEndpointPolicyProgram(state, options, endpointID)
	if err != nil {
		return PolicyEndpointPlan{}, err
	}
	desired, err := dataplane.EncodeProgram(program)
	if err != nil {
		return PolicyEndpointPlan{}, err
	}
	entryStore, ok := options.Store.(PolicyEndpointEntryStore)
	if !ok {
		return PolicyEndpointPlan{}, fmt.Errorf("policy endpoint entries are not available")
	}
	current := entryStore.Entries(endpointID)
	plan := dataplane.PlanPolicyUpdate(current, desired)
	stats := plan.Stats()
	return PolicyEndpointPlan{
		EndpointID:     endpointID,
		CurrentEntries: len(current),
		DesiredEntries: len(desired),
		Stats:          stats,
		Changed:        stats.Added != 0 || stats.Updated != 0 || stats.Deleted != 0,
	}, nil
}

func QuarantinePolicyEndpoint(ctx context.Context, state control.DesiredState, options ReconcileOptions, endpointID string) (dataplane.PolicyEndpointStatus, error) {
	if options.Node == "" {
		return dataplane.PolicyEndpointStatus{}, fmt.Errorf("node name is required")
	}
	if options.Store == nil {
		return dataplane.PolicyEndpointStatus{}, fmt.Errorf("policy store is required")
	}
	if endpointID == "" {
		return dataplane.PolicyEndpointStatus{}, fmt.Errorf("policy endpoint is required")
	}
	if err := validateAgentState(state); err != nil {
		return dataplane.PolicyEndpointStatus{}, err
	}
	endpoint, ok := desiredEndpointByPolicyID(state.Endpoints, endpointID)
	if !ok {
		return dataplane.PolicyEndpointStatus{}, fmt.Errorf("policy endpoint %q not found in desired state", endpointID)
	}
	if endpoint.Node != options.Node {
		return dataplane.PolicyEndpointStatus{}, fmt.Errorf("policy endpoint %q is assigned to node %q, not %q", endpointID, endpoint.Node, options.Node)
	}
	entries := quarantinePolicyMapEntries()
	if err := options.Store.ReplaceEndpoint(ctx, endpointID, entries); err != nil {
		return dataplane.PolicyEndpointStatus{}, fmt.Errorf("quarantine policy endpoint %s: %w", endpointID, err)
	}
	status := dataplane.PolicyEndpointStatus{
		EndpointID: endpointID,
		Entries:    uint32(len(entries)),
	}
	if statusStore, ok := options.Store.(PolicyEndpointStatusStore); ok {
		statuses, err := statusStore.PolicyEndpointStatuses(ctx)
		if err != nil {
			return dataplane.PolicyEndpointStatus{}, fmt.Errorf("read quarantined policy endpoint status: %w", err)
		}
		for _, candidate := range statuses {
			if candidate.EndpointID == endpointID {
				return candidate, nil
			}
		}
	}
	return status, nil
}

func compileEndpointPolicyProgram(state control.DesiredState, options ReconcileOptions, endpointID string) (policy.Program, error) {
	if options.Node == "" {
		return policy.Program{}, fmt.Errorf("node name is required")
	}
	if options.Store == nil {
		return policy.Program{}, fmt.Errorf("policy store is required")
	}
	if endpointID == "" {
		return policy.Program{}, fmt.Errorf("policy endpoint is required")
	}
	if err := validateAgentState(state); err != nil {
		return policy.Program{}, err
	}
	endpoint, ok := desiredEndpointByPolicyID(state.Endpoints, endpointID)
	if !ok {
		return policy.Program{}, fmt.Errorf("policy endpoint %q not found in desired state", endpointID)
	}
	if endpoint.Node != options.Node {
		return policy.Program{}, fmt.Errorf("policy endpoint %q is assigned to node %q, not %q", endpointID, endpoint.Node, options.Node)
	}
	if err := endpoint.Validate(); err != nil {
		return policy.Program{}, err
	}
	resolver := options.IdentityResolver
	if resolver == nil {
		resolver = policy.NewIdentityCache()
	}
	groups := securityGroupsForEndpointVPC(state.SecurityGroups, endpoint.VPC)
	return policy.CompileForEndpointWithContext(endpoint, groups, policy.CompileContext{
		Endpoints:        state.Endpoints,
		Subnets:          state.Subnets,
		Gateways:         state.Gateways,
		Services:         state.LoadBalancers,
		DNSRecords:       state.DNSRecords,
		CIDRGroups:       state.CIDRGroups,
		IdentityResolver: resolver,
	})
}

func UnquarantinePolicyEndpoint(ctx context.Context, state control.DesiredState, options ReconcileOptions, endpointID string) (dataplane.PolicyEndpointStatus, error) {
	status, err := RegeneratePolicyEndpoint(ctx, state, options, endpointID)
	if err != nil {
		return dataplane.PolicyEndpointStatus{}, fmt.Errorf("unquarantine policy endpoint %s: %w", endpointID, err)
	}
	return status, nil
}

func quarantinePolicyMapEntries() []dataplane.PolicyMapEntry {
	return []dataplane.PolicyMapEntry{
		quarantinePolicyMapEntry(dataplane.DirectionIngress),
		quarantinePolicyMapEntry(dataplane.DirectionEgress),
	}
}

func quarantinePolicyMapEntry(direction uint8) dataplane.PolicyMapEntry {
	return dataplane.PolicyMapEntry{
		Key: dataplane.PolicyKey{
			PrefixLen:  dataplane.StaticPrefixBits,
			Direction:  direction,
			Protocol:   0,
			DestPortBE: 0,
		},
		Value: dataplane.PolicyEntry{
			Deny:        1,
			L4PrefixLen: 0,
			Precedence:  ^uint32(0),
			RuleCookie:  0x51554152,
		},
	}
}

func (r *Reconciler) Reconcile(ctx context.Context, state control.DesiredState, options ReconcileOptions) (ReconcileResult, error) {
	if r == nil {
		return ReconcileResult{}, fmt.Errorf("reconciler is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if options.Store == nil {
		options.Store = r.store
	}
	result, targets, programs, err := prepareReconcile(ctx, state, options)
	if err != nil {
		return result, err
	}
	if err := r.syncPolicyStore(ctx, programs, options.Store); err != nil {
		return result, err
	}
	if err := populatePolicyMapUsageResult(ctx, options.Store, &result); err != nil {
		return result, err
	}
	if err := mitigatePolicyMapPressureResult(ctx, options.Store, programs, options.PolicyPressureMitigationThreshold, options.PolicyPressureQuarantine, &result); err != nil {
		return result, err
	}
	if err := populatePolicyMapDriftResult(ctx, options.Store, &result); err != nil {
		return result, err
	}
	if err := populatePolicyEndpointStatusResult(ctx, options.Store, &result); err != nil {
		return result, err
	}
	if err := populatePolicyRuleMetricsResult(ctx, options, &result); err != nil {
		return result, err
	}
	r.syncConntrackPrograms(programs)
	result.ConntrackExpired = r.conntrack.SweepIdle(conntrackIdleTimeout(options.ConntrackIdle))
	if options.TCXInterface != "" || options.TCXWorkload {
		tcxResult, tcxStats, tcxMetrics, err := r.syncTCXTargets(ctx, targets)
		applyTCXUpdateStats(&result, tcxStats)
		if err != nil {
			return result, fmt.Errorf("attach tcx policy for node %s: %w", options.Node, err)
		}
		addPolicyRuleMetricsResult(&result, tcxMetrics)
		result.TCX = tcxResult
	}
	return result, nil
}

func (r *Reconciler) syncPolicyStore(ctx context.Context, programs []policy.Program, store PolicyStore) error {
	if r == nil || store == nil {
		return nil
	}
	desired := make(map[string]struct{}, len(programs))
	for _, program := range programs {
		desired[program.EndpointID] = struct{}{}
	}
	tracked := make(map[string]struct{}, len(r.policyEndpoints))
	for endpointID := range r.policyEndpoints {
		tracked[endpointID] = struct{}{}
	}
	if inventory, ok := store.(PolicyEndpointInventory); ok {
		endpointIDs, err := inventory.EndpointIDs(ctx)
		if err != nil {
			return fmt.Errorf("list managed policy endpoints: %w", err)
		}
		for _, endpointID := range endpointIDs {
			tracked[endpointID] = struct{}{}
		}
	}
	for endpointID := range tracked {
		if _, ok := desired[endpointID]; ok {
			continue
		}
		if err := store.DeleteEndpoint(ctx, endpointID); err != nil {
			return fmt.Errorf("delete stale policy for endpoint %s: %w", endpointID, err)
		}
		delete(r.policyEndpoints, endpointID)
	}
	for endpointID := range desired {
		r.policyEndpoints[endpointID] = struct{}{}
	}
	return nil
}

func (r *Reconciler) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeTCXAttachments()
}

func (r *Reconciler) ConntrackStore() *dataplane.InMemoryConntrackStore {
	if r == nil {
		return nil
	}
	return r.conntrack
}

func conntrackIdleTimeout(timeout time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	return dataplane.DefaultConntrackMaxIdle
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

	if err := validateAgentState(state); err != nil {
		return ReconcileResult{}, nil, nil, err
	}

	backend := dataplane.NewPolicyBackend(options.Store)
	result := ReconcileResult{Node: options.Node, TCX: "not-requested", Datapath: "not-requested"}
	var localPrograms []policy.Program
	var tcxPrograms []policy.Program
	resolver := options.IdentityResolver
	if resolver == nil {
		resolver = policy.NewIdentityCache()
	}
	for _, endpoint := range state.Endpoints {
		if endpoint.Node != options.Node {
			continue
		}
		if err := endpoint.Validate(); err != nil {
			return ReconcileResult{}, nil, nil, err
		}
		groups := securityGroupsForEndpointVPC(state.SecurityGroups, endpoint.VPC)
		program, err := policy.CompileForEndpointWithContext(endpoint, groups, policy.CompileContext{
			Endpoints:        state.Endpoints,
			Subnets:          state.Subnets,
			Gateways:         state.Gateways,
			Services:         state.LoadBalancers,
			DNSRecords:       state.DNSRecords,
			CIDRGroups:       state.CIDRGroups,
			IdentityResolver: resolver,
		})
		if err != nil {
			return ReconcileResult{}, nil, nil, err
		}
		eventStore, _ := options.Store.(PolicyEventStore)
		beforeEvents := 0
		if eventStore != nil {
			beforeEvents = len(eventStore.Events())
		}
		result.Endpoints++
		result.Programs++
		result.Entries += len(program.MapEntries)
		if err := backend.ApplyEndpointProgram(ctx, program); err != nil {
			if eventStore != nil {
				recordPolicyEventsDelta(&result, eventStore.Events(), beforeEvents, program.EndpointID)
			}
			return result, nil, nil, fmt.Errorf("apply policy program for endpoint %s in vpc %s: %w", endpoint.ID, endpoint.VPC, err)
		}
		if eventStore != nil {
			recordPolicyEventsDelta(&result, eventStore.Events(), beforeEvents, program.EndpointID)
		} else if statsStore, ok := options.Store.(PolicyStatsStore); ok {
			stats := statsStore.LastStats(program.EndpointID)
			result.PolicyAdded += stats.Added
			result.PolicyUpdated += stats.Updated
			result.PolicyDeleted += stats.Deleted
			result.PolicyUnchanged += stats.Unchanged
			result.PolicyEvents++
			if stats.Revision > result.PolicyRevisionMax {
				result.PolicyRevisionMax = stats.Revision
			}
		}
		localPrograms = append(localPrograms, program)
		if tcxEligibleProgram(program) {
			result.TCXEligible++
			tcxPrograms = append(tcxPrograms, program)
		}
	}
	if options.LinuxDatapath != nil {
		linuxOptions := *options.LinuxDatapath
		linuxOptions.Node = options.Node
		linuxResult, err := linuxdatapath.Apply(ctx, state, linuxOptions)
		result.Datapath = "linux:" + linuxResult.Device
		result.LocalIPs = linuxResult.LocalAddresses
		result.RemoteRoutes = linuxResult.RemoteRoutes
		result.PolicyRoutes = linuxResult.PolicyRoutes
		result.ProviderNetworks = linuxResult.ProviderNetworks
		result.ProviderLinks = linuxResult.ProviderLinks
		result.ProviderReady = linuxResult.ProviderReady
		result.ProviderDegraded = linuxResult.ProviderDegraded
		result.ProviderStatus = append([]linuxdatapath.ProviderLinkStatus(nil), linuxResult.ProviderStatus...)
		result.ProviderIssues = append([]linuxdatapath.ProviderIssue(nil), linuxResult.ProviderIssues...)
		result.ProviderNetworkStatus = append([]linuxdatapath.ProviderNetworkStatus(nil), linuxResult.ProviderNetworkStatus...)
		result.ProviderInventoryTotal = linuxResult.ProviderInventoryTotal
		result.ProviderInventoryReady = linuxResult.ProviderInventoryReady
		result.ProviderInventoryDegraded = linuxResult.ProviderInventoryDegraded
		result.ProviderInventoryStatus = append([]linuxdatapath.ProviderInterface(nil), linuxResult.ProviderInventoryStatus...)
		result.Cleanup = linuxResult.CleanupPlanned
		if err != nil {
			return result, nil, nil, fmt.Errorf("apply linux datapath for node %s: %w", options.Node, err)
		}
	}
	if err := populatePolicyMapUsageResult(ctx, options.Store, &result); err != nil {
		return ReconcileResult{}, nil, nil, err
	}
	if err := mitigatePolicyMapPressureResult(ctx, options.Store, localPrograms, options.PolicyPressureMitigationThreshold, options.PolicyPressureQuarantine, &result); err != nil {
		return ReconcileResult{}, nil, nil, err
	}
	if err := populatePolicyMapDriftResult(ctx, options.Store, &result); err != nil {
		return ReconcileResult{}, nil, nil, err
	}
	if err := populatePolicyEndpointStatusResult(ctx, options.Store, &result); err != nil {
		return ReconcileResult{}, nil, nil, err
	}
	if err := populatePolicyRuleMetricsResult(ctx, options, &result); err != nil {
		return ReconcileResult{}, nil, nil, err
	}
	if err := sweepPolicyEndpointsResult(ctx, options.Store, localPrograms, options.PolicyGCMaxIdle, &result); err != nil {
		return ReconcileResult{}, nil, nil, err
	}
	if result.PolicyGCEndpoints != 0 {
		if err := populatePolicyMapUsageResult(ctx, options.Store, &result); err != nil {
			return ReconcileResult{}, nil, nil, err
		}
		if err := populatePolicyMapDriftResult(ctx, options.Store, &result); err != nil {
			return ReconcileResult{}, nil, nil, err
		}
		if err := populatePolicyEndpointStatusResult(ctx, options.Store, &result); err != nil {
			return ReconcileResult{}, nil, nil, err
		}
	}
	var targets []tcxTarget
	if options.TCXInterface != "" || options.TCXWorkload {
		var err error
		targets, err = tcxTargets(options, tcxPrograms)
		if err != nil {
			return ReconcileResult{}, nil, nil, err
		}
	}
	return result, targets, localPrograms, nil
}

func mitigatePolicyMapPressureResult(ctx context.Context, store PolicyStore, programs []policy.Program, threshold uint32, quarantine bool, result *ReconcileResult) error {
	if result == nil || threshold == 0 || result.PolicyMapPressureMax < threshold {
		return nil
	}
	inventory, ok := store.(PolicyEndpointInventory)
	if !ok {
		return nil
	}
	endpointIDs, err := inventory.EndpointIDs(ctx)
	if err != nil {
		return fmt.Errorf("list policy endpoints for pressure mitigation: %w", err)
	}
	keep := make(map[string]struct{}, len(programs))
	for _, program := range programs {
		keep[program.EndpointID] = struct{}{}
	}
	mitigated := 0
	for _, endpointID := range endpointIDs {
		if _, ok := keep[endpointID]; ok {
			continue
		}
		if err := store.DeleteEndpoint(ctx, endpointID); err != nil {
			return fmt.Errorf("mitigate policy map pressure by deleting endpoint %s: %w", endpointID, err)
		}
		mitigated++
	}
	result.PolicyPressureMitigated = mitigated
	if mitigated == 0 {
		return quarantinePolicyMapPressureResult(ctx, store, keep, threshold, quarantine, result)
	}
	if err := populatePolicyMapUsageResult(ctx, store, result); err != nil {
		return err
	}
	return quarantinePolicyMapPressureResult(ctx, store, keep, threshold, quarantine, result)
}

func quarantinePolicyMapPressureResult(ctx context.Context, store PolicyStore, keep map[string]struct{}, threshold uint32, quarantine bool, result *ReconcileResult) error {
	if !quarantine || result == nil || result.PolicyMapPressureMax < threshold || result.PolicyMapPressureEndpoint == "" {
		return nil
	}
	endpointID := result.PolicyMapPressureEndpoint
	if _, ok := keep[endpointID]; !ok {
		return nil
	}
	entries := quarantinePolicyMapEntries()
	if err := store.ReplaceEndpoint(ctx, endpointID, entries); err != nil {
		return fmt.Errorf("quarantine pressured policy endpoint %s: %w", endpointID, err)
	}
	result.PolicyPressureQuarantined = 1
	result.PolicyPressureQuarantineEndpoint = endpointID
	return populatePolicyMapUsageResult(ctx, store, result)
}

func sweepPolicyEndpointsResult(ctx context.Context, store PolicyStore, programs []policy.Program, maxIdle time.Duration, result *ReconcileResult) error {
	if maxIdle <= 0 {
		return nil
	}
	sweeper, ok := store.(PolicyEndpointSweeper)
	if !ok {
		return nil
	}
	keep := make([]string, 0, len(programs))
	for _, program := range programs {
		keep = append(keep, program.EndpointID)
	}
	swept, err := sweeper.SweepPolicyEndpoints(ctx, keep, maxIdle)
	if err != nil {
		return fmt.Errorf("sweep stale policy endpoints: %w", err)
	}
	result.PolicyGCEndpoints = swept
	return nil
}

func recordPolicyEventsDelta(result *ReconcileResult, events []dataplane.PolicyUpdateEvent, from int, endpointID string) {
	if result == nil {
		return
	}
	if from < 0 {
		from = 0
	}
	for i := from; i < len(events); i++ {
		event := events[i]
		if endpointID != "" && event.EndpointID != endpointID {
			continue
		}
		result.PolicyEvents++
		if event.Revision > result.PolicyRevisionMax {
			result.PolicyRevisionMax = event.Revision
		}
		if event.Success {
			result.PolicyAdded += event.Stats.Added
			result.PolicyUpdated += event.Stats.Updated
			result.PolicyDeleted += event.Stats.Deleted
			result.PolicyUnchanged += event.Stats.Unchanged
			continue
		}
		result.PolicyFailed++
		result.PolicyRollbacks++
		result.PolicyFailedEndpoint = event.EndpointID
		result.PolicyFailedRevision = event.Revision
		if event.Error != "" {
			result.PolicyLastError = event.Error
		}
	}
}

func populatePolicyMapUsageResult(ctx context.Context, store PolicyStore, result *ReconcileResult) error {
	if result == nil {
		return nil
	}
	usageStore, ok := store.(PolicyUsageStore)
	if !ok {
		result.PolicyMapEntries = 0
		result.PolicyMapCapacity = 0
		result.PolicyMapPressureMax = 0
		result.PolicyMapPressureEndpoint = ""
		result.PolicyMapPressureEndpoints = 0
		return nil
	}
	usages, err := usageStore.PolicyMapUsage(ctx)
	if err != nil {
		return fmt.Errorf("read policy map usage: %w", err)
	}
	summary := dataplane.SummarizePolicyMapUsage(usages)
	result.PolicyMapEntries = summary.Entries
	result.PolicyMapCapacity = summary.Capacity
	result.PolicyMapPressureMax = summary.MaxPressurePercent
	result.PolicyMapPressureEndpoint = summary.MaxPressureEndpoint
	result.PolicyMapPressureEndpoints = summary.PressureEndpoints
	return nil
}

func populatePolicyMapDriftResult(ctx context.Context, store PolicyStore, result *ReconcileResult) error {
	if result == nil {
		return nil
	}
	driftStore, ok := store.(PolicyDriftStore)
	if !ok {
		result.PolicyMapDriftEndpoints = 0
		result.PolicyMapDriftMissing = 0
		result.PolicyMapDriftExtra = 0
		result.PolicyMapDriftChanged = 0
		return nil
	}
	reports, err := driftStore.PolicyMapDrift(ctx)
	if err != nil {
		return fmt.Errorf("read policy map drift: %w", err)
	}
	summary := dataplane.SummarizePolicyMapDrift(reports)
	result.PolicyMapDriftEndpoints = summary.DriftedEndpoints
	result.PolicyMapDriftMissing = summary.MissingEntries
	result.PolicyMapDriftExtra = summary.ExtraEntries
	result.PolicyMapDriftChanged = summary.ChangedEntries
	return nil
}

func populatePolicyEndpointStatusResult(ctx context.Context, store PolicyStore, result *ReconcileResult) error {
	if result == nil {
		return nil
	}
	statusStore, ok := store.(PolicyEndpointStatusStore)
	if !ok {
		result.PolicyEndpointStatus = nil
		return nil
	}
	statuses, err := statusStore.PolicyEndpointStatuses(ctx)
	if err != nil {
		return fmt.Errorf("read policy endpoint status: %w", err)
	}
	result.PolicyEndpointStatus = append([]dataplane.PolicyEndpointStatus(nil), statuses...)
	return nil
}

func populatePolicyRuleMetricsResult(ctx context.Context, options ReconcileOptions, result *ReconcileResult) error {
	if result == nil {
		return nil
	}
	result.PolicyRulePackets = 0
	result.PolicyRuleBytes = 0
	result.PolicyRuleAllowed = 0
	result.PolicyRuleDropped = 0
	result.PolicyRuleRejected = 0
	result.PolicyRuleLogged = 0
	result.PolicyRuleStats = nil
	telemetry := options.PolicyTelemetry
	if telemetry == nil {
		var ok bool
		telemetry, ok = options.Store.(PolicyRuleMetricsStore)
		if !ok {
			return nil
		}
	}
	stats, err := telemetry.PolicyRuleMetrics(ctx)
	if err != nil {
		return fmt.Errorf("read policy rule metrics: %w", err)
	}
	addPolicyRuleMetricsResult(result, stats)
	return nil
}

func addPolicyRuleMetricsResult(result *ReconcileResult, stats []dataplane.RuleMetrics) {
	if result == nil {
		return
	}
	result.PolicyRuleStats = append(result.PolicyRuleStats, stats...)
	for _, stat := range stats {
		result.PolicyRulePackets += stat.Packets
		result.PolicyRuleBytes += stat.Bytes
		result.PolicyRuleAllowed += stat.Allowed
		result.PolicyRuleDropped += stat.Dropped
		result.PolicyRuleRejected += stat.Rejected
		result.PolicyRuleLogged += stat.Logged
	}
}

func securityGroupsForEndpointVPC(groups []model.SecurityGroup, vpc string) map[string]model.SecurityGroup {
	out := make(map[string]model.SecurityGroup)
	for _, group := range groups {
		if group.VPC == vpc {
			out[group.Name] = group
		}
	}
	return out
}

func desiredEndpointByPolicyID(endpoints []model.Endpoint, endpointID string) (model.Endpoint, bool) {
	for _, endpoint := range endpoints {
		if model.EndpointKey(endpoint.VPC, endpoint.ID) == endpointID {
			return endpoint, true
		}
	}
	return model.Endpoint{}, false
}

func validateAgentState(state control.DesiredState) error {
	groups := make(map[string]struct{}, len(state.SecurityGroups))
	for _, group := range state.SecurityGroups {
		if err := group.Validate(); err != nil {
			return err
		}
		key := group.VPC + "\x00" + group.Name
		if _, ok := groups[key]; ok {
			return fmt.Errorf("duplicate security group name %q in vpc %q", group.Name, group.VPC)
		}
		groups[key] = struct{}{}
	}
	endpoints := make(map[string]struct{}, len(state.Endpoints))
	for _, endpoint := range state.Endpoints {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		key := model.EndpointKey(endpoint.VPC, endpoint.ID)
		if _, ok := endpoints[key]; ok {
			return fmt.Errorf("duplicate endpoint id %q in vpc %q", endpoint.ID, endpoint.VPC)
		}
		endpoints[key] = struct{}{}
	}
	loadBalancers := make(map[string]struct{}, len(state.LoadBalancers))
	for _, lb := range state.LoadBalancers {
		if err := lb.Validate(); err != nil {
			return err
		}
		key := lb.VPC + "/" + lb.Name
		if _, ok := loadBalancers[key]; ok {
			return fmt.Errorf("duplicate load balancer %q in vpc %s", lb.Name, lb.VPC)
		}
		loadBalancers[key] = struct{}{}
	}
	cidrGroups := make(map[string]struct{}, len(state.CIDRGroups))
	for _, group := range state.CIDRGroups {
		if err := group.Validate(); err != nil {
			return err
		}
		key := group.VPC + "/" + group.Name
		if _, ok := cidrGroups[key]; ok {
			return fmt.Errorf("duplicate cidr group %q in vpc %s", group.Name, group.VPC)
		}
		cidrGroups[key] = struct{}{}
	}
	return nil
}

func tcxTargets(options ReconcileOptions, programs []policy.Program) ([]tcxTarget, error) {
	if options.TCXWorkload {
		targets := make([]tcxTarget, 0, len(programs))
		for _, program := range programs {
			if tcxEligibleProgramForDirection(program, model.DirectionIngress) {
				targets = append(targets, tcxTarget{
					ifName:          linuxdatapath.HostVethName(program.EndpointID),
					attach:          ebpf.AttachTCXEgress,
					policyDirection: model.DirectionIngress,
					programs:        []policy.Program{program},
				})
			}
			if tcxEligibleProgramForDirection(program, model.DirectionEgress) {
				targets = append(targets, tcxTarget{
					ifName:          linuxdatapath.HostVethName(program.EndpointID),
					attach:          ebpf.AttachTCXIngress,
					policyDirection: model.DirectionEgress,
					programs:        []policy.Program{program},
				})
			}
		}
		return targets, nil
	}
	if options.TCXInterface == "" {
		return nil, nil
	}
	if len(programs) == 0 {
		return nil, nil
	}
	ingressPrograms := make([]policy.Program, 0, len(programs))
	egressPrograms := make([]policy.Program, 0, len(programs))
	for _, program := range programs {
		if tcxEligibleProgramForDirection(program, model.DirectionIngress) {
			ingressPrograms = append(ingressPrograms, program)
		}
		if tcxEligibleProgramForDirection(program, model.DirectionEgress) {
			egressPrograms = append(egressPrograms, program)
		}
	}
	if len(ingressPrograms) == 0 && len(egressPrograms) == 0 {
		return nil, nil
	}
	targets := make([]tcxTarget, 0, 2)
	if len(ingressPrograms) > 0 {
		targetPrograms := ingressPrograms
		if len(targetPrograms) == 1 {
			targetPrograms = []policy.Program{tcxInterfaceProgram(targetPrograms[0])}
		}
		targets = append(targets, tcxTarget{
			ifName:          options.TCXInterface,
			attach:          ebpf.AttachTCXIngress,
			policyDirection: model.DirectionIngress,
			programs:        targetPrograms,
		})
	}
	if len(egressPrograms) > 0 {
		targetPrograms := egressPrograms
		if len(targetPrograms) == 1 {
			targetPrograms = []policy.Program{tcxInterfaceProgram(targetPrograms[0])}
		}
		targets = append(targets, tcxTarget{
			ifName:          options.TCXInterface,
			attach:          ebpf.AttachTCXEgress,
			policyDirection: model.DirectionEgress,
			programs:        targetPrograms,
		})
	}
	return targets, nil
}

func tcxInterfaceProgram(program policy.Program) policy.Program {
	cloned := program
	cloned.EndpointIP = netip.Addr{}
	return cloned
}

func tcxEligibleProgram(program policy.Program) bool {
	return tcxEligibleProgramForDirection(program, model.DirectionIngress) ||
		tcxEligibleProgramForDirection(program, model.DirectionEgress)
}

func tcxEligibleProgramForDirection(program policy.Program, direction model.Direction) bool {
	if _, err := dataplane.IPv4L4ACLRulesFromProgramForDirection(program, direction); err == nil {
		return true
	}
	_, err := dataplane.IPv6L4ACLRulesFromProgramForDirection(program, direction)
	return err == nil
}

func attachTCXTargets(ctx context.Context, targets []tcxTarget, hold time.Duration) (string, tcxUpdateStats, []dataplane.RuleMetrics, error) {
	if len(targets) == 0 {
		return "not-attached", tcxUpdateStats{}, nil, nil
	}
	stats := tcxUpdateStats{}
	attachments := make([]tcxAttachmentHandle, 0, len(targets))
	defer func() {
		for i := len(attachments) - 1; i >= 0; i-- {
			_ = attachments[i].close()
		}
	}()
	for _, target := range targets {
		stats.Attempted++
		attachment, err := attachTCXTarget(ctx, target)
		if err != nil {
			stats.Failed = 1
			stats.Rollbacks = len(attachments)
			stats.Target = tcxTargetLabel(target)
			stats.LastError = err.Error()
			return "", stats, nil, err
		}
		attachment = labelTCXAttachmentMetrics(attachment, tcxTelemetryEndpoint(target))
		attachments = append(attachments, attachment)
	}
	if hold > 0 {
		timer := time.NewTimer(hold)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			stats.Failed = 1
			stats.Rollbacks = len(attachments)
			stats.Target = "hold"
			stats.LastError = ctx.Err().Error()
			return "", stats, nil, ctx.Err()
		case <-timer.C:
		}
	}
	metrics, err := collectTCXRuleMetrics(ctx, attachments)
	if err != nil {
		stats.Failed = 1
		stats.Target = "metrics"
		stats.LastError = err.Error()
		return "", stats, nil, err
	}
	return formatTCXResult(attachments), stats, metrics, nil
}

func (r *Reconciler) syncTCXTargets(ctx context.Context, targets []tcxTarget) (string, tcxUpdateStats, []dataplane.RuleMetrics, error) {
	stats := tcxUpdateStats{}
	if len(targets) == 0 {
		if err := r.closeTCXAttachments(); err != nil {
			stats.Failed = 1
			stats.Target = "stale"
			stats.LastError = err.Error()
			return "", stats, nil, fmt.Errorf("close stale tcx attachments: %w", err)
		}
		return "not-attached", stats, nil, nil
	}
	desired := make(map[string]tcxTarget, len(targets))
	for _, target := range targets {
		desired[tcxTargetKey(target)] = target
	}
	next := make(map[string]tcxAttachmentHandle, len(desired))
	attached := make([]string, 0, len(targets))
	for key, target := range desired {
		signature := tcxTargetSignature(target)
		old, hasOld := r.attachments[key]
		if hasOld && old.signature == signature {
			next[key] = old
			stats.Reused++
			continue
		}
		stats.Attempted++
		attachment, err := r.attach(ctx, target)
		if err != nil {
			for i := len(attached) - 1; i >= 0; i-- {
				stale := attached[i]
				_ = next[stale].close()
			}
			stats.Failed = 1
			stats.Rollbacks = len(attached)
			stats.Target = tcxTargetLabel(target)
			stats.LastError = err.Error()
			return "", stats, nil, fmt.Errorf("attach tcx target %s: %w", tcxTargetLabel(target), err)
		}
		attachment = labelTCXAttachmentMetrics(attachment, tcxTelemetryEndpoint(target))
		attachment.signature = signature
		next[key] = attachment
		attached = append(attached, key)
	}
	var closeErr error
	for key, attachment := range r.attachments {
		if _, ok := next[key]; ok {
			continue
		}
		stats.Detached++
		if err := attachment.close(); err != nil && closeErr == nil {
			closeErr = fmt.Errorf("close stale tcx attachment %s: %w", key, err)
		}
	}
	if closeErr != nil {
		for _, attachment := range next {
			_ = attachment.close()
		}
		stats.Failed = 1
		stats.Rollbacks = len(attached)
		stats.Target = "stale"
		stats.LastError = closeErr.Error()
		return "", stats, nil, closeErr
	}
	r.attachments = next
	attachments := make([]tcxAttachmentHandle, 0, len(targets))
	for _, target := range targets {
		attachments = append(attachments, r.attachments[tcxTargetKey(target)])
	}
	metrics, err := collectTCXRuleMetrics(ctx, attachments)
	if err != nil {
		stats.Failed = 1
		stats.Target = "metrics"
		stats.LastError = err.Error()
		return "", stats, nil, err
	}
	return formatTCXResult(attachments), stats, metrics, nil
}

func applyTCXUpdateStats(result *ReconcileResult, stats tcxUpdateStats) {
	if result == nil {
		return
	}
	result.TCXFailed += stats.Failed
	result.TCXRollbacks += stats.Rollbacks
	if stats.Target != "" {
		result.TCXFailedTarget = stats.Target
	}
	if stats.LastError != "" {
		result.TCXLastError = stats.LastError
	}
}

func (r *Reconciler) closeTCXAttachments() error {
	var firstErr error
	for key, attachment := range r.attachments {
		if err := attachment.close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close tcx attachment %s: %w", key, err)
		}
		delete(r.attachments, key)
	}
	return firstErr
}

func attachTCXTarget(ctx context.Context, target tcxTarget) (tcxAttachmentHandle, error) {
	attachment, err := dataplane.AttachTCXL4ProgramsForDirection(ctx, target.ifName, target.programs, target.attach, target.policyDirection)
	if err != nil {
		return tcxAttachmentHandle{}, fmt.Errorf("attach tcx target %s: %w", tcxTargetLabel(target), err)
	}
	return tcxAttachmentHandle{
		result: attachment.Result,
		close:  attachment.Close,
		metrics: func(ctx context.Context) ([]dataplane.RuleMetrics, error) {
			return attachment.PolicyRuleMetrics(ctx)
		},
	}, nil
}

func labelTCXAttachmentMetrics(attachment tcxAttachmentHandle, endpointID string) tcxAttachmentHandle {
	if attachment.metrics == nil {
		return attachment
	}
	read := attachment.metrics
	attachment.metrics = func(ctx context.Context) ([]dataplane.RuleMetrics, error) {
		metrics, err := read(ctx)
		if err != nil {
			return nil, err
		}
		return labelTCXRuleMetrics(metrics, endpointID), nil
	}
	return attachment
}

func collectTCXRuleMetrics(ctx context.Context, attachments []tcxAttachmentHandle) ([]dataplane.RuleMetrics, error) {
	out := make([]dataplane.RuleMetrics, 0)
	for _, attachment := range attachments {
		if attachment.metrics == nil {
			continue
		}
		metrics, err := attachment.metrics(ctx)
		if err != nil {
			return nil, fmt.Errorf("read tcx policy counters: %w", err)
		}
		out = append(out, metrics...)
	}
	return out, nil
}

func labelTCXRuleMetrics(metrics []dataplane.RuleMetrics, endpointID string) []dataplane.RuleMetrics {
	out := append([]dataplane.RuleMetrics(nil), metrics...)
	for i := range out {
		if out[i].EndpointID == "" {
			out[i].EndpointID = endpointID
		}
	}
	return out
}

func tcxTelemetryEndpoint(target tcxTarget) string {
	if len(target.programs) == 1 && target.programs[0].EndpointID != "" {
		return target.programs[0].EndpointID
	}
	return "tcx:" + tcxTargetLabel(target)
}

func tcxTargetKey(target tcxTarget) string {
	return fmt.Sprintf("%s/%d/%s", target.ifName, target.attach, target.policyDirection)
}

func tcxTargetSignature(target tcxTarget) string {
	return fmt.Sprintf("%s/%#v", tcxTargetKey(target), target.programs)
}

func tcxTargetLabel(target tcxTarget) string {
	return fmt.Sprintf("iface=%s direction=%s attach=%d", target.ifName, target.policyDirection, target.attach)
}

func formatTCXResult(attachments []tcxAttachmentHandle) string {
	first := attachments[0].result
	if len(attachments) == 1 {
		return fmt.Sprintf("attached:%s:%s:%s", first.Interface, first.Direction, first.Mode)
	}
	sameInterface := true
	direction := first.Direction
	mode := first.Mode
	for _, attachment := range attachments[1:] {
		if attachment.result.Interface != first.Interface {
			sameInterface = false
		}
		if attachment.result.Direction != direction {
			direction = "mixed"
		}
		if attachment.result.Mode != mode {
			mode = "mixed"
		}
	}
	if sameInterface {
		return fmt.Sprintf("attached:%s:%s:%s", first.Interface, direction, mode)
	}
	return fmt.Sprintf("attached-workloads:%d:%s:%s", len(attachments), direction, mode)
}
