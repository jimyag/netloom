package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
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
	PolicyMapPressureHotspots        []dataplane.PolicyMapPressureHotspot
	PolicyPressureMitigated          int
	PolicyPressureQuarantined        int
	PolicyPressureQuarantineEndpoint string
	PolicyRollouts                   int
	PolicyRolloutPlanned             int
	PolicyRolloutApplied             int
	PolicyRolloutSkipped             int
	PolicyRolloutFailed              int
	PolicyRolloutRolledBack          int
	PolicyRolloutRollbackFailed      int
	PolicyRolloutSLOFailed           int
	PolicyRolloutProbeFailed         int
	PolicyRolloutPaused              int
	PolicyRolloutCancelled           int
	PolicyRolloutStatus              []NamedPolicyEndpointRollout
	PolicyMapDriftEndpoints          int
	PolicyMapDriftMissing            int
	PolicyMapDriftExtra              int
	PolicyMapDriftChanged            int
	PolicyEndpointStatus             []dataplane.PolicyEndpointStatus
	PolicyGCEndpoints                int
	PolicyFrozen                     int
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
	PolicyRuleCatalog                []PolicyRuleCatalogEntry
	TCXFailed                        int
	TCXRollbacks                     int
	TCXFailedTarget                  string
	TCXLastError                     string
	ConntrackExpired                 int
	TCXEligible                      int
	TCXSkipped                       int
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

type PolicyRuleCatalogEntry struct {
	EndpointID    string `json:"endpoint_id"`
	RuleCookie    uint32 `json:"rule_cookie"`
	RuleRef       string `json:"rule_ref"`
	VPC           string `json:"vpc,omitempty"`
	SecurityGroup string `json:"security_group,omitempty"`
	RuleID        string `json:"rule_id,omitempty"`
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
	PolicyPressureQuarantineThreshold uint32
	PolicyPressureQuarantine          bool
	DeferPolicyApply                  bool
	FrozenPolicyEndpoints             map[string]struct{}
	PolicyRolloutApprovalSecret       string
	PolicyRolloutResume               map[string][]string
	LinuxDatapath                     *linuxdatapath.Options
	LinuxDatapathApply                func(context.Context, control.DesiredState, linuxdatapath.Options) (linuxdatapath.Result, error)
}

type PolicyMapPressureHotspot = dataplane.PolicyMapPressureHotspot

type PolicyEndpointPlan struct {
	EndpointID     string                      `json:"endpoint_id"`
	CurrentEntries int                         `json:"current_entries"`
	DesiredEntries int                         `json:"desired_entries"`
	Stats          dataplane.PolicyUpdateStats `json:"stats"`
	Changed        bool                        `json:"changed"`
}

type PolicyEndpointRolloutOptions struct {
	EndpointIDs               []string
	Revision                  string
	BatchSize                 int
	DryRun                    bool
	Cancelled                 bool
	PressureAware             bool
	PressureThresholdPercent  uint32
	PressureAwareMinBatchSize int
	SLOGated                  bool
	SLODropThresholdPercent   uint32
	SLOMinPackets             uint64
	SLOWindowCount            int
	SLOWindowInterval         time.Duration
	Probes                    []control.PolicyRolloutProbe
	ApprovalRequired          bool
	Approved                  bool
	ApprovalRef               string
	ApprovalSignature         string
	ApprovalExpiresAt         time.Time
	ApprovalCallbackURL       string
	ApprovalCallbackTimeout   time.Duration
	AckRequired               bool
	Acknowledged              bool
	AckRef                    string
	AckExpiresAt              time.Time
	FinalizeRequired          bool
	Finalized                 bool
	FinalizeRef               string
	FinalizeExpiresAt         time.Time
	ChangePollURL             string
	ChangePollTimeout         time.Duration
	ChangeStatusURL           string
	ChangeStatusTimeout       time.Duration
	ResumeAppliedEndpointIDs  []string
	Paused                    bool
	PauseAfterBatches         int
	PromotionPercent          uint32
}

type PolicyEndpointRollout struct {
	Revision                  string                      `json:"revision,omitempty"`
	DryRun                    bool                        `json:"dry_run"`
	Cancelled                 bool                        `json:"cancelled,omitempty"`
	BatchSize                 int                         `json:"batch_size"`
	RequestedBatchSize        int                         `json:"requested_batch_size,omitempty"`
	PressureAware             bool                        `json:"pressure_aware,omitempty"`
	PressureAdjusted          bool                        `json:"pressure_adjusted,omitempty"`
	PressureThresholdPercent  uint32                      `json:"pressure_threshold_percent,omitempty"`
	PressureMaxPercent        uint32                      `json:"pressure_max_percent,omitempty"`
	PressureEndpoint          string                      `json:"pressure_endpoint,omitempty"`
	PressureHotspots          []PolicyMapPressureHotspot  `json:"pressure_hotspots,omitempty"`
	SLOGated                  bool                        `json:"slo_gated,omitempty"`
	SLODropThresholdPercent   uint32                      `json:"slo_drop_threshold_percent,omitempty"`
	SLOMinPackets             uint64                      `json:"slo_min_packets,omitempty"`
	SLOWindowCount            int                         `json:"slo_window_count,omitempty"`
	SLOWindowIntervalMS       uint32                      `json:"slo_window_interval_ms,omitempty"`
	SLOPackets                uint64                      `json:"slo_packets,omitempty"`
	SLODropPercent            uint32                      `json:"slo_drop_percent,omitempty"`
	SLOFailed                 bool                        `json:"slo_failed,omitempty"`
	SLOError                  string                      `json:"slo_error,omitempty"`
	SLOWindows                []PolicyEndpointSLOWindow   `json:"slo_windows,omitempty"`
	ProbeFailed               bool                        `json:"probe_failed,omitempty"`
	ProbeError                string                      `json:"probe_error,omitempty"`
	Probes                    []PolicyEndpointProbeResult `json:"probes,omitempty"`
	ApprovalRequired          bool                        `json:"approval_required,omitempty"`
	Approved                  bool                        `json:"approved,omitempty"`
	ApprovalRef               string                      `json:"approval_ref,omitempty"`
	ApprovalSignatureVerified bool                        `json:"approval_signature_verified,omitempty"`
	ApprovalExpiresAt         string                      `json:"approval_expires_at,omitempty"`
	ApprovalExpired           bool                        `json:"approval_expired,omitempty"`
	ApprovalCallbackURL       string                      `json:"approval_callback_url,omitempty"`
	ApprovalCallbackApproved  bool                        `json:"approval_callback_approved,omitempty"`
	ApprovalCallbackError     string                      `json:"approval_callback_error,omitempty"`
	AckRequired               bool                        `json:"ack_required,omitempty"`
	Acknowledged              bool                        `json:"acknowledged,omitempty"`
	AckRef                    string                      `json:"ack_ref,omitempty"`
	AckExpiresAt              string                      `json:"ack_expires_at,omitempty"`
	AckExpired                bool                        `json:"ack_expired,omitempty"`
	AckPending                bool                        `json:"ack_pending,omitempty"`
	FinalizeRequired          bool                        `json:"finalize_required,omitempty"`
	Finalized                 bool                        `json:"finalized,omitempty"`
	FinalizeRef               string                      `json:"finalize_ref,omitempty"`
	FinalizeExpiresAt         string                      `json:"finalize_expires_at,omitempty"`
	FinalizeExpired           bool                        `json:"finalize_expired,omitempty"`
	FinalizePending           bool                        `json:"finalize_pending,omitempty"`
	ChangePollURL             string                      `json:"change_poll_url,omitempty"`
	ChangePollAllowed         bool                        `json:"change_poll_allowed,omitempty"`
	ChangePollStatus          string                      `json:"change_poll_status,omitempty"`
	ChangePollError           string                      `json:"change_poll_error,omitempty"`
	ChangeStatusURL           string                      `json:"change_status_url,omitempty"`
	ChangeStatusSynced        bool                        `json:"change_status_synced,omitempty"`
	ChangeStatusError         string                      `json:"change_status_error,omitempty"`
	ExternalChangeStatus      string                      `json:"external_change_status,omitempty"`
	ExternalChangeURL         string                      `json:"external_change_url,omitempty"`
	ApprovalPending           bool                        `json:"approval_pending,omitempty"`
	Paused                    bool                        `json:"paused,omitempty"`
	PauseAfterBatches         int                         `json:"pause_after_batches,omitempty"`
	PausedAfterBatch          int                         `json:"paused_after_batch,omitempty"`
	PromotionPercent          uint32                      `json:"promotion_percent,omitempty"`
	PromotionLimit            int                         `json:"promotion_limit,omitempty"`
	ResumedApplied            int                         `json:"resumed_applied,omitempty"`
	Planned                   int                         `json:"planned"`
	Applied                   int                         `json:"applied"`
	Skipped                   int                         `json:"skipped"`
	Failed                    int                         `json:"failed"`
	RolledBack                int                         `json:"rolled_back,omitempty"`
	RollbackFailed            int                         `json:"rollback_failed,omitempty"`
	Items                     []PolicyEndpointRolloutItem `json:"items"`
}

type PolicyEndpointSLOWindow struct {
	Index       int    `json:"index"`
	Packets     uint64 `json:"packets"`
	Drops       uint64 `json:"drops"`
	DropPercent uint32 `json:"drop_percent"`
	Passed      bool   `json:"passed"`
	Reason      string `json:"reason,omitempty"`
}

type PolicyEndpointProbeResult struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Target     string `json:"target"`
	Passed     bool   `json:"passed"`
	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}

type PolicyEndpointRolloutItem struct {
	EndpointID string                         `json:"endpoint_id"`
	Batch      int                            `json:"batch"`
	Phase      string                         `json:"phase"`
	Reason     string                         `json:"reason,omitempty"`
	Plan       PolicyEndpointPlan             `json:"plan"`
	Status     dataplane.PolicyEndpointStatus `json:"endpoint_status,omitempty"`
	Error      string                         `json:"error,omitempty"`
}

type NamedPolicyEndpointRollout struct {
	Name    string                `json:"name"`
	Rollout PolicyEndpointRollout `json:"rollout"`
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
	if policyEndpointFrozen(options, endpointID) {
		return dataplane.PolicyEndpointStatus{}, fmt.Errorf("policy endpoint %s is frozen", endpointID)
	}
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
	if policyEndpointFrozen(options, endpointID) {
		return PolicyEndpointPlan{}, fmt.Errorf("policy endpoint %s is frozen", endpointID)
	}
	program, err := compileEndpointPolicyProgram(state, options, endpointID)
	if err != nil {
		return PolicyEndpointPlan{}, err
	}
	desired, err := dataplane.EncodeProgram(program)
	if err != nil {
		return PolicyEndpointPlan{}, err
	}
	return planPolicyEndpointEntries(endpointID, desired, options.Store)
}

func RolloutPolicyEndpoints(ctx context.Context, state control.DesiredState, options ReconcileOptions, rolloutOptions PolicyEndpointRolloutOptions) (PolicyEndpointRollout, error) {
	if options.Store == nil {
		return PolicyEndpointRollout{}, fmt.Errorf("policy store is required")
	}
	endpointIDs, err := rolloutPolicyEndpointIDs(state, options, rolloutOptions.EndpointIDs)
	if err != nil {
		return PolicyEndpointRollout{}, err
	}
	requestedBatchSize := normalizedRolloutBatchSize(rolloutOptions.BatchSize)
	batchSize, pressure, err := pressureAwareRolloutBatchSize(ctx, options.Store, requestedBatchSize, rolloutOptions)
	if err != nil {
		return PolicyEndpointRollout{}, err
	}
	rollout := PolicyEndpointRollout{
		Revision:                 rolloutOptions.Revision,
		DryRun:                   rolloutOptions.DryRun,
		Cancelled:                rolloutOptions.Cancelled,
		BatchSize:                batchSize,
		RequestedBatchSize:       requestedBatchSize,
		PressureAware:            rolloutOptions.PressureAware,
		PressureAdjusted:         batchSize != requestedBatchSize,
		PressureThresholdPercent: pressure.threshold,
		PressureMaxPercent:       pressure.maxPercent,
		PressureEndpoint:         pressure.endpointID,
		PressureHotspots:         append([]PolicyMapPressureHotspot(nil), pressure.hotspots...),
		SLOGated:                 rolloutOptions.SLOGated,
		SLODropThresholdPercent:  rolloutOptions.SLODropThresholdPercent,
		SLOMinPackets:            rolloutOptions.SLOMinPackets,
		SLOWindowCount:           normalizedSLOWindowCount(rolloutOptions.SLOWindowCount),
		SLOWindowIntervalMS:      uint32(rolloutOptions.SLOWindowInterval / time.Millisecond),
		ApprovalRequired:         rolloutOptions.ApprovalRequired,
		Approved:                 rolloutOptions.Approved,
		ApprovalRef:              rolloutOptions.ApprovalRef,
		ApprovalExpiresAt:        rolloutExpiryString(rolloutOptions.ApprovalExpiresAt),
		ApprovalCallbackURL:      rolloutOptions.ApprovalCallbackURL,
		AckRequired:              rolloutOptions.AckRequired,
		Acknowledged:             rolloutOptions.Acknowledged,
		AckRef:                   rolloutOptions.AckRef,
		AckExpiresAt:             rolloutExpiryString(rolloutOptions.AckExpiresAt),
		FinalizeRequired:         rolloutOptions.FinalizeRequired,
		Finalized:                rolloutOptions.Finalized,
		FinalizeRef:              rolloutOptions.FinalizeRef,
		FinalizeExpiresAt:        rolloutExpiryString(rolloutOptions.FinalizeExpiresAt),
		ChangePollURL:            rolloutOptions.ChangePollURL,
		ChangeStatusURL:          rolloutOptions.ChangeStatusURL,
		Paused:                   rolloutOptions.Paused,
		PauseAfterBatches:        rolloutOptions.PauseAfterBatches,
		PromotionPercent:         rolloutOptions.PromotionPercent,
		PromotionLimit:           rolloutPromotionLimit(len(endpointIDs), rolloutOptions.PromotionPercent),
		Items:                    make([]PolicyEndpointRolloutItem, 0, len(endpointIDs)),
	}
	type preparedEndpoint struct {
		program policy.Program
		plan    PolicyEndpointPlan
	}
	prepared := make([]preparedEndpoint, 0, len(endpointIDs))
	for i, endpointID := range endpointIDs {
		program, err := compileEndpointPolicyProgram(state, options, endpointID)
		if err != nil {
			return PolicyEndpointRollout{}, err
		}
		desired, err := dataplane.EncodeProgram(program)
		if err != nil {
			return PolicyEndpointRollout{}, err
		}
		plan, err := planPolicyEndpointEntries(endpointID, desired, options.Store)
		if err != nil {
			return PolicyEndpointRollout{}, err
		}
		prepared = append(prepared, preparedEndpoint{program: program, plan: plan})
		rollout.Planned++
		rollout.Items = append(rollout.Items, PolicyEndpointRolloutItem{
			EndpointID: endpointID,
			Batch:      rolloutBatch(i, batchSize),
			Phase:      "planned",
			Plan:       plan,
		})
	}
	if rolloutOptions.DryRun {
		failFrozenDryRunRolloutItems(options, &rollout)
		return rollout, nil
	}
	if rolloutOptions.Cancelled {
		cancelRolloutItems(&rollout)
		return syncPolicyRolloutChangeStatus(ctx, rolloutOptions, endpointIDs, rollout), nil
	}
	now := time.Now().UTC()
	if rolloutOptions.ApprovalRequired && rolloutExpired(rolloutOptions.ApprovalExpiresAt, now) {
		rollout.ApprovalExpired = true
		pauseRolloutItems(&rollout, 0, "approval_expired")
		return syncPolicyRolloutChangeStatus(ctx, rolloutOptions, endpointIDs, rollout), nil
	}
	if rolloutOptions.ApprovalRequired && !rolloutOptions.Approved {
		rollout.ApprovalPending = true
		pauseRolloutItems(&rollout, 0, "approval_pending")
		return syncPolicyRolloutChangeStatus(ctx, rolloutOptions, endpointIDs, rollout), nil
	}
	if rolloutOptions.ApprovalRequired && rolloutOptions.Approved {
		verified, err := verifyPolicyRolloutApprovalSignature(options.PolicyRolloutApprovalSecret, rolloutOptions.ApprovalSignature, rolloutOptions.ApprovalRef, endpointIDs)
		if err != nil {
			return rollout, err
		}
		rollout.ApprovalSignatureVerified = verified
		if strings.TrimSpace(rolloutOptions.ApprovalCallbackURL) != "" {
			approved, err := requestPolicyRolloutApproval(ctx, rolloutOptions, endpointIDs)
			if err != nil {
				rollout.ApprovalCallbackError = err.Error()
				rollout.ApprovalPending = true
				pauseRolloutItems(&rollout, 0, "approval_callback_error")
				return syncPolicyRolloutChangeStatus(ctx, rolloutOptions, endpointIDs, rollout), nil
			}
			if !approved {
				rollout.ApprovalCallbackError = "approval callback rejected rollout"
				rollout.ApprovalPending = true
				pauseRolloutItems(&rollout, 0, "approval_callback_rejected")
				return syncPolicyRolloutChangeStatus(ctx, rolloutOptions, endpointIDs, rollout), nil
			}
			rollout.ApprovalCallbackApproved = true
		}
	}
	if strings.TrimSpace(rolloutOptions.ChangePollURL) != "" {
		allowed, status, externalURL, err := pollPolicyRolloutChangeStatus(ctx, rolloutOptions, endpointIDs)
		rollout.ChangePollStatus = status
		rollout.ExternalChangeURL = externalURL
		if err != nil {
			rollout.ChangePollError = err.Error()
			rollout.ApprovalPending = true
			pauseRolloutItems(&rollout, 0, "change_poll_error")
			return syncPolicyRolloutChangeStatus(ctx, rolloutOptions, endpointIDs, rollout), nil
		}
		if !allowed {
			if status == "" {
				status = "not_allowed"
			}
			rollout.ChangePollStatus = status
			rollout.ChangePollError = "external change status is " + status
			rollout.ApprovalPending = true
			pauseRolloutItems(&rollout, 0, "change_poll_rejected")
			return syncPolicyRolloutChangeStatus(ctx, rolloutOptions, endpointIDs, rollout), nil
		}
		rollout.ChangePollAllowed = true
	}
	if rolloutOptions.AckRequired && rolloutExpired(rolloutOptions.AckExpiresAt, now) {
		rollout.AckExpired = true
		pauseRolloutItems(&rollout, 0, "ack_expired")
		return syncPolicyRolloutChangeStatus(ctx, rolloutOptions, endpointIDs, rollout), nil
	}
	if rolloutOptions.AckRequired && !rolloutOptions.Acknowledged {
		rollout.AckPending = true
		pauseRolloutItems(&rollout, 0, "ack_pending")
		return syncPolicyRolloutChangeStatus(ctx, rolloutOptions, endpointIDs, rollout), nil
	}
	if rolloutOptions.FinalizeRequired && rolloutExpired(rolloutOptions.FinalizeExpiresAt, now) {
		rollout.FinalizeExpired = true
		pauseRolloutItems(&rollout, 0, "finalize_expired")
		return syncPolicyRolloutChangeStatus(ctx, rolloutOptions, endpointIDs, rollout), nil
	}
	if rolloutOptions.Paused {
		pauseRolloutItems(&rollout, 0, "operator_paused")
		return syncPolicyRolloutChangeStatus(ctx, rolloutOptions, endpointIDs, rollout), nil
	}
	snapshots, err := snapshotRolloutPolicyEndpoints(ctx, options.Store, endpointIDs)
	if err != nil {
		return PolicyEndpointRollout{}, err
	}
	var sloBaseline []dataplane.RuleMetrics
	if rolloutOptions.SLOGated && normalizedSLOWindowCount(rolloutOptions.SLOWindowCount) > 1 {
		sloBaseline, err = rolloutSLOMetrics(ctx, options)
		if err != nil {
			return PolicyEndpointRollout{}, err
		}
	}
	backend := dataplane.NewPolicyBackend(options.Store)
	applied := make([]string, 0, len(rollout.Items))
	resumedApplied := stringSet(rolloutOptions.ResumeAppliedEndpointIDs)
	completedBatches := 0
	pauseReason := ""
	for i, item := range rollout.Items {
		if rollout.Failed != 0 {
			setRolloutItemPhase(&item, "skipped", "rollout_failed")
			rollout.Skipped++
			rollout.Items[i] = item
			continue
		}
		if rollout.Paused {
			setRolloutItemPhase(&item, "paused", nonEmptyString(pauseReason, "paused"))
			rollout.Skipped++
			rollout.Items[i] = item
			continue
		}
		resumeRequested := false
		if _, ok := resumedApplied[item.EndpointID]; ok {
			resumeRequested = true
		}
		if resumeRequested && !item.Plan.Changed {
			setRolloutItemPhase(&item, "resumed_applied", "resumed_applied")
			rollout.Applied++
			rollout.ResumedApplied++
			if status, ok, err := policyEndpointStatus(ctx, options.Store, item.EndpointID); err != nil {
				return PolicyEndpointRollout{}, fmt.Errorf("read resumed rolled out policy endpoint status: %w", err)
			} else if ok {
				item.Status = status
			}
			rollout.Items[i] = item
			if rolloutBatchComplete(rollout.Items, i) {
				completedBatches++
				if shouldPauseRolloutAfterItem(rollout, rolloutOptions, completedBatches, i) {
					rollout.Paused = true
					rollout.PausedAfterBatch = item.Batch
					pauseReason = rolloutPauseReason(rollout, rolloutOptions, completedBatches)
					if pauseReason == "finalize_pending" {
						rollout.FinalizePending = true
					}
				}
			}
			continue
		}
		if policyEndpointFrozen(options, item.EndpointID) {
			setRolloutItemPhase(&item, "failed", "policy_frozen")
			item.Error = "policy endpoint is frozen"
			rollout.Failed++
			rollout.Items[i] = item
			rollbackRolloutPolicyEndpoints(ctx, options.Store, snapshots, applied, &rollout)
			continue
		}
		if err := backend.ApplyEndpointProgram(ctx, prepared[i].program); err != nil {
			setRolloutItemPhase(&item, "failed", "apply_failed")
			item.Error = err.Error()
			rollout.Failed++
			rollout.Items[i] = item
			rollbackRolloutPolicyEndpoints(ctx, options.Store, snapshots, applied, &rollout)
			continue
		}
		if resumeRequested {
			setRolloutItemPhase(&item, "applied", "resume_drift_reapplied")
		} else {
			setRolloutItemPhase(&item, "applied", "")
		}
		rollout.Applied++
		applied = append(applied, item.EndpointID)
		if status, ok, err := policyEndpointStatus(ctx, options.Store, item.EndpointID); err != nil {
			return PolicyEndpointRollout{}, fmt.Errorf("read rolled out policy endpoint status: %w", err)
		} else if ok {
			item.Status = status
		} else {
			item.Status = dataplane.PolicyEndpointStatus{
				EndpointID: item.EndpointID,
				Entries:    uint32(item.Plan.DesiredEntries),
			}
		}
		rollout.Items[i] = item
		if rolloutOptions.SLOGated && rolloutBatchComplete(rollout.Items, i) {
			failed, nextBaseline, err := evaluateRolloutSLO(ctx, options, applied, rolloutOptions, sloBaseline, &rollout)
			if err != nil {
				return PolicyEndpointRollout{}, err
			}
			sloBaseline = nextBaseline
			if failed {
				rollout.Failed++
				setRolloutAppliedItemsReason(&rollout, applied, "slo_failed")
				rollbackRolloutPolicyEndpoints(ctx, options.Store, snapshots, applied, &rollout)
			}
		}
		if rollout.Failed == 0 && len(rolloutOptions.Probes) != 0 && rolloutBatchComplete(rollout.Items, i) {
			failed := evaluateRolloutProbes(ctx, rolloutOptions, &rollout)
			if failed {
				rollout.Failed++
				setRolloutAppliedItemsReason(&rollout, applied, "probe_failed")
				rollbackRolloutPolicyEndpoints(ctx, options.Store, snapshots, applied, &rollout)
			}
		}
		if rollout.Failed == 0 && rolloutBatchComplete(rollout.Items, i) {
			completedBatches++
			if shouldPauseRolloutAfterItem(rollout, rolloutOptions, completedBatches, i) {
				rollout.Paused = true
				rollout.PausedAfterBatch = item.Batch
				pauseReason = rolloutPauseReason(rollout, rolloutOptions, completedBatches)
				if pauseReason == "finalize_pending" {
					rollout.FinalizePending = true
				}
			}
		}
	}
	return syncPolicyRolloutChangeStatus(ctx, rolloutOptions, endpointIDs, rollout), nil
}

func PolicyRolloutApprovalSignature(secret, approvalRef string, endpointIDs []string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(policyRolloutApprovalPayload(approvalRef, endpointIDs)))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func rolloutExpiryString(expiresAt time.Time) string {
	if expiresAt.IsZero() {
		return ""
	}
	return expiresAt.UTC().Format(time.RFC3339)
}

func rolloutExpired(expiresAt, now time.Time) bool {
	return !expiresAt.IsZero() && !now.Before(expiresAt.UTC())
}

func verifyPolicyRolloutApprovalSignature(secret, signature, approvalRef string, endpointIDs []string) (bool, error) {
	if strings.TrimSpace(secret) == "" {
		return false, nil
	}
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return false, fmt.Errorf("policy rollout approval signature is required when approval secret is configured")
	}
	expected := PolicyRolloutApprovalSignature(secret, approvalRef, endpointIDs)
	if !hmac.Equal([]byte(strings.TrimPrefix(signature, "sha256=")), []byte(strings.TrimPrefix(expected, "sha256="))) {
		return false, fmt.Errorf("policy rollout approval signature is invalid")
	}
	return true, nil
}

type policyRolloutApprovalCallbackRequest struct {
	ApprovalRef string   `json:"approval_ref,omitempty"`
	Revision    string   `json:"revision,omitempty"`
	Endpoints   []string `json:"endpoints"`
}

type policyRolloutApprovalCallbackResponse struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason,omitempty"`
}

type policyRolloutChangeStatusRequest struct {
	ApprovalRef     string   `json:"approval_ref,omitempty"`
	AckRef          string   `json:"ack_ref,omitempty"`
	Revision        string   `json:"revision,omitempty"`
	Status          string   `json:"status"`
	Endpoints       []string `json:"endpoints"`
	Planned         int      `json:"planned"`
	Applied         int      `json:"applied"`
	Skipped         int      `json:"skipped"`
	Failed          int      `json:"failed"`
	RolledBack      int      `json:"rolled_back,omitempty"`
	RollbackFailed  int      `json:"rollback_failed,omitempty"`
	Paused          bool     `json:"paused,omitempty"`
	Cancelled       bool     `json:"cancelled,omitempty"`
	ApprovalPending bool     `json:"approval_pending,omitempty"`
	AckPending      bool     `json:"ack_pending,omitempty"`
	SLOFailed       bool     `json:"slo_failed,omitempty"`
	ProbeFailed     bool     `json:"probe_failed,omitempty"`
}

type policyRolloutChangeStatusResponse struct {
	Synced *bool  `json:"synced,omitempty"`
	Status string `json:"status,omitempty"`
	URL    string `json:"url,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type policyRolloutChangePollRequest struct {
	ApprovalRef string   `json:"approval_ref,omitempty"`
	Revision    string   `json:"revision,omitempty"`
	Endpoints   []string `json:"endpoints"`
}

type policyRolloutChangePollResponse struct {
	Allowed *bool  `json:"allowed,omitempty"`
	Status  string `json:"status,omitempty"`
	URL     string `json:"url,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func requestPolicyRolloutApproval(ctx context.Context, options PolicyEndpointRolloutOptions, endpointIDs []string) (bool, error) {
	callbackURL := strings.TrimSpace(options.ApprovalCallbackURL)
	if callbackURL == "" {
		return false, fmt.Errorf("policy rollout approval callback url is required")
	}
	timeout := options.ApprovalCallbackTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	callbackCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	payload := policyRolloutApprovalCallbackRequest{
		ApprovalRef: options.ApprovalRef,
		Revision:    options.Revision,
		Endpoints:   append([]string(nil), endpointIDs...),
	}
	sort.Strings(payload.Endpoints)
	raw, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	request, err := http.NewRequestWithContext(callbackCtx, http.MethodPost, callbackURL, bytes.NewReader(raw))
	if err != nil {
		return false, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false, fmt.Errorf("approval callback returned status %d", response.StatusCode)
	}
	var out policyRolloutApprovalCallbackResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		return false, fmt.Errorf("decode approval callback response: %w", err)
	}
	if !out.Approved && strings.TrimSpace(out.Reason) != "" {
		return false, fmt.Errorf("approval callback rejected rollout: %s", strings.TrimSpace(out.Reason))
	}
	return out.Approved, nil
}

func pollPolicyRolloutChangeStatus(ctx context.Context, options PolicyEndpointRolloutOptions, endpointIDs []string) (bool, string, string, error) {
	pollURL := strings.TrimSpace(options.ChangePollURL)
	if pollURL == "" {
		return false, "", "", fmt.Errorf("policy rollout change poll url is required")
	}
	timeout := options.ChangePollTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	callbackCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	payload := policyRolloutChangePollRequest{
		ApprovalRef: options.ApprovalRef,
		Revision:    options.Revision,
		Endpoints:   append([]string(nil), endpointIDs...),
	}
	sort.Strings(payload.Endpoints)
	raw, err := json.Marshal(payload)
	if err != nil {
		return false, "", "", err
	}
	request, err := http.NewRequestWithContext(callbackCtx, http.MethodPost, pollURL, bytes.NewReader(raw))
	if err != nil {
		return false, "", "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return false, "", "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false, "", "", fmt.Errorf("change poll callback returned status %d", response.StatusCode)
	}
	var out policyRolloutChangePollResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		return false, "", "", fmt.Errorf("decode change poll callback response: %w", err)
	}
	status := strings.TrimSpace(out.Status)
	externalURL := strings.TrimSpace(out.URL)
	if out.Allowed != nil {
		if !*out.Allowed && strings.TrimSpace(out.Reason) != "" {
			return false, status, externalURL, fmt.Errorf("change poll callback rejected rollout: %s", strings.TrimSpace(out.Reason))
		}
		return *out.Allowed, status, externalURL, nil
	}
	return policyRolloutChangeStatusAllowsApply(status), status, externalURL, nil
}

func policyRolloutChangeStatusAllowsApply(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "approved", "open", "ready", "scheduled", "implementing", "in_progress":
		return true
	default:
		return false
	}
}

func syncPolicyRolloutChangeStatus(ctx context.Context, options PolicyEndpointRolloutOptions, endpointIDs []string, rollout PolicyEndpointRollout) PolicyEndpointRollout {
	changeStatusURL := strings.TrimSpace(options.ChangeStatusURL)
	if rollout.DryRun || changeStatusURL == "" {
		return rollout
	}
	rollout.ChangeStatusURL = changeStatusURL
	status, externalStatus, externalURL, err := postPolicyRolloutChangeStatus(ctx, options, endpointIDs, rollout)
	if err != nil {
		rollout.ChangeStatusError = err.Error()
		return rollout
	}
	rollout.ChangeStatusSynced = true
	if externalStatus != "" {
		rollout.ExternalChangeStatus = externalStatus
	} else {
		rollout.ExternalChangeStatus = status
	}
	rollout.ExternalChangeURL = externalURL
	return rollout
}

func postPolicyRolloutChangeStatus(ctx context.Context, options PolicyEndpointRolloutOptions, endpointIDs []string, rollout PolicyEndpointRollout) (string, string, string, error) {
	timeout := options.ChangeStatusTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	callbackCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	status := policyRolloutChangeStatus(rollout)
	payload := policyRolloutChangeStatusRequest{
		ApprovalRef:     rollout.ApprovalRef,
		AckRef:          rollout.AckRef,
		Revision:        rollout.Revision,
		Status:          status,
		Endpoints:       append([]string(nil), endpointIDs...),
		Planned:         rollout.Planned,
		Applied:         rollout.Applied,
		Skipped:         rollout.Skipped,
		Failed:          rollout.Failed,
		RolledBack:      rollout.RolledBack,
		RollbackFailed:  rollout.RollbackFailed,
		Paused:          rollout.Paused,
		Cancelled:       rollout.Cancelled,
		ApprovalPending: rollout.ApprovalPending,
		AckPending:      rollout.AckPending,
		SLOFailed:       rollout.SLOFailed,
		ProbeFailed:     rollout.ProbeFailed,
	}
	sort.Strings(payload.Endpoints)
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", "", "", err
	}
	request, err := http.NewRequestWithContext(callbackCtx, http.MethodPost, strings.TrimSpace(options.ChangeStatusURL), bytes.NewReader(raw))
	if err != nil {
		return "", "", "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", "", "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", "", "", fmt.Errorf("change status callback returned status %d", response.StatusCode)
	}
	if response.ContentLength == 0 {
		return status, "", "", nil
	}
	var out policyRolloutChangeStatusResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		if err == io.EOF {
			return status, "", "", nil
		}
		return "", "", "", fmt.Errorf("decode change status callback response: %w", err)
	}
	if out.Synced != nil && !*out.Synced {
		reason := strings.TrimSpace(out.Reason)
		if reason == "" {
			reason = "external change system rejected status update"
		}
		return "", "", "", fmt.Errorf("change status callback rejected update: %s", reason)
	}
	return status, strings.TrimSpace(out.Status), strings.TrimSpace(out.URL), nil
}

func policyRolloutChangeStatus(rollout PolicyEndpointRollout) string {
	switch {
	case rollout.Cancelled:
		return "cancelled"
	case rollout.AckPending:
		return "ack_pending"
	case rollout.FinalizeExpired:
		return "finalize_expired"
	case rollout.FinalizePending:
		return "finalize_pending"
	case rollout.ApprovalPending:
		return "approval_pending"
	case rollout.Failed > 0:
		return "failed"
	case rollout.Paused:
		return "paused"
	case rollout.Applied > 0:
		return "applied"
	default:
		return "planned"
	}
}

func policyRolloutApprovalPayload(approvalRef string, endpointIDs []string) string {
	endpoints := append([]string(nil), endpointIDs...)
	sort.Strings(endpoints)
	return "netloom-policy-rollout-approval-v1\napproval_ref=" + approvalRef + "\nendpoints=" + strings.Join(endpoints, ",")
}

func pauseRolloutItems(rollout *PolicyEndpointRollout, afterBatch int, reason string) {
	rollout.Paused = true
	rollout.PausedAfterBatch = afterBatch
	if reason == "finalize_pending" {
		rollout.FinalizePending = true
	}
	for i := range rollout.Items {
		if rollout.Items[i].Phase == "planned" {
			setRolloutItemPhase(&rollout.Items[i], "paused", reason)
			rollout.Skipped++
		}
	}
}

func cancelRolloutItems(rollout *PolicyEndpointRollout) {
	rollout.Cancelled = true
	for i := range rollout.Items {
		if rollout.Items[i].Phase == "planned" {
			setRolloutItemPhase(&rollout.Items[i], "cancelled", "operator_cancelled")
			rollout.Skipped++
		}
	}
}

func setRolloutItemPhase(item *PolicyEndpointRolloutItem, phase, reason string) {
	item.Phase = phase
	item.Reason = reason
}

func setRolloutAppliedItemsReason(rollout *PolicyEndpointRollout, endpointIDs []string, reason string) {
	ids := stringSet(endpointIDs)
	for i := range rollout.Items {
		if _, ok := ids[rollout.Items[i].EndpointID]; !ok {
			continue
		}
		if rollout.Items[i].Phase == "applied" {
			rollout.Items[i].Reason = reason
		}
	}
}

func rolloutPauseReason(rollout PolicyEndpointRollout, options PolicyEndpointRolloutOptions, completedBatches int) string {
	if options.FinalizeRequired && !options.Finalized && completedBatches > 0 {
		return "finalize_pending"
	}
	if options.PauseAfterBatches > 0 && completedBatches >= options.PauseAfterBatches {
		return "pause_after_batch"
	}
	if rollout.PromotionLimit > 0 && rollout.Applied >= rollout.PromotionLimit {
		return "promotion_limit"
	}
	return "paused"
}

func nonEmptyString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func shouldPauseRolloutAfterItem(rollout PolicyEndpointRollout, options PolicyEndpointRolloutOptions, completedBatches int, index int) bool {
	if index >= len(rollout.Items)-1 {
		return false
	}
	if options.FinalizeRequired && !options.Finalized && completedBatches > 0 {
		return true
	}
	if options.PauseAfterBatches > 0 && completedBatches >= options.PauseAfterBatches {
		return true
	}
	return rollout.PromotionLimit > 0 && rollout.Applied >= rollout.PromotionLimit
}

func rolloutPromotionLimit(endpointCount int, promotionPercent uint32) int {
	if endpointCount <= 0 || promotionPercent == 0 || promotionPercent >= 100 {
		return 0
	}
	limit := int((uint64(endpointCount)*uint64(promotionPercent) + 99) / 100)
	if limit < 1 {
		return 1
	}
	if limit > endpointCount {
		return endpointCount
	}
	return limit
}

func rolloutBatchComplete(items []PolicyEndpointRolloutItem, index int) bool {
	return index >= len(items)-1 || items[index+1].Batch != items[index].Batch
}

func evaluateRolloutSLO(ctx context.Context, options ReconcileOptions, applied []string, rolloutOptions PolicyEndpointRolloutOptions, baseline []dataplane.RuleMetrics, rollout *PolicyEndpointRollout) (bool, []dataplane.RuleMetrics, error) {
	windowCount := normalizedSLOWindowCount(rolloutOptions.SLOWindowCount)
	if windowCount > 1 {
		return evaluateRolloutSLOWindows(ctx, options, applied, rolloutOptions, baseline, rollout)
	}
	stats, err := rolloutSLOMetrics(ctx, options)
	if err != nil {
		return false, nil, err
	}
	packets, drops := rolloutSLOPackets(stats, applied)
	failed := applyRolloutSLOResult(packets, drops, rolloutOptions, rollout)
	return failed, stats, nil
}

func evaluateRolloutSLOWindows(ctx context.Context, options ReconcileOptions, applied []string, rolloutOptions PolicyEndpointRolloutOptions, baseline []dataplane.RuleMetrics, rollout *PolicyEndpointRollout) (bool, []dataplane.RuleMetrics, error) {
	previous := baseline
	var totalPackets, totalDrops uint64
	windowCount := normalizedSLOWindowCount(rolloutOptions.SLOWindowCount)
	for i := 0; i < windowCount; i++ {
		if i > 0 && rolloutOptions.SLOWindowInterval > 0 {
			if err := waitRolloutSLOWindow(ctx, rolloutOptions.SLOWindowInterval); err != nil {
				return false, previous, err
			}
		}
		stats, err := rolloutSLOMetrics(ctx, options)
		if err != nil {
			return false, previous, err
		}
		packets, drops := rolloutSLODeltaPackets(previous, stats, applied)
		totalPackets += packets
		totalDrops += drops
		dropPercent := percentUint64(drops, packets)
		window := PolicyEndpointSLOWindow{
			Index:       i + 1,
			Packets:     packets,
			Drops:       drops,
			DropPercent: dropPercent,
			Passed:      true,
			Reason:      "ok",
		}
		previous = stats
		if packets < rolloutOptions.SLOMinPackets {
			window.Reason = "insufficient_samples"
			rollout.SLOWindows = append(rollout.SLOWindows, window)
			continue
		}
		if dropPercent > rolloutOptions.SLODropThresholdPercent {
			window.Passed = false
			window.Reason = "drop_threshold_exceeded"
			rollout.SLOWindows = append(rollout.SLOWindows, window)
			rollout.SLOPackets = totalPackets
			rollout.SLODropPercent = percentUint64(totalDrops, totalPackets)
			rollout.SLOFailed = true
			rollout.SLOError = fmt.Sprintf("policy rollout SLO failed: window=%d drop_percent=%d threshold=%d packets=%d min_packets=%d", window.Index, dropPercent, rolloutOptions.SLODropThresholdPercent, packets, rolloutOptions.SLOMinPackets)
			return true, previous, nil
		}
		rollout.SLOWindows = append(rollout.SLOWindows, window)
	}
	rollout.SLOPackets = totalPackets
	rollout.SLODropPercent = percentUint64(totalDrops, totalPackets)
	return false, previous, nil
}

func rolloutSLOMetrics(ctx context.Context, options ReconcileOptions) ([]dataplane.RuleMetrics, error) {
	telemetry := options.PolicyTelemetry
	if telemetry == nil {
		var ok bool
		telemetry, ok = options.Store.(PolicyRuleMetricsStore)
		if !ok {
			return nil, fmt.Errorf("slo-gated policy rollout requires policy rule telemetry")
		}
	}
	stats, err := telemetry.PolicyRuleMetrics(ctx)
	if err != nil {
		return nil, fmt.Errorf("read policy rollout SLO metrics: %w", err)
	}
	return stats, nil
}

func waitRolloutSLOWindow(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func applyRolloutSLOResult(packets, drops uint64, rolloutOptions PolicyEndpointRolloutOptions, rollout *PolicyEndpointRollout) bool {
	dropPercent := percentUint64(drops, packets)
	rollout.SLOPackets = packets
	rollout.SLODropPercent = dropPercent
	if packets < rolloutOptions.SLOMinPackets {
		return false
	}
	if dropPercent <= rolloutOptions.SLODropThresholdPercent {
		return false
	}
	rollout.SLOFailed = true
	rollout.SLOError = fmt.Sprintf("policy rollout SLO failed: drop_percent=%d threshold=%d packets=%d min_packets=%d", dropPercent, rolloutOptions.SLODropThresholdPercent, packets, rolloutOptions.SLOMinPackets)
	return true
}

func normalizedSLOWindowCount(count int) int {
	if count < 1 {
		return 1
	}
	return count
}

func rolloutSLOPackets(stats []dataplane.RuleMetrics, endpointIDs []string) (uint64, uint64) {
	endpoints := make(map[string]struct{}, len(endpointIDs))
	for _, endpointID := range endpointIDs {
		endpoints[endpointID] = struct{}{}
	}
	var packets, drops uint64
	for _, stat := range stats {
		if _, ok := endpoints[stat.EndpointID]; !ok {
			continue
		}
		packets += stat.Packets
		drops += maxUint64(stat.Dropped, stat.Rejected)
	}
	return packets, drops
}

func rolloutSLODeltaPackets(previous, current []dataplane.RuleMetrics, endpointIDs []string) (uint64, uint64) {
	previousByRule := make(map[string]dataplane.RuleMetrics, len(previous))
	for _, stat := range previous {
		previousByRule[rolloutSLOMetricKey(stat)] = stat
	}
	endpoints := make(map[string]struct{}, len(endpointIDs))
	for _, endpointID := range endpointIDs {
		endpoints[endpointID] = struct{}{}
	}
	var packets, drops uint64
	for _, stat := range current {
		if _, ok := endpoints[stat.EndpointID]; !ok {
			continue
		}
		prev := previousByRule[rolloutSLOMetricKey(stat)]
		packets += saturatingCounterDelta(prev.Packets, stat.Packets)
		drops += saturatingCounterDelta(maxUint64(prev.Dropped, prev.Rejected), maxUint64(stat.Dropped, stat.Rejected))
	}
	return packets, drops
}

func rolloutSLOMetricKey(stat dataplane.RuleMetrics) string {
	return fmt.Sprintf("%s\x00%d", stat.EndpointID, stat.RuleCookie)
}

func saturatingCounterDelta(previous, current uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}

func evaluateRolloutProbes(ctx context.Context, rolloutOptions PolicyEndpointRolloutOptions, rollout *PolicyEndpointRollout) bool {
	for _, probe := range rolloutOptions.Probes {
		result := executeRolloutProbe(ctx, probe)
		rollout.Probes = append(rollout.Probes, result)
		if !result.Passed {
			rollout.ProbeFailed = true
			rollout.ProbeError = fmt.Sprintf("policy rollout probe %q failed: %s", result.Name, result.Error)
			return true
		}
	}
	return false
}

func executeRolloutProbe(ctx context.Context, probe control.PolicyRolloutProbe) PolicyEndpointProbeResult {
	timeout := rolloutProbeTimeout(probe.TimeoutMS)
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch strings.ToLower(strings.TrimSpace(probe.Type)) {
	case "http":
		return executeHTTPRolloutProbe(probeCtx, probe)
	case "tcp":
		return executeTCPRolloutProbe(probeCtx, probe)
	case "tls":
		return executeTLSRolloutProbe(probeCtx, probe)
	default:
		return PolicyEndpointProbeResult{Name: probe.Name, Type: probe.Type, Passed: false, Error: "unsupported probe type"}
	}
}

func executeHTTPRolloutProbe(ctx context.Context, probe control.PolicyRolloutProbe) PolicyEndpointProbeResult {
	method := strings.ToUpper(strings.TrimSpace(probe.Method))
	if method == "" {
		method = http.MethodGet
	}
	expectedStatus := probe.ExpectedStatus
	if expectedStatus == 0 {
		expectedStatus = http.StatusOK
	}
	result := PolicyEndpointProbeResult{
		Name:   probe.Name,
		Type:   "http",
		Target: probe.URL,
	}
	request, err := http.NewRequestWithContext(ctx, method, probe.URL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer response.Body.Close()
	result.StatusCode = response.StatusCode
	if response.StatusCode != expectedStatus {
		result.Error = fmt.Sprintf("status=%d expected=%d", response.StatusCode, expectedStatus)
		return result
	}
	if expectedBody := strings.TrimSpace(probe.ExpectedBodyContains); expectedBody != "" {
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			result.Error = err.Error()
			return result
		}
		if !strings.Contains(string(body), expectedBody) {
			result.Error = fmt.Sprintf("body missing %q", expectedBody)
			return result
		}
	}
	result.Passed = true
	return result
}

func executeTCPRolloutProbe(ctx context.Context, probe control.PolicyRolloutProbe) PolicyEndpointProbeResult {
	result := PolicyEndpointProbeResult{
		Name:   probe.Name,
		Type:   "tcp",
		Target: probe.Address,
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", probe.Address)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	_ = conn.Close()
	result.Passed = true
	return result
}

func executeTLSRolloutProbe(ctx context.Context, probe control.PolicyRolloutProbe) PolicyEndpointProbeResult {
	result := PolicyEndpointProbeResult{
		Name:   probe.Name,
		Type:   "tls",
		Target: probe.Address,
	}
	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, "tcp", probe.Address)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer rawConn.Close()
	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		result.Error = err.Error()
		return result
	}
	result.Passed = true
	return result
}

func rolloutProbeTimeout(timeoutMS uint32) time.Duration {
	if timeoutMS == 0 {
		return 2 * time.Second
	}
	return time.Duration(timeoutMS) * time.Millisecond
}

func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func percentUint64(part, total uint64) uint32 {
	if total == 0 {
		return 0
	}
	if part >= total {
		return 100
	}
	return uint32(float64(part) * 100 / float64(total))
}

type policyEndpointSnapshot struct {
	entries []dataplane.PolicyMapEntry
	exists  bool
}

func failFrozenDryRunRolloutItems(options ReconcileOptions, rollout *PolicyEndpointRollout) {
	for i := range rollout.Items {
		if !policyEndpointFrozen(options, rollout.Items[i].EndpointID) {
			continue
		}
		setRolloutItemPhase(&rollout.Items[i], "failed", "policy_frozen")
		rollout.Items[i].Error = "policy endpoint is frozen"
		rollout.Failed++
	}
}

func snapshotRolloutPolicyEndpoints(ctx context.Context, store PolicyStore, endpointIDs []string) (map[string]policyEndpointSnapshot, error) {
	entryStore, ok := store.(PolicyEndpointEntryStore)
	if !ok {
		return nil, fmt.Errorf("policy rollout requires a snapshot-capable policy store")
	}
	exists := make(map[string]struct{}, len(endpointIDs))
	if inventory, ok := store.(PolicyEndpointInventory); ok {
		ids, err := inventory.EndpointIDs(ctx)
		if err != nil {
			return nil, fmt.Errorf("snapshot policy rollout endpoint inventory: %w", err)
		}
		for _, endpointID := range ids {
			exists[endpointID] = struct{}{}
		}
	}
	snapshots := make(map[string]policyEndpointSnapshot, len(endpointIDs))
	for _, endpointID := range endpointIDs {
		_, existed := exists[endpointID]
		snapshots[endpointID] = policyEndpointSnapshot{
			entries: entryStore.Entries(endpointID),
			exists:  existed,
		}
	}
	return snapshots, nil
}

func rollbackRolloutPolicyEndpoints(ctx context.Context, store PolicyStore, snapshots map[string]policyEndpointSnapshot, applied []string, rollout *PolicyEndpointRollout) {
	for i := len(applied) - 1; i >= 0; i-- {
		endpointID := applied[i]
		snapshot := snapshots[endpointID]
		var err error
		if snapshot.exists {
			err = store.ReplaceEndpoint(ctx, endpointID, snapshot.entries)
		} else {
			err = store.DeleteEndpoint(ctx, endpointID)
		}
		itemIndex := rolloutPolicyEndpointItemIndex(rollout.Items, endpointID)
		if err != nil {
			rollout.RollbackFailed++
			if itemIndex >= 0 {
				setRolloutItemPhase(&rollout.Items[itemIndex], "rollback_failed", "rollback_failed")
				rollout.Items[itemIndex].Error = err.Error()
			}
			continue
		}
		rollout.RolledBack++
		if itemIndex >= 0 {
			setRolloutItemPhase(&rollout.Items[itemIndex], "rolled_back", nonEmptyString(rollout.Items[itemIndex].Reason, "rollback"))
		}
	}
}

func rolloutPolicyEndpointItemIndex(items []PolicyEndpointRolloutItem, endpointID string) int {
	for i := range items {
		if items[i].EndpointID == endpointID {
			return i
		}
	}
	return -1
}

func ApplyPolicyRollouts(ctx context.Context, state control.DesiredState, options ReconcileOptions) ([]NamedPolicyEndpointRollout, error) {
	rollouts := activePolicyRolloutsForNode(state.PolicyRollouts, options.Node)
	if len(rollouts) == 0 {
		return nil, nil
	}
	if options.Store == nil {
		return nil, fmt.Errorf("policy store is required")
	}
	out := make([]NamedPolicyEndpointRollout, 0, len(rollouts))
	for _, rollout := range rollouts {
		endpointIDs, err := rolloutEndpointIDs(state, rollout)
		if err != nil {
			return nil, fmt.Errorf("policy rollout %q: %w", rollout.Name, err)
		}
		approvalExpiresAt, err := parsePolicyRolloutTime(rollout.ApprovalExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("policy rollout %q approval_expires_at: %w", rollout.Name, err)
		}
		ackExpiresAt, err := parsePolicyRolloutTime(rollout.AckExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("policy rollout %q ack_expires_at: %w", rollout.Name, err)
		}
		finalizeExpiresAt, err := parsePolicyRolloutTime(rollout.FinalizeExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("policy rollout %q finalize_expires_at: %w", rollout.Name, err)
		}
		revision, err := PolicyRolloutRevision(state, rollout, endpointIDs)
		if err != nil {
			return nil, fmt.Errorf("policy rollout %q revision: %w", rollout.Name, err)
		}
		result, err := RolloutPolicyEndpoints(ctx, state, options, PolicyEndpointRolloutOptions{
			EndpointIDs:               endpointIDs,
			Revision:                  revision,
			BatchSize:                 rollout.BatchSize,
			DryRun:                    rollout.DryRun,
			Cancelled:                 rollout.Cancelled,
			PressureAware:             rollout.PressureAware,
			PressureThresholdPercent:  rollout.PressureThresholdPercent,
			PressureAwareMinBatchSize: rollout.PressureAwareMinBatchSize,
			SLOGated:                  rollout.SLOGated,
			SLODropThresholdPercent:   rollout.SLODropThresholdPercent,
			SLOMinPackets:             rollout.SLOMinPackets,
			SLOWindowCount:            rollout.SLOWindowCount,
			SLOWindowInterval:         time.Duration(rollout.SLOWindowIntervalMS) * time.Millisecond,
			Probes:                    append([]control.PolicyRolloutProbe(nil), rollout.Probes...),
			ApprovalRequired:          rollout.ApprovalRequired,
			Approved:                  rollout.Approved,
			ApprovalRef:               rollout.ApprovalRef,
			ApprovalSignature:         rollout.ApprovalSignature,
			ApprovalExpiresAt:         approvalExpiresAt,
			ApprovalCallbackURL:       rollout.ApprovalCallbackURL,
			ApprovalCallbackTimeout:   time.Duration(rollout.ApprovalCallbackTimeoutMS) * time.Millisecond,
			AckRequired:               rollout.AckRequired,
			Acknowledged:              rollout.Acknowledged,
			AckRef:                    rollout.AckRef,
			AckExpiresAt:              ackExpiresAt,
			FinalizeRequired:          rollout.FinalizeRequired,
			Finalized:                 rollout.Finalized,
			FinalizeRef:               rollout.FinalizeRef,
			FinalizeExpiresAt:         finalizeExpiresAt,
			ChangePollURL:             rollout.ChangePollURL,
			ChangePollTimeout:         time.Duration(rollout.ChangePollTimeoutMS) * time.Millisecond,
			ChangeStatusURL:           rollout.ChangeStatusURL,
			ChangeStatusTimeout:       time.Duration(rollout.ChangeStatusTimeoutMS) * time.Millisecond,
			ResumeAppliedEndpointIDs:  options.PolicyRolloutResume[rollout.Name],
			Paused:                    rollout.Paused,
			PauseAfterBatches:         rollout.PauseAfterBatches,
			PromotionPercent:          rollout.PromotionPercent,
		})
		if err != nil {
			return nil, fmt.Errorf("policy rollout %q: %w", rollout.Name, err)
		}
		out = append(out, NamedPolicyEndpointRollout{Name: rollout.Name, Rollout: result})
		if result.Failed != 0 {
			break
		}
	}
	return out, nil
}

func PolicyRolloutRevision(state control.DesiredState, rollout control.PolicyRollout, endpointIDs []string) (string, error) {
	revision := strings.TrimSpace(rollout.Revision)
	if revision != "" {
		return revision, nil
	}
	payload := struct {
		Name      string               `json:"name"`
		Node      string               `json:"node,omitempty"`
		Endpoints []string             `json:"endpoints,omitempty"`
		Desired   control.DesiredState `json:"desired"`
	}{
		Name:      rollout.Name,
		Node:      rollout.Node,
		Endpoints: uniquePolicyEndpointIDs(endpointIDs),
		Desired: control.DesiredState{
			Subnets:        append([]model.Subnet(nil), state.Subnets...),
			Endpoints:      append([]model.Endpoint(nil), state.Endpoints...),
			Gateways:       append([]model.Gateway(nil), state.Gateways...),
			LoadBalancers:  append([]model.LoadBalancer(nil), state.LoadBalancers...),
			SecurityGroups: append([]model.SecurityGroup(nil), state.SecurityGroups...),
			CIDRGroups:     append([]model.CIDRGroup(nil), state.CIDRGroups...),
			DNSRecords:     append([]model.DNSRecord(nil), state.DNSRecords...),
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func parsePolicyRolloutTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("must be RFC3339")
	}
	return parsed, nil
}

func activePolicyRolloutsForNode(rollouts []control.PolicyRollout, node string) []control.PolicyRollout {
	out := make([]control.PolicyRollout, 0, len(rollouts))
	for _, rollout := range rollouts {
		if rollout.Disabled {
			continue
		}
		if rollout.Node != "" && rollout.Node != node {
			continue
		}
		out = append(out, rollout)
	}
	return out
}

func HasActivePolicyRollouts(state control.DesiredState, node string) bool {
	return len(activePolicyRolloutsForNode(state.PolicyRollouts, node)) != 0
}

func rolloutEndpointIDs(state control.DesiredState, rollout control.PolicyRollout) ([]string, error) {
	if len(rollout.Endpoints) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(rollout.Endpoints))
	for _, ref := range rollout.Endpoints {
		endpointID, err := resolveDesiredEndpointRef(state.Endpoints, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, endpointID)
	}
	return out, nil
}

func resolveDesiredEndpointRef(endpoints []model.Endpoint, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", fmt.Errorf("endpoint reference is empty")
	}
	if strings.Contains(ref, "\x00") {
		if _, ok := desiredEndpointByPolicyID(endpoints, ref); ok {
			return ref, nil
		}
		return "", fmt.Errorf("endpoint %q not found in desired state", ref)
	}
	vpc, id, ok := strings.Cut(ref, "/")
	if !ok || vpc == "" || id == "" {
		return "", fmt.Errorf("endpoint reference %q must use vpc/id", ref)
	}
	endpointID := model.EndpointKey(vpc, id)
	if _, ok := desiredEndpointByPolicyID(endpoints, endpointID); !ok {
		return "", fmt.Errorf("endpoint %q not found in desired state", ref)
	}
	return endpointID, nil
}

func ApplyPolicyRolloutResults(result *ReconcileResult, rollouts []NamedPolicyEndpointRollout) {
	if result == nil {
		return
	}
	result.PolicyRollouts = len(rollouts)
	result.PolicyRolloutStatus = append([]NamedPolicyEndpointRollout(nil), rollouts...)
	for _, rollout := range rollouts {
		result.PolicyRolloutPlanned += rollout.Rollout.Planned
		result.PolicyRolloutApplied += rollout.Rollout.Applied
		result.PolicyRolloutSkipped += rollout.Rollout.Skipped
		result.PolicyRolloutFailed += rollout.Rollout.Failed
		result.PolicyRolloutRolledBack += rollout.Rollout.RolledBack
		result.PolicyRolloutRollbackFailed += rollout.Rollout.RollbackFailed
		if rollout.Rollout.SLOFailed {
			result.PolicyRolloutSLOFailed++
		}
		if rollout.Rollout.ProbeFailed {
			result.PolicyRolloutProbeFailed++
		}
		if rollout.Rollout.Paused {
			result.PolicyRolloutPaused++
		}
		if rollout.Rollout.Cancelled {
			result.PolicyRolloutCancelled++
		}
	}
}

type rolloutPressureDecision struct {
	threshold  uint32
	maxPercent uint32
	endpointID string
	hotspots   []PolicyMapPressureHotspot
}

func pressureAwareRolloutBatchSize(ctx context.Context, store PolicyStore, requestedBatchSize int, options PolicyEndpointRolloutOptions) (int, rolloutPressureDecision, error) {
	requestedBatchSize = normalizedRolloutBatchSize(requestedBatchSize)
	decision := rolloutPressureDecision{}
	if !options.PressureAware {
		return requestedBatchSize, decision, nil
	}
	threshold := options.PressureThresholdPercent
	if threshold == 0 {
		threshold = dataplane.DefaultPolicyMapPressureThresholdPercent
	}
	if threshold > 100 {
		threshold = 100
	}
	decision.threshold = threshold
	usageStore, ok := store.(PolicyUsageStore)
	if !ok {
		return 0, decision, fmt.Errorf("policy map usage is required for pressure-aware rollout")
	}
	usages, err := usageStore.PolicyMapUsage(ctx)
	if err != nil {
		return 0, decision, fmt.Errorf("read policy map usage for pressure-aware rollout: %w", err)
	}
	summary := dataplane.SummarizePolicyMapUsage(usages)
	decision.maxPercent = summary.MaxPressurePercent
	decision.endpointID = summary.MaxPressureEndpoint
	decision.hotspots = append(decision.hotspots[:0], summary.PressureHotspots...)
	if summary.MaxPressurePercent < threshold {
		return requestedBatchSize, decision, nil
	}
	minBatchSize := normalizedRolloutBatchSize(options.PressureAwareMinBatchSize)
	if minBatchSize > requestedBatchSize {
		minBatchSize = requestedBatchSize
	}
	return minBatchSize, decision, nil
}

func normalizedRolloutBatchSize(batchSize int) int {
	if batchSize <= 0 {
		return 1
	}
	return batchSize
}

func planPolicyEndpointEntries(endpointID string, desired []dataplane.PolicyMapEntry, store PolicyStore) (PolicyEndpointPlan, error) {
	entryStore, ok := store.(PolicyEndpointEntryStore)
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

func rolloutPolicyEndpointIDs(state control.DesiredState, options ReconcileOptions, requested []string) ([]string, error) {
	if len(requested) > 0 {
		return uniquePolicyEndpointIDs(requested), nil
	}
	if options.Node == "" {
		return nil, fmt.Errorf("node name is required")
	}
	ids := make([]string, 0)
	for _, endpoint := range state.Endpoints {
		if endpoint.Node != options.Node {
			continue
		}
		ids = append(ids, model.EndpointKey(endpoint.VPC, endpoint.ID))
	}
	return uniquePolicyEndpointIDs(ids), nil
}

func uniquePolicyEndpointIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out[value] = struct{}{}
	}
	return out
}

func rolloutBatch(index, batchSize int) int {
	return index/batchSize + 1
}

func policyEndpointStatus(ctx context.Context, store PolicyStore, endpointID string) (dataplane.PolicyEndpointStatus, bool, error) {
	statusStore, ok := store.(PolicyEndpointStatusStore)
	if !ok {
		return dataplane.PolicyEndpointStatus{}, false, nil
	}
	statuses, err := statusStore.PolicyEndpointStatuses(ctx)
	if err != nil {
		return dataplane.PolicyEndpointStatus{}, false, err
	}
	for _, status := range statuses {
		if status.EndpointID == endpointID {
			return status, true, nil
		}
	}
	return dataplane.PolicyEndpointStatus{}, false, nil
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
	if policyEndpointFrozen(options, endpointID) {
		return dataplane.PolicyEndpointStatus{}, fmt.Errorf("policy endpoint %s is frozen", endpointID)
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

func RollbackPolicyEndpoint(ctx context.Context, state control.DesiredState, options ReconcileOptions, endpointID string) (dataplane.PolicyEndpointStatus, error) {
	status, err := RegeneratePolicyEndpoint(ctx, state, options, endpointID)
	if err != nil {
		return dataplane.PolicyEndpointStatus{}, fmt.Errorf("rollback policy endpoint %s: %w", endpointID, err)
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
	if err := r.syncPolicyStore(ctx, programs, options.Store, options.FrozenPolicyEndpoints); err != nil {
		return result, err
	}
	if err := populatePolicyMapUsageResult(ctx, options.Store, &result); err != nil {
		return result, err
	}
	if err := mitigatePolicyMapPressureResult(ctx, options.Store, programs, options.FrozenPolicyEndpoints, options.PolicyPressureMitigationThreshold, options.PolicyPressureQuarantineThreshold, options.PolicyPressureQuarantine, &result); err != nil {
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

func (r *Reconciler) syncPolicyStore(ctx context.Context, programs []policy.Program, store PolicyStore, frozen map[string]struct{}) error {
	if r == nil || store == nil {
		return nil
	}
	desired := policyEndpointKeepSet(programs, frozen)
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
		frozen := policyEndpointFrozen(options, program.EndpointID)
		if frozen {
			result.PolicyFrozen++
		}
		if !options.DeferPolicyApply && !frozen {
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
		}
		localPrograms = append(localPrograms, program)
		if frozen {
			continue
		}
		if tcxEligibleProgram(program) {
			result.TCXEligible++
			tcxPrograms = append(tcxPrograms, program)
		} else if len(program.MapEntries) > 0 {
			result.TCXSkipped++
		}
	}
	if options.LinuxDatapath != nil {
		linuxOptions := *options.LinuxDatapath
		linuxOptions.Node = options.Node
		applyLinuxDatapath := linuxdatapath.Apply
		if options.LinuxDatapathApply != nil {
			applyLinuxDatapath = options.LinuxDatapathApply
		}
		linuxResult, err := applyLinuxDatapath(ctx, state, linuxOptions)
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
	if err := mitigatePolicyMapPressureResult(ctx, options.Store, localPrograms, options.FrozenPolicyEndpoints, options.PolicyPressureMitigationThreshold, options.PolicyPressureQuarantineThreshold, options.PolicyPressureQuarantine, &result); err != nil {
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
	result.PolicyRuleCatalog = catalogPolicyRules(localPrograms)
	if err := sweepPolicyEndpointsResult(ctx, options.Store, localPrograms, options.FrozenPolicyEndpoints, options.PolicyGCMaxIdle, &result); err != nil {
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

func policyEndpointFrozen(options ReconcileOptions, endpointID string) bool {
	if len(options.FrozenPolicyEndpoints) == 0 {
		return false
	}
	_, ok := options.FrozenPolicyEndpoints[endpointID]
	return ok
}

func catalogPolicyRules(programs []policy.Program) []PolicyRuleCatalogEntry {
	byKey := make(map[string]PolicyRuleCatalogEntry)
	for _, program := range programs {
		for _, rule := range program.Rules {
			ref := policyRuleRef(rule)
			if ref == "" {
				continue
			}
			entry := PolicyRuleCatalogEntry{
				EndpointID:    program.EndpointID,
				RuleCookie:    dataplane.PolicyRuleCookie(ref),
				RuleRef:       ref,
				VPC:           rule.VPC,
				SecurityGroup: rule.SecurityGroup,
				RuleID:        rule.ID,
			}
			key := fmt.Sprintf("%s\x00%d", entry.EndpointID, entry.RuleCookie)
			byKey[key] = entry
		}
	}
	out := make([]PolicyRuleCatalogEntry, 0, len(byKey))
	for _, entry := range byKey {
		out = append(out, entry)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].EndpointID != out[j].EndpointID {
			return out[i].EndpointID < out[j].EndpointID
		}
		return out[i].RuleCookie < out[j].RuleCookie
	})
	return out
}

func policyRuleRef(rule policy.Rule) string {
	if rule.VPC == "" && rule.SecurityGroup == "" {
		return rule.ID
	}
	return strings.Join([]string{rule.VPC, rule.SecurityGroup, rule.ID}, "/")
}

func policyEndpointKeepSet(programs []policy.Program, frozen map[string]struct{}) map[string]struct{} {
	keep := make(map[string]struct{}, len(programs)+len(frozen))
	for _, program := range programs {
		keep[program.EndpointID] = struct{}{}
	}
	for endpointID := range frozen {
		keep[endpointID] = struct{}{}
	}
	return keep
}

func policyEndpointKeepList(programs []policy.Program, frozen map[string]struct{}) []string {
	keepSet := policyEndpointKeepSet(programs, frozen)
	keep := make([]string, 0, len(keepSet))
	for endpointID := range keepSet {
		keep = append(keep, endpointID)
	}
	sort.Strings(keep)
	return keep
}

func mitigatePolicyMapPressureResult(ctx context.Context, store PolicyStore, programs []policy.Program, frozen map[string]struct{}, mitigationThreshold, quarantineThreshold uint32, quarantine bool, result *ReconcileResult) error {
	if result == nil {
		return nil
	}
	keep := policyEndpointKeepSet(programs, frozen)

	if mitigationThreshold > 0 && result.PolicyMapPressureMax >= mitigationThreshold {
		inventory, ok := store.(PolicyEndpointInventory)
		if ok {
			endpointIDs, err := inventory.EndpointIDs(ctx)
			if err != nil {
				return fmt.Errorf("list policy endpoints for pressure mitigation: %w", err)
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
			if mitigated > 0 {
				if err := populatePolicyMapUsageResult(ctx, store, result); err != nil {
					return err
				}
			}
		}
	}

	if quarantineThreshold == 0 {
		quarantineThreshold = mitigationThreshold
	}
	if quarantineThreshold == 0 {
		return nil
	}
	return quarantinePolicyMapPressureResult(ctx, store, keep, quarantineThreshold, quarantine, result)
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

func sweepPolicyEndpointsResult(ctx context.Context, store PolicyStore, programs []policy.Program, frozen map[string]struct{}, maxIdle time.Duration, result *ReconcileResult) error {
	if maxIdle <= 0 {
		return nil
	}
	sweeper, ok := store.(PolicyEndpointSweeper)
	if !ok {
		return nil
	}
	keep := policyEndpointKeepList(programs, frozen)
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
		result.PolicyMapPressureHotspots = nil
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
	result.PolicyMapPressureHotspots = append(result.PolicyMapPressureHotspots[:0], summary.PressureHotspots...)
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
	seenRollouts := make(map[string]struct{}, len(state.PolicyRollouts))
	for _, rollout := range state.PolicyRollouts {
		if err := rollout.Validate(); err != nil {
			return err
		}
		if _, ok := seenRollouts[rollout.Name]; ok {
			return fmt.Errorf("duplicate policy rollout name %q", rollout.Name)
		}
		seenRollouts[rollout.Name] = struct{}{}
		for _, ref := range rollout.Endpoints {
			if _, err := resolveDesiredEndpointRef(state.Endpoints, ref); err != nil {
				return fmt.Errorf("policy rollout %q: %w", rollout.Name, err)
			}
		}
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
