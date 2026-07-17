package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jimyag/netloom/internal/agent"
	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/linuxdatapath"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
	"github.com/jimyag/netloom/internal/topology"
	"golang.org/x/sys/unix"
)

const (
	defaultBPFFSRoot        = "/sys/fs/bpf"
	defaultBPFFSPinRoot     = "/sys/fs/bpf/netloom/policy"
	defaultRuntimeBPFRoot   = "/var/run/netloom-ebpf"
	defaultRuntimePinRoot   = "/var/run/netloom-ebpf/policy"
	defaultMetadataRoot     = "/var/run/netloom-ebpf-meta/policy"
	policyRolloutStateKey   = "netloom_policy_rollout_state"
	policyRolloutHistoryKey = "netloom_policy_rollout_history"
	policyActionHistoryKey  = "netloom_policy_endpoint_action_history"
	policyEventsKey         = "netloom_policy_events"
	policyRulesKey          = "netloom_policy_rules"
	policyEntriesKey        = "netloom_policy_entries"
	policyEndpointStatusKey = "netloom_policy_endpoint_status"
	policyFreezeStateKey    = "netloom_policy_freeze_state"
	agentOVSDBStatusKey     = "netloom_agent_status"
	identityGroupsStateKey  = "netloom_identity_groups"
)

var runAgentRuntimePreflight = agent.RunRuntimePreflight

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "policy-explain":
			if err := runPolicyExplain(os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "policy-status":
			if err := runPolicyStatus(os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "policy-status-export":
			if err := runPolicyStatusExport(context.Background(), os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "policy-revision-wait":
			if err := runPolicyRevisionWait(context.Background(), os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "agent-status":
			if err := runAgentStatus(context.Background(), os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "policy-entries":
			if err := runPolicyEntries(os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "policy-entries-export":
			if err := runPolicyEntriesExport(context.Background(), os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "policy-action-history":
			if err := runPolicyActionHistory(context.Background(), os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "policy-events":
			if err := runPolicyEvents(context.Background(), os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "policy-rules":
			if err := runPolicyRules(context.Background(), os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "policy-rollout-history":
			if err := runPolicyRolloutHistory(context.Background(), os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "policy-rollout-state":
			if err := runPolicyRolloutState(context.Background(), os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "policy-freeze-state":
			if err := runPolicyFreezeState(context.Background(), os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "route-explain":
			if err := runRouteExplain(os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "identity-groups-import":
			if err := runIdentityGroupsImport(context.Background(), os.Args[2:], os.Stdin, os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "identity-groups-export":
			if err := runIdentityGroupsExport(context.Background(), os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "dns-observations-export":
			if err := runDNSObservationsExport(context.Background(), os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "desired-state-import":
			if err := runDesiredStateImport(context.Background(), os.Args[2:], os.Stdin, os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "desired-state-export":
			if err := runDesiredStateExport(context.Background(), os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		}
	}

	if path, ok := desiredStateRuntimePathFromEnv(); ok {
		if err := runStateFile(context.Background(), path); err != nil {
			log.Fatal(err)
		}
		return
	}

	result, err := agent.RunSelfTest(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("netloom-agent ready for node policy and datapath reconciliation endpoint=%s entries=%d allow=%s deny=%s policy_allowed=%d policy_dropped=%d policy_conntrack=%d policy_established=%d policy_logged=%d rule_stats=%s rule_catalog=%s drop_events=%d policy_events=%d trace_events=%d tcx=%s runtime_ready=%t runtime=%s\n", result.EndpointID, result.Entries, result.Allowed, result.Denied, result.PolicyStats.Allowed, result.PolicyStats.Dropped, result.PolicyStats.Conntrack, result.PolicyStats.Established, result.PolicyStats.Logged, formatRuleStats(result.RuleStats), formatRuleCatalog(result.RuleCatalog), result.DropEvents, result.PolicyEvents, result.TraceEvents, result.TCX, result.RuntimeReady, formatRuntimeChecks(result.Runtime))
}

func desiredStateRuntimePathFromEnv() (string, bool) {
	if path := strings.TrimSpace(os.Getenv("NETLOOM_STATE_FILE")); path != "" {
		return path, true
	}
	if strings.TrimSpace(os.Getenv("NETLOOM_OVSDB_ENDPOINT")) != "" {
		return "", true
	}
	return "", false
}

type policyExplainOptions struct {
	stateFile      string
	vpc            string
	endpoint       string
	remoteEndpoint string
	remoteVPC      string
	remoteIdentity uint
	remoteIP       string
	direction      string
	protocol       string
	sourcePort     uint
	destPort       uint
	icmpType       int
	icmpCode       int
	stateful       bool
}

type policyStatusOptions struct {
	stateFile string
	node      string
	endpoint  string
}

type policyStatusExportOptions struct {
	ovsdb    string
	endpoint string
}

type policyRevisionWaitOptions struct {
	ovsdb          string
	endpoint       string
	targetRevision uint64
	timeout        time.Duration
	interval       time.Duration
}

type agentStatusOptions struct {
	ovsdb string
}

type policyEntriesOptions struct {
	stateFile  string
	node       string
	endpoint   string
	ruleCookie string
}

type policyEntriesExportOptions struct {
	ovsdb      string
	endpoint   string
	ruleCookie string
}

type policyActionHistoryOptions struct {
	ovsdb    string
	endpoint string
	action   string
	success  string
	limit    int
}

type policyEventsOptions struct {
	ovsdb    string
	endpoint string
	limit    int
}

type policyRulesOptions struct {
	ovsdb      string
	endpoint   string
	ruleCookie string
	ruleRef    string
}

type policyRolloutHistoryOptions struct {
	ovsdb  string
	source string
	name   string
	limit  int
}

type policyRolloutStateOptions struct {
	ovsdb string
	name  string
	node  string
}

type policyFreezeStateOptions struct {
	ovsdb    string
	endpoint string
}

type routeExplainOptions struct {
	stateFile  string
	vpc        string
	source     string
	dest       string
	protocol   string
	sourcePort uint
	destPort   uint
}

type identityGroupsImportOptions struct {
	inputFile string
	ovsdb     string
}

type identityGroupsExportOptions struct {
	ovsdb  string
	source string
}

type dnsObservationsExportOptions struct {
	ovsdb string
}

type desiredStateImportOptions struct {
	inputFile string
	ovsdb     string
}

type desiredStateExportOptions struct {
	ovsdb string
}

type policyMapPressureHotspot = dataplane.PolicyMapPressureHotspot

type policyStatusOutput struct {
	Node                 string                           `json:"node"`
	Store                string                           `json:"store"`
	Ready                bool                             `json:"ready"`
	LastReconcileSuccess bool                             `json:"last_reconcile_success"`
	LastReconcileError   string                           `json:"last_reconcile_error,omitempty"`
	UpdatedAt            time.Time                        `json:"updated_at,omitempty"`
	FilterEndpoint       string                           `json:"filter_endpoint,omitempty"`
	EndpointCount        int                              `json:"endpoint_count"`
	PolicyMapEntries     uint32                           `json:"policy_map_entries"`
	PolicyMapCapacity    uint32                           `json:"policy_map_capacity"`
	PressureMax          uint32                           `json:"pressure_max"`
	PressureEndpoint     string                           `json:"pressure_endpoint,omitempty"`
	PressureEndpoints    int                              `json:"pressure_endpoints"`
	PressureHotspots     []policyMapPressureHotspot       `json:"pressure_hotspots,omitempty"`
	DriftEndpoints       int                              `json:"drift_endpoints"`
	DriftMissing         int                              `json:"drift_missing"`
	DriftExtra           int                              `json:"drift_extra"`
	DriftChanged         int                              `json:"drift_changed"`
	PolicyRevisionMax    uint64                           `json:"policy_revision_max"`
	FrozenEndpoints      []string                         `json:"frozen_endpoints,omitempty"`
	FrozenEndpointExpiry map[string]time.Time             `json:"frozen_endpoint_expiry,omitempty"`
	Statuses             []dataplane.PolicyEndpointStatus `json:"statuses"`
}

type policyStatusDocument struct {
	Node                 string                           `json:"node,omitempty"`
	Store                string                           `json:"store,omitempty"`
	LastReconcileSuccess bool                             `json:"last_reconcile_success"`
	LastReconcileError   string                           `json:"last_reconcile_error,omitempty"`
	UpdatedAt            time.Time                        `json:"updated_at,omitempty"`
	EndpointCount        int                              `json:"endpoint_count"`
	PolicyMapEntries     uint32                           `json:"policy_map_entries"`
	PolicyMapCapacity    uint32                           `json:"policy_map_capacity"`
	PressureMax          uint32                           `json:"pressure_max"`
	PressureEndpoint     string                           `json:"pressure_endpoint,omitempty"`
	PressureEndpoints    int                              `json:"pressure_endpoints"`
	PressureHotspots     []policyMapPressureHotspot       `json:"pressure_hotspots,omitempty"`
	DriftEndpoints       int                              `json:"drift_endpoints"`
	DriftMissing         int                              `json:"drift_missing"`
	DriftExtra           int                              `json:"drift_extra"`
	DriftChanged         int                              `json:"drift_changed"`
	PolicyRevisionMax    uint64                           `json:"policy_revision_max"`
	Statuses             []dataplane.PolicyEndpointStatus `json:"statuses"`
}

type policyRevisionWaitOutput struct {
	Ready          bool                           `json:"ready"`
	Node           string                         `json:"node,omitempty"`
	Store          string                         `json:"store,omitempty"`
	EndpointID     string                         `json:"endpoint_id"`
	TargetRevision uint64                         `json:"target_revision"`
	Revision       uint64                         `json:"revision"`
	UpdatedAt      time.Time                      `json:"updated_at,omitempty"`
	WaitedMS       int64                          `json:"waited_ms"`
	Status         dataplane.PolicyEndpointStatus `json:"status"`
}

type policyRulesOutput struct {
	Node                 string             `json:"node"`
	Store                string             `json:"store"`
	Ready                bool               `json:"ready"`
	LastReconcileSuccess bool               `json:"last_reconcile_success"`
	LastReconcileError   string             `json:"last_reconcile_error,omitempty"`
	UpdatedAt            time.Time          `json:"updated_at,omitempty"`
	FilterEndpoint       string             `json:"filter_endpoint,omitempty"`
	FilterRuleCookie     uint32             `json:"filter_rule_cookie,omitempty"`
	FilterRuleRef        string             `json:"filter_rule_ref,omitempty"`
	RuleCount            int                `json:"rule_count"`
	Packets              uint64             `json:"packets"`
	Bytes                uint64             `json:"bytes"`
	Allowed              uint64             `json:"allowed"`
	Dropped              uint64             `json:"dropped"`
	Rejected             uint64             `json:"rejected"`
	NoMatchDrops         uint64             `json:"no_match_drops"`
	DenyDrops            uint64             `json:"deny_drops"`
	RejectDrops          uint64             `json:"reject_drops"`
	Conntrack            uint64             `json:"conntrack"`
	Established          uint64             `json:"established"`
	Logged               uint64             `json:"logged"`
	Rules                []policyRuleOutput `json:"rules"`
}

type policyRuleOutput struct {
	EndpointID    string `json:"endpoint_id"`
	RuleCookie    uint32 `json:"rule_cookie"`
	RuleRef       string `json:"rule_ref,omitempty"`
	VPC           string `json:"vpc,omitempty"`
	SecurityGroup string `json:"security_group,omitempty"`
	RuleID        string `json:"rule_id,omitempty"`
	Packets       uint64 `json:"packets"`
	Bytes         uint64 `json:"bytes"`
	Allowed       uint64 `json:"allowed"`
	Dropped       uint64 `json:"dropped"`
	Rejected      uint64 `json:"rejected"`
	NoMatchDrops  uint64 `json:"no_match_drops"`
	DenyDrops     uint64 `json:"deny_drops"`
	RejectDrops   uint64 `json:"reject_drops"`
	Conntrack     uint64 `json:"conntrack"`
	Established   uint64 `json:"established"`
	Logged        uint64 `json:"logged"`
}

type policyEventsOutput struct {
	Node                 string                        `json:"node"`
	Store                string                        `json:"store"`
	Ready                bool                          `json:"ready"`
	LastReconcileSuccess bool                          `json:"last_reconcile_success"`
	LastReconcileError   string                        `json:"last_reconcile_error,omitempty"`
	UpdatedAt            time.Time                     `json:"updated_at,omitempty"`
	TotalEvents          int                           `json:"total_events"`
	EventCount           int                           `json:"event_count"`
	Limit                int                           `json:"limit"`
	FilterEndpoint       string                        `json:"filter_endpoint,omitempty"`
	Events               []dataplane.PolicyUpdateEvent `json:"events"`
}

type policyEntriesOutput struct {
	Node                 string                 `json:"node"`
	Store                string                 `json:"store"`
	Ready                bool                   `json:"ready"`
	LastReconcileSuccess bool                   `json:"last_reconcile_success"`
	LastReconcileError   string                 `json:"last_reconcile_error,omitempty"`
	EndpointID           string                 `json:"endpoint_id"`
	FilterRuleCookie     uint32                 `json:"filter_rule_cookie,omitempty"`
	EntryCount           int                    `json:"entry_count"`
	Entries              []policyMapEntryOutput `json:"entries"`
}

type policyEntriesExportOutput struct {
	Node                 string                        `json:"node"`
	Store                string                        `json:"store"`
	Ready                bool                          `json:"ready"`
	LastReconcileSuccess bool                          `json:"last_reconcile_success"`
	LastReconcileError   string                        `json:"last_reconcile_error,omitempty"`
	UpdatedAt            time.Time                     `json:"updated_at,omitempty"`
	TotalEndpoints       int                           `json:"total_endpoints"`
	EndpointCount        int                           `json:"endpoint_count"`
	FilterEndpoint       string                        `json:"filter_endpoint,omitempty"`
	FilterRuleCookie     uint32                        `json:"filter_rule_cookie,omitempty"`
	Endpoints            []policyEntriesEndpointOutput `json:"endpoints"`
}

type policyEntriesEndpointOutput struct {
	EndpointID string                 `json:"endpoint_id"`
	EntryCount int                    `json:"entry_count"`
	Entries    []policyMapEntryOutput `json:"entries"`
}

type policyMapEntryOutput struct {
	Key        policyMapKeyOutput   `json:"key"`
	Value      policyMapValueOutput `json:"value"`
	RemoteCIDR string               `json:"remote_cidr,omitempty"`
}

type policyMapKeyOutput struct {
	PrefixLen      uint32 `json:"prefix_len"`
	RemoteIdentity uint32 `json:"remote_identity"`
	Direction      uint8  `json:"direction"`
	Protocol       uint8  `json:"protocol"`
	DestPortBE     uint16 `json:"dest_port_be"`
}

type policyMapValueOutput struct {
	Deny            uint8  `json:"deny"`
	L4PrefixLen     uint8  `json:"l4_prefix_len"`
	Stateful        uint8  `json:"stateful"`
	Log             uint8  `json:"log"`
	Precedence      uint32 `json:"precedence"`
	RuleCookie      uint32 `json:"rule_cookie"`
	Reject          uint8  `json:"reject"`
	RequireIdentity uint8  `json:"require_identity"`
	Packets         uint64 `json:"packets"`
	Bytes           uint64 `json:"bytes"`
}

type policyEndpointActionOutput struct {
	EndpointID    string                         `json:"endpoint_id"`
	Action        string                         `json:"action"`
	Deleted       bool                           `json:"deleted,omitempty"`
	Planned       bool                           `json:"planned,omitempty"`
	RolledOut     bool                           `json:"rolled_out,omitempty"`
	RolledBack    bool                           `json:"rolled_back,omitempty"`
	Regenerated   bool                           `json:"regenerated,omitempty"`
	Quarantined   bool                           `json:"quarantined,omitempty"`
	Unquarantined bool                           `json:"unquarantined,omitempty"`
	Frozen        bool                           `json:"frozen,omitempty"`
	Unfrozen      bool                           `json:"unfrozen,omitempty"`
	ExpiresAt     *time.Time                     `json:"expires_at,omitempty"`
	Plan          agent.PolicyEndpointPlan       `json:"plan,omitempty"`
	Rollout       agent.PolicyEndpointRollout    `json:"rollout,omitempty"`
	EndpointInfo  dataplane.PolicyEndpointStatus `json:"endpoint_status,omitempty"`
}

type policyRolloutHistoryOutput struct {
	Ready        bool                        `json:"ready"`
	TotalEvents  int                         `json:"total_events,omitempty"`
	EventCount   int                         `json:"event_count,omitempty"`
	Limit        int                         `json:"limit,omitempty"`
	FilterSource string                      `json:"filter_source,omitempty"`
	FilterName   string                      `json:"filter_name,omitempty"`
	History      []policyRolloutHistoryEntry `json:"history"`
}

type policyActionHistoryOutput struct {
	Ready          bool                       `json:"ready"`
	TotalEvents    int                        `json:"total_events"`
	EventCount     int                        `json:"event_count"`
	Limit          int                        `json:"limit"`
	FilterEndpoint string                     `json:"filter_endpoint,omitempty"`
	FilterAction   string                     `json:"filter_action,omitempty"`
	FilterSuccess  *bool                      `json:"filter_success,omitempty"`
	History        []policyActionHistoryEntry `json:"history"`
}

type policyRolloutHistoryEntry struct {
	ID          string                      `json:"id"`
	Source      string                      `json:"source"`
	Name        string                      `json:"name,omitempty"`
	Node        string                      `json:"node,omitempty"`
	Store       string                      `json:"store,omitempty"`
	CompletedAt time.Time                   `json:"completed_at"`
	DurationMS  int64                       `json:"duration_ms,omitempty"`
	Rollout     agent.PolicyEndpointRollout `json:"rollout"`
}

type policyActionHistoryEntry struct {
	ID          string    `json:"id"`
	Action      string    `json:"action"`
	EndpointID  string    `json:"endpoint_id"`
	Node        string    `json:"node,omitempty"`
	Store       string    `json:"store,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
	Revision    uint64    `json:"revision,omitempty"`
	Entries     uint32    `json:"entries,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
}

type policyEventsDocument struct {
	Node                 string                        `json:"node,omitempty"`
	Store                string                        `json:"store,omitempty"`
	LastReconcileSuccess bool                          `json:"last_reconcile_success"`
	LastReconcileError   string                        `json:"last_reconcile_error,omitempty"`
	UpdatedAt            time.Time                     `json:"updated_at,omitempty"`
	TotalEvents          int                           `json:"total_events"`
	Events               []dataplane.PolicyUpdateEvent `json:"events"`
}

type policyRulesDocument struct {
	Node                 string             `json:"node,omitempty"`
	Store                string             `json:"store,omitempty"`
	LastReconcileSuccess bool               `json:"last_reconcile_success"`
	LastReconcileError   string             `json:"last_reconcile_error,omitempty"`
	UpdatedAt            time.Time          `json:"updated_at,omitempty"`
	Rules                []policyRuleOutput `json:"rules"`
}

type policyEntriesDocument struct {
	Node                 string                        `json:"node,omitempty"`
	Store                string                        `json:"store,omitempty"`
	LastReconcileSuccess bool                          `json:"last_reconcile_success"`
	LastReconcileError   string                        `json:"last_reconcile_error,omitempty"`
	UpdatedAt            time.Time                     `json:"updated_at,omitempty"`
	Endpoints            []policyEntriesEndpointOutput `json:"endpoints"`
}

type policyRolloutStateDocument struct {
	Rollouts []policyRolloutStateEntry `json:"rollouts"`
}

type policyRolloutStateOutput struct {
	Ready         bool                      `json:"ready"`
	TotalRollouts int                       `json:"total_rollouts"`
	RolloutCount  int                       `json:"rollout_count"`
	FilterName    string                    `json:"filter_name,omitempty"`
	FilterNode    string                    `json:"filter_node,omitempty"`
	Rollouts      []policyRolloutStateEntry `json:"rollouts"`
}

type policyRolloutStateEntry struct {
	Name             string    `json:"name"`
	Node             string    `json:"node,omitempty"`
	Revision         string    `json:"revision,omitempty"`
	Store            string    `json:"store,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
	AppliedEndpoints []string  `json:"applied_endpoints,omitempty"`
	Paused           bool      `json:"paused,omitempty"`
	Failed           int       `json:"failed,omitempty"`
}

type policyFreezeStateDocument struct {
	FrozenEndpoints []policyFreezeStateEntry `json:"frozen_endpoints,omitempty"`
	UpdatedAt       time.Time                `json:"updated_at,omitempty"`
}

type policyFreezeStateOutput struct {
	Ready                 bool                     `json:"ready"`
	TotalFrozenEndpoints  int                      `json:"total_frozen_endpoints"`
	ActiveFrozenEndpoints int                      `json:"active_frozen_endpoints"`
	FilterEndpoint        string                   `json:"filter_endpoint,omitempty"`
	UpdatedAt             time.Time                `json:"updated_at,omitempty"`
	FrozenEndpoints       []policyFreezeStateEntry `json:"frozen_endpoints"`
}

type policyFreezeStateEntry struct {
	EndpointID string    `json:"endpoint_id"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}

type policyEndpointFreezeRequest struct {
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

type policyRolloutStateStore interface {
	Load(context.Context) (policyRolloutStateDocument, error)
	Save(context.Context, policyRolloutStateDocument) error
}

type policyFreezeStateStore interface {
	Load(context.Context) (policyFreezeStateDocument, error)
	Save(context.Context, policyFreezeStateDocument) error
}

type policyRolloutHistoryStore interface {
	Load(context.Context) ([]policyRolloutHistoryEntry, error)
	Append(context.Context, policyRolloutHistoryEntry) error
}

type policyActionHistoryStore interface {
	Load(context.Context) ([]policyActionHistoryEntry, error)
	Append(context.Context, policyActionHistoryEntry) error
}

type policyEventsStore interface {
	Load(context.Context) (policyEventsDocument, error)
	Save(context.Context, policyEventsDocument) error
}

type policyStatusStore interface {
	Load(context.Context) (policyStatusDocument, error)
	Save(context.Context, policyStatusDocument) error
}

type policyRulesStore interface {
	Load(context.Context) (policyRulesDocument, error)
	Save(context.Context, policyRulesDocument) error
}

type policyEntriesStore interface {
	Load(context.Context) (policyEntriesDocument, error)
	Save(context.Context, policyEntriesDocument) error
}

type dnsObservationStore interface {
	LoadDNSObservations(context.Context) ([]model.DNSRecord, error)
}

type openVSwitchExternalIDStore interface {
	OpenVSwitchExternalID(context.Context, string) (string, bool, error)
	SetOpenVSwitchExternalID(context.Context, string, string) error
}

type ovsdbPolicyRolloutStateStore struct {
	syncer openVSwitchExternalIDStore
}

type ovsdbPolicyFreezeStateStore struct {
	syncer openVSwitchExternalIDStore
}

type ovsdbPolicyRolloutHistoryStore struct {
	syncer openVSwitchExternalIDStore
}

type ovsdbPolicyActionHistoryStore struct {
	syncer openVSwitchExternalIDStore
}

type ovsdbPolicyEventsStore struct {
	syncer openVSwitchExternalIDStore
}

type ovsdbPolicyStatusStore struct {
	syncer openVSwitchExternalIDStore
}

type ovsdbPolicyRulesStore struct {
	syncer openVSwitchExternalIDStore
}

type ovsdbPolicyEntriesStore struct {
	syncer openVSwitchExternalIDStore
}

type ovsdbDNSObservationStore struct {
	syncer openVSwitchExternalIDStore
}

type policyEndpointRolloutRequest struct {
	Endpoints                 []string                     `json:"endpoints"`
	Revision                  string                       `json:"revision,omitempty"`
	BatchSize                 int                          `json:"batch_size"`
	DryRun                    bool                         `json:"dry_run"`
	PressureAware             bool                         `json:"pressure_aware"`
	PressureThresholdPercent  uint32                       `json:"pressure_threshold_percent"`
	PressureAwareMinBatchSize int                          `json:"pressure_aware_min_batch_size"`
	SLOGated                  bool                         `json:"slo_gated"`
	SLODropThresholdPercent   uint32                       `json:"slo_drop_threshold_percent"`
	SLOMinPackets             uint64                       `json:"slo_min_packets"`
	SLOWindowCount            int                          `json:"slo_window_count"`
	SLOWindowIntervalMS       uint32                       `json:"slo_window_interval_ms"`
	Probes                    []control.PolicyRolloutProbe `json:"probes,omitempty"`
	ApprovalRequired          bool                         `json:"approval_required,omitempty"`
	Approved                  bool                         `json:"approved,omitempty"`
	ApprovalRef               string                       `json:"approval_ref,omitempty"`
	ApprovalSignature         string                       `json:"approval_signature,omitempty"`
	ApprovalExpiresAt         string                       `json:"approval_expires_at,omitempty"`
	ApprovalCallbackURL       string                       `json:"approval_callback_url,omitempty"`
	ApprovalCallbackTimeoutMS uint32                       `json:"approval_callback_timeout_ms,omitempty"`
	AckRequired               bool                         `json:"ack_required,omitempty"`
	Acknowledged              bool                         `json:"acknowledged,omitempty"`
	AckRef                    string                       `json:"ack_ref,omitempty"`
	AckExpiresAt              string                       `json:"ack_expires_at,omitempty"`
	FinalizeRequired          bool                         `json:"finalize_required,omitempty"`
	Finalized                 bool                         `json:"finalized,omitempty"`
	FinalizeRef               string                       `json:"finalize_ref,omitempty"`
	FinalizeExpiresAt         string                       `json:"finalize_expires_at,omitempty"`
	ChangePollURL             string                       `json:"change_poll_url,omitempty"`
	ChangePollTimeoutMS       uint32                       `json:"change_poll_timeout_ms,omitempty"`
	ChangeStatusURL           string                       `json:"change_status_url,omitempty"`
	ChangeStatusTimeoutMS     uint32                       `json:"change_status_timeout_ms,omitempty"`
	Paused                    bool                         `json:"paused,omitempty"`
	PauseAfterBatches         int                          `json:"pause_after_batches,omitempty"`
	PromotionPercent          uint32                       `json:"promotion_percent,omitempty"`
}

func runPolicyExplain(args []string, stdout io.Writer) error {
	var opts policyExplainOptions
	flags := flag.NewFlagSet("netloom-agent policy-explain", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.stateFile, "state", os.Getenv("NETLOOM_STATE_FILE"), "desired-state JSON path")
	flags.StringVar(&opts.vpc, "vpc", "", "endpoint VPC")
	flags.StringVar(&opts.endpoint, "endpoint", "", "endpoint ID")
	flags.StringVar(&opts.remoteEndpoint, "remote-endpoint", "", "remote endpoint ID used to derive identity and default remote IP")
	flags.StringVar(&opts.remoteVPC, "remote-vpc", "", "remote endpoint VPC; defaults to -vpc")
	flags.UintVar(&opts.remoteIdentity, "remote-identity", 0, "remote identity")
	flags.StringVar(&opts.remoteIP, "remote-ip", "", "remote IP")
	flags.StringVar(&opts.direction, "direction", "", "ingress or egress")
	flags.StringVar(&opts.protocol, "protocol", "tcp", "tcp, udp, icmp, icmpv6, or any")
	flags.UintVar(&opts.sourcePort, "source-port", 0, "source port")
	flags.UintVar(&opts.destPort, "dest-port", 0, "destination port")
	flags.IntVar(&opts.icmpType, "icmp-type", 0, "ICMP type")
	flags.IntVar(&opts.icmpCode, "icmp-code", 0, "ICMP code")
	flags.BoolVar(&opts.stateful, "stateful", false, "explain stateful policy behavior")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if opts.vpc == "" {
		return errors.New("missing -vpc")
	}
	if opts.endpoint == "" {
		return errors.New("missing -endpoint")
	}
	if opts.direction == "" {
		return errors.New("missing -direction")
	}

	state, err := loadDesiredStateFromPathOrOVSDB(context.Background(), opts.stateFile, nil)
	if err != nil {
		return err
	}
	state, err = withRuntimeObservationsContext(context.Background(), state)
	if err != nil {
		return err
	}
	explanation, err := explainPolicyFromState(state, opts)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(explanation)
}

func runPolicyStatus(args []string, stdout io.Writer) error {
	var opts policyStatusOptions
	flags := flag.NewFlagSet("netloom-agent policy-status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.stateFile, "state", os.Getenv("NETLOOM_STATE_FILE"), "desired-state JSON path")
	flags.StringVar(&opts.node, "node", os.Getenv("NETLOOM_NODE_NAME"), "node name")
	flags.StringVar(&opts.endpoint, "endpoint", "", "optional endpoint key or endpoint ID to include")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.node) == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		opts.node = hostname
	}

	state, err := loadDesiredStateFromPathOrOVSDB(context.Background(), opts.stateFile, nil)
	if err != nil {
		return err
	}
	state, err = withRuntimeObservationsContext(context.Background(), state)
	if err != nil {
		return err
	}
	store, storeName, closeStore := policyStore()
	defer closeStore()
	result, err := agent.ReconcileNodeWithOptions(context.Background(), state, agent.ReconcileOptions{
		Node:  opts.node,
		Store: store,
	})
	if err != nil {
		return err
	}
	statuses := filterPolicyEndpointStatuses(result.PolicyEndpointStatus, opts.endpoint, state.Endpoints)
	output := policyStatusOutputFromResult(result, storeName, statuses)
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runPolicyStatusExport(ctx context.Context, args []string, stdout io.Writer) error {
	var opts policyStatusExportOptions
	flags := flag.NewFlagSet("netloom-agent policy-status-export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	flags.StringVar(&opts.endpoint, "endpoint", "", "optional endpoint key or endpoint ID to include")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runPolicyStatusExportWithStore(ctx, opts, stdout, ovsdbPolicyStatusStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)})
}

func runPolicyStatusExportWithStore(ctx context.Context, opts policyStatusExportOptions, stdout io.Writer, store policyStatusStore) error {
	if store == nil {
		return errors.New("missing policy status store")
	}
	doc, err := store.Load(ctx)
	if err != nil {
		return err
	}
	output := policyStatusOutputFromDocument(doc, strings.TrimSpace(opts.endpoint))
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runPolicyRevisionWait(ctx context.Context, args []string, stdout io.Writer) error {
	var opts policyRevisionWaitOptions
	flags := flag.NewFlagSet("netloom-agent policy-revision-wait", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	flags.StringVar(&opts.endpoint, "endpoint", "", "endpoint key or endpoint ID to wait for")
	flags.Uint64Var(&opts.targetRevision, "revision", 0, "minimum policy revision that must be applied")
	flags.DurationVar(&opts.timeout, "timeout", 30*time.Second, "maximum time to wait; 0 checks once")
	flags.DurationVar(&opts.interval, "interval", time.Second, "poll interval while waiting")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runPolicyRevisionWaitWithStore(ctx, opts, stdout, ovsdbPolicyStatusStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)})
}

func runPolicyRevisionWaitWithStore(ctx context.Context, opts policyRevisionWaitOptions, stdout io.Writer, store policyStatusStore) error {
	if store == nil {
		return errors.New("missing policy status store")
	}
	if strings.TrimSpace(opts.endpoint) == "" {
		return errors.New("missing -endpoint")
	}
	if opts.targetRevision == 0 {
		return errors.New("missing -revision")
	}
	if opts.interval <= 0 {
		opts.interval = time.Second
	}
	start := time.Now()
	var lastStatus dataplane.PolicyEndpointStatus
	var lastDoc policyStatusDocument
	var sawEndpoint bool
	for {
		doc, err := store.Load(ctx)
		if err != nil {
			return err
		}
		lastDoc = doc
		statuses := filterPolicyEndpointStatuses(doc.Statuses, opts.endpoint, nil)
		if len(statuses) > 0 {
			lastStatus = statuses[0]
			sawEndpoint = true
			if lastStatus.Revision >= opts.targetRevision {
				output := policyRevisionWaitOutput{
					Ready:          true,
					Node:           doc.Node,
					Store:          doc.Store,
					EndpointID:     lastStatus.EndpointID,
					TargetRevision: opts.targetRevision,
					Revision:       lastStatus.Revision,
					UpdatedAt:      doc.UpdatedAt,
					WaitedMS:       time.Since(start).Milliseconds(),
					Status:         lastStatus,
				}
				encoder := json.NewEncoder(stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(output)
			}
		}
		if opts.timeout == 0 || time.Since(start) >= opts.timeout {
			if !sawEndpoint {
				return fmt.Errorf("policy endpoint %q not found before revision %d", opts.endpoint, opts.targetRevision)
			}
			return fmt.Errorf("policy endpoint %s revision %d did not reach target revision %d before timeout; last status updated at %s",
				lastStatus.EndpointID, lastStatus.Revision, opts.targetRevision, lastDoc.UpdatedAt.Format(time.RFC3339Nano))
		}
		wait := opts.interval
		remaining := opts.timeout - time.Since(start)
		if remaining < wait {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func runAgentStatus(ctx context.Context, args []string, stdout io.Writer) error {
	var opts agentStatusOptions
	flags := flag.NewFlagSet("netloom-agent agent-status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runAgentStatusWithStore(ctx, stdout, linuxdatapath.NewLibOVSDBProviderSyncer(client))
}

func runAgentStatusWithStore(ctx context.Context, stdout io.Writer, store openVSwitchExternalIDStore) error {
	if store == nil {
		return errors.New("missing Open_vSwitch external_id store")
	}
	raw, ok, err := store.OpenVSwitchExternalID(ctx, agentOVSDBStatusKey)
	if err != nil {
		return err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing Open_vSwitch external_ids:%s", agentOVSDBStatusKey)
	}
	var status agentOVSDBStatus
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		return fmt.Errorf("decode Open_vSwitch external_ids:%s: %w", agentOVSDBStatusKey, err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}

func runPolicyEntries(args []string, stdout io.Writer) error {
	var opts policyEntriesOptions
	flags := flag.NewFlagSet("netloom-agent policy-entries", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.stateFile, "state", os.Getenv("NETLOOM_STATE_FILE"), "desired-state JSON path")
	flags.StringVar(&opts.node, "node", os.Getenv("NETLOOM_NODE_NAME"), "node name")
	flags.StringVar(&opts.endpoint, "endpoint", "", "endpoint key or endpoint ID to inspect")
	flags.StringVar(&opts.ruleCookie, "rule-cookie", "", "optional dataplane rule cookie to include")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.endpoint) == "" {
		return errors.New("missing -endpoint")
	}
	if strings.TrimSpace(opts.node) == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		opts.node = hostname
	}

	state, err := loadDesiredStateFromPathOrOVSDB(context.Background(), opts.stateFile, nil)
	if err != nil {
		return err
	}
	state, err = withRuntimeObservationsContext(context.Background(), state)
	if err != nil {
		return err
	}
	store, storeName, closeStore := policyStore()
	defer closeStore()
	result, err := agent.ReconcileNodeWithOptions(context.Background(), state, agent.ReconcileOptions{
		Node:  opts.node,
		Store: store,
	})
	if err != nil {
		return err
	}
	entryStore, ok := store.(agent.PolicyEndpointEntryStore)
	if !ok {
		return errors.New("policy entries are not enabled")
	}
	snapshot := agentMetricsSnapshot{
		Result:  result,
		Store:   storeName,
		State:   state,
		Success: true,
	}
	endpointID, err := resolvePolicyEndpointIDFromSnapshot(opts.endpoint, snapshot)
	if err != nil {
		return err
	}
	filter, err := policyEntryFilterFromValues("", opts.ruleCookie)
	if err != nil {
		return err
	}
	output := policyEntriesOutputFromSnapshot(snapshot, endpointID, entryStore.Entries(endpointID), filter)
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runPolicyEntriesExport(ctx context.Context, args []string, stdout io.Writer) error {
	var opts policyEntriesExportOptions
	flags := flag.NewFlagSet("netloom-agent policy-entries-export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	flags.StringVar(&opts.endpoint, "endpoint", "", "optional endpoint key or endpoint ID to include")
	flags.StringVar(&opts.ruleCookie, "rule-cookie", "", "optional dataplane rule cookie to include")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runPolicyEntriesExportWithStore(ctx, opts, stdout, ovsdbPolicyEntriesStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)})
}

func runPolicyEntriesExportWithStore(ctx context.Context, opts policyEntriesExportOptions, stdout io.Writer, store policyEntriesStore) error {
	if store == nil {
		return errors.New("missing policy entries store")
	}
	doc, err := store.Load(ctx)
	if err != nil {
		return err
	}
	filter, err := policyEntryFilterFromValues(opts.endpoint, opts.ruleCookie)
	if err != nil {
		return err
	}
	output := policyEntriesExportOutputFromDocument(doc, filter)
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runPolicyActionHistory(ctx context.Context, args []string, stdout io.Writer) error {
	opts := policyActionHistoryOptions{limit: defaultPolicyEventsLimit}
	flags := flag.NewFlagSet("netloom-agent policy-action-history", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	flags.StringVar(&opts.endpoint, "endpoint", "", "optional endpoint key or endpoint ID to include")
	flags.StringVar(&opts.action, "action", "", "optional lifecycle action to include")
	flags.StringVar(&opts.success, "success", "", "optional success filter: true or false")
	flags.IntVar(&opts.limit, "limit", defaultPolicyEventsLimit, "maximum recent action history entries")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runPolicyActionHistoryWithStore(ctx, opts, stdout, ovsdbPolicyActionHistoryStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)})
}

func runPolicyActionHistoryWithStore(ctx context.Context, opts policyActionHistoryOptions, stdout io.Writer, store policyActionHistoryStore) error {
	if store == nil {
		return errors.New("missing policy action history store")
	}
	if opts.limit < 0 {
		return fmt.Errorf("invalid limit %d", opts.limit)
	}
	if opts.limit > maxPolicyEventsLimit {
		opts.limit = maxPolicyEventsLimit
	}
	success, err := policyActionSuccessFromString(opts.success)
	if err != nil {
		return err
	}
	history, err := store.Load(ctx)
	if err != nil {
		return err
	}
	endpoint := strings.TrimSpace(opts.endpoint)
	action := strings.TrimSpace(opts.action)
	filtered := filterPolicyActionHistory(history, endpoint, action, success)
	recent := recentPolicyActionHistory(filtered, opts.limit)
	output := policyActionHistoryOutput{
		Ready:          true,
		TotalEvents:    len(history),
		EventCount:     len(recent),
		Limit:          opts.limit,
		FilterEndpoint: endpoint,
		FilterAction:   action,
		FilterSuccess:  success,
		History:        recent,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runPolicyEvents(ctx context.Context, args []string, stdout io.Writer) error {
	opts := policyEventsOptions{limit: defaultPolicyEventsLimit}
	flags := flag.NewFlagSet("netloom-agent policy-events", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	flags.StringVar(&opts.endpoint, "endpoint", "", "optional endpoint key or endpoint ID to include")
	flags.IntVar(&opts.limit, "limit", defaultPolicyEventsLimit, "maximum recent policy update events")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runPolicyEventsWithStore(ctx, opts, stdout, ovsdbPolicyEventsStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)})
}

func runPolicyEventsWithStore(ctx context.Context, opts policyEventsOptions, stdout io.Writer, store policyEventsStore) error {
	if store == nil {
		return errors.New("missing policy events store")
	}
	if opts.limit < 0 {
		return fmt.Errorf("invalid limit %d", opts.limit)
	}
	if opts.limit > maxPolicyEventsLimit {
		opts.limit = maxPolicyEventsLimit
	}
	doc, err := store.Load(ctx)
	if err != nil {
		return err
	}
	endpoint := strings.TrimSpace(opts.endpoint)
	filtered := filterPolicyUpdateEvents(doc.Events, endpoint)
	recent := recentPolicyUpdateEvents(filtered, opts.limit)
	output := policyEventsOutput{
		Node:                 doc.Node,
		Store:                doc.Store,
		Ready:                true,
		LastReconcileSuccess: doc.LastReconcileSuccess,
		LastReconcileError:   doc.LastReconcileError,
		UpdatedAt:            doc.UpdatedAt,
		TotalEvents:          doc.TotalEvents,
		EventCount:           len(recent),
		Limit:                opts.limit,
		FilterEndpoint:       endpoint,
		Events:               recent,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runPolicyRules(ctx context.Context, args []string, stdout io.Writer) error {
	var opts policyRulesOptions
	flags := flag.NewFlagSet("netloom-agent policy-rules", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	flags.StringVar(&opts.endpoint, "endpoint", "", "optional endpoint key or endpoint ID to include")
	flags.StringVar(&opts.ruleCookie, "rule-cookie", "", "optional dataplane rule cookie to include")
	flags.StringVar(&opts.ruleRef, "rule-ref", "", "optional policy rule reference to include")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runPolicyRulesWithStore(ctx, opts, stdout, ovsdbPolicyRulesStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)})
}

func runPolicyRulesWithStore(ctx context.Context, opts policyRulesOptions, stdout io.Writer, store policyRulesStore) error {
	if store == nil {
		return errors.New("missing policy rules store")
	}
	doc, err := store.Load(ctx)
	if err != nil {
		return err
	}
	filter, err := policyRuleFilterFromOptions(opts)
	if err != nil {
		return err
	}
	output := policyRulesOutputFromDocument(doc, filter)
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runPolicyRolloutHistory(ctx context.Context, args []string, stdout io.Writer) error {
	opts := policyRolloutHistoryOptions{limit: defaultPolicyEventsLimit}
	flags := flag.NewFlagSet("netloom-agent policy-rollout-history", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	flags.StringVar(&opts.source, "source", "", "optional rollout history source to include")
	flags.StringVar(&opts.name, "name", "", "optional rollout name to include")
	flags.IntVar(&opts.limit, "limit", defaultPolicyEventsLimit, "maximum recent rollout history entries")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runPolicyRolloutHistoryWithStore(ctx, opts, stdout, ovsdbPolicyRolloutHistoryStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)})
}

func runPolicyRolloutHistoryWithStore(ctx context.Context, opts policyRolloutHistoryOptions, stdout io.Writer, store policyRolloutHistoryStore) error {
	if store == nil {
		return errors.New("missing policy rollout history store")
	}
	if opts.limit < 0 {
		return fmt.Errorf("invalid limit %d", opts.limit)
	}
	if opts.limit > maxPolicyEventsLimit {
		opts.limit = maxPolicyEventsLimit
	}
	history, err := store.Load(ctx)
	if err != nil {
		return err
	}
	source := strings.TrimSpace(opts.source)
	name := strings.TrimSpace(opts.name)
	filtered := filterPolicyRolloutHistory(history, source, name)
	recent := recentPolicyRolloutHistory(filtered, opts.limit)
	output := policyRolloutHistoryOutput{
		Ready:        true,
		TotalEvents:  len(history),
		EventCount:   len(recent),
		Limit:        opts.limit,
		FilterSource: source,
		FilterName:   name,
		History:      recent,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runPolicyRolloutState(ctx context.Context, args []string, stdout io.Writer) error {
	var opts policyRolloutStateOptions
	flags := flag.NewFlagSet("netloom-agent policy-rollout-state", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	flags.StringVar(&opts.name, "name", "", "optional rollout name to include")
	flags.StringVar(&opts.node, "node", "", "optional rollout node to include")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runPolicyRolloutStateWithStore(ctx, opts, stdout, ovsdbPolicyRolloutStateStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)})
}

func runPolicyRolloutStateWithStore(ctx context.Context, opts policyRolloutStateOptions, stdout io.Writer, store policyRolloutStateStore) error {
	if store == nil {
		return errors.New("missing policy rollout state store")
	}
	doc, err := store.Load(ctx)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(opts.name)
	node := strings.TrimSpace(opts.node)
	rollouts := filterPolicyRolloutState(doc.Rollouts, name, node)
	output := policyRolloutStateOutput{
		Ready:         true,
		TotalRollouts: len(doc.Rollouts),
		RolloutCount:  len(rollouts),
		FilterName:    name,
		FilterNode:    node,
		Rollouts:      rollouts,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runPolicyFreezeState(ctx context.Context, args []string, stdout io.Writer) error {
	var opts policyFreezeStateOptions
	flags := flag.NewFlagSet("netloom-agent policy-freeze-state", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	flags.StringVar(&opts.endpoint, "endpoint", "", "optional endpoint key to include")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runPolicyFreezeStateWithStore(ctx, opts, stdout, ovsdbPolicyFreezeStateStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)}, time.Now())
}

func runPolicyFreezeStateWithStore(ctx context.Context, opts policyFreezeStateOptions, stdout io.Writer, store policyFreezeStateStore, now time.Time) error {
	if store == nil {
		return errors.New("missing policy freeze state store")
	}
	doc, err := store.Load(ctx)
	if err != nil {
		return err
	}
	active := normalizePolicyFreezeStateEntries(doc.FrozenEndpoints, now)
	endpoint := strings.TrimSpace(opts.endpoint)
	filtered := filterPolicyFreezeState(active, endpoint)
	output := policyFreezeStateOutput{
		Ready:                 true,
		TotalFrozenEndpoints:  len(doc.FrozenEndpoints),
		ActiveFrozenEndpoints: len(active),
		FilterEndpoint:        endpoint,
		UpdatedAt:             doc.UpdatedAt,
		FrozenEndpoints:       filtered,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runRouteExplain(args []string, stdout io.Writer) error {
	var opts routeExplainOptions
	flags := flag.NewFlagSet("netloom-agent route-explain", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.stateFile, "state", os.Getenv("NETLOOM_STATE_FILE"), "desired-state JSON path")
	flags.StringVar(&opts.vpc, "vpc", "", "packet VPC")
	flags.StringVar(&opts.source, "source", "", "packet source IP")
	flags.StringVar(&opts.dest, "dest", "", "packet destination IP")
	flags.StringVar(&opts.protocol, "protocol", "any", "any, tcp, udp, or icmp")
	flags.UintVar(&opts.sourcePort, "source-port", 0, "source port")
	flags.UintVar(&opts.destPort, "dest-port", 0, "destination port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	state, err := loadDesiredStateFromPathOrOVSDB(context.Background(), opts.stateFile, nil)
	if err != nil {
		return err
	}
	decision, err := explainRouteFromState(state, opts)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(decision)
}

func runIdentityGroupsImport(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	var opts identityGroupsImportOptions
	flags := flag.NewFlagSet("netloom-agent identity-groups-import", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.inputFile, "in", "-", "identity group observations JSON path or - for stdin")
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runIdentityGroupsImportWithStore(ctx, opts, stdin, stdout, linuxdatapath.NewLibOVSDBProviderSyncer(client))
}

func runIdentityGroupsImportWithStore(ctx context.Context, opts identityGroupsImportOptions, stdin io.Reader, stdout io.Writer, store openVSwitchExternalIDStore) error {
	if store == nil {
		return errors.New("missing Open_vSwitch external_id store")
	}
	input, closeInput, err := identityGroupsImportInput(opts.inputFile, stdin)
	if err != nil {
		return err
	}
	if closeInput != nil {
		defer closeInput()
	}
	groups, err := control.LoadIdentityGroupObservationsJSON(input)
	if err != nil {
		return err
	}
	raw, err := control.MarshalIdentityGroupObservationsJSON(groups)
	if err != nil {
		return err
	}
	if err := store.SetOpenVSwitchExternalID(ctx, control.IdentityGroupObservationsOpenVSwitchExternalID, string(raw)); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "identity_groups=%d external_id=%s\n", len(groups), control.IdentityGroupObservationsOpenVSwitchExternalID)
	return err
}

func runIdentityGroupsExport(ctx context.Context, args []string, stdout io.Writer) error {
	var opts identityGroupsExportOptions
	flags := flag.NewFlagSet("netloom-agent identity-groups-export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	flags.StringVar(&opts.source, "source", "resolved", "identity group source: resolved or observations")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runIdentityGroupsExportWithStore(ctx, opts, stdout, linuxdatapath.NewLibOVSDBProviderSyncer(client))
}

func runIdentityGroupsExportWithStore(ctx context.Context, opts identityGroupsExportOptions, stdout io.Writer, store openVSwitchExternalIDStore) error {
	if store == nil {
		return errors.New("missing Open_vSwitch external_id store")
	}
	key, err := identityGroupsExportExternalID(opts.source)
	if err != nil {
		return err
	}
	raw, ok, err := store.OpenVSwitchExternalID(ctx, key)
	if err != nil {
		return err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing Open_vSwitch external_ids:%s", key)
	}
	var document any
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return fmt.Errorf("decode Open_vSwitch external_ids:%s: %w", key, err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func identityGroupsExportExternalID(source string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "resolved":
		return identityGroupsStateKey, nil
	case "observations", "observed":
		return control.IdentityGroupObservationsOpenVSwitchExternalID, nil
	default:
		return "", fmt.Errorf("unsupported identity groups source %q", source)
	}
}

func runDNSObservationsExport(ctx context.Context, args []string, stdout io.Writer) error {
	var opts dnsObservationsExportOptions
	flags := flag.NewFlagSet("netloom-agent dns-observations-export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runDNSObservationsExportWithStore(ctx, stdout, ovsdbDNSObservationStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)})
}

func runDNSObservationsExportWithStore(ctx context.Context, stdout io.Writer, store dnsObservationStore) error {
	if store == nil {
		return errors.New("missing DNS observation store")
	}
	records, err := store.LoadDNSObservations(ctx)
	if err != nil {
		return err
	}
	raw, err := control.MarshalDNSObservationsJSON(records)
	if err != nil {
		return err
	}
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func runDesiredStateImport(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	var opts desiredStateImportOptions
	flags := flag.NewFlagSet("netloom-agent desired-state-import", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.inputFile, "in", "-", "desired-state JSON path or - for stdin")
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runDesiredStateImportWithStore(ctx, opts, stdin, stdout, linuxdatapath.NewLibOVSDBProviderSyncer(client))
}

func runDesiredStateImportWithStore(ctx context.Context, opts desiredStateImportOptions, stdin io.Reader, stdout io.Writer, store openVSwitchExternalIDStore) error {
	if store == nil {
		return errors.New("missing Open_vSwitch external_id store")
	}
	input, closeInput, err := desiredStateImportInput(opts.inputFile, stdin)
	if err != nil {
		return err
	}
	if closeInput != nil {
		defer closeInput()
	}
	state, err := control.LoadDesiredStateJSON(input)
	if err != nil {
		return err
	}
	raw, err := control.MarshalDesiredStateJSON(state)
	if err != nil {
		return err
	}
	summary, err := control.MarshalDesiredStateSummaryJSON(state)
	if err != nil {
		return err
	}
	if err := store.SetOpenVSwitchExternalID(ctx, "netloom_owner", "netloom"); err != nil {
		return err
	}
	if err := store.SetOpenVSwitchExternalID(ctx, control.DesiredStateOpenVSwitchExternalID, string(raw)); err != nil {
		return err
	}
	revision := control.DesiredStateRevision(raw)
	if err := store.SetOpenVSwitchExternalID(ctx, control.DesiredStateRevisionOpenVSwitchExternalID, revision); err != nil {
		return err
	}
	if err := store.SetOpenVSwitchExternalID(ctx, control.DesiredStateSummaryOpenVSwitchExternalID, string(summary)); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "desired_state vpcs=%d subnets=%d endpoints=%d revision=%s external_id=%s\n", len(state.VPCs), len(state.Subnets), len(state.Endpoints), revision, control.DesiredStateOpenVSwitchExternalID)
	return err
}

func runDesiredStateExport(ctx context.Context, args []string, stdout io.Writer) error {
	var opts desiredStateExportOptions
	flags := flag.NewFlagSet("netloom-agent desired-state-export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.ovsdb, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ovsdb) == "" {
		return errors.New("missing -ovsdb or NETLOOM_OVSDB_ENDPOINT")
	}
	client, closeStore, err := newOpenVSwitchClient(ctx, opts.ovsdb)
	if err != nil {
		return err
	}
	defer closeStore()
	return runDesiredStateExportWithStore(ctx, stdout, linuxdatapath.NewLibOVSDBProviderSyncer(client))
}

func runDesiredStateExportWithStore(ctx context.Context, stdout io.Writer, store openVSwitchExternalIDStore) error {
	if store == nil {
		return errors.New("missing Open_vSwitch external_id store")
	}
	state, err := loadDesiredStateFromPathOrOVSDB(ctx, "", store)
	if err != nil {
		return err
	}
	raw, err := control.MarshalDesiredStateJSON(state)
	if err != nil {
		return err
	}
	_, err = stdout.Write(append(raw, '\n'))
	return err
}

func identityGroupsImportInput(path string, stdin io.Reader) (io.Reader, func(), error) {
	return desiredStateImportInput(path, stdin)
}

func desiredStateImportInput(path string, stdin io.Reader) (io.Reader, func(), error) {
	path = strings.TrimSpace(path)
	if path == "" || path == "-" {
		if stdin == nil {
			return nil, nil, errors.New("missing stdin")
		}
		return stdin, nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return file, func() { _ = file.Close() }, nil
}

func loadDesiredStateFromPathOrOVSDB(ctx context.Context, path string, store openVSwitchExternalIDStore) (control.DesiredState, error) {
	path = strings.TrimSpace(path)
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return control.DesiredState{}, err
		}
		defer file.Close()
		return control.LoadDesiredStateJSON(file)
	}
	if store == nil {
		envStore, closeStore, err := identityGroupObservationStoreFromEnv(ctx)
		if err != nil {
			return control.DesiredState{}, err
		}
		defer closeStore()
		store = envStore
	}
	if store == nil {
		return control.DesiredState{}, errors.New("missing -state, NETLOOM_STATE_FILE, or NETLOOM_OVSDB_ENDPOINT with Open_vSwitch desired state")
	}
	raw, ok, err := store.OpenVSwitchExternalID(ctx, control.DesiredStateOpenVSwitchExternalID)
	if err != nil {
		return control.DesiredState{}, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return control.DesiredState{}, fmt.Errorf("missing Open_vSwitch external_ids:%s", control.DesiredStateOpenVSwitchExternalID)
	}
	revision, _, err := store.OpenVSwitchExternalID(ctx, control.DesiredStateRevisionOpenVSwitchExternalID)
	if err != nil {
		return control.DesiredState{}, err
	}
	if err := control.ValidateDesiredStateRevision([]byte(raw), revision); err != nil {
		return control.DesiredState{}, fmt.Errorf("validate Open_vSwitch external_ids:%s: %w", control.DesiredStateRevisionOpenVSwitchExternalID, err)
	}
	state, err := control.LoadDesiredStateJSON(strings.NewReader(raw))
	if err != nil {
		return control.DesiredState{}, fmt.Errorf("decode Open_vSwitch external_ids:%s: %w", control.DesiredStateOpenVSwitchExternalID, err)
	}
	return state, nil
}

func filterPolicyEndpointStatuses(statuses []dataplane.PolicyEndpointStatus, endpoint string, endpoints []model.Endpoint) []dataplane.PolicyEndpointStatus {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return append([]dataplane.PolicyEndpointStatus(nil), statuses...)
	}
	keys := map[string]struct{}{endpoint: {}}
	if vpc, id, ok := strings.Cut(endpoint, "/"); ok && vpc != "" && id != "" {
		keys[model.EndpointKey(vpc, id)] = struct{}{}
	}
	for _, candidate := range endpoints {
		if candidate.ID == endpoint {
			keys[model.EndpointKey(candidate.VPC, candidate.ID)] = struct{}{}
		}
	}
	filtered := make([]dataplane.PolicyEndpointStatus, 0, len(statuses))
	for _, status := range statuses {
		if _, ok := keys[status.EndpointID]; ok {
			filtered = append(filtered, status)
			continue
		}
		if vpc, id, ok := strings.Cut(status.EndpointID, "\x00"); ok && (id == endpoint || vpc+"/"+id == endpoint) {
			filtered = append(filtered, status)
		}
	}
	return filtered
}

func policyStatusOutputFromResult(result agent.ReconcileResult, storeName string, statuses []dataplane.PolicyEndpointStatus) policyStatusOutput {
	return policyStatusOutput{
		Node:              result.Node,
		Store:             storeName,
		EndpointCount:     len(statuses),
		PolicyMapEntries:  result.PolicyMapEntries,
		PolicyMapCapacity: result.PolicyMapCapacity,
		PressureMax:       result.PolicyMapPressureMax,
		PressureEndpoint:  result.PolicyMapPressureEndpoint,
		PressureEndpoints: result.PolicyMapPressureEndpoints,
		PressureHotspots:  append([]dataplane.PolicyMapPressureHotspot(nil), result.PolicyMapPressureHotspots...),
		DriftEndpoints:    result.PolicyMapDriftEndpoints,
		DriftMissing:      result.PolicyMapDriftMissing,
		DriftExtra:        result.PolicyMapDriftExtra,
		DriftChanged:      result.PolicyMapDriftChanged,
		PolicyRevisionMax: result.PolicyRevisionMax,
		Statuses:          statuses,
	}
}

func policyStatusOutputFromDocument(doc policyStatusDocument, endpoint string) policyStatusOutput {
	filtered := filterPolicyEndpointStatuses(doc.Statuses, endpoint, nil)
	return policyStatusOutput{
		Node:                 doc.Node,
		Store:                doc.Store,
		Ready:                true,
		LastReconcileSuccess: doc.LastReconcileSuccess,
		LastReconcileError:   doc.LastReconcileError,
		UpdatedAt:            doc.UpdatedAt,
		FilterEndpoint:       strings.TrimSpace(endpoint),
		EndpointCount:        len(filtered),
		PolicyMapEntries:     doc.PolicyMapEntries,
		PolicyMapCapacity:    doc.PolicyMapCapacity,
		PressureMax:          doc.PressureMax,
		PressureEndpoint:     doc.PressureEndpoint,
		PressureEndpoints:    doc.PressureEndpoints,
		PressureHotspots:     append([]dataplane.PolicyMapPressureHotspot(nil), doc.PressureHotspots...),
		DriftEndpoints:       doc.DriftEndpoints,
		DriftMissing:         doc.DriftMissing,
		DriftExtra:           doc.DriftExtra,
		DriftChanged:         doc.DriftChanged,
		PolicyRevisionMax:    doc.PolicyRevisionMax,
		Statuses:             filtered,
	}
}

func policyStatusDocumentFromSnapshot(snapshot agentMetricsSnapshot) policyStatusDocument {
	statuses := append([]dataplane.PolicyEndpointStatus(nil), snapshot.Result.PolicyEndpointStatus...)
	return policyStatusDocument{
		Node:                 snapshot.Result.Node,
		Store:                snapshot.Store,
		LastReconcileSuccess: snapshot.Success,
		LastReconcileError:   snapshot.Error,
		UpdatedAt:            time.Now().UTC(),
		EndpointCount:        len(statuses),
		PolicyMapEntries:     snapshot.Result.PolicyMapEntries,
		PolicyMapCapacity:    snapshot.Result.PolicyMapCapacity,
		PressureMax:          snapshot.Result.PolicyMapPressureMax,
		PressureEndpoint:     snapshot.Result.PolicyMapPressureEndpoint,
		PressureEndpoints:    snapshot.Result.PolicyMapPressureEndpoints,
		PressureHotspots:     append([]dataplane.PolicyMapPressureHotspot(nil), snapshot.Result.PolicyMapPressureHotspots...),
		DriftEndpoints:       snapshot.Result.PolicyMapDriftEndpoints,
		DriftMissing:         snapshot.Result.PolicyMapDriftMissing,
		DriftExtra:           snapshot.Result.PolicyMapDriftExtra,
		DriftChanged:         snapshot.Result.PolicyMapDriftChanged,
		PolicyRevisionMax:    snapshot.Result.PolicyRevisionMax,
		Statuses:             statuses,
	}
}

type policyRuleFilter struct {
	Endpoint   string
	RuleCookie *uint32
	RuleRef    string
}

func policyRuleFilterFromOptions(opts policyRulesOptions) (policyRuleFilter, error) {
	return policyRuleFilterFromValues(opts.endpoint, opts.ruleCookie, opts.ruleRef)
}

func policyRuleFilterFromRequest(r *http.Request, endpoint string) (policyRuleFilter, error) {
	return policyRuleFilterFromValues(endpoint, r.URL.Query().Get("rule_cookie"), r.URL.Query().Get("rule_ref"))
}

func policyRuleFilterFromValues(endpoint, ruleCookie, ruleRef string) (policyRuleFilter, error) {
	filter := policyRuleFilter{
		Endpoint: strings.TrimSpace(endpoint),
		RuleRef:  strings.TrimSpace(ruleRef),
	}
	ruleCookie = strings.TrimSpace(ruleCookie)
	if ruleCookie == "" {
		return filter, nil
	}
	value, err := strconv.ParseUint(ruleCookie, 10, 32)
	if err != nil {
		return filter, fmt.Errorf("invalid rule cookie %q", ruleCookie)
	}
	cookie := uint32(value)
	filter.RuleCookie = &cookie
	return filter, nil
}

func policyRulesOutputFromResult(result agent.ReconcileResult, storeName string, filter policyRuleFilter) policyRulesOutput {
	stats := filterPolicyRuleStats(result.PolicyRuleStats, filter.Endpoint)
	catalog := filterPolicyRuleCatalog(result.PolicyRuleCatalog, filter.Endpoint)
	rules := filterPolicyRuleOutputs(mergePolicyRuleStatsAndCatalog(stats, catalog), filter)
	output := policyRulesOutputFromRules(result.Node, storeName, rules, filter)
	return output
}

func policyRulesOutputFromDocument(doc policyRulesDocument, filter policyRuleFilter) policyRulesOutput {
	rules := filterPolicyRuleOutputs(doc.Rules, filter)
	output := policyRulesOutputFromRules(doc.Node, doc.Store, rules, filter)
	output.Ready = true
	output.LastReconcileSuccess = doc.LastReconcileSuccess
	output.LastReconcileError = doc.LastReconcileError
	output.UpdatedAt = doc.UpdatedAt
	return output
}

func policyRulesOutputFromRules(node, store string, rules []policyRuleOutput, filter policyRuleFilter) policyRulesOutput {
	output := policyRulesOutput{
		Node:             node,
		Store:            store,
		FilterEndpoint:   filter.Endpoint,
		FilterRuleRef:    filter.RuleRef,
		FilterRuleCookie: filterRuleCookieValue(filter),
		RuleCount:        len(rules),
		Rules:            rules,
	}
	for _, rule := range rules {
		output.Packets += rule.Packets
		output.Bytes += rule.Bytes
		output.Allowed += rule.Allowed
		output.Dropped += rule.Dropped
		output.Rejected += rule.Rejected
		output.NoMatchDrops += rule.NoMatchDrops
		output.DenyDrops += rule.DenyDrops
		output.RejectDrops += rule.RejectDrops
		output.Conntrack += rule.Conntrack
		output.Established += rule.Established
		output.Logged += rule.Logged
	}
	return output
}

const (
	defaultPolicyEventsLimit = 100
	maxPolicyEventsLimit     = 1000
)

func policyEventsOutputFromSnapshot(snapshot agentMetricsSnapshot, events []dataplane.PolicyUpdateEvent, endpoint string, limit int) policyEventsOutput {
	filtered := filterPolicyUpdateEvents(events, endpoint)
	recent := recentPolicyUpdateEvents(filtered, limit)
	return policyEventsOutput{
		Node:                 snapshot.Result.Node,
		Store:                snapshot.Store,
		Ready:                true,
		LastReconcileSuccess: snapshot.Success,
		LastReconcileError:   snapshot.Error,
		TotalEvents:          len(events),
		EventCount:           len(recent),
		Limit:                limit,
		FilterEndpoint:       strings.TrimSpace(endpoint),
		Events:               recent,
	}
}

type policyEntryFilter struct {
	Endpoint   string
	RuleCookie *uint32
}

func policyEntryFilterFromRequest(r *http.Request, endpoint string) (policyEntryFilter, error) {
	return policyEntryFilterFromValues(endpoint, r.URL.Query().Get("rule_cookie"))
}

func policyEntryFilterFromValues(endpoint, ruleCookie string) (policyEntryFilter, error) {
	filter := policyEntryFilter{Endpoint: strings.TrimSpace(endpoint)}
	ruleCookie = strings.TrimSpace(ruleCookie)
	if ruleCookie == "" {
		return filter, nil
	}
	value, err := strconv.ParseUint(ruleCookie, 10, 32)
	if err != nil {
		return filter, fmt.Errorf("invalid rule cookie %q", ruleCookie)
	}
	cookie := uint32(value)
	filter.RuleCookie = &cookie
	return filter, nil
}

func policyEntriesOutputFromSnapshot(snapshot agentMetricsSnapshot, endpointID string, entries []dataplane.PolicyMapEntry, filter policyEntryFilter) policyEntriesOutput {
	entries = filterDataplanePolicyEntries(entries, filter)
	output := policyEntriesOutput{
		Node:                 snapshot.Result.Node,
		Store:                snapshot.Store,
		Ready:                true,
		LastReconcileSuccess: snapshot.Success,
		LastReconcileError:   snapshot.Error,
		EndpointID:           endpointID,
		FilterRuleCookie:     filterEntryRuleCookieValue(filter),
		EntryCount:           len(entries),
		Entries:              make([]policyMapEntryOutput, 0, len(entries)),
	}
	for _, entry := range entries {
		output.Entries = append(output.Entries, policyMapEntryOutputFromEntry(entry))
	}
	return output
}

func policyEntriesExportOutputFromDocument(doc policyEntriesDocument, filter policyEntryFilter) policyEntriesExportOutput {
	filtered := filterPolicyEntryEndpoints(doc.Endpoints, filter)
	return policyEntriesExportOutput{
		Node:                 doc.Node,
		Store:                doc.Store,
		Ready:                true,
		LastReconcileSuccess: doc.LastReconcileSuccess,
		LastReconcileError:   doc.LastReconcileError,
		UpdatedAt:            doc.UpdatedAt,
		TotalEndpoints:       len(doc.Endpoints),
		EndpointCount:        len(filtered),
		FilterEndpoint:       filter.Endpoint,
		FilterRuleCookie:     filterEntryRuleCookieValue(filter),
		Endpoints:            filtered,
	}
}

func filterPolicyEntryEndpoints(endpoints []policyEntriesEndpointOutput, filter policyEntryFilter) []policyEntriesEndpointOutput {
	if filter.Endpoint == "" && filter.RuleCookie == nil {
		return append([]policyEntriesEndpointOutput(nil), endpoints...)
	}
	out := make([]policyEntriesEndpointOutput, 0, len(endpoints))
	for _, entry := range endpoints {
		if filter.Endpoint != "" && !policyRuleEndpointMatches(entry.EndpointID, filter.Endpoint) {
			continue
		}
		next := entry
		next.Entries = filterPolicyMapEntryOutputs(entry.Entries, filter)
		next.EntryCount = len(next.Entries)
		if filter.RuleCookie != nil && len(next.Entries) == 0 {
			continue
		}
		out = append(out, next)
	}
	return out
}

func filterDataplanePolicyEntries(entries []dataplane.PolicyMapEntry, filter policyEntryFilter) []dataplane.PolicyMapEntry {
	if filter.RuleCookie == nil {
		return append([]dataplane.PolicyMapEntry(nil), entries...)
	}
	out := make([]dataplane.PolicyMapEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Value.RuleCookie == *filter.RuleCookie {
			out = append(out, entry)
		}
	}
	return out
}

func filterPolicyMapEntryOutputs(entries []policyMapEntryOutput, filter policyEntryFilter) []policyMapEntryOutput {
	if filter.RuleCookie == nil {
		return append([]policyMapEntryOutput(nil), entries...)
	}
	out := make([]policyMapEntryOutput, 0, len(entries))
	for _, entry := range entries {
		if entry.Value.RuleCookie == *filter.RuleCookie {
			out = append(out, entry)
		}
	}
	return out
}

func filterEntryRuleCookieValue(filter policyEntryFilter) uint32 {
	if filter.RuleCookie == nil {
		return 0
	}
	return *filter.RuleCookie
}

func policyEntriesEndpointOutputFromEntries(endpointID string, entries []dataplane.PolicyMapEntry) policyEntriesEndpointOutput {
	output := policyEntriesEndpointOutput{
		EndpointID: endpointID,
		EntryCount: len(entries),
		Entries:    make([]policyMapEntryOutput, 0, len(entries)),
	}
	for _, entry := range entries {
		output.Entries = append(output.Entries, policyMapEntryOutputFromEntry(entry))
	}
	return output
}

func policyMapEntryOutputFromEntry(entry dataplane.PolicyMapEntry) policyMapEntryOutput {
	out := policyMapEntryOutput{
		Key: policyMapKeyOutput{
			PrefixLen:      entry.Key.PrefixLen,
			RemoteIdentity: entry.Key.RemoteIdentity,
			Direction:      entry.Key.Direction,
			Protocol:       entry.Key.Protocol,
			DestPortBE:     entry.Key.DestPortBE,
		},
		Value: policyMapValueOutput{
			Deny:            entry.Value.Deny,
			L4PrefixLen:     entry.Value.L4PrefixLen,
			Stateful:        entry.Value.Stateful,
			Log:             entry.Value.Log,
			Precedence:      entry.Value.Precedence,
			RuleCookie:      entry.Value.RuleCookie,
			Reject:          entry.Value.Reject,
			RequireIdentity: entry.Value.RequireIdentity,
			Packets:         entry.Value.Packets,
			Bytes:           entry.Value.Bytes,
		},
	}
	if entry.RemoteCIDR.IsValid() {
		out.RemoteCIDR = entry.RemoteCIDR.String()
	}
	return out
}

func filterPolicyUpdateEvents(events []dataplane.PolicyUpdateEvent, endpoint string) []dataplane.PolicyUpdateEvent {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return append([]dataplane.PolicyUpdateEvent(nil), events...)
	}
	out := make([]dataplane.PolicyUpdateEvent, 0, len(events))
	for _, event := range events {
		if policyRuleEndpointMatches(event.EndpointID, endpoint) {
			out = append(out, event)
		}
	}
	return out
}

func recentPolicyUpdateEvents(events []dataplane.PolicyUpdateEvent, limit int) []dataplane.PolicyUpdateEvent {
	if limit <= 0 {
		return nil
	}
	if len(events) <= limit {
		return append([]dataplane.PolicyUpdateEvent(nil), events...)
	}
	return append([]dataplane.PolicyUpdateEvent(nil), events[len(events)-limit:]...)
}

func trimPolicyUpdateEvents(events []dataplane.PolicyUpdateEvent) []dataplane.PolicyUpdateEvent {
	const limit = 128
	if len(events) <= limit {
		return append([]dataplane.PolicyUpdateEvent(nil), events...)
	}
	return append([]dataplane.PolicyUpdateEvent(nil), events[len(events)-limit:]...)
}

func filterPolicyRuleOutputs(rules []policyRuleOutput, filter policyRuleFilter) []policyRuleOutput {
	if filter.Endpoint == "" && filter.RuleCookie == nil && filter.RuleRef == "" {
		return append([]policyRuleOutput(nil), rules...)
	}
	out := make([]policyRuleOutput, 0, len(rules))
	for _, rule := range rules {
		if policyRuleMatches(rule, filter) {
			out = append(out, rule)
		}
	}
	return out
}

func policyRuleMatches(rule policyRuleOutput, filter policyRuleFilter) bool {
	if filter.Endpoint != "" && !policyRuleEndpointMatches(rule.EndpointID, filter.Endpoint) {
		return false
	}
	if filter.RuleCookie != nil && rule.RuleCookie != *filter.RuleCookie {
		return false
	}
	if filter.RuleRef != "" && rule.RuleRef != filter.RuleRef {
		return false
	}
	return true
}

func filterRuleCookieValue(filter policyRuleFilter) uint32 {
	if filter.RuleCookie == nil {
		return 0
	}
	return *filter.RuleCookie
}

func filterPolicyRuleStats(stats []dataplane.RuleMetrics, endpoint string) []dataplane.RuleMetrics {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return append([]dataplane.RuleMetrics(nil), stats...)
	}
	out := make([]dataplane.RuleMetrics, 0, len(stats))
	for _, stat := range stats {
		if policyRuleEndpointMatches(stat.EndpointID, endpoint) {
			out = append(out, stat)
		}
	}
	return out
}

func filterPolicyRuleCatalog(catalog []agent.PolicyRuleCatalogEntry, endpoint string) []agent.PolicyRuleCatalogEntry {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return append([]agent.PolicyRuleCatalogEntry(nil), catalog...)
	}
	out := make([]agent.PolicyRuleCatalogEntry, 0, len(catalog))
	for _, entry := range catalog {
		if policyRuleEndpointMatches(entry.EndpointID, endpoint) {
			out = append(out, entry)
		}
	}
	return out
}

func policyRuleEndpointMatches(endpointID, endpoint string) bool {
	if endpointID == endpoint {
		return true
	}
	if vpc, id, ok := strings.Cut(endpointID, "\x00"); ok {
		return id == endpoint || vpc+"/"+id == endpoint
	}
	return false
}

func mergePolicyRuleStatsAndCatalog(stats []dataplane.RuleMetrics, catalog []agent.PolicyRuleCatalogEntry) []policyRuleOutput {
	byKey := make(map[string]policyRuleOutput, len(stats)+len(catalog))
	for _, entry := range catalog {
		key := policyRuleMetricKey(entry.EndpointID, entry.RuleCookie)
		rule := byKey[key]
		rule.EndpointID = entry.EndpointID
		rule.RuleCookie = entry.RuleCookie
		rule.RuleRef = entry.RuleRef
		rule.VPC = entry.VPC
		rule.SecurityGroup = entry.SecurityGroup
		rule.RuleID = entry.RuleID
		byKey[key] = rule
	}
	for _, stat := range stats {
		key := policyRuleMetricKey(stat.EndpointID, stat.RuleCookie)
		rule := byKey[key]
		rule.EndpointID = stat.EndpointID
		rule.RuleCookie = stat.RuleCookie
		rule.Packets = stat.Packets
		rule.Bytes = stat.Bytes
		rule.Allowed = stat.Allowed
		rule.Dropped = stat.Dropped
		rule.Rejected = stat.Rejected
		rule.NoMatchDrops = stat.NoMatchDrops
		rule.DenyDrops = stat.DenyDrops
		rule.RejectDrops = stat.RejectDrops
		rule.Conntrack = stat.Conntrack
		rule.Established = stat.Established
		rule.Logged = stat.Logged
		byKey[key] = rule
	}
	out := make([]policyRuleOutput, 0, len(byKey))
	for _, rule := range byKey {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EndpointID != out[j].EndpointID {
			return out[i].EndpointID < out[j].EndpointID
		}
		return out[i].RuleCookie < out[j].RuleCookie
	})
	return out
}

func explainRouteFromState(state control.DesiredState, opts routeExplainOptions) (topology.Decision, error) {
	packet, err := routePacketFromExplainOptions(opts)
	if err != nil {
		return topology.Decision{}, err
	}
	return topology.Resolve(topologyStateFromDesired(state), packet)
}

func routePacketFromExplainOptions(opts routeExplainOptions) (topology.Packet, error) {
	if opts.vpc == "" {
		return topology.Packet{}, errors.New("missing -vpc")
	}
	source, err := parseRequiredAddr("source", opts.source)
	if err != nil {
		return topology.Packet{}, err
	}
	dest, err := parseRequiredAddr("dest", opts.dest)
	if err != nil {
		return topology.Packet{}, err
	}
	protocol, err := parseRouteProtocol(opts.protocol)
	if err != nil {
		return topology.Packet{}, err
	}
	sourcePort, err := parseUint16Flag("source-port", opts.sourcePort)
	if err != nil {
		return topology.Packet{}, err
	}
	destPort, err := parseUint16Flag("dest-port", opts.destPort)
	if err != nil {
		return topology.Packet{}, err
	}
	return topology.Packet{
		SourcePort: sourcePort,
		VPC:        opts.vpc,
		Source:     source,
		Dest:       dest,
		Protocol:   protocol,
		DestPort:   destPort,
	}, nil
}

func parseRouteProtocol(value string) (model.Protocol, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(model.ProtocolAny):
		return model.ProtocolAny, nil
	case string(model.ProtocolTCP):
		return model.ProtocolTCP, nil
	case string(model.ProtocolUDP):
		return model.ProtocolUDP, nil
	case string(model.ProtocolICMP), "icmpv6":
		return model.ProtocolICMP, nil
	default:
		return "", fmt.Errorf("unsupported protocol %q", value)
	}
}

func topologyStateFromDesired(state control.DesiredState) topology.State {
	vpcs := make(map[string]model.VPC, len(state.VPCs))
	for _, vpc := range state.VPCs {
		vpcs[vpc.Name] = vpc
	}
	subnets := make(map[string]model.Subnet, len(state.Subnets))
	for _, subnet := range state.Subnets {
		subnets[subnet.VPC+"\x00"+subnet.Name] = subnet
	}
	endpoints := make(map[string]model.Endpoint, len(state.Endpoints))
	for _, endpoint := range state.Endpoints {
		endpoints[model.EndpointKey(endpoint.VPC, endpoint.ID)] = endpoint
	}
	routeTables := make(map[string]model.RouteTable, len(state.RouteTables))
	for _, table := range state.RouteTables {
		routeTables[table.VPC+"\x00"+table.Name] = table
	}
	gateways := make(map[string]model.Gateway, len(state.Gateways))
	for _, gateway := range state.Gateways {
		gateways[gateway.VPC+"\x00"+gateway.Name] = gateway
	}
	natRules := make(map[string]model.NATRule, len(state.NATRules))
	for _, rule := range state.NATRules {
		natRules[rule.VPC+"\x00"+rule.Name] = rule
	}
	loadBalancers := make(map[string]model.LoadBalancer, len(state.LoadBalancers))
	for _, lb := range state.LoadBalancers {
		loadBalancers[lb.VPC+"\x00"+lb.Name] = lb
	}
	return topology.State{
		VPCs:          vpcs,
		Subnets:       subnets,
		Endpoints:     endpoints,
		RouteTables:   routeTables,
		PolicyRoutes:  append([]model.PolicyRoute(nil), state.PolicyRoutes...),
		Gateways:      gateways,
		NATRules:      natRules,
		LoadBalancers: loadBalancers,
	}
}

func cloneDesiredState(state control.DesiredState) control.DesiredState {
	return control.DesiredState{
		VPCs:             append([]model.VPC(nil), state.VPCs...),
		Subnets:          append([]model.Subnet(nil), state.Subnets...),
		Endpoints:        append([]model.Endpoint(nil), state.Endpoints...),
		RouteTables:      append([]model.RouteTable(nil), state.RouteTables...),
		PolicyRoutes:     append([]model.PolicyRoute(nil), state.PolicyRoutes...),
		Gateways:         append([]model.Gateway(nil), state.Gateways...),
		NATRules:         append([]model.NATRule(nil), state.NATRules...),
		LoadBalancers:    append([]model.LoadBalancer(nil), state.LoadBalancers...),
		SecurityGroups:   append([]model.SecurityGroup(nil), state.SecurityGroups...),
		CIDRGroups:       append([]model.CIDRGroup(nil), state.CIDRGroups...),
		ProviderNetworks: append([]model.ProviderNetwork(nil), state.ProviderNetworks...),
		IdentityGroups:   append([]model.IdentityGroup(nil), state.IdentityGroups...),
		DNSRecords:       append([]model.DNSRecord(nil), state.DNSRecords...),
		PolicyRollouts:   append([]control.PolicyRollout(nil), state.PolicyRollouts...),
	}
}

func explainPolicyFromState(state control.DesiredState, opts policyExplainOptions) (dataplane.PolicyExplanation, error) {
	endpoint, ok := findEndpoint(state.Endpoints, opts.vpc, opts.endpoint)
	if !ok {
		return dataplane.PolicyExplanation{}, fmt.Errorf("endpoint %s/%s not found", opts.vpc, opts.endpoint)
	}
	remoteEndpoint, hasRemoteEndpoint, err := resolveRemoteEndpoint(state.Endpoints, opts)
	if err != nil {
		return dataplane.PolicyExplanation{}, err
	}
	groups := securityGroupsForEndpoint(state.SecurityGroups, endpoint.VPC)
	program, err := policy.CompileForEndpointWithContext(endpoint, groups, policy.CompileContext{
		Endpoints:  state.Endpoints,
		Subnets:    state.Subnets,
		Gateways:   state.Gateways,
		Services:   state.LoadBalancers,
		DNSRecords: state.DNSRecords,
		CIDRGroups: state.CIDRGroups,
	})
	if err != nil {
		return dataplane.PolicyExplanation{}, err
	}
	entries, err := dataplane.EncodeProgram(program)
	if err != nil {
		return dataplane.PolicyExplanation{}, err
	}
	packet, err := packetFromExplainOptions(opts, remoteEndpoint, hasRemoteEndpoint)
	if err != nil {
		return dataplane.PolicyExplanation{}, err
	}
	if opts.stateful {
		return dataplane.ExplainStateful(program.EndpointID, entries, packet, dataplane.NewInMemoryConntrackStore()), nil
	}
	return dataplane.Explain(program.EndpointID, entries, packet), nil
}

func securityGroupsForEndpoint(groups []model.SecurityGroup, vpc string) map[string]model.SecurityGroup {
	out := make(map[string]model.SecurityGroup, len(groups))
	for _, group := range groups {
		if group.VPC == vpc {
			out[group.Name] = group
		}
	}
	return out
}

func findEndpoint(endpoints []model.Endpoint, vpc, id string) (model.Endpoint, bool) {
	for _, endpoint := range endpoints {
		if endpoint.VPC == vpc && endpoint.ID == id {
			return endpoint, true
		}
	}
	return model.Endpoint{}, false
}

func resolveRemoteEndpoint(endpoints []model.Endpoint, opts policyExplainOptions) (model.Endpoint, bool, error) {
	if opts.remoteEndpoint == "" {
		return model.Endpoint{}, false, nil
	}
	remoteVPC := opts.remoteVPC
	if remoteVPC == "" {
		remoteVPC = opts.vpc
	}
	endpoint, ok := findEndpoint(endpoints, remoteVPC, opts.remoteEndpoint)
	if !ok {
		return model.Endpoint{}, false, fmt.Errorf("remote endpoint %s/%s not found", remoteVPC, opts.remoteEndpoint)
	}
	return endpoint, true, nil
}

func packetFromExplainOptions(opts policyExplainOptions, remoteEndpoint model.Endpoint, hasRemoteEndpoint bool) (dataplane.Packet, error) {
	direction, err := parsePacketDirection(opts.direction)
	if err != nil {
		return dataplane.Packet{}, err
	}
	remoteIP, err := parseOptionalAddr(opts.remoteIP)
	if err != nil {
		return dataplane.Packet{}, err
	}
	remoteIdentity := uint32(opts.remoteIdentity)
	if hasRemoteEndpoint {
		if !remoteIP.IsValid() {
			remoteIP = remoteEndpoint.IP
		}
		if remoteIdentity == 0 {
			remoteIdentity = policy.EndpointIdentity(model.EndpointKey(remoteEndpoint.VPC, remoteEndpoint.ID))
		}
	}
	protocol, err := parsePacketProtocol(opts.protocol, remoteIP)
	if err != nil {
		return dataplane.Packet{}, err
	}
	sourcePort, err := parseUint16Flag("source-port", opts.sourcePort)
	if err != nil {
		return dataplane.Packet{}, err
	}
	destPort, err := parseUint16Flag("dest-port", opts.destPort)
	if err != nil {
		return dataplane.Packet{}, err
	}
	icmpType, err := parseUint8Flag("icmp-type", opts.icmpType)
	if err != nil {
		return dataplane.Packet{}, err
	}
	icmpCode, err := parseUint8Flag("icmp-code", opts.icmpCode)
	if err != nil {
		return dataplane.Packet{}, err
	}
	return dataplane.Packet{
		SourcePort:     sourcePort,
		RemoteIdentity: remoteIdentity,
		RemoteIP:       remoteIP,
		Direction:      direction,
		Protocol:       protocol,
		DestPort:       destPort,
		ICMPType:       icmpType,
		ICMPCode:       icmpCode,
	}, nil
}

func parsePacketDirection(value string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(model.DirectionIngress):
		return dataplane.DirectionIngress, nil
	case string(model.DirectionEgress):
		return dataplane.DirectionEgress, nil
	default:
		return 0, fmt.Errorf("unsupported direction %q", value)
	}
}

func parsePacketProtocol(value string, remoteIP netip.Addr) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(model.ProtocolAny):
		return 0, nil
	case string(model.ProtocolTCP):
		return 6, nil
	case string(model.ProtocolUDP):
		return 17, nil
	case string(model.ProtocolICMP):
		if remoteIP.IsValid() && remoteIP.Is6() && !remoteIP.Is4() {
			return 58, nil
		}
		return 1, nil
	case "icmpv6":
		return 58, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q", value)
	}
}

func parseOptionalAddr(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid remote IP %q: %w", value, err)
	}
	return addr, nil
}

func parseRequiredAddr(name, value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, fmt.Errorf("missing -%s", name)
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid %s IP %q: %w", name, value, err)
	}
	return addr, nil
}

func parseUint16Flag(name string, value uint) (uint16, error) {
	if value > 0xffff {
		return 0, fmt.Errorf("-%s must be <= 65535", name)
	}
	return uint16(value), nil
}

func parseUint8Flag(name string, value int) (uint8, error) {
	if value < 0 || value > 0xff {
		return 0, fmt.Errorf("-%s must be between 0 and 255", name)
	}
	return uint8(value), nil
}

func runStateFile(ctx context.Context, path string) error {
	node := os.Getenv("NETLOOM_NODE_NAME")
	if node == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		node = hostname
	}
	store, storeName, closeStore := policyStore()
	defer closeStore()
	hold, err := tcxHold()
	if err != nil {
		return err
	}
	interval, err := reconcileInterval()
	if err != nil {
		return err
	}
	if interval == 0 {
		return reconcileStateFileOnce(ctx, path, node, storeName, store, hold, nil, nil)
	}
	reconciler := agent.NewReconciler(store)
	defer func() {
		_ = reconciler.Close()
	}()
	metrics := newAgentMetrics(store)
	historyStore, closeHistoryStore, err := policyRolloutHistoryStoreFromEnv(ctx)
	if err != nil {
		return err
	}
	defer closeHistoryStore()
	if err := configurePolicyRolloutHistory(ctx, metrics, historyStore); err != nil {
		return err
	}
	actionHistoryStore, closeActionHistoryStore, err := policyActionHistoryStoreFromEnv(ctx)
	if err != nil {
		return err
	}
	defer closeActionHistoryStore()
	if err := configurePolicyActionHistory(ctx, metrics, actionHistoryStore); err != nil {
		return err
	}
	statusStore, closeStatusStore, err := policyStatusStoreFromEnv(ctx)
	if err != nil {
		return err
	}
	defer closeStatusStore()
	configurePolicyStatusStore(metrics, statusStore)
	eventsStore, closeEventsStore, err := policyEventsStoreFromEnv(ctx)
	if err != nil {
		return err
	}
	defer closeEventsStore()
	configurePolicyEventsStore(metrics, eventsStore)
	rulesStore, closeRulesStore, err := policyRulesStoreFromEnv(ctx)
	if err != nil {
		return err
	}
	defer closeRulesStore()
	configurePolicyRulesStore(metrics, rulesStore)
	entriesStore, closeEntriesStore, err := policyEntriesStoreFromEnv(ctx)
	if err != nil {
		return err
	}
	defer closeEntriesStore()
	configurePolicyEntriesStore(metrics, entriesStore)
	freezeStore, closeFreezeStore, err := policyFreezeStateStoreFromEnv(ctx)
	if err != nil {
		return err
	}
	defer closeFreezeStore()
	if err := configurePolicyFreezeState(ctx, metrics, freezeStore); err != nil {
		return err
	}
	if closeMetrics, err := startAgentMetricsServer(ctx, os.Getenv("NETLOOM_AGENT_METRICS_ADDR"), metrics); err != nil {
		return err
	} else {
		defer closeMetrics()
	}
	identityGroupFeedCache := &control.IdentityGroupObservationCache{}
	reconcile := func() error {
		return reconcileStateFile(ctx, path, node, storeName, reconciler, metrics, identityGroupFeedCache)
	}
	for {
		if err := reconcile(); err != nil {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func reconcileStateFile(ctx context.Context, path, node, storeName string, reconciler *agent.Reconciler, metrics *agentMetrics, identityGroupFeedCache *control.IdentityGroupObservationCache) error {
	start := time.Now()
	runtimeChecks := runAgentRuntimePreflight()
	linuxOptions, rolloutStateStore, dnsObservationStore, identityGroupStore, closeLinuxOptions, err := linuxDatapathOptionsWithOVSDBSyncer(ctx)
	if err != nil {
		duration := time.Since(start)
		result := agent.ReconcileResult{Node: node}
		printReconcileFailure(result, storeName, err, duration)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	}
	defer closeLinuxOptions()

	state, err := loadDesiredStateFromPathOrOVSDB(ctx, path, identityGroupStore)
	if err != nil {
		duration := time.Since(start)
		result := agent.ReconcileResult{Node: node}
		syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	}
	state, err = withRuntimeObservationsAtContextCacheStore(ctx, state, time.Now().UTC(), identityGroupFeedCache, dnsObservationStore, identityGroupStore)
	if err != nil {
		duration := time.Since(start)
		result := agent.ReconcileResult{Node: node}
		syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	}
	if err := enforceRuntimePreflight(runtimeChecks); err != nil {
		duration := time.Since(start)
		result := agent.ReconcileResult{Node: node}
		printReconcileFailure(result, storeName, err, duration)
		syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	}
	result, err := reconciler.Reconcile(ctx, state, agent.ReconcileOptions{
		Node:                              node,
		TCXInterface:                      os.Getenv("NETLOOM_TCX_IFACE"),
		TCXWorkload:                       os.Getenv("NETLOOM_TCX_WORKLOAD") == "1",
		ConntrackIdle:                     conntrackIdleTimeout(),
		PolicyGCMaxIdle:                   policyGCMaxIdle(),
		PolicyPressureMitigationThreshold: policyPressureMitigationThreshold(),
		PolicyPressureQuarantineThreshold: policyPressureQuarantineThreshold(),
		PolicyPressureQuarantine:          policyPressureQuarantine(),
		DeferPolicyApply:                  agent.HasActivePolicyRollouts(state, node),
		FrozenPolicyEndpoints:             metrics.frozenPolicyEndpointsSnapshot(),
		PolicyRolloutApprovalSecret:       policyRolloutApprovalSecret(),
		LinuxDatapath:                     linuxOptions,
	})
	if err != nil {
		duration := time.Since(start)
		printReconcileFailure(result, storeName, err, duration)
		syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	}
	var rolloutHistory []agent.NamedPolicyEndpointRollout
	rolloutResume, err := loadPolicyRolloutResume(ctx, rolloutStateStore, node, state)
	if err != nil {
		duration := time.Since(start)
		printReconcileFailure(result, storeName, err, duration)
		syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	}
	if rollouts, err := agent.ApplyPolicyRollouts(ctx, state, agent.ReconcileOptions{
		Node:                        node,
		Store:                       metrics.store,
		FrozenPolicyEndpoints:       metrics.frozenPolicyEndpointsSnapshot(),
		PolicyRolloutApprovalSecret: policyRolloutApprovalSecret(),
		PolicyRolloutResume:         rolloutResume,
	}); err != nil {
		duration := time.Since(start)
		printReconcileFailure(result, storeName, err, duration)
		syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	} else {
		agent.ApplyPolicyRolloutResults(&result, rollouts)
		rolloutHistory = rollouts
		if err := savePolicyRolloutResume(ctx, rolloutStateStore, node, storeName, rollouts); err != nil {
			duration := time.Since(start)
			printReconcileFailure(result, storeName, err, duration)
			syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
			observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
			return err
		}
	}
	duration := time.Since(start)
	recordNamedPolicyRolloutHistory(metrics, "desired-state", rolloutHistory, result.Node, storeName, duration)
	printReconcileResult(result, storeName, duration)
	syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, nil, duration, runtimeChecks)
	observeAgentReconcileResultWithState(metrics, result, storeName, duration, state, runtimeChecks)
	return nil
}

func reconcileStateFileOnce(ctx context.Context, path, node, storeName string, store agent.PolicyStore, hold time.Duration, metrics *agentMetrics, identityGroupFeedCache *control.IdentityGroupObservationCache) error {
	runtimeChecks := runAgentRuntimePreflight()
	linuxOptions, rolloutStateStore, dnsObservationStore, identityGroupStore, closeLinuxOptions, err := linuxDatapathOptionsWithOVSDBSyncer(ctx)
	if err != nil {
		start := time.Now()
		result := agent.ReconcileResult{Node: node}
		printReconcileFailure(result, storeName, err, time.Since(start))
		observeAgentReconcileFailure(metrics, result, storeName, err, time.Since(start), runtimeChecks)
		return err
	}
	defer closeLinuxOptions()
	return reconcileStateFileOnceWithRuntimeStores(ctx, path, node, storeName, store, hold, metrics, identityGroupFeedCache, linuxOptions, rolloutStateStore, dnsObservationStore, identityGroupStore)
}

func reconcileStateFileOnceWithRuntimeStores(ctx context.Context, path, node, storeName string, store agent.PolicyStore, hold time.Duration, metrics *agentMetrics, identityGroupFeedCache *control.IdentityGroupObservationCache, linuxOptions *linuxdatapath.Options, rolloutStateStore policyRolloutStateStore, dnsObservationStore dnsObservationStore, identityGroupStore openVSwitchExternalIDStore) error {
	start := time.Now()
	runtimeChecks := runAgentRuntimePreflight()
	state, err := loadDesiredStateFromPathOrOVSDB(ctx, path, identityGroupStore)
	if err != nil {
		result := agent.ReconcileResult{Node: node}
		duration := time.Since(start)
		syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	}
	if agent.HasActivePolicyRollouts(state, node) && rolloutStateStore == nil {
		err := errors.New("policy_rollouts require NETLOOM_OVSDB_ENDPOINT for Open_vSwitch rollout state")
		result := agent.ReconcileResult{Node: node}
		duration := time.Since(start)
		syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	}
	state, err = withRuntimeObservationsAtContextCacheStore(ctx, state, time.Now().UTC(), identityGroupFeedCache, dnsObservationStore, identityGroupStore)
	if err != nil {
		result := agent.ReconcileResult{Node: node}
		duration := time.Since(start)
		syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	}
	if err := enforceRuntimePreflight(runtimeChecks); err != nil {
		result := agent.ReconcileResult{Node: node}
		duration := time.Since(start)
		printReconcileFailure(result, storeName, err, duration)
		syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	}
	result, err := agent.ReconcileNodeWithOptions(ctx, state, agent.ReconcileOptions{
		Node:                              node,
		Store:                             store,
		TCXInterface:                      os.Getenv("NETLOOM_TCX_IFACE"),
		TCXWorkload:                       os.Getenv("NETLOOM_TCX_WORKLOAD") == "1",
		TCXHold:                           hold,
		PolicyGCMaxIdle:                   policyGCMaxIdle(),
		PolicyPressureMitigationThreshold: policyPressureMitigationThreshold(),
		PolicyPressureQuarantineThreshold: policyPressureQuarantineThreshold(),
		PolicyPressureQuarantine:          policyPressureQuarantine(),
		DeferPolicyApply:                  agent.HasActivePolicyRollouts(state, node),
		PolicyRolloutApprovalSecret:       policyRolloutApprovalSecret(),
		LinuxDatapath:                     linuxOptions,
	})
	if err != nil {
		duration := time.Since(start)
		printReconcileFailure(result, storeName, err, duration)
		syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	}
	var rolloutHistory []agent.NamedPolicyEndpointRollout
	rolloutResume, err := loadPolicyRolloutResume(ctx, rolloutStateStore, node, state)
	if err != nil {
		duration := time.Since(start)
		printReconcileFailure(result, storeName, err, duration)
		syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	}
	if rollouts, err := agent.ApplyPolicyRollouts(ctx, state, agent.ReconcileOptions{
		Node:                        node,
		Store:                       store,
		FrozenPolicyEndpoints:       metrics.frozenPolicyEndpointsSnapshot(),
		PolicyRolloutApprovalSecret: policyRolloutApprovalSecret(),
		PolicyRolloutResume:         rolloutResume,
	}); err != nil {
		duration := time.Since(start)
		printReconcileFailure(result, storeName, err, duration)
		syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
		return err
	} else {
		agent.ApplyPolicyRolloutResults(&result, rollouts)
		rolloutHistory = rollouts
		if err := savePolicyRolloutResume(ctx, rolloutStateStore, node, storeName, rollouts); err != nil {
			duration := time.Since(start)
			printReconcileFailure(result, storeName, err, duration)
			syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, err, duration, runtimeChecks)
			observeAgentReconcileFailure(metrics, result, storeName, err, duration, runtimeChecks)
			return err
		}
	}
	duration := time.Since(start)
	recordNamedPolicyRolloutHistory(metrics, "desired-state", rolloutHistory, result.Node, storeName, duration)
	printReconcileResult(result, storeName, duration)
	syncAgentOVSDBStatus(ctx, identityGroupStore, result, storeName, nil, duration, runtimeChecks)
	observeAgentReconcileResultWithState(metrics, result, storeName, duration, state, runtimeChecks)
	return nil
}

func withDNSObservations(state control.DesiredState) (control.DesiredState, error) {
	return withDNSObservationsAt(state, time.Now().UTC())
}

func withRuntimeObservations(state control.DesiredState) (control.DesiredState, error) {
	return withRuntimeObservationsAt(state, time.Now().UTC())
}

func withRuntimeObservationsContext(ctx context.Context, state control.DesiredState) (control.DesiredState, error) {
	return withRuntimeObservationsAtContextCache(ctx, state, time.Now().UTC(), nil)
}

func withRuntimeObservationsAt(state control.DesiredState, now time.Time) (control.DesiredState, error) {
	return withRuntimeObservationsAtContextCache(context.Background(), state, now, nil)
}

func withRuntimeObservationsAtContext(ctx context.Context, state control.DesiredState, now time.Time) (control.DesiredState, error) {
	return withRuntimeObservationsAtContextCache(ctx, state, now, nil)
}

func withRuntimeObservationsContextCache(ctx context.Context, state control.DesiredState, cache *control.IdentityGroupObservationCache) (control.DesiredState, error) {
	return withRuntimeObservationsAtContextCache(ctx, state, time.Now().UTC(), cache)
}

func withRuntimeObservationsAtContextCache(ctx context.Context, state control.DesiredState, now time.Time, cache *control.IdentityGroupObservationCache) (control.DesiredState, error) {
	identityStore, closeIdentityStore, err := identityGroupObservationStoreFromEnv(ctx)
	if err != nil {
		return control.DesiredState{}, err
	}
	defer closeIdentityStore()
	return withRuntimeObservationsAtContextCacheStore(ctx, state, now, cache, nil, identityStore)
}

func withRuntimeObservationsAtContextCacheStore(ctx context.Context, state control.DesiredState, now time.Time, cache *control.IdentityGroupObservationCache, dnsStore dnsObservationStore, identityStore openVSwitchExternalIDStore) (control.DesiredState, error) {
	next, err := withDNSObservationsAtContextStore(ctx, state, now, dnsStore)
	if err != nil {
		return control.DesiredState{}, err
	}
	return withIdentityGroupObservationsAtContextCacheStore(ctx, next, now, cache, identityStore)
}

func withDNSObservationsAt(state control.DesiredState, now time.Time) (control.DesiredState, error) {
	return withDNSObservationsAtContextStore(context.Background(), state, now, nil)
}

func withDNSObservationsAtContextStore(ctx context.Context, state control.DesiredState, now time.Time, store dnsObservationStore) (control.DesiredState, error) {
	if store == nil {
		return state, nil
	}
	records, err := store.LoadDNSObservations(ctx)
	if err != nil {
		return control.DesiredState{}, err
	}
	merged, err := control.MergeDNSRecords(state.DNSRecords, records)
	if err != nil {
		return control.DesiredState{}, err
	}
	merged, err = control.PruneExpiredDNSRecords(merged, now)
	if err != nil {
		return control.DesiredState{}, err
	}
	state.DNSRecords = merged
	return state, nil
}

func withIdentityGroupObservations(state control.DesiredState) (control.DesiredState, error) {
	return withIdentityGroupObservationsAt(state, time.Now().UTC())
}

func withIdentityGroupObservationsAt(state control.DesiredState, now time.Time) (control.DesiredState, error) {
	return withIdentityGroupObservationsAtContext(context.Background(), state, now)
}

func withIdentityGroupObservationsAtContext(ctx context.Context, state control.DesiredState, now time.Time) (control.DesiredState, error) {
	return withIdentityGroupObservationsAtContextCache(ctx, state, now, nil)
}

func withIdentityGroupObservationsAtContextCache(ctx context.Context, state control.DesiredState, now time.Time, cache *control.IdentityGroupObservationCache) (control.DesiredState, error) {
	store, closeStore, err := identityGroupObservationStoreFromEnv(ctx)
	if err != nil {
		return control.DesiredState{}, err
	}
	defer closeStore()
	return withIdentityGroupObservationsAtContextCacheStore(ctx, state, now, cache, store)
}

func withIdentityGroupObservationsAtContextCacheStore(ctx context.Context, state control.DesiredState, now time.Time, cache *control.IdentityGroupObservationCache, store openVSwitchExternalIDStore) (control.DesiredState, error) {
	localGroups, err := loadIdentityGroupObservationsFromOpenVSwitchExternalID(ctx, store)
	if err != nil {
		return control.DesiredState{}, err
	}
	return control.MergeIdentityGroupObservations(ctx, state, control.IdentityGroupObservationOptions{
		LocalGroups: localGroups,
		URL:         os.Getenv("NETLOOM_IDENTITY_GROUPS_URL"),
		BearerToken: os.Getenv("NETLOOM_IDENTITY_GROUPS_BEARER_TOKEN"),
		Timeout:     identityGroupFeedTimeout(),
		Now:         now,
		BackoffBase: identityGroupFeedBackoffInitial(),
		BackoffMax:  identityGroupFeedBackoffMax(),
		Cache:       cache,
		TLSCAFile:   os.Getenv("NETLOOM_IDENTITY_GROUPS_TLS_CA_FILE"),
		TLSCertFile: os.Getenv("NETLOOM_IDENTITY_GROUPS_TLS_CERT_FILE"),
		TLSKeyFile:  os.Getenv("NETLOOM_IDENTITY_GROUPS_TLS_KEY_FILE"),
	})
}

func loadIdentityGroupObservationsFromOpenVSwitchExternalID(ctx context.Context, store openVSwitchExternalIDStore) ([]model.IdentityGroup, error) {
	if store == nil {
		return nil, nil
	}
	raw, ok, err := store.OpenVSwitchExternalID(ctx, control.IdentityGroupObservationsOpenVSwitchExternalID)
	if err != nil {
		return nil, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	groups, err := control.LoadIdentityGroupObservationsJSON(strings.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode Open_vSwitch external_ids:%s: %w", control.IdentityGroupObservationsOpenVSwitchExternalID, err)
	}
	return groups, nil
}

func identityGroupFeedTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("NETLOOM_IDENTITY_GROUPS_TIMEOUT_MS"))
	if raw == "" {
		return 5 * time.Second
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms < 0 {
		return 5 * time.Second
	}
	return time.Duration(ms) * time.Millisecond
}

func identityGroupFeedBackoffInitial() time.Duration {
	return identityGroupFeedBackoffDuration("NETLOOM_IDENTITY_GROUPS_BACKOFF_INITIAL_MS", time.Second)
}

func identityGroupFeedBackoffMax() time.Duration {
	return identityGroupFeedBackoffDuration("NETLOOM_IDENTITY_GROUPS_BACKOFF_MAX_MS", time.Minute)
}

func identityGroupFeedBackoffDuration(env string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(env))
	if raw == "" {
		return fallback
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms < 0 {
		return fallback
	}
	return time.Duration(ms) * time.Millisecond
}

func printReconcileResult(result agent.ReconcileResult, storeName string, duration time.Duration) {
	fmt.Printf("netloom-agent reconciled node policy node=%s store=%s endpoints=%d programs=%d entries=%d policy_map_entries=%d policy_map_capacity=%d policy_map_pressure_max=%d policy_map_pressure_endpoint=%s policy_map_pressure_endpoints=%d policy_pressure_mitigated=%d policy_pressure_quarantined=%d policy_pressure_quarantine_endpoint=%s policy_rollouts=%d policy_rollout_planned=%d policy_rollout_applied=%d policy_rollout_skipped=%d policy_rollout_failed=%d policy_rollout_rolled_back=%d policy_rollout_rollback_failed=%d policy_rollout_slo_failed=%d policy_rollout_probe_failed=%d policy_rollout_paused=%d policy_rollout_cancelled=%d policy_map_drift_endpoints=%d policy_map_drift_missing=%d policy_map_drift_extra=%d policy_map_drift_changed=%d policy_gc_endpoints=%d policy_added=%d policy_updated=%d policy_deleted=%d policy_unchanged=%d policy_events=%d policy_failed=%d policy_rollbacks=%d policy_failed_endpoint=%s policy_failed_revision=%d policy_revision_max=%d policy_last_error=%s policy_rule_packets=%d policy_rule_bytes=%d policy_rule_allowed=%d policy_rule_dropped=%d policy_rule_rejected=%d policy_rule_logged=%d policy_rule_stats=%s conntrack_expired=%d tcx_eligible=%d tcx_skipped=%d tcx=%s tcx_failed=%d tcx_rollbacks=%d tcx_failed_target=%s tcx_last_error=%s datapath=%s local_ips=%d remote_routes=%d policy_routes=%d provider_networks=%d provider_links=%d provider_ready=%d provider_degraded=%d provider_status=%s provider_network_status=%s provider_issues=%s provider_inventory_total=%d provider_inventory_ready=%d provider_inventory_degraded=%d provider_inventory_status=%s cleanup=%t reconcile_duration_ms=%d\n", result.Node, storeName, result.Endpoints, result.Programs, result.Entries, result.PolicyMapEntries, result.PolicyMapCapacity, result.PolicyMapPressureMax, formatResultValue(result.PolicyMapPressureEndpoint), result.PolicyMapPressureEndpoints, result.PolicyPressureMitigated, result.PolicyPressureQuarantined, formatResultValue(result.PolicyPressureQuarantineEndpoint), result.PolicyRollouts, result.PolicyRolloutPlanned, result.PolicyRolloutApplied, result.PolicyRolloutSkipped, result.PolicyRolloutFailed, result.PolicyRolloutRolledBack, result.PolicyRolloutRollbackFailed, result.PolicyRolloutSLOFailed, result.PolicyRolloutProbeFailed, result.PolicyRolloutPaused, result.PolicyRolloutCancelled, result.PolicyMapDriftEndpoints, result.PolicyMapDriftMissing, result.PolicyMapDriftExtra, result.PolicyMapDriftChanged, result.PolicyGCEndpoints, result.PolicyAdded, result.PolicyUpdated, result.PolicyDeleted, result.PolicyUnchanged, result.PolicyEvents, result.PolicyFailed, result.PolicyRollbacks, formatResultValue(result.PolicyFailedEndpoint), result.PolicyFailedRevision, result.PolicyRevisionMax, formatResultError(result.PolicyLastError), result.PolicyRulePackets, result.PolicyRuleBytes, result.PolicyRuleAllowed, result.PolicyRuleDropped, result.PolicyRuleRejected, result.PolicyRuleLogged, formatEndpointRuleStats(result.PolicyRuleStats), result.ConntrackExpired, result.TCXEligible, result.TCXSkipped, result.TCX, result.TCXFailed, result.TCXRollbacks, formatResultValue(result.TCXFailedTarget), formatResultError(result.TCXLastError), result.Datapath, result.LocalIPs, result.RemoteRoutes, result.PolicyRoutes, result.ProviderNetworks, result.ProviderLinks, result.ProviderReady, result.ProviderDegraded, formatProviderStatus(result.ProviderStatus), formatProviderNetworkStatus(result.ProviderNetworkStatus), formatProviderIssues(result.ProviderIssues), result.ProviderInventoryTotal, result.ProviderInventoryReady, result.ProviderInventoryDegraded, formatProviderInventoryStatus(result.ProviderInventoryStatus), result.Cleanup, duration.Milliseconds())
}

func printReconcileFailure(result agent.ReconcileResult, storeName string, err error, duration time.Duration) {
	fmt.Printf("netloom-agent reconcile failed node=%s store=%s endpoints=%d programs=%d entries=%d policy_map_entries=%d policy_map_capacity=%d policy_map_pressure_max=%d policy_map_pressure_endpoint=%s policy_map_pressure_endpoints=%d policy_pressure_mitigated=%d policy_pressure_quarantined=%d policy_pressure_quarantine_endpoint=%s policy_rollouts=%d policy_rollout_planned=%d policy_rollout_applied=%d policy_rollout_skipped=%d policy_rollout_failed=%d policy_rollout_rolled_back=%d policy_rollout_rollback_failed=%d policy_rollout_slo_failed=%d policy_rollout_probe_failed=%d policy_rollout_paused=%d policy_rollout_cancelled=%d policy_map_drift_endpoints=%d policy_map_drift_missing=%d policy_map_drift_extra=%d policy_map_drift_changed=%d policy_gc_endpoints=%d policy_added=%d policy_updated=%d policy_deleted=%d policy_unchanged=%d policy_events=%d policy_failed=%d policy_rollbacks=%d policy_failed_endpoint=%s policy_failed_revision=%d policy_revision_max=%d policy_last_error=%s policy_rule_packets=%d policy_rule_bytes=%d policy_rule_allowed=%d policy_rule_dropped=%d policy_rule_rejected=%d policy_rule_logged=%d policy_rule_stats=%s tcx_eligible=%d tcx_skipped=%d tcx=%s tcx_failed=%d tcx_rollbacks=%d tcx_failed_target=%s tcx_last_error=%s provider_networks=%d provider_links=%d provider_ready=%d provider_degraded=%d provider_status=%s provider_network_status=%s provider_issues=%s provider_inventory_total=%d provider_inventory_ready=%d provider_inventory_degraded=%d provider_inventory_status=%s err=%s reconcile_duration_ms=%d\n", result.Node, storeName, result.Endpoints, result.Programs, result.Entries, result.PolicyMapEntries, result.PolicyMapCapacity, result.PolicyMapPressureMax, formatResultValue(result.PolicyMapPressureEndpoint), result.PolicyMapPressureEndpoints, result.PolicyPressureMitigated, result.PolicyPressureQuarantined, formatResultValue(result.PolicyPressureQuarantineEndpoint), result.PolicyRollouts, result.PolicyRolloutPlanned, result.PolicyRolloutApplied, result.PolicyRolloutSkipped, result.PolicyRolloutFailed, result.PolicyRolloutRolledBack, result.PolicyRolloutRollbackFailed, result.PolicyRolloutSLOFailed, result.PolicyRolloutProbeFailed, result.PolicyRolloutPaused, result.PolicyRolloutCancelled, result.PolicyMapDriftEndpoints, result.PolicyMapDriftMissing, result.PolicyMapDriftExtra, result.PolicyMapDriftChanged, result.PolicyGCEndpoints, result.PolicyAdded, result.PolicyUpdated, result.PolicyDeleted, result.PolicyUnchanged, result.PolicyEvents, result.PolicyFailed, result.PolicyRollbacks, formatResultValue(result.PolicyFailedEndpoint), result.PolicyFailedRevision, result.PolicyRevisionMax, formatResultError(result.PolicyLastError), result.PolicyRulePackets, result.PolicyRuleBytes, result.PolicyRuleAllowed, result.PolicyRuleDropped, result.PolicyRuleRejected, result.PolicyRuleLogged, formatEndpointRuleStats(result.PolicyRuleStats), result.TCXEligible, result.TCXSkipped, result.TCX, result.TCXFailed, result.TCXRollbacks, formatResultValue(result.TCXFailedTarget), formatResultError(result.TCXLastError), result.ProviderNetworks, result.ProviderLinks, result.ProviderReady, result.ProviderDegraded, formatProviderStatus(result.ProviderStatus), formatProviderNetworkStatus(result.ProviderNetworkStatus), formatProviderIssues(result.ProviderIssues), result.ProviderInventoryTotal, result.ProviderInventoryReady, result.ProviderInventoryDegraded, formatProviderInventoryStatus(result.ProviderInventoryStatus), formatResultError(fmt.Sprint(err)), duration.Milliseconds())
}

type agentOVSDBStatus struct {
	SchemaVersion             int    `json:"schema_version"`
	UpdatedAt                 string `json:"updated_at"`
	Node                      string `json:"node"`
	Store                     string `json:"store"`
	Status                    string `json:"status"`
	Error                     string `json:"error,omitempty"`
	Endpoints                 int    `json:"endpoints"`
	Programs                  int    `json:"programs"`
	Entries                   int    `json:"entries"`
	PolicyMapEntries          uint32 `json:"policy_map_entries"`
	PolicyMapCapacity         uint32 `json:"policy_map_capacity"`
	PolicyMapPressureMax      uint32 `json:"policy_map_pressure_max"`
	PolicyMapPressureEndpoint string `json:"policy_map_pressure_endpoint,omitempty"`

	PolicyMapPressureHotspots []policyMapPressureHotspot `json:"policy_map_pressure_hotspots,omitempty"`

	PolicyPressureMitigated       int                  `json:"policy_pressure_mitigated"`
	PolicyPressureQuarantined     int                  `json:"policy_pressure_quarantined"`
	PolicyRollouts                int                  `json:"policy_rollouts"`
	PolicyRolloutPlanned          int                  `json:"policy_rollout_planned"`
	PolicyRolloutApplied          int                  `json:"policy_rollout_applied"`
	PolicyRolloutSkipped          int                  `json:"policy_rollout_skipped"`
	PolicyRolloutFailed           int                  `json:"policy_rollout_failed"`
	PolicyRolloutRolledBack       int                  `json:"policy_rollout_rolled_back"`
	PolicyRolloutRollbackFailed   int                  `json:"policy_rollout_rollback_failed"`
	PolicyRolloutSLOFailed        int                  `json:"policy_rollout_slo_failed"`
	PolicyRolloutProbeFailed      int                  `json:"policy_rollout_probe_failed"`
	PolicyRolloutPaused           int                  `json:"policy_rollout_paused"`
	PolicyRolloutCancelled        int                  `json:"policy_rollout_cancelled"`
	PolicyMapDriftEndpoints       int                  `json:"policy_map_drift_endpoints"`
	PolicyMapDriftMissing         int                  `json:"policy_map_drift_missing"`
	PolicyMapDriftExtra           int                  `json:"policy_map_drift_extra"`
	PolicyMapDriftChanged         int                  `json:"policy_map_drift_changed"`
	PolicyGCEndpoints             int                  `json:"policy_gc_endpoints"`
	PolicyFailed                  int                  `json:"policy_failed"`
	PolicyRollbacks               int                  `json:"policy_rollbacks"`
	PolicyFailedEndpoint          string               `json:"policy_failed_endpoint,omitempty"`
	PolicyFailedRevision          uint64               `json:"policy_failed_revision,omitempty"`
	PolicyRevisionMax             uint64               `json:"policy_revision_max"`
	PolicyLastError               string               `json:"policy_last_error,omitempty"`
	TCX                           string               `json:"tcx"`
	TCXFailed                     int                  `json:"tcx_failed"`
	TCXRollbacks                  int                  `json:"tcx_rollbacks"`
	TCXFailedTarget               string               `json:"tcx_failed_target,omitempty"`
	TCXLastError                  string               `json:"tcx_last_error,omitempty"`
	RuntimeReady                  bool                 `json:"runtime_ready"`
	RuntimeFailed                 int                  `json:"runtime_failed"`
	RuntimeWarned                 int                  `json:"runtime_warned"`
	Runtime                       []agent.RuntimeCheck `json:"runtime,omitempty"`
	Datapath                      string               `json:"datapath,omitempty"`
	LocalIPs                      int                  `json:"local_ips"`
	RemoteRoutes                  int                  `json:"remote_routes"`
	PolicyRoutes                  int                  `json:"policy_routes"`
	ProviderNetworks              int                  `json:"provider_networks"`
	ProviderLinks                 int                  `json:"provider_links"`
	ProviderReady                 int                  `json:"provider_ready"`
	ProviderDegraded              int                  `json:"provider_degraded"`
	ProviderIssues                int                  `json:"provider_issues"`
	ProviderInventoryTotal        int                  `json:"provider_inventory_total"`
	ProviderInventoryReady        int                  `json:"provider_inventory_ready"`
	ProviderInventoryDegraded     int                  `json:"provider_inventory_degraded"`
	Cleanup                       bool                 `json:"cleanup"`
	ReconcileDurationMilliseconds int64                `json:"reconcile_duration_ms"`
}

func syncAgentOVSDBStatus(ctx context.Context, store openVSwitchExternalIDStore, result agent.ReconcileResult, storeName string, reconcileErr error, duration time.Duration, runtimeChecks []agent.RuntimeCheck) {
	if store == nil {
		return
	}
	runtimeFailed, runtimeWarned := countRuntimeCheckStatuses(runtimeChecks)
	status := agentOVSDBStatus{
		SchemaVersion:                 1,
		UpdatedAt:                     time.Now().UTC().Format(time.RFC3339Nano),
		Node:                          result.Node,
		Store:                         storeName,
		Status:                        "success",
		Endpoints:                     result.Endpoints,
		Programs:                      result.Programs,
		Entries:                       result.Entries,
		PolicyMapEntries:              result.PolicyMapEntries,
		PolicyMapCapacity:             result.PolicyMapCapacity,
		PolicyMapPressureMax:          result.PolicyMapPressureMax,
		PolicyMapPressureEndpoint:     result.PolicyMapPressureEndpoint,
		PolicyMapPressureHotspots:     append([]dataplane.PolicyMapPressureHotspot(nil), result.PolicyMapPressureHotspots...),
		PolicyPressureMitigated:       result.PolicyPressureMitigated,
		PolicyPressureQuarantined:     result.PolicyPressureQuarantined,
		PolicyRollouts:                result.PolicyRollouts,
		PolicyRolloutPlanned:          result.PolicyRolloutPlanned,
		PolicyRolloutApplied:          result.PolicyRolloutApplied,
		PolicyRolloutSkipped:          result.PolicyRolloutSkipped,
		PolicyRolloutFailed:           result.PolicyRolloutFailed,
		PolicyRolloutRolledBack:       result.PolicyRolloutRolledBack,
		PolicyRolloutRollbackFailed:   result.PolicyRolloutRollbackFailed,
		PolicyRolloutSLOFailed:        result.PolicyRolloutSLOFailed,
		PolicyRolloutProbeFailed:      result.PolicyRolloutProbeFailed,
		PolicyRolloutPaused:           result.PolicyRolloutPaused,
		PolicyRolloutCancelled:        result.PolicyRolloutCancelled,
		PolicyMapDriftEndpoints:       result.PolicyMapDriftEndpoints,
		PolicyMapDriftMissing:         result.PolicyMapDriftMissing,
		PolicyMapDriftExtra:           result.PolicyMapDriftExtra,
		PolicyMapDriftChanged:         result.PolicyMapDriftChanged,
		PolicyGCEndpoints:             result.PolicyGCEndpoints,
		PolicyFailed:                  result.PolicyFailed,
		PolicyRollbacks:               result.PolicyRollbacks,
		PolicyFailedEndpoint:          result.PolicyFailedEndpoint,
		PolicyFailedRevision:          result.PolicyFailedRevision,
		PolicyRevisionMax:             result.PolicyRevisionMax,
		PolicyLastError:               result.PolicyLastError,
		TCX:                           result.TCX,
		TCXFailed:                     result.TCXFailed,
		TCXRollbacks:                  result.TCXRollbacks,
		TCXFailedTarget:               result.TCXFailedTarget,
		TCXLastError:                  result.TCXLastError,
		RuntimeReady:                  agent.RuntimeChecksReady(runtimeChecks),
		RuntimeFailed:                 runtimeFailed,
		RuntimeWarned:                 runtimeWarned,
		Runtime:                       cloneRuntimeChecks(runtimeChecks),
		Datapath:                      result.Datapath,
		LocalIPs:                      result.LocalIPs,
		RemoteRoutes:                  result.RemoteRoutes,
		PolicyRoutes:                  result.PolicyRoutes,
		ProviderNetworks:              result.ProviderNetworks,
		ProviderLinks:                 result.ProviderLinks,
		ProviderReady:                 result.ProviderReady,
		ProviderDegraded:              result.ProviderDegraded,
		ProviderIssues:                len(result.ProviderIssues),
		ProviderInventoryTotal:        result.ProviderInventoryTotal,
		ProviderInventoryReady:        result.ProviderInventoryReady,
		ProviderInventoryDegraded:     result.ProviderInventoryDegraded,
		Cleanup:                       result.Cleanup,
		ReconcileDurationMilliseconds: duration.Milliseconds(),
	}
	if reconcileErr != nil {
		status.Status = "error"
		status.Error = reconcileErr.Error()
	}
	raw, err := json.Marshal(status)
	if err != nil {
		log.Printf("encode Open_vSwitch agent status: %v", err)
		return
	}
	if err := store.SetOpenVSwitchExternalID(ctx, "netloom_owner", "netloom"); err != nil {
		log.Printf("write Open_vSwitch external_ids:netloom_owner: %v", err)
		return
	}
	if err := store.SetOpenVSwitchExternalID(ctx, agentOVSDBStatusKey, string(raw)); err != nil {
		log.Printf("write Open_vSwitch external_ids:%s: %v", agentOVSDBStatusKey, err)
	}
}

func formatResultValue(value string) string {
	if value == "" {
		return "none"
	}
	return strconv.Quote(value)
}

func formatResultError(value string) string {
	if value == "" {
		return "none"
	}
	return strconv.Quote(value)
}

func formatProviderStatus(statuses []linuxdatapath.ProviderLinkStatus) string {
	if len(statuses) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(statuses))
	for _, status := range statuses {
		state := "pending"
		if status.Ready {
			state = "ready"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%d:%s:%s:%s:%s", status.ProviderNetwork, status.ParentDevice, status.VLAN, status.LinkName, state, fallbackProviderState(status.ParentState), fallbackProviderState(status.LinkState)))
	}
	return strings.Join(parts, ",")
}

func formatProviderInventoryStatus(statuses []linuxdatapath.ProviderInterface) string {
	if len(statuses) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(statuses))
	for _, status := range statuses {
		state := fallbackProviderState(status.State)
		if status.Ready && (state == "unknown" || state == "down" || state == "missing") {
			state = "up"
		}
		parts = append(parts, fmt.Sprintf("%s:%s", status.Name, state))
	}
	return strings.Join(parts, ",")
}

func formatProviderIssues(issues []linuxdatapath.ProviderIssue) string {
	if len(issues) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(issues))
	for _, issue := range issues {
		parts = append(parts, fmt.Sprintf("%s:%s:%s:%d:%s:%s", issue.ProviderNetwork, issue.Node, issue.ParentDevice, issue.VLAN, issue.Reason, issue.Detail))
	}
	return strings.Join(parts, ",")
}

func formatProviderNetworkStatus(statuses []linuxdatapath.ProviderNetworkStatus) string {
	if len(statuses) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(statuses))
	for _, status := range statuses {
		state := "degraded"
		if status.Ready {
			state = "ready"
		}
		reasons := "none"
		if len(status.Reasons) > 0 {
			reasons = strings.Join(status.Reasons, "+")
		}
		usage := ""
		if status.TenantCount > 0 {
			usage = fmt.Sprintf(":tenants=%d:subnets=%d:endpoints=%d:%s", status.TenantCount, status.SubnetCount, status.EndpointCount, formatProviderTenantUsage(status.TenantUsage))
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%d/%d:%d:%s%s", status.ProviderNetwork, state, status.ReadyLinks, status.LinkCount, status.IssueCount, reasons, usage))
	}
	return strings.Join(parts, ",")
}

func formatProviderTenantUsage(usages []linuxdatapath.ProviderTenantUsage) string {
	if len(usages) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(usages))
	for _, usage := range usages {
		state := "ok"
		if usage.Exceeded {
			state = "exceeded"
		}
		parts = append(parts, fmt.Sprintf("%s=%s:%d/%d:%d/%d", usage.Tenant, state, usage.Subnets, usage.MaxSubnets, usage.Endpoints, usage.MaxEndpoints))
	}
	return strings.Join(parts, "+")
}

func fallbackProviderState(state string) string {
	if state == "" {
		return "unknown"
	}
	return state
}

func formatRuleStats(stats []dataplane.RuleMetrics) string {
	if len(stats) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(stats))
	for _, stat := range stats {
		parts = append(parts, fmt.Sprintf("%d:p=%d,b=%d,a=%d,d=%d,r=%d,nm=%d,ct=%d,est=%d,log=%d", stat.RuleCookie, stat.Packets, stat.Bytes, stat.Allowed, stat.Dropped, stat.Rejected, stat.NoMatchDrops, stat.Conntrack, stat.Established, stat.Logged))
	}
	return strings.Join(parts, ";")
}

func formatRuleCatalog(catalog []agent.PolicyRuleCatalogEntry) string {
	if len(catalog) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(catalog))
	for _, entry := range catalog {
		parts = append(parts, fmt.Sprintf("%d:%s", entry.RuleCookie, entry.RuleRef))
	}
	return strings.Join(parts, ";")
}

func formatRuntimeChecks(checks []agent.RuntimeCheck) string {
	if len(checks) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(checks))
	for _, check := range checks {
		required := "optional"
		if check.Required {
			required = "required"
		}
		detail := strings.NewReplacer(",", "_", ";", "_", " ", "_").Replace(strings.TrimSpace(check.Detail))
		if detail == "" {
			detail = "-"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s:%s", check.Name, check.Status, required, detail))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func countRuntimeCheckStatuses(checks []agent.RuntimeCheck) (failed, warned int) {
	for _, check := range checks {
		switch check.Status {
		case "fail":
			failed++
		case "warn":
			warned++
		}
	}
	return failed, warned
}

func enforceRuntimePreflight(checks []agent.RuntimeCheck) error {
	if !runtimePreflightStrictEnabled() || agent.RuntimeChecksReady(checks) {
		return nil
	}
	return fmt.Errorf("runtime preflight failed: %s", formatFailedRuntimeChecks(checks))
}

func runtimePreflightStrictEnabled() bool {
	raw := strings.TrimSpace(os.Getenv("NETLOOM_RUNTIME_PREFLIGHT_STRICT"))
	return raw == "1" || strings.EqualFold(raw, "true") || strings.EqualFold(raw, "yes")
}

func formatFailedRuntimeChecks(checks []agent.RuntimeCheck) string {
	parts := make([]string, 0, len(checks))
	for _, check := range checks {
		if !(check.Required && check.Status == "fail") {
			continue
		}
		detail := strings.TrimSpace(check.Detail)
		if detail == "" {
			detail = "-"
		}
		parts = append(parts, fmt.Sprintf("%s=%s(%s)", check.Name, check.Status, detail))
	}
	if len(parts) == 0 {
		return "none"
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func cloneRuntimeChecks(checks []agent.RuntimeCheck) []agent.RuntimeCheck {
	if len(checks) == 0 {
		return nil
	}
	return append([]agent.RuntimeCheck(nil), checks...)
}

func formatEndpointRuleStats(stats []dataplane.RuleMetrics) string {
	if len(stats) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(stats))
	for _, stat := range stats {
		parts = append(parts, fmt.Sprintf("%s/%d:p=%d,b=%d,a=%d,d=%d,r=%d,nm=%d,ct=%d,est=%d,log=%d", strconv.Quote(stat.EndpointID), stat.RuleCookie, stat.Packets, stat.Bytes, stat.Allowed, stat.Dropped, stat.Rejected, stat.NoMatchDrops, stat.Conntrack, stat.Established, stat.Logged))
	}
	return strings.Join(parts, ";")
}

type agentMetrics struct {
	mu                  sync.RWMutex
	snapshot            agentMetricsSnapshot
	totals              agentMetricsTotals
	ready               bool
	store               agent.PolicyStore
	rolloutHistoryStore policyRolloutHistoryStore
	rolloutHistory      []policyRolloutHistoryEntry
	actionHistoryStore  policyActionHistoryStore
	actionHistory       []policyActionHistoryEntry
	policyStatusStore   policyStatusStore
	policyEventsStore   policyEventsStore
	policyRulesStore    policyRulesStore
	policyEntriesStore  policyEntriesStore
	freezeStateStore    policyFreezeStateStore
	frozenEndpoints     map[string]time.Time
}

type agentMetricsSnapshot struct {
	Result   agent.ReconcileResult
	Store    string
	State    control.DesiredState
	Duration time.Duration
	Success  bool
	Error    string
	Runtime  []agent.RuntimeCheck
}

type agentMetricsTotals struct {
	Attempts                  uint64
	Successes                 uint64
	Failures                  uint64
	DurationSum               time.Duration
	DurationBuckets           []uint64
	PolicyAdded               uint64
	PolicyUpdated             uint64
	PolicyDeleted             uint64
	PolicyUnchanged           uint64
	PolicyEvents              uint64
	PolicyFailed              uint64
	PolicyRollbacks           uint64
	PolicyGCEndpoints         uint64
	PolicyPressureMitigated   uint64
	PolicyPressureQuarantined uint64
	PolicyRolloutPlanned      uint64
	PolicyRolloutApplied      uint64
	PolicyRolloutSkipped      uint64
	PolicyRolloutFailed       uint64
	PolicyRolloutRolledBack   uint64
	PolicyRolloutRollbackFail uint64
	PolicyRolloutSLOFailed    uint64
	PolicyRolloutProbeFailed  uint64
	PolicyRolloutPaused       uint64
	PolicyRolloutCancelled    uint64
	TCXFailed                 uint64
	TCXRollbacks              uint64
	ProviderDegraded          uint64
	ConntrackExpired          uint64
	PolicyRulePackets         uint64
	PolicyRuleBytes           uint64
	PolicyRuleDropped         uint64
	PolicyRuleRejected        uint64
	PolicyRuleNoMatchDrops    uint64
	PolicyRuleDenyDrops       uint64
	PolicyRuleRejectDrops     uint64
}

var agentReconcileDurationBuckets = []time.Duration{
	10 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	2500 * time.Millisecond,
	5 * time.Second,
	10 * time.Second,
	30 * time.Second,
}

func newAgentMetrics(store ...agent.PolicyStore) *agentMetrics {
	var policyStore agent.PolicyStore
	if len(store) > 0 {
		policyStore = store[0]
	}
	return &agentMetrics{
		totals:          agentMetricsTotals{DurationBuckets: make([]uint64, len(agentReconcileDurationBuckets))},
		store:           policyStore,
		frozenEndpoints: make(map[string]time.Time),
	}
}

func configurePolicyRolloutHistory(ctx context.Context, metrics *agentMetrics, store policyRolloutHistoryStore) error {
	if metrics == nil {
		return nil
	}
	if store == nil {
		return nil
	}
	history, err := store.Load(ctx)
	if err != nil {
		return err
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.rolloutHistoryStore = store
	metrics.rolloutHistory = history
	return nil
}

func configurePolicyActionHistory(ctx context.Context, metrics *agentMetrics, store policyActionHistoryStore) error {
	if metrics == nil {
		return nil
	}
	if store == nil {
		return nil
	}
	history, err := store.Load(ctx)
	if err != nil {
		return err
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.actionHistoryStore = store
	metrics.actionHistory = history
	return nil
}

func configurePolicyStatusStore(metrics *agentMetrics, store policyStatusStore) {
	if metrics == nil || store == nil {
		return
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.policyStatusStore = store
}

func configurePolicyEventsStore(metrics *agentMetrics, store policyEventsStore) {
	if metrics == nil || store == nil {
		return
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.policyEventsStore = store
}

func configurePolicyRulesStore(metrics *agentMetrics, store policyRulesStore) {
	if metrics == nil || store == nil {
		return
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.policyRulesStore = store
}

func configurePolicyEntriesStore(metrics *agentMetrics, store policyEntriesStore) {
	if metrics == nil || store == nil {
		return
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.policyEntriesStore = store
}

func configurePolicyFreezeState(ctx context.Context, metrics *agentMetrics, store policyFreezeStateStore) error {
	if metrics == nil {
		return nil
	}
	if store == nil {
		return nil
	}
	doc, err := store.Load(ctx)
	if err != nil {
		return err
	}
	frozen := make(map[string]time.Time, len(doc.FrozenEndpoints))
	now := time.Now()
	for _, entry := range doc.FrozenEndpoints {
		endpointID := strings.TrimSpace(entry.EndpointID)
		if endpointID == "" {
			continue
		}
		if !entry.ExpiresAt.IsZero() && !now.Before(entry.ExpiresAt) {
			continue
		}
		frozen[endpointID] = entry.ExpiresAt
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.freezeStateStore = store
	metrics.frozenEndpoints = frozen
	return nil
}

func trimPolicyRolloutHistory(history []policyRolloutHistoryEntry) []policyRolloutHistoryEntry {
	const limit = 128
	if len(history) <= limit {
		return append([]policyRolloutHistoryEntry(nil), history...)
	}
	return append([]policyRolloutHistoryEntry(nil), history[len(history)-limit:]...)
}

func filterPolicyRolloutHistory(history []policyRolloutHistoryEntry, source, name string) []policyRolloutHistoryEntry {
	source = strings.TrimSpace(source)
	name = strings.TrimSpace(name)
	out := make([]policyRolloutHistoryEntry, 0, len(history))
	for _, entry := range history {
		if source != "" && entry.Source != source {
			continue
		}
		if name != "" && entry.Name != name {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func recentPolicyRolloutHistory(history []policyRolloutHistoryEntry, limit int) []policyRolloutHistoryEntry {
	if limit == 0 || len(history) == 0 {
		return nil
	}
	if len(history) <= limit {
		return append([]policyRolloutHistoryEntry(nil), history...)
	}
	return append([]policyRolloutHistoryEntry(nil), history[len(history)-limit:]...)
}

func filterPolicyRolloutState(rollouts []policyRolloutStateEntry, name, node string) []policyRolloutStateEntry {
	name = strings.TrimSpace(name)
	node = strings.TrimSpace(node)
	out := make([]policyRolloutStateEntry, 0, len(rollouts))
	for _, rollout := range rollouts {
		if name != "" && rollout.Name != name {
			continue
		}
		if node != "" && rollout.Node != node {
			continue
		}
		out = append(out, rollout)
	}
	return out
}

func filterPolicyFreezeState(entries []policyFreezeStateEntry, endpoint string) []policyFreezeStateEntry {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return append([]policyFreezeStateEntry(nil), entries...)
	}
	candidates := policyEndpointCandidates(endpoint)
	out := make([]policyFreezeStateEntry, 0, len(entries))
	for _, entry := range entries {
		if _, ok := candidates[entry.EndpointID]; ok {
			out = append(out, entry)
		}
	}
	return out
}

func trimPolicyActionHistory(history []policyActionHistoryEntry) []policyActionHistoryEntry {
	const limit = 256
	if len(history) <= limit {
		return append([]policyActionHistoryEntry(nil), history...)
	}
	return append([]policyActionHistoryEntry(nil), history[len(history)-limit:]...)
}

func (m *agentMetrics) recordPolicyRolloutHistory(entry policyRolloutHistoryEntry) error {
	if m == nil {
		return nil
	}
	if entry.ID == "" {
		entry.ID = strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	if entry.CompletedAt.IsZero() {
		entry.CompletedAt = time.Now().UTC()
	}
	m.mu.Lock()
	m.rolloutHistory = trimPolicyRolloutHistory(append(m.rolloutHistory, entry))
	store := m.rolloutHistoryStore
	m.mu.Unlock()
	if store == nil {
		return nil
	}
	return store.Append(context.Background(), entry)
}

func (m *agentMetrics) recordPolicyActionHistory(ctx context.Context, entry policyActionHistoryEntry) error {
	if m == nil {
		return nil
	}
	if entry.ID == "" {
		entry.ID = strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	if entry.CompletedAt.IsZero() {
		entry.CompletedAt = time.Now().UTC()
	}
	if entry.Error == "" {
		entry.Success = true
	}
	m.mu.Lock()
	m.actionHistory = trimPolicyActionHistory(append(m.actionHistory, entry))
	store := m.actionHistoryStore
	m.mu.Unlock()
	if store == nil {
		return nil
	}
	return store.Append(ctx, entry)
}

func (m *agentMetrics) policyRolloutHistory() []policyRolloutHistoryEntry {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]policyRolloutHistoryEntry(nil), m.rolloutHistory...)
}

func (m *agentMetrics) policyActionHistory() []policyActionHistoryEntry {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]policyActionHistoryEntry(nil), m.actionHistory...)
}

func filterPolicyActionHistory(history []policyActionHistoryEntry, endpoint, action string, success *bool) []policyActionHistoryEntry {
	endpoint = strings.TrimSpace(endpoint)
	action = strings.TrimSpace(action)
	candidates := map[string]struct{}{}
	if endpoint != "" {
		candidates = policyEndpointCandidates(endpoint)
	}
	out := make([]policyActionHistoryEntry, 0, len(history))
	for _, entry := range history {
		if action != "" && entry.Action != action {
			continue
		}
		if success != nil && entry.Success != *success {
			continue
		}
		if endpoint != "" {
			if _, ok := candidates[entry.EndpointID]; !ok {
				continue
			}
		}
		out = append(out, entry)
	}
	return out
}

func recentPolicyActionHistory(history []policyActionHistoryEntry, limit int) []policyActionHistoryEntry {
	if limit == 0 || len(history) == 0 {
		return nil
	}
	if len(history) <= limit {
		return append([]policyActionHistoryEntry(nil), history...)
	}
	return append([]policyActionHistoryEntry(nil), history[len(history)-limit:]...)
}

func recordNamedPolicyRolloutHistory(metrics *agentMetrics, source string, rollouts []agent.NamedPolicyEndpointRollout, node, store string, duration time.Duration) {
	for _, rollout := range rollouts {
		if err := metrics.recordPolicyRolloutHistory(policyRolloutHistoryEntry{
			Source:     source,
			Name:       rollout.Name,
			Node:       node,
			Store:      store,
			DurationMS: duration.Milliseconds(),
			Rollout:    rollout.Rollout,
		}); err != nil {
			log.Printf("record policy rollout history: %v", err)
		}
	}
}

func loadPolicyRolloutResume(ctx context.Context, store policyRolloutStateStore, node string, state control.DesiredState) (map[string][]string, error) {
	if store == nil {
		return nil, nil
	}
	doc, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	revisions, err := desiredPolicyRolloutRevisions(state, node)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string)
	for _, entry := range doc.Rollouts {
		if entry.Name == "" || (entry.Node != "" && entry.Node != node) {
			continue
		}
		if revision := revisions[entry.Name]; revision == "" || entry.Revision != revision {
			continue
		}
		out[entry.Name] = uniqueStrings(append(out[entry.Name], entry.AppliedEndpoints...))
	}
	return out, nil
}

func desiredPolicyRolloutRevisions(state control.DesiredState, node string) (map[string]string, error) {
	out := make(map[string]string)
	for _, rollout := range state.PolicyRollouts {
		if rollout.Disabled || (rollout.Node != "" && rollout.Node != node) {
			continue
		}
		endpointIDs, err := rolloutEndpointIDsForRevision(state, rollout)
		if err != nil {
			return nil, fmt.Errorf("policy rollout %q: %w", rollout.Name, err)
		}
		revision, err := agent.PolicyRolloutRevision(state, rollout, endpointIDs)
		if err != nil {
			return nil, fmt.Errorf("policy rollout %q: %w", rollout.Name, err)
		}
		out[rollout.Name] = revision
	}
	return out, nil
}

func rolloutEndpointIDsForRevision(state control.DesiredState, rollout control.PolicyRollout) ([]string, error) {
	if len(rollout.Endpoints) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(rollout.Endpoints))
	for _, ref := range rollout.Endpoints {
		endpointID, err := resolveDesiredEndpointRefForRevision(state.Endpoints, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, endpointID)
	}
	return out, nil
}

func resolveDesiredEndpointRefForRevision(endpoints []model.Endpoint, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", fmt.Errorf("endpoint reference is empty")
	}
	if strings.Contains(ref, "\x00") {
		for _, endpoint := range endpoints {
			if model.EndpointKey(endpoint.VPC, endpoint.ID) == ref {
				return ref, nil
			}
		}
		return "", fmt.Errorf("endpoint %q not found in desired state", ref)
	}
	vpc, id, ok := strings.Cut(ref, "/")
	if !ok || vpc == "" || id == "" {
		return "", fmt.Errorf("endpoint reference %q must use vpc/id", ref)
	}
	endpointID := model.EndpointKey(vpc, id)
	for _, endpoint := range endpoints {
		if model.EndpointKey(endpoint.VPC, endpoint.ID) == endpointID {
			return endpointID, nil
		}
	}
	return "", fmt.Errorf("endpoint %q not found in desired state", ref)
}

func savePolicyRolloutResume(ctx context.Context, store policyRolloutStateStore, node, storeName string, rollouts []agent.NamedPolicyEndpointRollout) error {
	if store == nil {
		return nil
	}
	doc, err := store.Load(ctx)
	if err != nil {
		return err
	}
	next := make([]policyRolloutStateEntry, 0, len(doc.Rollouts)+len(rollouts))
	for _, entry := range doc.Rollouts {
		if entry.Node == node {
			continue
		}
		next = append(next, entry)
	}
	for _, named := range rollouts {
		applied := rolloutAppliedEndpoints(named.Rollout)
		if len(applied) == 0 || (!named.Rollout.Paused && named.Rollout.Failed == 0) || named.Rollout.DryRun {
			continue
		}
		next = append(next, policyRolloutStateEntry{
			Name:             named.Name,
			Node:             node,
			Revision:         named.Rollout.Revision,
			Store:            storeName,
			UpdatedAt:        time.Now().UTC(),
			AppliedEndpoints: applied,
			Paused:           named.Rollout.Paused,
			Failed:           named.Rollout.Failed,
		})
	}
	doc.Rollouts = next
	return store.Save(ctx, doc)
}

func rolloutAppliedEndpoints(rollout agent.PolicyEndpointRollout) []string {
	endpoints := make([]string, 0, len(rollout.Items))
	for _, item := range rollout.Items {
		switch item.Phase {
		case "applied", "resumed_applied":
			endpoints = append(endpoints, item.EndpointID)
		}
	}
	return uniqueStrings(endpoints)
}

func (s ovsdbPolicyRolloutStateStore) Load(ctx context.Context) (policyRolloutStateDocument, error) {
	var doc policyRolloutStateDocument
	if s.syncer == nil {
		return doc, nil
	}
	raw, ok, err := s.syncer.OpenVSwitchExternalID(ctx, policyRolloutStateKey)
	if err != nil {
		return doc, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return doc, nil
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return doc, fmt.Errorf("decode Open_vSwitch external_ids:%s: %w", policyRolloutStateKey, err)
	}
	return doc, nil
}

func (s ovsdbPolicyRolloutStateStore) Save(ctx context.Context, doc policyRolloutStateDocument) error {
	if s.syncer == nil {
		return nil
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode Open_vSwitch external_ids:%s: %w", policyRolloutStateKey, err)
	}
	return s.syncer.SetOpenVSwitchExternalID(ctx, policyRolloutStateKey, string(raw))
}

func (s ovsdbPolicyFreezeStateStore) Load(ctx context.Context) (policyFreezeStateDocument, error) {
	var doc policyFreezeStateDocument
	if s.syncer == nil {
		return doc, nil
	}
	raw, ok, err := s.syncer.OpenVSwitchExternalID(ctx, policyFreezeStateKey)
	if err != nil {
		return doc, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return doc, nil
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return doc, fmt.Errorf("decode Open_vSwitch external_ids:%s: %w", policyFreezeStateKey, err)
	}
	doc.FrozenEndpoints = normalizePolicyFreezeStateEntries(doc.FrozenEndpoints, time.Now())
	return doc, nil
}

func (s ovsdbPolicyFreezeStateStore) Save(ctx context.Context, doc policyFreezeStateDocument) error {
	if s.syncer == nil {
		return nil
	}
	doc.FrozenEndpoints = normalizePolicyFreezeStateEntries(doc.FrozenEndpoints, time.Now())
	if doc.UpdatedAt.IsZero() {
		doc.UpdatedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode Open_vSwitch external_ids:%s: %w", policyFreezeStateKey, err)
	}
	return s.syncer.SetOpenVSwitchExternalID(ctx, policyFreezeStateKey, string(raw))
}

func (s ovsdbPolicyRolloutHistoryStore) Load(ctx context.Context) ([]policyRolloutHistoryEntry, error) {
	if s.syncer == nil {
		return nil, nil
	}
	raw, ok, err := s.syncer.OpenVSwitchExternalID(ctx, policyRolloutHistoryKey)
	if err != nil {
		return nil, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var history []policyRolloutHistoryEntry
	if err := json.Unmarshal([]byte(raw), &history); err != nil {
		return nil, fmt.Errorf("decode Open_vSwitch external_ids:%s: %w", policyRolloutHistoryKey, err)
	}
	return trimPolicyRolloutHistory(history), nil
}

func (s ovsdbPolicyRolloutHistoryStore) Append(ctx context.Context, entry policyRolloutHistoryEntry) error {
	if s.syncer == nil {
		return nil
	}
	history, err := s.Load(ctx)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(trimPolicyRolloutHistory(append(history, entry)))
	if err != nil {
		return fmt.Errorf("encode Open_vSwitch external_ids:%s: %w", policyRolloutHistoryKey, err)
	}
	return s.syncer.SetOpenVSwitchExternalID(ctx, policyRolloutHistoryKey, string(raw))
}

func (s ovsdbPolicyActionHistoryStore) Load(ctx context.Context) ([]policyActionHistoryEntry, error) {
	if s.syncer == nil {
		return nil, nil
	}
	raw, ok, err := s.syncer.OpenVSwitchExternalID(ctx, policyActionHistoryKey)
	if err != nil {
		return nil, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var history []policyActionHistoryEntry
	if err := json.Unmarshal([]byte(raw), &history); err != nil {
		return nil, fmt.Errorf("decode Open_vSwitch external_ids:%s: %w", policyActionHistoryKey, err)
	}
	return trimPolicyActionHistory(history), nil
}

func (s ovsdbPolicyActionHistoryStore) Append(ctx context.Context, entry policyActionHistoryEntry) error {
	if s.syncer == nil {
		return nil
	}
	history, err := s.Load(ctx)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(trimPolicyActionHistory(append(history, entry)))
	if err != nil {
		return fmt.Errorf("encode Open_vSwitch external_ids:%s: %w", policyActionHistoryKey, err)
	}
	return s.syncer.SetOpenVSwitchExternalID(ctx, policyActionHistoryKey, string(raw))
}

func (s ovsdbPolicyStatusStore) Load(ctx context.Context) (policyStatusDocument, error) {
	var doc policyStatusDocument
	if s.syncer == nil {
		return doc, nil
	}
	raw, ok, err := s.syncer.OpenVSwitchExternalID(ctx, policyEndpointStatusKey)
	if err != nil {
		return doc, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return doc, nil
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return doc, fmt.Errorf("decode Open_vSwitch external_ids:%s: %w", policyEndpointStatusKey, err)
	}
	return doc, nil
}

func (s ovsdbPolicyStatusStore) Save(ctx context.Context, doc policyStatusDocument) error {
	if s.syncer == nil {
		return nil
	}
	if doc.UpdatedAt.IsZero() {
		doc.UpdatedAt = time.Now().UTC()
	}
	if doc.EndpointCount < len(doc.Statuses) {
		doc.EndpointCount = len(doc.Statuses)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode Open_vSwitch external_ids:%s: %w", policyEndpointStatusKey, err)
	}
	return s.syncer.SetOpenVSwitchExternalID(ctx, policyEndpointStatusKey, string(raw))
}

func (s ovsdbPolicyEventsStore) Load(ctx context.Context) (policyEventsDocument, error) {
	var doc policyEventsDocument
	if s.syncer == nil {
		return doc, nil
	}
	raw, ok, err := s.syncer.OpenVSwitchExternalID(ctx, policyEventsKey)
	if err != nil {
		return doc, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return doc, nil
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return doc, fmt.Errorf("decode Open_vSwitch external_ids:%s: %w", policyEventsKey, err)
	}
	doc.Events = trimPolicyUpdateEvents(doc.Events)
	if doc.TotalEvents < len(doc.Events) {
		doc.TotalEvents = len(doc.Events)
	}
	return doc, nil
}

func (s ovsdbPolicyEventsStore) Save(ctx context.Context, doc policyEventsDocument) error {
	if s.syncer == nil {
		return nil
	}
	doc.Events = trimPolicyUpdateEvents(doc.Events)
	if doc.TotalEvents < len(doc.Events) {
		doc.TotalEvents = len(doc.Events)
	}
	if doc.UpdatedAt.IsZero() {
		doc.UpdatedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode Open_vSwitch external_ids:%s: %w", policyEventsKey, err)
	}
	return s.syncer.SetOpenVSwitchExternalID(ctx, policyEventsKey, string(raw))
}

func (s ovsdbPolicyRulesStore) Load(ctx context.Context) (policyRulesDocument, error) {
	var doc policyRulesDocument
	if s.syncer == nil {
		return doc, nil
	}
	raw, ok, err := s.syncer.OpenVSwitchExternalID(ctx, policyRulesKey)
	if err != nil {
		return doc, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return doc, nil
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return doc, fmt.Errorf("decode Open_vSwitch external_ids:%s: %w", policyRulesKey, err)
	}
	return doc, nil
}

func (s ovsdbPolicyRulesStore) Save(ctx context.Context, doc policyRulesDocument) error {
	if s.syncer == nil {
		return nil
	}
	if doc.UpdatedAt.IsZero() {
		doc.UpdatedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode Open_vSwitch external_ids:%s: %w", policyRulesKey, err)
	}
	return s.syncer.SetOpenVSwitchExternalID(ctx, policyRulesKey, string(raw))
}

func (s ovsdbPolicyEntriesStore) Load(ctx context.Context) (policyEntriesDocument, error) {
	var doc policyEntriesDocument
	if s.syncer == nil {
		return doc, nil
	}
	raw, ok, err := s.syncer.OpenVSwitchExternalID(ctx, policyEntriesKey)
	if err != nil {
		return doc, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return doc, nil
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return doc, fmt.Errorf("decode Open_vSwitch external_ids:%s: %w", policyEntriesKey, err)
	}
	return doc, nil
}

func (s ovsdbPolicyEntriesStore) Save(ctx context.Context, doc policyEntriesDocument) error {
	if s.syncer == nil {
		return nil
	}
	if doc.UpdatedAt.IsZero() {
		doc.UpdatedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode Open_vSwitch external_ids:%s: %w", policyEntriesKey, err)
	}
	return s.syncer.SetOpenVSwitchExternalID(ctx, policyEntriesKey, string(raw))
}

func (s ovsdbDNSObservationStore) LoadDNSObservations(ctx context.Context) ([]model.DNSRecord, error) {
	if s.syncer == nil {
		return nil, nil
	}
	raw, ok, err := s.syncer.OpenVSwitchExternalID(ctx, control.DNSObservationsOpenVSwitchExternalID)
	if err != nil {
		return nil, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	records, err := control.LoadDNSObservationsJSON(strings.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode Open_vSwitch external_ids:%s: %w", control.DNSObservationsOpenVSwitchExternalID, err)
	}
	return records, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizePolicyFreezeStateEntries(values []policyFreezeStateEntry, now time.Time) []policyFreezeStateEntry {
	seen := make(map[string]policyFreezeStateEntry, len(values))
	for _, value := range values {
		value.EndpointID = strings.TrimSpace(value.EndpointID)
		if value.EndpointID == "" {
			continue
		}
		if !value.ExpiresAt.IsZero() && !now.Before(value.ExpiresAt) {
			continue
		}
		seen[value.EndpointID] = value
	}
	out := make([]policyFreezeStateEntry, 0, len(seen))
	for _, value := range seen {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].EndpointID < out[j].EndpointID
	})
	return out
}

func sortedFrozenPolicyEndpointIDs(values map[string]time.Time) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func cloneFrozenPolicyEndpoints(values map[string]time.Time) map[string]time.Time {
	out := make(map[string]time.Time, len(values))
	for endpointID, expiresAt := range values {
		endpointID = strings.TrimSpace(endpointID)
		if endpointID == "" {
			continue
		}
		out[endpointID] = expiresAt
	}
	return out
}

func observeAgentReconcileResult(metrics *agentMetrics, result agent.ReconcileResult, storeName string, duration time.Duration, runtimeChecks ...[]agent.RuntimeCheck) {
	observeAgentReconcileResultWithState(metrics, result, storeName, duration, control.DesiredState{}, runtimeChecks...)
}

func observeAgentReconcileResultWithState(metrics *agentMetrics, result agent.ReconcileResult, storeName string, duration time.Duration, state control.DesiredState, runtimeChecks ...[]agent.RuntimeCheck) {
	if metrics == nil {
		return
	}
	metrics.observe(agentMetricsSnapshot{
		Result:   result,
		Store:    storeName,
		State:    cloneDesiredState(state),
		Duration: duration,
		Success:  true,
		Runtime:  firstRuntimeChecks(runtimeChecks),
	})
}

func observeAgentReconcileFailure(metrics *agentMetrics, result agent.ReconcileResult, storeName string, err error, duration time.Duration, runtimeChecks ...[]agent.RuntimeCheck) {
	if metrics == nil {
		return
	}
	message := ""
	if err != nil {
		message = err.Error()
	}
	metrics.observe(agentMetricsSnapshot{
		Result:   result,
		Store:    storeName,
		Duration: duration,
		Success:  false,
		Error:    message,
		Runtime:  firstRuntimeChecks(runtimeChecks),
	})
}

func firstRuntimeChecks(values [][]agent.RuntimeCheck) []agent.RuntimeCheck {
	if len(values) == 0 {
		return nil
	}
	return cloneRuntimeChecks(values[0])
}

func (m *agentMetrics) observe(snapshot agentMetricsSnapshot) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.snapshot = snapshot
	m.totals.observe(snapshot)
	m.ready = true
	statusStore := m.policyStatusStore
	eventStore := m.policyEventsStore
	rulesStore := m.policyRulesStore
	entriesStore := m.policyEntriesStore
	policyStore := m.store
	events := policyUpdateEventsFromStore(m.store)
	m.mu.Unlock()
	if statusStore != nil {
		doc := policyStatusDocumentFromSnapshot(snapshot)
		if err := statusStore.Save(context.Background(), doc); err != nil {
			log.Printf("persist policy endpoint status: %v", err)
		}
	}
	if eventStore != nil {
		doc := policyEventsDocumentFromSnapshot(snapshot, events)
		if err := eventStore.Save(context.Background(), doc); err != nil {
			log.Printf("persist policy events: %v", err)
		}
	}
	if rulesStore != nil {
		doc := policyRulesDocumentFromSnapshot(snapshot)
		if err := rulesStore.Save(context.Background(), doc); err != nil {
			log.Printf("persist policy rules: %v", err)
		}
	}
	if entriesStore != nil {
		doc, ok, err := policyEntriesDocumentFromStore(context.Background(), snapshot, policyStore)
		if err != nil {
			log.Printf("build policy entries snapshot: %v", err)
		} else if ok {
			if err := entriesStore.Save(context.Background(), doc); err != nil {
				log.Printf("persist policy entries: %v", err)
			}
		}
	}
}

func policyUpdateEventsFromStore(store agent.PolicyStore) []dataplane.PolicyUpdateEvent {
	eventStore, ok := store.(agent.PolicyEventStore)
	if !ok {
		return nil
	}
	return eventStore.Events()
}

func policyEventsDocumentFromSnapshot(snapshot agentMetricsSnapshot, events []dataplane.PolicyUpdateEvent) policyEventsDocument {
	return policyEventsDocument{
		Node:                 snapshot.Result.Node,
		Store:                snapshot.Store,
		LastReconcileSuccess: snapshot.Success,
		LastReconcileError:   snapshot.Error,
		UpdatedAt:            time.Now().UTC(),
		TotalEvents:          len(events),
		Events:               trimPolicyUpdateEvents(events),
	}
}

func policyRulesDocumentFromSnapshot(snapshot agentMetricsSnapshot) policyRulesDocument {
	output := policyRulesOutputFromResult(snapshot.Result, snapshot.Store, policyRuleFilter{})
	return policyRulesDocument{
		Node:                 output.Node,
		Store:                output.Store,
		LastReconcileSuccess: snapshot.Success,
		LastReconcileError:   snapshot.Error,
		UpdatedAt:            time.Now().UTC(),
		Rules:                append([]policyRuleOutput(nil), output.Rules...),
	}
}

func policyEntriesDocumentFromStore(ctx context.Context, snapshot agentMetricsSnapshot, store agent.PolicyStore) (policyEntriesDocument, bool, error) {
	var doc policyEntriesDocument
	inventory, ok := store.(agent.PolicyEndpointInventory)
	if !ok {
		return doc, false, nil
	}
	entryStore, ok := store.(agent.PolicyEndpointEntryStore)
	if !ok {
		return doc, false, nil
	}
	endpointIDs, err := inventory.EndpointIDs(ctx)
	if err != nil {
		return doc, false, err
	}
	sort.Strings(endpointIDs)
	doc = policyEntriesDocument{
		Node:                 snapshot.Result.Node,
		Store:                snapshot.Store,
		LastReconcileSuccess: snapshot.Success,
		LastReconcileError:   snapshot.Error,
		UpdatedAt:            time.Now().UTC(),
		Endpoints:            make([]policyEntriesEndpointOutput, 0, len(endpointIDs)),
	}
	for _, endpointID := range endpointIDs {
		doc.Endpoints = append(doc.Endpoints, policyEntriesEndpointOutputFromEntries(endpointID, entryStore.Entries(endpointID)))
	}
	return doc, true, nil
}

func (t *agentMetricsTotals) observe(snapshot agentMetricsSnapshot) {
	t.Attempts++
	if snapshot.Success {
		t.Successes++
	} else {
		t.Failures++
	}
	t.DurationSum += snapshot.Duration
	for i, bucket := range agentReconcileDurationBuckets {
		if snapshot.Duration <= bucket {
			t.DurationBuckets[i]++
		}
	}
	result := snapshot.Result
	t.PolicyAdded += uint64(nonNegative(result.PolicyAdded))
	t.PolicyUpdated += uint64(nonNegative(result.PolicyUpdated))
	t.PolicyDeleted += uint64(nonNegative(result.PolicyDeleted))
	t.PolicyUnchanged += uint64(nonNegative(result.PolicyUnchanged))
	t.PolicyEvents += uint64(nonNegative(result.PolicyEvents))
	t.PolicyFailed += uint64(nonNegative(result.PolicyFailed))
	t.PolicyRollbacks += uint64(nonNegative(result.PolicyRollbacks))
	t.PolicyGCEndpoints += uint64(nonNegative(result.PolicyGCEndpoints))
	t.PolicyPressureMitigated += uint64(nonNegative(result.PolicyPressureMitigated))
	t.PolicyPressureQuarantined += uint64(nonNegative(result.PolicyPressureQuarantined))
	t.PolicyRolloutPlanned += uint64(nonNegative(result.PolicyRolloutPlanned))
	t.PolicyRolloutApplied += uint64(nonNegative(result.PolicyRolloutApplied))
	t.PolicyRolloutSkipped += uint64(nonNegative(result.PolicyRolloutSkipped))
	t.PolicyRolloutFailed += uint64(nonNegative(result.PolicyRolloutFailed))
	t.PolicyRolloutRolledBack += uint64(nonNegative(result.PolicyRolloutRolledBack))
	t.PolicyRolloutRollbackFail += uint64(nonNegative(result.PolicyRolloutRollbackFailed))
	t.PolicyRolloutSLOFailed += uint64(nonNegative(result.PolicyRolloutSLOFailed))
	t.PolicyRolloutProbeFailed += uint64(nonNegative(result.PolicyRolloutProbeFailed))
	t.PolicyRolloutPaused += uint64(nonNegative(result.PolicyRolloutPaused))
	t.PolicyRolloutCancelled += uint64(nonNegative(result.PolicyRolloutCancelled))
	t.TCXFailed += uint64(nonNegative(result.TCXFailed))
	t.TCXRollbacks += uint64(nonNegative(result.TCXRollbacks))
	t.ProviderDegraded += uint64(nonNegative(result.ProviderDegraded))
	t.ConntrackExpired += uint64(nonNegative(result.ConntrackExpired))
	t.PolicyRulePackets += result.PolicyRulePackets
	t.PolicyRuleBytes += result.PolicyRuleBytes
	t.PolicyRuleDropped += result.PolicyRuleDropped
	t.PolicyRuleRejected += result.PolicyRuleRejected
	noMatchDrops, denyDrops, rejectDrops := policyRuleDropReasonTotals(result.PolicyRuleStats)
	t.PolicyRuleNoMatchDrops += noMatchDrops
	t.PolicyRuleDenyDrops += denyDrops
	t.PolicyRuleRejectDrops += rejectDrops
}

func (m *agentMetrics) snapshotValue() (agentMetricsSnapshot, agentMetricsTotals, bool) {
	if m == nil {
		return agentMetricsSnapshot{}, agentMetricsTotals{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshot, cloneAgentMetricsTotals(m.totals), m.ready
}

func (m *agentMetrics) frozenPolicyEndpointsSnapshot() map[string]struct{} {
	if m == nil {
		return nil
	}
	m.pruneExpiredFrozenPolicyEndpoints(context.Background(), time.Now())
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.frozenEndpoints) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(m.frozenEndpoints))
	for endpointID := range m.frozenEndpoints {
		out[endpointID] = struct{}{}
	}
	return out
}

func (m *agentMetrics) frozenPolicyEndpointIDs() []string {
	if m == nil {
		return nil
	}
	m.pruneExpiredFrozenPolicyEndpoints(context.Background(), time.Now())
	m.mu.RLock()
	defer m.mu.RUnlock()
	return sortedFrozenPolicyEndpointIDs(m.frozenEndpoints)
}

func (m *agentMetrics) frozenPolicyEndpointExpirations() map[string]time.Time {
	if m == nil {
		return nil
	}
	m.pruneExpiredFrozenPolicyEndpoints(context.Background(), time.Now())
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]time.Time)
	for endpointID, expiresAt := range m.frozenEndpoints {
		if expiresAt.IsZero() {
			continue
		}
		out[endpointID] = expiresAt
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (m *agentMetrics) frozenPolicyStateEntriesLocked() []policyFreezeStateEntry {
	entries := make([]policyFreezeStateEntry, 0, len(m.frozenEndpoints))
	for endpointID, expiresAt := range m.frozenEndpoints {
		entries = append(entries, policyFreezeStateEntry{
			EndpointID: endpointID,
			ExpiresAt:  expiresAt,
		})
	}
	return normalizePolicyFreezeStateEntries(entries, time.Now())
}

func (m *agentMetrics) saveFrozenPolicyEndpoints(ctx context.Context, endpoints []policyFreezeStateEntry) error {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	store := m.freezeStateStore
	m.mu.RUnlock()
	if store == nil {
		return nil
	}
	return store.Save(ctx, policyFreezeStateDocument{
		FrozenEndpoints: endpoints,
		UpdatedAt:       time.Now().UTC(),
	})
}

func (m *agentMetrics) pruneExpiredFrozenPolicyEndpoints(ctx context.Context, now time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	changed := false
	for endpointID, expiresAt := range m.frozenEndpoints {
		if expiresAt.IsZero() || now.Before(expiresAt) {
			continue
		}
		delete(m.frozenEndpoints, endpointID)
		changed = true
	}
	if !changed {
		m.mu.Unlock()
		return
	}
	next := m.frozenPolicyStateEntriesLocked()
	m.mu.Unlock()
	if err := m.saveFrozenPolicyEndpoints(ctx, next); err != nil {
		log.Printf("persist expired policy freeze cleanup: %v", err)
	}
}

func (m *agentMetrics) policyEndpointFrozen(endpointID string) bool {
	if m == nil {
		return false
	}
	m.pruneExpiredFrozenPolicyEndpoints(context.Background(), time.Now())
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.frozenEndpoints[endpointID]
	return ok
}

func (m *agentMetrics) freezePolicyEndpoint(ctx context.Context, endpoint string, expiresAt time.Time) (string, time.Time, error) {
	if m == nil {
		return "", time.Time{}, errors.New("policy endpoint actions are not enabled")
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready || !snapshot.Success {
		return "", time.Time{}, errors.New("policy endpoint state is not ready")
	}
	endpointID, err := resolvePolicyEndpointIDFromSnapshot(endpoint, snapshot)
	if err != nil {
		return "", time.Time{}, err
	}
	m.mu.Lock()
	previous := cloneFrozenPolicyEndpoints(m.frozenEndpoints)
	if m.frozenEndpoints == nil {
		m.frozenEndpoints = make(map[string]time.Time)
	}
	m.frozenEndpoints[endpointID] = expiresAt
	next := m.frozenPolicyStateEntriesLocked()
	m.mu.Unlock()
	if err := m.saveFrozenPolicyEndpoints(ctx, next); err != nil {
		m.mu.Lock()
		m.frozenEndpoints = previous
		m.mu.Unlock()
		return "", time.Time{}, err
	}
	return endpointID, expiresAt, nil
}

func (m *agentMetrics) unfreezePolicyEndpoint(ctx context.Context, endpoint string) (string, error) {
	if m == nil {
		return "", errors.New("policy endpoint actions are not enabled")
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready || !snapshot.Success {
		return "", errors.New("policy endpoint state is not ready")
	}
	endpointID, err := resolvePolicyEndpointIDFromSnapshot(endpoint, snapshot)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	previous := cloneFrozenPolicyEndpoints(m.frozenEndpoints)
	delete(m.frozenEndpoints, endpointID)
	next := m.frozenPolicyStateEntriesLocked()
	m.mu.Unlock()
	if err := m.saveFrozenPolicyEndpoints(ctx, next); err != nil {
		m.mu.Lock()
		m.frozenEndpoints = previous
		m.mu.Unlock()
		return "", err
	}
	return endpointID, nil
}

func (m *agentMetrics) deletePolicyEndpoint(ctx context.Context, endpoint string) (string, error) {
	if m == nil || m.store == nil {
		return "", errors.New("policy endpoint actions are not enabled")
	}
	endpointID, err := m.resolvePolicyEndpointID(endpoint)
	if err != nil {
		return "", err
	}
	if m.policyEndpointFrozen(endpointID) {
		return "", fmt.Errorf("policy endpoint %s is frozen", endpointID)
	}
	if err := m.store.DeleteEndpoint(ctx, endpointID); err != nil {
		return "", err
	}
	m.removePolicyEndpointStatus(endpointID)
	return endpointID, nil
}

func (m *agentMetrics) regeneratePolicyEndpoint(ctx context.Context, endpoint string) (dataplane.PolicyEndpointStatus, error) {
	if m == nil || m.store == nil {
		return dataplane.PolicyEndpointStatus{}, errors.New("policy endpoint actions are not enabled")
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready || !snapshot.Success {
		return dataplane.PolicyEndpointStatus{}, errors.New("policy endpoint state is not ready")
	}
	endpointID, err := resolvePolicyEndpointIDFromSnapshot(endpoint, snapshot)
	if err != nil {
		return dataplane.PolicyEndpointStatus{}, err
	}
	status, err := agent.RegeneratePolicyEndpoint(ctx, snapshot.State, agent.ReconcileOptions{
		Node:                  snapshot.Result.Node,
		Store:                 m.store,
		FrozenPolicyEndpoints: m.frozenPolicyEndpointsSnapshot(),
	}, endpointID)
	if err != nil {
		return dataplane.PolicyEndpointStatus{}, err
	}
	m.upsertPolicyEndpointStatus(status)
	return status, nil
}

func (m *agentMetrics) planPolicyEndpoint(ctx context.Context, endpoint string) (agent.PolicyEndpointPlan, error) {
	if m == nil || m.store == nil {
		return agent.PolicyEndpointPlan{}, errors.New("policy endpoint actions are not enabled")
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready || !snapshot.Success {
		return agent.PolicyEndpointPlan{}, errors.New("policy endpoint state is not ready")
	}
	endpointID, err := resolvePolicyEndpointIDFromSnapshot(endpoint, snapshot)
	if err != nil {
		return agent.PolicyEndpointPlan{}, err
	}
	return agent.PlanPolicyEndpoint(ctx, snapshot.State, agent.ReconcileOptions{
		Node:                  snapshot.Result.Node,
		Store:                 m.store,
		FrozenPolicyEndpoints: m.frozenPolicyEndpointsSnapshot(),
	}, endpointID)
}

func (m *agentMetrics) quarantinePolicyEndpoint(ctx context.Context, endpoint string) (dataplane.PolicyEndpointStatus, error) {
	if m == nil || m.store == nil {
		return dataplane.PolicyEndpointStatus{}, errors.New("policy endpoint actions are not enabled")
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready || !snapshot.Success {
		return dataplane.PolicyEndpointStatus{}, errors.New("policy endpoint state is not ready")
	}
	endpointID, err := resolvePolicyEndpointIDFromSnapshot(endpoint, snapshot)
	if err != nil {
		return dataplane.PolicyEndpointStatus{}, err
	}
	status, err := agent.QuarantinePolicyEndpoint(ctx, snapshot.State, agent.ReconcileOptions{
		Node:                  snapshot.Result.Node,
		Store:                 m.store,
		FrozenPolicyEndpoints: m.frozenPolicyEndpointsSnapshot(),
	}, endpointID)
	if err != nil {
		return dataplane.PolicyEndpointStatus{}, err
	}
	m.upsertPolicyEndpointStatus(status)
	return status, nil
}

func (m *agentMetrics) unquarantinePolicyEndpoint(ctx context.Context, endpoint string) (dataplane.PolicyEndpointStatus, error) {
	if m == nil || m.store == nil {
		return dataplane.PolicyEndpointStatus{}, errors.New("policy endpoint actions are not enabled")
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready || !snapshot.Success {
		return dataplane.PolicyEndpointStatus{}, errors.New("policy endpoint state is not ready")
	}
	endpointID, err := resolvePolicyEndpointIDFromSnapshot(endpoint, snapshot)
	if err != nil {
		return dataplane.PolicyEndpointStatus{}, err
	}
	status, err := agent.UnquarantinePolicyEndpoint(ctx, snapshot.State, agent.ReconcileOptions{
		Node:                  snapshot.Result.Node,
		Store:                 m.store,
		FrozenPolicyEndpoints: m.frozenPolicyEndpointsSnapshot(),
	}, endpointID)
	if err != nil {
		return dataplane.PolicyEndpointStatus{}, err
	}
	m.upsertPolicyEndpointStatus(status)
	return status, nil
}

func (m *agentMetrics) rollbackPolicyEndpoint(ctx context.Context, endpoint string) (dataplane.PolicyEndpointStatus, error) {
	if m == nil || m.store == nil {
		return dataplane.PolicyEndpointStatus{}, errors.New("policy endpoint actions are not enabled")
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready || !snapshot.Success {
		return dataplane.PolicyEndpointStatus{}, errors.New("policy endpoint state is not ready")
	}
	endpointID, err := resolvePolicyEndpointIDFromSnapshot(endpoint, snapshot)
	if err != nil {
		return dataplane.PolicyEndpointStatus{}, err
	}
	status, err := agent.RollbackPolicyEndpoint(ctx, snapshot.State, agent.ReconcileOptions{
		Node:                  snapshot.Result.Node,
		Store:                 m.store,
		FrozenPolicyEndpoints: m.frozenPolicyEndpointsSnapshot(),
	}, endpointID)
	if err != nil {
		return dataplane.PolicyEndpointStatus{}, err
	}
	m.upsertPolicyEndpointStatus(status)
	return status, nil
}

func (m *agentMetrics) rolloutPolicyEndpoints(ctx context.Context, request policyEndpointRolloutRequest) (agent.PolicyEndpointRollout, error) {
	if m == nil || m.store == nil {
		return agent.PolicyEndpointRollout{}, errors.New("policy endpoint actions are not enabled")
	}
	start := time.Now()
	snapshot, _, ready := m.snapshotValue()
	if !ready || !snapshot.Success {
		return agent.PolicyEndpointRollout{}, errors.New("policy endpoint state is not ready")
	}
	endpoints := make([]string, 0, len(request.Endpoints))
	for _, endpoint := range request.Endpoints {
		endpointID, err := resolvePolicyEndpointIDFromSnapshot(endpoint, snapshot)
		if err != nil {
			return agent.PolicyEndpointRollout{}, err
		}
		endpoints = append(endpoints, endpointID)
	}
	approvalExpiresAt, err := parsePolicyRolloutRequestTime(request.ApprovalExpiresAt)
	if err != nil {
		return agent.PolicyEndpointRollout{}, fmt.Errorf("approval_expires_at: %w", err)
	}
	ackExpiresAt, err := parsePolicyRolloutRequestTime(request.AckExpiresAt)
	if err != nil {
		return agent.PolicyEndpointRollout{}, fmt.Errorf("ack_expires_at: %w", err)
	}
	finalizeExpiresAt, err := parsePolicyRolloutRequestTime(request.FinalizeExpiresAt)
	if err != nil {
		return agent.PolicyEndpointRollout{}, fmt.Errorf("finalize_expires_at: %w", err)
	}
	revision := strings.TrimSpace(request.Revision)
	if revision == "" {
		revision, err = agent.PolicyRolloutRevision(snapshot.State, control.PolicyRollout{
			Name:      "manual",
			Node:      snapshot.Result.Node,
			Endpoints: append([]string(nil), request.Endpoints...),
		}, endpoints)
		if err != nil {
			return agent.PolicyEndpointRollout{}, fmt.Errorf("revision: %w", err)
		}
	}
	rollout, err := agent.RolloutPolicyEndpoints(ctx, snapshot.State, agent.ReconcileOptions{
		Node:                        snapshot.Result.Node,
		Store:                       m.store,
		PolicyTelemetry:             m.storeTelemetry(),
		FrozenPolicyEndpoints:       m.frozenPolicyEndpointsSnapshot(),
		PolicyRolloutApprovalSecret: policyRolloutApprovalSecret(),
	}, agent.PolicyEndpointRolloutOptions{
		EndpointIDs:               endpoints,
		Revision:                  revision,
		BatchSize:                 request.BatchSize,
		DryRun:                    request.DryRun,
		PressureAware:             request.PressureAware,
		PressureThresholdPercent:  request.PressureThresholdPercent,
		PressureAwareMinBatchSize: request.PressureAwareMinBatchSize,
		SLOGated:                  request.SLOGated,
		SLODropThresholdPercent:   request.SLODropThresholdPercent,
		SLOMinPackets:             request.SLOMinPackets,
		SLOWindowCount:            request.SLOWindowCount,
		SLOWindowInterval:         time.Duration(request.SLOWindowIntervalMS) * time.Millisecond,
		Probes:                    append([]control.PolicyRolloutProbe(nil), request.Probes...),
		ApprovalRequired:          request.ApprovalRequired,
		Approved:                  request.Approved,
		ApprovalRef:               request.ApprovalRef,
		ApprovalSignature:         request.ApprovalSignature,
		ApprovalExpiresAt:         approvalExpiresAt,
		ApprovalCallbackURL:       request.ApprovalCallbackURL,
		ApprovalCallbackTimeout:   time.Duration(request.ApprovalCallbackTimeoutMS) * time.Millisecond,
		AckRequired:               request.AckRequired,
		Acknowledged:              request.Acknowledged,
		AckRef:                    request.AckRef,
		AckExpiresAt:              ackExpiresAt,
		FinalizeRequired:          request.FinalizeRequired,
		Finalized:                 request.Finalized,
		FinalizeRef:               request.FinalizeRef,
		FinalizeExpiresAt:         finalizeExpiresAt,
		ChangePollURL:             request.ChangePollURL,
		ChangePollTimeout:         time.Duration(request.ChangePollTimeoutMS) * time.Millisecond,
		ChangeStatusURL:           request.ChangeStatusURL,
		ChangeStatusTimeout:       time.Duration(request.ChangeStatusTimeoutMS) * time.Millisecond,
		Paused:                    request.Paused,
		PauseAfterBatches:         request.PauseAfterBatches,
		PromotionPercent:          request.PromotionPercent,
	})
	if err != nil {
		return agent.PolicyEndpointRollout{}, err
	}
	if !rollout.DryRun {
		for _, item := range rollout.Items {
			if item.Phase == "applied" {
				m.upsertPolicyEndpointStatus(item.Status)
			}
		}
	}
	if err := m.recordPolicyRolloutHistory(policyRolloutHistoryEntry{
		Source:     "manual",
		Node:       snapshot.Result.Node,
		Store:      snapshot.Store,
		DurationMS: time.Since(start).Milliseconds(),
		Rollout:    rollout,
	}); err != nil {
		return agent.PolicyEndpointRollout{}, err
	}
	return rollout, nil
}

func (m *agentMetrics) storeTelemetry() agent.PolicyRuleMetricsStore {
	if m == nil {
		return nil
	}
	telemetry, _ := m.store.(agent.PolicyRuleMetricsStore)
	return telemetry
}

func parsePolicyRolloutRequestTime(value string) (time.Time, error) {
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

func (m *agentMetrics) resolvePolicyEndpointID(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", errors.New("missing policy endpoint")
	}
	candidates := policyEndpointCandidates(endpoint)
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.ready {
		return "", errors.New("policy endpoint status is not ready")
	}
	for _, status := range m.snapshot.Result.PolicyEndpointStatus {
		if _, ok := candidates[status.EndpointID]; ok {
			return status.EndpointID, nil
		}
		if vpc, id, ok := strings.Cut(status.EndpointID, "\x00"); ok && (id == endpoint || vpc+"/"+id == endpoint) {
			return status.EndpointID, nil
		}
	}
	return "", fmt.Errorf("policy endpoint %q not found", endpoint)
}

func resolvePolicyEndpointIDFromSnapshot(endpoint string, snapshot agentMetricsSnapshot) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", errors.New("missing policy endpoint")
	}
	candidates := policyEndpointCandidates(endpoint)
	for _, status := range snapshot.Result.PolicyEndpointStatus {
		if _, ok := candidates[status.EndpointID]; ok {
			return status.EndpointID, nil
		}
		if vpc, id, ok := strings.Cut(status.EndpointID, "\x00"); ok && (id == endpoint || vpc+"/"+id == endpoint) {
			return status.EndpointID, nil
		}
	}
	for _, candidate := range snapshot.State.Endpoints {
		endpointID := model.EndpointKey(candidate.VPC, candidate.ID)
		if _, ok := candidates[endpointID]; ok {
			return endpointID, nil
		}
		if candidate.ID == endpoint || candidate.VPC+"/"+candidate.ID == endpoint {
			return endpointID, nil
		}
	}
	return "", fmt.Errorf("policy endpoint %q not found", endpoint)
}

func policyEndpointCandidates(endpoint string) map[string]struct{} {
	candidates := map[string]struct{}{endpoint: {}}
	if vpc, id, ok := strings.Cut(endpoint, "/"); ok && vpc != "" && id != "" {
		candidates[model.EndpointKey(vpc, id)] = struct{}{}
	}
	return candidates
}

func (m *agentMetrics) removePolicyEndpointStatus(endpointID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	statuses := m.snapshot.Result.PolicyEndpointStatus
	filtered := statuses[:0]
	for _, status := range statuses {
		if status.EndpointID == endpointID {
			continue
		}
		filtered = append(filtered, status)
	}
	m.snapshot.Result.PolicyEndpointStatus = append([]dataplane.PolicyEndpointStatus(nil), filtered...)
}

func (m *agentMetrics) upsertPolicyEndpointStatus(next dataplane.PolicyEndpointStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	statuses := append([]dataplane.PolicyEndpointStatus(nil), m.snapshot.Result.PolicyEndpointStatus...)
	for i := range statuses {
		if statuses[i].EndpointID == next.EndpointID {
			statuses[i] = next
			m.snapshot.Result.PolicyEndpointStatus = statuses
			if next.Revision > m.snapshot.Result.PolicyRevisionMax {
				m.snapshot.Result.PolicyRevisionMax = next.Revision
			}
			return
		}
	}
	statuses = append(statuses, next)
	m.snapshot.Result.PolicyEndpointStatus = statuses
	if next.Revision > m.snapshot.Result.PolicyRevisionMax {
		m.snapshot.Result.PolicyRevisionMax = next.Revision
	}
}

func cloneAgentMetricsTotals(totals agentMetricsTotals) agentMetricsTotals {
	totals.DurationBuckets = append([]uint64(nil), totals.DurationBuckets...)
	return totals
}

func startAgentMetricsServer(ctx context.Context, addr string, metrics *agentMetrics) (func(), error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return func() {}, nil
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen agent metrics endpoint %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", metrics.handleMetrics)
	mux.HandleFunc("/policy/explain", metrics.handlePolicyExplain)
	mux.HandleFunc("/policy/endpoints", metrics.handlePolicyEndpoints)
	mux.HandleFunc("/policy/endpoints/", metrics.handlePolicyEndpoints)
	mux.HandleFunc("/policy/events", metrics.handlePolicyEvents)
	mux.HandleFunc("/policy/events/", metrics.handlePolicyEvents)
	mux.HandleFunc("/policy/entries", metrics.handlePolicyEntries)
	mux.HandleFunc("/policy/entries/", metrics.handlePolicyEntries)
	mux.HandleFunc("/policy/rules", metrics.handlePolicyRules)
	mux.HandleFunc("/policy/rules/", metrics.handlePolicyRules)
	mux.HandleFunc("/route/explain", metrics.handleRouteExplain)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	server := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("netloom-agent metrics endpoint stopped: %v", err)
		}
	}()
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}, nil
}

func (m *agentMetrics) handlePolicyEndpoints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if isPolicyRolloutHistoryRequest(r) {
		m.handlePolicyRolloutHistory(w, r)
		return
	}
	if isPolicyActionHistoryRequest(r) {
		m.handlePolicyActionHistory(w, r)
		return
	}
	if isPolicyEndpointRevisionRequest(r) {
		m.handlePolicyEndpointRevision(w, r)
		return
	}
	if r.Method == http.MethodDelete {
		m.handlePolicyEndpointDelete(w, r)
		return
	}
	if r.Method == http.MethodPost {
		m.handlePolicyEndpointRegenerate(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	endpoint := policyEndpointFromRequest(r)
	snapshot, _, ready := m.snapshotValue()
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy endpoint status is not ready"})
		return
	}
	statuses := filterPolicyEndpointStatuses(snapshot.Result.PolicyEndpointStatus, endpoint, nil)
	if endpoint != "" && len(statuses) == 0 {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy endpoint not found"})
		return
	}
	output := policyStatusOutputFromResult(snapshot.Result, snapshot.Store, statuses)
	output.Ready = true
	output.LastReconcileSuccess = snapshot.Success
	output.LastReconcileError = snapshot.Error
	output.FrozenEndpoints = m.frozenPolicyEndpointIDs()
	output.FrozenEndpointExpiry = m.frozenPolicyEndpointExpirations()
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(output)
}

func isPolicyRolloutHistoryRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	return strings.Trim(r.URL.Path, "/") == "policy/endpoints/rollout/history"
}

func isPolicyActionHistoryRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	return strings.Trim(r.URL.Path, "/") == "policy/endpoints/actions/history"
}

func isPolicyEndpointRevisionRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	path := strings.Trim(r.URL.Path, "/")
	return strings.HasPrefix(path, "policy/endpoints/") && strings.HasSuffix(path, "/revision")
}

func (m *agentMetrics) handlePolicyRolloutHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(policyRolloutHistoryOutput{
		Ready:   true,
		History: m.policyRolloutHistory(),
	})
}

func (m *agentMetrics) handlePolicyEndpointRevision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	endpoint := policyEndpointRevisionFromRequest(r)
	if endpoint == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing policy endpoint"})
		return
	}
	targetRevision, err := policyEndpointTargetRevisionFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	timeout, err := policyEndpointRevisionTimeoutFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	interval, err := policyEndpointRevisionIntervalFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	start := time.Now()
	var lastStatus dataplane.PolicyEndpointStatus
	var sawEndpoint bool
	for {
		snapshot, _, ready := m.snapshotValue()
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy endpoint status is not ready"})
			return
		}
		statuses := filterPolicyEndpointStatuses(snapshot.Result.PolicyEndpointStatus, endpoint, nil)
		if len(statuses) > 0 {
			lastStatus = statuses[0]
			sawEndpoint = true
			if lastStatus.Revision >= targetRevision {
				output := policyRevisionWaitOutput{
					Ready:          true,
					Node:           snapshot.Result.Node,
					Store:          snapshot.Store,
					EndpointID:     lastStatus.EndpointID,
					TargetRevision: targetRevision,
					Revision:       lastStatus.Revision,
					WaitedMS:       time.Since(start).Milliseconds(),
					Status:         lastStatus,
				}
				encoder := json.NewEncoder(w)
				encoder.SetIndent("", "  ")
				_ = encoder.Encode(output)
				return
			}
		}
		if timeout == 0 || time.Since(start) >= timeout {
			if !sawEndpoint {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy endpoint not found"})
				return
			}
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("policy endpoint %s revision %d did not reach target revision %d before timeout", lastStatus.EndpointID, lastStatus.Revision, targetRevision)})
			return
		}
		wait := interval
		remaining := timeout - time.Since(start)
		if remaining < wait {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-r.Context().Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (m *agentMetrics) handlePolicyActionHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	limit, err := policyEventsLimitFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	endpoint := strings.TrimSpace(r.URL.Query().Get("endpoint"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	success, err := policyActionSuccessFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	history := m.policyActionHistory()
	filtered := filterPolicyActionHistory(history, endpoint, action, success)
	recent := recentPolicyActionHistory(filtered, limit)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(policyActionHistoryOutput{
		Ready:          true,
		TotalEvents:    len(history),
		EventCount:     len(recent),
		Limit:          limit,
		FilterEndpoint: endpoint,
		FilterAction:   action,
		FilterSuccess:  success,
		History:        recent,
	})
}

func (m *agentMetrics) handlePolicyRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	endpoint := policyRuleEndpointFromRequest(r)
	filter, err := policyRuleFilterFromRequest(r, endpoint)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy rule metrics are not ready"})
		return
	}
	output := policyRulesOutputFromResult(snapshot.Result, snapshot.Store, filter)
	output.Ready = true
	output.LastReconcileSuccess = snapshot.Success
	output.LastReconcileError = snapshot.Error
	if (filter.Endpoint != "" || filter.RuleCookie != nil || filter.RuleRef != "") && len(output.Rules) == 0 {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy rule metrics not found"})
		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(output)
}

func (m *agentMetrics) handlePolicyEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy events are not ready"})
		return
	}
	eventStore, ok := m.store.(agent.PolicyEventStore)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy events are not enabled"})
		return
	}
	limit, err := policyEventsLimitFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	endpoint := policyEventEndpointFromRequest(r)
	events := eventStore.Events()
	output := policyEventsOutputFromSnapshot(snapshot, events, endpoint, limit)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(output)
}

func (m *agentMetrics) handlePolicyEntries(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy entries are not ready"})
		return
	}
	entryStore, ok := m.store.(agent.PolicyEndpointEntryStore)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy entries are not enabled"})
		return
	}
	endpoint := policyEntryEndpointFromRequest(r)
	filter, err := policyEntryFilterFromRequest(r, endpoint)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	endpointID, err := resolvePolicyEndpointIDFromSnapshot(endpoint, snapshot)
	if err != nil {
		statusCode := http.StatusNotFound
		if strings.Contains(err.Error(), "missing") {
			statusCode = http.StatusBadRequest
		}
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	output := policyEntriesOutputFromSnapshot(snapshot, endpointID, entryStore.Entries(endpointID), filter)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(output)
}

func (m *agentMetrics) handlePolicyEndpointDelete(w http.ResponseWriter, r *http.Request) {
	endpoint := policyEndpointFromRequest(r)
	if endpoint == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing policy endpoint"})
		return
	}
	endpointID, err := m.deletePolicyEndpoint(r.Context(), endpoint)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not enabled"), strings.Contains(err.Error(), "not ready"):
			status = http.StatusServiceUnavailable
		case strings.Contains(err.Error(), "frozen"):
			status = http.StatusConflict
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		case strings.Contains(err.Error(), "missing"):
			status = http.StatusBadRequest
		}
		m.recordPolicyEndpointActionFailure(r.Context(), "delete", endpoint, err)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	m.recordPolicyEndpointAction(r.Context(), policyActionHistoryEntry{
		Action:     "delete",
		EndpointID: endpointID,
	})
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(policyEndpointActionOutput{
		EndpointID: endpointID,
		Action:     "delete",
		Deleted:    true,
	})
}

func (m *agentMetrics) handlePolicyEndpointRegenerate(w http.ResponseWriter, r *http.Request) {
	endpoint, action := policyEndpointActionFromRequest(r)
	if endpoint == "rollout" || action == "rollout" {
		m.handlePolicyEndpointRollout(w, r)
		return
	}
	if action == "quarantine" {
		m.handlePolicyEndpointQuarantine(w, r, endpoint)
		return
	}
	if action == "unquarantine" {
		m.handlePolicyEndpointUnquarantine(w, r, endpoint)
		return
	}
	if action == "rollback" {
		m.handlePolicyEndpointRollback(w, r, endpoint)
		return
	}
	if action == "freeze" {
		m.handlePolicyEndpointFreeze(w, r, endpoint)
		return
	}
	if action == "unfreeze" {
		m.handlePolicyEndpointUnfreeze(w, r, endpoint)
		return
	}
	if action == "plan" || action == "dry-run" || action == "preview" {
		m.handlePolicyEndpointPlan(w, r, endpoint)
		return
	}
	if action != "" && action != "regenerate" && action != "reconcile" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unsupported policy endpoint action"})
		return
	}
	if endpoint == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing policy endpoint"})
		return
	}
	status, err := m.regeneratePolicyEndpoint(r.Context(), endpoint)
	if err != nil {
		statusCode := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not enabled"), strings.Contains(err.Error(), "not ready"):
			statusCode = http.StatusServiceUnavailable
		case strings.Contains(err.Error(), "frozen"):
			statusCode = http.StatusConflict
		case strings.Contains(err.Error(), "not found"):
			statusCode = http.StatusNotFound
		case strings.Contains(err.Error(), "missing"), strings.Contains(err.Error(), "required"), strings.Contains(err.Error(), "assigned to node"):
			statusCode = http.StatusBadRequest
		}
		m.recordPolicyEndpointActionFailure(r.Context(), "regenerate", endpoint, err)
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	m.recordPolicyEndpointAction(r.Context(), policyActionHistoryEntry{
		Action:     "regenerate",
		EndpointID: status.EndpointID,
		Revision:   status.Revision,
		Entries:    status.Entries,
	})
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(policyEndpointActionOutput{
		EndpointID:   status.EndpointID,
		Action:       "regenerate",
		Regenerated:  true,
		EndpointInfo: status,
	})
}

func (m *agentMetrics) handlePolicyEndpointRollout(w http.ResponseWriter, r *http.Request) {
	var request policyEndpointRolloutRequest
	if r.Body != nil && r.Body != http.NoBody {
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid rollout request"})
			return
		}
	}
	rollout, err := m.rolloutPolicyEndpoints(r.Context(), request)
	if err != nil {
		statusCode := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not enabled"), strings.Contains(err.Error(), "not ready"):
			statusCode = http.StatusServiceUnavailable
		case strings.Contains(err.Error(), "frozen"):
			statusCode = http.StatusConflict
		case strings.Contains(err.Error(), "not found"):
			statusCode = http.StatusNotFound
		case strings.Contains(err.Error(), "missing"), strings.Contains(err.Error(), "required"), strings.Contains(err.Error(), "assigned to node"):
			statusCode = http.StatusBadRequest
		}
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(policyEndpointActionOutput{
		Action:    "rollout",
		RolledOut: !rollout.DryRun && rollout.Failed == 0 && !rollout.ApprovalPending && !rollout.AckPending,
		Rollout:   rollout,
	})
}

func (m *agentMetrics) handlePolicyEndpointPlan(w http.ResponseWriter, r *http.Request, endpoint string) {
	if endpoint == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing policy endpoint"})
		return
	}
	plan, err := m.planPolicyEndpoint(r.Context(), endpoint)
	if err != nil {
		m.recordPolicyEndpointActionFailure(r.Context(), "plan", endpoint, err)
		statusCode := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not enabled"), strings.Contains(err.Error(), "not ready"):
			statusCode = http.StatusServiceUnavailable
		case strings.Contains(err.Error(), "frozen"):
			statusCode = http.StatusConflict
		case strings.Contains(err.Error(), "not found"):
			statusCode = http.StatusNotFound
		case strings.Contains(err.Error(), "missing"), strings.Contains(err.Error(), "required"), strings.Contains(err.Error(), "assigned to node"):
			statusCode = http.StatusBadRequest
		}
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	m.recordPolicyEndpointAction(r.Context(), policyActionHistoryEntry{
		Action:     "plan",
		EndpointID: plan.EndpointID,
		Revision:   plan.Stats.Revision,
		Entries:    uint32(plan.DesiredEntries),
	})
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(policyEndpointActionOutput{
		EndpointID: plan.EndpointID,
		Action:     "plan",
		Planned:    true,
		Plan:       plan,
	})
}

func (m *agentMetrics) recordPolicyEndpointAction(ctx context.Context, entry policyActionHistoryEntry) {
	if m == nil {
		return
	}
	snapshot, _, ready := m.snapshotValue()
	if ready {
		if entry.Node == "" {
			entry.Node = snapshot.Result.Node
		}
		if entry.Store == "" {
			entry.Store = snapshot.Store
		}
	}
	if err := m.recordPolicyActionHistory(ctx, entry); err != nil {
		log.Printf("record policy endpoint action history: %v", err)
	}
}

func (m *agentMetrics) recordPolicyEndpointActionFailure(ctx context.Context, action, endpoint string, actionErr error) {
	if actionErr == nil {
		return
	}
	endpointID := strings.TrimSpace(endpoint)
	if m != nil {
		if resolved, err := m.resolvePolicyEndpointID(endpoint); err == nil {
			endpointID = resolved
		}
	}
	m.recordPolicyEndpointAction(ctx, policyActionHistoryEntry{
		Action:     action,
		EndpointID: endpointID,
		Success:    false,
		Error:      actionErr.Error(),
	})
}

func decodePolicyEndpointFreezeRequest(r *http.Request) (policyEndpointFreezeRequest, error) {
	var request policyEndpointFreezeRequest
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return request, nil
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		return request, errors.New("invalid freeze request")
	}
	return request, nil
}

func policyFreezeExpiresAt(request policyEndpointFreezeRequest, now time.Time) (time.Time, error) {
	hasTTL := request.TTLSeconds != 0
	hasExpiresAt := strings.TrimSpace(request.ExpiresAt) != ""
	if hasTTL && hasExpiresAt {
		return time.Time{}, errors.New("freeze request must use ttl_seconds or expires_at, not both")
	}
	if hasTTL {
		if request.TTLSeconds < 0 {
			return time.Time{}, errors.New("freeze ttl_seconds must be positive")
		}
		expiresAt := now.Add(time.Duration(request.TTLSeconds) * time.Second).UTC()
		if !now.Before(expiresAt) {
			return time.Time{}, errors.New("freeze ttl_seconds must be positive")
		}
		return expiresAt, nil
	}
	if hasExpiresAt {
		expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(request.ExpiresAt))
		if err != nil {
			return time.Time{}, errors.New("freeze expires_at must use RFC3339")
		}
		expiresAt = expiresAt.UTC()
		if !now.Before(expiresAt) {
			return time.Time{}, errors.New("freeze expires_at must be in the future")
		}
		return expiresAt, nil
	}
	return time.Time{}, nil
}

func (m *agentMetrics) handlePolicyEndpointFreeze(w http.ResponseWriter, r *http.Request, endpoint string) {
	if endpoint == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing policy endpoint"})
		return
	}
	request, err := decodePolicyEndpointFreezeRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	expiresAt, err := policyFreezeExpiresAt(request, time.Now())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	endpointID, expiresAt, err := m.freezePolicyEndpoint(r.Context(), endpoint, expiresAt)
	if err != nil {
		statusCode := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not enabled"), strings.Contains(err.Error(), "not ready"):
			statusCode = http.StatusServiceUnavailable
		case strings.Contains(err.Error(), "not found"):
			statusCode = http.StatusNotFound
		case strings.Contains(err.Error(), "missing"), strings.Contains(err.Error(), "required"):
			statusCode = http.StatusBadRequest
		}
		m.recordPolicyEndpointActionFailure(r.Context(), "freeze", endpoint, err)
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	m.recordPolicyEndpointAction(r.Context(), policyActionHistoryEntry{
		Action:     "freeze",
		EndpointID: endpointID,
		ExpiresAt:  expiresAt,
	})
	w.WriteHeader(http.StatusOK)
	response := policyEndpointActionOutput{
		EndpointID: endpointID,
		Action:     "freeze",
		Frozen:     true,
	}
	if !expiresAt.IsZero() {
		response.ExpiresAt = &expiresAt
	}
	_ = json.NewEncoder(w).Encode(response)
}

func (m *agentMetrics) handlePolicyEndpointUnfreeze(w http.ResponseWriter, r *http.Request, endpoint string) {
	if endpoint == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing policy endpoint"})
		return
	}
	endpointID, err := m.unfreezePolicyEndpoint(r.Context(), endpoint)
	if err != nil {
		statusCode := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not enabled"), strings.Contains(err.Error(), "not ready"):
			statusCode = http.StatusServiceUnavailable
		case strings.Contains(err.Error(), "not found"):
			statusCode = http.StatusNotFound
		case strings.Contains(err.Error(), "missing"), strings.Contains(err.Error(), "required"):
			statusCode = http.StatusBadRequest
		}
		m.recordPolicyEndpointActionFailure(r.Context(), "unfreeze", endpoint, err)
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	m.recordPolicyEndpointAction(r.Context(), policyActionHistoryEntry{
		Action:     "unfreeze",
		EndpointID: endpointID,
	})
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(policyEndpointActionOutput{
		EndpointID: endpointID,
		Action:     "unfreeze",
		Unfrozen:   true,
	})
}

func (m *agentMetrics) handlePolicyEndpointQuarantine(w http.ResponseWriter, r *http.Request, endpoint string) {
	if endpoint == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing policy endpoint"})
		return
	}
	status, err := m.quarantinePolicyEndpoint(r.Context(), endpoint)
	if err != nil {
		statusCode := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not enabled"), strings.Contains(err.Error(), "not ready"):
			statusCode = http.StatusServiceUnavailable
		case strings.Contains(err.Error(), "frozen"):
			statusCode = http.StatusConflict
		case strings.Contains(err.Error(), "not found"):
			statusCode = http.StatusNotFound
		case strings.Contains(err.Error(), "missing"), strings.Contains(err.Error(), "required"), strings.Contains(err.Error(), "assigned to node"):
			statusCode = http.StatusBadRequest
		}
		m.recordPolicyEndpointActionFailure(r.Context(), "quarantine", endpoint, err)
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	m.recordPolicyEndpointAction(r.Context(), policyActionHistoryEntry{
		Action:     "quarantine",
		EndpointID: status.EndpointID,
		Revision:   status.Revision,
		Entries:    status.Entries,
	})
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(policyEndpointActionOutput{
		EndpointID:   status.EndpointID,
		Action:       "quarantine",
		Quarantined:  true,
		EndpointInfo: status,
	})
}

func (m *agentMetrics) handlePolicyEndpointUnquarantine(w http.ResponseWriter, r *http.Request, endpoint string) {
	if endpoint == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing policy endpoint"})
		return
	}
	status, err := m.unquarantinePolicyEndpoint(r.Context(), endpoint)
	if err != nil {
		statusCode := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not enabled"), strings.Contains(err.Error(), "not ready"):
			statusCode = http.StatusServiceUnavailable
		case strings.Contains(err.Error(), "not found"):
			statusCode = http.StatusNotFound
		case strings.Contains(err.Error(), "missing"), strings.Contains(err.Error(), "required"), strings.Contains(err.Error(), "assigned to node"):
			statusCode = http.StatusBadRequest
		}
		m.recordPolicyEndpointActionFailure(r.Context(), "unquarantine", endpoint, err)
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	m.recordPolicyEndpointAction(r.Context(), policyActionHistoryEntry{
		Action:     "unquarantine",
		EndpointID: status.EndpointID,
		Revision:   status.Revision,
		Entries:    status.Entries,
	})
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(policyEndpointActionOutput{
		EndpointID:    status.EndpointID,
		Action:        "unquarantine",
		Unquarantined: true,
		EndpointInfo:  status,
	})
}

func (m *agentMetrics) handlePolicyEndpointRollback(w http.ResponseWriter, r *http.Request, endpoint string) {
	if endpoint == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing policy endpoint"})
		return
	}
	status, err := m.rollbackPolicyEndpoint(r.Context(), endpoint)
	if err != nil {
		statusCode := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not enabled"), strings.Contains(err.Error(), "not ready"):
			statusCode = http.StatusServiceUnavailable
		case strings.Contains(err.Error(), "not found"):
			statusCode = http.StatusNotFound
		case strings.Contains(err.Error(), "missing"), strings.Contains(err.Error(), "required"), strings.Contains(err.Error(), "assigned to node"):
			statusCode = http.StatusBadRequest
		}
		m.recordPolicyEndpointActionFailure(r.Context(), "rollback", endpoint, err)
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	m.recordPolicyEndpointAction(r.Context(), policyActionHistoryEntry{
		Action:     "rollback",
		EndpointID: status.EndpointID,
		Revision:   status.Revision,
		Entries:    status.Entries,
	})
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(policyEndpointActionOutput{
		EndpointID:   status.EndpointID,
		Action:       "rollback",
		RolledBack:   true,
		EndpointInfo: status,
	})
}

func policyEndpointFromRequest(r *http.Request) string {
	endpoint := strings.TrimSpace(r.URL.Query().Get("endpoint"))
	if strings.HasPrefix(r.URL.Path, "/policy/endpoints/") {
		pathEndpoint := strings.TrimPrefix(r.URL.Path, "/policy/endpoints/")
		if decoded, err := url.PathUnescape(pathEndpoint); err == nil {
			pathEndpoint = decoded
		}
		if strings.TrimSpace(pathEndpoint) != "" {
			endpoint = strings.TrimSpace(pathEndpoint)
		}
	}
	return endpoint
}

func policyEndpointRevisionFromRequest(r *http.Request) string {
	endpoint := strings.TrimSpace(r.URL.Query().Get("endpoint"))
	if strings.HasPrefix(r.URL.Path, "/policy/endpoints/") {
		pathEndpoint := strings.TrimPrefix(r.URL.Path, "/policy/endpoints/")
		pathEndpoint = strings.TrimSuffix(pathEndpoint, "/revision")
		if decoded, err := url.PathUnescape(pathEndpoint); err == nil {
			pathEndpoint = decoded
		}
		if strings.TrimSpace(pathEndpoint) != "" {
			endpoint = strings.TrimSpace(pathEndpoint)
		}
	}
	return endpoint
}

func policyEndpointTargetRevisionFromRequest(r *http.Request) (uint64, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("target_revision"))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("revision"))
	}
	if raw == "" {
		return 0, errors.New("missing target_revision")
	}
	revision, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || revision == 0 {
		return 0, fmt.Errorf("invalid target_revision %q", raw)
	}
	return revision, nil
}

func policyEndpointRevisionTimeoutFromRequest(r *http.Request) (time.Duration, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("timeout_ms"))
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("invalid timeout_ms %q", raw)
	}
	return time.Duration(value) * time.Millisecond, nil
}

func policyEndpointRevisionIntervalFromRequest(r *http.Request) (time.Duration, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("interval_ms"))
	if raw == "" {
		return 200 * time.Millisecond, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid interval_ms %q", raw)
	}
	return time.Duration(value) * time.Millisecond, nil
}

func policyRuleEndpointFromRequest(r *http.Request) string {
	endpoint := strings.TrimSpace(r.URL.Query().Get("endpoint"))
	if strings.HasPrefix(r.URL.Path, "/policy/rules/") {
		pathEndpoint := strings.TrimPrefix(r.URL.Path, "/policy/rules/")
		if decoded, err := url.PathUnescape(pathEndpoint); err == nil {
			pathEndpoint = decoded
		}
		if strings.TrimSpace(pathEndpoint) != "" {
			endpoint = strings.TrimSpace(pathEndpoint)
		}
	}
	return endpoint
}

func policyEventEndpointFromRequest(r *http.Request) string {
	endpoint := strings.TrimSpace(r.URL.Query().Get("endpoint"))
	if strings.HasPrefix(r.URL.Path, "/policy/events/") {
		pathEndpoint := strings.TrimPrefix(r.URL.Path, "/policy/events/")
		if decoded, err := url.PathUnescape(pathEndpoint); err == nil {
			pathEndpoint = decoded
		}
		if strings.TrimSpace(pathEndpoint) != "" {
			endpoint = strings.TrimSpace(pathEndpoint)
		}
	}
	return endpoint
}

func policyEntryEndpointFromRequest(r *http.Request) string {
	endpoint := strings.TrimSpace(r.URL.Query().Get("endpoint"))
	if strings.HasPrefix(r.URL.Path, "/policy/entries/") {
		pathEndpoint := strings.TrimPrefix(r.URL.Path, "/policy/entries/")
		if decoded, err := url.PathUnescape(pathEndpoint); err == nil {
			pathEndpoint = decoded
		}
		if strings.TrimSpace(pathEndpoint) != "" {
			endpoint = strings.TrimSpace(pathEndpoint)
		}
	}
	return endpoint
}

func policyEventsLimitFromRequest(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return defaultPolicyEventsLimit, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 0 {
		return 0, fmt.Errorf("invalid limit %q", raw)
	}
	if limit > maxPolicyEventsLimit {
		return maxPolicyEventsLimit, nil
	}
	return limit, nil
}

func policyActionSuccessFromRequest(r *http.Request) (*bool, error) {
	return policyActionSuccessFromString(r.URL.Query().Get("success"))
}

func policyActionSuccessFromString(raw string) (*bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid success %q", raw)
	}
	return &value, nil
}

func policyEndpointActionFromRequest(r *http.Request) (string, string) {
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	endpoint := strings.TrimSpace(r.URL.Query().Get("endpoint"))
	if strings.HasPrefix(r.URL.Path, "/policy/endpoints/") {
		pathEndpoint := strings.TrimPrefix(r.URL.Path, "/policy/endpoints/")
		if decoded, err := url.PathUnescape(pathEndpoint); err == nil {
			pathEndpoint = decoded
		}
		pathEndpoint = strings.TrimSpace(pathEndpoint)
		for _, suffix := range []string{"/regenerate", "/reconcile", "/quarantine", "/unquarantine", "/rollback", "/freeze", "/unfreeze", "/plan", "/dry-run", "/preview", "/rollout"} {
			if strings.HasSuffix(pathEndpoint, suffix) {
				if action == "" {
					action = strings.TrimPrefix(suffix, "/")
				}
				pathEndpoint = strings.TrimSuffix(pathEndpoint, suffix)
				break
			}
		}
		if pathEndpoint != "" {
			endpoint = strings.TrimSpace(pathEndpoint)
		}
	}
	return endpoint, action
}

func (m *agentMetrics) handlePolicyExplain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready || !snapshot.Success {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy explain state is not ready"})
		return
	}
	opts, err := policyExplainOptionsFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	explanation, err := explainPolicyFromState(snapshot.State, opts)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(explanation)
}

func policyExplainOptionsFromRequest(r *http.Request) (policyExplainOptions, error) {
	query := r.URL.Query()
	remoteIdentity, err := parseOptionalUintQuery(query.Get("remote-identity"), query.Get("remote_identity"))
	if err != nil {
		return policyExplainOptions{}, fmt.Errorf("invalid remote identity: %w", err)
	}
	sourcePort, err := parseOptionalUintQuery(query.Get("source-port"), query.Get("source_port"))
	if err != nil {
		return policyExplainOptions{}, fmt.Errorf("invalid source port: %w", err)
	}
	destPort, err := parseOptionalUintQuery(query.Get("dest-port"), query.Get("dest_port"))
	if err != nil {
		return policyExplainOptions{}, fmt.Errorf("invalid destination port: %w", err)
	}
	icmpType, err := parseOptionalIntQuery(query.Get("icmp-type"), query.Get("icmp_type"))
	if err != nil {
		return policyExplainOptions{}, fmt.Errorf("invalid icmp type: %w", err)
	}
	icmpCode, err := parseOptionalIntQuery(query.Get("icmp-code"), query.Get("icmp_code"))
	if err != nil {
		return policyExplainOptions{}, fmt.Errorf("invalid icmp code: %w", err)
	}
	stateful, err := parseOptionalBoolQuery(query.Get("stateful"))
	if err != nil {
		return policyExplainOptions{}, fmt.Errorf("invalid stateful value: %w", err)
	}
	return policyExplainOptions{
		vpc:            query.Get("vpc"),
		endpoint:       query.Get("endpoint"),
		remoteEndpoint: firstNonEmptyQuery(query.Get("remote-endpoint"), query.Get("remote_endpoint")),
		remoteVPC:      firstNonEmptyQuery(query.Get("remote-vpc"), query.Get("remote_vpc")),
		remoteIdentity: remoteIdentity,
		remoteIP:       firstNonEmptyQuery(query.Get("remote-ip"), query.Get("remote_ip")),
		direction:      query.Get("direction"),
		protocol:       query.Get("protocol"),
		sourcePort:     sourcePort,
		destPort:       destPort,
		icmpType:       icmpType,
		icmpCode:       icmpCode,
		stateful:       stateful,
	}, nil
}

func (m *agentMetrics) handleRouteExplain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready || !snapshot.Success {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "route explain state is not ready"})
		return
	}
	opts, err := routeExplainOptionsFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	decision, err := explainRouteFromState(snapshot.State, opts)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(decision)
}

func routeExplainOptionsFromRequest(r *http.Request) (routeExplainOptions, error) {
	query := r.URL.Query()
	sourcePort, err := parseOptionalUintQuery(query.Get("source-port"), query.Get("source_port"))
	if err != nil {
		return routeExplainOptions{}, fmt.Errorf("invalid source port: %w", err)
	}
	destPort, err := parseOptionalUintQuery(query.Get("dest-port"), query.Get("dest_port"))
	if err != nil {
		return routeExplainOptions{}, fmt.Errorf("invalid destination port: %w", err)
	}
	return routeExplainOptions{
		vpc:        query.Get("vpc"),
		source:     query.Get("source"),
		dest:       query.Get("dest"),
		protocol:   query.Get("protocol"),
		sourcePort: sourcePort,
		destPort:   destPort,
	}, nil
}

func parseOptionalUintQuery(values ...string) (uint, error) {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseUint(value, 10, 0)
		if err != nil {
			return 0, err
		}
		return uint(parsed), nil
	}
	return 0, nil
}

func parseOptionalIntQuery(values ...string) (int, error) {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, err
		}
		return parsed, nil
	}
	return 0, nil
}

func parseOptionalBoolQuery(value string) (bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, nil
	}
	return strconv.ParseBool(value)
}

func firstNonEmptyQuery(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (m *agentMetrics) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	snapshot, totals, ready := m.snapshotValue()
	if !ready {
		writeMetricHelp(w, "netloom_agent_reconcile_ready", "Whether the agent has completed at least one reconcile attempt.")
		writeMetricType(w, "netloom_agent_reconcile_ready", "gauge")
		fmt.Fprintln(w, "netloom_agent_reconcile_ready 0")
		return
	}
	writeAgentMetrics(w, snapshot, totals)
}

func writeAgentMetrics(w ioStringWriter, snapshot agentMetricsSnapshot, totals agentMetricsTotals) {
	result := snapshot.Result
	baseLabels := prometheusLabels(map[string]string{
		"node":  result.Node,
		"store": snapshot.Store,
	})
	success := 0
	if snapshot.Success {
		success = 1
	}
	writeMetricHelp(w, "netloom_agent_reconcile_ready", "Whether the agent has completed at least one reconcile attempt.")
	writeMetricType(w, "netloom_agent_reconcile_ready", "gauge")
	fmt.Fprintln(w, "netloom_agent_reconcile_ready 1")
	writeMetricHelp(w, "netloom_agent_reconcile_success", "Whether the last agent reconcile attempt succeeded.")
	writeMetricType(w, "netloom_agent_reconcile_success", "gauge")
	fmt.Fprintf(w, "netloom_agent_reconcile_success%s %d\n", baseLabels, success)
	writeMetricHelp(w, "netloom_agent_reconcile_duration_milliseconds", "Duration of the last agent reconcile attempt in milliseconds.")
	writeMetricType(w, "netloom_agent_reconcile_duration_milliseconds", "gauge")
	fmt.Fprintf(w, "netloom_agent_reconcile_duration_milliseconds%s %d\n", baseLabels, snapshot.Duration.Milliseconds())
	writeAgentCounter(w, "netloom_agent_reconcile_attempts_total", baseLabels, totals.Attempts)
	writeAgentCounter(w, "netloom_agent_reconcile_success_total", baseLabels, totals.Successes)
	writeAgentCounter(w, "netloom_agent_reconcile_failure_total", baseLabels, totals.Failures)
	writeAgentDurationHistogram(w, result.Node, snapshot.Store, baseLabels, totals)
	if !snapshot.Success && snapshot.Error != "" {
		fmt.Fprintf(w, "netloom_agent_reconcile_last_error%s 1\n", prometheusLabels(map[string]string{
			"node":  result.Node,
			"store": snapshot.Store,
			"error": snapshot.Error,
		}))
	}
	runtimeReady := 1
	if !agent.RuntimeChecksReady(snapshot.Runtime) {
		runtimeReady = 0
	}
	runtimeFailed, runtimeWarned := countRuntimeCheckStatuses(snapshot.Runtime)
	writeMetricType(w, "netloom_agent_runtime_ready", "gauge")
	fmt.Fprintf(w, "netloom_agent_runtime_ready%s %d\n", baseLabels, runtimeReady)
	writeMetricType(w, "netloom_agent_runtime_failed_checks", "gauge")
	fmt.Fprintf(w, "netloom_agent_runtime_failed_checks%s %d\n", baseLabels, runtimeFailed)
	writeMetricType(w, "netloom_agent_runtime_warned_checks", "gauge")
	fmt.Fprintf(w, "netloom_agent_runtime_warned_checks%s %d\n", baseLabels, runtimeWarned)
	writeMetricType(w, "netloom_agent_runtime_check_status", "gauge")
	for _, check := range snapshot.Runtime {
		value := 0
		if check.Status == "ok" || check.Status == "skip" {
			value = 1
		}
		required := "false"
		if check.Required {
			required = "true"
		}
		fmt.Fprintf(w, "netloom_agent_runtime_check_status%s %d\n", prometheusLabels(map[string]string{
			"node":     result.Node,
			"store":    snapshot.Store,
			"check":    check.Name,
			"status":   check.Status,
			"required": required,
		}), value)
	}

	writeMetricType(w, "netloom_agent_policy_map_entries", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_entries%s %d\n", baseLabels, result.PolicyMapEntries)
	writeMetricType(w, "netloom_agent_policy_map_capacity", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_capacity%s %d\n", baseLabels, result.PolicyMapCapacity)
	writeMetricType(w, "netloom_agent_policy_map_pressure_percent", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_pressure_percent%s %d\n", prometheusLabels(map[string]string{
		"node":     result.Node,
		"store":    snapshot.Store,
		"endpoint": result.PolicyMapPressureEndpoint,
	}), result.PolicyMapPressureMax)
	writeMetricType(w, "netloom_agent_policy_map_pressure_hotspot_percent", "gauge")
	writeMetricType(w, "netloom_agent_policy_map_pressure_hotspot_entries", "gauge")
	writeMetricType(w, "netloom_agent_policy_map_pressure_hotspot_capacity", "gauge")
	for i, hotspot := range result.PolicyMapPressureHotspots {
		labels := prometheusLabels(map[string]string{
			"node":     result.Node,
			"store":    snapshot.Store,
			"endpoint": hotspot.EndpointID,
			"rank":     strconv.Itoa(i + 1),
		})
		fmt.Fprintf(w, "netloom_agent_policy_map_pressure_hotspot_percent%s %d\n", labels, hotspot.PressurePercent)
		fmt.Fprintf(w, "netloom_agent_policy_map_pressure_hotspot_entries%s %d\n", labels, hotspot.Entries)
		fmt.Fprintf(w, "netloom_agent_policy_map_pressure_hotspot_capacity%s %d\n", labels, hotspot.Capacity)
	}
	writeMetricType(w, "netloom_agent_policy_map_pressure_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_pressure_endpoints%s %d\n", baseLabels, result.PolicyMapPressureEndpoints)
	writeMetricType(w, "netloom_agent_policy_map_drift_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_drift_endpoints%s %d\n", baseLabels, result.PolicyMapDriftEndpoints)
	writeMetricType(w, "netloom_agent_policy_map_drift_missing_entries", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_drift_missing_entries%s %d\n", baseLabels, result.PolicyMapDriftMissing)
	writeMetricType(w, "netloom_agent_policy_map_drift_extra_entries", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_drift_extra_entries%s %d\n", baseLabels, result.PolicyMapDriftExtra)
	writeMetricType(w, "netloom_agent_policy_map_drift_changed_entries", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_drift_changed_entries%s %d\n", baseLabels, result.PolicyMapDriftChanged)
	writeMetricType(w, "netloom_agent_policy_gc_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_gc_endpoints%s %d\n", baseLabels, result.PolicyGCEndpoints)
	writeMetricType(w, "netloom_agent_policy_pressure_mitigated_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_pressure_mitigated_endpoints%s %d\n", baseLabels, result.PolicyPressureMitigated)
	writeMetricType(w, "netloom_agent_policy_pressure_quarantined_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_pressure_quarantined_endpoints%s %d\n", baseLabels, result.PolicyPressureQuarantined)
	writeMetricType(w, "netloom_agent_policy_pressure_quarantine_endpoint", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_pressure_quarantine_endpoint%s %d\n", prometheusLabels(map[string]string{
		"node":     result.Node,
		"store":    snapshot.Store,
		"endpoint": result.PolicyPressureQuarantineEndpoint,
	}), result.PolicyPressureQuarantined)
	writeMetricType(w, "netloom_agent_policy_rollouts", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_rollouts%s %d\n", baseLabels, result.PolicyRollouts)
	writeMetricType(w, "netloom_agent_policy_rollout_planned_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_rollout_planned_endpoints%s %d\n", baseLabels, result.PolicyRolloutPlanned)
	writeMetricType(w, "netloom_agent_policy_rollout_applied_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_rollout_applied_endpoints%s %d\n", baseLabels, result.PolicyRolloutApplied)
	writeMetricType(w, "netloom_agent_policy_rollout_skipped_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_rollout_skipped_endpoints%s %d\n", baseLabels, result.PolicyRolloutSkipped)
	writeMetricType(w, "netloom_agent_policy_rollout_failed_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_rollout_failed_endpoints%s %d\n", baseLabels, result.PolicyRolloutFailed)
	writeMetricType(w, "netloom_agent_policy_rollout_rolled_back_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_rollout_rolled_back_endpoints%s %d\n", baseLabels, result.PolicyRolloutRolledBack)
	writeMetricType(w, "netloom_agent_policy_rollout_rollback_failed_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_rollout_rollback_failed_endpoints%s %d\n", baseLabels, result.PolicyRolloutRollbackFailed)
	writeMetricType(w, "netloom_agent_policy_rollout_slo_failed", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_rollout_slo_failed%s %d\n", baseLabels, result.PolicyRolloutSLOFailed)
	writeMetricType(w, "netloom_agent_policy_rollout_probe_failed", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_rollout_probe_failed%s %d\n", baseLabels, result.PolicyRolloutProbeFailed)
	writeMetricType(w, "netloom_agent_policy_rollout_paused", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_rollout_paused%s %d\n", baseLabels, result.PolicyRolloutPaused)
	writeMetricType(w, "netloom_agent_policy_rollout_cancelled", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_rollout_cancelled%s %d\n", baseLabels, result.PolicyRolloutCancelled)
	writeMetricType(w, "netloom_agent_provider_tenant_subnets", "gauge")
	writeMetricType(w, "netloom_agent_provider_tenant_endpoints", "gauge")
	writeMetricType(w, "netloom_agent_provider_tenant_max_subnets", "gauge")
	writeMetricType(w, "netloom_agent_provider_tenant_max_endpoints", "gauge")
	writeMetricType(w, "netloom_agent_provider_tenant_quota_exceeded", "gauge")
	for _, status := range result.ProviderNetworkStatus {
		for _, usage := range status.TenantUsage {
			labels := prometheusLabels(map[string]string{
				"node":             result.Node,
				"store":            snapshot.Store,
				"provider_network": status.ProviderNetwork,
				"tenant":           usage.Tenant,
			})
			exceeded := 0
			if usage.Exceeded {
				exceeded = 1
			}
			fmt.Fprintf(w, "netloom_agent_provider_tenant_subnets%s %d\n", labels, usage.Subnets)
			fmt.Fprintf(w, "netloom_agent_provider_tenant_endpoints%s %d\n", labels, usage.Endpoints)
			fmt.Fprintf(w, "netloom_agent_provider_tenant_max_subnets%s %d\n", labels, usage.MaxSubnets)
			fmt.Fprintf(w, "netloom_agent_provider_tenant_max_endpoints%s %d\n", labels, usage.MaxEndpoints)
			fmt.Fprintf(w, "netloom_agent_provider_tenant_quota_exceeded%s %d\n", labels, exceeded)
		}
	}
	writeAgentCounter(w, "netloom_agent_policy_added_total", baseLabels, totals.PolicyAdded)
	writeAgentCounter(w, "netloom_agent_policy_updated_total", baseLabels, totals.PolicyUpdated)
	writeAgentCounter(w, "netloom_agent_policy_deleted_total", baseLabels, totals.PolicyDeleted)
	writeAgentCounter(w, "netloom_agent_policy_unchanged_total", baseLabels, totals.PolicyUnchanged)
	writeAgentCounter(w, "netloom_agent_policy_events_total", baseLabels, totals.PolicyEvents)
	writeAgentCounter(w, "netloom_agent_policy_failed_total", baseLabels, totals.PolicyFailed)
	writeAgentCounter(w, "netloom_agent_policy_rollbacks_total", baseLabels, totals.PolicyRollbacks)
	writeAgentCounter(w, "netloom_agent_policy_gc_endpoints_total", baseLabels, totals.PolicyGCEndpoints)
	writeAgentCounter(w, "netloom_agent_policy_pressure_mitigated_endpoints_total", baseLabels, totals.PolicyPressureMitigated)
	writeAgentCounter(w, "netloom_agent_policy_pressure_quarantined_endpoints_total", baseLabels, totals.PolicyPressureQuarantined)
	writeAgentCounter(w, "netloom_agent_policy_rollout_planned_endpoints_total", baseLabels, totals.PolicyRolloutPlanned)
	writeAgentCounter(w, "netloom_agent_policy_rollout_applied_endpoints_total", baseLabels, totals.PolicyRolloutApplied)
	writeAgentCounter(w, "netloom_agent_policy_rollout_skipped_endpoints_total", baseLabels, totals.PolicyRolloutSkipped)
	writeAgentCounter(w, "netloom_agent_policy_rollout_failed_endpoints_total", baseLabels, totals.PolicyRolloutFailed)
	writeAgentCounter(w, "netloom_agent_policy_rollout_rolled_back_endpoints_total", baseLabels, totals.PolicyRolloutRolledBack)
	writeAgentCounter(w, "netloom_agent_policy_rollout_rollback_failed_endpoints_total", baseLabels, totals.PolicyRolloutRollbackFail)
	writeAgentCounter(w, "netloom_agent_policy_rollout_slo_failed_total", baseLabels, totals.PolicyRolloutSLOFailed)
	writeAgentCounter(w, "netloom_agent_policy_rollout_probe_failed_total", baseLabels, totals.PolicyRolloutProbeFailed)
	writeAgentCounter(w, "netloom_agent_policy_rollout_paused_total", baseLabels, totals.PolicyRolloutPaused)
	writeAgentCounter(w, "netloom_agent_policy_rollout_cancelled_total", baseLabels, totals.PolicyRolloutCancelled)
	writeAgentCounter(w, "netloom_agent_tcx_failed_total", baseLabels, totals.TCXFailed)
	writeAgentCounter(w, "netloom_agent_tcx_rollbacks_total", baseLabels, totals.TCXRollbacks)
	writeAgentCounter(w, "netloom_agent_provider_degraded_total", baseLabels, totals.ProviderDegraded)
	writeAgentCounter(w, "netloom_agent_conntrack_expired_total", baseLabels, totals.ConntrackExpired)
	writeAgentCounter(w, "netloom_agent_policy_rule_packets_observed_total", baseLabels, totals.PolicyRulePackets)
	writeAgentCounter(w, "netloom_agent_policy_rule_bytes_observed_total", baseLabels, totals.PolicyRuleBytes)
	writeAgentCounter(w, "netloom_agent_policy_rule_dropped_observed_total", baseLabels, totals.PolicyRuleDropped)
	writeAgentCounter(w, "netloom_agent_policy_rule_rejected_observed_total", baseLabels, totals.PolicyRuleRejected)
	writeAgentCounter(w, "netloom_agent_policy_rule_no_match_drops_observed_total", baseLabels, totals.PolicyRuleNoMatchDrops)
	writeAgentCounter(w, "netloom_agent_policy_rule_deny_drops_observed_total", baseLabels, totals.PolicyRuleDenyDrops)
	writeAgentCounter(w, "netloom_agent_policy_rule_reject_drops_observed_total", baseLabels, totals.PolicyRuleRejectDrops)

	writeMetricType(w, "netloom_agent_policy_rule_packets_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_packets_total%s %d\n", baseLabels, result.PolicyRulePackets)
	writeMetricType(w, "netloom_agent_policy_rule_bytes_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_bytes_total%s %d\n", baseLabels, result.PolicyRuleBytes)
	writeMetricType(w, "netloom_agent_policy_rule_allowed_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_allowed_total%s %d\n", baseLabels, result.PolicyRuleAllowed)
	writeMetricType(w, "netloom_agent_policy_rule_dropped_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_dropped_total%s %d\n", baseLabels, result.PolicyRuleDropped)
	writeMetricType(w, "netloom_agent_policy_rule_rejected_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_rejected_total%s %d\n", baseLabels, result.PolicyRuleRejected)
	writeMetricType(w, "netloom_agent_policy_rule_logged_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_logged_total%s %d\n", baseLabels, result.PolicyRuleLogged)
	noMatchDrops, denyDrops, rejectDrops := policyRuleDropReasonTotals(result.PolicyRuleStats)
	writeMetricType(w, "netloom_agent_policy_rule_no_match_drops_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_no_match_drops_total%s %d\n", baseLabels, noMatchDrops)
	writeMetricType(w, "netloom_agent_policy_rule_deny_drops_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_deny_drops_total%s %d\n", baseLabels, denyDrops)
	writeMetricType(w, "netloom_agent_policy_rule_reject_drops_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_reject_drops_total%s %d\n", baseLabels, rejectDrops)
	ruleCatalog := policyRuleCatalogByMetricKey(result.PolicyRuleCatalog)
	for _, stat := range result.PolicyRuleStats {
		catalog := ruleCatalog[policyRuleMetricKey(stat.EndpointID, stat.RuleCookie)]
		labels := prometheusLabels(map[string]string{
			"node":           result.Node,
			"store":          snapshot.Store,
			"endpoint":       stat.EndpointID,
			"rule_cookie":    strconv.FormatUint(uint64(stat.RuleCookie), 10),
			"rule_ref":       catalog.RuleRef,
			"vpc":            catalog.VPC,
			"security_group": catalog.SecurityGroup,
			"rule_id":        catalog.RuleID,
		})
		fmt.Fprintf(w, "netloom_agent_policy_rule_packets_by_rule_total%s %d\n", labels, stat.Packets)
		fmt.Fprintf(w, "netloom_agent_policy_rule_bytes_by_rule_total%s %d\n", labels, stat.Bytes)
		fmt.Fprintf(w, "netloom_agent_policy_rule_allowed_by_rule_total%s %d\n", labels, stat.Allowed)
		fmt.Fprintf(w, "netloom_agent_policy_rule_dropped_by_rule_total%s %d\n", labels, stat.Dropped)
		fmt.Fprintf(w, "netloom_agent_policy_rule_rejected_by_rule_total%s %d\n", labels, stat.Rejected)
		fmt.Fprintf(w, "netloom_agent_policy_rule_no_match_drops_by_rule_total%s %d\n", labels, stat.NoMatchDrops)
		fmt.Fprintf(w, "netloom_agent_policy_rule_deny_drops_by_rule_total%s %d\n", labels, stat.DenyDrops)
		fmt.Fprintf(w, "netloom_agent_policy_rule_reject_drops_by_rule_total%s %d\n", labels, stat.RejectDrops)
		fmt.Fprintf(w, "netloom_agent_policy_rule_logged_by_rule_total%s %d\n", labels, stat.Logged)
	}

	writeMetricType(w, "netloom_agent_tcx_eligible", "gauge")
	fmt.Fprintf(w, "netloom_agent_tcx_eligible%s %d\n", baseLabels, result.TCXEligible)
	writeMetricType(w, "netloom_agent_tcx_skipped", "gauge")
	fmt.Fprintf(w, "netloom_agent_tcx_skipped%s %d\n", baseLabels, result.TCXSkipped)
	writeMetricType(w, "netloom_agent_tcx_failed", "gauge")
	fmt.Fprintf(w, "netloom_agent_tcx_failed%s %d\n", prometheusLabels(map[string]string{
		"node":   result.Node,
		"store":  snapshot.Store,
		"target": result.TCXFailedTarget,
	}), result.TCXFailed)
	writeMetricType(w, "netloom_agent_tcx_rollbacks", "gauge")
	fmt.Fprintf(w, "netloom_agent_tcx_rollbacks%s %d\n", baseLabels, result.TCXRollbacks)
}

func policyRuleDropReasonTotals(stats []dataplane.RuleMetrics) (uint64, uint64, uint64) {
	var noMatchDrops, denyDrops, rejectDrops uint64
	for _, stat := range stats {
		noMatchDrops += stat.NoMatchDrops
		denyDrops += stat.DenyDrops
		rejectDrops += stat.RejectDrops
	}
	return noMatchDrops, denyDrops, rejectDrops
}

func policyRuleCatalogByMetricKey(catalog []agent.PolicyRuleCatalogEntry) map[string]agent.PolicyRuleCatalogEntry {
	out := make(map[string]agent.PolicyRuleCatalogEntry, len(catalog))
	for _, entry := range catalog {
		out[policyRuleMetricKey(entry.EndpointID, entry.RuleCookie)] = entry
	}
	return out
}

func policyRuleMetricKey(endpointID string, cookie uint32) string {
	return fmt.Sprintf("%s\x00%d", endpointID, cookie)
}

func writeAgentCounter(w ioStringWriter, name, labels string, value uint64) {
	writeMetricType(w, name, "counter")
	fmt.Fprintf(w, "%s%s %d\n", name, labels, value)
}

func writeAgentDurationHistogram(w ioStringWriter, node, store, baseLabels string, totals agentMetricsTotals) {
	name := "netloom_agent_reconcile_duration_milliseconds_histogram"
	writeMetricType(w, name, "histogram")
	for i, bucket := range agentReconcileDurationBuckets {
		labels := prometheusLabels(map[string]string{
			"le":    strconv.FormatInt(bucket.Milliseconds(), 10),
			"node":  node,
			"store": store,
		})
		fmt.Fprintf(w, "%s_bucket%s %d\n", name, labels, totals.DurationBuckets[i])
	}
	fmt.Fprintf(w, "%s_bucket%s %d\n", name, prometheusLabels(map[string]string{"le": "+Inf", "node": node, "store": store}), totals.Attempts)
	fmt.Fprintf(w, "%s_sum%s %d\n", name, baseLabels, totals.DurationSum.Milliseconds())
	fmt.Fprintf(w, "%s_count%s %d\n", name, baseLabels, totals.Attempts)
}

type ioStringWriter interface {
	Write([]byte) (int, error)
}

func writeMetricHelp(w ioStringWriter, name, help string) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
}

func writeMetricType(w ioStringWriter, name, typ string) {
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
}

func prometheusLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strconv.Quote(labels[key]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func nonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func reconcileInterval() (time.Duration, error) {
	raw := os.Getenv("NETLOOM_RECONCILE_INTERVAL_MS")
	if raw == "" {
		return 0, nil
	}
	ms, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NETLOOM_RECONCILE_INTERVAL_MS: %w", err)
	}
	if ms <= 0 {
		return 0, nil
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func policyStore() (agent.PolicyStore, string, func()) {
	if os.Getenv("NETLOOM_POLICY_STORE") == "ebpf" {
		cfg := dataplane.EBPFPolicyStoreConfig{}
		if maxEntries, err := parseUint32Env("NETLOOM_EBPF_MAP_MAX_ENTRIES"); err == nil {
			cfg.MaxEntries = maxEntries
		}
		if schemaVersion, err := parseUint32Env("NETLOOM_EBPF_MAP_SCHEMA_VERSION"); err == nil {
			cfg.SchemaVersion = schemaVersion
		}
		if overflow, err := dataplane.ParsePolicyMapOverflowAction(os.Getenv("NETLOOM_EBPF_MAP_OVERFLOW_ACTION")); err == nil {
			cfg.OverflowAction = overflow
		}
		cfg.PinRoot = ebpfMapPinRoot()
		cfg.MetadataRoot = ebpfMapMetadataRoot()
		store := dataplane.NewEBPFPolicyStoreWithConfig(cfg)
		return store, "ebpf", func() {
			_ = store.Close()
		}
	}
	return dataplane.NewInMemoryPolicyStore(), "memory", func() {}
}

func ebpfMapPinRoot() string {
	if configured := strings.TrimSpace(os.Getenv("NETLOOM_EBPF_MAP_PIN_ROOT")); configured != "" {
		return configured
	}
	if err := ensureBPFFSPinRoot(defaultBPFFSRoot, defaultBPFFSPinRoot); err == nil {
		return defaultBPFFSPinRoot
	}
	if err := ensureBPFFSPinRoot(defaultRuntimeBPFRoot, defaultRuntimePinRoot); err == nil {
		return defaultRuntimePinRoot
	}
	return defaultRuntimePinRoot
}

func ebpfMapMetadataRoot() string {
	if configured := strings.TrimSpace(os.Getenv("NETLOOM_EBPF_MAP_METADATA_ROOT")); configured != "" {
		return configured
	}
	return defaultMetadataRoot
}

func ensureDirAccessible(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("not a directory")
	}
	return nil
}

func ensureBPFFSPinRoot(mountRoot, pinRoot string) error {
	if err := ensureBPFFSMounted(mountRoot); err != nil {
		return err
	}
	return os.MkdirAll(pinRoot, 0o755)
}

func ensureBPFFSMounted(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return err
	}
	if fs.Type == unix.BPF_FS_MAGIC {
		return nil
	}
	if err := unix.Mount("bpffs", path, "bpf", 0, ""); err != nil {
		return err
	}
	if err := unix.Statfs(path, &fs); err != nil {
		return err
	}
	if fs.Type != unix.BPF_FS_MAGIC {
		return fmt.Errorf("%s is not backed by bpffs", path)
	}
	return nil
}

func parseUint32Env(key string) (uint32, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return 0, fmt.Errorf("%s is empty", key)
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, err
	}
	if value == 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}
	return uint32(value), nil
}

func tcxHold() (time.Duration, error) {
	raw := os.Getenv("NETLOOM_TCX_HOLD_MS")
	if raw == "" {
		return 0, nil
	}
	ms, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NETLOOM_TCX_HOLD_MS: %w", err)
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func conntrackIdleTimeout() time.Duration {
	ms := getenvIntDefault("NETLOOM_CONNTRACK_MAX_IDLE_MS", 0)
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func policyGCMaxIdle() time.Duration {
	ms := getenvIntDefault("NETLOOM_POLICY_GC_MAX_IDLE_MS", 0)
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func policyPressureMitigationThreshold() uint32 {
	value := getenvIntDefault("NETLOOM_POLICY_PRESSURE_MITIGATION_THRESHOLD", 0)
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return uint32(value)
}

func policyPressureQuarantineThreshold() uint32 {
	value := getenvIntDefault("NETLOOM_POLICY_PRESSURE_QUARANTINE_THRESHOLD", 0)
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return uint32(value)
}

func policyPressureQuarantine() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NETLOOM_POLICY_PRESSURE_QUARANTINE"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func policyRolloutApprovalSecret() string {
	return strings.TrimSpace(os.Getenv("NETLOOM_POLICY_ROLLOUT_APPROVAL_SECRET"))
}

func linuxDatapathOptions() *linuxdatapath.Options {
	if os.Getenv("NETLOOM_LINUX_DATAPATH") != "1" {
		return nil
	}
	return &linuxdatapath.Options{
		Mode:                 getenvDefault("NETLOOM_LINUX_DATAPATH_MODE", "local"),
		Backend:              "netlink",
		LocalDevice:          getenvDefault("NETLOOM_DATAPATH_DEV", "lo"),
		UnderlayDevice:       getenvDefault("NETLOOM_UNDERLAY_DEV", "eth0"),
		ProviderLinks:        parseProviderLinks(os.Getenv("NETLOOM_PROVIDER_NETWORK_LINKS")),
		SyncOVSDB:            ovsdbSyncEnabled(),
		NetNSPrefix:          getenvDefault("NETLOOM_NETNS_PREFIX", "nl"),
		WorkloadIF:           getenvDefault("NETLOOM_WORKLOAD_IF", "eth0"),
		NodeUnderlays:        parseNodeUnderlays(os.Getenv("NETLOOM_NODE_UNDERLAYS")),
		PolicyTableBase:      getenvIntDefault("NETLOOM_POLICY_ROUTE_TABLE_BASE", 10000),
		PolicyTableSize:      getenvIntDefault("NETLOOM_POLICY_ROUTE_TABLE_SIZE", 1024),
		CleanupStale:         os.Getenv("NETLOOM_LINUX_DATAPATH_CLEANUP") == "1",
		StrictProviderHealth: os.Getenv("NETLOOM_PROVIDER_HEALTH_STRICT") == "1",
	}
}

func linuxDatapathOptionsWithOVSDBSyncer(ctx context.Context) (*linuxdatapath.Options, policyRolloutStateStore, dnsObservationStore, openVSwitchExternalIDStore, func(), error) {
	options := linuxDatapathOptions()
	endpoint := strings.TrimSpace(os.Getenv("NETLOOM_OVSDB_ENDPOINT"))
	if endpoint == "" {
		return options, nil, nil, nil, func() {}, nil
	}
	client, closeFn, err := newOpenVSwitchClient(ctx, endpoint)
	if err != nil {
		return nil, nil, nil, nil, func() {}, err
	}
	providerOVSDB := linuxdatapath.NewLibOVSDBProviderSyncer(client)
	if options != nil && options.SyncOVSDB {
		options.ProviderOVSDBSyncer = providerOVSDB
		options.ProviderOVSDBReader = providerOVSDB
	}
	return options, ovsdbPolicyRolloutStateStore{syncer: providerOVSDB}, ovsdbDNSObservationStore{syncer: providerOVSDB}, providerOVSDB, closeFn, nil
}

func policyRolloutHistoryStoreFromEnv(ctx context.Context) (policyRolloutHistoryStore, func(), error) {
	endpoint := strings.TrimSpace(os.Getenv("NETLOOM_OVSDB_ENDPOINT"))
	if endpoint == "" {
		return nil, func() {}, nil
	}
	client, closeFn, err := newOpenVSwitchClient(ctx, endpoint)
	if err != nil {
		return nil, func() {}, err
	}
	return ovsdbPolicyRolloutHistoryStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)}, closeFn, nil
}

func policyActionHistoryStoreFromEnv(ctx context.Context) (policyActionHistoryStore, func(), error) {
	endpoint := strings.TrimSpace(os.Getenv("NETLOOM_OVSDB_ENDPOINT"))
	if endpoint == "" {
		return nil, func() {}, nil
	}
	client, closeFn, err := newOpenVSwitchClient(ctx, endpoint)
	if err != nil {
		return nil, func() {}, err
	}
	return ovsdbPolicyActionHistoryStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)}, closeFn, nil
}

func policyStatusStoreFromEnv(ctx context.Context) (policyStatusStore, func(), error) {
	endpoint := strings.TrimSpace(os.Getenv("NETLOOM_OVSDB_ENDPOINT"))
	if endpoint == "" {
		return nil, func() {}, nil
	}
	client, closeFn, err := newOpenVSwitchClient(ctx, endpoint)
	if err != nil {
		return nil, func() {}, err
	}
	return ovsdbPolicyStatusStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)}, closeFn, nil
}

func policyEventsStoreFromEnv(ctx context.Context) (policyEventsStore, func(), error) {
	endpoint := strings.TrimSpace(os.Getenv("NETLOOM_OVSDB_ENDPOINT"))
	if endpoint == "" {
		return nil, func() {}, nil
	}
	client, closeFn, err := newOpenVSwitchClient(ctx, endpoint)
	if err != nil {
		return nil, func() {}, err
	}
	return ovsdbPolicyEventsStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)}, closeFn, nil
}

func policyRulesStoreFromEnv(ctx context.Context) (policyRulesStore, func(), error) {
	endpoint := strings.TrimSpace(os.Getenv("NETLOOM_OVSDB_ENDPOINT"))
	if endpoint == "" {
		return nil, func() {}, nil
	}
	client, closeFn, err := newOpenVSwitchClient(ctx, endpoint)
	if err != nil {
		return nil, func() {}, err
	}
	return ovsdbPolicyRulesStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)}, closeFn, nil
}

func policyEntriesStoreFromEnv(ctx context.Context) (policyEntriesStore, func(), error) {
	endpoint := strings.TrimSpace(os.Getenv("NETLOOM_OVSDB_ENDPOINT"))
	if endpoint == "" {
		return nil, func() {}, nil
	}
	client, closeFn, err := newOpenVSwitchClient(ctx, endpoint)
	if err != nil {
		return nil, func() {}, err
	}
	return ovsdbPolicyEntriesStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)}, closeFn, nil
}

func policyFreezeStateStoreFromEnv(ctx context.Context) (policyFreezeStateStore, func(), error) {
	endpoint := strings.TrimSpace(os.Getenv("NETLOOM_OVSDB_ENDPOINT"))
	if endpoint == "" {
		return nil, func() {}, nil
	}
	client, closeFn, err := newOpenVSwitchClient(ctx, endpoint)
	if err != nil {
		return nil, func() {}, err
	}
	return ovsdbPolicyFreezeStateStore{syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client)}, closeFn, nil
}

func identityGroupObservationStoreFromEnv(ctx context.Context) (openVSwitchExternalIDStore, func(), error) {
	endpoint := strings.TrimSpace(os.Getenv("NETLOOM_OVSDB_ENDPOINT"))
	if endpoint == "" {
		return nil, func() {}, nil
	}
	client, closeFn, err := newOpenVSwitchClient(ctx, endpoint)
	if err != nil {
		return nil, func() {}, err
	}
	return linuxdatapath.NewLibOVSDBProviderSyncer(client), closeFn, nil
}

func ovsdbSyncEnabled() bool {
	return strings.TrimSpace(os.Getenv("NETLOOM_OVSDB_ENDPOINT")) != "" ||
		os.Getenv("NETLOOM_OVSDB_SYNC") == "1"
}

func newOpenVSwitchClient(ctx context.Context, endpoint string) (linuxdatapath.OVSDBClient, func(), error) {
	return linuxdatapath.NewOpenVSwitchClient(ctx, endpoint)
}

func getenvDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getenvIntDefault(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func parseNodeUnderlays(raw string) map[string][]netip.Addr {
	out := make(map[string][]netip.Addr)
	for _, item := range strings.Split(raw, ",") {
		if item == "" {
			continue
		}
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err == nil {
			out[name] = append(out[name], addr)
		}
	}
	return out
}

func parseProviderLinks(raw string) map[string]string {
	out := make(map[string]string)
	for _, item := range strings.Split(raw, ",") {
		if item == "" {
			continue
		}
		provider, device, ok := strings.Cut(item, "=")
		provider = strings.TrimSpace(provider)
		device = strings.TrimSpace(device)
		if !ok || provider == "" || device == "" {
			continue
		}
		out[provider] = device
	}
	return out
}
