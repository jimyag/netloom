package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jimyag/netloom/internal/agent"
	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/linuxdatapath"
	"golang.org/x/sys/unix"
)

const (
	defaultBPFFSRoot      = "/sys/fs/bpf"
	defaultBPFFSPinRoot   = "/sys/fs/bpf/netloom/policy"
	defaultRuntimeBPFRoot = "/var/run/netloom-ebpf"
	defaultRuntimePinRoot = "/var/run/netloom-ebpf/policy"
	defaultMetadataRoot   = "/var/run/netloom-ebpf-meta/policy"
)

func main() {
	if stateFile := os.Getenv("NETLOOM_STATE_FILE"); stateFile != "" {
		if err := runStateFile(context.Background(), stateFile); err != nil {
			log.Fatal(err)
		}
		return
	}

	result, err := agent.RunSelfTest(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("netloom-agent ready for node policy and dataplane reconciliation endpoint=%s entries=%d allow=%s deny=%s policy_allowed=%d policy_dropped=%d policy_conntrack=%d policy_established=%d policy_logged=%d rule_stats=%s drop_events=%d policy_events=%d trace_events=%d tcx=%s\n", result.EndpointID, result.Entries, result.Allowed, result.Denied, result.PolicyStats.Allowed, result.PolicyStats.Dropped, result.PolicyStats.Conntrack, result.PolicyStats.Established, result.PolicyStats.Logged, formatRuleStats(result.RuleStats), result.DropEvents, result.PolicyEvents, result.TraceEvents, result.TCX)
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
		return reconcileStateFileOnce(ctx, path, node, storeName, store, hold)
	}
	reconciler := agent.NewReconciler(store)
	defer func() {
		_ = reconciler.Close()
	}()
	reconcile := func() error {
		return reconcileStateFile(ctx, path, node, storeName, reconciler)
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

func reconcileStateFile(ctx context.Context, path, node, storeName string, reconciler *agent.Reconciler) error {
	start := time.Now()
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	state, err := control.LoadDesiredStateJSON(file)
	if err != nil {
		return err
	}
	state, err = withDNSObservations(state)
	if err != nil {
		return err
	}
	result, err := reconciler.Reconcile(ctx, state, agent.ReconcileOptions{
		Node:          node,
		TCXInterface:  os.Getenv("NETLOOM_TCX_IFACE"),
		TCXWorkload:   os.Getenv("NETLOOM_TCX_WORKLOAD") == "1",
		ConntrackIdle: conntrackIdleTimeout(),
		LinuxDatapath: linuxDatapathOptions(),
	})
	if err != nil {
		printReconcileFailure(result, storeName, err, time.Since(start))
		return err
	}
	printReconcileResult(result, storeName, time.Since(start))
	return nil
}

func reconcileStateFileOnce(ctx context.Context, path, node, storeName string, store agent.PolicyStore, hold time.Duration) error {
	start := time.Now()
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	state, err := control.LoadDesiredStateJSON(file)
	if err != nil {
		return err
	}
	state, err = withDNSObservations(state)
	if err != nil {
		return err
	}
	result, err := agent.ReconcileNodeWithOptions(ctx, state, agent.ReconcileOptions{
		Node:          node,
		Store:         store,
		TCXInterface:  os.Getenv("NETLOOM_TCX_IFACE"),
		TCXWorkload:   os.Getenv("NETLOOM_TCX_WORKLOAD") == "1",
		TCXHold:       hold,
		LinuxDatapath: linuxDatapathOptions(),
	})
	if err != nil {
		printReconcileFailure(result, storeName, err, time.Since(start))
		return err
	}
	printReconcileResult(result, storeName, time.Since(start))
	return nil
}

func withDNSObservations(state control.DesiredState) (control.DesiredState, error) {
	return withDNSObservationsAt(state, time.Now().UTC())
}

func withDNSObservationsAt(state control.DesiredState, now time.Time) (control.DesiredState, error) {
	path := os.Getenv("NETLOOM_DNS_OBSERVATIONS_FILE")
	if path == "" {
		return state, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return control.DesiredState{}, err
	}
	defer file.Close()
	records, err := control.LoadDNSObservationsJSON(file)
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

func printReconcileResult(result agent.ReconcileResult, storeName string, duration time.Duration) {
	fmt.Printf("netloom-agent reconciled node policy node=%s store=%s endpoints=%d programs=%d entries=%d policy_map_entries=%d policy_map_capacity=%d policy_map_pressure_max=%d policy_map_pressure_endpoint=%s policy_map_pressure_endpoints=%d policy_added=%d policy_updated=%d policy_deleted=%d policy_unchanged=%d policy_events=%d policy_failed=%d policy_rollbacks=%d policy_failed_endpoint=%s policy_failed_revision=%d policy_revision_max=%d policy_last_error=%s policy_rule_packets=%d policy_rule_bytes=%d policy_rule_allowed=%d policy_rule_dropped=%d policy_rule_rejected=%d policy_rule_logged=%d policy_rule_stats=%s conntrack_expired=%d tcx_eligible=%d tcx=%s tcx_failed=%d tcx_rollbacks=%d tcx_failed_target=%s tcx_last_error=%s datapath=%s local_ips=%d remote_routes=%d policy_routes=%d provider_networks=%d provider_links=%d provider_ready=%d provider_degraded=%d provider_status=%s provider_network_status=%s provider_issues=%s provider_inventory_total=%d provider_inventory_ready=%d provider_inventory_degraded=%d provider_inventory_status=%s cleanup=%t reconcile_duration_ms=%d\n", result.Node, storeName, result.Endpoints, result.Programs, result.Entries, result.PolicyMapEntries, result.PolicyMapCapacity, result.PolicyMapPressureMax, formatResultValue(result.PolicyMapPressureEndpoint), result.PolicyMapPressureEndpoints, result.PolicyAdded, result.PolicyUpdated, result.PolicyDeleted, result.PolicyUnchanged, result.PolicyEvents, result.PolicyFailed, result.PolicyRollbacks, formatResultValue(result.PolicyFailedEndpoint), result.PolicyFailedRevision, result.PolicyRevisionMax, formatResultError(result.PolicyLastError), result.PolicyRulePackets, result.PolicyRuleBytes, result.PolicyRuleAllowed, result.PolicyRuleDropped, result.PolicyRuleRejected, result.PolicyRuleLogged, formatEndpointRuleStats(result.PolicyRuleStats), result.ConntrackExpired, result.TCXEligible, result.TCX, result.TCXFailed, result.TCXRollbacks, formatResultValue(result.TCXFailedTarget), formatResultError(result.TCXLastError), result.Datapath, result.LocalIPs, result.RemoteRoutes, result.PolicyRoutes, result.ProviderNetworks, result.ProviderLinks, result.ProviderReady, result.ProviderDegraded, formatProviderStatus(result.ProviderStatus), formatProviderNetworkStatus(result.ProviderNetworkStatus), formatProviderIssues(result.ProviderIssues), result.ProviderInventoryTotal, result.ProviderInventoryReady, result.ProviderInventoryDegraded, formatProviderInventoryStatus(result.ProviderInventoryStatus), result.Cleanup, duration.Milliseconds())
}

func printReconcileFailure(result agent.ReconcileResult, storeName string, err error, duration time.Duration) {
	fmt.Printf("netloom-agent reconcile failed node=%s store=%s endpoints=%d programs=%d entries=%d policy_map_entries=%d policy_map_capacity=%d policy_map_pressure_max=%d policy_map_pressure_endpoint=%s policy_map_pressure_endpoints=%d policy_added=%d policy_updated=%d policy_deleted=%d policy_unchanged=%d policy_events=%d policy_failed=%d policy_rollbacks=%d policy_failed_endpoint=%s policy_failed_revision=%d policy_revision_max=%d policy_last_error=%s policy_rule_packets=%d policy_rule_bytes=%d policy_rule_allowed=%d policy_rule_dropped=%d policy_rule_rejected=%d policy_rule_logged=%d policy_rule_stats=%s tcx_eligible=%d tcx=%s tcx_failed=%d tcx_rollbacks=%d tcx_failed_target=%s tcx_last_error=%s provider_networks=%d provider_links=%d provider_ready=%d provider_degraded=%d provider_status=%s provider_network_status=%s provider_issues=%s provider_inventory_total=%d provider_inventory_ready=%d provider_inventory_degraded=%d provider_inventory_status=%s err=%s reconcile_duration_ms=%d\n", result.Node, storeName, result.Endpoints, result.Programs, result.Entries, result.PolicyMapEntries, result.PolicyMapCapacity, result.PolicyMapPressureMax, formatResultValue(result.PolicyMapPressureEndpoint), result.PolicyMapPressureEndpoints, result.PolicyAdded, result.PolicyUpdated, result.PolicyDeleted, result.PolicyUnchanged, result.PolicyEvents, result.PolicyFailed, result.PolicyRollbacks, formatResultValue(result.PolicyFailedEndpoint), result.PolicyFailedRevision, result.PolicyRevisionMax, formatResultError(result.PolicyLastError), result.PolicyRulePackets, result.PolicyRuleBytes, result.PolicyRuleAllowed, result.PolicyRuleDropped, result.PolicyRuleRejected, result.PolicyRuleLogged, formatEndpointRuleStats(result.PolicyRuleStats), result.TCXEligible, result.TCX, result.TCXFailed, result.TCXRollbacks, formatResultValue(result.TCXFailedTarget), formatResultError(result.TCXLastError), result.ProviderNetworks, result.ProviderLinks, result.ProviderReady, result.ProviderDegraded, formatProviderStatus(result.ProviderStatus), formatProviderNetworkStatus(result.ProviderNetworkStatus), formatProviderIssues(result.ProviderIssues), result.ProviderInventoryTotal, result.ProviderInventoryReady, result.ProviderInventoryDegraded, formatProviderInventoryStatus(result.ProviderInventoryStatus), formatResultError(fmt.Sprint(err)), duration.Milliseconds())
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
		parts = append(parts, fmt.Sprintf("%s:%s:%d/%d:%d:%s", status.ProviderNetwork, state, status.ReadyLinks, status.LinkCount, status.IssueCount, reasons))
	}
	return strings.Join(parts, ",")
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

func linuxDatapathOptions() *linuxdatapath.Options {
	if os.Getenv("NETLOOM_LINUX_DATAPATH") != "1" {
		return nil
	}
	return &linuxdatapath.Options{
		Mode:                 getenvDefault("NETLOOM_LINUX_DATAPATH_MODE", "local"),
		Backend:              getenvDefault("NETLOOM_LINUX_DATAPATH_BACKEND", "netlink"),
		LocalDevice:          getenvDefault("NETLOOM_DATAPATH_DEV", "lo"),
		UnderlayDevice:       getenvDefault("NETLOOM_UNDERLAY_DEV", "eth0"),
		ProviderLinks:        parseProviderLinks(os.Getenv("NETLOOM_PROVIDER_NETWORK_LINKS")),
		NetNSPrefix:          getenvDefault("NETLOOM_NETNS_PREFIX", "nl"),
		WorkloadIF:           getenvDefault("NETLOOM_WORKLOAD_IF", "eth0"),
		NodeUnderlays:        parseNodeUnderlays(os.Getenv("NETLOOM_NODE_UNDERLAYS")),
		PolicyTableBase:      getenvIntDefault("NETLOOM_POLICY_ROUTE_TABLE_BASE", 10000),
		PolicyTableSize:      getenvIntDefault("NETLOOM_POLICY_ROUTE_TABLE_SIZE", 1024),
		CleanupStale:         os.Getenv("NETLOOM_LINUX_DATAPATH_CLEANUP") == "1",
		StrictProviderHealth: os.Getenv("NETLOOM_PROVIDER_HEALTH_STRICT") == "1",
	}
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
