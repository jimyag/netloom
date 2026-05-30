package main

import (
	"context"
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
	fmt.Printf("netloom-agent ready for node policy and dataplane reconciliation endpoint=%s entries=%d allow=%s deny=%s policy_allowed=%d policy_dropped=%d policy_logged=%d drop_events=%d policy_events=%d tcx=%s\n", result.EndpointID, result.Entries, result.Allowed, result.Denied, result.PolicyStats.Allowed, result.PolicyStats.Dropped, result.PolicyStats.Logged, result.DropEvents, result.PolicyEvents, result.TCX)
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
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	state, err := control.LoadDesiredStateJSON(file)
	if err != nil {
		return err
	}
	result, err := reconciler.Reconcile(ctx, state, agent.ReconcileOptions{
		Node:          node,
		TCXInterface:  os.Getenv("NETLOOM_TCX_IFACE"),
		TCXWorkload:   os.Getenv("NETLOOM_TCX_WORKLOAD") == "1",
		LinuxDatapath: linuxDatapathOptions(),
	})
	if err != nil {
		return err
	}
	printReconcileResult(result, storeName)
	return nil
}

func reconcileStateFileOnce(ctx context.Context, path, node, storeName string, store agent.PolicyStore, hold time.Duration) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	state, err := control.LoadDesiredStateJSON(file)
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
		return err
	}
	printReconcileResult(result, storeName)
	return nil
}

func printReconcileResult(result agent.ReconcileResult, storeName string) {
	fmt.Printf("netloom-agent reconciled node policy node=%s store=%s endpoints=%d programs=%d entries=%d tcx_eligible=%d tcx=%s datapath=%s local_ips=%d remote_routes=%d policy_routes=%d cleanup=%t\n", result.Node, storeName, result.Endpoints, result.Programs, result.Entries, result.TCXEligible, result.TCX, result.Datapath, result.LocalIPs, result.RemoteRoutes, result.PolicyRoutes, result.Cleanup)
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
		store := dataplane.NewEBPFPolicyStore(0)
		return store, "ebpf", func() {
			_ = store.Close()
		}
	}
	return dataplane.NewInMemoryPolicyStore(), "memory", func() {}
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

func linuxDatapathOptions() *linuxdatapath.Options {
	if os.Getenv("NETLOOM_LINUX_DATAPATH") != "1" {
		return nil
	}
	return &linuxdatapath.Options{
		Mode:            getenvDefault("NETLOOM_LINUX_DATAPATH_MODE", "local"),
		Backend:         getenvDefault("NETLOOM_LINUX_DATAPATH_BACKEND", "netlink"),
		LocalDevice:     getenvDefault("NETLOOM_DATAPATH_DEV", "lo"),
		UnderlayDevice:  getenvDefault("NETLOOM_UNDERLAY_DEV", "eth0"),
		NetNSPrefix:     getenvDefault("NETLOOM_NETNS_PREFIX", "nl"),
		WorkloadIF:      getenvDefault("NETLOOM_WORKLOAD_IF", "eth0"),
		NodeUnderlays:   parseNodeUnderlays(os.Getenv("NETLOOM_NODE_UNDERLAYS")),
		PolicyTableBase: getenvIntDefault("NETLOOM_POLICY_ROUTE_TABLE_BASE", 10000),
		PolicyTableSize: getenvIntDefault("NETLOOM_POLICY_ROUTE_TABLE_SIZE", 1024),
		CleanupStale:    os.Getenv("NETLOOM_LINUX_DATAPATH_CLEANUP") == "1",
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

func parseNodeUnderlays(raw string) map[string]netip.Addr {
	out := make(map[string]netip.Addr)
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
			out[name] = addr
		}
	}
	return out
}
