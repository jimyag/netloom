package linuxdatapath

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/model"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const netnsRunDir = "/var/run/netns"

func ApplyNetlink(ctx context.Context, state control.DesiredState, options Options) (Result, error) {
	normalized, result, err := normalizeOptions(options)
	if err != nil {
		return Result{}, err
	}
	if result.Mode == "local" {
		return applyLocalNetlink(ctx, state, normalized, result)
	}
	if result.Mode != "netns" {
		return Result{}, fmt.Errorf("unsupported linux datapath mode %q", result.Mode)
	}
	return applyNetNSNetlink(ctx, state, normalized, result)
}

func applyLocalNetlink(ctx context.Context, state control.DesiredState, options Options, result Result) (Result, error) {
	root, err := netlink.NewHandle()
	if err != nil {
		return Result{}, err
	}
	defer root.Close()
	result.CleanupPlanned = options.CleanupStale
	if len(options.ProviderInventory) == 0 {
		links, err := root.LinkList()
		if err != nil {
			return Result{}, fmt.Errorf("list provider inventory: %w", err)
		}
		options.ProviderInventory = providerInventoryFromNetlink(links)
	}
	result.ProviderInventoryStatus = append([]ProviderInterface(nil), options.ProviderInventory...)
	result.ProviderInventoryTotal, result.ProviderInventoryReady, result.ProviderInventoryDegraded = summarizeProviderInventory(options.ProviderInventory)
	providerSpecs, err := desiredProviderNetworkLinkSpecs(state, options.Node, options.ProviderLinks, options.ProviderInventory)
	if err != nil {
		applyProviderPlanningIssue(&result, err)
		return result, err
	}
	result.ProviderNetworks, result.ProviderLinks = summarizeProviderNetworkSpecs(providerSpecs)
	result.ProviderStatus = make([]ProviderLinkStatus, 0, len(providerSpecs))
	for _, spec := range providerSpecs {
		status, err := ensureProviderNetworkLink(root, spec)
		if status.ProviderNetwork != "" {
			result.ProviderStatus = append(result.ProviderStatus, status)
			result.ProviderReady, result.ProviderDegraded = summarizeProviderLinkHealth(result.ProviderStatus)
		}
		if err != nil {
			return result, fmt.Errorf("ensure provider link %s: %w", spec.Name, err)
		}
	}
	result.ProviderReady, result.ProviderDegraded = summarizeProviderLinkHealth(result.ProviderStatus)
	result.ProviderNetworkStatus = summarizeProviderNetworkStatus(result.ProviderStatus, result.ProviderIssues)
	if options.CleanupStale {
		if err := cleanupStaleProviderNetworkLinks(root, providerSpecs); err != nil {
			return Result{}, err
		}
	}

	localLink, err := root.LinkByName(options.LocalDevice)
	if err != nil {
		return Result{}, fmt.Errorf("lookup local device %s: %w", options.LocalDevice, err)
	}
	if err := root.LinkSetUp(localLink); err != nil {
		return Result{}, fmt.Errorf("set %s up: %w", options.LocalDevice, err)
	}
	var underlay netlink.Link
	if hasRemoteEndpoints(state.Endpoints, options.Node) || options.CleanupStale {
		underlay, err = root.LinkByName(options.UnderlayDevice)
		if err != nil {
			return Result{}, fmt.Errorf("lookup underlay device %s: %w", options.UnderlayDevice, err)
		}
	}
	desiredRemoteRoutes := make(map[string]struct{})
	desiredLocalPrefixes := make(map[string]struct{})
	for _, endpoint := range state.Endpoints {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if endpoint.Node == options.Node {
			desiredLocalPrefixes[endpointPrefix(endpoint.IP)] = struct{}{}
			if err := replaceAddr(root, localLink, endpoint.IP, addrPrefixBits(endpoint.IP)); err != nil {
				return Result{}, fmt.Errorf("assign %s to %s: %w", endpoint.IP, options.LocalDevice, err)
			}
			result.LocalAddresses++
			continue
		}
		nextHop, err := resolveNode(ctx, endpoint.Node, endpoint.IP, options.NodeUnderlays)
		if err != nil {
			return Result{}, fmt.Errorf("resolve underlay for node %s: %w", endpoint.Node, err)
		}
		desiredRemoteRoutes[endpointPrefix(endpoint.IP)] = struct{}{}
		if err := replaceRemoteEndpointRoute(root, endpoint.IP, nextHop, underlay.Attrs().Index); err != nil {
			return Result{}, fmt.Errorf("route %s via %s: %w", endpoint.IP, nextHop, err)
		}
		result.RemoteRoutes++
	}
	if options.CleanupStale {
		if options.LocalDevice != "lo" {
			if err := cleanupStaleManagedAddrs(root, localLink, desiredLocalPrefixes); err != nil {
				return Result{}, fmt.Errorf("cleanup stale local addresses on %s: %w", options.LocalDevice, err)
			}
		}
		if err := cleanupStaleRemoteRoutes(root, desiredRemoteRoutes, underlay.Attrs().Index); err != nil {
			return Result{}, err
		}
	}
	policyRoutes, err := applyPolicyRoutesNetlink(root, state, options)
	if err != nil {
		return Result{}, err
	}
	result.PolicyRoutes = policyRoutes
	return result, nil
}

func applyNetNSNetlink(ctx context.Context, state control.DesiredState, options Options, result Result) (Result, error) {
	result.Device = "netns"
	result.CleanupPlanned = options.CleanupStale
	if err := setIPv4Forwarding(); err != nil {
		return Result{}, err
	}
	root, err := netlink.NewHandle()
	if err != nil {
		return Result{}, err
	}
	defer root.Close()
	if len(options.ProviderInventory) == 0 {
		links, err := root.LinkList()
		if err != nil {
			return Result{}, fmt.Errorf("list provider inventory: %w", err)
		}
		options.ProviderInventory = providerInventoryFromNetlink(links)
	}
	result.ProviderInventoryStatus = append([]ProviderInterface(nil), options.ProviderInventory...)
	result.ProviderInventoryTotal, result.ProviderInventoryReady, result.ProviderInventoryDegraded = summarizeProviderInventory(options.ProviderInventory)
	providerSpecs, err := desiredProviderNetworkLinkSpecs(state, options.Node, options.ProviderLinks, options.ProviderInventory)
	if err != nil {
		applyProviderPlanningIssue(&result, err)
		return result, err
	}
	result.ProviderNetworks, result.ProviderLinks = summarizeProviderNetworkSpecs(providerSpecs)
	result.ProviderStatus = make([]ProviderLinkStatus, 0, len(providerSpecs))
	for _, spec := range providerSpecs {
		status, err := ensureProviderNetworkLink(root, spec)
		if status.ProviderNetwork != "" {
			result.ProviderStatus = append(result.ProviderStatus, status)
			result.ProviderReady, result.ProviderDegraded = summarizeProviderLinkHealth(result.ProviderStatus)
		}
		if err != nil {
			return result, fmt.Errorf("ensure provider link %s: %w", spec.Name, err)
		}
	}
	result.ProviderReady, result.ProviderDegraded = summarizeProviderLinkHealth(result.ProviderStatus)
	result.ProviderNetworkStatus = summarizeProviderNetworkStatus(result.ProviderStatus, result.ProviderIssues)
	if options.CleanupStale {
		if err := cleanupStaleProviderNetworkLinks(root, providerSpecs); err != nil {
			return Result{}, err
		}
	}

	if options.CleanupStale {
		if err := cleanupStaleNamespaces(state, options.Node, options.NetNSPrefix); err != nil {
			return Result{}, err
		}
	}
	var underlay netlink.Link
	if hasRemoteEndpoints(state.Endpoints, options.Node) || options.CleanupStale {
		underlay, err = root.LinkByName(options.UnderlayDevice)
		if err != nil {
			return Result{}, fmt.Errorf("lookup underlay device %s: %w", options.UnderlayDevice, err)
		}
	}
	desiredRemoteRoutes := make(map[string]struct{})
	desiredLocalPrefixes := make(map[string]struct{})
	for _, endpoint := range state.Endpoints {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if endpoint.Node == options.Node {
			desiredLocalPrefixes[endpointPrefix(endpoint.IP)] = struct{}{}
			if err := ensureNetNSWorkload(root, model.EndpointKey(endpoint.VPC, endpoint.ID), endpoint.IP, options.WorkloadIF, workloadHostGateway(endpoint.IP, options.HostGateway), options.NetNSPrefix); err != nil {
				return Result{}, fmt.Errorf("ensure workload %s: %w", endpoint.ID, err)
			}
			result.LocalAddresses++
			continue
		}
		nextHop, err := resolveNode(ctx, endpoint.Node, endpoint.IP, options.NodeUnderlays)
		if err != nil {
			return Result{}, fmt.Errorf("resolve underlay for node %s: %w", endpoint.Node, err)
		}
		desiredRemoteRoutes[endpointPrefix(endpoint.IP)] = struct{}{}
		if err := replaceRemoteEndpointRoute(root, endpoint.IP, nextHop, underlay.Attrs().Index); err != nil {
			return Result{}, fmt.Errorf("route %s via %s: %w", endpoint.IP, nextHop, err)
		}
		result.RemoteRoutes++
	}
	if options.CleanupStale {
		if err := cleanupStaleRemoteRoutes(root, desiredRemoteRoutes, underlay.Attrs().Index); err != nil {
			return Result{}, err
		}
		if err := cleanupStaleWorkloadRoutes(root, desiredLocalPrefixes); err != nil {
			return Result{}, err
		}
	}
	policyRoutes, err := applyPolicyRoutesNetlink(root, state, options)
	if err != nil {
		return Result{}, err
	}
	result.PolicyRoutes = policyRoutes
	return result, nil
}

func normalizeOptions(options Options) (Options, Result, error) {
	if options.Node == "" {
		return Options{}, Result{}, fmt.Errorf("node name is required")
	}
	if options.LocalDevice == "" {
		options.LocalDevice = "lo"
	}
	if options.Mode == "" {
		options.Mode = "local"
	}
	if options.UnderlayDevice == "" {
		options.UnderlayDevice = "eth0"
	}
	if options.WorkloadIF == "" {
		options.WorkloadIF = "eth0"
	}
	if !options.HostGateway.IsValid() {
		options.HostGateway = defaultIPv4HostGateway
	}
	if options.PolicyTableBase == 0 {
		options.PolicyTableBase = 10000
	}
	if options.PolicyTableSize == 0 {
		options.PolicyTableSize = 1024
	}
	return options, Result{Device: options.LocalDevice, Mode: options.Mode}, nil
}

func setIPv4Forwarding() error {
	writes := map[string]string{
		"/proc/sys/net/ipv4/ip_forward":             "1",
		"/proc/sys/net/ipv4/conf/all/rp_filter":     "0",
		"/proc/sys/net/ipv4/conf/default/rp_filter": "0",
		"/proc/sys/net/ipv6/conf/all/forwarding":    "1",
	}
	for path, value := range writes {
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

func applyPolicyRoutesNetlink(root *netlink.Handle, state control.DesiredState, options Options) (int, error) {
	localVPCs := localVPCSet(state.Endpoints, options.Node)
	routes := append([]model.PolicyRoute(nil), state.PolicyRoutes...)
	sortPolicyRoutes(routes)
	applicable, err := applicablePolicyRoutes(routes, localVPCs)
	if err != nil {
		return 0, err
	}

	needsUnderlay := false
	for _, route := range applicable {
		if route.Action.Type != model.ActionAllow {
			needsUnderlay = true
			break
		}
	}
	var underlay netlink.Link
	if needsUnderlay {
		underlay, err = root.LinkByName(options.UnderlayDevice)
	}
	if err != nil {
		return 0, fmt.Errorf("lookup policy route device %s: %w", options.UnderlayDevice, err)
	}
	applied := 0
	tables, err := allocatePolicyRouteTables(applicable, options)
	if err != nil {
		return 0, err
	}
	desiredRules := make([]*netlink.Rule, 0, len(applicable))
	desiredRoutes := make(map[int]*netlink.Route)
	for _, route := range applicable {
		table := linuxMainRouteTable
		if route.Action.Type != model.ActionAllow {
			table = tables[policyRouteTableKey(route)]
			desiredRoutes[table], err = policyRouteNetlinkRoute(route, table, underlay.Attrs().Index)
			if err != nil {
				return 0, fmt.Errorf("build policy route %s table %d: %w", route.Name, table, err)
			}
		}
		desiredRules = append(desiredRules, netlinkPolicyRules(route, linuxPolicyRulePriority(route.Priority), table)...)
		applied++
	}
	for table, route := range desiredRoutes {
		if err := syncPolicyRouteTable(root, table, route); err != nil {
			return 0, fmt.Errorf("sync policy route table %d: %w", table, err)
		}
	}
	if err := cleanupStalePolicyRouteTables(root, desiredRoutes, options); err != nil {
		return 0, err
	}
	if err := syncManagedPolicyRules(root, desiredRules, options); err != nil {
		return 0, err
	}
	return applied, nil
}

func applicablePolicyRoutes(routes []model.PolicyRoute, localVPCs map[string]struct{}) ([]model.PolicyRoute, error) {
	out := make([]model.PolicyRoute, 0, len(routes))
	for _, route := range routes {
		if _, ok := localVPCs[route.VPC]; !ok {
			continue
		}
		if err := route.Validate(); err != nil {
			return nil, fmt.Errorf("policy route %s: %w", route.Name, err)
		}
		out = append(out, route)
	}
	return out, nil
}

func sortPolicyRoutes(routes []model.PolicyRoute) {
	sort.SliceStable(routes, func(i, j int) bool {
		if routes[i].Priority != routes[j].Priority {
			return routes[i].Priority > routes[j].Priority
		}
		if routes[i].VPC != routes[j].VPC {
			return routes[i].VPC < routes[j].VPC
		}
		return routes[i].Name < routes[j].Name
	})
}

func allocatePolicyRouteTables(routes []model.PolicyRoute, options Options) (map[string]int, error) {
	out := make(map[string]int)
	used := make(map[int]string)
	for _, route := range routes {
		if route.Action.Type == model.ActionAllow {
			continue
		}
		key := policyRouteTableKey(route)
		if _, ok := out[key]; ok {
			return nil, fmt.Errorf("duplicate policy route name %q in vpc %q", route.Name, route.VPC)
		}
		if len(used) >= options.PolicyTableSize {
			return nil, fmt.Errorf("policy route table range exhausted: base=%d size=%d", options.PolicyTableBase, options.PolicyTableSize)
		}
		offset := policyRouteTableOffset(key, options.PolicyTableSize)
		for probe := 0; probe < options.PolicyTableSize; probe++ {
			table := options.PolicyTableBase + ((offset + probe) % options.PolicyTableSize)
			if _, ok := used[table]; ok {
				continue
			}
			used[table] = key
			out[key] = table
			break
		}
	}
	return out, nil
}

func policyRouteTableKey(route model.PolicyRoute) string {
	return route.VPC + "\x00" + route.Name
}

func policyRouteTableOffset(name string, size int) int {
	if size <= 1 {
		return 0
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(name))
	return int(hash.Sum32() % uint32(size))
}

func syncManagedPolicyRules(root *netlink.Handle, desired []*netlink.Rule, options Options) error {
	var existing []netlink.Rule
	for _, family := range netlinkPolicyRuleFamilies() {
		rules, err := root.RuleList(family)
		if err != nil {
			return fmt.Errorf("list policy rules family %d: %w", family, err)
		}
		existing = append(existing, rules...)
	}
	plan := planManagedPolicyRuleSync(existing, desired, options)
	for _, rule := range plan.Delete {
		ruleCopy := *rule
		if err := root.RuleDel(&ruleCopy); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("delete stale policy rule family %d table %d priority %d: %w", rule.Family, rule.Table, rule.Priority, err)
		}
	}
	for _, rule := range plan.Add {
		if err := root.RuleAdd(rule); err != nil && !errors.Is(err, os.ErrExist) && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("add policy rule table %d priority %d: %w", rule.Table, rule.Priority, err)
		}
	}
	return nil
}

type managedPolicyRuleSyncPlan struct {
	Add    []*netlink.Rule
	Delete []*netlink.Rule
}

func planManagedPolicyRuleSync(existing []netlink.Rule, desired []*netlink.Rule, options Options) managedPolicyRuleSyncPlan {
	desiredSet := make(map[string]*netlink.Rule, len(desired))
	for _, rule := range desired {
		desiredSet[policyRuleKey(*rule)] = rule
	}
	existingSet := make(map[string]struct{}, len(desired))
	var plan managedPolicyRuleSyncPlan
	for i := range existing {
		rule := existing[i]
		if !managedPolicyRule(rule, options) {
			continue
		}
		key := policyRuleKey(rule)
		if _, ok := desiredSet[key]; ok {
			existingSet[key] = struct{}{}
			continue
		}
		ruleCopy := rule
		plan.Delete = append(plan.Delete, &ruleCopy)
	}
	for key, rule := range desiredSet {
		if _, ok := existingSet[key]; ok {
			continue
		}
		plan.Add = append(plan.Add, rule)
	}
	sortPolicyRuleSyncPlan(&plan)
	return plan
}

func sortPolicyRuleSyncPlan(plan *managedPolicyRuleSyncPlan) {
	sort.SliceStable(plan.Add, func(i, j int) bool {
		return policyRuleKey(*plan.Add[i]) < policyRuleKey(*plan.Add[j])
	})
	sort.SliceStable(plan.Delete, func(i, j int) bool {
		return policyRuleKey(*plan.Delete[i]) < policyRuleKey(*plan.Delete[j])
	})
}

func netlinkPolicyRuleFamilies() []int {
	return []int{netlink.FAMILY_V4, netlink.FAMILY_V6}
}

func managedPolicyTable(table int, options Options) bool {
	return table >= options.PolicyTableBase && table < options.PolicyTableBase+options.PolicyTableSize
}

func managedPolicyRule(rule netlink.Rule, options Options) bool {
	return managedPolicyTable(rule.Table, options) || int(rule.Protocol) == linuxPolicyRuleProtocolID
}

func hasRemoteEndpoints(endpoints []model.Endpoint, node string) bool {
	for _, endpoint := range endpoints {
		if endpoint.Node != node {
			return true
		}
	}
	return false
}

func replaceRemoteEndpointRoute(handle *netlink.Handle, dst netip.Addr, gw netip.Addr, linkIndex int) error {
	route, err := remoteEndpointNetlinkRoute(dst, gw, linkIndex)
	if err != nil {
		return err
	}
	return handle.RouteReplace(route)
}

func remoteEndpointNetlinkRoute(dst netip.Addr, gw netip.Addr, linkIndex int) (*netlink.Route, error) {
	dstNet, err := ipNet(dst, addrPrefixBits(dst))
	if err != nil {
		return nil, err
	}
	route := &netlink.Route{
		Table:     linuxMainRouteTable,
		LinkIndex: linkIndex,
		Dst:       dstNet,
		Protocol:  linuxRemoteRouteProtocolID,
	}
	if gw.IsValid() {
		route.Gw = addrIP(gw)
	}
	return route, nil
}

func cleanupStaleRemoteRoutes(root *netlink.Handle, desired map[string]struct{}, linkIndex int) error {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := root.RouteListFiltered(family, &netlink.Route{
			Table:     linuxMainRouteTable,
			LinkIndex: linkIndex,
			Protocol:  linuxRemoteRouteProtocolID,
		}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF|netlink.RT_FILTER_PROTOCOL)
		if err != nil {
			return fmt.Errorf("list stale remote routes: %w", err)
		}
		for i := range routes {
			route := routes[i]
			if _, ok := desired[ipNetString(route.Dst)]; ok {
				continue
			}
			if err := root.RouteDel(&route); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("delete stale remote route %s: %w", ipNetString(route.Dst), err)
			}
		}
	}
	return nil
}

func cleanupStaleManagedAddrs(handle *netlink.Handle, link netlink.Link, desired map[string]struct{}) error {
	addrs, err := handle.AddrList(link, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	for i := range addrs {
		addr := addrs[i]
		key, ok := managedAddrKey(addr)
		if !ok {
			continue
		}
		if _, keep := desired[key]; keep {
			continue
		}
		if err := handle.AddrDel(link, &addr); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("delete stale address %s: %w", key, err)
		}
	}
	return nil
}

func ensureProviderNetworkLink(root *netlink.Handle, spec providerNetworkLinkSpec) (ProviderLinkStatus, error) {
	parent, err := root.LinkByName(spec.ParentDevice)
	if err != nil {
		return providerLinkFailureStatus(spec, "missing", "missing"), fmt.Errorf("lookup parent device %s: %w", spec.ParentDevice, err)
	}
	link, err := root.LinkByName(spec.Name)
	if err != nil {
		if !isLinkNotFound(err) {
			return providerLinkFailureStatusWithParent(spec, parent, "unknown"), err
		}
		if err := root.LinkAdd(&netlink.Vlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        spec.Name,
				ParentIndex: parent.Attrs().Index,
			},
			VlanId: int(spec.VLAN),
		}); err != nil && !errors.Is(err, os.ErrExist) && !errors.Is(err, unix.EEXIST) {
			return providerLinkFailureStatusWithParent(spec, parent, "create-failed"), fmt.Errorf("create vlan link %s: %w", spec.Name, err)
		}
		link, err = root.LinkByName(spec.Name)
		if err != nil {
			return providerLinkFailureStatusWithParent(spec, parent, "missing"), err
		}
	}
	vlan, ok := link.(*netlink.Vlan)
	if !ok {
		return providerLinkFailureStatusWithParent(spec, parent, "type-mismatch"), fmt.Errorf("link %s exists but is %T, want vlan", spec.Name, link)
	}
	if vlan.VlanId != int(spec.VLAN) {
		return providerLinkFailureStatusWithParent(spec, parent, "vlan-mismatch"), fmt.Errorf("link %s vlan id = %d, want %d", spec.Name, vlan.VlanId, spec.VLAN)
	}
	if link.Attrs().ParentIndex != parent.Attrs().Index {
		return providerLinkFailureStatusWithParent(spec, parent, "parent-mismatch"), fmt.Errorf("link %s parent index = %d, want %d", spec.Name, link.Attrs().ParentIndex, parent.Attrs().Index)
	}
	if err := root.LinkSetUp(link); err != nil {
		if providerLinkSetupCanDegrade(err) {
			return providerLinkStatus(root, spec)
		}
		return providerLinkFailureStatusWithParent(spec, parent, "setup-failed"), fmt.Errorf("set link %s up: %w", spec.Name, err)
	}
	return providerLinkStatus(root, spec)
}

func providerLinkStatus(root *netlink.Handle, spec providerNetworkLinkSpec) (ProviderLinkStatus, error) {
	parent, err := root.LinkByName(spec.ParentDevice)
	if err != nil {
		return providerLinkFailureStatus(spec, "missing", "missing"), fmt.Errorf("refresh parent device %s: %w", spec.ParentDevice, err)
	}
	link, err := root.LinkByName(spec.Name)
	if err != nil {
		return providerLinkFailureStatusWithParent(spec, parent, "missing"), fmt.Errorf("refresh provider link %s: %w", spec.Name, err)
	}
	return ProviderLinkStatus{
		ProviderNetwork: spec.ProviderNetwork,
		ParentDevice:    spec.ParentDevice,
		VLAN:            spec.VLAN,
		LinkName:        spec.Name,
		Ready:           providerOperStateReady(parent.Attrs().OperState) && providerOperStateReady(link.Attrs().OperState),
		ParentState:     operStateName(parent.Attrs().OperState),
		LinkState:       operStateName(link.Attrs().OperState),
	}, nil
}

func providerLinkFailureStatus(spec providerNetworkLinkSpec, parentState, linkState string) ProviderLinkStatus {
	return ProviderLinkStatus{
		ProviderNetwork: spec.ProviderNetwork,
		ParentDevice:    spec.ParentDevice,
		VLAN:            spec.VLAN,
		LinkName:        spec.Name,
		Ready:           false,
		ParentState:     parentState,
		LinkState:       linkState,
	}
}

func providerLinkFailureStatusWithParent(spec providerNetworkLinkSpec, parent netlink.Link, linkState string) ProviderLinkStatus {
	parentState := "unknown"
	if parent != nil && parent.Attrs() != nil {
		parentState = operStateName(parent.Attrs().OperState)
	}
	return providerLinkFailureStatus(spec, parentState, linkState)
}

func providerLinkSetupCanDegrade(err error) bool {
	return errors.Is(err, unix.ENETDOWN)
}

func operStateName(state netlink.LinkOperState) string {
	switch state {
	case netlink.OperUp:
		return "up"
	case netlink.OperDown:
		return "down"
	case netlink.OperLowerLayerDown:
		return "lower-down"
	case netlink.OperTesting:
		return "testing"
	case netlink.OperDormant:
		return "dormant"
	case netlink.OperNotPresent:
		return "not-present"
	case netlink.OperUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

func providerInventoryFromNetlink(links []netlink.Link) []ProviderInterface {
	out := make([]ProviderInterface, 0, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil || attrs.Name == "" {
			continue
		}
		out = append(out, ProviderInterface{
			Name:  attrs.Name,
			Ready: providerOperStateReady(attrs.OperState),
			State: operStateName(attrs.OperState),
		})
	}
	return out
}

func providerOperStateReady(state netlink.LinkOperState) bool {
	switch state {
	case netlink.OperDown, netlink.OperLowerLayerDown, netlink.OperNotPresent:
		return false
	default:
		return true
	}
}

func cleanupStaleProviderNetworkLinks(root *netlink.Handle, desired []providerNetworkLinkSpec) error {
	keep := make(map[string]struct{}, len(desired))
	for _, spec := range desired {
		keep[spec.Name] = struct{}{}
	}
	links, err := root.LinkList()
	if err != nil {
		return fmt.Errorf("list provider links: %w", err)
	}
	for _, link := range links {
		name := link.Attrs().Name
		if !strings.HasPrefix(name, providerLinkPrefix) {
			continue
		}
		if _, ok := keep[name]; ok {
			continue
		}
		if _, ok := link.(*netlink.Vlan); !ok {
			continue
		}
		if err := root.LinkDel(link); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("delete stale provider link %s: %w", name, err)
		}
	}
	return nil
}

func managedAddrKey(addr netlink.Addr) (string, bool) {
	if addr.IPNet == nil {
		return "", false
	}
	bits, maxBits := addr.IPNet.Mask.Size()
	if bits != maxBits || (maxBits != 32 && maxBits != 128) {
		return "", false
	}
	ip, ok := netip.AddrFromSlice(addr.IPNet.IP)
	if !ok {
		return "", false
	}
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() {
		return "", false
	}
	return endpointPrefix(ip), true
}

func cleanupStaleWorkloadRoutes(root *netlink.Handle, desired map[string]struct{}) error {
	linkNames := make(map[int]string)
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := root.RouteListFiltered(family, &netlink.Route{Table: linuxMainRouteTable}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return fmt.Errorf("list local workload routes: %w", err)
		}
		for i := range routes {
			route := routes[i]
			if route.Dst == nil || route.LinkIndex == 0 {
				continue
			}
			name, ok := linkNames[route.LinkIndex]
			if !ok {
				link, err := root.LinkByIndex(route.LinkIndex)
				if err != nil {
					if isLinkNotFound(err) {
						continue
					}
					return fmt.Errorf("lookup workload route link %d: %w", route.LinkIndex, err)
				}
				name = link.Attrs().Name
				linkNames[route.LinkIndex] = name
			}
			if !strings.HasPrefix(name, "nlh") {
				continue
			}
			key := ipNetString(route.Dst)
			if _, keep := desired[key]; keep {
				continue
			}
			if err := root.RouteDel(&route); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("delete stale workload route %s on %s: %w", key, name, err)
			}
		}
	}
	return nil
}

func policyRouteNetlinkRoute(route model.PolicyRoute, table, linkIndex int) (*netlink.Route, error) {
	dst, err := ipNetFromPrefix(linuxPolicyRouteDestination(route))
	if err != nil {
		return nil, err
	}
	nlRoute := &netlink.Route{Table: table, Dst: dst}
	if route.Action.Type == model.ActionDrop {
		nlRoute.Type = unix.RTN_BLACKHOLE
	} else {
		nextHops := route.Action.RerouteNextHops()
		if len(nextHops) == 1 {
			nlRoute.LinkIndex = linkIndex
			nlRoute.Gw = addrIP(nextHops[0])
		} else {
			nlRoute.MultiPath = make([]*netlink.NexthopInfo, 0, len(nextHops))
			for _, nextHop := range nextHops {
				nlRoute.MultiPath = append(nlRoute.MultiPath, &netlink.NexthopInfo{
					LinkIndex: linkIndex,
					Gw:        addrIP(nextHop),
				})
			}
		}
	}
	return nlRoute, nil
}

func syncPolicyRouteTable(root *netlink.Handle, table int, desired *netlink.Route) error {
	current, err := policyRouteTableRoutes(root, table)
	if err != nil {
		return err
	}
	for i := range current {
		route := current[i]
		if routeSameDestination(route, *desired) {
			continue
		}
		if err := root.RouteDel(&route); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, route := range current {
		if routeEquivalent(route, *desired) {
			return nil
		}
	}
	return root.RouteReplace(desired)
}

func cleanupStalePolicyRouteTables(root *netlink.Handle, desired map[int]*netlink.Route, options Options) error {
	for _, table := range managedPolicyTables(options) {
		if _, ok := desired[table]; ok {
			continue
		}
		routes, err := policyRouteTableRoutes(root, table)
		if err != nil {
			return fmt.Errorf("list stale policy route table %d: %w", table, err)
		}
		for i := range routes {
			route := routes[i]
			if err := root.RouteDel(&route); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("delete stale policy route table %d: %w", table, err)
			}
		}
	}
	return nil
}

func managedPolicyTables(options Options) []int {
	tables := make([]int, 0, options.PolicyTableSize)
	for table := options.PolicyTableBase; table < options.PolicyTableBase+options.PolicyTableSize; table++ {
		tables = append(tables, table)
	}
	return tables
}

func policyRouteTableRoutes(root *netlink.Handle, table int) ([]netlink.Route, error) {
	var out []netlink.Route
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := root.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return nil, err
		}
		out = append(out, routes...)
	}
	return out, nil
}

func netlinkPolicyRules(route model.PolicyRoute, priority, table int) []*netlink.Rule {
	srcPorts := route.Match.SrcPorts
	dstPorts := route.Match.DstPorts
	if len(srcPorts) == 0 {
		srcPorts = []model.PortRange{{}}
	}
	if len(dstPorts) == 0 {
		dstPorts = []model.PortRange{{}}
	}
	rules := make([]*netlink.Rule, 0, len(srcPorts)*len(dstPorts))
	for i := range srcPorts {
		for j := range dstPorts {
			var srcPort, dstPort *model.PortRange
			if len(route.Match.SrcPorts) > 0 {
				srcPort = &srcPorts[i]
			}
			if len(route.Match.DstPorts) > 0 {
				dstPort = &dstPorts[j]
			}
			rules = append(rules, netlinkPolicyRule(route, priority, table, srcPort, dstPort))
		}
	}
	return rules
}

func netlinkPolicyRule(route model.PolicyRoute, priority, table int, srcPort, dstPort *model.PortRange) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Priority = priority
	rule.Table = table
	rule.Family = policyRouteFamily(route)
	rule.Protocol = linuxPolicyRuleProtocolID
	if route.Match.Source.IsValid() {
		rule.Src, _ = ipNetFromPrefix(route.Match.Source)
	}
	if route.Match.Destination.IsValid() {
		rule.Dst, _ = ipNetFromPrefix(route.Match.Destination)
	}
	if proto := linuxPolicyRuleProtocolNumber(route.Match.Protocol, rule.Family); proto != 0 {
		rule.IPProto = proto
	}
	if srcPort != nil {
		rule.Sport = netlink.NewRulePortRange(srcPort.From, srcPort.To)
	}
	if dstPort != nil {
		rule.Dport = netlink.NewRulePortRange(dstPort.From, dstPort.To)
	}
	return rule
}

func policyRuleKey(rule netlink.Rule) string {
	parts := []string{
		fmt.Sprintf("priority=%d", rule.Priority),
		fmt.Sprintf("table=%d", rule.Table),
		fmt.Sprintf("family=%d", rule.Family),
		fmt.Sprintf("protocol=%d", rule.Protocol),
		fmt.Sprintf("ipproto=%d", rule.IPProto),
	}
	if rule.Src != nil {
		parts = append(parts, "src="+rule.Src.String())
	}
	if rule.Dst != nil {
		parts = append(parts, "dst="+rule.Dst.String())
	}
	if rule.Dport != nil {
		parts = append(parts, fmt.Sprintf("dport=%d-%d", rule.Dport.Start, rule.Dport.End))
	}
	if rule.Sport != nil {
		parts = append(parts, fmt.Sprintf("sport=%d-%d", rule.Sport.Start, rule.Sport.End))
	}
	return strings.Join(parts, "|")
}

func routeSameDestination(a, b netlink.Route) bool {
	return a.Table == b.Table && ipNetString(a.Dst) == ipNetString(b.Dst)
}

func routeEquivalent(a, b netlink.Route) bool {
	if !routeSameDestination(a, b) || a.Type != b.Type || a.LinkIndex != b.LinkIndex || !a.Gw.Equal(b.Gw) {
		return false
	}
	return nexthopSetKey(a.MultiPath) == nexthopSetKey(b.MultiPath)
}

func nexthopSetKey(nextHops []*netlink.NexthopInfo) string {
	if len(nextHops) == 0 {
		return ""
	}
	parts := make([]string, 0, len(nextHops))
	for _, nextHop := range nextHops {
		if nextHop == nil {
			parts = append(parts, "<nil>")
			continue
		}
		parts = append(parts, fmt.Sprintf("if=%d|gw=%s|hops=%d|flags=%d", nextHop.LinkIndex, nextHop.Gw.String(), nextHop.Hops, nextHop.Flags))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func ipNetString(value *net.IPNet) string {
	if value == nil {
		return ""
	}
	return value.String()
}

func policyRouteFamily(route model.PolicyRoute) int {
	if route.Match.Source.IsValid() {
		return ipRuleFamily(route.Match.Source.Addr())
	}
	if route.Match.Destination.IsValid() {
		return ipRuleFamily(route.Match.Destination.Addr())
	}
	for _, nextHop := range route.Action.RerouteNextHops() {
		if nextHop.IsValid() {
			return ipRuleFamily(nextHop)
		}
	}
	return unix.AF_INET
}

func ipRuleFamily(addr netip.Addr) int {
	if addr.Is6() {
		return unix.AF_INET6
	}
	return unix.AF_INET
}

func linuxPolicyRuleProtocolNumber(protocol model.Protocol, family int) int {
	switch protocol {
	case model.ProtocolTCP:
		return unix.IPPROTO_TCP
	case model.ProtocolUDP:
		return unix.IPPROTO_UDP
	case model.ProtocolICMP:
		if family == unix.AF_INET6 {
			return unix.IPPROTO_ICMPV6
		}
		return unix.IPPROTO_ICMP
	default:
		return 0
	}
}

func ensureNetNSWorkload(root *netlink.Handle, endpointID string, ip netip.Addr, workloadIF string, hostGateway netip.Addr, prefix string) error {
	nsName := netnsName(endpointID, prefix)
	nsHandle, err := ensureNamedNetNS(nsName)
	if err != nil {
		return err
	}
	defer nsHandle.Close()

	nsLinkExists, err := linkExistsInNS(nsHandle, workloadIF)
	if err != nil {
		return err
	}
	hostVeth := HostVethName(endpointID)
	peerVeth := peerVethName(endpointID)
	hostLink, hostErr := root.LinkByName(hostVeth)
	if !nsLinkExists && isLinkNotFound(hostErr) {
		if err := root.LinkAdd(&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: hostVeth},
			PeerName:  peerVeth,
		}); err != nil {
			return fmt.Errorf("create veth %s/%s: %w", hostVeth, peerVeth, err)
		}
		peer, err := root.LinkByName(peerVeth)
		if err != nil {
			return fmt.Errorf("lookup peer veth %s: %w", peerVeth, err)
		}
		if err := root.LinkSetNsFd(peer, int(nsHandle)); err != nil {
			return fmt.Errorf("move %s to netns %s: %w", peerVeth, nsName, err)
		}
		ns, err := netlink.NewHandleAt(nsHandle)
		if err != nil {
			return err
		}
		defer ns.Close()
		moved, err := ns.LinkByName(peerVeth)
		if err != nil {
			return fmt.Errorf("lookup moved peer %s: %w", peerVeth, err)
		}
		if peerVeth != workloadIF {
			if err := ns.LinkSetName(moved, workloadIF); err != nil {
				return fmt.Errorf("rename %s to %s: %w", peerVeth, workloadIF, err)
			}
		}
	} else if hostErr != nil && !isLinkNotFound(hostErr) {
		return fmt.Errorf("lookup host veth %s: %w", hostVeth, hostErr)
	}

	hostLink, err = root.LinkByName(hostVeth)
	if err != nil {
		return fmt.Errorf("lookup host veth %s: %w", hostVeth, err)
	}
	if err := replaceAddr(root, hostLink, hostGateway, addrPrefixBits(hostGateway)); err != nil {
		return fmt.Errorf("assign host gateway %s: %w", hostGateway, err)
	}
	if err := root.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("set host veth %s up: %w", hostVeth, err)
	}
	if err := replaceRoute(root, ip, addrPrefixBits(ip), netip.Addr{}, hostLink.Attrs().Index, 0); err != nil {
		return fmt.Errorf("route workload %s: %w", ip, err)
	}

	ns, err := netlink.NewHandleAt(nsHandle)
	if err != nil {
		return err
	}
	defer ns.Close()
	if lo, err := ns.LinkByName("lo"); err == nil {
		if err := ns.LinkSetUp(lo); err != nil {
			return fmt.Errorf("set lo up in %s: %w", nsName, err)
		}
	}
	workload, err := ns.LinkByName(workloadIF)
	if err != nil {
		return fmt.Errorf("lookup workload iface %s in %s: %w", workloadIF, nsName, err)
	}
	if err := cleanupStaleManagedAddrs(ns, workload, map[string]struct{}{endpointPrefix(ip): struct{}{}}); err != nil {
		return fmt.Errorf("cleanup stale workload addresses in %s: %w", nsName, err)
	}
	if err := replaceAddr(ns, workload, ip, addrPrefixBits(ip)); err != nil {
		return fmt.Errorf("assign workload ip %s: %w", ip, err)
	}
	if err := ns.LinkSetUp(workload); err != nil {
		return fmt.Errorf("set workload iface %s up: %w", workloadIF, err)
	}
	if err := replaceRoute(ns, netip.Addr{}, 0, hostGateway, workload.Attrs().Index, unix.RTNH_F_ONLINK); err != nil {
		return fmt.Errorf("set default route via %s: %w", hostGateway, err)
	}
	return nil
}

func ensureNamedNetNS(name string) (netns.NsHandle, error) {
	nsHandle, err := netns.GetFromName(name)
	if err == nil {
		return nsHandle, nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		return netns.None(), err
	}
	defer orig.Close()
	nsHandle, err = netns.NewNamed(name)
	if err != nil {
		return netns.None(), err
	}
	if err := netns.Set(orig); err != nil {
		_ = nsHandle.Close()
		return netns.None(), err
	}
	return nsHandle, nil
}

func cleanupStaleNamespaces(state control.DesiredState, node, prefix string) error {
	keep := make(map[string]struct{})
	for _, endpoint := range state.Endpoints {
		if endpoint.Node == node {
			keep[netnsName(model.EndpointKey(endpoint.VPC, endpoint.ID), prefix)] = struct{}{}
		}
	}
	names, err := listManagedNetNS(prefix)
	if err != nil {
		return err
	}
	for _, name := range names {
		if _, ok := keep[name]; ok {
			continue
		}
		if err := netns.DeleteNamed(name); err != nil {
			return fmt.Errorf("delete stale netns %s: %w", name, err)
		}
	}
	return nil
}

func listManagedNetNS(prefix string) ([]string, error) {
	return listManagedNetNSAt(netnsRunDir, prefix)
}

func listManagedNetNSAt(dir, prefix string) ([]string, error) {
	if prefix == "" {
		prefix = "nl"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	matchPrefix := netnsName("", prefix)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, matchPrefix) {
			out = append(out, name)
		}
	}
	return out, nil
}

func linkExistsInNS(nsHandle netns.NsHandle, ifName string) (bool, error) {
	ns, err := netlink.NewHandleAt(nsHandle)
	if err != nil {
		return false, err
	}
	defer ns.Close()
	_, err = ns.LinkByName(ifName)
	if err == nil {
		return true, nil
	}
	if isLinkNotFound(err) {
		return false, nil
	}
	return false, err
}

func replaceAddr(handle *netlink.Handle, link netlink.Link, addr netip.Addr, bits int) error {
	ipNet, err := ipNet(addr, bits)
	if err != nil {
		return err
	}
	nlAddr := &netlink.Addr{IPNet: ipNet}
	if addr.Is6() {
		nlAddr.Flags = unix.IFA_F_NODAD
	}
	return handle.AddrReplace(link, nlAddr)
}

func replaceRoute(handle *netlink.Handle, dst netip.Addr, bits int, gw netip.Addr, linkIndex int, flags int) error {
	var dstNet *net.IPNet
	var err error
	if dst.IsValid() {
		dstNet, err = ipNet(dst, bits)
		if err != nil {
			return err
		}
	}
	route := &netlink.Route{LinkIndex: linkIndex, Dst: dstNet, Flags: flags}
	if gw.IsValid() {
		route.Gw = addrIP(gw)
	}
	return handle.RouteReplace(route)
}

func ipNet(addr netip.Addr, bits int) (*net.IPNet, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("invalid ip address")
	}
	maxBits := 32
	if addr.Is6() {
		maxBits = 128
	}
	return &net.IPNet{IP: addrIP(addr), Mask: net.CIDRMask(bits, maxBits)}, nil
}

func ipNetFromPrefix(prefix netip.Prefix) (*net.IPNet, error) {
	if !prefix.IsValid() {
		return nil, fmt.Errorf("invalid ip prefix")
	}
	return ipNet(prefix.Addr(), prefix.Bits())
}

func addrIP(addr netip.Addr) net.IP {
	if addr.Is4() {
		raw := addr.As4()
		return net.IPv4(raw[0], raw[1], raw[2], raw[3])
	}
	raw := addr.As16()
	return net.IP(raw[:])
}

func isLinkNotFound(err error) bool {
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound)
}
