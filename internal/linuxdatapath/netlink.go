package linuxdatapath

import (
	"context"
	"errors"
	"fmt"
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

	localLink, err := root.LinkByName(options.LocalDevice)
	if err != nil {
		return Result{}, fmt.Errorf("lookup local device %s: %w", options.LocalDevice, err)
	}
	if err := root.LinkSetUp(localLink); err != nil {
		return Result{}, fmt.Errorf("set %s up: %w", options.LocalDevice, err)
	}
	for _, endpoint := range state.Endpoints {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if endpoint.Node == options.Node {
			if err := replaceAddr(root, localLink, endpoint.IP, addrPrefixBits(endpoint.IP)); err != nil {
				return Result{}, fmt.Errorf("assign %s to %s: %w", endpoint.IP, options.LocalDevice, err)
			}
			result.LocalAddresses++
			continue
		}
		nextHop, err := resolveNode(ctx, endpoint.Node, options.NodeUnderlays)
		if err != nil {
			return Result{}, fmt.Errorf("resolve underlay for node %s: %w", endpoint.Node, err)
		}
		underlay, err := root.LinkByName(options.UnderlayDevice)
		if err != nil {
			return Result{}, fmt.Errorf("lookup underlay device %s: %w", options.UnderlayDevice, err)
		}
		if err := replaceRoute(root, endpoint.IP, addrPrefixBits(endpoint.IP), nextHop, underlay.Attrs().Index, 0); err != nil {
			return Result{}, fmt.Errorf("route %s via %s: %w", endpoint.IP, nextHop, err)
		}
		result.RemoteRoutes++
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

	if options.CleanupStale {
		if err := cleanupStaleNamespaces(state, options.Node, options.NetNSPrefix); err != nil {
			return Result{}, err
		}
	}
	for _, endpoint := range state.Endpoints {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if endpoint.Node == options.Node {
			if err := ensureNetNSWorkload(root, endpoint.ID, endpoint.IP, options.WorkloadIF, options.HostGateway, options.NetNSPrefix); err != nil {
				return Result{}, fmt.Errorf("ensure workload %s: %w", endpoint.ID, err)
			}
			result.LocalAddresses++
			continue
		}
		nextHop, err := resolveNode(ctx, endpoint.Node, options.NodeUnderlays)
		if err != nil {
			return Result{}, fmt.Errorf("resolve underlay for node %s: %w", endpoint.Node, err)
		}
		underlay, err := root.LinkByName(options.UnderlayDevice)
		if err != nil {
			return Result{}, fmt.Errorf("lookup underlay device %s: %w", options.UnderlayDevice, err)
		}
		if err := replaceRoute(root, endpoint.IP, addrPrefixBits(endpoint.IP), nextHop, underlay.Attrs().Index, 0); err != nil {
			return Result{}, fmt.Errorf("route %s via %s: %w", endpoint.IP, nextHop, err)
		}
		result.RemoteRoutes++
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
		options.HostGateway = netip.MustParseAddr("169.254.1.1")
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
	if err := cleanupManagedPolicyRules(root, options); err != nil {
		return 0, err
	}

	applied := 0
	tableOffset := 0
	for _, route := range applicable {
		table := linuxMainRouteTable
		if route.Action.Type != model.ActionAllow {
			table = options.PolicyTableBase + tableOffset
			tableOffset++
			if err := flushPolicyRouteTable(root, table); err != nil {
				return 0, fmt.Errorf("flush policy route table %d: %w", table, err)
			}
			if err := replacePolicyRoute(root, route, table, underlay.Attrs().Index); err != nil {
				return 0, fmt.Errorf("replace policy route %s table %d: %w", route.Name, table, err)
			}
		}
		for _, rule := range netlinkPolicyRules(route, linuxPolicyRulePriority(route.Priority), table) {
			if err := root.RuleAdd(rule); err != nil {
				return 0, fmt.Errorf("add policy rule %s: %w", route.Name, err)
			}
		}
		applied++
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
		return routes[i].Name < routes[j].Name
	})
}

func cleanupManagedPolicyRules(root *netlink.Handle, options Options) error {
	for _, family := range netlinkPolicyRuleFamilies() {
		rules, err := root.RuleList(family)
		if err != nil {
			return fmt.Errorf("list policy rules family %d: %w", family, err)
		}
		for _, rule := range rules {
			if !managedPolicyRule(rule, options) {
				continue
			}
			ruleCopy := rule
			if err := root.RuleDel(&ruleCopy); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("delete stale policy rule family %d table %d priority %d: %w", family, rule.Table, rule.Priority, err)
			}
		}
	}
	return nil
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

func flushPolicyRouteTable(root *netlink.Handle, table int) error {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := root.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for i := range routes {
			route := routes[i]
			if err := root.RouteDel(&route); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func replacePolicyRoute(root *netlink.Handle, route model.PolicyRoute, table, linkIndex int) error {
	dst, err := ipNetFromPrefix(linuxPolicyRouteDestination(route))
	if err != nil {
		return err
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
	return root.RouteReplace(nlRoute)
}

func netlinkPolicyRules(route model.PolicyRoute, priority, table int) []*netlink.Rule {
	if len(route.Match.DstPorts) == 0 {
		return []*netlink.Rule{netlinkPolicyRule(route, priority, table, nil)}
	}
	rules := make([]*netlink.Rule, 0, len(route.Match.DstPorts))
	for i := range route.Match.DstPorts {
		rules = append(rules, netlinkPolicyRule(route, priority, table, &route.Match.DstPorts[i]))
	}
	return rules
}

func netlinkPolicyRule(route model.PolicyRoute, priority, table int, port *model.PortRange) *netlink.Rule {
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
	if port != nil {
		rule.Dport = netlink.NewRulePortRange(port.From, port.To)
	}
	return rule
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
			keep[netnsName(endpoint.ID, prefix)] = struct{}{}
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
	return handle.AddrReplace(link, &netlink.Addr{IPNet: ipNet})
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
