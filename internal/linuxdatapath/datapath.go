package linuxdatapath

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/model"
)

type Operation struct {
	Command string
	Args    []string
}

type Executor interface {
	Execute(ctx context.Context, op Operation) error
}

type Options struct {
	Node            string
	Mode            string
	Backend         string
	LocalDevice     string
	UnderlayDevice  string
	NodeUnderlays   map[string][]netip.Addr
	ProviderLinks   map[string]string
	NetNSPrefix     string
	WorkloadIF      string
	HostGateway     netip.Addr
	PolicyTableBase int
	PolicyTableSize int
	CleanupStale    bool
	Executor        Executor
}

type Result struct {
	LocalAddresses   int
	RemoteRoutes     int
	PolicyRoutes     int
	ProviderNetworks int
	ProviderLinks    int
	Device           string
	Mode             string
	CleanupPlanned   bool
}

type CommandExecutor struct{}

const (
	linuxMainRouteTable        = 254
	linuxPolicyRuleProtocolID  = 186
	linuxRemoteRouteProtocolID = 187
	providerLinkPrefix         = "nlv"
)

var (
	defaultIPv4HostGateway = netip.MustParseAddr("169.254.1.1")
	defaultIPv6HostGateway = netip.MustParseAddr("fd00::1")
)

func (CommandExecutor) Execute(ctx context.Context, op Operation) error {
	cmd := exec.CommandContext(ctx, op.Command, op.Args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", op.Command, strings.Join(op.Args, " "), err, output)
	}
	return nil
}

func Apply(ctx context.Context, state control.DesiredState, options Options) (Result, error) {
	switch datapathBackend(options.Backend) {
	case "netlink":
		return ApplyNetlink(ctx, state, options)
	case "command":
	default:
		return Result{}, fmt.Errorf("unsupported linux datapath backend %q", options.Backend)
	}
	ops, result, err := Plan(ctx, state, options)
	if err != nil {
		return Result{}, err
	}
	executor := options.Executor
	if executor == nil {
		executor = CommandExecutor{}
	}
	for _, op := range ops {
		if err := executor.Execute(ctx, op); err != nil {
			return Result{}, err
		}
	}
	return result, nil
}

func datapathBackend(backend string) string {
	if backend == "" {
		return "netlink"
	}
	return backend
}

func Plan(ctx context.Context, state control.DesiredState, options Options) ([]Operation, Result, error) {
	if options.Node == "" {
		return nil, Result{}, fmt.Errorf("node name is required")
	}
	localDevice := options.LocalDevice
	if localDevice == "" {
		localDevice = "lo"
	}
	mode := options.Mode
	if mode == "" {
		mode = "local"
	}
	underlayDevice := options.UnderlayDevice
	if underlayDevice == "" {
		underlayDevice = "eth0"
	}
	workloadIF := options.WorkloadIF
	if workloadIF == "" {
		workloadIF = "eth0"
	}
	hostGateway := options.HostGateway
	policyTableBase := options.PolicyTableBase
	if policyTableBase == 0 {
		policyTableBase = 10000
	}
	policyTableSize := options.PolicyTableSize
	if policyTableSize == 0 {
		policyTableSize = 1024
	}

	result := Result{Device: localDevice, Mode: mode, CleanupPlanned: options.CleanupStale}
	var ops []Operation
	providerSpecs, err := desiredProviderNetworkLinkSpecs(state, options.Node, options.ProviderLinks)
	if err != nil {
		return nil, Result{}, err
	}
	result.ProviderNetworks, result.ProviderLinks = summarizeProviderNetworkSpecs(providerSpecs)
	ops = append(ops, planProviderNetworkLinks(providerSpecs)...)
	if options.CleanupStale {
		ops = append(ops, planProviderNetworkLinkCleanup(providerSpecs))
	}
	if mode == "local" {
		ops = append(ops, Operation{Command: "ip", Args: []string{"link", "set", localDevice, "up"}})
	}
	if mode == "netns" {
		result.Device = "netns"
		ops = append(ops,
			shellOperation("sysctl -w net.ipv4.ip_forward=1 >/dev/null"),
			shellOperation("sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null"),
			shellOperation("sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null"),
			shellOperation("sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null"),
		)
		if options.CleanupStale {
			ops = append(ops, planNetNSCleanup(state, options.Node, options.NetNSPrefix))
		}
	}
	for _, endpoint := range state.Endpoints {
		if endpoint.Node == options.Node {
			if mode == "netns" {
				ops = append(ops, planNetNSWorkload(model.EndpointKey(endpoint.VPC, endpoint.ID), endpoint.IP, workloadIF, workloadHostGateway(endpoint.IP, hostGateway), options.NetNSPrefix)...)
			} else {
				ops = append(ops, Operation{
					Command: "ip",
					Args:    []string{"addr", "replace", endpoint.IP.String() + "/" + strconv.Itoa(addrPrefixBits(endpoint.IP)), "dev", localDevice},
				})
			}
			result.LocalAddresses++
			continue
		}
		prefix := endpoint.IP.String() + "/" + strconv.Itoa(addrPrefixBits(endpoint.IP))
		nextHop, err := resolveNode(ctx, endpoint.Node, endpoint.IP, options.NodeUnderlays)
		if err != nil {
			return nil, Result{}, fmt.Errorf("resolve underlay for node %s: %w", endpoint.Node, err)
		}
		ops = append(ops, Operation{
			Command: "ip",
			Args:    []string{"route", "replace", prefix, "via", nextHop.String(), "dev", underlayDevice, "proto", strconv.Itoa(linuxRemoteRouteProtocolID)},
		})
		result.RemoteRoutes++
	}
	if options.CleanupStale && mode == "local" && localDevice != "lo" {
		ops = append(ops, planLocalAddressCleanup(state, options.Node, localDevice))
	}
	if options.CleanupStale {
		ops = append(ops, planRemoteRouteCleanup(state, options.Node, underlayDevice))
	}
	if options.CleanupStale && mode == "netns" {
		ops = append(ops, planNetNSLocalRouteCleanup(state, options.Node))
	}
	policyOps, policyRoutes, err := planPolicyRoutes(state, options.Node, underlayDevice, policyTableBase, policyTableSize, options.CleanupStale)
	if err != nil {
		return nil, Result{}, err
	}
	ops = append(ops, policyOps...)
	result.PolicyRoutes = policyRoutes
	return ops, result, nil
}

type providerNetworkLinkSpec struct {
	ProviderNetwork string
	ParentDevice    string
	VLAN            uint16
	Name            string
}

func desiredProviderNetworkLinkSpecs(state control.DesiredState, node string, mappings map[string]string) ([]providerNetworkLinkSpec, error) {
	subnets := make(map[string]model.Subnet, len(state.Subnets))
	for _, subnet := range state.Subnets {
		subnets[subnetStateKey(subnet.VPC, subnet.Name)] = subnet
	}
	nodeMappings := providerLinkMappingsForNode(state.ProviderNetworks, node, mappings)
	seen := make(map[string]providerNetworkLinkSpec)
	claimedLinks := make(map[string]providerNetworkLinkSpec)
	for _, endpoint := range state.Endpoints {
		if endpoint.Node != node {
			continue
		}
		subnet, ok := subnets[subnetStateKey(endpoint.VPC, endpoint.Subnet)]
		if !ok || subnet.ProviderNetwork == "" || subnet.VLAN == 0 {
			continue
		}
		parent := nodeMappings[subnet.ProviderNetwork]
		if parent == "" {
			return nil, fmt.Errorf("provider network %q requires parent device mapping on node %q", subnet.ProviderNetwork, node)
		}
		spec := providerNetworkLinkSpec{
			ProviderNetwork: subnet.ProviderNetwork,
			ParentDevice:    parent,
			VLAN:            subnet.VLAN,
			Name:            providerNetworkLinkName(subnet.ProviderNetwork, parent, subnet.VLAN),
		}
		linkKey := parent + "|" + strconv.Itoa(int(spec.VLAN))
		if claimed, ok := claimedLinks[linkKey]; ok && claimed.ProviderNetwork != spec.ProviderNetwork {
			return nil, fmt.Errorf("provider networks %q and %q both require parent %s vlan %d", claimed.ProviderNetwork, spec.ProviderNetwork, parent, spec.VLAN)
		}
		claimedLinks[linkKey] = spec
		seen[providerNetworkLinkKey(spec)] = spec
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	specs := make([]providerNetworkLinkSpec, 0, len(keys))
	for _, key := range keys {
		specs = append(specs, seen[key])
	}
	return specs, nil
}

func providerLinkMappingsForNode(providerNetworks []model.ProviderNetwork, node string, fallback map[string]string) map[string]string {
	mappings := make(map[string]string, len(fallback)+len(providerNetworks))
	for name, device := range fallback {
		mappings[name] = device
	}
	for _, providerNetwork := range providerNetworks {
		for _, providerNode := range providerNetwork.Nodes {
			if providerNode.Node != node {
				continue
			}
			mappings[providerNetwork.Name] = providerNode.Interface
			break
		}
	}
	return mappings
}

func summarizeProviderNetworkSpecs(specs []providerNetworkLinkSpec) (int, int) {
	uniqueNetworks := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		uniqueNetworks[spec.ProviderNetwork] = struct{}{}
	}
	return len(uniqueNetworks), len(specs)
}

func providerNetworkLinkKey(spec providerNetworkLinkSpec) string {
	return spec.ProviderNetwork + "|" + spec.ParentDevice + "|" + strconv.Itoa(int(spec.VLAN))
}

func providerNetworkLinkName(providerNetwork, parent string, vlan uint16) string {
	return shortName(providerLinkPrefix, providerNetwork+"|"+parent+"|"+strconv.Itoa(int(vlan)))
}

func planProviderNetworkLinks(specs []providerNetworkLinkSpec) []Operation {
	ops := make([]Operation, 0, len(specs)*2)
	for _, spec := range specs {
		ops = append(ops,
			shellOperation("ip link show "+spec.Name+" >/dev/null 2>&1 || ip link add link "+spec.ParentDevice+" name "+spec.Name+" type vlan id "+strconv.Itoa(int(spec.VLAN))),
			Operation{Command: "ip", Args: []string{"link", "set", spec.Name, "up"}},
		)
	}
	return ops
}

func planProviderNetworkLinkCleanup(specs []providerNetworkLinkSpec) Operation {
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.Name)
	}
	return shellOperation("for link in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep '^" + providerLinkPrefix + "' || true); do case '" + keepSet(names) + "' in *\" $link \"*) ;; *) ip link del \"$link\" 2>/dev/null || true ;; esac; done")
}

func planPolicyRoutes(state control.DesiredState, node, device string, tableBase, tableSize int, cleanup bool) ([]Operation, int, error) {
	localVPCs := localVPCSet(state.Endpoints, node)
	routes := append([]model.PolicyRoute(nil), state.PolicyRoutes...)
	sortPolicyRoutes(routes)
	applicable, err := applicablePolicyRoutes(routes, localVPCs)
	if err != nil {
		return nil, 0, err
	}

	var ops []Operation
	if cleanup {
		ops = append(ops, planPolicyRouteCleanup(tableBase, tableSize))
	}
	if len(applicable) == 0 {
		return ops, 0, nil
	}
	tables, err := allocatePolicyRouteTables(applicable, Options{PolicyTableBase: tableBase, PolicyTableSize: tableSize})
	if err != nil {
		return nil, 0, err
	}
	applied := 0
	for _, route := range applicable {
		table := linuxMainRouteTable
		rulePriority := linuxPolicyRulePriority(route.Priority)
		if route.Action.Type != model.ActionAllow {
			table = tables[policyRouteTableKey(route)]
			destination := linuxPolicyRouteDestination(route)
			if route.Action.Type == model.ActionDrop {
				ops = append(ops, Operation{
					Command: "ip",
					Args:    []string{"route", "replace", "blackhole", destination.String(), "table", strconv.Itoa(table)},
				})
			} else {
				nextHops := route.Action.RerouteNextHops()
				args := []string{"route", "replace", destination.String()}
				if len(nextHops) == 1 {
					args = append(args, "via", nextHops[0].String(), "dev", device)
				} else {
					for _, nextHop := range nextHops {
						args = append(args, "nexthop", "via", nextHop.String(), "dev", device)
					}
				}
				args = append(args, "table", strconv.Itoa(table))
				ops = append(ops, Operation{
					Command: "ip",
					Args:    args,
				})
			}
		}
		for _, ruleArgs := range linuxPolicyRuleArgs(route, rulePriority, table) {
			ops = append(ops, shellOperation("ip rule del "+ruleArgs+" 2>/dev/null || true; ip rule add "+ruleArgs))
		}
		applied++
	}
	return ops, applied, nil
}

func planPolicyRouteCleanup(tableBase, tableSize int) Operation {
	start := strconv.Itoa(tableBase)
	end := strconv.Itoa(tableBase + tableSize)
	protocol := strconv.Itoa(linuxPolicyRuleProtocolID)
	return shellOperation(
		"ip rule show | awk -v start=" + start + " -v end=" + end + " -v proto=" + protocol + " '{ managed=0; for (i=1; i<=NF; i++) { if (($i == \"lookup\" || $i == \"table\") && $(i+1) >= start && $(i+1) < end) managed=1; if (($i == \"proto\" || $i == \"protocol\") && $(i+1) == proto) managed=1 } if (managed) print }' | while read -r rule; do priority=${rule%%:*}; table=$(printf '%s\\n' \"$rule\" | awk '{ for (i=1; i<=NF; i++) if (($i == \"lookup\" || $i == \"table\")) { print $(i+1); exit } }'); ip rule del priority \"$priority\" table \"$table\" 2>/dev/null || true; done; " +
			"for family in '' '-6'; do table=" + start + "; while [ \"$table\" -lt " + end + " ]; do ip $family route flush table \"$table\" 2>/dev/null || true; table=$((table+1)); done; done",
	)
}

func planRemoteRouteCleanup(state control.DesiredState, node, device string) Operation {
	keep := keepSet(remoteEndpointPrefixes(state, node))
	protocol := strconv.Itoa(linuxRemoteRouteProtocolID)
	script := "for family in '' '-6'; do ip $family -o route show proto " + protocol + " dev " + device + " 2>/dev/null | awk '{print $1}' | while read -r dst; do case '" + keep + "' in *\" $dst \"*) ;; *) ip $family route del \"$dst\" dev " + device + " proto " + protocol + " 2>/dev/null || true ;; esac; done; done"
	return shellOperation(script)
}

func planLocalAddressCleanup(state control.DesiredState, node, device string) Operation {
	keep := keepSet(localEndpointPrefixes(state, node))
	script := "for family in '' '-6'; do ip $family -o addr show dev " + device + " 2>/dev/null | awk '{print $4}' | while read -r addr; do case \"$addr\" in 127.0.0.1/8|::1/128) continue ;; esac; case \"$addr\" in */32|*/128) : ;; *) continue ;; esac; case '" + keep + "' in *\" $addr \"*) ;; *) ip $family addr del \"$addr\" dev " + device + " 2>/dev/null || true ;; esac; done; done"
	return shellOperation(script)
}

func planNetNSLocalRouteCleanup(state control.DesiredState, node string) Operation {
	keep := keepSet(localEndpointPrefixes(state, node))
	script := "for family in '' '-6'; do ip $family -o route show table main 2>/dev/null | awk '{ dst=$1; dev=\"\"; for (i=1; i<=NF; i++) if ($i == \"dev\") { dev=$(i+1); break } if (dev ~ /^nlh/) print dst, dev }' | while read -r dst dev; do case '" + keep + "' in *\" $dst \"*) ;; *) ip $family route del \"$dst\" dev \"$dev\" 2>/dev/null || true ;; esac; done; done"
	return shellOperation(script)
}

func remoteEndpointPrefixes(state control.DesiredState, node string) []string {
	var prefixes []string
	for _, endpoint := range state.Endpoints {
		if endpoint.Node == node {
			continue
		}
		prefixes = append(prefixes, endpointPrefix(endpoint.IP))
	}
	return prefixes
}

func subnetStateKey(vpc, subnet string) string {
	return vpc + "\x00" + subnet
}

func localEndpointPrefixes(state control.DesiredState, node string) []string {
	var prefixes []string
	for _, endpoint := range state.Endpoints {
		if endpoint.Node != node {
			continue
		}
		prefixes = append(prefixes, endpointPrefix(endpoint.IP))
	}
	return prefixes
}

func endpointPrefix(ip netip.Addr) string {
	return ip.String() + "/" + strconv.Itoa(addrPrefixBits(ip))
}

func localVPCSet(endpoints []model.Endpoint, node string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, endpoint := range endpoints {
		if endpoint.Node == node {
			out[endpoint.VPC] = struct{}{}
		}
	}
	return out
}

func linuxPolicyRouteDestination(route model.PolicyRoute) netip.Prefix {
	if route.Match.Destination.IsValid() {
		return route.Match.Destination
	}
	if route.Match.Source.IsValid() && route.Match.Source.Addr().Is6() {
		return netip.MustParsePrefix("::/0")
	}
	return netip.MustParsePrefix("0.0.0.0/0")
}

func linuxPolicyRulePriority(priority int) int {
	out := 10000 - priority
	if out < 1 {
		return 1
	}
	return out
}

func linuxPolicyRuleArgs(route model.PolicyRoute, priority, table int) []string {
	srcPorts := route.Match.SrcPorts
	dstPorts := route.Match.DstPorts
	if len(srcPorts) == 0 {
		srcPorts = []model.PortRange{{}}
	}
	if len(dstPorts) == 0 {
		dstPorts = []model.PortRange{{}}
	}
	args := make([]string, 0, len(srcPorts)*len(dstPorts))
	for i := range srcPorts {
		for j := range dstPorts {
			var srcPort, dstPort *model.PortRange
			if len(route.Match.SrcPorts) > 0 {
				srcPort = &srcPorts[i]
			}
			if len(route.Match.DstPorts) > 0 {
				dstPort = &dstPorts[j]
			}
			args = append(args, linuxPolicyRuleArgsForPort(route, priority, table, srcPort, dstPort))
		}
	}
	return args
}

func linuxPolicyRuleArgsForPort(route model.PolicyRoute, priority, table int, srcPort, dstPort *model.PortRange) string {
	args := []string{"priority", strconv.Itoa(priority)}
	if route.Match.Source.IsValid() {
		args = append(args, "from", route.Match.Source.String())
	}
	if route.Match.Destination.IsValid() {
		args = append(args, "to", route.Match.Destination.String())
	}
	if protocol := linuxPolicyRuleProtocol(route.Match.Protocol, routeIPFamily(route)); protocol != "" {
		args = append(args, "ipproto", protocol)
	}
	if srcPort != nil {
		args = append(args, "sport", linuxPolicyRulePort(*srcPort))
	}
	if dstPort != nil {
		args = append(args, "dport", linuxPolicyRulePort(*dstPort))
	}
	args = append(args, "table", strconv.Itoa(table), "protocol", strconv.Itoa(linuxPolicyRuleProtocolID))
	return strings.Join(args, " ")
}

func routeIPFamily(route model.PolicyRoute) int {
	if route.Match.Source.IsValid() && route.Match.Source.Addr().Is6() {
		return 6
	}
	if route.Match.Destination.IsValid() && route.Match.Destination.Addr().Is6() {
		return 6
	}
	for _, nextHop := range route.Action.RerouteNextHops() {
		if nextHop.Is6() {
			return 6
		}
	}
	return 4
}

func linuxPolicyRuleProtocol(protocol model.Protocol, family int) string {
	switch protocol {
	case "", model.ProtocolAny:
		return ""
	case model.ProtocolTCP:
		return "tcp"
	case model.ProtocolUDP:
		return "udp"
	case model.ProtocolICMP:
		if family == 6 {
			return "ipv6-icmp"
		}
		return "icmp"
	default:
		return string(protocol)
	}
}

func linuxPolicyRulePort(port model.PortRange) string {
	if port.From == port.To {
		return strconv.Itoa(int(port.From))
	}
	return strconv.Itoa(int(port.From)) + "-" + strconv.Itoa(int(port.To))
}

func planNetNSCleanup(state control.DesiredState, node, prefix string) Operation {
	var keep []string
	for _, endpoint := range state.Endpoints {
		if endpoint.Node == node {
			keep = append(keep, netnsName(model.EndpointKey(endpoint.VPC, endpoint.ID), prefix))
		}
	}
	return shellOperation("for ns in $(ip netns list | awk '{print $1}' | grep '^" + shellQuote(netnsName("", prefix)) + "' || true); do case '" + keepSet(keep) + "' in *\" $ns \"*) ;; *) ip netns del \"$ns\" ;; esac; done")
}

func keepSet(names []string) string {
	if len(names) == 0 {
		return " "
	}
	return " " + strings.Join(names, " ") + " "
}

func shellQuote(value string) string {
	return strings.ReplaceAll(value, "'", "'\"'\"'")
}

func planNetNSWorkload(endpointID string, ip netip.Addr, workloadIF string, hostGateway netip.Addr, prefix string) []Operation {
	ns := netnsName(endpointID, prefix)
	hostVeth := HostVethName(endpointID)
	peerVeth := peerVethName(endpointID)
	workloadPrefix := endpointPrefix(ip)
	return []Operation{
		shellOperation("ip netns add " + ns + " 2>/dev/null || true"),
		shellOperation("ip -n " + ns + " link show " + workloadIF + " >/dev/null 2>&1 || { ip link show " + hostVeth + " >/dev/null 2>&1 || ip link add " + hostVeth + " type veth peer name " + peerVeth + "; ip link set " + peerVeth + " netns " + ns + "; ip -n " + ns + " link set " + peerVeth + " name " + workloadIF + "; }"),
		{Command: "ip", Args: ipAddrReplaceArgs(hostGateway, hostVeth)},
		{Command: "ip", Args: []string{"link", "set", hostVeth, "up"}},
		{Command: "ip", Args: []string{"route", "replace", ip.String() + "/" + strconv.Itoa(addrPrefixBits(ip)), "dev", hostVeth}},
		{Command: "ip", Args: []string{"netns", "exec", ns, "ip", "link", "set", "lo", "up"}},
		shellOperation("ip -n " + ns + " -o addr show dev " + workloadIF + " 2>/dev/null | awk '{print $4}' | while read -r addr; do case \"$addr\" in 127.0.0.1/8|::1/128) continue ;; esac; case \"$addr\" in */32|*/128) : ;; *) continue ;; esac; case ' " + workloadPrefix + " ' in *\" $addr \"*) ;; *) ip -n " + ns + " addr del \"$addr\" dev " + workloadIF + " 2>/dev/null || true ;; esac; done"),
		{Command: "ip", Args: append([]string{"netns", "exec", ns, "ip"}, ipAddrReplaceArgs(ip, workloadIF)...)},
		{Command: "ip", Args: []string{"netns", "exec", ns, "ip", "link", "set", workloadIF, "up"}},
		{Command: "ip", Args: []string{"netns", "exec", ns, "ip", "route", "replace", "default", "via", hostGateway.String(), "dev", workloadIF, "onlink"}},
	}
}

func addrPrefixBits(addr netip.Addr) int {
	if addr.Is6() {
		return 128
	}
	return 32
}

func workloadHostGateway(ip, configured netip.Addr) netip.Addr {
	if configured.IsValid() && configured.Is6() == ip.Is6() {
		return configured
	}
	if ip.Is6() {
		return defaultIPv6HostGateway
	}
	return defaultIPv4HostGateway
}

func ipAddrReplaceArgs(addr netip.Addr, dev string) []string {
	args := []string{"addr", "replace", addr.String() + "/" + strconv.Itoa(addrPrefixBits(addr)), "dev", dev}
	if addr.Is6() {
		args = append(args, "nodad")
	}
	return args
}

func shellOperation(script string) Operation {
	return Operation{Command: "sh", Args: []string{"-c", script}}
}

func netnsName(endpointID, prefix string) string {
	if prefix == "" {
		prefix = "nl"
	}
	return prefix + "-" + sanitize(endpointID)
}

func HostVethName(endpointID string) string {
	return shortName("nlh", endpointID)
}

func peerVethName(endpointID string) string {
	return shortName("nlp", endpointID)
}

func shortName(prefix, value string) string {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(value))
	return fmt.Sprintf("%s%x", prefix, hash.Sum32())
}

func sanitize(value string) string {
	var out strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-':
			out.WriteRune(r)
		case r == '_':
			out.WriteString("__")
		case r == '.':
			out.WriteString("_d")
		case r == '/':
			out.WriteString("_s")
		case r == ':':
			out.WriteString("_c")
		case r == ' ':
			out.WriteString("_w")
		default:
			out.WriteString("_x")
			out.WriteString(fmt.Sprintf("%06x", r))
		}
	}
	return out.String()
}

func resolveNode(ctx context.Context, node string, targetIP netip.Addr, underlays map[string][]netip.Addr) (netip.Addr, error) {
	if node == "" {
		return netip.Addr{}, fmt.Errorf("node name is required")
	}
	for _, addr := range underlays[node] {
		if addr.IsValid() && (!targetIP.IsValid() || addr.Is6() == targetIP.Is6()) {
			return addr, nil
		}
	}
	network := "ip4"
	if targetIP.IsValid() && targetIP.Is6() {
		network = "ip6"
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, network, node)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		if !targetIP.IsValid() || ip.Is6() == targetIP.Is6() {
			return ip, nil
		}
	}
	if targetIP.Is6() {
		return netip.Addr{}, fmt.Errorf("node %s has no IPv6 address", node)
	}
	return netip.Addr{}, fmt.Errorf("node %s has no IPv4 address", node)
}
