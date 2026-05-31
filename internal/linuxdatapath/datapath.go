package linuxdatapath

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os/exec"
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
	NodeUnderlays   map[string]netip.Addr
	NetNSPrefix     string
	WorkloadIF      string
	HostGateway     netip.Addr
	PolicyTableBase int
	PolicyTableSize int
	CleanupStale    bool
	Executor        Executor
}

type Result struct {
	LocalAddresses int
	RemoteRoutes   int
	PolicyRoutes   int
	Device         string
	Mode           string
	CleanupPlanned bool
}

type CommandExecutor struct{}

const (
	linuxMainRouteTable        = 254
	linuxPolicyRuleProtocolID  = 186
	linuxRemoteRouteProtocolID = 187
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
	if !hostGateway.IsValid() {
		hostGateway = netip.MustParseAddr("169.254.1.1")
	}
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
	if mode == "local" {
		ops = append(ops, Operation{Command: "ip", Args: []string{"link", "set", localDevice, "up"}})
	}
	if mode == "netns" {
		result.Device = "netns"
		ops = append(ops,
			shellOperation("sysctl -w net.ipv4.ip_forward=1 >/dev/null"),
			shellOperation("sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null"),
			shellOperation("sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null"),
		)
		if options.CleanupStale {
			ops = append(ops, planNetNSCleanup(state, options.Node, options.NetNSPrefix))
		}
	}
	for _, endpoint := range state.Endpoints {
		if endpoint.Node == options.Node {
			if mode == "netns" {
				ops = append(ops, planNetNSWorkload(endpoint.ID, endpoint.IP, workloadIF, hostGateway, options.NetNSPrefix)...)
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
		nextHop, err := resolveNode(ctx, endpoint.Node, options.NodeUnderlays)
		if err != nil {
			return nil, Result{}, fmt.Errorf("resolve underlay for node %s: %w", endpoint.Node, err)
		}
		ops = append(ops, Operation{
			Command: "ip",
			Args:    []string{"route", "replace", prefix, "via", nextHop.String(), "dev", underlayDevice, "proto", strconv.Itoa(linuxRemoteRouteProtocolID)},
		})
		result.RemoteRoutes++
	}
	if options.CleanupStale {
		ops = append(ops, planRemoteRouteCleanup(state, options.Node, underlayDevice))
	}
	policyOps, policyRoutes, err := planPolicyRoutes(state, options.Node, underlayDevice, policyTableBase, policyTableSize, options.CleanupStale)
	if err != nil {
		return nil, Result{}, err
	}
	ops = append(ops, policyOps...)
	result.PolicyRoutes = policyRoutes
	return ops, result, nil
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
			table = tables[route.Name]
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
	return shellOperation("ip rule show | awk -v start=" + start + " -v end=" + end + " -v proto=" + protocol + " '{ managed=0; for (i=1; i<=NF; i++) { if (($i == \"lookup\" || $i == \"table\") && $(i+1) >= start && $(i+1) < end) managed=1; if (($i == \"proto\" || $i == \"protocol\") && $(i+1) == proto) managed=1 } if (managed) print }' | while read -r rule; do priority=${rule%%:*}; table=$(printf '%s\\n' \"$rule\" | awk '{ for (i=1; i<=NF; i++) if (($i == \"lookup\" || $i == \"table\")) { print $(i+1); exit } }'); ip rule del priority \"$priority\" table \"$table\" 2>/dev/null || true; done")
}

func planRemoteRouteCleanup(state control.DesiredState, node, device string) Operation {
	keep := keepSet(remoteEndpointPrefixes(state, node))
	protocol := strconv.Itoa(linuxRemoteRouteProtocolID)
	script := "for family in '' '-6'; do ip $family -o route show proto " + protocol + " dev " + device + " 2>/dev/null | awk '{print $1}' | while read -r dst; do case '" + keep + "' in *\" $dst \"*) ;; *) ip $family route del \"$dst\" dev " + device + " proto " + protocol + " 2>/dev/null || true ;; esac; done; done"
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
	if len(route.Match.DstPorts) == 0 {
		return []string{linuxPolicyRuleArgsForPort(route, priority, table, nil)}
	}
	args := make([]string, 0, len(route.Match.DstPorts))
	for i := range route.Match.DstPorts {
		args = append(args, linuxPolicyRuleArgsForPort(route, priority, table, &route.Match.DstPorts[i]))
	}
	return args
}

func linuxPolicyRuleArgsForPort(route model.PolicyRoute, priority, table int, port *model.PortRange) string {
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
	if port != nil {
		args = append(args, "dport", linuxPolicyRulePort(*port))
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
			keep = append(keep, netnsName(endpoint.ID, prefix))
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
	return []Operation{
		shellOperation("ip netns add " + ns + " 2>/dev/null || true"),
		shellOperation("ip -n " + ns + " link show " + workloadIF + " >/dev/null 2>&1 || { ip link show " + hostVeth + " >/dev/null 2>&1 || ip link add " + hostVeth + " type veth peer name " + peerVeth + "; ip link set " + peerVeth + " netns " + ns + "; ip -n " + ns + " link set " + peerVeth + " name " + workloadIF + "; }"),
		{Command: "ip", Args: []string{"addr", "replace", hostGateway.String() + "/" + strconv.Itoa(addrPrefixBits(hostGateway)), "dev", hostVeth}},
		{Command: "ip", Args: []string{"link", "set", hostVeth, "up"}},
		{Command: "ip", Args: []string{"route", "replace", ip.String() + "/" + strconv.Itoa(addrPrefixBits(ip)), "dev", hostVeth}},
		{Command: "ip", Args: []string{"netns", "exec", ns, "ip", "link", "set", "lo", "up"}},
		{Command: "ip", Args: []string{"netns", "exec", ns, "ip", "addr", "replace", ip.String() + "/" + strconv.Itoa(addrPrefixBits(ip)), "dev", workloadIF}},
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

func resolveNode(ctx context.Context, node string, underlays map[string]netip.Addr) (netip.Addr, error) {
	if node == "" {
		return netip.Addr{}, fmt.Errorf("node name is required")
	}
	if addr := underlays[node]; addr.IsValid() {
		return addr, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", node)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		if ip.Is4() {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("node %s has no IPv4 address", node)
}
