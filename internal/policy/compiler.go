package policy

import (
	"fmt"
	"hash/fnv"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jimyag/netloom/internal/model"
)

type Program struct {
	EndpointID string
	MapEntries []MapEntry
	Rules      []Rule
}

type Rule struct {
	ID              string
	Tier            int
	Priority        int
	Direction       model.Direction
	Protocol        model.Protocol
	RemoteCIDR      netip.Prefix
	RemoteGroup     string
	RemoteService   string
	RemoteCIDRGroup string
	RemoteEntity    string
	RemoteEndpoint  string
	RemoteFQDN      string
	Ports           []model.PortRange
	NamedPorts      []string
	ICMPType        *uint8
	ICMPCode        *uint8
	Action          model.Action
	Stateful        bool
	Log             bool
	SecurityGroup   string
}

type MapEntry struct {
	Key        MapKey
	Value      MapValue
	RemoteCIDR netip.Prefix
	RuleID     string
}

type MapKey struct {
	RemoteIdentity uint32
	Direction      model.Direction
	Protocol       model.Protocol
	DestPort       uint16
	L4PrefixBits   uint8
}

type MapValue struct {
	Deny       bool
	Reject     bool
	Precedence uint32
	Stateful   bool
	Log        bool
}

type CompileContext struct {
	Endpoints  []model.Endpoint
	Subnets    []model.Subnet
	Gateways   []model.Gateway
	Services   []model.LoadBalancer
	DNSRecords []model.DNSRecord
	CIDRGroups []model.CIDRGroup
	Now        time.Time
}

type gatewayCIDR struct {
	node string
	cidr netip.Prefix
}

func CompileForEndpoint(endpoint model.Endpoint, groups map[string]model.SecurityGroup) (Program, error) {
	return CompileForEndpointWithContext(endpoint, groups, CompileContext{})
}

func CompileForEndpointWithState(endpoint model.Endpoint, groups map[string]model.SecurityGroup, endpoints []model.Endpoint) (Program, error) {
	return CompileForEndpointWithContext(endpoint, groups, CompileContext{Endpoints: endpoints})
}

func CompileForEndpointWithContext(endpoint model.Endpoint, groups map[string]model.SecurityGroup, ctx CompileContext) (Program, error) {
	if err := endpoint.Validate(); err != nil {
		return Program{}, err
	}
	membersByGroup, err := indexRemoteGroupMembers(endpoint.VPC, groups, ctx.Endpoints)
	if err != nil {
		return Program{}, err
	}
	endpointsBySelector, err := indexEndpointSelectorMembers(endpoint.VPC, ctx.Endpoints)
	if err != nil {
		return Program{}, err
	}
	dnsRecords, err := indexDNSRecords(ctx.DNSRecords, ctx.Now)
	if err != nil {
		return Program{}, err
	}
	cidrGroups, err := indexCIDRGroups(endpoint.VPC, ctx.CIDRGroups)
	if err != nil {
		return Program{}, err
	}
	services, err := indexServices(endpoint.VPC, ctx.Services)
	if err != nil {
		return Program{}, err
	}
	subnetsByVPC, err := indexSubnetsByVPC(ctx.Subnets)
	if err != nil {
		return Program{}, err
	}
	gatewayCIDRsByVPC, err := indexGatewayCIDRsByVPC(ctx.Gateways)
	if err != nil {
		return Program{}, err
	}
	program := Program{EndpointID: endpoint.ID}
	attachedGroups := make([]model.SecurityGroup, 0, len(endpoint.SecurityGroups))
	for _, groupName := range endpoint.SecurityGroups {
		group, ok := groups[groupName]
		if !ok {
			return Program{}, fmt.Errorf("endpoint %s references unknown security group %s", endpoint.ID, groupName)
		}
		if group.VPC != endpoint.VPC {
			return Program{}, fmt.Errorf("security group %s belongs to vpc %s, endpoint %s belongs to %s", group.Name, group.VPC, endpoint.ID, endpoint.VPC)
		}
		if err := group.Validate(); err != nil {
			return Program{}, err
		}
		attachedGroups = append(attachedGroups, group)
		for _, rule := range group.Rules {
			compiledRules, err := expandRule(endpoint, group, rule, membersByGroup, endpointsBySelector, dnsRecords, cidrGroups, services, subnetsByVPC, gatewayCIDRsByVPC)
			if err != nil {
				return Program{}, err
			}
			for _, compiledRule := range compiledRules {
				program.Rules = append(program.Rules, compiledRule)
				entries, err := compileMapEntries(compiledRule)
				if err != nil {
					return Program{}, err
				}
				program.MapEntries = append(program.MapEntries, entries...)
			}
		}
	}
	if err := appendDefaultAllowRules(&program, attachedGroups); err != nil {
		return Program{}, err
	}
	sort.SliceStable(program.Rules, func(i, j int) bool {
		if left, right := precedence(program.Rules[i]), precedence(program.Rules[j]); left != right {
			return left > right
		}
		return program.Rules[i].ID < program.Rules[j].ID
	})
	sort.SliceStable(program.MapEntries, func(i, j int) bool {
		if program.MapEntries[i].Value.Precedence != program.MapEntries[j].Value.Precedence {
			return program.MapEntries[i].Value.Precedence > program.MapEntries[j].Value.Precedence
		}
		return program.MapEntries[i].RuleID < program.MapEntries[j].RuleID
	})
	return program, nil
}

func appendDefaultAllowRules(program *Program, groups []model.SecurityGroup) error {
	for _, direction := range []model.Direction{model.DirectionIngress, model.DirectionEgress} {
		if !defaultDenyDisabledForDirection(groups, direction) {
			continue
		}
		rule := Rule{
			ID:        "netloom-default-allow-" + string(direction),
			Tier:      1,
			Direction: direction,
			Protocol:  model.ProtocolAny,
			Action:    model.ActionAllow,
		}
		program.Rules = append(program.Rules, rule)
		entries, err := compileMapEntries(rule)
		if err != nil {
			return err
		}
		program.MapEntries = append(program.MapEntries, entries...)
	}
	return nil
}

func defaultDenyDisabledForDirection(groups []model.SecurityGroup, direction model.Direction) bool {
	if len(groups) == 0 {
		return false
	}
	for _, group := range groups {
		var setting *bool
		switch direction {
		case model.DirectionIngress:
			setting = group.DefaultDenyIngress
		case model.DirectionEgress:
			setting = group.DefaultDenyEgress
		default:
			return false
		}
		if setting == nil || *setting {
			return false
		}
	}
	return true
}

func expandRule(endpoint model.Endpoint, securityGroup model.SecurityGroup, rule model.SecurityGroupRule, membersByGroup map[string][]model.Endpoint, endpointsBySelector []model.Endpoint, dnsRecords map[string][]netip.Addr, cidrGroups map[string][]netip.Prefix, services map[string]model.LoadBalancer, subnetsByVPC map[string][]netip.Prefix, gatewayCIDRsByVPC map[string][]gatewayCIDR) ([]Rule, error) {
	base := Rule{
		ID:              rule.ID,
		Tier:            securityGroup.Tier,
		Priority:        rule.Priority,
		Direction:       rule.Direction,
		Protocol:        rule.Protocol,
		RemoteCIDR:      rule.RemoteCIDR,
		RemoteGroup:     rule.RemoteGroup,
		RemoteService:   rule.RemoteService,
		RemoteCIDRGroup: rule.RemoteCIDRGroup,
		Ports:           append([]model.PortRange(nil), rule.Ports...),
		NamedPorts:      append([]string(nil), rule.NamedPorts...),
		ICMPType:        cloneUint8Ptr(rule.ICMPType),
		ICMPCode:        cloneUint8Ptr(rule.ICMPCode),
		Action:          rule.Action,
		Stateful:        rule.Stateful,
		Log:             rule.Log,
		SecurityGroup:   securityGroup.Name,
	}
	if len(rule.NamedPorts) > 0 && rule.Direction == model.DirectionIngress {
		ports, err := resolveNamedPorts(rule.Ports, rule.NamedPorts, rule.Protocol, endpoint)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		base.Ports = ports
	}
	if len(rule.NamedPorts) > 0 && rule.Direction == model.DirectionEgress && rule.RemoteGroup == "" && !hasRemoteEndpointSelector(rule) {
		return nil, fmt.Errorf("rule %s: named ports require remote_group or remote_endpoint_selector for egress rules", rule.ID)
	}
	if len(rule.RemoteFQDNs) > 0 {
		return expandFQDNRule(base, rule.RemoteFQDNs, dnsRecords)
	}
	if len(rule.RemoteEntities) > 0 {
		return expandEntityRule(base, endpoint, rule.RemoteEntities, subnetsByVPC, gatewayCIDRsByVPC)
	}
	if rule.RemoteService != "" {
		return expandServiceRule(base, services)
	}
	if rule.RemoteCIDRGroup != "" {
		return expandCIDRGroupRule(base, cidrGroups)
	}
	if rule.RemoteCIDR.IsValid() && len(rule.ExceptCIDRs) > 0 {
		return expandCIDRExceptRule(base, rule.ExceptCIDRs), nil
	}
	if hasRemoteEndpointSelector(rule) {
		return expandEndpointSelectorRule(endpoint, base, rule, endpointsBySelector)
	}
	if rule.RemoteGroup == "" || membersByGroup == nil {
		return []Rule{base}, nil
	}
	members, ok := membersByGroup[rule.RemoteGroup]
	if !ok {
		return nil, fmt.Errorf("rule %s references unknown remote security group %s", rule.ID, rule.RemoteGroup)
	}
	return expandEndpointMembers(endpoint, base, rule, members)
}

func expandEndpointSelectorRule(endpoint model.Endpoint, base Rule, rule model.SecurityGroupRule, endpoints []model.Endpoint) ([]Rule, error) {
	if endpoints == nil {
		return nil, fmt.Errorf("rule %s remote_endpoint_selector has no endpoint context", rule.ID)
	}
	members := make([]model.Endpoint, 0)
	for _, candidate := range endpoints {
		if candidate.Labels.MatchesSelector(rule.RemoteEndpointSelector, rule.RemoteEndpointExprs) {
			members = append(members, candidate)
		}
	}
	return expandEndpointMembers(endpoint, base, rule, members)
}

func hasRemoteEndpointSelector(rule model.SecurityGroupRule) bool {
	return len(rule.RemoteEndpointSelector) > 0 || len(rule.RemoteEndpointExprs) > 0
}

func expandEndpointMembers(endpoint model.Endpoint, base Rule, rule model.SecurityGroupRule, members []model.Endpoint) ([]Rule, error) {
	out := make([]Rule, 0, len(members))
	for _, member := range members {
		if member.ID == endpoint.ID {
			continue
		}
		expanded := base
		expanded.RemoteEndpoint = member.ID
		if len(rule.NamedPorts) > 0 && rule.Direction == model.DirectionEgress {
			ports, err := resolveNamedPorts(rule.Ports, rule.NamedPorts, rule.Protocol, member)
			if err != nil {
				return nil, fmt.Errorf("rule %s remote endpoint %s: %w", rule.ID, member.ID, err)
			}
			expanded.Ports = ports
		}
		if member.IP.Is4() || member.IP.Is6() {
			bits := 128
			if member.IP.Is4() {
				bits = 32
			}
			expanded.RemoteCIDR = netip.PrefixFrom(member.IP, bits)
		}
		out = append(out, expanded)
	}
	return out, nil
}

func expandEntityRule(base Rule, endpoint model.Endpoint, entities []string, subnetsByVPC map[string][]netip.Prefix, gatewayCIDRsByVPC map[string][]gatewayCIDR) ([]Rule, error) {
	seen := make(map[string]struct{})
	var out []Rule
	for _, entity := range entities {
		cidrs, err := entityCIDRs(entity, endpoint, subnetsByVPC, gatewayCIDRsByVPC)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", base.ID, err)
		}
		for _, cidr := range cidrs {
			key := entity + "|" + cidr.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			expanded := base
			expanded.RemoteEntity = entity
			expanded.RemoteCIDR = cidr
			out = append(out, expanded)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RemoteEntity != out[j].RemoteEntity {
			return out[i].RemoteEntity < out[j].RemoteEntity
		}
		return out[i].RemoteCIDR.String() < out[j].RemoteCIDR.String()
	})
	return out, nil
}

func entityCIDRs(entity string, endpoint model.Endpoint, subnetsByVPC map[string][]netip.Prefix, gatewayCIDRsByVPC map[string][]gatewayCIDR) ([]netip.Prefix, error) {
	switch entity {
	case "all":
		return allCIDRs(), nil
	case "world":
		return worldCIDRs(endpoint.VPC, subnetsByVPC, allCIDRs())
	case "world-ipv4":
		return worldCIDRs(endpoint.VPC, subnetsByVPC, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	case "world-ipv6":
		return worldCIDRs(endpoint.VPC, subnetsByVPC, []netip.Prefix{netip.MustParsePrefix("::/0")})
	case "host":
		cidrs := gatewayCIDRs(gatewayCIDRsByVPC[endpoint.VPC], func(gateway gatewayCIDR) bool {
			return true
		})
		if len(cidrs) == 0 {
			return nil, fmt.Errorf("remote entity host requires at least one gateway in vpc %s", endpoint.VPC)
		}
		return cidrs, nil
	case "remote-node":
		cidrs := gatewayCIDRs(gatewayCIDRsByVPC[endpoint.VPC], func(gateway gatewayCIDR) bool {
			return gateway.node != endpoint.Node
		})
		if len(cidrs) == 0 {
			return nil, fmt.Errorf("remote entity remote-node requires at least one gateway on a different node in vpc %s", endpoint.VPC)
		}
		return cidrs, nil
	case "private":
		return []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("fc00::/7"),
		}, nil
	case "cluster":
		cidrs := append([]netip.Prefix(nil), subnetsByVPC[endpoint.VPC]...)
		if len(cidrs) == 0 {
			return nil, fmt.Errorf("remote entity cluster requires at least one subnet in vpc %s", endpoint.VPC)
		}
		sort.SliceStable(cidrs, func(i, j int) bool { return cidrs[i].String() < cidrs[j].String() })
		return cidrs, nil
	case "none":
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported remote entity %q", entity)
	}
}

func gatewayCIDRs(gateways []gatewayCIDR, keep func(gatewayCIDR) bool) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(gateways))
	for _, gateway := range gateways {
		if keep(gateway) {
			out = append(out, gateway.cidr)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func allCIDRs() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
}

func worldCIDRs(vpc string, subnetsByVPC map[string][]netip.Prefix, initial []netip.Prefix) ([]netip.Prefix, error) {
	clusterCIDRs := append([]netip.Prefix(nil), subnetsByVPC[vpc]...)
	if len(clusterCIDRs) == 0 {
		return nil, fmt.Errorf("remote entity world requires at least one subnet in vpc %s", vpc)
	}
	cidrs := append([]netip.Prefix(nil), initial...)
	for _, clusterCIDR := range clusterCIDRs {
		clusterCIDR = clusterCIDR.Masked()
		var next []netip.Prefix
		for _, cidr := range cidrs {
			if cidr.Addr().Is4() != clusterCIDR.Addr().Is4() {
				next = append(next, cidr)
				continue
			}
			next = append(next, subtractPrefix(cidr, clusterCIDR)...)
		}
		cidrs = next
	}
	sort.SliceStable(cidrs, func(i, j int) bool {
		return cidrs[i].String() < cidrs[j].String()
	})
	return cidrs, nil
}

func resolveNamedPorts(staticPorts []model.PortRange, names []string, protocol model.Protocol, endpoint model.Endpoint) ([]model.PortRange, error) {
	out := append([]model.PortRange(nil), staticPorts...)
	if len(names) == 0 {
		return out, nil
	}
	if protocol != model.ProtocolTCP && protocol != model.ProtocolUDP {
		return nil, fmt.Errorf("named ports require tcp or udp protocol")
	}
	byName := make(map[string]uint16, len(endpoint.NamedPorts))
	for _, port := range endpoint.NamedPorts {
		if port.Protocol == protocol {
			byName[port.Name] = port.Port
		}
	}
	for _, name := range names {
		port, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("named port %s/%s is not defined on endpoint %s", protocol, name, endpoint.ID)
		}
		out = append(out, model.PortRange{From: port, To: port})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out, nil
}

func expandCIDRGroupRule(base Rule, groups map[string][]netip.Prefix) ([]Rule, error) {
	cidrs, ok := groups[base.RemoteCIDRGroup]
	if !ok {
		return nil, fmt.Errorf("rule %s references unknown remote cidr group %s", base.ID, base.RemoteCIDRGroup)
	}
	out := make([]Rule, 0, len(cidrs))
	for _, cidr := range cidrs {
		expanded := base
		expanded.RemoteCIDR = cidr
		out = append(out, expanded)
	}
	return out, nil
}

func expandServiceRule(base Rule, services map[string]model.LoadBalancer) ([]Rule, error) {
	service, ok := services[base.RemoteService]
	if !ok {
		return nil, fmt.Errorf("rule %s references unknown remote service %s", base.ID, base.RemoteService)
	}
	out := make([]Rule, 0, len(service.Frontends()))
	seen := make(map[string]struct{})
	for _, frontend := range service.Frontends() {
		if base.Protocol != "" && base.Protocol != model.ProtocolAny && base.Protocol != frontend.Protocol {
			continue
		}
		expanded := base
		bits := 128
		if frontend.VIP.Is4() {
			bits = 32
		}
		expanded.RemoteCIDR = netip.PrefixFrom(frontend.VIP, bits)
		if expanded.Protocol == "" || expanded.Protocol == model.ProtocolAny {
			expanded.Protocol = frontend.Protocol
		}
		if len(expanded.Ports) == 0 {
			expanded.Ports = []model.PortRange{{From: frontend.Port, To: frontend.Port}}
		}
		key := expanded.RemoteCIDR.String() + "|" + string(expanded.Protocol) + "|" + portRangesKey(expanded.Ports)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, expanded)
	}
	return out, nil
}

func portRangesKey(ports []model.PortRange) string {
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, fmt.Sprintf("%d-%d", port.From, port.To))
	}
	return strings.Join(parts, ",")
}

func expandCIDRExceptRule(base Rule, exceptCIDRs []netip.Prefix) []Rule {
	cidrs := []netip.Prefix{base.RemoteCIDR.Masked()}
	for _, except := range exceptCIDRs {
		except = except.Masked()
		var next []netip.Prefix
		for _, cidr := range cidrs {
			next = append(next, subtractPrefix(cidr, except)...)
		}
		cidrs = next
	}
	sort.SliceStable(cidrs, func(i, j int) bool {
		return cidrs[i].String() < cidrs[j].String()
	})
	out := make([]Rule, 0, len(cidrs))
	for _, cidr := range cidrs {
		expanded := base
		expanded.RemoteCIDR = cidr
		out = append(out, expanded)
	}
	return out
}

func subtractPrefix(base, except netip.Prefix) []netip.Prefix {
	base = base.Masked()
	except = except.Masked()
	if !prefixContainsPrefix(base, except) {
		return []netip.Prefix{base}
	}
	if base == except {
		return nil
	}
	left, right := splitPrefix(base)
	out := subtractPrefix(left, except)
	out = append(out, subtractPrefix(right, except)...)
	return out
}

func splitPrefix(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := prefix.Bits()
	nextBits := bits + 1
	left := netip.PrefixFrom(prefix.Addr(), nextBits).Masked()
	rightAddr := setPrefixBit(prefix.Addr(), bits)
	right := netip.PrefixFrom(rightAddr, nextBits).Masked()
	return left, right
}

func setPrefixBit(addr netip.Addr, bit int) netip.Addr {
	if addr.Is4() {
		raw := addr.As4()
		raw[bit/8] |= 1 << (7 - uint(bit%8))
		return netip.AddrFrom4(raw)
	}
	raw := addr.As16()
	raw[bit/8] |= 1 << (7 - uint(bit%8))
	return netip.AddrFrom16(raw)
}

func prefixContainsPrefix(parent, child netip.Prefix) bool {
	return parent.IsValid() && child.IsValid() &&
		parent.Addr().Is4() == child.Addr().Is4() &&
		parent.Bits() <= child.Bits() &&
		parent.Contains(child.Addr()) &&
		parent.Contains(prefixLastAddr(child))
}

func prefixLastAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	bits := 128
	bytes := addr.As16()
	if addr.Is4() {
		bits = 32
		raw := addr.As4()
		bytes = [16]byte{}
		copy(bytes[12:], raw[:])
	}
	for bit := prefix.Bits(); bit < bits; bit++ {
		byteIndex := bit / 8
		if addr.Is4() {
			byteIndex += 12
		}
		bytes[byteIndex] |= 1 << (7 - uint(bit%8))
	}
	if addr.Is4() {
		return netip.AddrFrom4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]})
	}
	return netip.AddrFrom16(bytes)
}

func expandFQDNRule(base Rule, selectors []model.FQDNSelector, records map[string][]netip.Addr) ([]Rule, error) {
	if len(records) == 0 {
		return nil, nil
	}
	type match struct {
		name string
		cidr netip.Prefix
	}
	seen := make(map[string]struct{})
	var matches []match
	for recordName, ips := range records {
		ok, err := fqdnSelectorsMatch(selectors, recordName)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", base.ID, err)
		}
		if !ok {
			continue
		}
		for _, ip := range ips {
			cidr := fqdnIPPrefix(ip)
			key := recordName + "|" + cidr.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			matches = append(matches, match{name: recordName, cidr: cidr})
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].name != matches[j].name {
			return matches[i].name < matches[j].name
		}
		return matches[i].cidr.String() < matches[j].cidr.String()
	})
	out := make([]Rule, 0, len(matches))
	for _, match := range matches {
		expanded := base
		expanded.RemoteFQDN = match.name
		expanded.RemoteCIDR = match.cidr
		out = append(out, expanded)
	}
	return out, nil
}

func fqdnSelectorsMatch(selectors []model.FQDNSelector, name string) (bool, error) {
	for _, selector := range selectors {
		if selector.MatchName != "" && normalizeDNSName(selector.MatchName) == name {
			return true, nil
		}
		if selector.MatchPattern != "" {
			matched, err := fqdnPatternMatches(selector.MatchPattern, name)
			if err != nil {
				return false, fmt.Errorf("invalid fqdn pattern %q: %w", selector.MatchPattern, err)
			}
			if matched {
				return true, nil
			}
		}
	}
	return false, nil
}

func fqdnPatternMatches(pattern, name string) (bool, error) {
	pattern = strings.TrimSpace(pattern)
	if dnsWildcardPattern(pattern) {
		return normalizeDNSName(name) != "", nil
	}
	pattern = normalizeDNSName(pattern)
	name = normalizeDNSName(name)
	regexPattern := fqdnPatternRegexp(pattern)
	matcher, err := regexp.Compile("^" + regexPattern + "$")
	if err != nil {
		return false, err
	}
	return matcher.MatchString(name), nil
}

func fqdnPatternRegexp(pattern string) string {
	if strings.HasPrefix(pattern, "**.") {
		return `([-a-z0-9_]+\.)+` + fqdnPatternRegexp(strings.TrimPrefix(pattern, "**."))
	}
	regexPattern := strings.ReplaceAll(pattern, ".", `\.`)
	regexPattern = wildcardPattern.ReplaceAllString(regexPattern, `[-a-z0-9_]*`)
	return regexPattern
}

func dnsWildcardPattern(pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if strings.HasSuffix(pattern, ".") {
		pattern = strings.TrimSuffix(pattern, ".")
	}
	return pattern != "" && strings.Trim(pattern, "*") == ""
}

var wildcardPattern = regexp.MustCompile(`\*+`)

func indexRemoteGroupMembers(vpc string, groups map[string]model.SecurityGroup, endpoints []model.Endpoint) (map[string][]model.Endpoint, error) {
	if endpoints == nil {
		return nil, nil
	}
	out := make(map[string][]model.Endpoint, len(groups))
	for name, group := range groups {
		if group.VPC != vpc {
			continue
		}
		out[name] = nil
	}
	for _, endpoint := range endpoints {
		if endpoint.VPC != vpc {
			continue
		}
		if err := endpoint.Validate(); err != nil {
			return nil, err
		}
		for _, groupName := range endpoint.SecurityGroups {
			if _, ok := out[groupName]; ok {
				out[groupName] = append(out[groupName], endpoint)
			}
		}
	}
	for name := range out {
		sort.SliceStable(out[name], func(i, j int) bool {
			return out[name][i].ID < out[name][j].ID
		})
	}
	return out, nil
}

func indexEndpointSelectorMembers(vpc string, endpoints []model.Endpoint) ([]model.Endpoint, error) {
	if endpoints == nil {
		return nil, nil
	}
	out := make([]model.Endpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.VPC != vpc {
			continue
		}
		if err := endpoint.Validate(); err != nil {
			return nil, err
		}
		out = append(out, endpoint)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func indexDNSRecords(records []model.DNSRecord, now time.Time) (map[string][]netip.Addr, error) {
	if len(records) == 0 {
		return nil, nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	out := make(map[string][]netip.Addr, len(records))
	for _, record := range records {
		if err := record.Validate(); err != nil {
			return nil, err
		}
		if record.IsExpired(now) {
			continue
		}
		name := normalizeDNSName(record.Name)
		out[name] = append(out[name], record.IPs...)
	}
	for name := range out {
		sort.SliceStable(out[name], func(i, j int) bool {
			return out[name][i].String() < out[name][j].String()
		})
	}
	return out, nil
}

func indexCIDRGroups(vpc string, groups []model.CIDRGroup) (map[string][]netip.Prefix, error) {
	if len(groups) == 0 {
		return nil, nil
	}
	out := make(map[string][]netip.Prefix, len(groups))
	for _, group := range groups {
		if err := group.Validate(); err != nil {
			return nil, err
		}
		if group.VPC != vpc {
			continue
		}
		if _, ok := out[group.Name]; ok {
			return nil, fmt.Errorf("duplicate cidr group %q in vpc %s", group.Name, vpc)
		}
		cidrs := make([]netip.Prefix, 0, len(group.CIDRs))
		for _, cidr := range group.CIDRs {
			cidrs = append(cidrs, cidr.Masked())
		}
		for _, entry := range group.Entries {
			cidrs = append(cidrs, expandCIDRGroupEntry(entry)...)
		}
		sort.SliceStable(cidrs, func(i, j int) bool {
			return cidrs[i].String() < cidrs[j].String()
		})
		out[group.Name] = dedupeCIDRs(cidrs)
	}
	return out, nil
}

func indexServices(vpc string, services []model.LoadBalancer) (map[string]model.LoadBalancer, error) {
	if len(services) == 0 {
		return nil, nil
	}
	out := make(map[string]model.LoadBalancer, len(services))
	for _, service := range services {
		if err := service.Validate(); err != nil {
			return nil, err
		}
		if service.VPC != vpc {
			continue
		}
		if _, ok := out[service.Name]; ok {
			return nil, fmt.Errorf("duplicate service %q in vpc %s", service.Name, vpc)
		}
		out[service.Name] = service
	}
	return out, nil
}

func expandCIDRGroupEntry(entry model.CIDRGroupEntry) []netip.Prefix {
	cidrs := []netip.Prefix{entry.CIDR.Masked()}
	for _, except := range entry.ExceptCIDRs {
		except = except.Masked()
		var next []netip.Prefix
		for _, cidr := range cidrs {
			next = append(next, subtractPrefix(cidr, except)...)
		}
		cidrs = next
	}
	return cidrs
}

func dedupeCIDRs(cidrs []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(cidrs))
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		if _, ok := seen[cidr]; ok {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	return out
}

func indexSubnetsByVPC(subnets []model.Subnet) (map[string][]netip.Prefix, error) {
	out := make(map[string][]netip.Prefix)
	for _, subnet := range subnets {
		if err := subnet.Validate(); err != nil {
			return nil, err
		}
		out[subnet.VPC] = append(out[subnet.VPC], subnet.CIDR.Masked())
	}
	for vpc := range out {
		sort.SliceStable(out[vpc], func(i, j int) bool {
			return out[vpc][i].String() < out[vpc][j].String()
		})
	}
	return out, nil
}

func indexGatewayCIDRsByVPC(gateways []model.Gateway) (map[string][]gatewayCIDR, error) {
	out := make(map[string][]gatewayCIDR)
	for _, gateway := range gateways {
		if err := gateway.Validate(); err != nil {
			return nil, err
		}
		bits := 128
		if gateway.LANIP.Is4() {
			bits = 32
		}
		out[gateway.VPC] = append(out[gateway.VPC], gatewayCIDR{
			node: gateway.Node,
			cidr: netip.PrefixFrom(gateway.LANIP, bits),
		})
	}
	for vpc := range out {
		sort.SliceStable(out[vpc], func(i, j int) bool {
			if out[vpc][i].cidr != out[vpc][j].cidr {
				return out[vpc][i].cidr.String() < out[vpc][j].cidr.String()
			}
			return out[vpc][i].node < out[vpc][j].node
		})
	}
	return out, nil
}

func compileMapEntries(rule Rule) ([]MapEntry, error) {
	portPrefixes, err := l4PortPrefixes(rule)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
	}

	entries := make([]MapEntry, 0, len(portPrefixes))
	for _, port := range portPrefixes {
		entries = append(entries, MapEntry{
			Key: MapKey{
				RemoteIdentity: remoteIdentity(rule),
				Direction:      rule.Direction,
				Protocol:       normalizedProtocol(rule.Protocol),
				DestPort:       port.port,
				L4PrefixBits:   port.l4PrefixBits,
			},
			Value: MapValue{
				Deny:       rule.Action == model.ActionDrop || rule.Action == model.ActionReject,
				Reject:     rule.Action == model.ActionReject,
				Precedence: precedence(rule),
				Stateful:   rule.Stateful,
				Log:        rule.Log || rule.Action == model.ActionLog,
			},
			RemoteCIDR: rule.RemoteCIDR,
			RuleID:     rule.ID,
		})
	}
	return entries, nil
}

type portPrefix struct {
	port         uint16
	l4PrefixBits uint8
}

func l4PortPrefixes(rule Rule) ([]portPrefix, error) {
	protocol := normalizedProtocol(rule.Protocol)
	if protocol == model.ProtocolICMP {
		return icmpPrefixes(rule), nil
	}
	if len(rule.Ports) == 0 {
		if protocol == model.ProtocolAny {
			return []portPrefix{{port: 0, l4PrefixBits: 0}}, nil
		}
		return []portPrefix{{port: 0, l4PrefixBits: 8}}, nil
	}
	if protocol == model.ProtocolAny {
		return nil, fmt.Errorf("ports require a concrete L4 protocol")
	}

	var out []portPrefix
	for _, portRange := range rule.Ports {
		if err := portRange.Validate(); err != nil {
			return nil, err
		}
		for _, block := range splitPortRange(portRange.From, portRange.To) {
			out = append(out, portPrefix{
				port:         block.port,
				l4PrefixBits: 8 + block.prefixBits,
			})
		}
	}
	return out, nil
}

func icmpPrefixes(rule Rule) []portPrefix {
	if rule.ICMPType == nil {
		return []portPrefix{{port: 0, l4PrefixBits: 8}}
	}
	value := uint16(*rule.ICMPType) << 8
	prefixBits := uint8(16)
	if rule.ICMPCode != nil {
		value |= uint16(*rule.ICMPCode)
		prefixBits = 24
	}
	return []portPrefix{{port: value, l4PrefixBits: prefixBits}}
}

func cloneUint8Ptr(value *uint8) *uint8 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

type portBlock struct {
	port       uint16
	prefixBits uint8
}

func splitPortRange(from, to uint16) []portBlock {
	var blocks []portBlock
	for current := uint32(from); current <= uint32(to); {
		size := current & -current
		if size == 0 {
			size = 1 << 16
		}
		remaining := uint32(to) - current + 1
		for size > remaining {
			size >>= 1
		}
		blocks = append(blocks, portBlock{
			port:       uint16(current),
			prefixBits: uint8(16 - log2(size)),
		})
		current += size
	}
	return blocks
}

func log2(value uint32) uint32 {
	var out uint32
	for value > 1 {
		value >>= 1
		out++
	}
	return out
}

func remoteIdentity(rule Rule) uint32 {
	switch {
	case rule.RemoteEndpoint != "":
		return EndpointIdentity(rule.RemoteEndpoint)
	case rule.RemoteEntity != "":
		return stableIdentity("entity:" + rule.RemoteEntity + ":" + rule.RemoteCIDR.String())
	case rule.RemoteService != "":
		return stableIdentity("service:" + rule.RemoteService + ":" + rule.RemoteCIDR.String())
	case rule.RemoteCIDR.IsValid():
		return stableIdentity("cidr:" + rule.RemoteCIDR.String())
	case rule.RemoteGroup != "":
		return stableIdentity("sg:" + rule.RemoteGroup)
	default:
		return 0
	}
}

func fqdnIPPrefix(ip netip.Addr) netip.Prefix {
	if ip.Is4() {
		return netip.PrefixFrom(ip, 32)
	}
	return netip.PrefixFrom(ip, 128)
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func EndpointIdentity(endpointID string) uint32 {
	return stableIdentity("endpoint:" + endpointID)
}

func stableIdentity(value string) uint32 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(value))
	return 1<<31 | hash.Sum32()&0x7fffffff
}

func normalizedProtocol(protocol model.Protocol) model.Protocol {
	if protocol == "" {
		return model.ProtocolAny
	}
	return protocol
}

func l4PrefixBits(protocol model.Protocol, port uint16) uint8 {
	if protocol == "" || protocol == model.ProtocolAny {
		return 0
	}
	if port == 0 {
		return 8
	}
	return 24
}

func precedence(rule Rule) uint32 {
	if rule.Tier <= 0 && (rule.Action == model.ActionDrop || rule.Action == model.ActionReject) {
		return math.MaxUint32
	}
	tier := rule.Tier
	if tier < 0 {
		tier = 0
	}
	if tier > 1 {
		tier = 1
	}
	priority := rule.Priority
	if priority < 0 {
		priority = 0
	}
	if priority > model.SecurityGroupPriorityMax {
		priority = model.SecurityGroupPriorityMax
	}
	priorityScore := 0
	if priority != 0 {
		priorityScore = model.SecurityGroupPriorityMax - priority + 1
	}
	precedence := uint32(1-tier) << 31
	if rule.Action == model.ActionDrop || rule.Action == model.ActionReject {
		precedence |= 1 << 30
	}
	return precedence | uint32(priorityScore)
}
