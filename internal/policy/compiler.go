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
	Priority        int
	Direction       model.Direction
	Protocol        model.Protocol
	RemoteCIDR      netip.Prefix
	RemoteGroup     string
	RemoteCIDRGroup string
	RemoteEndpoint  string
	RemoteFQDN      string
	Ports           []model.PortRange
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
	DNSRecords []model.DNSRecord
	CIDRGroups []model.CIDRGroup
	Now        time.Time
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
	dnsRecords, err := indexDNSRecords(ctx.DNSRecords, ctx.Now)
	if err != nil {
		return Program{}, err
	}
	cidrGroups, err := indexCIDRGroups(endpoint.VPC, ctx.CIDRGroups)
	if err != nil {
		return Program{}, err
	}
	program := Program{EndpointID: endpoint.ID}
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
		for _, rule := range group.Rules {
			compiledRules, err := expandRule(endpoint, group.Name, rule, membersByGroup, dnsRecords, cidrGroups)
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
	sort.SliceStable(program.Rules, func(i, j int) bool {
		return program.Rules[i].Priority > program.Rules[j].Priority
	})
	sort.SliceStable(program.MapEntries, func(i, j int) bool {
		if program.MapEntries[i].Value.Precedence != program.MapEntries[j].Value.Precedence {
			return program.MapEntries[i].Value.Precedence > program.MapEntries[j].Value.Precedence
		}
		return program.MapEntries[i].RuleID < program.MapEntries[j].RuleID
	})
	return program, nil
}

func expandRule(endpoint model.Endpoint, securityGroup string, rule model.SecurityGroupRule, membersByGroup map[string][]model.Endpoint, dnsRecords map[string][]netip.Addr, cidrGroups map[string][]netip.Prefix) ([]Rule, error) {
	base := Rule{
		ID:              rule.ID,
		Priority:        rule.Priority,
		Direction:       rule.Direction,
		Protocol:        rule.Protocol,
		RemoteCIDR:      rule.RemoteCIDR,
		RemoteGroup:     rule.RemoteGroup,
		RemoteCIDRGroup: rule.RemoteCIDRGroup,
		Ports:           append([]model.PortRange(nil), rule.Ports...),
		Action:          rule.Action,
		Stateful:        rule.Stateful,
		Log:             rule.Log,
		SecurityGroup:   securityGroup,
	}
	if len(rule.RemoteFQDNs) > 0 {
		return expandFQDNRule(base, rule.RemoteFQDNs, dnsRecords)
	}
	if rule.RemoteCIDRGroup != "" {
		return expandCIDRGroupRule(base, cidrGroups)
	}
	if rule.RemoteCIDR.IsValid() && len(rule.ExceptCIDRs) > 0 {
		return expandCIDRExceptRule(base, rule.ExceptCIDRs), nil
	}
	if rule.RemoteGroup == "" || membersByGroup == nil {
		return []Rule{base}, nil
	}
	members, ok := membersByGroup[rule.RemoteGroup]
	if !ok {
		return nil, fmt.Errorf("rule %s references unknown remote security group %s", rule.ID, rule.RemoteGroup)
	}
	out := make([]Rule, 0, len(members))
	for _, member := range members {
		if member.ID == endpoint.ID {
			continue
		}
		expanded := base
		expanded.RemoteEndpoint = member.ID
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
		cidrs := make([]netip.Prefix, 0, len(group.CIDRs))
		for _, cidr := range group.CIDRs {
			cidrs = append(cidrs, cidr.Masked())
		}
		sort.SliceStable(cidrs, func(i, j int) bool {
			return cidrs[i].String() < cidrs[j].String()
		})
		out[group.Name] = cidrs
	}
	return out, nil
}

func compileMapEntries(rule Rule) ([]MapEntry, error) {
	portPrefixes, err := l4PortPrefixes(rule.Protocol, rule.Ports)
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

func l4PortPrefixes(protocol model.Protocol, ports []model.PortRange) ([]portPrefix, error) {
	protocol = normalizedProtocol(protocol)
	if len(ports) == 0 {
		if protocol == model.ProtocolAny {
			return []portPrefix{{port: 0, l4PrefixBits: 0}}, nil
		}
		return []portPrefix{{port: 0, l4PrefixBits: 8}}, nil
	}
	if protocol == model.ProtocolAny {
		return nil, fmt.Errorf("ports require a concrete L4 protocol")
	}

	var out []portPrefix
	for _, portRange := range ports {
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
	if rule.Action == model.ActionDrop || rule.Action == model.ActionReject {
		return math.MaxUint32
	}
	if rule.Priority < 0 {
		return 0
	}
	return uint32(rule.Priority)
}
