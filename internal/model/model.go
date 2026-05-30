package model

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type Action string

const (
	ActionAllow    Action = "allow"
	ActionDrop     Action = "drop"
	ActionReroute  Action = "reroute"
	ActionReject   Action = "reject"
	ActionLog      Action = "log"
	ActionSNAT     Action = "snat"
	ActionDNAT     Action = "dnat"
	ActionDNATSNAT Action = "dnat_and_snat"
)

type Direction string

const (
	DirectionIngress Direction = "ingress"
	DirectionEgress  Direction = "egress"
)

type Protocol string

const (
	ProtocolAny  Protocol = "any"
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolICMP Protocol = "icmp"
)

type VPC struct {
	Name string `json:"name"`
}

type Subnet struct {
	Name            string       `json:"name"`
	VPC             string       `json:"vpc"`
	CIDR            netip.Prefix `json:"cidr"`
	Gateway         netip.Addr   `json:"gateway"`
	ProviderNetwork string       `json:"provider_network"`
	VLAN            uint16       `json:"vlan"`
	DHCP            DHCPOptions  `json:"dhcp"`
}

type DHCPOptions struct {
	Enabled   bool   `json:"enabled"`
	LeaseTime uint32 `json:"lease_time"`
	MTU       uint16 `json:"mtu"`
}

type Endpoint struct {
	ID             string     `json:"id"`
	VPC            string     `json:"vpc"`
	Subnet         string     `json:"subnet"`
	IP             netip.Addr `json:"ip"`
	Node           string     `json:"node"`
	SecurityGroups []string   `json:"security_groups"`
}

type RouteTable struct {
	Name   string  `json:"name"`
	VPC    string  `json:"vpc"`
	Routes []Route `json:"routes"`
}

type Route struct {
	Destination netip.Prefix `json:"destination"`
	NextHop     netip.Addr   `json:"next_hop"`
	NextHops    []netip.Addr `json:"next_hops"`
	Blackhole   bool         `json:"blackhole"`
}

type PolicyRoute struct {
	Name     string      `json:"name"`
	VPC      string      `json:"vpc"`
	Priority int         `json:"priority"`
	Match    RouteMatch  `json:"match"`
	Action   RouteAction `json:"action"`
}

type RouteMatch struct {
	Source      netip.Prefix `json:"source"`
	Destination netip.Prefix `json:"destination"`
	Protocol    Protocol     `json:"protocol"`
	DstPorts    []PortRange  `json:"dst_ports"`
}

type RouteAction struct {
	Type     Action       `json:"type"`
	NextHop  netip.Addr   `json:"next_hop"`
	NextHops []netip.Addr `json:"next_hops"`
}

type Gateway struct {
	Name        string     `json:"name"`
	VPC         string     `json:"vpc"`
	Node        string     `json:"node"`
	ExternalIF  string     `json:"external_if"`
	LANIP       netip.Addr `json:"lan_ip"`
	Distributed bool       `json:"distributed"`
}

type NATRule struct {
	Name         string       `json:"name"`
	VPC          string       `json:"vpc"`
	Type         Action       `json:"type"`
	MatchCIDR    netip.Prefix `json:"match_cidr"`
	ExternalIP   netip.Addr   `json:"external_ip"`
	TargetIP     netip.Addr   `json:"target_ip"`
	Protocol     Protocol     `json:"protocol"`
	ExternalPort uint16       `json:"external_port"`
	TargetPort   uint16       `json:"target_port"`
}

type LoadBalancer struct {
	Name            string                  `json:"name"`
	VPC             string                  `json:"vpc"`
	VIP             netip.Addr              `json:"vip"`
	Port            uint16                  `json:"port"`
	Protocol        Protocol                `json:"protocol"`
	Backends        []LoadBalancerBackend   `json:"backends"`
	Subnets         []string                `json:"subnets"`
	SessionAffinity bool                    `json:"session_affinity"`
	AffinityTimeout uint32                  `json:"affinity_timeout"`
	HealthCheck     LoadBalancerHealthCheck `json:"health_check"`
}

type LoadBalancerBackend struct {
	IP   netip.Addr `json:"ip"`
	Port uint16     `json:"port"`
}

type LoadBalancerHealthCheck struct {
	Enabled      bool   `json:"enabled"`
	Interval     uint32 `json:"interval"`
	Timeout      uint32 `json:"timeout"`
	SuccessCount uint32 `json:"success_count"`
	FailureCount uint32 `json:"failure_count"`
}

type SecurityGroup struct {
	Name  string              `json:"name"`
	VPC   string              `json:"vpc"`
	Rules []SecurityGroupRule `json:"rules"`
}

type CIDRGroup struct {
	Name  string         `json:"name"`
	VPC   string         `json:"vpc"`
	CIDRs []netip.Prefix `json:"cidrs"`
}

type SecurityGroupRule struct {
	ID              string         `json:"id"`
	Priority        int            `json:"priority"`
	Direction       Direction      `json:"direction"`
	Protocol        Protocol       `json:"protocol"`
	RemoteCIDR      netip.Prefix   `json:"remote_cidr"`
	ExceptCIDRs     []netip.Prefix `json:"except_cidrs"`
	RemoteGroup     string         `json:"remote_group"`
	RemoteCIDRGroup string         `json:"remote_cidr_group"`
	RemoteFQDNs     []FQDNSelector `json:"remote_fqdns"`
	Ports           []PortRange    `json:"ports"`
	Action          Action         `json:"action"`
	Stateful        bool           `json:"stateful"`
	Log             bool           `json:"log"`
	Description     string         `json:"description"`
}

type FQDNSelector struct {
	MatchName    string `json:"match_name"`
	MatchPattern string `json:"match_pattern"`
}

type DNSRecord struct {
	Name       string       `json:"name"`
	IPs        []netip.Addr `json:"ips"`
	TTLSeconds uint32       `json:"ttl_seconds"`
	ObservedAt time.Time    `json:"observed_at"`
}

type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}

func (v VPC) Validate() error {
	if v.Name == "" {
		return errors.New("vpc name is required")
	}
	return nil
}

func (s Subnet) Validate() error {
	if s.Name == "" {
		return errors.New("subnet name is required")
	}
	if s.VPC == "" {
		return errors.New("subnet vpc is required")
	}
	if !s.CIDR.IsValid() {
		return errors.New("subnet cidr is required")
	}
	if !s.Gateway.IsValid() {
		return errors.New("subnet gateway is required")
	}
	if !s.CIDR.Contains(s.Gateway) {
		return fmt.Errorf("subnet gateway %s is outside cidr %s", s.Gateway, s.CIDR)
	}
	if s.VLAN > 4094 {
		return errors.New("subnet vlan must be between 1 and 4094")
	}
	if s.VLAN != 0 && s.ProviderNetwork == "" {
		return errors.New("subnet vlan requires provider network")
	}
	if err := s.DHCP.Validate(); err != nil {
		return fmt.Errorf("subnet dhcp: %w", err)
	}
	return nil
}

func (d DHCPOptions) Validate() error {
	if !d.Enabled {
		if d.LeaseTime != 0 || d.MTU != 0 {
			return errors.New("disabled dhcp must not set lease time or mtu")
		}
		return nil
	}
	if d.LeaseTime != 0 && d.LeaseTime < 60 {
		return errors.New("dhcp lease time must be at least 60 seconds")
	}
	return nil
}

func (e Endpoint) Validate() error {
	if e.ID == "" {
		return errors.New("endpoint id is required")
	}
	if e.VPC == "" {
		return errors.New("endpoint vpc is required")
	}
	if e.Subnet == "" {
		return errors.New("endpoint subnet is required")
	}
	if !e.IP.IsValid() {
		return errors.New("endpoint ip is required")
	}
	if e.Node == "" {
		return errors.New("endpoint node is required")
	}
	return nil
}

func (r RouteTable) Validate() error {
	if r.Name == "" {
		return errors.New("route table name is required")
	}
	if r.VPC == "" {
		return errors.New("route table vpc is required")
	}
	for i, route := range r.Routes {
		if err := route.Validate(); err != nil {
			return fmt.Errorf("route %d: %w", i, err)
		}
	}
	return nil
}

func (r Route) Validate() error {
	if !r.Destination.IsValid() {
		return errors.New("route destination is required")
	}
	if r.Blackhole {
		if r.NextHop.IsValid() || len(r.NextHops) > 0 {
			return errors.New("blackhole route must not set next hop")
		}
		return nil
	}
	nextHops := r.RouteNextHops()
	if len(nextHops) == 0 {
		return errors.New("route next hop is required when route is not blackhole")
	}
	seen := make(map[netip.Addr]struct{}, len(nextHops))
	for _, nextHop := range nextHops {
		if !nextHop.IsValid() {
			return errors.New("route next hop is invalid")
		}
		if nextHop.Is4() != r.Destination.Addr().Is4() {
			return errors.New("route next hop family must match destination")
		}
		if _, ok := seen[nextHop]; ok {
			return fmt.Errorf("route next hop %s is duplicated", nextHop)
		}
		seen[nextHop] = struct{}{}
	}
	return nil
}

func (r Route) RouteNextHops() []netip.Addr {
	nextHops := make([]netip.Addr, 0, 1+len(r.NextHops))
	if r.NextHop.IsValid() {
		nextHops = append(nextHops, r.NextHop)
	}
	nextHops = append(nextHops, r.NextHops...)
	return nextHops
}

func (r PolicyRoute) Validate() error {
	if r.Name == "" {
		return errors.New("policy route name is required")
	}
	if r.VPC == "" {
		return errors.New("policy route vpc is required")
	}
	if r.Priority < 0 {
		return errors.New("policy route priority must be non-negative")
	}
	if r.Action.Type == "" {
		return errors.New("policy route action is required")
	}
	if !slices.Contains([]Action{ActionAllow, ActionDrop, ActionReroute}, r.Action.Type) {
		return fmt.Errorf("unsupported policy route action %q", r.Action.Type)
	}
	nextHops := r.Action.RerouteNextHops()
	if r.Action.Type == ActionReroute && len(nextHops) == 0 {
		return errors.New("policy route reroute action requires next hop")
	}
	if err := r.Match.Validate(); err != nil {
		return fmt.Errorf("policy route match: %w", err)
	}
	if r.Action.Type == ActionReroute {
		seen := make(map[netip.Addr]struct{}, len(nextHops))
		familyIs4 := nextHops[0].Is4()
		for i, nextHop := range nextHops {
			if !nextHop.IsValid() {
				return fmt.Errorf("policy route reroute next hop %d is invalid", i)
			}
			if nextHop.Is4() != familyIs4 {
				return errors.New("policy route reroute next hops must use the same IP family")
			}
			if _, ok := seen[nextHop]; ok {
				return fmt.Errorf("policy route reroute next hop %s is duplicated", nextHop)
			}
			seen[nextHop] = struct{}{}
			if r.Match.Destination.IsValid() && nextHop.Is4() != r.Match.Destination.Addr().Is4() {
				return errors.New("policy route reroute next hop family must match destination")
			}
			if !r.Match.Destination.IsValid() && r.Match.Source.IsValid() && nextHop.Is4() != r.Match.Source.Addr().Is4() {
				return errors.New("policy route reroute next hop family must match source")
			}
		}
	}
	return nil
}

func (a RouteAction) RerouteNextHops() []netip.Addr {
	nextHops := make([]netip.Addr, 0, 1+len(a.NextHops))
	if a.NextHop.IsValid() {
		nextHops = append(nextHops, a.NextHop)
	}
	nextHops = append(nextHops, a.NextHops...)
	return nextHops
}

func (m RouteMatch) Validate() error {
	if m.Protocol == "" {
		m.Protocol = ProtocolAny
	}
	if !validProtocol(m.Protocol) {
		return fmt.Errorf("unsupported protocol %q", m.Protocol)
	}
	if m.Source.IsValid() && m.Destination.IsValid() && m.Source.Addr().Is4() != m.Destination.Addr().Is4() {
		return errors.New("source and destination prefixes must use the same IP family")
	}
	if len(m.DstPorts) > 0 && m.Protocol != ProtocolTCP && m.Protocol != ProtocolUDP {
		return errors.New("dst ports require tcp or udp protocol")
	}
	for i, p := range m.DstPorts {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("dst port range %d: %w", i, err)
		}
	}
	return nil
}

func (g Gateway) Validate() error {
	if g.Name == "" {
		return errors.New("gateway name is required")
	}
	if g.VPC == "" {
		return errors.New("gateway vpc is required")
	}
	if g.Node == "" {
		return errors.New("gateway node is required")
	}
	if !g.LANIP.IsValid() {
		return errors.New("gateway lan ip is required")
	}
	return nil
}

func (n NATRule) Validate() error {
	if n.Name == "" {
		return errors.New("nat rule name is required")
	}
	if n.VPC == "" {
		return errors.New("nat rule vpc is required")
	}
	if !slices.Contains([]Action{ActionSNAT, ActionDNAT, ActionDNATSNAT}, n.Type) {
		return fmt.Errorf("unsupported nat action %q", n.Type)
	}
	if !n.ExternalIP.IsValid() {
		return errors.New("nat external ip is required")
	}
	if n.Protocol == "" {
		n.Protocol = ProtocolAny
	}
	if !validProtocol(n.Protocol) {
		return fmt.Errorf("unsupported nat protocol %q", n.Protocol)
	}
	hasPortMapping := n.ExternalPort != 0 || n.TargetPort != 0
	switch n.Type {
	case ActionSNAT:
		if !n.MatchCIDR.IsValid() {
			return errors.New("snat match cidr is required")
		}
		if n.ExternalIP.Is4() != n.MatchCIDR.Addr().Is4() {
			return errors.New("snat external ip family must match cidr")
		}
		if n.TargetIP.IsValid() {
			return errors.New("snat target ip must be empty")
		}
		if hasPortMapping {
			return errors.New("snat port mapping is not supported")
		}
		if n.Protocol != ProtocolAny {
			return errors.New("snat protocol must be any")
		}
	case ActionDNAT:
		if !n.TargetIP.IsValid() {
			return errors.New("dnat target ip is required")
		}
		if n.ExternalIP.Is4() != n.TargetIP.Is4() {
			return errors.New("dnat external ip family must match target ip")
		}
		if hasPortMapping {
			if n.ExternalPort == 0 || n.TargetPort == 0 {
				return errors.New("dnat port mapping requires both external and target ports")
			}
			if n.ExternalPort != n.TargetPort {
				return errors.New("dnat port translation is not supported")
			}
			if n.Protocol != ProtocolTCP && n.Protocol != ProtocolUDP {
				return errors.New("dnat port mapping requires tcp or udp protocol")
			}
		}
	case ActionDNATSNAT:
		if !n.TargetIP.IsValid() {
			return errors.New("dnat_and_snat target ip is required")
		}
		if n.ExternalIP.Is4() != n.TargetIP.Is4() {
			return errors.New("dnat_and_snat external ip family must match target ip")
		}
		if hasPortMapping {
			return errors.New("dnat_and_snat port mapping is not supported")
		}
		if n.Protocol != ProtocolAny {
			return errors.New("dnat_and_snat protocol must be any")
		}
	}
	return nil
}

func (l LoadBalancer) Validate() error {
	if l.Name == "" {
		return errors.New("load balancer name is required")
	}
	if l.VPC == "" {
		return errors.New("load balancer vpc is required")
	}
	if !l.VIP.IsValid() {
		return errors.New("load balancer vip is required")
	}
	if l.Port == 0 {
		return errors.New("load balancer port is required")
	}
	if l.Protocol == "" {
		l.Protocol = ProtocolTCP
	}
	if l.Protocol != ProtocolTCP && l.Protocol != ProtocolUDP {
		return fmt.Errorf("unsupported load balancer protocol %q", l.Protocol)
	}
	if len(l.Backends) == 0 {
		return errors.New("load balancer backends are required")
	}
	if !l.SessionAffinity && l.AffinityTimeout != 0 {
		return errors.New("load balancer affinity timeout requires session affinity")
	}
	if l.AffinityTimeout > 86400 {
		return errors.New("load balancer affinity timeout must be at most 86400 seconds")
	}
	if err := l.HealthCheck.Validate(); err != nil {
		return fmt.Errorf("load balancer health check: %w", err)
	}
	for i, backend := range l.Backends {
		if err := backend.Validate(); err != nil {
			return fmt.Errorf("load balancer backend %d: %w", i, err)
		}
		if backend.IP.Is4() != l.VIP.Is4() {
			return fmt.Errorf("load balancer backend %d ip family must match vip", i)
		}
	}
	for i, subnet := range l.Subnets {
		if subnet == "" {
			return fmt.Errorf("load balancer subnet %d is empty", i)
		}
	}
	return nil
}

func (h LoadBalancerHealthCheck) Validate() error {
	if !h.Enabled {
		if h.Interval != 0 || h.Timeout != 0 || h.SuccessCount != 0 || h.FailureCount != 0 {
			return errors.New("disabled health check must not set interval, timeout, success count or failure count")
		}
		return nil
	}
	if h.Interval > 86400 {
		return errors.New("health check interval must be at most 86400 seconds")
	}
	if h.Timeout > 86400 {
		return errors.New("health check timeout must be at most 86400 seconds")
	}
	if h.SuccessCount > 255 {
		return errors.New("health check success count must be at most 255")
	}
	if h.FailureCount > 255 {
		return errors.New("health check failure count must be at most 255")
	}
	return nil
}

func (b LoadBalancerBackend) Validate() error {
	if !b.IP.IsValid() {
		return errors.New("backend ip is required")
	}
	if b.Port == 0 {
		return errors.New("backend port is required")
	}
	return nil
}

func (s SecurityGroup) Validate() error {
	if s.Name == "" {
		return errors.New("security group name is required")
	}
	if s.VPC == "" {
		return errors.New("security group vpc is required")
	}
	for i, rule := range s.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("security group rule %d: %w", i, err)
		}
	}
	return nil
}

func (g CIDRGroup) Validate() error {
	if g.Name == "" {
		return errors.New("cidr group name is required")
	}
	if g.VPC == "" {
		return errors.New("cidr group vpc is required")
	}
	if len(g.CIDRs) == 0 {
		return errors.New("cidr group cidrs are required")
	}
	seen := make(map[netip.Prefix]struct{}, len(g.CIDRs))
	for i, cidr := range g.CIDRs {
		if !cidr.IsValid() {
			return fmt.Errorf("cidr group cidr %d is invalid", i)
		}
		cidr = cidr.Masked()
		if _, ok := seen[cidr]; ok {
			return fmt.Errorf("cidr group cidr %s is duplicated", cidr)
		}
		seen[cidr] = struct{}{}
	}
	return nil
}

func (r SecurityGroupRule) Validate() error {
	if r.ID == "" {
		return errors.New("rule id is required")
	}
	if r.Direction != DirectionIngress && r.Direction != DirectionEgress {
		return fmt.Errorf("unsupported direction %q", r.Direction)
	}
	if r.Protocol == "" {
		r.Protocol = ProtocolAny
	}
	if !validProtocol(r.Protocol) {
		return fmt.Errorf("unsupported protocol %q", r.Protocol)
	}
	if !slices.Contains([]Action{ActionAllow, ActionDrop, ActionReject, ActionLog}, r.Action) {
		return fmt.Errorf("unsupported security action %q", r.Action)
	}
	if len(r.Ports) > 0 && r.Protocol != ProtocolTCP && r.Protocol != ProtocolUDP {
		return errors.New("ports require tcp or udp protocol")
	}
	remoteSelectors := 0
	if r.RemoteCIDR.IsValid() {
		remoteSelectors++
	}
	if r.RemoteGroup != "" {
		remoteSelectors++
	}
	if r.RemoteCIDRGroup != "" {
		remoteSelectors++
	}
	if len(r.RemoteFQDNs) > 0 {
		remoteSelectors++
	}
	if remoteSelectors > 1 {
		return errors.New("remote cidr, remote group, remote cidr group and remote fqdns are mutually exclusive")
	}
	if len(r.ExceptCIDRs) > 0 && !r.RemoteCIDR.IsValid() {
		return errors.New("except cidrs require remote cidr")
	}
	for i, except := range r.ExceptCIDRs {
		if !except.IsValid() {
			return fmt.Errorf("except cidr %d is invalid", i)
		}
		except = except.Masked()
		if except.Addr().Is4() != r.RemoteCIDR.Addr().Is4() {
			return fmt.Errorf("except cidr %s family must match remote cidr", except)
		}
		if !prefixContainsPrefix(r.RemoteCIDR.Masked(), except) {
			return fmt.Errorf("except cidr %s must be contained within remote cidr %s", except, r.RemoteCIDR.Masked())
		}
	}
	if len(r.RemoteFQDNs) > 0 && r.Direction != DirectionEgress {
		return errors.New("remote fqdns are only supported for egress rules")
	}
	for i, selector := range r.RemoteFQDNs {
		if err := selector.Validate(); err != nil {
			return fmt.Errorf("remote fqdn %d: %w", i, err)
		}
	}
	for i, p := range r.Ports {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("port range %d: %w", i, err)
		}
	}
	return nil
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

func (s FQDNSelector) Validate() error {
	matchName := strings.TrimSpace(s.MatchName)
	matchPattern := strings.TrimSpace(s.MatchPattern)
	switch {
	case matchName == "" && matchPattern == "":
		return errors.New("match name or match pattern is required")
	case matchName != "" && matchPattern != "":
		return errors.New("match name and match pattern are mutually exclusive")
	case matchName != "":
		return validateDNSName(matchName, false)
	default:
		return validateDNSName(matchPattern, true)
	}
}

func (r DNSRecord) Validate() error {
	if err := validateDNSName(r.Name, false); err != nil {
		return fmt.Errorf("dns record name: %w", err)
	}
	if len(r.IPs) == 0 {
		return errors.New("dns record ips are required")
	}
	if r.TTLSeconds > 0 && r.ObservedAt.IsZero() {
		return errors.New("dns record observed_at is required when ttl_seconds is set")
	}
	if r.TTLSeconds == 0 && !r.ObservedAt.IsZero() {
		return errors.New("dns record observed_at requires ttl_seconds")
	}
	for i, ip := range r.IPs {
		if !ip.IsValid() {
			return fmt.Errorf("dns record ip %d is invalid", i)
		}
	}
	return nil
}

func (r DNSRecord) IsExpired(now time.Time) bool {
	if r.TTLSeconds == 0 {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	expiresAt := r.ObservedAt.Add(time.Duration(r.TTLSeconds) * time.Second)
	return !now.Before(expiresAt)
}

func validateDNSName(name string, allowWildcard bool) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("dns name is required")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '.':
		case allowWildcard && r == '*':
		default:
			return fmt.Errorf("dns name %q contains unsupported character %q", name, r)
		}
	}
	return nil
}

func (p PortRange) Validate() error {
	if p.From == 0 || p.To == 0 {
		return errors.New("port range must be non-zero")
	}
	if p.From > p.To {
		return fmt.Errorf("port range start %d exceeds end %d", p.From, p.To)
	}
	return nil
}

func validProtocol(p Protocol) bool {
	return slices.Contains([]Protocol{ProtocolAny, ProtocolTCP, ProtocolUDP, ProtocolICMP}, p)
}
