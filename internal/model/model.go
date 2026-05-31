package model

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
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

const (
	SecurityGroupPriorityMin = 1
	SecurityGroupPriorityMax = 16384
)

type VPC struct {
	Name string `json:"name"`
}

type Subnet struct {
	Name            string         `json:"name"`
	VPC             string         `json:"vpc"`
	CIDR            netip.Prefix   `json:"cidr"`
	Gateway         netip.Addr     `json:"gateway"`
	ExcludeCIDRs    []netip.Prefix `json:"exclude_cidrs"`
	ProviderNetwork string         `json:"provider_network"`
	VLAN            uint16         `json:"vlan"`
	DHCP            DHCPOptions    `json:"dhcp"`
}

type DHCPOptions struct {
	Enabled       bool         `json:"enabled"`
	LeaseTime     uint32       `json:"lease_time"`
	MTU           uint16       `json:"mtu"`
	DNSServers    []netip.Addr `json:"dns_servers"`
	DomainName    string       `json:"domain_name"`
	SearchDomains []string     `json:"search_domains"`
}

type Endpoint struct {
	ID             string      `json:"id"`
	VPC            string      `json:"vpc"`
	Subnet         string      `json:"subnet"`
	IP             netip.Addr  `json:"ip"`
	MAC            string      `json:"mac"`
	Node           string      `json:"node"`
	SecurityGroups []string    `json:"security_groups"`
	NamedPorts     []NamedPort `json:"named_ports"`
	Labels         Labels      `json:"labels"`
}

type RouteTable struct {
	Name   string  `json:"name"`
	VPC    string  `json:"vpc"`
	Routes []Route `json:"routes"`
}

type Route struct {
	Destination netip.Prefix `json:"destination"`
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
	SrcPorts    []PortRange  `json:"src_ports"`
	DstPorts    []PortRange  `json:"dst_ports"`
}

type RouteAction struct {
	Type     Action       `json:"type"`
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
	LogicalPort  string       `json:"logical_port"`
	ExternalMAC  string       `json:"external_mac"`
}

type LoadBalancer struct {
	Name            string                  `json:"name"`
	VPC             string                  `json:"vpc"`
	VIP             netip.Addr              `json:"vip"`
	Ports           []LoadBalancerPort      `json:"ports"`
	Subnets         []string                `json:"subnets"`
	SessionAffinity bool                    `json:"session_affinity"`
	AffinityTimeout uint32                  `json:"affinity_timeout"`
	SelectionFields []string                `json:"selection_fields"`
	HealthCheck     LoadBalancerHealthCheck `json:"health_check"`
}

type LoadBalancerPort struct {
	Name     string                `json:"name"`
	Port     uint16                `json:"port"`
	Protocol Protocol              `json:"protocol"`
	Backends []LoadBalancerBackend `json:"backends"`
}

type LoadBalancerFrontend struct {
	Name     string
	VIP      netip.Addr
	Port     uint16
	Protocol Protocol
	Backends []LoadBalancerBackend
}

type LoadBalancerBackend struct {
	IP      netip.Addr `json:"ip"`
	Port    uint16     `json:"port"`
	Healthy *bool      `json:"healthy,omitempty"`
}

type LoadBalancerHealthCheck struct {
	Enabled      bool   `json:"enabled"`
	Interval     uint32 `json:"interval"`
	Timeout      uint32 `json:"timeout"`
	SuccessCount uint32 `json:"success_count"`
	FailureCount uint32 `json:"failure_count"`
}

type SecurityGroup struct {
	Name               string              `json:"name"`
	VPC                string              `json:"vpc"`
	Tier               int                 `json:"tier"`
	DefaultDenyIngress *bool               `json:"default_deny_ingress,omitempty"`
	DefaultDenyEgress  *bool               `json:"default_deny_egress,omitempty"`
	Rules              []SecurityGroupRule `json:"rules"`
}

type CIDRGroup struct {
	Name    string           `json:"name"`
	VPC     string           `json:"vpc"`
	CIDRs   []netip.Prefix   `json:"cidrs"`
	Entries []CIDRGroupEntry `json:"entries"`
}

type CIDRGroupEntry struct {
	CIDR        netip.Prefix   `json:"cidr"`
	ExceptCIDRs []netip.Prefix `json:"except_cidrs"`
}

type SecurityGroupRule struct {
	ID                     string         `json:"id"`
	Priority               int            `json:"priority"`
	Direction              Direction      `json:"direction"`
	Protocol               Protocol       `json:"protocol"`
	RemoteCIDR             netip.Prefix   `json:"remote_cidr"`
	ExceptCIDRs            []netip.Prefix `json:"except_cidrs"`
	RemoteGroup            string         `json:"remote_group"`
	RemoteEndpointSelector Labels         `json:"remote_endpoint_selector"`
	RemoteEndpointExprs    []LabelExpr    `json:"remote_endpoint_expressions"`
	RemoteService          string         `json:"remote_service"`
	RemoteCIDRGroup        string         `json:"remote_cidr_group"`
	RemoteEntities         []string       `json:"remote_entities"`
	RemoteFQDNs            []FQDNSelector `json:"remote_fqdns"`
	Ports                  []PortRange    `json:"ports"`
	NamedPorts             []string       `json:"named_ports"`
	ICMPType               *uint8         `json:"icmp_type,omitempty"`
	ICMPCode               *uint8         `json:"icmp_code,omitempty"`
	Action                 Action         `json:"action"`
	Stateful               bool           `json:"stateful"`
	Log                    bool           `json:"log"`
	Description            string         `json:"description"`
}

type Labels map[string]string

type LabelExpr struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type NamedPort struct {
	Name     string   `json:"name"`
	Protocol Protocol `json:"protocol"`
	Port     uint16   `json:"port"`
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
	seenExcludeCIDRs := make(map[netip.Prefix]struct{}, len(s.ExcludeCIDRs))
	for i, exclude := range s.ExcludeCIDRs {
		if !exclude.IsValid() {
			return fmt.Errorf("subnet exclude cidr %d is invalid", i)
		}
		exclude = exclude.Masked()
		if exclude.Addr().Is4() != s.CIDR.Addr().Is4() {
			return fmt.Errorf("subnet exclude cidr %s family must match cidr %s", exclude, s.CIDR)
		}
		if !s.CIDR.Contains(exclude.Addr()) || !s.CIDR.Contains(prefixLastAddr(exclude)) {
			return fmt.Errorf("subnet exclude cidr %s is outside cidr %s", exclude, s.CIDR)
		}
		if _, ok := seenExcludeCIDRs[exclude]; ok {
			return fmt.Errorf("subnet exclude cidr %s is duplicated", exclude)
		}
		seenExcludeCIDRs[exclude] = struct{}{}
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

func (s Subnet) Excludes(ip netip.Addr) bool {
	for _, exclude := range s.ExcludeCIDRs {
		if exclude.Contains(ip) {
			return true
		}
	}
	return false
}

func (d DHCPOptions) Validate() error {
	if !d.Enabled {
		if d.LeaseTime != 0 || d.MTU != 0 || len(d.DNSServers) != 0 || d.DomainName != "" || len(d.SearchDomains) != 0 {
			return errors.New("disabled dhcp must not set lease time, mtu, dns servers, domain name, or search domains")
		}
		return nil
	}
	if d.LeaseTime != 0 && d.LeaseTime < 60 {
		return errors.New("dhcp lease time must be at least 60 seconds")
	}
	for i, server := range d.DNSServers {
		if !server.IsValid() {
			return fmt.Errorf("dhcp dns server %d is invalid", i)
		}
	}
	if d.DomainName != "" {
		if err := validateDNSName(d.DomainName, false); err != nil {
			return fmt.Errorf("dhcp domain name: %w", err)
		}
	}
	for i, domain := range d.SearchDomains {
		if err := validateDNSName(domain, false); err != nil {
			return fmt.Errorf("dhcp search domain %d: %w", i, err)
		}
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
	if strings.TrimSpace(e.MAC) != "" {
		if _, err := net.ParseMAC(e.MAC); err != nil {
			return fmt.Errorf("endpoint mac is invalid: %w", err)
		}
	}
	if e.Node == "" {
		return errors.New("endpoint node is required")
	}
	if err := e.Labels.Validate(); err != nil {
		return fmt.Errorf("endpoint labels: %w", err)
	}
	seenGroups := make(map[string]struct{}, len(e.SecurityGroups))
	for _, group := range e.SecurityGroups {
		if group == "" {
			return errors.New("endpoint security group is empty")
		}
		if _, ok := seenGroups[group]; ok {
			return fmt.Errorf("endpoint security group %q is duplicated", group)
		}
		seenGroups[group] = struct{}{}
	}
	seenPorts := make(map[string]struct{}, len(e.NamedPorts))
	for i, port := range e.NamedPorts {
		if err := port.Validate(); err != nil {
			return fmt.Errorf("named port %d: %w", i, err)
		}
		key := string(port.Protocol) + "/" + port.Name
		if _, ok := seenPorts[key]; ok {
			return fmt.Errorf("named port %s/%s is duplicated", port.Protocol, port.Name)
		}
		seenPorts[key] = struct{}{}
	}
	return nil
}

func (l Labels) Validate() error {
	for key, value := range l {
		if strings.TrimSpace(key) == "" {
			return errors.New("label key is required")
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("label %q value is required", key)
		}
		if strings.ContainsAny(key, " \t\r\n") {
			return fmt.Errorf("label key %q must not contain whitespace", key)
		}
	}
	return nil
}

func (l Labels) Matches(selector Labels) bool {
	if len(selector) == 0 {
		return false
	}
	for key, value := range selector {
		if l[key] != value {
			return false
		}
	}
	return true
}

func (l Labels) MatchesSelector(selector Labels, expressions []LabelExpr) bool {
	if len(selector) == 0 && len(expressions) == 0 {
		return false
	}
	for key, value := range selector {
		if l[key] != value {
			return false
		}
	}
	for _, expression := range expressions {
		if !expression.Matches(l) {
			return false
		}
	}
	return true
}

func (e LabelExpr) Validate() error {
	if strings.TrimSpace(e.Key) == "" {
		return errors.New("label expression key is required")
	}
	if strings.ContainsAny(e.Key, " \t\r\n") {
		return fmt.Errorf("label expression key %q must not contain whitespace", e.Key)
	}
	operator := normalizeLabelExprOperator(e.Operator)
	switch operator {
	case "in", "notin":
		if len(e.Values) == 0 {
			return fmt.Errorf("label expression %q operator %s requires values", e.Key, e.Operator)
		}
	case "exists", "doesnotexist":
		if len(e.Values) != 0 {
			return fmt.Errorf("label expression %q operator %s must not set values", e.Key, e.Operator)
		}
	default:
		return fmt.Errorf("unsupported label expression operator %q", e.Operator)
	}
	seen := make(map[string]struct{}, len(e.Values))
	for i, value := range e.Values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("label expression %q value %d is required", e.Key, i)
		}
		if _, ok := seen[value]; ok {
			return fmt.Errorf("label expression %q value %q is duplicated", e.Key, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func (e LabelExpr) Matches(labels Labels) bool {
	operator := normalizeLabelExprOperator(e.Operator)
	value, ok := labels[e.Key]
	switch operator {
	case "in":
		if !ok {
			return false
		}
		return slices.Contains(e.Values, value)
	case "notin":
		if !ok {
			return true
		}
		return !slices.Contains(e.Values, value)
	case "exists":
		return ok
	case "doesnotexist":
		return !ok
	default:
		return false
	}
}

func normalizeLabelExprOperator(operator string) string {
	operator = strings.ToLower(strings.TrimSpace(operator))
	operator = strings.ReplaceAll(operator, "_", "")
	operator = strings.ReplaceAll(operator, "-", "")
	return operator
}

func (e Endpoint) NormalizedMAC() string {
	if strings.TrimSpace(e.MAC) == "" {
		return ""
	}
	mac, err := net.ParseMAC(e.MAC)
	if err != nil {
		return ""
	}
	return mac.String()
}

func GatewayMAC(ip netip.Addr) string {
	if ip.Is4() {
		raw := ip.As4()
		return fmt.Sprintf("0a:58:%02x:%02x:%02x:%02x", raw[0], raw[1], raw[2], raw[3])
	}
	raw := ip.As16()
	return fmt.Sprintf("0a:58:%02x:%02x:%02x:%02x", raw[12], raw[13], raw[14], raw[15])
}

func SubnetGatewayMAC(vpc, subnet string, ip netip.Addr) string {
	sum := sha256.Sum256([]byte(vpc + "\x00" + subnet + "\x00" + ip.String()))
	return fmt.Sprintf("0a:58:%02x:%02x:%02x:%02x", sum[0], sum[1], sum[2], sum[3])
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
		if len(r.NextHops) > 0 {
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
	nextHops := make([]netip.Addr, 0, len(r.NextHops))
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
	if r.Action.Type != ActionReroute && len(nextHops) > 0 {
		return errors.New("policy route next hops are only supported for reroute action")
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
	nextHops := make([]netip.Addr, 0, len(a.NextHops))
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
	if len(m.SrcPorts) > 0 && m.Protocol != ProtocolTCP && m.Protocol != ProtocolUDP {
		return errors.New("src ports require tcp or udp protocol")
	}
	if len(m.DstPorts) > 0 && m.Protocol != ProtocolTCP && m.Protocol != ProtocolUDP {
		return errors.New("dst ports require tcp or udp protocol")
	}
	for i, p := range m.SrcPorts {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("src port range %d: %w", i, err)
		}
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
	if strings.TrimSpace(g.ExternalIF) == "" {
		return errors.New("gateway external_if is required")
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
	if err := n.validateDistributedNATFields(); err != nil {
		return err
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
			if n.ExternalPort == 0 || n.TargetPort == 0 {
				return errors.New("dnat_and_snat port mapping requires both external and target ports")
			}
			if n.Protocol != ProtocolTCP && n.Protocol != ProtocolUDP {
				return errors.New("dnat_and_snat port mapping requires tcp or udp protocol")
			}
		} else if n.Protocol != ProtocolAny {
			return errors.New("dnat_and_snat protocol must be any")
		}
	}
	return nil
}

func (n NATRule) validateDistributedNATFields() error {
	hasLogicalPort := strings.TrimSpace(n.LogicalPort) != ""
	hasExternalMAC := strings.TrimSpace(n.ExternalMAC) != ""
	if !hasLogicalPort && !hasExternalMAC {
		return nil
	}
	if n.Type != ActionDNATSNAT {
		return errors.New("logical_port and external_mac are only supported for dnat_and_snat")
	}
	if !hasLogicalPort || !hasExternalMAC {
		return errors.New("logical_port and external_mac must be set together")
	}
	if _, err := net.ParseMAC(n.ExternalMAC); err != nil {
		return fmt.Errorf("external_mac is invalid: %w", err)
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
	if len(l.Ports) == 0 {
		return errors.New("load balancer ports are required")
	}
	frontends := l.Frontends()
	if !l.SessionAffinity && l.AffinityTimeout != 0 {
		return errors.New("load balancer affinity timeout requires session affinity")
	}
	if l.AffinityTimeout > 86400 {
		return errors.New("load balancer affinity timeout must be at most 86400 seconds")
	}
	if err := l.validateSelectionFields(); err != nil {
		return err
	}
	if err := l.HealthCheck.Validate(); err != nil {
		return fmt.Errorf("load balancer health check: %w", err)
	}
	seenFrontends := make(map[string]struct{}, len(frontends))
	for i, frontend := range frontends {
		if frontend.Port == 0 {
			return fmt.Errorf("load balancer frontend %d port is required", i)
		}
		if frontend.Protocol != ProtocolTCP && frontend.Protocol != ProtocolUDP {
			return fmt.Errorf("unsupported load balancer protocol %q", frontend.Protocol)
		}
		if len(frontend.Backends) == 0 {
			return fmt.Errorf("load balancer frontend %d backends are required", i)
		}
		key := string(frontend.Protocol) + "/" + frontend.VIP.String() + "/" + fmt.Sprint(frontend.Port)
		if _, ok := seenFrontends[key]; ok {
			return fmt.Errorf("load balancer frontend %s/%s:%d is duplicated", frontend.VIP, frontend.Protocol, frontend.Port)
		}
		seenFrontends[key] = struct{}{}
		healthyBackends := 0
		seenBackends := make(map[string]struct{}, len(frontend.Backends))
		for j, backend := range frontend.Backends {
			if err := backend.Validate(); err != nil {
				return fmt.Errorf("load balancer frontend %d backend %d: %w", i, j, err)
			}
			if backend.IP.Is4() != l.VIP.Is4() {
				return fmt.Errorf("load balancer frontend %d backend %d ip family must match vip", i, j)
			}
			backendKey := netip.AddrPortFrom(backend.IP, backend.Port).String()
			if _, ok := seenBackends[backendKey]; ok {
				return fmt.Errorf("load balancer frontend %d backend %s is duplicated", i, backendKey)
			}
			seenBackends[backendKey] = struct{}{}
			if backend.IsHealthy() {
				healthyBackends++
			}
		}
		if healthyBackends == 0 {
			return fmt.Errorf("load balancer frontend %d must have at least one healthy backend", i)
		}
	}
	seenSubnets := make(map[string]struct{}, len(l.Subnets))
	for i, subnet := range l.Subnets {
		if subnet == "" {
			return fmt.Errorf("load balancer subnet %d is empty", i)
		}
		if _, ok := seenSubnets[subnet]; ok {
			return fmt.Errorf("load balancer subnet %q is duplicated", subnet)
		}
		seenSubnets[subnet] = struct{}{}
	}
	return nil
}

func (l LoadBalancer) Frontends() []LoadBalancerFrontend {
	frontends := make([]LoadBalancerFrontend, 0, len(l.Ports))
	for _, port := range l.Ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = ProtocolTCP
		}
		name := port.Name
		if name == "" {
			name = fmt.Sprintf("%s-%d", protocol, port.Port)
		}
		frontends = append(frontends, LoadBalancerFrontend{
			Name:     name,
			VIP:      l.VIP,
			Port:     port.Port,
			Protocol: protocol,
			Backends: append([]LoadBalancerBackend(nil), port.Backends...),
		})
	}
	return frontends
}

func (l LoadBalancer) validateSelectionFields() error {
	seen := make(map[string]struct{}, len(l.SelectionFields))
	for i, field := range l.SelectionFields {
		field = strings.TrimSpace(field)
		if field == "" {
			return fmt.Errorf("load balancer selection field %d is empty", i)
		}
		if _, ok := seen[field]; ok {
			return fmt.Errorf("load balancer selection field %q is duplicated", field)
		}
		seen[field] = struct{}{}
		switch field {
		case "ip_src", "ip_dst":
			if l.VIP.Is6() && !l.VIP.Is4() {
				return fmt.Errorf("load balancer selection field %q requires IPv4 VIP", field)
			}
		case "ipv6_src", "ipv6_dst":
			if l.VIP.Is4() {
				return fmt.Errorf("load balancer selection field %q requires IPv6 VIP", field)
			}
		case "tp_src", "tp_dst":
		default:
			return fmt.Errorf("unsupported load balancer selection field %q", field)
		}
	}
	return nil
}

func (l LoadBalancer) EffectiveSelectionFields() []string {
	fields := normalizedLoadBalancerSelectionFields(l.SelectionFields)
	if len(fields) > 0 {
		return fields
	}
	if !l.SessionAffinity {
		return nil
	}
	if l.VIP.Is6() && !l.VIP.Is4() {
		return []string{"ipv6_src"}
	}
	return []string{"ip_src"}
}

func normalizedLoadBalancerSelectionFields(fields []string) []string {
	normalized := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			normalized = append(normalized, field)
		}
	}
	slices.Sort(normalized)
	return normalized
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

func (b LoadBalancerBackend) IsHealthy() bool {
	return b.Healthy == nil || *b.Healthy
}

func (s SecurityGroup) Validate() error {
	if s.Name == "" {
		return errors.New("security group name is required")
	}
	if s.VPC == "" {
		return errors.New("security group vpc is required")
	}
	if s.Tier < 0 || s.Tier > 1 {
		return errors.New("security group tier must be between 0 and 1")
	}
	seenRules := make(map[string]struct{}, len(s.Rules))
	for i, rule := range s.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("security group rule %d: %w", i, err)
		}
		if _, ok := seenRules[rule.ID]; ok {
			return fmt.Errorf("security group rule %q is duplicated", rule.ID)
		}
		seenRules[rule.ID] = struct{}{}
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
	if len(g.CIDRs) == 0 && len(g.Entries) == 0 {
		return errors.New("cidr group cidrs or entries are required")
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
	for i, entry := range g.Entries {
		if err := entry.Validate(); err != nil {
			return fmt.Errorf("cidr group entry %d: %w", i, err)
		}
		cidr := entry.CIDR.Masked()
		if _, ok := seen[cidr]; ok {
			return fmt.Errorf("cidr group cidr %s is duplicated", cidr)
		}
		seen[cidr] = struct{}{}
	}
	return nil
}

func (e CIDRGroupEntry) Validate() error {
	if !e.CIDR.IsValid() {
		return errors.New("cidr is invalid")
	}
	cidr := e.CIDR.Masked()
	seen := make(map[netip.Prefix]struct{}, len(e.ExceptCIDRs))
	for i, except := range e.ExceptCIDRs {
		if !except.IsValid() {
			return fmt.Errorf("except cidr %d is invalid", i)
		}
		except = except.Masked()
		if except.Addr().Is4() != cidr.Addr().Is4() {
			return fmt.Errorf("except cidr %s family must match cidr", except)
		}
		if !prefixContainsPrefix(cidr, except) {
			return fmt.Errorf("except cidr %s must be contained within cidr %s", except, cidr)
		}
		if _, ok := seen[except]; ok {
			return fmt.Errorf("except cidr %s is duplicated", except)
		}
		seen[except] = struct{}{}
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
	if r.Priority < SecurityGroupPriorityMin || r.Priority > SecurityGroupPriorityMax {
		return fmt.Errorf("security group rule priority must be between %d and %d", SecurityGroupPriorityMin, SecurityGroupPriorityMax)
	}
	if !slices.Contains([]Action{ActionAllow, ActionDrop, ActionReject, ActionLog}, r.Action) {
		return fmt.Errorf("unsupported security action %q", r.Action)
	}
	if len(r.Ports) > 0 && r.Protocol != ProtocolTCP && r.Protocol != ProtocolUDP && !(r.Protocol == ProtocolAny && r.RemoteService != "") {
		return errors.New("ports require tcp or udp protocol")
	}
	if len(r.NamedPorts) > 0 && r.Protocol != ProtocolTCP && r.Protocol != ProtocolUDP {
		return errors.New("named ports require tcp or udp protocol")
	}
	seenNamedPorts := make(map[string]struct{}, len(r.NamedPorts))
	for i, name := range r.NamedPorts {
		if err := validateNamedPortName(name); err != nil {
			return fmt.Errorf("named port %d: %w", i, err)
		}
		if _, ok := seenNamedPorts[name]; ok {
			return fmt.Errorf("named port %s is duplicated", name)
		}
		seenNamedPorts[name] = struct{}{}
	}
	if r.ICMPType != nil && r.Protocol != ProtocolICMP {
		return errors.New("icmp_type requires icmp protocol")
	}
	if r.ICMPCode != nil && r.Protocol != ProtocolICMP {
		return errors.New("icmp_code requires icmp protocol")
	}
	if r.ICMPCode != nil && r.ICMPType == nil {
		return errors.New("icmp_code requires icmp_type")
	}
	remoteSelectors := 0
	if r.RemoteCIDR.IsValid() {
		remoteSelectors++
	}
	if r.RemoteGroup != "" {
		remoteSelectors++
	}
	if len(r.RemoteEndpointSelector) > 0 || len(r.RemoteEndpointExprs) > 0 {
		remoteSelectors++
	}
	if r.RemoteService != "" {
		remoteSelectors++
	}
	if r.RemoteCIDRGroup != "" {
		remoteSelectors++
	}
	if len(r.RemoteEntities) > 0 {
		remoteSelectors++
	}
	if len(r.RemoteFQDNs) > 0 {
		remoteSelectors++
	}
	if remoteSelectors > 1 {
		return errors.New("remote cidr, remote group, remote endpoint selector, remote service, remote cidr group, remote entities and remote fqdns are mutually exclusive")
	}
	if r.RemoteService != "" && r.Direction != DirectionEgress {
		return errors.New("remote service is only supported for egress rules")
	}
	if err := r.RemoteEndpointSelector.Validate(); err != nil {
		return fmt.Errorf("remote endpoint selector: %w", err)
	}
	for i, expression := range r.RemoteEndpointExprs {
		if err := expression.Validate(); err != nil {
			return fmt.Errorf("remote endpoint expression %d: %w", i, err)
		}
	}
	seenEntities := make(map[string]struct{}, len(r.RemoteEntities))
	for i, entity := range r.RemoteEntities {
		switch entity {
		case "all", "world", "world-ipv4", "world-ipv6", "cluster", "private", "host", "remote-node", "none":
		default:
			return fmt.Errorf("remote entity %d: unsupported remote entity %q", i, entity)
		}
		if _, ok := seenEntities[entity]; ok {
			return fmt.Errorf("remote entity %q is duplicated", entity)
		}
		seenEntities[entity] = struct{}{}
	}
	if _, ok := seenEntities["none"]; ok && len(seenEntities) > 1 {
		return errors.New("remote entity none must not be combined with other remote entities")
	}
	if len(r.ExceptCIDRs) > 0 && !r.RemoteCIDR.IsValid() {
		return errors.New("except cidrs require remote cidr")
	}
	seenExceptCIDRs := make(map[netip.Prefix]struct{}, len(r.ExceptCIDRs))
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
		if _, ok := seenExceptCIDRs[except]; ok {
			return fmt.Errorf("except cidr %s is duplicated", except)
		}
		seenExceptCIDRs[except] = struct{}{}
	}
	if len(r.RemoteFQDNs) > 0 && r.Direction != DirectionEgress {
		return errors.New("remote fqdns are only supported for egress rules")
	}
	for i, selector := range r.RemoteFQDNs {
		if err := selector.Validate(); err != nil {
			return fmt.Errorf("remote fqdn %d: %w", i, err)
		}
	}
	seenPorts := make(map[PortRange]struct{}, len(r.Ports))
	for i, p := range r.Ports {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("port range %d: %w", i, err)
		}
		if _, ok := seenPorts[p]; ok {
			return fmt.Errorf("port range %d %d-%d is duplicated", i, p.From, p.To)
		}
		seenPorts[p] = struct{}{}
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
	seenIPs := make(map[netip.Addr]struct{}, len(r.IPs))
	for i, ip := range r.IPs {
		if !ip.IsValid() {
			return fmt.Errorf("dns record ip %d is invalid", i)
		}
		if _, ok := seenIPs[ip]; ok {
			return fmt.Errorf("dns record ip %s is duplicated", ip)
		}
		seenIPs[ip] = struct{}{}
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
		case r == '-' || r == '.' || r == '_':
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

func (p NamedPort) Validate() error {
	if err := validateNamedPortName(p.Name); err != nil {
		return err
	}
	if p.Protocol != ProtocolTCP && p.Protocol != ProtocolUDP {
		return errors.New("named port protocol must be tcp or udp")
	}
	if p.Port == 0 {
		return errors.New("named port number must be between 1 and 65535")
	}
	return nil
}

func validateNamedPortName(name string) error {
	if name == "" {
		return errors.New("named port name is required")
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return fmt.Errorf("named port name %q contains unsupported character %q", name, r)
	}
	return nil
}

func validProtocol(p Protocol) bool {
	return slices.Contains([]Protocol{ProtocolAny, ProtocolTCP, ProtocolUDP, ProtocolICMP}, p)
}
