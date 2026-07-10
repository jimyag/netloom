package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
	"github.com/jimyag/netloom/internal/topology"
)

type TopologyBackend interface {
	EnsureVPC(context.Context, model.VPC) error
	EnsureSubnet(context.Context, model.Subnet) error
	EnsureEndpoint(context.Context, model.Endpoint) error
	EnsureRouteTable(context.Context, model.RouteTable) error
	EnsurePolicyRoute(context.Context, model.PolicyRoute) error
	EnsureGateway(context.Context, model.Gateway) error
	EnsureNATRule(context.Context, model.NATRule) error
	EnsureLoadBalancer(context.Context, model.LoadBalancer) error
}

type TopologyLifecycleBackend interface {
	BeginTopologyReconcile(context.Context, topology.State) error
	CleanupTopology(context.Context, topology.State) error
}

type MultiTopologyBackend []TopologyBackend

func (m MultiTopologyBackend) BeginTopologyReconcile(ctx context.Context, state topology.State) error {
	for _, backend := range m {
		if lifecycle, ok := backend.(TopologyLifecycleBackend); ok {
			if err := lifecycle.BeginTopologyReconcile(ctx, state); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m MultiTopologyBackend) CleanupTopology(ctx context.Context, state topology.State) error {
	for _, backend := range m {
		if lifecycle, ok := backend.(TopologyLifecycleBackend); ok {
			if err := lifecycle.CleanupTopology(ctx, state); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsureVPC(ctx context.Context, vpc model.VPC) error {
	for _, backend := range m {
		if err := backend.EnsureVPC(ctx, vpc); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsureSubnet(ctx context.Context, subnet model.Subnet) error {
	for _, backend := range m {
		if err := backend.EnsureSubnet(ctx, subnet); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsureEndpoint(ctx context.Context, endpoint model.Endpoint) error {
	for _, backend := range m {
		if err := backend.EnsureEndpoint(ctx, endpoint); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsureRouteTable(ctx context.Context, table model.RouteTable) error {
	for _, backend := range m {
		if err := backend.EnsureRouteTable(ctx, table); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsurePolicyRoute(ctx context.Context, route model.PolicyRoute) error {
	for _, backend := range m {
		if err := backend.EnsurePolicyRoute(ctx, route); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsureGateway(ctx context.Context, gateway model.Gateway) error {
	for _, backend := range m {
		if err := backend.EnsureGateway(ctx, gateway); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsureNATRule(ctx context.Context, rule model.NATRule) error {
	for _, backend := range m {
		if err := backend.EnsureNATRule(ctx, rule); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTopologyBackend) EnsureLoadBalancer(ctx context.Context, lb model.LoadBalancer) error {
	for _, backend := range m {
		if err := backend.EnsureLoadBalancer(ctx, lb); err != nil {
			return err
		}
	}
	return nil
}

type PolicyBackend interface {
	ApplyEndpointProgram(context.Context, policy.Program) error
}

type PolicyLifecycleBackend interface {
	CleanupPolicy(context.Context, DesiredState) error
}

type DesiredState struct {
	VPCs             []model.VPC             `json:"vpcs"`
	ProviderNetworks []model.ProviderNetwork `json:"provider_networks"`
	Subnets          []model.Subnet          `json:"subnets"`
	Endpoints        []model.Endpoint        `json:"endpoints"`
	RouteTables      []model.RouteTable      `json:"route_tables"`
	PolicyRoutes     []model.PolicyRoute     `json:"policy_routes"`
	Gateways         []model.Gateway         `json:"gateways"`
	NATRules         []model.NATRule         `json:"nat_rules"`
	LoadBalancers    []model.LoadBalancer    `json:"load_balancers"`
	SecurityGroups   []model.SecurityGroup   `json:"security_groups"`
	CIDRGroups       []model.CIDRGroup       `json:"cidr_groups"`
	DNSRecords       []model.DNSRecord       `json:"dns_records"`
	PolicyRollouts   []PolicyRollout         `json:"policy_rollouts"`
}

type PolicyRollout struct {
	Name                      string               `json:"name"`
	Node                      string               `json:"node,omitempty"`
	Endpoints                 []string             `json:"endpoints,omitempty"`
	BatchSize                 int                  `json:"batch_size"`
	PressureAware             bool                 `json:"pressure_aware"`
	PressureThresholdPercent  uint32               `json:"pressure_threshold_percent"`
	PressureAwareMinBatchSize int                  `json:"pressure_aware_min_batch_size"`
	SLOGated                  bool                 `json:"slo_gated"`
	SLODropThresholdPercent   uint32               `json:"slo_drop_threshold_percent"`
	SLOMinPackets             uint64               `json:"slo_min_packets"`
	SLOWindowCount            int                  `json:"slo_window_count"`
	SLOWindowIntervalMS       uint32               `json:"slo_window_interval_ms"`
	Probes                    []PolicyRolloutProbe `json:"probes,omitempty"`
	ApprovalRequired          bool                 `json:"approval_required,omitempty"`
	Approved                  bool                 `json:"approved,omitempty"`
	ApprovalRef               string               `json:"approval_ref,omitempty"`
	ApprovalSignature         string               `json:"approval_signature,omitempty"`
	ApprovalCallbackURL       string               `json:"approval_callback_url,omitempty"`
	ApprovalCallbackTimeoutMS uint32               `json:"approval_callback_timeout_ms,omitempty"`
	Paused                    bool                 `json:"paused,omitempty"`
	PauseAfterBatches         int                  `json:"pause_after_batches,omitempty"`
	PromotionPercent          uint32               `json:"promotion_percent,omitempty"`
	Disabled                  bool                 `json:"disabled,omitempty"`
}

type PolicyRolloutProbe struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	URL            string `json:"url,omitempty"`
	Address        string `json:"address,omitempty"`
	Method         string `json:"method,omitempty"`
	ExpectedStatus int    `json:"expected_status,omitempty"`
	TimeoutMS      uint32 `json:"timeout_ms,omitempty"`
}

func (r PolicyRollout) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("policy rollout name is required")
	}
	if r.BatchSize < 0 {
		return fmt.Errorf("policy rollout %q batch_size must not be negative", r.Name)
	}
	if r.PressureThresholdPercent > 100 {
		return fmt.Errorf("policy rollout %q pressure_threshold_percent must be <= 100", r.Name)
	}
	if r.PressureAwareMinBatchSize < 0 {
		return fmt.Errorf("policy rollout %q pressure_aware_min_batch_size must not be negative", r.Name)
	}
	if r.SLODropThresholdPercent > 100 {
		return fmt.Errorf("policy rollout %q slo_drop_threshold_percent must be <= 100", r.Name)
	}
	if r.SLOWindowCount < 0 {
		return fmt.Errorf("policy rollout %q slo_window_count must not be negative", r.Name)
	}
	if r.PauseAfterBatches < 0 {
		return fmt.Errorf("policy rollout %q pause_after_batches must not be negative", r.Name)
	}
	if r.PromotionPercent > 100 {
		return fmt.Errorf("policy rollout %q promotion_percent must be <= 100", r.Name)
	}
	if strings.TrimSpace(r.ApprovalCallbackURL) != "" {
		parsed, err := url.Parse(r.ApprovalCallbackURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("policy rollout %q approval_callback_url must be http or https", r.Name)
		}
	}
	seenProbes := make(map[string]struct{}, len(r.Probes))
	for _, probe := range r.Probes {
		if err := probe.Validate(r.Name); err != nil {
			return err
		}
		name := strings.TrimSpace(probe.Name)
		if _, ok := seenProbes[name]; ok {
			return fmt.Errorf("policy rollout %q probe %q is duplicated", r.Name, name)
		}
		seenProbes[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(r.Endpoints))
	for _, endpoint := range r.Endpoints {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			return fmt.Errorf("policy rollout %q endpoint is empty", r.Name)
		}
		if _, ok := seen[endpoint]; ok {
			return fmt.Errorf("policy rollout %q endpoint %q is duplicated", r.Name, endpoint)
		}
		seen[endpoint] = struct{}{}
	}
	return nil
}

func (p PolicyRolloutProbe) Validate(rollout string) error {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return fmt.Errorf("policy rollout %q probe name is required", rollout)
	}
	probeType := strings.ToLower(strings.TrimSpace(p.Type))
	switch probeType {
	case "http":
		if strings.TrimSpace(p.URL) == "" {
			return fmt.Errorf("policy rollout %q probe %q url is required", rollout, name)
		}
		parsed, err := url.Parse(p.URL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("policy rollout %q probe %q url must be http or https", rollout, name)
		}
		if p.ExpectedStatus < 0 || p.ExpectedStatus > 599 {
			return fmt.Errorf("policy rollout %q probe %q expected_status must be between 0 and 599", rollout, name)
		}
	case "tcp":
		if strings.TrimSpace(p.Address) == "" {
			return fmt.Errorf("policy rollout %q probe %q address is required", rollout, name)
		}
		host, port, err := net.SplitHostPort(p.Address)
		if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			return fmt.Errorf("policy rollout %q probe %q address must be host:port", rollout, name)
		}
	default:
		return fmt.Errorf("policy rollout %q probe %q type must be http or tcp", rollout, name)
	}
	return nil
}

type Controller struct {
	topology         TopologyBackend
	policy           PolicyBackend
	mu               sync.Mutex
	identityResolver policy.IdentityResolver
}

func NewController(topology TopologyBackend, policyBackend PolicyBackend) *Controller {
	return &Controller{
		topology:         topology,
		policy:           policyBackend,
		identityResolver: policy.NewIdentityCache(),
	}
}

func (c *Controller) Reconcile(ctx context.Context, state DesiredState) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := validateObjectGraph(state); err != nil {
		return err
	}
	if err := validateNATRules(state.NATRules); err != nil {
		return err
	}
	if err := validateLoadBalancers(state.LoadBalancers); err != nil {
		return err
	}
	if err := validateInboundVIPConflicts(state.NATRules, state.LoadBalancers); err != nil {
		return err
	}
	if err := validatePolicyRollouts(state.PolicyRollouts); err != nil {
		return err
	}
	if err := validateRouteTables(state.RouteTables); err != nil {
		return err
	}
	if err := validatePolicyRoutes(state.PolicyRoutes); err != nil {
		return err
	}
	topologyState := desiredTopologyState(state)
	if lifecycle, ok := c.topology.(TopologyLifecycleBackend); ok {
		if err := lifecycle.BeginTopologyReconcile(ctx, topologyState); err != nil {
			return fmt.Errorf("begin topology reconcile: %w", err)
		}
		if err := lifecycle.CleanupTopology(ctx, topologyState); err != nil {
			return fmt.Errorf("cleanup topology: %w", err)
		}
	}

	for _, vpc := range state.VPCs {
		if err := vpc.Validate(); err != nil {
			return err
		}
		if err := c.topology.EnsureVPC(ctx, vpc); err != nil {
			return fmt.Errorf("ensure vpc %s: %w", vpc.Name, err)
		}
	}
	for _, subnet := range state.Subnets {
		if err := subnet.Validate(); err != nil {
			return err
		}
		if err := c.topology.EnsureSubnet(ctx, subnet); err != nil {
			return fmt.Errorf("ensure subnet %s: %w", subnet.Name, err)
		}
	}
	for _, rt := range state.RouteTables {
		if err := rt.Validate(); err != nil {
			return err
		}
		if err := c.topology.EnsureRouteTable(ctx, rt); err != nil {
			return fmt.Errorf("ensure route table %s: %w", rt.Name, err)
		}
	}
	policyRoutes := append([]model.PolicyRoute(nil), state.PolicyRoutes...)
	sort.SliceStable(policyRoutes, func(i, j int) bool {
		return policyRoutes[i].Priority > policyRoutes[j].Priority
	})
	for _, route := range policyRoutes {
		if err := route.Validate(); err != nil {
			return err
		}
		if err := c.topology.EnsurePolicyRoute(ctx, route); err != nil {
			return fmt.Errorf("ensure policy route %s: %w", route.Name, err)
		}
	}
	for _, gateway := range state.Gateways {
		if err := gateway.Validate(); err != nil {
			return err
		}
		if err := c.topology.EnsureGateway(ctx, gateway); err != nil {
			return fmt.Errorf("ensure gateway %s: %w", gateway.Name, err)
		}
	}
	for _, endpoint := range state.Endpoints {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		groups := securityGroupsForVPC(state.SecurityGroups, endpoint.VPC)
		resolver := c.identityResolver
		if resolver == nil {
			resolver = policy.NewIdentityCache()
		}
		if err := c.topology.EnsureEndpoint(ctx, endpoint); err != nil {
			return fmt.Errorf("ensure endpoint %s: %w", endpoint.ID, err)
		}
		program, err := policy.CompileForEndpointWithContext(endpoint, groups, policy.CompileContext{
			Endpoints:        state.Endpoints,
			Subnets:          state.Subnets,
			Gateways:         state.Gateways,
			Services:         state.LoadBalancers,
			DNSRecords:       state.DNSRecords,
			CIDRGroups:       state.CIDRGroups,
			IdentityResolver: resolver,
		})
		if err != nil {
			return err
		}
		if err := c.policy.ApplyEndpointProgram(ctx, program); err != nil {
			return fmt.Errorf("apply policy program for endpoint %s: %w", endpoint.ID, err)
		}
	}
	for _, rule := range state.NATRules {
		if err := c.topology.EnsureNATRule(ctx, rule); err != nil {
			return fmt.Errorf("ensure nat rule %s: %w", rule.Name, err)
		}
	}
	for _, lb := range state.LoadBalancers {
		if err := c.topology.EnsureLoadBalancer(ctx, lb); err != nil {
			return fmt.Errorf("ensure load balancer %s: %w", lb.Name, err)
		}
	}
	if lifecycle, ok := c.policy.(PolicyLifecycleBackend); ok {
		if err := lifecycle.CleanupPolicy(ctx, state); err != nil {
			return fmt.Errorf("cleanup policy: %w", err)
		}
	}
	return nil
}

func securityGroupsForVPC(groups []model.SecurityGroup, vpc string) map[string]model.SecurityGroup {
	out := make(map[string]model.SecurityGroup)
	for _, group := range groups {
		if group.VPC == vpc {
			out[group.Name] = group
		}
	}
	return out
}

func securityGroupKey(vpc, name string) string {
	return vpc + "\x00" + name
}

func cidrGroupKey(vpc, name string) string {
	return vpc + "\x00" + name
}

func loadBalancerKey(vpc, name string) string {
	return vpc + "\x00" + name
}

func natRuleKey(vpc, name string) string {
	return vpc + "\x00" + name
}

func routeTableKey(vpc, name string) string {
	return vpc + "\x00" + name
}

func subnetKey(vpc, name string) string {
	return vpc + "\x00" + name
}

func gatewayKey(vpc, name string) string {
	return vpc + "\x00" + name
}

func validateNATRules(rules []model.NATRule) error {
	names := make(map[string]struct{}, len(rules))
	type snatRule struct {
		name string
		vpc  string
		cidr netip.Prefix
	}
	var snatRules []snatRule
	inboundAllPorts := make(map[string]string)
	inboundPortKeys := make(map[string]string)
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return err
		}
		nameKey := natRuleKey(rule.VPC, rule.Name)
		if _, ok := names[nameKey]; ok {
			return fmt.Errorf("duplicate nat rule name %q in vpc %q", rule.Name, rule.VPC)
		}
		names[nameKey] = struct{}{}

		if rule.Type == model.ActionSNAT {
			for _, existing := range snatRules {
				if existing.vpc == rule.VPC && prefixesOverlap(existing.cidr, rule.MatchCIDR) {
					return fmt.Errorf("snat rule %q conflicts with %q on overlapping cidr %s in vpc %s", rule.Name, existing.name, rule.MatchCIDR, rule.VPC)
				}
			}
			snatRules = append(snatRules, snatRule{name: rule.Name, vpc: rule.VPC, cidr: rule.MatchCIDR})
			continue
		}

		baseKey := rule.VPC + "|" + rule.ExternalIP.String()
		if rule.ExternalPort == 0 {
			if prev := inboundAllPorts[baseKey]; prev != "" {
				return fmt.Errorf("nat rule %q conflicts with %q on external ip %s", rule.Name, prev, rule.ExternalIP)
			}
			if prev := inboundPortKeysPrefix(inboundPortKeys, baseKey); prev != "" {
				return fmt.Errorf("nat rule %q conflicts with %q on external ip %s", rule.Name, prev, rule.ExternalIP)
			}
			inboundAllPorts[baseKey] = rule.Name
			continue
		}
		if prev := inboundAllPorts[baseKey]; prev != "" {
			return fmt.Errorf("nat rule %q conflicts with %q on external ip %s", rule.Name, prev, rule.ExternalIP)
		}
		portKey := fmt.Sprintf("%s|%s|%d", baseKey, rule.Protocol, rule.ExternalPort)
		if prev := inboundPortKeys[portKey]; prev != "" {
			return fmt.Errorf("nat rule %q conflicts with %q on %s/%s:%d", rule.Name, prev, rule.ExternalIP, rule.Protocol, rule.ExternalPort)
		}
		inboundPortKeys[portKey] = rule.Name
	}
	return nil
}

func inboundPortKeysPrefix(keys map[string]string, prefix string) string {
	for key, name := range keys {
		if strings.HasPrefix(key, prefix+"|") {
			return name
		}
	}
	return ""
}

func validatePolicyRollouts(rollouts []PolicyRollout) error {
	seen := make(map[string]struct{}, len(rollouts))
	for _, rollout := range rollouts {
		if err := rollout.Validate(); err != nil {
			return err
		}
		if _, ok := seen[rollout.Name]; ok {
			return fmt.Errorf("duplicate policy rollout name %q", rollout.Name)
		}
		seen[rollout.Name] = struct{}{}
	}
	return nil
}

func validateObjectGraph(state DesiredState) error {
	vpcs := make(map[string]struct{}, len(state.VPCs))
	for _, vpc := range state.VPCs {
		if err := vpc.Validate(); err != nil {
			return err
		}
		if _, ok := vpcs[vpc.Name]; ok {
			return fmt.Errorf("duplicate vpc name %q", vpc.Name)
		}
		vpcs[vpc.Name] = struct{}{}
	}

	providerNetworks := make(map[string]model.ProviderNetwork, len(state.ProviderNetworks))
	for _, providerNetwork := range state.ProviderNetworks {
		if err := providerNetwork.Validate(); err != nil {
			return err
		}
		if _, ok := providerNetworks[providerNetwork.Name]; ok {
			return fmt.Errorf("duplicate provider network name %q", providerNetwork.Name)
		}
		providerNetworks[providerNetwork.Name] = providerNetwork
	}

	subnets := make(map[string]model.Subnet, len(state.Subnets))
	for _, subnet := range state.Subnets {
		if err := subnet.Validate(); err != nil {
			return err
		}
		key := subnetKey(subnet.VPC, subnet.Name)
		if _, ok := subnets[key]; ok {
			return fmt.Errorf("duplicate subnet name %q in vpc %q", subnet.Name, subnet.VPC)
		}
		if _, ok := vpcs[subnet.VPC]; !ok {
			return fmt.Errorf("subnet %q references unknown vpc %q", subnet.Name, subnet.VPC)
		}
		if subnet.ProviderNetwork != "" {
			if _, ok := providerNetworks[subnet.ProviderNetwork]; !ok {
				return fmt.Errorf("subnet %q references unknown provider network %q", subnet.Name, subnet.ProviderNetwork)
			}
		}
		for _, existing := range subnets {
			if existing.VPC == subnet.VPC && prefixesOverlap(existing.CIDR, subnet.CIDR) {
				return fmt.Errorf("subnet %q cidr %s overlaps with subnet %q cidr %s in vpc %q", subnet.Name, subnet.CIDR, existing.Name, existing.CIDR, subnet.VPC)
			}
		}
		subnets[key] = subnet
	}

	securityGroups := make(map[string]model.SecurityGroup, len(state.SecurityGroups))
	cidrGroups := make(map[string]model.CIDRGroup, len(state.CIDRGroups))
	loadBalancers := make(map[string]model.LoadBalancer, len(state.LoadBalancers))
	for _, lb := range state.LoadBalancers {
		if err := lb.Validate(); err != nil {
			return err
		}
		key := loadBalancerKey(lb.VPC, lb.Name)
		if _, ok := loadBalancers[key]; ok {
			return fmt.Errorf("duplicate load balancer name %q in vpc %q", lb.Name, lb.VPC)
		}
		if _, ok := vpcs[lb.VPC]; !ok {
			return fmt.Errorf("load balancer %q references unknown vpc %q", lb.Name, lb.VPC)
		}
		for _, subnetName := range lb.Subnets {
			subnet, ok := subnets[subnetKey(lb.VPC, subnetName)]
			if !ok {
				return fmt.Errorf("load balancer %q references unknown subnet %q", lb.Name, subnetName)
			}
			if subnet.VPC != lb.VPC {
				return fmt.Errorf("load balancer %q references subnet %q in vpc %q, want %q", lb.Name, subnetName, subnet.VPC, lb.VPC)
			}
		}
		for _, frontend := range lb.Frontends() {
			if err := validateAddressOutsideVPCSubnets(subnets, lb.VPC, frontend.VIP, fmt.Sprintf("load balancer %q vip %s", lb.Name, frontend.VIP)); err != nil {
				return err
			}
			for _, backend := range frontend.Backends {
				if err := validateAddressInVPCSubnets(subnets, lb.VPC, backend.IP, fmt.Sprintf("load balancer %q backend %s", lb.Name, netip.AddrPortFrom(backend.IP, backend.Port))); err != nil {
					return err
				}
			}
		}
		loadBalancers[key] = lb
	}
	for _, group := range state.CIDRGroups {
		if err := group.Validate(); err != nil {
			return err
		}
		key := cidrGroupKey(group.VPC, group.Name)
		if _, ok := cidrGroups[key]; ok {
			return fmt.Errorf("duplicate cidr group name %q in vpc %q", group.Name, group.VPC)
		}
		if _, ok := vpcs[group.VPC]; !ok {
			return fmt.Errorf("cidr group %q references unknown vpc %q", group.Name, group.VPC)
		}
		cidrGroups[key] = group
	}
	for _, group := range state.SecurityGroups {
		if err := group.Validate(); err != nil {
			return err
		}
		key := securityGroupKey(group.VPC, group.Name)
		if _, ok := securityGroups[key]; ok {
			return fmt.Errorf("duplicate security group name %q in vpc %q", group.Name, group.VPC)
		}
		if _, ok := vpcs[group.VPC]; !ok {
			return fmt.Errorf("security group %q references unknown vpc %q", group.Name, group.VPC)
		}
		securityGroups[key] = group
	}
	for _, group := range securityGroups {
		for _, rule := range group.Rules {
			if rule.RemoteGroup != "" {
				if _, ok := securityGroups[securityGroupKey(group.VPC, rule.RemoteGroup)]; !ok {
					return fmt.Errorf("security group rule %q references unknown remote group %q", rule.ID, rule.RemoteGroup)
				}
			}
			if rule.RemoteCIDRGroup != "" {
				if _, ok := cidrGroups[cidrGroupKey(group.VPC, rule.RemoteCIDRGroup)]; !ok {
					return fmt.Errorf("security group rule %q references unknown remote cidr group %q", rule.ID, rule.RemoteCIDRGroup)
				}
			}
			if rule.RemoteService != "" {
				service, ok := loadBalancers[loadBalancerKey(group.VPC, rule.RemoteService)]
				if !ok {
					return fmt.Errorf("security group rule %q references unknown remote service %q", rule.ID, rule.RemoteService)
				}
				if !loadBalancerHasMatchingFrontendProtocol(service, rule.Protocol) {
					return fmt.Errorf("security group rule %q references remote service %q without matching %s frontend", rule.ID, rule.RemoteService, effectiveProtocol(rule.Protocol))
				}
				if len(rule.Ports) > 0 && !loadBalancerHasMatchingFrontendPort(service, rule.Protocol, rule.Ports) {
					return fmt.Errorf("security group rule %q references remote service %q without matching %s frontend port %s", rule.ID, rule.RemoteService, effectiveProtocol(rule.Protocol), portRangesKey(rule.Ports))
				}
			}
		}
	}

	endpoints := make(map[string]model.Endpoint, len(state.Endpoints))
	endpointIPs := make(map[string]string, len(state.Endpoints))
	endpointMACs := make(map[string]string, len(state.Endpoints))
	for _, endpoint := range state.Endpoints {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		key := model.EndpointKey(endpoint.VPC, endpoint.ID)
		if _, ok := endpoints[key]; ok {
			return fmt.Errorf("duplicate endpoint id %q in vpc %q", endpoint.ID, endpoint.VPC)
		}
		if _, ok := vpcs[endpoint.VPC]; !ok {
			return fmt.Errorf("endpoint %q references unknown vpc %q", endpoint.ID, endpoint.VPC)
		}
		subnet, ok := subnets[subnetKey(endpoint.VPC, endpoint.Subnet)]
		if !ok {
			return fmt.Errorf("endpoint %q references unknown subnet %q", endpoint.ID, endpoint.Subnet)
		}
		if subnet.VPC != endpoint.VPC {
			return fmt.Errorf("endpoint %q references subnet %q in vpc %q, want %q", endpoint.ID, endpoint.Subnet, subnet.VPC, endpoint.VPC)
		}
		if !subnet.CIDR.Contains(endpoint.IP) {
			return fmt.Errorf("endpoint %q ip %s is outside subnet %q cidr %s", endpoint.ID, endpoint.IP, endpoint.Subnet, subnet.CIDR)
		}
		if subnet.Excludes(endpoint.IP) {
			return fmt.Errorf("endpoint %q ip %s is excluded by subnet %q", endpoint.ID, endpoint.IP, endpoint.Subnet)
		}
		if endpoint.IP == subnet.Gateway {
			return fmt.Errorf("endpoint %q ip %s conflicts with subnet %q gateway ip", endpoint.ID, endpoint.IP, endpoint.Subnet)
		}
		if mac := endpoint.NormalizedMAC(); mac != "" {
			gatewayMAC := model.SubnetGatewayMAC(subnet.VPC, subnet.Name, subnet.Gateway)
			if mac == gatewayMAC {
				return fmt.Errorf("endpoint %q mac %s conflicts with subnet %q gateway mac", endpoint.ID, mac, endpoint.Subnet)
			}
			macKey := subnetKey(endpoint.VPC, endpoint.Subnet) + "|" + mac
			if previous := endpointMACs[macKey]; previous != "" {
				return fmt.Errorf("endpoint %q conflicts with %q on mac %s in subnet %s", endpoint.ID, previous, mac, endpoint.Subnet)
			}
			endpointMACs[macKey] = endpoint.ID
		}
		for _, groupName := range endpoint.SecurityGroups {
			if _, ok := securityGroups[securityGroupKey(endpoint.VPC, groupName)]; !ok {
				return fmt.Errorf("endpoint %q references unknown security group %q", endpoint.ID, groupName)
			}
		}
		ipKey := endpoint.VPC + "|" + endpoint.IP.String()
		if previous := endpointIPs[ipKey]; previous != "" {
			return fmt.Errorf("endpoint %q conflicts with %q on ip %s in vpc %s", endpoint.ID, previous, endpoint.IP, endpoint.VPC)
		}
		endpointIPs[ipKey] = endpoint.ID
		endpoints[key] = endpoint
	}
	if err := validateProviderNetworkTenantQuotas(providerNetworks, subnets, state.Endpoints); err != nil {
		return err
	}
	if err := validateSecurityGroupNamedPortReferences(state.SecurityGroups, state.Endpoints, securityGroups); err != nil {
		return err
	}

	gateways := make(map[string]model.Gateway, len(state.Gateways))
	gatewayIPs := make(map[string]string, len(state.Gateways))
	gatewayInterfaces := make(map[string]string, len(state.Gateways))
	for _, gateway := range state.Gateways {
		if err := gateway.Validate(); err != nil {
			return err
		}
		key := gatewayKey(gateway.VPC, gateway.Name)
		if _, ok := gateways[key]; ok {
			return fmt.Errorf("duplicate gateway name %q in vpc %q", gateway.Name, gateway.VPC)
		}
		if _, ok := vpcs[gateway.VPC]; !ok {
			return fmt.Errorf("gateway %q references unknown vpc %q", gateway.Name, gateway.VPC)
		}
		if err := validateAddressInVPCSubnets(subnets, gateway.VPC, gateway.LANIP, fmt.Sprintf("gateway %q lan ip %s", gateway.Name, gateway.LANIP)); err != nil {
			return err
		}
		if subnet, ok := subnetContainingAddress(subnets, gateway.VPC, gateway.LANIP); ok && gateway.LANIP == subnet.Gateway {
			return fmt.Errorf("gateway %q lan ip %s conflicts with subnet %q gateway ip", gateway.Name, gateway.LANIP, subnet.Name)
		}
		ipKey := gateway.VPC + "|" + gateway.LANIP.String()
		if previous := endpointIPs[ipKey]; previous != "" {
			return fmt.Errorf("gateway %q lan ip %s conflicts with endpoint %q in vpc %s", gateway.Name, gateway.LANIP, previous, gateway.VPC)
		}
		if previous := gatewayIPs[ipKey]; previous != "" {
			return fmt.Errorf("gateway %q conflicts with %q on lan ip %s in vpc %s", gateway.Name, previous, gateway.LANIP, gateway.VPC)
		}
		ifKey := gateway.Node + "|" + gateway.ExternalIF
		if previous := gatewayInterfaces[ifKey]; previous != "" {
			return fmt.Errorf("gateway %q conflicts with %q on external_if %s on node %s", gateway.Name, previous, gateway.ExternalIF, gateway.Node)
		}
		gatewayInterfaces[ifKey] = gateway.Name
		gatewayIPs[ipKey] = gateway.Name
		gateways[key] = gateway
	}
	if err := validateSecurityGroupRemoteEntities(state.SecurityGroups, state.Endpoints, securityGroups, gateways, subnets); err != nil {
		return err
	}

	for _, table := range state.RouteTables {
		if err := table.Validate(); err != nil {
			return err
		}
		if _, ok := vpcs[table.VPC]; !ok {
			return fmt.Errorf("route table %q references unknown vpc %q", table.Name, table.VPC)
		}
		for _, route := range table.Routes {
			if route.Blackhole {
				continue
			}
			for _, nextHop := range route.RouteNextHops() {
				if err := validateAddressInVPCSubnets(subnets, table.VPC, nextHop, fmt.Sprintf("route table %q next hop %s", table.Name, nextHop)); err != nil {
					return err
				}
			}
		}
	}
	for _, route := range state.PolicyRoutes {
		if err := route.Validate(); err != nil {
			return err
		}
		if _, ok := vpcs[route.VPC]; !ok {
			return fmt.Errorf("policy route %q references unknown vpc %q", route.Name, route.VPC)
		}
		if route.Match.Source.IsValid() {
			if err := validatePrefixInVPCSubnets(subnets, route.VPC, route.Match.Source, fmt.Sprintf("policy route %q source %s", route.Name, route.Match.Source)); err != nil {
				return err
			}
		}
		if route.Action.Type == model.ActionReroute {
			for _, nextHop := range route.Action.RerouteNextHops() {
				if err := validateAddressInVPCSubnets(subnets, route.VPC, nextHop, fmt.Sprintf("policy route %q next hop %s", route.Name, nextHop)); err != nil {
					return err
				}
			}
		}
	}
	for _, rule := range state.NATRules {
		if err := rule.Validate(); err != nil {
			return err
		}
		if _, ok := vpcs[rule.VPC]; !ok {
			return fmt.Errorf("nat rule %q references unknown vpc %q", rule.Name, rule.VPC)
		}
		if err := validateAddressOutsideVPCSubnets(subnets, rule.VPC, rule.ExternalIP, fmt.Sprintf("nat rule %q external ip %s", rule.Name, rule.ExternalIP)); err != nil {
			return err
		}
		if rule.Type == model.ActionSNAT {
			if err := validatePrefixInVPCSubnets(subnets, rule.VPC, rule.MatchCIDR, fmt.Sprintf("nat rule %q match cidr %s", rule.Name, rule.MatchCIDR)); err != nil {
				return err
			}
		}
		if rule.Type == model.ActionDNAT || rule.Type == model.ActionDNATSNAT {
			if err := validateAddressInVPCSubnets(subnets, rule.VPC, rule.TargetIP, fmt.Sprintf("nat rule %q target ip %s", rule.Name, rule.TargetIP)); err != nil {
				return err
			}
		}
	}
	for _, record := range state.DNSRecords {
		if err := record.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateSecurityGroupNamedPortReferences(groups []model.SecurityGroup, endpoints []model.Endpoint, groupByName map[string]model.SecurityGroup) error {
	for _, endpoint := range endpoints {
		for _, groupName := range endpoint.SecurityGroups {
			group := groupByName[securityGroupKey(endpoint.VPC, groupName)]
			for _, rule := range group.Rules {
				if len(rule.NamedPorts) == 0 {
					continue
				}
				switch rule.Direction {
				case model.DirectionIngress:
					if err := validateEndpointNamedPorts(rule, endpoint); err != nil {
						return err
					}
				case model.DirectionEgress:
					members, err := egressNamedPortMembers(rule, endpoint, endpoints)
					if err != nil {
						return err
					}
					for _, member := range members {
						if err := validateEndpointNamedPorts(rule, member); err != nil {
							return fmt.Errorf("security group rule %q remote endpoint %q: %w", rule.ID, member.ID, err)
						}
					}
				}
			}
		}
	}
	return nil
}

func loadBalancerHasMatchingFrontendProtocol(lb model.LoadBalancer, protocol model.Protocol) bool {
	protocol = effectiveProtocol(protocol)
	for _, frontend := range lb.Frontends() {
		if protocol == model.ProtocolAny || frontend.Protocol == protocol {
			return true
		}
	}
	return false
}

func loadBalancerHasMatchingFrontendPort(lb model.LoadBalancer, protocol model.Protocol, ports []model.PortRange) bool {
	protocol = effectiveProtocol(protocol)
	for _, frontend := range lb.Frontends() {
		if protocol != model.ProtocolAny && frontend.Protocol != protocol {
			continue
		}
		if portRangesContain(ports, frontend.Port) {
			return true
		}
	}
	return false
}

func portRangesContain(ranges []model.PortRange, port uint16) bool {
	for _, portRange := range ranges {
		if portRange.From <= port && port <= portRange.To {
			return true
		}
	}
	return false
}

func portRangesKey(ranges []model.PortRange) string {
	parts := make([]string, 0, len(ranges))
	for _, portRange := range ranges {
		parts = append(parts, fmt.Sprintf("%d-%d", portRange.From, portRange.To))
	}
	return strings.Join(parts, ",")
}

func effectiveProtocol(protocol model.Protocol) model.Protocol {
	if protocol == "" {
		return model.ProtocolAny
	}
	return protocol
}

func egressNamedPortMembers(rule model.SecurityGroupRule, endpoint model.Endpoint, endpoints []model.Endpoint) ([]model.Endpoint, error) {
	switch {
	case rule.RemoteGroup != "":
		return endpointsInSecurityGroup(endpoint, endpoints, rule.RemoteGroup), nil
	case len(rule.RemoteEndpointSelector) > 0 || len(rule.RemoteEndpointExprs) > 0:
		return endpointsMatchingSelector(endpoint, endpoints, rule.RemoteEndpointSelector, rule.RemoteEndpointExprs), nil
	default:
		return nil, fmt.Errorf("security group rule %q named ports require remote_group or remote_endpoint_selector for egress rules", rule.ID)
	}
}

func endpointsInSecurityGroup(endpoint model.Endpoint, endpoints []model.Endpoint, groupName string) []model.Endpoint {
	members := make([]model.Endpoint, 0)
	for _, candidate := range endpoints {
		if candidate.ID == endpoint.ID || candidate.VPC != endpoint.VPC {
			continue
		}
		if endpointHasSecurityGroup(candidate, groupName) {
			members = append(members, candidate)
		}
	}
	return members
}

func endpointsMatchingSelector(endpoint model.Endpoint, endpoints []model.Endpoint, selector model.Labels, expressions []model.LabelExpr) []model.Endpoint {
	members := make([]model.Endpoint, 0)
	for _, candidate := range endpoints {
		if candidate.ID == endpoint.ID || candidate.VPC != endpoint.VPC {
			continue
		}
		if candidate.Labels.MatchesSelector(selector, expressions) {
			members = append(members, candidate)
		}
	}
	return members
}

func endpointHasSecurityGroup(endpoint model.Endpoint, groupName string) bool {
	for _, attached := range endpoint.SecurityGroups {
		if attached == groupName {
			return true
		}
	}
	return false
}

func validateSecurityGroupRemoteEntities(groups []model.SecurityGroup, endpoints []model.Endpoint, groupByName map[string]model.SecurityGroup, gateways map[string]model.Gateway, subnets map[string]model.Subnet) error {
	if len(groups) == 0 || len(endpoints) == 0 {
		return nil
	}
	gatewayNodesByVPC := make(map[string]map[string]struct{})
	for _, gateway := range gateways {
		if _, ok := gatewayNodesByVPC[gateway.VPC]; !ok {
			gatewayNodesByVPC[gateway.VPC] = make(map[string]struct{})
		}
		gatewayNodesByVPC[gateway.VPC][gateway.Node] = struct{}{}
	}
	hasSubnetByVPC := make(map[string]bool)
	for _, subnet := range subnets {
		hasSubnetByVPC[subnet.VPC] = true
	}
	for _, endpoint := range endpoints {
		for _, groupName := range endpoint.SecurityGroups {
			group := groupByName[securityGroupKey(endpoint.VPC, groupName)]
			for _, rule := range group.Rules {
				for _, entity := range rule.RemoteEntities {
					switch entity {
					case "cluster", "world", "world-ipv4", "world-ipv6":
						if !hasSubnetByVPC[endpoint.VPC] {
							return fmt.Errorf("security group rule %q remote entity %s requires at least one subnet in vpc %q", rule.ID, entity, endpoint.VPC)
						}
					case "host":
						if len(gatewayNodesByVPC[endpoint.VPC]) == 0 {
							return fmt.Errorf("security group rule %q remote entity host requires at least one gateway in vpc %q", rule.ID, endpoint.VPC)
						}
					case "remote-node":
						if !hasRemoteGatewayNode(gatewayNodesByVPC[endpoint.VPC], endpoint.Node) {
							return fmt.Errorf("security group rule %q remote entity remote-node requires at least one gateway on a different node in vpc %q", rule.ID, endpoint.VPC)
						}
					}
				}
			}
		}
	}
	return nil
}

func hasRemoteGatewayNode(nodes map[string]struct{}, localNode string) bool {
	for node := range nodes {
		if node != localNode {
			return true
		}
	}
	return false
}

func validateEndpointNamedPorts(rule model.SecurityGroupRule, endpoint model.Endpoint) error {
	for _, name := range rule.NamedPorts {
		if !endpointDefinesNamedPort(endpoint, rule.Protocol, name) {
			return fmt.Errorf("security group rule %q named port %s/%s is not defined on endpoint %q", rule.ID, rule.Protocol, name, endpoint.ID)
		}
	}
	return nil
}

func endpointDefinesNamedPort(endpoint model.Endpoint, protocol model.Protocol, name string) bool {
	for _, port := range endpoint.NamedPorts {
		if port.Protocol == protocol && port.Name == name {
			return true
		}
	}
	return false
}

func validateAddressOutsideVPCSubnets(subnets map[string]model.Subnet, vpc string, addr netip.Addr, subject string) error {
	if subnet, ok := subnetContainingAddress(subnets, vpc, addr); ok {
		return fmt.Errorf("%s is inside subnet %q in vpc %q", subject, subnet.Name, vpc)
	}
	return nil
}

func validateAddressInVPCSubnets(subnets map[string]model.Subnet, vpc string, addr netip.Addr, subject string) error {
	subnet, ok := subnetContainingAddress(subnets, vpc, addr)
	if !ok {
		return fmt.Errorf("%s is outside vpc %q subnets", subject, vpc)
	}
	if subnet.Excludes(addr) {
		return fmt.Errorf("%s is excluded by subnet %q", subject, subnet.Name)
	}
	return nil
}

func validatePrefixInVPCSubnets(subnets map[string]model.Subnet, vpc string, prefix netip.Prefix, subject string) error {
	subnet, ok := subnetContainingPrefix(subnets, vpc, prefix)
	if !ok {
		return fmt.Errorf("%s is outside vpc %q subnets", subject, vpc)
	}
	if exclude, ok := prefixOverlapsSubnetExclude(subnet, prefix); ok {
		return fmt.Errorf("%s overlaps excluded cidr %s in subnet %q", subject, exclude, subnet.Name)
	}
	return nil
}

func prefixOverlapsSubnetExclude(subnet model.Subnet, prefix netip.Prefix) (netip.Prefix, bool) {
	prefix = prefix.Masked()
	for _, exclude := range subnet.ExcludeCIDRs {
		exclude = exclude.Masked()
		if prefixesOverlap(prefix, exclude) {
			return exclude, true
		}
	}
	return netip.Prefix{}, false
}

func subnetContainingAddress(subnets map[string]model.Subnet, vpc string, addr netip.Addr) (model.Subnet, bool) {
	for _, subnet := range subnets {
		if subnet.VPC == vpc && subnet.CIDR.Contains(addr) {
			return subnet, true
		}
	}
	return model.Subnet{}, false
}

func subnetContainingPrefix(subnets map[string]model.Subnet, vpc string, prefix netip.Prefix) (model.Subnet, bool) {
	first := prefix.Masked().Addr()
	last := prefixLastAddress(prefix)
	for _, subnet := range subnets {
		if subnet.VPC == vpc && subnet.CIDR.Contains(first) && subnet.CIDR.Contains(last) {
			return subnet, true
		}
	}
	return model.Subnet{}, false
}

func prefixesOverlap(left, right netip.Prefix) bool {
	left = left.Masked()
	right = right.Masked()
	if !left.IsValid() || !right.IsValid() || left.Addr().Is4() != right.Addr().Is4() {
		return false
	}
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func prefixLastAddress(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr()
	if addr.Is4() {
		bytes := addr.As4()
		setHostBits(bytes[:], prefix.Bits(), 32)
		return netip.AddrFrom4(bytes)
	}
	bytes := addr.As16()
	setHostBits(bytes[:], prefix.Bits(), 128)
	return netip.AddrFrom16(bytes)
}

func setHostBits(bytes []byte, prefixBits, totalBits int) {
	for bit := prefixBits; bit < totalBits; bit++ {
		bytes[bit/8] |= 1 << uint(7-bit%8)
	}
}

func validateLoadBalancers(loadBalancers []model.LoadBalancer) error {
	names := make(map[string]struct{}, len(loadBalancers))
	vips := make(map[string]string, len(loadBalancers))
	for _, lb := range loadBalancers {
		if err := lb.Validate(); err != nil {
			return err
		}
		nameKey := loadBalancerKey(lb.VPC, lb.Name)
		if _, ok := names[nameKey]; ok {
			return fmt.Errorf("duplicate load balancer name %q in vpc %q", lb.Name, lb.VPC)
		}
		names[nameKey] = struct{}{}

		for _, frontend := range lb.Frontends() {
			key := fmt.Sprintf("%s|%s|%s|%d", lb.VPC, frontend.VIP, frontend.Protocol, frontend.Port)
			if prev := vips[key]; prev != "" {
				return fmt.Errorf("load balancer %q conflicts with %q on %s/%s:%d", lb.Name, prev, frontend.VIP, frontend.Protocol, frontend.Port)
			}
			vips[key] = lb.Name
		}
	}
	return nil
}

func validateInboundVIPConflicts(natRules []model.NATRule, loadBalancers []model.LoadBalancer) error {
	allPortNATs := make(map[string]string)
	portNATs := make(map[string]string)
	for _, rule := range natRules {
		if rule.Type == model.ActionSNAT {
			continue
		}
		baseKey := rule.VPC + "|" + rule.ExternalIP.String()
		if rule.ExternalPort == 0 {
			allPortNATs[baseKey] = rule.Name
			continue
		}
		portNATs[fmt.Sprintf("%s|%s|%d", baseKey, rule.Protocol, rule.ExternalPort)] = rule.Name
	}
	for _, lb := range loadBalancers {
		for _, frontend := range lb.Frontends() {
			baseKey := lb.VPC + "|" + frontend.VIP.String()
			if prev := allPortNATs[baseKey]; prev != "" {
				return fmt.Errorf("load balancer %q conflicts with nat rule %q on external ip %s", lb.Name, prev, frontend.VIP)
			}
			if prev := portNATs[fmt.Sprintf("%s|%s|%d", baseKey, frontend.Protocol, frontend.Port)]; prev != "" {
				return fmt.Errorf("load balancer %q conflicts with nat rule %q on %s:%d", lb.Name, prev, frontend.VIP, frontend.Port)
			}
		}
	}
	return nil
}

func validateRouteTables(tables []model.RouteTable) error {
	names := make(map[string]struct{}, len(tables))
	destinations := make(map[string]string)
	for _, table := range tables {
		if err := table.Validate(); err != nil {
			return err
		}
		nameKey := routeTableKey(table.VPC, table.Name)
		if _, ok := names[nameKey]; ok {
			return fmt.Errorf("duplicate route table name %q in vpc %q", table.Name, table.VPC)
		}
		names[nameKey] = struct{}{}
		for _, route := range table.Routes {
			key := table.VPC + "|" + route.Destination.String()
			if prev := destinations[key]; prev != "" {
				return fmt.Errorf("route table %q conflicts with %q on %s in vpc %s", table.Name, prev, route.Destination, table.VPC)
			}
			destinations[key] = table.Name
		}
	}
	return nil
}

func validatePolicyRoutes(routes []model.PolicyRoute) error {
	names := make(map[string]struct{}, len(routes))
	type policyRouteRecord struct {
		name     string
		vpc      string
		priority int
		match    model.RouteMatch
	}
	var records []policyRouteRecord
	for _, route := range routes {
		if err := route.Validate(); err != nil {
			return err
		}
		nameKey := route.VPC + "\x00" + route.Name
		if _, ok := names[nameKey]; ok {
			return fmt.Errorf("duplicate policy route name %q in vpc %q", route.Name, route.VPC)
		}
		names[nameKey] = struct{}{}
		for _, existing := range records {
			if existing.vpc == route.VPC && existing.priority == route.Priority && routeMatchesOverlap(existing.match, route.Match) {
				return fmt.Errorf("policy route %q conflicts with %q on overlapping priority %d match %s in vpc %s", route.Name, existing.name, route.Priority, routeMatchKey(route.Match), route.VPC)
			}
		}
		records = append(records, policyRouteRecord{name: route.Name, vpc: route.VPC, priority: route.Priority, match: route.Match})
	}
	return nil
}

func routeMatchesOverlap(left, right model.RouteMatch) bool {
	return prefixesMayOverlap(left.Source, right.Source) &&
		prefixesMayOverlap(left.Destination, right.Destination) &&
		protocolsMayOverlap(left.Protocol, right.Protocol) &&
		portRangesMayOverlap(left.SrcPorts, right.SrcPorts) &&
		portRangesMayOverlap(left.DstPorts, right.DstPorts)
}

func prefixesMayOverlap(left, right netip.Prefix) bool {
	if !left.IsValid() || !right.IsValid() {
		return true
	}
	return prefixesOverlap(left, right)
}

func protocolsMayOverlap(left, right model.Protocol) bool {
	if left == "" || left == model.ProtocolAny || right == "" || right == model.ProtocolAny {
		return true
	}
	return left == right
}

func portRangesMayOverlap(left, right []model.PortRange) bool {
	if len(left) == 0 || len(right) == 0 {
		return true
	}
	for _, leftPort := range left {
		for _, rightPort := range right {
			if leftPort.From <= rightPort.To && rightPort.From <= leftPort.To {
				return true
			}
		}
	}
	return false
}

func routeMatchKey(match model.RouteMatch) string {
	protocol := match.Protocol
	if protocol == "" {
		protocol = model.ProtocolAny
	}
	return fmt.Sprintf("src=%s|dst=%s|proto=%s|sports=%s|dports=%s", match.Source, match.Destination, protocol, routeMatchPortKey(match.SrcPorts), routeMatchPortKey(match.DstPorts))
}

func routeMatchPortKey(ranges []model.PortRange) string {
	ports := make([]string, 0, len(ranges))
	for _, port := range ranges {
		ports = append(ports, fmt.Sprintf("%d-%d", port.From, port.To))
	}
	sort.Strings(ports)
	return strings.Join(ports, ",")
}

type providerTenantUsage struct {
	subnets   int
	endpoints int
}

func validateProviderNetworkTenantQuotas(providerNetworks map[string]model.ProviderNetwork, subnets map[string]model.Subnet, endpoints []model.Endpoint) error {
	usage := providerNetworkTenantUsage(subnets, endpoints)
	for providerName, provider := range providerNetworks {
		providerUsage := usage[providerName]
		for _, quota := range provider.TenantQuotas {
			tenantUsage := providerUsage[quota.Tenant]
			if quota.MaxSubnets > 0 && tenantUsage.subnets > quota.MaxSubnets {
				return fmt.Errorf("provider network %q tenant %q uses %d subnets, exceeds max_subnets %d", providerName, quota.Tenant, tenantUsage.subnets, quota.MaxSubnets)
			}
			if quota.MaxEndpoints > 0 && tenantUsage.endpoints > quota.MaxEndpoints {
				return fmt.Errorf("provider network %q tenant %q uses %d endpoints, exceeds max_endpoints %d", providerName, quota.Tenant, tenantUsage.endpoints, quota.MaxEndpoints)
			}
		}
	}
	return nil
}

func providerNetworkTenantUsage(subnets map[string]model.Subnet, endpoints []model.Endpoint) map[string]map[string]providerTenantUsage {
	usage := make(map[string]map[string]providerTenantUsage)
	subnetProviders := make(map[string]string, len(subnets))
	for key, subnet := range subnets {
		if subnet.ProviderNetwork == "" {
			continue
		}
		subnetProviders[key] = subnet.ProviderNetwork
		tenantUsage := providerTenantUsageFor(usage, subnet.ProviderNetwork, subnet.VPC)
		tenantUsage.subnets++
		setProviderTenantUsage(usage, subnet.ProviderNetwork, subnet.VPC, tenantUsage)
	}
	for _, endpoint := range endpoints {
		providerName := subnetProviders[subnetKey(endpoint.VPC, endpoint.Subnet)]
		if providerName == "" {
			continue
		}
		tenantUsage := providerTenantUsageFor(usage, providerName, endpoint.VPC)
		tenantUsage.endpoints++
		setProviderTenantUsage(usage, providerName, endpoint.VPC, tenantUsage)
	}
	return usage
}

func providerTenantUsageFor(usage map[string]map[string]providerTenantUsage, provider, tenant string) providerTenantUsage {
	if usage[provider] == nil {
		usage[provider] = make(map[string]providerTenantUsage)
	}
	return usage[provider][tenant]
}

func setProviderTenantUsage(usage map[string]map[string]providerTenantUsage, provider, tenant string, value providerTenantUsage) {
	if usage[provider] == nil {
		usage[provider] = make(map[string]providerTenantUsage)
	}
	usage[provider][tenant] = value
}

func desiredTopologyState(state DesiredState) topology.State {
	vpcs := make(map[string]model.VPC, len(state.VPCs))
	for _, vpc := range state.VPCs {
		vpcs[vpc.Name] = vpc
	}
	subnets := make(map[string]model.Subnet, len(state.Subnets))
	for _, subnet := range state.Subnets {
		subnets[subnetKey(subnet.VPC, subnet.Name)] = subnet
	}
	endpoints := make(map[string]model.Endpoint, len(state.Endpoints))
	for _, endpoint := range state.Endpoints {
		endpoints[model.EndpointKey(endpoint.VPC, endpoint.ID)] = endpoint
	}
	routeTables := make(map[string]model.RouteTable, len(state.RouteTables))
	for _, table := range state.RouteTables {
		routeTables[routeTableKey(table.VPC, table.Name)] = table
	}
	gateways := make(map[string]model.Gateway, len(state.Gateways))
	for _, gateway := range state.Gateways {
		gateways[gatewayKey(gateway.VPC, gateway.Name)] = gateway
	}
	natRules := make(map[string]model.NATRule, len(state.NATRules))
	for _, rule := range state.NATRules {
		natRules[natRuleKey(rule.VPC, rule.Name)] = rule
	}
	loadBalancers := make(map[string]model.LoadBalancer, len(state.LoadBalancers))
	for _, lb := range state.LoadBalancers {
		loadBalancers[loadBalancerKey(lb.VPC, lb.Name)] = lb
	}
	return topology.State{
		VPCs:          vpcs,
		Subnets:       subnets,
		Endpoints:     endpoints,
		RouteTables:   routeTables,
		PolicyRoutes:  append([]model.PolicyRoute(nil), state.PolicyRoutes...),
		Gateways:      gateways,
		NATRules:      natRules,
		LoadBalancers: loadBalancers,
	}
}
