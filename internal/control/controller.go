package control

import (
	"context"
	"fmt"
	"sort"
	"strings"

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
	VPCs           []model.VPC           `json:"vpcs"`
	Subnets        []model.Subnet        `json:"subnets"`
	Endpoints      []model.Endpoint      `json:"endpoints"`
	RouteTables    []model.RouteTable    `json:"route_tables"`
	PolicyRoutes   []model.PolicyRoute   `json:"policy_routes"`
	Gateways       []model.Gateway       `json:"gateways"`
	NATRules       []model.NATRule       `json:"nat_rules"`
	LoadBalancers  []model.LoadBalancer  `json:"load_balancers"`
	SecurityGroups []model.SecurityGroup `json:"security_groups"`
	CIDRGroups     []model.CIDRGroup     `json:"cidr_groups"`
	DNSRecords     []model.DNSRecord     `json:"dns_records"`
}

type Controller struct {
	topology TopologyBackend
	policy   PolicyBackend
}

func NewController(topology TopologyBackend, policy PolicyBackend) *Controller {
	return &Controller{topology: topology, policy: policy}
}

func (c *Controller) Reconcile(ctx context.Context, state DesiredState) error {
	if err := validateObjectGraph(state); err != nil {
		return err
	}
	groups := make(map[string]model.SecurityGroup, len(state.SecurityGroups))
	for _, group := range state.SecurityGroups {
		if err := group.Validate(); err != nil {
			return err
		}
		groups[group.Name] = group
	}
	if err := validateNATRules(state.NATRules); err != nil {
		return err
	}
	if err := validateLoadBalancers(state.LoadBalancers); err != nil {
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
	for _, endpoint := range state.Endpoints {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		if err := c.topology.EnsureEndpoint(ctx, endpoint); err != nil {
			return fmt.Errorf("ensure endpoint %s: %w", endpoint.ID, err)
		}
		program, err := policy.CompileForEndpointWithContext(endpoint, groups, policy.CompileContext{
			Endpoints:  state.Endpoints,
			Subnets:    state.Subnets,
			DNSRecords: state.DNSRecords,
			CIDRGroups: state.CIDRGroups,
		})
		if err != nil {
			return err
		}
		if err := c.policy.ApplyEndpointProgram(ctx, program); err != nil {
			return fmt.Errorf("apply policy program for endpoint %s: %w", endpoint.ID, err)
		}
	}
	if lifecycle, ok := c.topology.(TopologyLifecycleBackend); ok {
		if err := lifecycle.CleanupTopology(ctx, topologyState); err != nil {
			return fmt.Errorf("cleanup topology: %w", err)
		}
	}
	if lifecycle, ok := c.policy.(PolicyLifecycleBackend); ok {
		if err := lifecycle.CleanupPolicy(ctx, state); err != nil {
			return fmt.Errorf("cleanup policy: %w", err)
		}
	}
	return nil
}

func validateNATRules(rules []model.NATRule) error {
	names := make(map[string]struct{}, len(rules))
	snatKeys := make(map[string]string)
	inboundAllPorts := make(map[string]string)
	inboundPortKeys := make(map[string]string)
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return err
		}
		if _, ok := names[rule.Name]; ok {
			return fmt.Errorf("duplicate nat rule name %q", rule.Name)
		}
		names[rule.Name] = struct{}{}

		if rule.Type == model.ActionSNAT {
			key := rule.VPC + "|" + rule.MatchCIDR.String()
			if prev := snatKeys[key]; prev != "" {
				return fmt.Errorf("snat rule %q conflicts with %q on %s", rule.Name, prev, rule.MatchCIDR)
			}
			snatKeys[key] = rule.Name
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
		portKey := fmt.Sprintf("%s|%d", baseKey, rule.ExternalPort)
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

	subnets := make(map[string]model.Subnet, len(state.Subnets))
	for _, subnet := range state.Subnets {
		if err := subnet.Validate(); err != nil {
			return err
		}
		if _, ok := subnets[subnet.Name]; ok {
			return fmt.Errorf("duplicate subnet name %q", subnet.Name)
		}
		if _, ok := vpcs[subnet.VPC]; !ok {
			return fmt.Errorf("subnet %q references unknown vpc %q", subnet.Name, subnet.VPC)
		}
		subnets[subnet.Name] = subnet
	}

	securityGroups := make(map[string]model.SecurityGroup, len(state.SecurityGroups))
	cidrGroups := make(map[string]model.CIDRGroup, len(state.CIDRGroups))
	for _, group := range state.CIDRGroups {
		if err := group.Validate(); err != nil {
			return err
		}
		if _, ok := cidrGroups[group.Name]; ok {
			return fmt.Errorf("duplicate cidr group name %q", group.Name)
		}
		if _, ok := vpcs[group.VPC]; !ok {
			return fmt.Errorf("cidr group %q references unknown vpc %q", group.Name, group.VPC)
		}
		cidrGroups[group.Name] = group
	}
	for _, group := range state.SecurityGroups {
		if err := group.Validate(); err != nil {
			return err
		}
		if _, ok := securityGroups[group.Name]; ok {
			return fmt.Errorf("duplicate security group name %q", group.Name)
		}
		if _, ok := vpcs[group.VPC]; !ok {
			return fmt.Errorf("security group %q references unknown vpc %q", group.Name, group.VPC)
		}
		securityGroups[group.Name] = group
	}
	for _, group := range securityGroups {
		for _, rule := range group.Rules {
			if rule.RemoteGroup != "" {
				remote, ok := securityGroups[rule.RemoteGroup]
				if !ok {
					return fmt.Errorf("security group rule %q references unknown remote group %q", rule.ID, rule.RemoteGroup)
				}
				if remote.VPC != group.VPC {
					return fmt.Errorf("security group rule %q references remote group %q in vpc %q, want %q", rule.ID, rule.RemoteGroup, remote.VPC, group.VPC)
				}
			}
			if rule.RemoteCIDRGroup != "" {
				remote, ok := cidrGroups[rule.RemoteCIDRGroup]
				if !ok {
					return fmt.Errorf("security group rule %q references unknown remote cidr group %q", rule.ID, rule.RemoteCIDRGroup)
				}
				if remote.VPC != group.VPC {
					return fmt.Errorf("security group rule %q references remote cidr group %q in vpc %q, want %q", rule.ID, rule.RemoteCIDRGroup, remote.VPC, group.VPC)
				}
			}
		}
	}

	endpoints := make(map[string]model.Endpoint, len(state.Endpoints))
	endpointIPs := make(map[string]string, len(state.Endpoints))
	for _, endpoint := range state.Endpoints {
		if err := endpoint.Validate(); err != nil {
			return err
		}
		if _, ok := endpoints[endpoint.ID]; ok {
			return fmt.Errorf("duplicate endpoint id %q", endpoint.ID)
		}
		if _, ok := vpcs[endpoint.VPC]; !ok {
			return fmt.Errorf("endpoint %q references unknown vpc %q", endpoint.ID, endpoint.VPC)
		}
		subnet, ok := subnets[endpoint.Subnet]
		if !ok {
			return fmt.Errorf("endpoint %q references unknown subnet %q", endpoint.ID, endpoint.Subnet)
		}
		if subnet.VPC != endpoint.VPC {
			return fmt.Errorf("endpoint %q references subnet %q in vpc %q, want %q", endpoint.ID, endpoint.Subnet, subnet.VPC, endpoint.VPC)
		}
		if !subnet.CIDR.Contains(endpoint.IP) {
			return fmt.Errorf("endpoint %q ip %s is outside subnet %q cidr %s", endpoint.ID, endpoint.IP, endpoint.Subnet, subnet.CIDR)
		}
		for _, groupName := range endpoint.SecurityGroups {
			group, ok := securityGroups[groupName]
			if !ok {
				return fmt.Errorf("endpoint %q references unknown security group %q", endpoint.ID, groupName)
			}
			if group.VPC != endpoint.VPC {
				return fmt.Errorf("endpoint %q references security group %q in vpc %q, want %q", endpoint.ID, groupName, group.VPC, endpoint.VPC)
			}
		}
		ipKey := endpoint.VPC + "|" + endpoint.IP.String()
		if previous := endpointIPs[ipKey]; previous != "" {
			return fmt.Errorf("endpoint %q conflicts with %q on ip %s in vpc %s", endpoint.ID, previous, endpoint.IP, endpoint.VPC)
		}
		endpointIPs[ipKey] = endpoint.ID
		endpoints[endpoint.ID] = endpoint
	}

	gateways := make(map[string]struct{}, len(state.Gateways))
	for _, gateway := range state.Gateways {
		if err := gateway.Validate(); err != nil {
			return err
		}
		if _, ok := gateways[gateway.Name]; ok {
			return fmt.Errorf("duplicate gateway name %q", gateway.Name)
		}
		if _, ok := vpcs[gateway.VPC]; !ok {
			return fmt.Errorf("gateway %q references unknown vpc %q", gateway.Name, gateway.VPC)
		}
		gateways[gateway.Name] = struct{}{}
	}

	for _, table := range state.RouteTables {
		if err := table.Validate(); err != nil {
			return err
		}
		if _, ok := vpcs[table.VPC]; !ok {
			return fmt.Errorf("route table %q references unknown vpc %q", table.Name, table.VPC)
		}
	}
	for _, route := range state.PolicyRoutes {
		if err := route.Validate(); err != nil {
			return err
		}
		if _, ok := vpcs[route.VPC]; !ok {
			return fmt.Errorf("policy route %q references unknown vpc %q", route.Name, route.VPC)
		}
	}
	for _, rule := range state.NATRules {
		if err := rule.Validate(); err != nil {
			return err
		}
		if _, ok := vpcs[rule.VPC]; !ok {
			return fmt.Errorf("nat rule %q references unknown vpc %q", rule.Name, rule.VPC)
		}
	}
	for _, lb := range state.LoadBalancers {
		if err := lb.Validate(); err != nil {
			return err
		}
		if _, ok := vpcs[lb.VPC]; !ok {
			return fmt.Errorf("load balancer %q references unknown vpc %q", lb.Name, lb.VPC)
		}
		for _, subnetName := range lb.Subnets {
			subnet, ok := subnets[subnetName]
			if !ok {
				return fmt.Errorf("load balancer %q references unknown subnet %q", lb.Name, subnetName)
			}
			if subnet.VPC != lb.VPC {
				return fmt.Errorf("load balancer %q references subnet %q in vpc %q, want %q", lb.Name, subnetName, subnet.VPC, lb.VPC)
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

func validateLoadBalancers(loadBalancers []model.LoadBalancer) error {
	names := make(map[string]struct{}, len(loadBalancers))
	vips := make(map[string]string, len(loadBalancers))
	for _, lb := range loadBalancers {
		if err := lb.Validate(); err != nil {
			return err
		}
		if _, ok := names[lb.Name]; ok {
			return fmt.Errorf("duplicate load balancer name %q", lb.Name)
		}
		names[lb.Name] = struct{}{}

		protocol := lb.Protocol
		if protocol == "" {
			protocol = model.ProtocolTCP
		}
		key := fmt.Sprintf("%s|%s|%s|%d", lb.VPC, lb.VIP, protocol, lb.Port)
		if prev := vips[key]; prev != "" {
			return fmt.Errorf("load balancer %q conflicts with %q on %s/%s:%d", lb.Name, prev, lb.VIP, protocol, lb.Port)
		}
		vips[key] = lb.Name
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
		if _, ok := names[table.Name]; ok {
			return fmt.Errorf("duplicate route table name %q", table.Name)
		}
		names[table.Name] = struct{}{}
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
	matches := make(map[string]string, len(routes))
	for _, route := range routes {
		if err := route.Validate(); err != nil {
			return err
		}
		if _, ok := names[route.Name]; ok {
			return fmt.Errorf("duplicate policy route name %q", route.Name)
		}
		names[route.Name] = struct{}{}
		key := fmt.Sprintf("%s|%d|%s", route.VPC, route.Priority, routeMatchKey(route.Match))
		if prev := matches[key]; prev != "" {
			return fmt.Errorf("policy route %q conflicts with %q on priority %d match %s in vpc %s", route.Name, prev, route.Priority, routeMatchKey(route.Match), route.VPC)
		}
		matches[key] = route.Name
	}
	return nil
}

func routeMatchKey(match model.RouteMatch) string {
	protocol := match.Protocol
	if protocol == "" {
		protocol = model.ProtocolAny
	}
	ports := make([]string, 0, len(match.DstPorts))
	for _, port := range match.DstPorts {
		ports = append(ports, fmt.Sprintf("%d-%d", port.From, port.To))
	}
	sort.Strings(ports)
	return fmt.Sprintf("src=%s|dst=%s|proto=%s|dports=%s", match.Source, match.Destination, protocol, strings.Join(ports, ","))
}

func desiredTopologyState(state DesiredState) topology.State {
	vpcs := make(map[string]model.VPC, len(state.VPCs))
	for _, vpc := range state.VPCs {
		vpcs[vpc.Name] = vpc
	}
	subnets := make(map[string]model.Subnet, len(state.Subnets))
	for _, subnet := range state.Subnets {
		subnets[subnet.Name] = subnet
	}
	endpoints := make(map[string]model.Endpoint, len(state.Endpoints))
	for _, endpoint := range state.Endpoints {
		endpoints[endpoint.ID] = endpoint
	}
	routeTables := make(map[string]model.RouteTable, len(state.RouteTables))
	for _, table := range state.RouteTables {
		routeTables[table.Name] = table
	}
	gateways := make(map[string]model.Gateway, len(state.Gateways))
	for _, gateway := range state.Gateways {
		gateways[gateway.Name] = gateway
	}
	natRules := make(map[string]model.NATRule, len(state.NATRules))
	for _, rule := range state.NATRules {
		natRules[rule.Name] = rule
	}
	loadBalancers := make(map[string]model.LoadBalancer, len(state.LoadBalancers))
	for _, lb := range state.LoadBalancers {
		loadBalancers[lb.Name] = lb
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
