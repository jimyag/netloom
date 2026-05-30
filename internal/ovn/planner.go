package ovn

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/jimyag/netloom/internal/model"
)

type Operation struct {
	Command string
	Flags   []string
	Args    []string
}

func (o Operation) String() string {
	parts := append([]string(nil), o.Flags...)
	parts = append(parts, o.Command)
	parts = append(parts, o.Args...)
	return strings.Join(parts, " ")
}

type Planner struct {
	mu                       sync.Mutex
	ops                      []Operation
	vpcRouters               map[string]string
	subnets                  map[string]model.Subnet
	loadBalancerHealthChecks map[string]string
}

func NewPlanner() *Planner {
	return &Planner{
		vpcRouters:               make(map[string]string),
		subnets:                  make(map[string]model.Subnet),
		loadBalancerHealthChecks: make(map[string]string),
	}
}

func (p *Planner) EnsureVPC(_ context.Context, vpc model.VPC) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	router := logicalRouter(vpc.Name)
	p.vpcRouters[vpc.Name] = router
	p.ops = append(p.ops,
		Operation{Command: "lr-add", Flags: []string{"--may-exist"}, Args: []string{router}},
		setOperation("logical_router", router, "external_ids:netloom_owner=netloom", "external_ids:netloom_vpc="+vpc.Name),
	)
	return nil
}

func (p *Planner) EnsureSubnet(_ context.Context, subnet model.Subnet) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	router := p.routerForVPC(subnet.VPC)
	p.subnets[subnet.Name] = subnet
	switchName := logicalSwitch(subnet.Name)
	routerPort := routerPortName(router, subnet.Name)
	switchPort := switchRouterPortName(switchName, subnet.Name)
	routerMAC := deterministicMAC(subnet.Gateway)
	p.ops = append(p.ops,
		Operation{Command: "ls-add", Flags: []string{"--may-exist"}, Args: []string{switchName}},
		setOperation("logical_switch", switchName, "external_ids:netloom_owner=netloom", "external_ids:netloom_subnet="+subnet.Name, "external_ids:netloom_vpc="+subnet.VPC),
		Operation{Command: "lrp-add", Flags: []string{"--may-exist"}, Args: []string{router, routerPort, routerMAC, subnet.Gateway.String() + "/" + fmt.Sprint(subnet.CIDR.Bits())}},
		setOperation("logical_router_port", routerPort, "external_ids:netloom_owner=netloom", "external_ids:netloom_subnet="+subnet.Name),
		Operation{Command: "lsp-add", Flags: []string{"--may-exist"}, Args: []string{switchName, switchPort}},
		Operation{Command: "lsp-set-type", Args: []string{switchPort, "router"}},
		Operation{Command: "lsp-set-addresses", Args: []string{switchPort, routerMAC}},
		Operation{Command: "lsp-set-options", Args: []string{switchPort, "router-port=" + routerPort}},
		setOperation("logical_switch_port", switchPort, "external_ids:netloom_owner=netloom", "external_ids:netloom_subnet="+subnet.Name, "external_ids:netloom_role=router"),
	)
	if subnet.DHCP.Enabled && subnet.CIDR.Addr().Is6() {
		p.ops = append(p.ops, setOperation("logical_router_port", routerPort, "ipv6_ra_configs:address_mode=dhcpv6_stateful"))
	} else {
		p.ops = append(p.ops, Operation{Command: "remove", Args: []string{"logical_router_port", routerPort, "ipv6_ra_configs", "address_mode"}})
	}
	if subnet.ProviderNetwork != "" {
		localnetPort := localnetPortName(switchName, subnet.Name)
		p.ops = append(p.ops,
			Operation{Command: "lsp-del", Flags: []string{"--if-exists"}, Args: []string{localnetPort}},
			Operation{Command: "lsp-add-localnet-port", Flags: []string{"--may-exist"}, Args: []string{switchName, localnetPort, subnet.ProviderNetwork}},
			setOperation("logical_switch_port", localnetPort, "external_ids:netloom_owner=netloom", "external_ids:netloom_subnet="+subnet.Name, "external_ids:netloom_provider_network="+subnet.ProviderNetwork),
		)
		if subnet.VLAN != 0 {
			p.ops = append(p.ops, setOperation("logical_switch_port", localnetPort, fmt.Sprintf("tag=%d", subnet.VLAN)))
		}
	} else {
		p.ops = append(p.ops, Operation{Command: "lsp-del", Flags: []string{"--if-exists"}, Args: []string{localnetPortName(switchName, subnet.Name)}})
	}
	return nil
}

func (p *Planner) EnsureEndpoint(_ context.Context, endpoint model.Endpoint) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	port := logicalPort(endpoint.ID)
	p.ops = append(p.ops,
		Operation{Command: "lsp-add", Flags: []string{"--may-exist"}, Args: []string{logicalSwitch(endpoint.Subnet), port}},
		Operation{Command: "lsp-set-addresses", Args: []string{port, "dynamic " + endpoint.IP.String()}},
		setOperation("logical_switch_port", port, "external_ids:netloom_owner=netloom", "external_ids:netloom_endpoint="+endpoint.ID, "external_ids:netloom_node="+endpoint.Node, "external_ids:netloom_vpc="+endpoint.VPC, "external_ids:netloom_subnet="+endpoint.Subnet),
		Operation{Command: "lsp-set-dhcpv4-options", Args: []string{port}},
		Operation{Command: "lsp-set-dhcpv6-options", Args: []string{port}},
	)
	if subnet, ok := p.subnets[endpoint.Subnet]; ok && subnet.DHCP.Enabled && endpoint.IP.Is4() {
		dhcpID := dhcpOptionsUUID(endpoint, 4)
		p.ops = append(p.ops,
			Operation{Command: "create", Flags: []string{"--id=" + dhcpID}, Args: dhcpv4OptionsArgs(subnet, endpoint)},
			Operation{Command: "set", Args: []string{"logical_switch_port", port, "dhcpv4_options=" + dhcpID}},
		)
	}
	if subnet, ok := p.subnets[endpoint.Subnet]; ok && subnet.DHCP.Enabled && endpoint.IP.Is6() {
		dhcpID := dhcpOptionsUUID(endpoint, 6)
		p.ops = append(p.ops,
			Operation{Command: "create", Flags: []string{"--id=" + dhcpID}, Args: dhcpv6OptionsArgs(subnet, endpoint)},
			Operation{Command: "set", Args: []string{"logical_switch_port", port, "dhcpv6_options=" + dhcpID}},
		)
	}
	return nil
}

func (p *Planner) EnsureRouteTable(_ context.Context, table model.RouteTable) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	router := p.routerForVPC(table.VPC)
	for _, route := range table.Routes {
		p.ops = append(p.ops, Operation{Command: "lr-route-del", Flags: []string{"--if-exists"}, Args: []string{router, route.Destination.String()}})
		if route.Blackhole {
			p.ops = append(p.ops, Operation{Command: "lr-route-add", Flags: []string{"--may-exist"}, Args: []string{router, route.Destination.String(), "discard"}})
			continue
		}
		nextHops := route.RouteNextHops()
		if len(nextHops) == 1 {
			p.ops = append(p.ops, Operation{Command: "lr-route-add", Flags: []string{"--may-exist"}, Args: []string{router, route.Destination.String(), nextHops[0].String()}})
			continue
		}
		for _, nextHop := range nextHops {
			p.ops = append(p.ops, Operation{Command: "lr-route-add", Flags: []string{"--may-exist", "--ecmp"}, Args: []string{router, route.Destination.String(), nextHop.String()}})
		}
	}
	return nil
}

func (p *Planner) EnsurePolicyRoute(_ context.Context, route model.PolicyRoute) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	router := p.routerForVPC(route.VPC)
	match := policyRouteMatch(route.Match)
	action := route.Action.Type
	p.ops = append(p.ops, Operation{Command: "lr-policy-del", Flags: []string{"--if-exists"}, Args: []string{router, fmt.Sprint(route.Priority), match}})
	if action == model.ActionReroute {
		nextHops := route.Action.RerouteNextHops()
		if len(nextHops) == 1 {
			p.ops = append(p.ops, Operation{Command: "lr-policy-add", Flags: []string{"--may-exist"}, Args: []string{router, fmt.Sprint(route.Priority), match, "reroute", nextHops[0].String()}})
			return nil
		}
		uuid := namedUUID("nl_lrp_" + sanitize(route.Name))
		p.ops = append(p.ops,
			Operation{Command: "create", Flags: []string{"--id=" + uuid}, Args: logicalRouterPolicyArgs(route, match, nextHops)},
			Operation{Command: "add", Args: []string{"logical_router", router, "policies", uuid}},
		)
		return nil
	}
	p.ops = append(p.ops, Operation{Command: "lr-policy-add", Flags: []string{"--may-exist"}, Args: []string{router, fmt.Sprint(route.Priority), match, string(action)}})
	return nil
}

func (p *Planner) EnsureGateway(_ context.Context, gateway model.Gateway) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	router := p.routerForVPC(gateway.VPC)
	args := []string{
		router,
		"external_ids:netloom_gateway=" + gateway.Name,
		"external_ids:netloom_gateway_lan_ip=" + gateway.LANIP.String(),
		fmt.Sprintf("external_ids:netloom_gateway_distributed=%t", gateway.Distributed),
	}
	if !gateway.Distributed {
		args = append(args, "options:chassis="+gateway.Node)
	}
	if gateway.ExternalIF != "" {
		args = append(args, "external_ids:netloom_external_if="+gateway.ExternalIF)
	}
	p.ops = append(p.ops, setOperation("logical_router", router, append(args[1:], "external_ids:netloom_owner=netloom")...))
	if gateway.Distributed {
		p.ops = append(p.ops, Operation{Command: "remove", Args: []string{"logical_router", router, "options", "chassis"}})
	}
	return nil
}

func (p *Planner) EnsureNATRule(_ context.Context, rule model.NATRule) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	router := p.routerForVPC(rule.VPC)
	p.ops = append(p.ops, Operation{Command: "lr-nat-del", Flags: []string{"--if-exists"}, Args: []string{router, natType(rule.Type), natDeleteMatch(rule)}})
	switch rule.Type {
	case model.ActionSNAT:
		p.ops = append(p.ops, Operation{Command: "lr-nat-add", Flags: []string{"--may-exist"}, Args: []string{router, "snat", rule.ExternalIP.String(), rule.MatchCIDR.String()}})
	case model.ActionDNAT:
		if natUsesLoadBalancer(rule) {
			name := natLoadBalancerName(rule.Name)
			lb := natLoadBalancer(rule)
			p.ops = append(p.ops,
				Operation{Command: "lb-del", Flags: []string{"--if-exists"}, Args: []string{name, loadBalancerVIP(lb)}},
				Operation{Command: "lb-add", Flags: []string{"--may-exist"}, Args: []string{name, loadBalancerVIP(lb), loadBalancerBackends(lb), string(loadBalancerProtocol(lb))}},
				setOperation("load_balancer", name, "external_ids:netloom_owner=netloom", "external_ids:netloom_nat="+rule.Name, "external_ids:netloom_vpc="+rule.VPC),
				Operation{Command: "lr-lb-add", Flags: []string{"--may-exist"}, Args: []string{router, name}},
			)
			return nil
		}
		op := Operation{Command: "lr-nat-add", Flags: []string{"--may-exist"}, Args: []string{router, "dnat", rule.ExternalIP.String(), rule.TargetIP.String()}}
		if rule.ExternalPort != 0 {
			op.Flags = append([]string{"--portrange"}, op.Flags...)
			op.Args = append(op.Args, fmt.Sprint(rule.ExternalPort))
		}
		p.ops = append(p.ops, op)
	case model.ActionDNATSNAT:
		args := []string{router, "dnat_and_snat", rule.ExternalIP.String(), rule.TargetIP.String()}
		if rule.LogicalPort != "" {
			args = append(args, rule.LogicalPort, rule.ExternalMAC)
		}
		p.ops = append(p.ops, Operation{Command: "lr-nat-add", Flags: []string{"--may-exist"}, Args: args})
	}
	return nil
}

func (p *Planner) EnsureLoadBalancer(_ context.Context, lb model.LoadBalancer) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	name := loadBalancerName(lb.Name)
	router := p.routerForVPC(lb.VPC)
	p.ops = append(p.ops,
		Operation{Command: "lb-del", Flags: []string{"--if-exists"}, Args: []string{name, loadBalancerVIP(lb)}},
		Operation{Command: "lb-add", Flags: []string{"--may-exist"}, Args: []string{name, loadBalancerVIP(lb), loadBalancerBackends(lb), string(loadBalancerProtocol(lb))}},
		setOperation("load_balancer", name, loadBalancerOptions(lb)...),
		Operation{Command: "lr-lb-add", Flags: []string{"--may-exist"}, Args: []string{router, name}},
	)
	if !lb.SessionAffinity {
		p.ops = append(p.ops, Operation{Command: "remove", Args: []string{"load_balancer", name, "options", "affinity_timeout"}})
	}
	p.ops = append(p.ops, p.loadBalancerHealthCheckOperations(name, lb)...)
	for _, subnet := range lb.Subnets {
		p.ops = append(p.ops, Operation{Command: "ls-lb-add", Flags: []string{"--may-exist"}, Args: []string{logicalSwitch(subnet), name}})
	}
	return nil
}

func (p *Planner) Operations() []Operation {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Operation(nil), p.ops...)
}

func (p *Planner) Append(ops ...Operation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ops = append(p.ops, cloneOperations(ops)...)
}

func (p *Planner) SyncLoadBalancerHealthChecks(loadBalancers map[string]model.LoadBalancer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for name := range p.loadBalancerHealthChecks {
		if _, ok := loadBalancers[name]; !ok {
			delete(p.loadBalancerHealthChecks, name)
		}
	}
}

func setOperation(table, record string, pairs ...string) Operation {
	args := append([]string{table, record}, pairs...)
	return Operation{Command: "set", Args: args}
}

func (p *Planner) routerForVPC(vpc string) string {
	if router := p.vpcRouters[vpc]; router != "" {
		return router
	}
	router := logicalRouter(vpc)
	p.vpcRouters[vpc] = router
	return router
}

func logicalRouter(vpc string) string {
	return "nl_lr_" + sanitize(vpc)
}

func logicalSwitch(subnet string) string {
	return "nl_ls_" + sanitize(subnet)
}

func logicalPort(endpoint string) string {
	return "nl_lp_" + sanitize(endpoint)
}

func loadBalancerName(name string) string {
	return "nl_lb_" + sanitize(name)
}

func namedUUID(name string) string {
	replacer := strings.NewReplacer("-", "_")
	return "@" + replacer.Replace(name)
}

func routerPortName(router, subnet string) string {
	return router + "_to_" + sanitize(subnet)
}

func switchRouterPortName(switchName, subnet string) string {
	return switchName + "_to_" + sanitize(subnet) + "_router"
}

func localnetPortName(switchName, subnet string) string {
	return switchName + "_to_" + sanitize(subnet) + "_localnet"
}

func sanitize(value string) string {
	replacer := strings.NewReplacer("/", "_", ":", "_", ".", "_")
	return replacer.Replace(value)
}

func deterministicMAC(ip netip.Addr) string {
	if ip.Is4() {
		raw := ip.As4()
		return fmt.Sprintf("0a:58:%02x:%02x:%02x:%02x", raw[0], raw[1], raw[2], raw[3])
	}
	raw := ip.As16()
	return fmt.Sprintf("0a:58:%02x:%02x:%02x:%02x", raw[12], raw[13], raw[14], raw[15])
}

func dhcpOptionsUUID(endpoint model.Endpoint, family int) string {
	if family == 6 {
		return namedUUID("nl_dhcp6_" + sanitize(endpoint.ID))
	}
	return namedUUID("nl_dhcp_" + sanitize(endpoint.ID))
}

func dhcpv4OptionsArgs(subnet model.Subnet, endpoint model.Endpoint) []string {
	leaseTime := subnet.DHCP.LeaseTime
	if leaseTime == 0 {
		leaseTime = 3600
	}
	args := []string{
		"DHCP_Options",
		"cidr=" + subnet.CIDR.String(),
		"options:server_id=" + subnet.Gateway.String(),
		"options:server_mac=" + deterministicMAC(subnet.Gateway),
		"options:router=" + subnet.Gateway.String(),
		fmt.Sprintf("options:lease_time=%d", leaseTime),
		"external_ids:netloom_owner=netloom",
		"external_ids:netloom_subnet=" + subnet.Name,
		"external_ids:netloom_endpoint=" + endpoint.ID,
	}
	if subnet.DHCP.MTU != 0 {
		args = append(args, fmt.Sprintf("options:mtu=%d", subnet.DHCP.MTU))
	}
	return args
}

func dhcpv6OptionsArgs(subnet model.Subnet, endpoint model.Endpoint) []string {
	args := []string{
		"DHCP_Options",
		"cidr=" + subnet.CIDR.String(),
		"options:server_id=" + deterministicMAC(subnet.Gateway),
		"external_ids:netloom_owner=netloom",
		"external_ids:netloom_subnet=" + subnet.Name,
		"external_ids:netloom_endpoint=" + endpoint.ID,
	}
	return args
}

func loadBalancerVIP(lb model.LoadBalancer) string {
	return netip.AddrPortFrom(lb.VIP, lb.Port).String()
}

func loadBalancerBackends(lb model.LoadBalancer) string {
	backends := make([]string, 0, len(lb.Backends))
	for _, backend := range lb.Backends {
		if !backend.IsHealthy() {
			continue
		}
		backends = append(backends, netip.AddrPortFrom(backend.IP, backend.Port).String())
	}
	sort.Strings(backends)
	return strings.Join(backends, ",")
}

func loadBalancerProtocol(lb model.LoadBalancer) model.Protocol {
	if lb.Protocol == "" {
		return model.ProtocolTCP
	}
	return lb.Protocol
}

func natUsesLoadBalancer(rule model.NATRule) bool {
	return rule.Type == model.ActionDNAT &&
		rule.ExternalPort != 0 &&
		rule.TargetPort != 0 &&
		rule.ExternalPort != rule.TargetPort
}

func natLoadBalancerName(ruleName string) string {
	replacer := strings.NewReplacer("-", "_")
	return "nl_natlb_" + replacer.Replace(sanitize(ruleName))
}

func natLoadBalancer(rule model.NATRule) model.LoadBalancer {
	return model.LoadBalancer{
		Name:     rule.Name,
		VPC:      rule.VPC,
		VIP:      rule.ExternalIP,
		Port:     rule.ExternalPort,
		Protocol: rule.Protocol,
		Backends: []model.LoadBalancerBackend{{
			IP:   rule.TargetIP,
			Port: rule.TargetPort,
		}},
	}
}

func loadBalancerOptions(lb model.LoadBalancer) []string {
	options := []string{
		"external_ids:netloom_owner=netloom",
		"external_ids:netloom_load_balancer=" + lb.Name,
		"external_ids:netloom_vpc=" + lb.VPC,
		"selection_fields=" + ovnStringSetValues(lb.EffectiveSelectionFields()),
	}
	if lb.SessionAffinity {
		timeout := lb.AffinityTimeout
		if timeout == 0 {
			timeout = 10800
		}
		options = append(options,
			"options:affinity_timeout="+fmt.Sprint(timeout),
			"external_ids:netloom_session_affinity=true",
		)
		return options
	}
	return append(options, "external_ids:netloom_session_affinity=false")
}

func (p *Planner) loadBalancerHealthCheckOperations(name string, lb model.LoadBalancer) []Operation {
	if !lb.HealthCheck.Enabled {
		delete(p.loadBalancerHealthChecks, lb.Name)
		return []Operation{{Command: "clear", Args: []string{"load_balancer", name, "health_check"}}}
	}
	signature := loadBalancerHealthCheckSignature(lb)
	if p.loadBalancerHealthChecks[lb.Name] == signature {
		return nil
	}
	p.loadBalancerHealthChecks[lb.Name] = signature
	uuid := loadBalancerHealthCheckUUID(lb.Name)
	return []Operation{
		{Command: "clear", Args: []string{"load_balancer", name, "health_check"}},
		{Command: "create", Flags: []string{"--id=" + uuid}, Args: loadBalancerHealthCheckArgs(lb)},
		{Command: "add", Args: []string{"load_balancer", name, "health_check", uuid}},
	}
}

func loadBalancerHealthCheckSignature(lb model.LoadBalancer) string {
	return strings.Join(loadBalancerHealthCheckArgs(lb), "|")
}

func loadBalancerHealthCheckUUID(lbName string) string {
	return namedUUID("nl_lbhc_" + sanitize(lbName))
}

func loadBalancerHealthCheckArgs(lb model.LoadBalancer) []string {
	hc := lb.HealthCheck
	interval := hc.Interval
	if interval == 0 {
		interval = 5
	}
	timeout := hc.Timeout
	if timeout == 0 {
		timeout = 20
	}
	successCount := hc.SuccessCount
	if successCount == 0 {
		successCount = 3
	}
	failureCount := hc.FailureCount
	if failureCount == 0 {
		failureCount = 3
	}
	return []string{
		"Load_Balancer_Health_Check",
		"vip=" + loadBalancerVIP(lb),
		fmt.Sprintf("options:interval=%d", interval),
		fmt.Sprintf("options:timeout=%d", timeout),
		fmt.Sprintf("options:success_count=%d", successCount),
		fmt.Sprintf("options:failure_count=%d", failureCount),
		"external_ids:netloom_owner=netloom",
		"external_ids:netloom_load_balancer=" + lb.Name,
		"external_ids:netloom_vpc=" + lb.VPC,
	}
}

func logicalRouterPolicyArgs(route model.PolicyRoute, match string, nextHops []netip.Addr) []string {
	args := []string{
		"Logical_Router_Policy",
		fmt.Sprintf("priority=%d", route.Priority),
		"match=" + match,
		"action=reroute",
		"nexthops=" + ovnStringSet(nextHops),
		"external_ids:netloom_owner=netloom",
		"external_ids:netloom_policy_route=" + route.Name,
		"external_ids:netloom_vpc=" + route.VPC,
	}
	return args
}

func ovnStringSet(addrs []netip.Addr) string {
	values := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		values = append(values, addr.String())
	}
	return ovnStringSetValues(values)
}

func ovnStringSetValues(values []string) string {
	sort.Strings(values)
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, `"`+value+`"`)
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

func policyRouteMatch(match model.RouteMatch) string {
	parts := []string{}
	if match.Source.IsValid() {
		parts = append(parts, ipFamily(match.Source)+".src == "+match.Source.String())
	}
	if match.Destination.IsValid() {
		parts = append(parts, ipFamily(match.Destination)+".dst == "+match.Destination.String())
	}
	if match.Protocol != "" && match.Protocol != model.ProtocolAny {
		parts = append(parts, string(match.Protocol))
	}
	for _, port := range match.DstPorts {
		if port.From == port.To {
			parts = append(parts, fmt.Sprintf("%s.dst == %d", match.Protocol, port.From))
		} else {
			parts = append(parts, fmt.Sprintf("%s.dst >= %d && %s.dst <= %d", match.Protocol, port.From, match.Protocol, port.To))
		}
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "1 == 1"
	}
	return strings.Join(parts, " && ")
}

func ipFamily(prefix netip.Prefix) string {
	if prefix.Addr().Is6() {
		return "ip6"
	}
	return "ip4"
}
