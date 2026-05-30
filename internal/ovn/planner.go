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
	mu         sync.Mutex
	ops        []Operation
	vpcRouters map[string]string
	subnets    map[string]model.Subnet
}

func NewPlanner() *Planner {
	return &Planner{
		vpcRouters: make(map[string]string),
		subnets:    make(map[string]model.Subnet),
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
	if subnet.ProviderNetwork != "" {
		localnetPort := localnetPortName(switchName, subnet.Name)
		p.ops = append(p.ops,
			Operation{Command: "lsp-add-localnet-port", Flags: []string{"--may-exist"}, Args: []string{switchName, localnetPort, subnet.ProviderNetwork}},
			setOperation("logical_switch_port", localnetPort, "external_ids:netloom_owner=netloom", "external_ids:netloom_subnet="+subnet.Name, "external_ids:netloom_provider_network="+subnet.ProviderNetwork),
		)
		if subnet.VLAN != 0 {
			p.ops = append(p.ops, setOperation("logical_switch_port", localnetPort, fmt.Sprintf("tag=%d", subnet.VLAN)))
		}
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
	)
	if subnet, ok := p.subnets[endpoint.Subnet]; ok && subnet.DHCP.Enabled && endpoint.IP.Is4() {
		dhcpID := namedUUID("nl_dhcp_" + sanitize(endpoint.ID))
		p.ops = append(p.ops,
			Operation{Command: "create", Flags: []string{"--id=" + dhcpID}, Args: dhcpOptionsArgs(subnet, endpoint)},
			Operation{Command: "set", Args: []string{"logical_switch_port", port, "dhcpv4_options=" + dhcpID}},
		)
	}
	return nil
}

func (p *Planner) EnsureRouteTable(_ context.Context, table model.RouteTable) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	router := p.routerForVPC(table.VPC)
	for _, route := range table.Routes {
		if route.Blackhole {
			p.ops = append(p.ops, Operation{Command: "lr-route-add", Flags: []string{"--may-exist"}, Args: []string{router, route.Destination.String(), "discard"}})
			continue
		}
		p.ops = append(p.ops, Operation{Command: "lr-route-add", Flags: []string{"--may-exist"}, Args: []string{router, route.Destination.String(), route.NextHop.String()}})
	}
	return nil
}

func (p *Planner) EnsurePolicyRoute(_ context.Context, route model.PolicyRoute) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	router := p.routerForVPC(route.VPC)
	match := policyRouteMatch(route.Match)
	action := route.Action.Type
	if action == model.ActionReroute {
		p.ops = append(p.ops, Operation{Command: "lr-policy-add", Flags: []string{"--may-exist"}, Args: []string{router, fmt.Sprint(route.Priority), match, "reroute", route.Action.NextHop.String()}})
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
		op := Operation{Command: "lr-nat-add", Flags: []string{"--may-exist"}, Args: []string{router, "dnat", rule.ExternalIP.String(), rule.TargetIP.String()}}
		if rule.ExternalPort != 0 {
			op.Flags = append([]string{"--portrange"}, op.Flags...)
			op.Args = append(op.Args, fmt.Sprint(rule.ExternalPort))
		}
		p.ops = append(p.ops, op)
	case model.ActionDNATSNAT:
		p.ops = append(p.ops, Operation{Command: "lr-nat-add", Flags: []string{"--may-exist"}, Args: []string{router, "dnat_and_snat", rule.ExternalIP.String(), rule.TargetIP.String()}})
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
		setOperation("load_balancer", name, "external_ids:netloom_owner=netloom", "external_ids:netloom_load_balancer="+lb.Name, "external_ids:netloom_vpc="+lb.VPC),
		Operation{Command: "lr-lb-add", Flags: []string{"--may-exist"}, Args: []string{router, name}},
	)
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

func dhcpOptionsArgs(subnet model.Subnet, endpoint model.Endpoint) []string {
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

func loadBalancerVIP(lb model.LoadBalancer) string {
	return netip.AddrPortFrom(lb.VIP, lb.Port).String()
}

func loadBalancerBackends(lb model.LoadBalancer) string {
	backends := make([]string, 0, len(lb.Backends))
	for _, backend := range lb.Backends {
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

func policyRouteMatch(match model.RouteMatch) string {
	parts := []string{}
	if match.Source.IsValid() {
		parts = append(parts, "ip4.src == "+match.Source.String())
	}
	if match.Destination.IsValid() {
		parts = append(parts, "ip4.dst == "+match.Destination.String())
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
