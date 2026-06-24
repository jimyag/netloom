package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jimyag/netloom/internal/agent"
	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/linuxdatapath"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
	"github.com/jimyag/netloom/internal/topology"
	"golang.org/x/sys/unix"
)

const (
	defaultBPFFSRoot      = "/sys/fs/bpf"
	defaultBPFFSPinRoot   = "/sys/fs/bpf/netloom/policy"
	defaultRuntimeBPFRoot = "/var/run/netloom-ebpf"
	defaultRuntimePinRoot = "/var/run/netloom-ebpf/policy"
	defaultMetadataRoot   = "/var/run/netloom-ebpf-meta/policy"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "policy-explain":
			if err := runPolicyExplain(os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "policy-status":
			if err := runPolicyStatus(os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "route-explain":
			if err := runRouteExplain(os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		}
	}

	if stateFile := os.Getenv("NETLOOM_STATE_FILE"); stateFile != "" {
		if err := runStateFile(context.Background(), stateFile); err != nil {
			log.Fatal(err)
		}
		return
	}

	result, err := agent.RunSelfTest(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("netloom-agent ready for node policy and dataplane reconciliation endpoint=%s entries=%d allow=%s deny=%s policy_allowed=%d policy_dropped=%d policy_conntrack=%d policy_established=%d policy_logged=%d rule_stats=%s drop_events=%d policy_events=%d trace_events=%d tcx=%s\n", result.EndpointID, result.Entries, result.Allowed, result.Denied, result.PolicyStats.Allowed, result.PolicyStats.Dropped, result.PolicyStats.Conntrack, result.PolicyStats.Established, result.PolicyStats.Logged, formatRuleStats(result.RuleStats), result.DropEvents, result.PolicyEvents, result.TraceEvents, result.TCX)
}

type policyExplainOptions struct {
	stateFile      string
	vpc            string
	endpoint       string
	remoteEndpoint string
	remoteVPC      string
	remoteIdentity uint
	remoteIP       string
	direction      string
	protocol       string
	sourcePort     uint
	destPort       uint
	icmpType       int
	icmpCode       int
	stateful       bool
}

type policyStatusOptions struct {
	stateFile string
	node      string
	endpoint  string
}

type routeExplainOptions struct {
	stateFile  string
	vpc        string
	source     string
	dest       string
	protocol   string
	sourcePort uint
	destPort   uint
}

type policyStatusOutput struct {
	Node                 string                           `json:"node"`
	Store                string                           `json:"store"`
	Ready                bool                             `json:"ready"`
	LastReconcileSuccess bool                             `json:"last_reconcile_success"`
	LastReconcileError   string                           `json:"last_reconcile_error,omitempty"`
	EndpointCount        int                              `json:"endpoint_count"`
	PolicyMapEntries     uint32                           `json:"policy_map_entries"`
	PolicyMapCapacity    uint32                           `json:"policy_map_capacity"`
	PressureMax          uint32                           `json:"pressure_max"`
	PressureEndpoint     string                           `json:"pressure_endpoint,omitempty"`
	PressureEndpoints    int                              `json:"pressure_endpoints"`
	DriftEndpoints       int                              `json:"drift_endpoints"`
	DriftMissing         int                              `json:"drift_missing"`
	DriftExtra           int                              `json:"drift_extra"`
	DriftChanged         int                              `json:"drift_changed"`
	PolicyRevisionMax    uint64                           `json:"policy_revision_max"`
	Statuses             []dataplane.PolicyEndpointStatus `json:"statuses"`
}

func runPolicyExplain(args []string, stdout io.Writer) error {
	var opts policyExplainOptions
	flags := flag.NewFlagSet("netloom-agent policy-explain", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.stateFile, "state", os.Getenv("NETLOOM_STATE_FILE"), "desired-state JSON path")
	flags.StringVar(&opts.vpc, "vpc", "", "endpoint VPC")
	flags.StringVar(&opts.endpoint, "endpoint", "", "endpoint ID")
	flags.StringVar(&opts.remoteEndpoint, "remote-endpoint", "", "remote endpoint ID used to derive identity and default remote IP")
	flags.StringVar(&opts.remoteVPC, "remote-vpc", "", "remote endpoint VPC; defaults to -vpc")
	flags.UintVar(&opts.remoteIdentity, "remote-identity", 0, "remote identity")
	flags.StringVar(&opts.remoteIP, "remote-ip", "", "remote IP")
	flags.StringVar(&opts.direction, "direction", "", "ingress or egress")
	flags.StringVar(&opts.protocol, "protocol", "tcp", "tcp, udp, icmp, icmpv6, or any")
	flags.UintVar(&opts.sourcePort, "source-port", 0, "source port")
	flags.UintVar(&opts.destPort, "dest-port", 0, "destination port")
	flags.IntVar(&opts.icmpType, "icmp-type", 0, "ICMP type")
	flags.IntVar(&opts.icmpCode, "icmp-code", 0, "ICMP code")
	flags.BoolVar(&opts.stateful, "stateful", false, "explain stateful policy behavior")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if opts.stateFile == "" {
		return errors.New("missing -state or NETLOOM_STATE_FILE")
	}
	if opts.vpc == "" {
		return errors.New("missing -vpc")
	}
	if opts.endpoint == "" {
		return errors.New("missing -endpoint")
	}
	if opts.direction == "" {
		return errors.New("missing -direction")
	}

	file, err := os.Open(opts.stateFile)
	if err != nil {
		return err
	}
	defer file.Close()
	state, err := control.LoadDesiredStateJSON(file)
	if err != nil {
		return err
	}
	state, err = withDNSObservations(state)
	if err != nil {
		return err
	}
	explanation, err := explainPolicyFromState(state, opts)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(explanation)
}

func runPolicyStatus(args []string, stdout io.Writer) error {
	var opts policyStatusOptions
	flags := flag.NewFlagSet("netloom-agent policy-status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.stateFile, "state", os.Getenv("NETLOOM_STATE_FILE"), "desired-state JSON path")
	flags.StringVar(&opts.node, "node", os.Getenv("NETLOOM_NODE_NAME"), "node name")
	flags.StringVar(&opts.endpoint, "endpoint", "", "optional endpoint key or endpoint ID to include")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if opts.stateFile == "" {
		return errors.New("missing -state or NETLOOM_STATE_FILE")
	}
	if strings.TrimSpace(opts.node) == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		opts.node = hostname
	}

	file, err := os.Open(opts.stateFile)
	if err != nil {
		return err
	}
	defer file.Close()
	state, err := control.LoadDesiredStateJSON(file)
	if err != nil {
		return err
	}
	state, err = withDNSObservations(state)
	if err != nil {
		return err
	}
	store, storeName, closeStore := policyStore()
	defer closeStore()
	result, err := agent.ReconcileNodeWithOptions(context.Background(), state, agent.ReconcileOptions{
		Node:  opts.node,
		Store: store,
	})
	if err != nil {
		return err
	}
	statuses := filterPolicyEndpointStatuses(result.PolicyEndpointStatus, opts.endpoint, state.Endpoints)
	output := policyStatusOutputFromResult(result, storeName, statuses)
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runRouteExplain(args []string, stdout io.Writer) error {
	var opts routeExplainOptions
	flags := flag.NewFlagSet("netloom-agent route-explain", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.stateFile, "state", os.Getenv("NETLOOM_STATE_FILE"), "desired-state JSON path")
	flags.StringVar(&opts.vpc, "vpc", "", "packet VPC")
	flags.StringVar(&opts.source, "source", "", "packet source IP")
	flags.StringVar(&opts.dest, "dest", "", "packet destination IP")
	flags.StringVar(&opts.protocol, "protocol", "any", "any, tcp, udp, or icmp")
	flags.UintVar(&opts.sourcePort, "source-port", 0, "source port")
	flags.UintVar(&opts.destPort, "dest-port", 0, "destination port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if opts.stateFile == "" {
		return errors.New("missing -state or NETLOOM_STATE_FILE")
	}
	file, err := os.Open(opts.stateFile)
	if err != nil {
		return err
	}
	defer file.Close()
	state, err := control.LoadDesiredStateJSON(file)
	if err != nil {
		return err
	}
	decision, err := explainRouteFromState(state, opts)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(decision)
}

func filterPolicyEndpointStatuses(statuses []dataplane.PolicyEndpointStatus, endpoint string, endpoints []model.Endpoint) []dataplane.PolicyEndpointStatus {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return append([]dataplane.PolicyEndpointStatus(nil), statuses...)
	}
	keys := map[string]struct{}{endpoint: {}}
	if vpc, id, ok := strings.Cut(endpoint, "/"); ok && vpc != "" && id != "" {
		keys[model.EndpointKey(vpc, id)] = struct{}{}
	}
	for _, candidate := range endpoints {
		if candidate.ID == endpoint {
			keys[model.EndpointKey(candidate.VPC, candidate.ID)] = struct{}{}
		}
	}
	filtered := make([]dataplane.PolicyEndpointStatus, 0, len(statuses))
	for _, status := range statuses {
		if _, ok := keys[status.EndpointID]; ok {
			filtered = append(filtered, status)
			continue
		}
		if vpc, id, ok := strings.Cut(status.EndpointID, "\x00"); ok && (id == endpoint || vpc+"/"+id == endpoint) {
			filtered = append(filtered, status)
		}
	}
	return filtered
}

func policyStatusOutputFromResult(result agent.ReconcileResult, storeName string, statuses []dataplane.PolicyEndpointStatus) policyStatusOutput {
	return policyStatusOutput{
		Node:              result.Node,
		Store:             storeName,
		EndpointCount:     len(statuses),
		PolicyMapEntries:  result.PolicyMapEntries,
		PolicyMapCapacity: result.PolicyMapCapacity,
		PressureMax:       result.PolicyMapPressureMax,
		PressureEndpoint:  result.PolicyMapPressureEndpoint,
		PressureEndpoints: result.PolicyMapPressureEndpoints,
		DriftEndpoints:    result.PolicyMapDriftEndpoints,
		DriftMissing:      result.PolicyMapDriftMissing,
		DriftExtra:        result.PolicyMapDriftExtra,
		DriftChanged:      result.PolicyMapDriftChanged,
		PolicyRevisionMax: result.PolicyRevisionMax,
		Statuses:          statuses,
	}
}

func explainRouteFromState(state control.DesiredState, opts routeExplainOptions) (topology.Decision, error) {
	packet, err := routePacketFromExplainOptions(opts)
	if err != nil {
		return topology.Decision{}, err
	}
	return topology.Resolve(topologyStateFromDesired(state), packet)
}

func routePacketFromExplainOptions(opts routeExplainOptions) (topology.Packet, error) {
	if opts.vpc == "" {
		return topology.Packet{}, errors.New("missing -vpc")
	}
	source, err := parseRequiredAddr("source", opts.source)
	if err != nil {
		return topology.Packet{}, err
	}
	dest, err := parseRequiredAddr("dest", opts.dest)
	if err != nil {
		return topology.Packet{}, err
	}
	protocol, err := parseRouteProtocol(opts.protocol)
	if err != nil {
		return topology.Packet{}, err
	}
	sourcePort, err := parseUint16Flag("source-port", opts.sourcePort)
	if err != nil {
		return topology.Packet{}, err
	}
	destPort, err := parseUint16Flag("dest-port", opts.destPort)
	if err != nil {
		return topology.Packet{}, err
	}
	return topology.Packet{
		SourcePort: sourcePort,
		VPC:        opts.vpc,
		Source:     source,
		Dest:       dest,
		Protocol:   protocol,
		DestPort:   destPort,
	}, nil
}

func parseRouteProtocol(value string) (model.Protocol, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(model.ProtocolAny):
		return model.ProtocolAny, nil
	case string(model.ProtocolTCP):
		return model.ProtocolTCP, nil
	case string(model.ProtocolUDP):
		return model.ProtocolUDP, nil
	case string(model.ProtocolICMP), "icmpv6":
		return model.ProtocolICMP, nil
	default:
		return "", fmt.Errorf("unsupported protocol %q", value)
	}
}

func topologyStateFromDesired(state control.DesiredState) topology.State {
	vpcs := make(map[string]model.VPC, len(state.VPCs))
	for _, vpc := range state.VPCs {
		vpcs[vpc.Name] = vpc
	}
	subnets := make(map[string]model.Subnet, len(state.Subnets))
	for _, subnet := range state.Subnets {
		subnets[subnet.VPC+"\x00"+subnet.Name] = subnet
	}
	endpoints := make(map[string]model.Endpoint, len(state.Endpoints))
	for _, endpoint := range state.Endpoints {
		endpoints[model.EndpointKey(endpoint.VPC, endpoint.ID)] = endpoint
	}
	routeTables := make(map[string]model.RouteTable, len(state.RouteTables))
	for _, table := range state.RouteTables {
		routeTables[table.VPC+"\x00"+table.Name] = table
	}
	gateways := make(map[string]model.Gateway, len(state.Gateways))
	for _, gateway := range state.Gateways {
		gateways[gateway.VPC+"\x00"+gateway.Name] = gateway
	}
	natRules := make(map[string]model.NATRule, len(state.NATRules))
	for _, rule := range state.NATRules {
		natRules[rule.VPC+"\x00"+rule.Name] = rule
	}
	loadBalancers := make(map[string]model.LoadBalancer, len(state.LoadBalancers))
	for _, lb := range state.LoadBalancers {
		loadBalancers[lb.VPC+"\x00"+lb.Name] = lb
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

func cloneDesiredState(state control.DesiredState) control.DesiredState {
	return control.DesiredState{
		VPCs:             append([]model.VPC(nil), state.VPCs...),
		Subnets:          append([]model.Subnet(nil), state.Subnets...),
		Endpoints:        append([]model.Endpoint(nil), state.Endpoints...),
		RouteTables:      append([]model.RouteTable(nil), state.RouteTables...),
		PolicyRoutes:     append([]model.PolicyRoute(nil), state.PolicyRoutes...),
		Gateways:         append([]model.Gateway(nil), state.Gateways...),
		NATRules:         append([]model.NATRule(nil), state.NATRules...),
		LoadBalancers:    append([]model.LoadBalancer(nil), state.LoadBalancers...),
		SecurityGroups:   append([]model.SecurityGroup(nil), state.SecurityGroups...),
		CIDRGroups:       append([]model.CIDRGroup(nil), state.CIDRGroups...),
		ProviderNetworks: append([]model.ProviderNetwork(nil), state.ProviderNetworks...),
		DNSRecords:       append([]model.DNSRecord(nil), state.DNSRecords...),
	}
}

func explainPolicyFromState(state control.DesiredState, opts policyExplainOptions) (dataplane.PolicyExplanation, error) {
	endpoint, ok := findEndpoint(state.Endpoints, opts.vpc, opts.endpoint)
	if !ok {
		return dataplane.PolicyExplanation{}, fmt.Errorf("endpoint %s/%s not found", opts.vpc, opts.endpoint)
	}
	remoteEndpoint, hasRemoteEndpoint, err := resolveRemoteEndpoint(state.Endpoints, opts)
	if err != nil {
		return dataplane.PolicyExplanation{}, err
	}
	groups := securityGroupsForEndpoint(state.SecurityGroups, endpoint.VPC)
	program, err := policy.CompileForEndpointWithContext(endpoint, groups, policy.CompileContext{
		Endpoints:  state.Endpoints,
		Subnets:    state.Subnets,
		Gateways:   state.Gateways,
		Services:   state.LoadBalancers,
		DNSRecords: state.DNSRecords,
		CIDRGroups: state.CIDRGroups,
	})
	if err != nil {
		return dataplane.PolicyExplanation{}, err
	}
	entries, err := dataplane.EncodeProgram(program)
	if err != nil {
		return dataplane.PolicyExplanation{}, err
	}
	packet, err := packetFromExplainOptions(opts, remoteEndpoint, hasRemoteEndpoint)
	if err != nil {
		return dataplane.PolicyExplanation{}, err
	}
	if opts.stateful {
		return dataplane.ExplainStateful(program.EndpointID, entries, packet, dataplane.NewInMemoryConntrackStore()), nil
	}
	return dataplane.Explain(program.EndpointID, entries, packet), nil
}

func securityGroupsForEndpoint(groups []model.SecurityGroup, vpc string) map[string]model.SecurityGroup {
	out := make(map[string]model.SecurityGroup, len(groups))
	for _, group := range groups {
		if group.VPC == vpc {
			out[group.Name] = group
		}
	}
	return out
}

func findEndpoint(endpoints []model.Endpoint, vpc, id string) (model.Endpoint, bool) {
	for _, endpoint := range endpoints {
		if endpoint.VPC == vpc && endpoint.ID == id {
			return endpoint, true
		}
	}
	return model.Endpoint{}, false
}

func resolveRemoteEndpoint(endpoints []model.Endpoint, opts policyExplainOptions) (model.Endpoint, bool, error) {
	if opts.remoteEndpoint == "" {
		return model.Endpoint{}, false, nil
	}
	remoteVPC := opts.remoteVPC
	if remoteVPC == "" {
		remoteVPC = opts.vpc
	}
	endpoint, ok := findEndpoint(endpoints, remoteVPC, opts.remoteEndpoint)
	if !ok {
		return model.Endpoint{}, false, fmt.Errorf("remote endpoint %s/%s not found", remoteVPC, opts.remoteEndpoint)
	}
	return endpoint, true, nil
}

func packetFromExplainOptions(opts policyExplainOptions, remoteEndpoint model.Endpoint, hasRemoteEndpoint bool) (dataplane.Packet, error) {
	direction, err := parsePacketDirection(opts.direction)
	if err != nil {
		return dataplane.Packet{}, err
	}
	remoteIP, err := parseOptionalAddr(opts.remoteIP)
	if err != nil {
		return dataplane.Packet{}, err
	}
	remoteIdentity := uint32(opts.remoteIdentity)
	if hasRemoteEndpoint {
		if !remoteIP.IsValid() {
			remoteIP = remoteEndpoint.IP
		}
		if remoteIdentity == 0 {
			remoteIdentity = policy.EndpointIdentity(model.EndpointKey(remoteEndpoint.VPC, remoteEndpoint.ID))
		}
	}
	protocol, err := parsePacketProtocol(opts.protocol, remoteIP)
	if err != nil {
		return dataplane.Packet{}, err
	}
	sourcePort, err := parseUint16Flag("source-port", opts.sourcePort)
	if err != nil {
		return dataplane.Packet{}, err
	}
	destPort, err := parseUint16Flag("dest-port", opts.destPort)
	if err != nil {
		return dataplane.Packet{}, err
	}
	icmpType, err := parseUint8Flag("icmp-type", opts.icmpType)
	if err != nil {
		return dataplane.Packet{}, err
	}
	icmpCode, err := parseUint8Flag("icmp-code", opts.icmpCode)
	if err != nil {
		return dataplane.Packet{}, err
	}
	return dataplane.Packet{
		SourcePort:     sourcePort,
		RemoteIdentity: remoteIdentity,
		RemoteIP:       remoteIP,
		Direction:      direction,
		Protocol:       protocol,
		DestPort:       destPort,
		ICMPType:       icmpType,
		ICMPCode:       icmpCode,
	}, nil
}

func parsePacketDirection(value string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(model.DirectionIngress):
		return dataplane.DirectionIngress, nil
	case string(model.DirectionEgress):
		return dataplane.DirectionEgress, nil
	default:
		return 0, fmt.Errorf("unsupported direction %q", value)
	}
}

func parsePacketProtocol(value string, remoteIP netip.Addr) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(model.ProtocolAny):
		return 0, nil
	case string(model.ProtocolTCP):
		return 6, nil
	case string(model.ProtocolUDP):
		return 17, nil
	case string(model.ProtocolICMP):
		if remoteIP.IsValid() && remoteIP.Is6() && !remoteIP.Is4() {
			return 58, nil
		}
		return 1, nil
	case "icmpv6":
		return 58, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q", value)
	}
}

func parseOptionalAddr(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid remote IP %q: %w", value, err)
	}
	return addr, nil
}

func parseRequiredAddr(name, value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, fmt.Errorf("missing -%s", name)
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid %s IP %q: %w", name, value, err)
	}
	return addr, nil
}

func parseUint16Flag(name string, value uint) (uint16, error) {
	if value > 0xffff {
		return 0, fmt.Errorf("-%s must be <= 65535", name)
	}
	return uint16(value), nil
}

func parseUint8Flag(name string, value int) (uint8, error) {
	if value < 0 || value > 0xff {
		return 0, fmt.Errorf("-%s must be between 0 and 255", name)
	}
	return uint8(value), nil
}

func runStateFile(ctx context.Context, path string) error {
	node := os.Getenv("NETLOOM_NODE_NAME")
	if node == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		node = hostname
	}
	store, storeName, closeStore := policyStore()
	defer closeStore()
	hold, err := tcxHold()
	if err != nil {
		return err
	}
	interval, err := reconcileInterval()
	if err != nil {
		return err
	}
	if interval == 0 {
		return reconcileStateFileOnce(ctx, path, node, storeName, store, hold, nil)
	}
	reconciler := agent.NewReconciler(store)
	defer func() {
		_ = reconciler.Close()
	}()
	metrics := newAgentMetrics()
	if closeMetrics, err := startAgentMetricsServer(ctx, os.Getenv("NETLOOM_AGENT_METRICS_ADDR"), metrics); err != nil {
		return err
	} else {
		defer closeMetrics()
	}
	reconcile := func() error {
		return reconcileStateFile(ctx, path, node, storeName, reconciler, metrics)
	}
	for {
		if err := reconcile(); err != nil {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func reconcileStateFile(ctx context.Context, path, node, storeName string, reconciler *agent.Reconciler, metrics *agentMetrics) error {
	start := time.Now()
	file, err := os.Open(path)
	if err != nil {
		observeAgentReconcileFailure(metrics, agent.ReconcileResult{Node: node}, storeName, err, time.Since(start))
		return err
	}
	defer file.Close()

	state, err := control.LoadDesiredStateJSON(file)
	if err != nil {
		observeAgentReconcileFailure(metrics, agent.ReconcileResult{Node: node}, storeName, err, time.Since(start))
		return err
	}
	state, err = withDNSObservations(state)
	if err != nil {
		observeAgentReconcileFailure(metrics, agent.ReconcileResult{Node: node}, storeName, err, time.Since(start))
		return err
	}
	result, err := reconciler.Reconcile(ctx, state, agent.ReconcileOptions{
		Node:            node,
		TCXInterface:    os.Getenv("NETLOOM_TCX_IFACE"),
		TCXWorkload:     os.Getenv("NETLOOM_TCX_WORKLOAD") == "1",
		ConntrackIdle:   conntrackIdleTimeout(),
		PolicyGCMaxIdle: policyGCMaxIdle(),
		LinuxDatapath:   linuxDatapathOptions(),
	})
	if err != nil {
		duration := time.Since(start)
		printReconcileFailure(result, storeName, err, duration)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration)
		return err
	}
	duration := time.Since(start)
	printReconcileResult(result, storeName, duration)
	observeAgentReconcileResultWithState(metrics, result, storeName, duration, state)
	return nil
}

func reconcileStateFileOnce(ctx context.Context, path, node, storeName string, store agent.PolicyStore, hold time.Duration, metrics *agentMetrics) error {
	start := time.Now()
	file, err := os.Open(path)
	if err != nil {
		observeAgentReconcileFailure(metrics, agent.ReconcileResult{Node: node}, storeName, err, time.Since(start))
		return err
	}
	defer file.Close()

	state, err := control.LoadDesiredStateJSON(file)
	if err != nil {
		observeAgentReconcileFailure(metrics, agent.ReconcileResult{Node: node}, storeName, err, time.Since(start))
		return err
	}
	state, err = withDNSObservations(state)
	if err != nil {
		observeAgentReconcileFailure(metrics, agent.ReconcileResult{Node: node}, storeName, err, time.Since(start))
		return err
	}
	result, err := agent.ReconcileNodeWithOptions(ctx, state, agent.ReconcileOptions{
		Node:            node,
		Store:           store,
		TCXInterface:    os.Getenv("NETLOOM_TCX_IFACE"),
		TCXWorkload:     os.Getenv("NETLOOM_TCX_WORKLOAD") == "1",
		TCXHold:         hold,
		PolicyGCMaxIdle: policyGCMaxIdle(),
		LinuxDatapath:   linuxDatapathOptions(),
	})
	if err != nil {
		duration := time.Since(start)
		printReconcileFailure(result, storeName, err, duration)
		observeAgentReconcileFailure(metrics, result, storeName, err, duration)
		return err
	}
	duration := time.Since(start)
	printReconcileResult(result, storeName, duration)
	observeAgentReconcileResultWithState(metrics, result, storeName, duration, state)
	return nil
}

func withDNSObservations(state control.DesiredState) (control.DesiredState, error) {
	return withDNSObservationsAt(state, time.Now().UTC())
}

func withDNSObservationsAt(state control.DesiredState, now time.Time) (control.DesiredState, error) {
	path := os.Getenv("NETLOOM_DNS_OBSERVATIONS_FILE")
	if path == "" {
		return state, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return control.DesiredState{}, err
	}
	defer file.Close()
	records, err := control.LoadDNSObservationsJSON(file)
	if err != nil {
		return control.DesiredState{}, err
	}
	merged, err := control.MergeDNSRecords(state.DNSRecords, records)
	if err != nil {
		return control.DesiredState{}, err
	}
	merged, err = control.PruneExpiredDNSRecords(merged, now)
	if err != nil {
		return control.DesiredState{}, err
	}
	state.DNSRecords = merged
	return state, nil
}

func printReconcileResult(result agent.ReconcileResult, storeName string, duration time.Duration) {
	fmt.Printf("netloom-agent reconciled node policy node=%s store=%s endpoints=%d programs=%d entries=%d policy_map_entries=%d policy_map_capacity=%d policy_map_pressure_max=%d policy_map_pressure_endpoint=%s policy_map_pressure_endpoints=%d policy_map_drift_endpoints=%d policy_map_drift_missing=%d policy_map_drift_extra=%d policy_map_drift_changed=%d policy_gc_endpoints=%d policy_added=%d policy_updated=%d policy_deleted=%d policy_unchanged=%d policy_events=%d policy_failed=%d policy_rollbacks=%d policy_failed_endpoint=%s policy_failed_revision=%d policy_revision_max=%d policy_last_error=%s policy_rule_packets=%d policy_rule_bytes=%d policy_rule_allowed=%d policy_rule_dropped=%d policy_rule_rejected=%d policy_rule_logged=%d policy_rule_stats=%s conntrack_expired=%d tcx_eligible=%d tcx=%s tcx_failed=%d tcx_rollbacks=%d tcx_failed_target=%s tcx_last_error=%s datapath=%s local_ips=%d remote_routes=%d policy_routes=%d provider_networks=%d provider_links=%d provider_ready=%d provider_degraded=%d provider_status=%s provider_network_status=%s provider_issues=%s provider_inventory_total=%d provider_inventory_ready=%d provider_inventory_degraded=%d provider_inventory_status=%s cleanup=%t reconcile_duration_ms=%d\n", result.Node, storeName, result.Endpoints, result.Programs, result.Entries, result.PolicyMapEntries, result.PolicyMapCapacity, result.PolicyMapPressureMax, formatResultValue(result.PolicyMapPressureEndpoint), result.PolicyMapPressureEndpoints, result.PolicyMapDriftEndpoints, result.PolicyMapDriftMissing, result.PolicyMapDriftExtra, result.PolicyMapDriftChanged, result.PolicyGCEndpoints, result.PolicyAdded, result.PolicyUpdated, result.PolicyDeleted, result.PolicyUnchanged, result.PolicyEvents, result.PolicyFailed, result.PolicyRollbacks, formatResultValue(result.PolicyFailedEndpoint), result.PolicyFailedRevision, result.PolicyRevisionMax, formatResultError(result.PolicyLastError), result.PolicyRulePackets, result.PolicyRuleBytes, result.PolicyRuleAllowed, result.PolicyRuleDropped, result.PolicyRuleRejected, result.PolicyRuleLogged, formatEndpointRuleStats(result.PolicyRuleStats), result.ConntrackExpired, result.TCXEligible, result.TCX, result.TCXFailed, result.TCXRollbacks, formatResultValue(result.TCXFailedTarget), formatResultError(result.TCXLastError), result.Datapath, result.LocalIPs, result.RemoteRoutes, result.PolicyRoutes, result.ProviderNetworks, result.ProviderLinks, result.ProviderReady, result.ProviderDegraded, formatProviderStatus(result.ProviderStatus), formatProviderNetworkStatus(result.ProviderNetworkStatus), formatProviderIssues(result.ProviderIssues), result.ProviderInventoryTotal, result.ProviderInventoryReady, result.ProviderInventoryDegraded, formatProviderInventoryStatus(result.ProviderInventoryStatus), result.Cleanup, duration.Milliseconds())
}

func printReconcileFailure(result agent.ReconcileResult, storeName string, err error, duration time.Duration) {
	fmt.Printf("netloom-agent reconcile failed node=%s store=%s endpoints=%d programs=%d entries=%d policy_map_entries=%d policy_map_capacity=%d policy_map_pressure_max=%d policy_map_pressure_endpoint=%s policy_map_pressure_endpoints=%d policy_map_drift_endpoints=%d policy_map_drift_missing=%d policy_map_drift_extra=%d policy_map_drift_changed=%d policy_gc_endpoints=%d policy_added=%d policy_updated=%d policy_deleted=%d policy_unchanged=%d policy_events=%d policy_failed=%d policy_rollbacks=%d policy_failed_endpoint=%s policy_failed_revision=%d policy_revision_max=%d policy_last_error=%s policy_rule_packets=%d policy_rule_bytes=%d policy_rule_allowed=%d policy_rule_dropped=%d policy_rule_rejected=%d policy_rule_logged=%d policy_rule_stats=%s tcx_eligible=%d tcx=%s tcx_failed=%d tcx_rollbacks=%d tcx_failed_target=%s tcx_last_error=%s provider_networks=%d provider_links=%d provider_ready=%d provider_degraded=%d provider_status=%s provider_network_status=%s provider_issues=%s provider_inventory_total=%d provider_inventory_ready=%d provider_inventory_degraded=%d provider_inventory_status=%s err=%s reconcile_duration_ms=%d\n", result.Node, storeName, result.Endpoints, result.Programs, result.Entries, result.PolicyMapEntries, result.PolicyMapCapacity, result.PolicyMapPressureMax, formatResultValue(result.PolicyMapPressureEndpoint), result.PolicyMapPressureEndpoints, result.PolicyMapDriftEndpoints, result.PolicyMapDriftMissing, result.PolicyMapDriftExtra, result.PolicyMapDriftChanged, result.PolicyGCEndpoints, result.PolicyAdded, result.PolicyUpdated, result.PolicyDeleted, result.PolicyUnchanged, result.PolicyEvents, result.PolicyFailed, result.PolicyRollbacks, formatResultValue(result.PolicyFailedEndpoint), result.PolicyFailedRevision, result.PolicyRevisionMax, formatResultError(result.PolicyLastError), result.PolicyRulePackets, result.PolicyRuleBytes, result.PolicyRuleAllowed, result.PolicyRuleDropped, result.PolicyRuleRejected, result.PolicyRuleLogged, formatEndpointRuleStats(result.PolicyRuleStats), result.TCXEligible, result.TCX, result.TCXFailed, result.TCXRollbacks, formatResultValue(result.TCXFailedTarget), formatResultError(result.TCXLastError), result.ProviderNetworks, result.ProviderLinks, result.ProviderReady, result.ProviderDegraded, formatProviderStatus(result.ProviderStatus), formatProviderNetworkStatus(result.ProviderNetworkStatus), formatProviderIssues(result.ProviderIssues), result.ProviderInventoryTotal, result.ProviderInventoryReady, result.ProviderInventoryDegraded, formatProviderInventoryStatus(result.ProviderInventoryStatus), formatResultError(fmt.Sprint(err)), duration.Milliseconds())
}

func formatResultValue(value string) string {
	if value == "" {
		return "none"
	}
	return strconv.Quote(value)
}

func formatResultError(value string) string {
	if value == "" {
		return "none"
	}
	return strconv.Quote(value)
}

func formatProviderStatus(statuses []linuxdatapath.ProviderLinkStatus) string {
	if len(statuses) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(statuses))
	for _, status := range statuses {
		state := "pending"
		if status.Ready {
			state = "ready"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%d:%s:%s:%s:%s", status.ProviderNetwork, status.ParentDevice, status.VLAN, status.LinkName, state, fallbackProviderState(status.ParentState), fallbackProviderState(status.LinkState)))
	}
	return strings.Join(parts, ",")
}

func formatProviderInventoryStatus(statuses []linuxdatapath.ProviderInterface) string {
	if len(statuses) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(statuses))
	for _, status := range statuses {
		state := fallbackProviderState(status.State)
		if status.Ready && (state == "unknown" || state == "down" || state == "missing") {
			state = "up"
		}
		parts = append(parts, fmt.Sprintf("%s:%s", status.Name, state))
	}
	return strings.Join(parts, ",")
}

func formatProviderIssues(issues []linuxdatapath.ProviderIssue) string {
	if len(issues) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(issues))
	for _, issue := range issues {
		parts = append(parts, fmt.Sprintf("%s:%s:%s:%d:%s:%s", issue.ProviderNetwork, issue.Node, issue.ParentDevice, issue.VLAN, issue.Reason, issue.Detail))
	}
	return strings.Join(parts, ",")
}

func formatProviderNetworkStatus(statuses []linuxdatapath.ProviderNetworkStatus) string {
	if len(statuses) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(statuses))
	for _, status := range statuses {
		state := "degraded"
		if status.Ready {
			state = "ready"
		}
		reasons := "none"
		if len(status.Reasons) > 0 {
			reasons = strings.Join(status.Reasons, "+")
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%d/%d:%d:%s", status.ProviderNetwork, state, status.ReadyLinks, status.LinkCount, status.IssueCount, reasons))
	}
	return strings.Join(parts, ",")
}

func fallbackProviderState(state string) string {
	if state == "" {
		return "unknown"
	}
	return state
}

func formatRuleStats(stats []dataplane.RuleMetrics) string {
	if len(stats) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(stats))
	for _, stat := range stats {
		parts = append(parts, fmt.Sprintf("%d:p=%d,b=%d,a=%d,d=%d,r=%d,nm=%d,ct=%d,est=%d,log=%d", stat.RuleCookie, stat.Packets, stat.Bytes, stat.Allowed, stat.Dropped, stat.Rejected, stat.NoMatchDrops, stat.Conntrack, stat.Established, stat.Logged))
	}
	return strings.Join(parts, ";")
}

func formatEndpointRuleStats(stats []dataplane.RuleMetrics) string {
	if len(stats) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(stats))
	for _, stat := range stats {
		parts = append(parts, fmt.Sprintf("%s/%d:p=%d,b=%d,a=%d,d=%d,r=%d,nm=%d,ct=%d,est=%d,log=%d", strconv.Quote(stat.EndpointID), stat.RuleCookie, stat.Packets, stat.Bytes, stat.Allowed, stat.Dropped, stat.Rejected, stat.NoMatchDrops, stat.Conntrack, stat.Established, stat.Logged))
	}
	return strings.Join(parts, ";")
}

type agentMetrics struct {
	mu       sync.RWMutex
	snapshot agentMetricsSnapshot
	totals   agentMetricsTotals
	ready    bool
}

type agentMetricsSnapshot struct {
	Result   agent.ReconcileResult
	Store    string
	State    control.DesiredState
	Duration time.Duration
	Success  bool
	Error    string
}

type agentMetricsTotals struct {
	Attempts           uint64
	Successes          uint64
	Failures           uint64
	DurationSum        time.Duration
	DurationBuckets    []uint64
	PolicyAdded        uint64
	PolicyUpdated      uint64
	PolicyDeleted      uint64
	PolicyUnchanged    uint64
	PolicyEvents       uint64
	PolicyFailed       uint64
	PolicyRollbacks    uint64
	PolicyGCEndpoints  uint64
	TCXFailed          uint64
	TCXRollbacks       uint64
	ProviderDegraded   uint64
	ConntrackExpired   uint64
	PolicyRulePackets  uint64
	PolicyRuleBytes    uint64
	PolicyRuleDropped  uint64
	PolicyRuleRejected uint64
}

var agentReconcileDurationBuckets = []time.Duration{
	10 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	2500 * time.Millisecond,
	5 * time.Second,
	10 * time.Second,
	30 * time.Second,
}

func newAgentMetrics() *agentMetrics {
	return &agentMetrics{totals: agentMetricsTotals{DurationBuckets: make([]uint64, len(agentReconcileDurationBuckets))}}
}

func observeAgentReconcileResult(metrics *agentMetrics, result agent.ReconcileResult, storeName string, duration time.Duration) {
	observeAgentReconcileResultWithState(metrics, result, storeName, duration, control.DesiredState{})
}

func observeAgentReconcileResultWithState(metrics *agentMetrics, result agent.ReconcileResult, storeName string, duration time.Duration, state control.DesiredState) {
	if metrics == nil {
		return
	}
	metrics.observe(agentMetricsSnapshot{
		Result:   result,
		Store:    storeName,
		State:    cloneDesiredState(state),
		Duration: duration,
		Success:  true,
	})
}

func observeAgentReconcileFailure(metrics *agentMetrics, result agent.ReconcileResult, storeName string, err error, duration time.Duration) {
	if metrics == nil {
		return
	}
	message := ""
	if err != nil {
		message = err.Error()
	}
	metrics.observe(agentMetricsSnapshot{
		Result:   result,
		Store:    storeName,
		Duration: duration,
		Success:  false,
		Error:    message,
	})
}

func (m *agentMetrics) observe(snapshot agentMetricsSnapshot) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshot = snapshot
	m.totals.observe(snapshot)
	m.ready = true
}

func (t *agentMetricsTotals) observe(snapshot agentMetricsSnapshot) {
	t.Attempts++
	if snapshot.Success {
		t.Successes++
	} else {
		t.Failures++
	}
	t.DurationSum += snapshot.Duration
	for i, bucket := range agentReconcileDurationBuckets {
		if snapshot.Duration <= bucket {
			t.DurationBuckets[i]++
		}
	}
	result := snapshot.Result
	t.PolicyAdded += uint64(nonNegative(result.PolicyAdded))
	t.PolicyUpdated += uint64(nonNegative(result.PolicyUpdated))
	t.PolicyDeleted += uint64(nonNegative(result.PolicyDeleted))
	t.PolicyUnchanged += uint64(nonNegative(result.PolicyUnchanged))
	t.PolicyEvents += uint64(nonNegative(result.PolicyEvents))
	t.PolicyFailed += uint64(nonNegative(result.PolicyFailed))
	t.PolicyRollbacks += uint64(nonNegative(result.PolicyRollbacks))
	t.PolicyGCEndpoints += uint64(nonNegative(result.PolicyGCEndpoints))
	t.TCXFailed += uint64(nonNegative(result.TCXFailed))
	t.TCXRollbacks += uint64(nonNegative(result.TCXRollbacks))
	t.ProviderDegraded += uint64(nonNegative(result.ProviderDegraded))
	t.ConntrackExpired += uint64(nonNegative(result.ConntrackExpired))
	t.PolicyRulePackets += result.PolicyRulePackets
	t.PolicyRuleBytes += result.PolicyRuleBytes
	t.PolicyRuleDropped += result.PolicyRuleDropped
	t.PolicyRuleRejected += result.PolicyRuleRejected
}

func (m *agentMetrics) snapshotValue() (agentMetricsSnapshot, agentMetricsTotals, bool) {
	if m == nil {
		return agentMetricsSnapshot{}, agentMetricsTotals{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshot, cloneAgentMetricsTotals(m.totals), m.ready
}

func cloneAgentMetricsTotals(totals agentMetricsTotals) agentMetricsTotals {
	totals.DurationBuckets = append([]uint64(nil), totals.DurationBuckets...)
	return totals
}

func startAgentMetricsServer(ctx context.Context, addr string, metrics *agentMetrics) (func(), error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return func() {}, nil
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen agent metrics endpoint %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", metrics.handleMetrics)
	mux.HandleFunc("/policy/explain", metrics.handlePolicyExplain)
	mux.HandleFunc("/policy/endpoints", metrics.handlePolicyEndpoints)
	mux.HandleFunc("/policy/endpoints/", metrics.handlePolicyEndpoints)
	mux.HandleFunc("/route/explain", metrics.handleRouteExplain)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	server := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("netloom-agent metrics endpoint stopped: %v", err)
		}
	}()
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}, nil
}

func (m *agentMetrics) handlePolicyEndpoints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	endpoint := strings.TrimSpace(r.URL.Query().Get("endpoint"))
	if strings.HasPrefix(r.URL.Path, "/policy/endpoints/") {
		pathEndpoint := strings.TrimPrefix(r.URL.Path, "/policy/endpoints/")
		if decoded, err := url.PathUnescape(pathEndpoint); err == nil {
			pathEndpoint = decoded
		}
		if strings.TrimSpace(pathEndpoint) != "" {
			endpoint = strings.TrimSpace(pathEndpoint)
		}
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy endpoint status is not ready"})
		return
	}
	statuses := filterPolicyEndpointStatuses(snapshot.Result.PolicyEndpointStatus, endpoint, nil)
	if endpoint != "" && len(statuses) == 0 {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy endpoint not found"})
		return
	}
	output := policyStatusOutputFromResult(snapshot.Result, snapshot.Store, statuses)
	output.Ready = true
	output.LastReconcileSuccess = snapshot.Success
	output.LastReconcileError = snapshot.Error
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(output)
}

func (m *agentMetrics) handlePolicyExplain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready || !snapshot.Success {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy explain state is not ready"})
		return
	}
	opts, err := policyExplainOptionsFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	explanation, err := explainPolicyFromState(snapshot.State, opts)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(explanation)
}

func policyExplainOptionsFromRequest(r *http.Request) (policyExplainOptions, error) {
	query := r.URL.Query()
	remoteIdentity, err := parseOptionalUintQuery(query.Get("remote-identity"), query.Get("remote_identity"))
	if err != nil {
		return policyExplainOptions{}, fmt.Errorf("invalid remote identity: %w", err)
	}
	sourcePort, err := parseOptionalUintQuery(query.Get("source-port"), query.Get("source_port"))
	if err != nil {
		return policyExplainOptions{}, fmt.Errorf("invalid source port: %w", err)
	}
	destPort, err := parseOptionalUintQuery(query.Get("dest-port"), query.Get("dest_port"))
	if err != nil {
		return policyExplainOptions{}, fmt.Errorf("invalid destination port: %w", err)
	}
	icmpType, err := parseOptionalIntQuery(query.Get("icmp-type"), query.Get("icmp_type"))
	if err != nil {
		return policyExplainOptions{}, fmt.Errorf("invalid icmp type: %w", err)
	}
	icmpCode, err := parseOptionalIntQuery(query.Get("icmp-code"), query.Get("icmp_code"))
	if err != nil {
		return policyExplainOptions{}, fmt.Errorf("invalid icmp code: %w", err)
	}
	stateful, err := parseOptionalBoolQuery(query.Get("stateful"))
	if err != nil {
		return policyExplainOptions{}, fmt.Errorf("invalid stateful value: %w", err)
	}
	return policyExplainOptions{
		vpc:            query.Get("vpc"),
		endpoint:       query.Get("endpoint"),
		remoteEndpoint: firstNonEmptyQuery(query.Get("remote-endpoint"), query.Get("remote_endpoint")),
		remoteVPC:      firstNonEmptyQuery(query.Get("remote-vpc"), query.Get("remote_vpc")),
		remoteIdentity: remoteIdentity,
		remoteIP:       firstNonEmptyQuery(query.Get("remote-ip"), query.Get("remote_ip")),
		direction:      query.Get("direction"),
		protocol:       query.Get("protocol"),
		sourcePort:     sourcePort,
		destPort:       destPort,
		icmpType:       icmpType,
		icmpCode:       icmpCode,
		stateful:       stateful,
	}, nil
}

func (m *agentMetrics) handleRouteExplain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	snapshot, _, ready := m.snapshotValue()
	if !ready || !snapshot.Success {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "route explain state is not ready"})
		return
	}
	opts, err := routeExplainOptionsFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	decision, err := explainRouteFromState(snapshot.State, opts)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(decision)
}

func routeExplainOptionsFromRequest(r *http.Request) (routeExplainOptions, error) {
	query := r.URL.Query()
	sourcePort, err := parseOptionalUintQuery(query.Get("source-port"), query.Get("source_port"))
	if err != nil {
		return routeExplainOptions{}, fmt.Errorf("invalid source port: %w", err)
	}
	destPort, err := parseOptionalUintQuery(query.Get("dest-port"), query.Get("dest_port"))
	if err != nil {
		return routeExplainOptions{}, fmt.Errorf("invalid destination port: %w", err)
	}
	return routeExplainOptions{
		vpc:        query.Get("vpc"),
		source:     query.Get("source"),
		dest:       query.Get("dest"),
		protocol:   query.Get("protocol"),
		sourcePort: sourcePort,
		destPort:   destPort,
	}, nil
}

func parseOptionalUintQuery(values ...string) (uint, error) {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseUint(value, 10, 0)
		if err != nil {
			return 0, err
		}
		return uint(parsed), nil
	}
	return 0, nil
}

func parseOptionalIntQuery(values ...string) (int, error) {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, err
		}
		return parsed, nil
	}
	return 0, nil
}

func parseOptionalBoolQuery(value string) (bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, nil
	}
	return strconv.ParseBool(value)
}

func firstNonEmptyQuery(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (m *agentMetrics) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	snapshot, totals, ready := m.snapshotValue()
	if !ready {
		writeMetricHelp(w, "netloom_agent_reconcile_ready", "Whether the agent has completed at least one reconcile attempt.")
		writeMetricType(w, "netloom_agent_reconcile_ready", "gauge")
		fmt.Fprintln(w, "netloom_agent_reconcile_ready 0")
		return
	}
	writeAgentMetrics(w, snapshot, totals)
}

func writeAgentMetrics(w ioStringWriter, snapshot agentMetricsSnapshot, totals agentMetricsTotals) {
	result := snapshot.Result
	baseLabels := prometheusLabels(map[string]string{
		"node":  result.Node,
		"store": snapshot.Store,
	})
	success := 0
	if snapshot.Success {
		success = 1
	}
	writeMetricHelp(w, "netloom_agent_reconcile_ready", "Whether the agent has completed at least one reconcile attempt.")
	writeMetricType(w, "netloom_agent_reconcile_ready", "gauge")
	fmt.Fprintln(w, "netloom_agent_reconcile_ready 1")
	writeMetricHelp(w, "netloom_agent_reconcile_success", "Whether the last agent reconcile attempt succeeded.")
	writeMetricType(w, "netloom_agent_reconcile_success", "gauge")
	fmt.Fprintf(w, "netloom_agent_reconcile_success%s %d\n", baseLabels, success)
	writeMetricHelp(w, "netloom_agent_reconcile_duration_milliseconds", "Duration of the last agent reconcile attempt in milliseconds.")
	writeMetricType(w, "netloom_agent_reconcile_duration_milliseconds", "gauge")
	fmt.Fprintf(w, "netloom_agent_reconcile_duration_milliseconds%s %d\n", baseLabels, snapshot.Duration.Milliseconds())
	writeAgentCounter(w, "netloom_agent_reconcile_attempts_total", baseLabels, totals.Attempts)
	writeAgentCounter(w, "netloom_agent_reconcile_success_total", baseLabels, totals.Successes)
	writeAgentCounter(w, "netloom_agent_reconcile_failure_total", baseLabels, totals.Failures)
	writeAgentDurationHistogram(w, result.Node, snapshot.Store, baseLabels, totals)
	if !snapshot.Success && snapshot.Error != "" {
		fmt.Fprintf(w, "netloom_agent_reconcile_last_error%s 1\n", prometheusLabels(map[string]string{
			"node":  result.Node,
			"store": snapshot.Store,
			"error": snapshot.Error,
		}))
	}

	writeMetricType(w, "netloom_agent_policy_map_entries", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_entries%s %d\n", baseLabels, result.PolicyMapEntries)
	writeMetricType(w, "netloom_agent_policy_map_capacity", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_capacity%s %d\n", baseLabels, result.PolicyMapCapacity)
	writeMetricType(w, "netloom_agent_policy_map_pressure_percent", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_pressure_percent%s %d\n", prometheusLabels(map[string]string{
		"node":     result.Node,
		"store":    snapshot.Store,
		"endpoint": result.PolicyMapPressureEndpoint,
	}), result.PolicyMapPressureMax)
	writeMetricType(w, "netloom_agent_policy_map_pressure_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_pressure_endpoints%s %d\n", baseLabels, result.PolicyMapPressureEndpoints)
	writeMetricType(w, "netloom_agent_policy_map_drift_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_drift_endpoints%s %d\n", baseLabels, result.PolicyMapDriftEndpoints)
	writeMetricType(w, "netloom_agent_policy_map_drift_missing_entries", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_drift_missing_entries%s %d\n", baseLabels, result.PolicyMapDriftMissing)
	writeMetricType(w, "netloom_agent_policy_map_drift_extra_entries", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_drift_extra_entries%s %d\n", baseLabels, result.PolicyMapDriftExtra)
	writeMetricType(w, "netloom_agent_policy_map_drift_changed_entries", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_map_drift_changed_entries%s %d\n", baseLabels, result.PolicyMapDriftChanged)
	writeMetricType(w, "netloom_agent_policy_gc_endpoints", "gauge")
	fmt.Fprintf(w, "netloom_agent_policy_gc_endpoints%s %d\n", baseLabels, result.PolicyGCEndpoints)
	writeAgentCounter(w, "netloom_agent_policy_added_total", baseLabels, totals.PolicyAdded)
	writeAgentCounter(w, "netloom_agent_policy_updated_total", baseLabels, totals.PolicyUpdated)
	writeAgentCounter(w, "netloom_agent_policy_deleted_total", baseLabels, totals.PolicyDeleted)
	writeAgentCounter(w, "netloom_agent_policy_unchanged_total", baseLabels, totals.PolicyUnchanged)
	writeAgentCounter(w, "netloom_agent_policy_events_total", baseLabels, totals.PolicyEvents)
	writeAgentCounter(w, "netloom_agent_policy_failed_total", baseLabels, totals.PolicyFailed)
	writeAgentCounter(w, "netloom_agent_policy_rollbacks_total", baseLabels, totals.PolicyRollbacks)
	writeAgentCounter(w, "netloom_agent_policy_gc_endpoints_total", baseLabels, totals.PolicyGCEndpoints)
	writeAgentCounter(w, "netloom_agent_tcx_failed_total", baseLabels, totals.TCXFailed)
	writeAgentCounter(w, "netloom_agent_tcx_rollbacks_total", baseLabels, totals.TCXRollbacks)
	writeAgentCounter(w, "netloom_agent_provider_degraded_total", baseLabels, totals.ProviderDegraded)
	writeAgentCounter(w, "netloom_agent_conntrack_expired_total", baseLabels, totals.ConntrackExpired)
	writeAgentCounter(w, "netloom_agent_policy_rule_packets_observed_total", baseLabels, totals.PolicyRulePackets)
	writeAgentCounter(w, "netloom_agent_policy_rule_bytes_observed_total", baseLabels, totals.PolicyRuleBytes)
	writeAgentCounter(w, "netloom_agent_policy_rule_dropped_observed_total", baseLabels, totals.PolicyRuleDropped)
	writeAgentCounter(w, "netloom_agent_policy_rule_rejected_observed_total", baseLabels, totals.PolicyRuleRejected)

	writeMetricType(w, "netloom_agent_policy_rule_packets_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_packets_total%s %d\n", baseLabels, result.PolicyRulePackets)
	writeMetricType(w, "netloom_agent_policy_rule_bytes_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_bytes_total%s %d\n", baseLabels, result.PolicyRuleBytes)
	writeMetricType(w, "netloom_agent_policy_rule_allowed_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_allowed_total%s %d\n", baseLabels, result.PolicyRuleAllowed)
	writeMetricType(w, "netloom_agent_policy_rule_dropped_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_dropped_total%s %d\n", baseLabels, result.PolicyRuleDropped)
	writeMetricType(w, "netloom_agent_policy_rule_rejected_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_rejected_total%s %d\n", baseLabels, result.PolicyRuleRejected)
	writeMetricType(w, "netloom_agent_policy_rule_logged_total", "counter")
	fmt.Fprintf(w, "netloom_agent_policy_rule_logged_total%s %d\n", baseLabels, result.PolicyRuleLogged)
	for _, stat := range result.PolicyRuleStats {
		labels := prometheusLabels(map[string]string{
			"node":        result.Node,
			"store":       snapshot.Store,
			"endpoint":    stat.EndpointID,
			"rule_cookie": strconv.FormatUint(uint64(stat.RuleCookie), 10),
		})
		fmt.Fprintf(w, "netloom_agent_policy_rule_packets_by_rule_total%s %d\n", labels, stat.Packets)
		fmt.Fprintf(w, "netloom_agent_policy_rule_bytes_by_rule_total%s %d\n", labels, stat.Bytes)
		fmt.Fprintf(w, "netloom_agent_policy_rule_allowed_by_rule_total%s %d\n", labels, stat.Allowed)
		fmt.Fprintf(w, "netloom_agent_policy_rule_dropped_by_rule_total%s %d\n", labels, stat.Dropped)
		fmt.Fprintf(w, "netloom_agent_policy_rule_rejected_by_rule_total%s %d\n", labels, stat.Rejected)
		fmt.Fprintf(w, "netloom_agent_policy_rule_logged_by_rule_total%s %d\n", labels, stat.Logged)
	}

	writeMetricType(w, "netloom_agent_tcx_eligible", "gauge")
	fmt.Fprintf(w, "netloom_agent_tcx_eligible%s %d\n", baseLabels, result.TCXEligible)
	writeMetricType(w, "netloom_agent_tcx_failed", "gauge")
	fmt.Fprintf(w, "netloom_agent_tcx_failed%s %d\n", prometheusLabels(map[string]string{
		"node":   result.Node,
		"store":  snapshot.Store,
		"target": result.TCXFailedTarget,
	}), result.TCXFailed)
	writeMetricType(w, "netloom_agent_tcx_rollbacks", "gauge")
	fmt.Fprintf(w, "netloom_agent_tcx_rollbacks%s %d\n", baseLabels, result.TCXRollbacks)
}

func writeAgentCounter(w ioStringWriter, name, labels string, value uint64) {
	writeMetricType(w, name, "counter")
	fmt.Fprintf(w, "%s%s %d\n", name, labels, value)
}

func writeAgentDurationHistogram(w ioStringWriter, node, store, baseLabels string, totals agentMetricsTotals) {
	name := "netloom_agent_reconcile_duration_milliseconds_histogram"
	writeMetricType(w, name, "histogram")
	for i, bucket := range agentReconcileDurationBuckets {
		labels := prometheusLabels(map[string]string{
			"le":    strconv.FormatInt(bucket.Milliseconds(), 10),
			"node":  node,
			"store": store,
		})
		fmt.Fprintf(w, "%s_bucket%s %d\n", name, labels, totals.DurationBuckets[i])
	}
	fmt.Fprintf(w, "%s_bucket%s %d\n", name, prometheusLabels(map[string]string{"le": "+Inf", "node": node, "store": store}), totals.Attempts)
	fmt.Fprintf(w, "%s_sum%s %d\n", name, baseLabels, totals.DurationSum.Milliseconds())
	fmt.Fprintf(w, "%s_count%s %d\n", name, baseLabels, totals.Attempts)
}

type ioStringWriter interface {
	Write([]byte) (int, error)
}

func writeMetricHelp(w ioStringWriter, name, help string) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
}

func writeMetricType(w ioStringWriter, name, typ string) {
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
}

func prometheusLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strconv.Quote(labels[key]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func nonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func reconcileInterval() (time.Duration, error) {
	raw := os.Getenv("NETLOOM_RECONCILE_INTERVAL_MS")
	if raw == "" {
		return 0, nil
	}
	ms, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NETLOOM_RECONCILE_INTERVAL_MS: %w", err)
	}
	if ms <= 0 {
		return 0, nil
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func policyStore() (agent.PolicyStore, string, func()) {
	if os.Getenv("NETLOOM_POLICY_STORE") == "ebpf" {
		cfg := dataplane.EBPFPolicyStoreConfig{}
		if maxEntries, err := parseUint32Env("NETLOOM_EBPF_MAP_MAX_ENTRIES"); err == nil {
			cfg.MaxEntries = maxEntries
		}
		if schemaVersion, err := parseUint32Env("NETLOOM_EBPF_MAP_SCHEMA_VERSION"); err == nil {
			cfg.SchemaVersion = schemaVersion
		}
		if overflow, err := dataplane.ParsePolicyMapOverflowAction(os.Getenv("NETLOOM_EBPF_MAP_OVERFLOW_ACTION")); err == nil {
			cfg.OverflowAction = overflow
		}
		cfg.PinRoot = ebpfMapPinRoot()
		cfg.MetadataRoot = ebpfMapMetadataRoot()
		store := dataplane.NewEBPFPolicyStoreWithConfig(cfg)
		return store, "ebpf", func() {
			_ = store.Close()
		}
	}
	return dataplane.NewInMemoryPolicyStore(), "memory", func() {}
}

func ebpfMapPinRoot() string {
	if configured := strings.TrimSpace(os.Getenv("NETLOOM_EBPF_MAP_PIN_ROOT")); configured != "" {
		return configured
	}
	if err := ensureBPFFSPinRoot(defaultBPFFSRoot, defaultBPFFSPinRoot); err == nil {
		return defaultBPFFSPinRoot
	}
	if err := ensureBPFFSPinRoot(defaultRuntimeBPFRoot, defaultRuntimePinRoot); err == nil {
		return defaultRuntimePinRoot
	}
	return defaultRuntimePinRoot
}

func ebpfMapMetadataRoot() string {
	if configured := strings.TrimSpace(os.Getenv("NETLOOM_EBPF_MAP_METADATA_ROOT")); configured != "" {
		return configured
	}
	return defaultMetadataRoot
}

func ensureDirAccessible(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("not a directory")
	}
	return nil
}

func ensureBPFFSPinRoot(mountRoot, pinRoot string) error {
	if err := ensureBPFFSMounted(mountRoot); err != nil {
		return err
	}
	return os.MkdirAll(pinRoot, 0o755)
}

func ensureBPFFSMounted(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return err
	}
	if fs.Type == unix.BPF_FS_MAGIC {
		return nil
	}
	if err := unix.Mount("bpffs", path, "bpf", 0, ""); err != nil {
		return err
	}
	if err := unix.Statfs(path, &fs); err != nil {
		return err
	}
	if fs.Type != unix.BPF_FS_MAGIC {
		return fmt.Errorf("%s is not backed by bpffs", path)
	}
	return nil
}

func parseUint32Env(key string) (uint32, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return 0, fmt.Errorf("%s is empty", key)
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, err
	}
	if value == 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}
	return uint32(value), nil
}

func tcxHold() (time.Duration, error) {
	raw := os.Getenv("NETLOOM_TCX_HOLD_MS")
	if raw == "" {
		return 0, nil
	}
	ms, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NETLOOM_TCX_HOLD_MS: %w", err)
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func conntrackIdleTimeout() time.Duration {
	ms := getenvIntDefault("NETLOOM_CONNTRACK_MAX_IDLE_MS", 0)
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func policyGCMaxIdle() time.Duration {
	ms := getenvIntDefault("NETLOOM_POLICY_GC_MAX_IDLE_MS", 0)
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func linuxDatapathOptions() *linuxdatapath.Options {
	if os.Getenv("NETLOOM_LINUX_DATAPATH") != "1" {
		return nil
	}
	return &linuxdatapath.Options{
		Mode:                 getenvDefault("NETLOOM_LINUX_DATAPATH_MODE", "local"),
		Backend:              getenvDefault("NETLOOM_LINUX_DATAPATH_BACKEND", "netlink"),
		LocalDevice:          getenvDefault("NETLOOM_DATAPATH_DEV", "lo"),
		UnderlayDevice:       getenvDefault("NETLOOM_UNDERLAY_DEV", "eth0"),
		ProviderLinks:        parseProviderLinks(os.Getenv("NETLOOM_PROVIDER_NETWORK_LINKS")),
		SyncOVSDB:            os.Getenv("NETLOOM_OVSDB_SYNC") == "1",
		NetNSPrefix:          getenvDefault("NETLOOM_NETNS_PREFIX", "nl"),
		WorkloadIF:           getenvDefault("NETLOOM_WORKLOAD_IF", "eth0"),
		NodeUnderlays:        parseNodeUnderlays(os.Getenv("NETLOOM_NODE_UNDERLAYS")),
		PolicyTableBase:      getenvIntDefault("NETLOOM_POLICY_ROUTE_TABLE_BASE", 10000),
		PolicyTableSize:      getenvIntDefault("NETLOOM_POLICY_ROUTE_TABLE_SIZE", 1024),
		CleanupStale:         os.Getenv("NETLOOM_LINUX_DATAPATH_CLEANUP") == "1",
		StrictProviderHealth: os.Getenv("NETLOOM_PROVIDER_HEALTH_STRICT") == "1",
	}
}

func getenvDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getenvIntDefault(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func parseNodeUnderlays(raw string) map[string][]netip.Addr {
	out := make(map[string][]netip.Addr)
	for _, item := range strings.Split(raw, ",") {
		if item == "" {
			continue
		}
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err == nil {
			out[name] = append(out[name], addr)
		}
	}
	return out
}

func parseProviderLinks(raw string) map[string]string {
	out := make(map[string]string)
	for _, item := range strings.Split(raw, ",") {
		if item == "" {
			continue
		}
		provider, device, ok := strings.Cut(item, "=")
		provider = strings.TrimSpace(provider)
		device = strings.TrimSpace(device)
		if !ok || provider == "" || device == "" {
			continue
		}
		out[provider] = device
	}
	return out
}
