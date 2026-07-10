package ovn

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ovn-kubernetes/libovsdb/client"
	ovsmodel "github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/ovnnb"
)

type LibOVSDBTopologyWriter struct {
	client                  client.Client
	clientCloser            func()
	mu                      sync.Mutex
	last                    desiredSnapshot
	lastCleanup             CleanupStats
	seen                    bool
	reconnectEnabled        bool
	reconnectInitialBackoff time.Duration
	reconnectMaxBackoff     time.Duration
	reconnectClient         func(context.Context) (client.Client, func(), error)
	reconnectFailures       int
	nextReconnect           time.Time
}

func NewLibOVSDBTopologyWriter(client client.Client) *LibOVSDBTopologyWriter {
	return &LibOVSDBTopologyWriter{client: client}
}

func (w *LibOVSDBTopologyWriter) EnsureVPC(ctx context.Context, vpc model.VPC) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	router := &ovnnb.LogicalRouter{
		Name:        logicalRouter(vpc.Name),
		ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_vpc": vpc.Name},
	}
	existing, ok, err := w.logicalRouterByName(ctx, router.Name)
	if err != nil {
		return err
	}
	var ops []ovsdb.Operation
	if !ok {
		ops, err = w.client.Create(router)
		if err != nil {
			return fmt.Errorf("create logical router %s: %w", router.Name, err)
		}
	} else {
		nextExternalIDs := mergeStringMap(existing.ExternalIDs, router.ExternalIDs)
		if reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) {
			return nil
		}
		existing.ExternalIDs = nextExternalIDs
		ops, err = w.client.Where(existing).Update(existing, &existing.ExternalIDs)
		if err != nil {
			return fmt.Errorf("update logical router %s external IDs: %w", router.Name, err)
		}
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("transact logical router %s: %w", router.Name, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("logical router %s operation errors=%+v: %w", router.Name, opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) EnsureSubnet(ctx context.Context, subnet model.Subnet) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	routerName := logicalRouter(subnet.VPC)
	router, ok, err := w.logicalRouterByName(ctx, routerName)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("logical router %s must exist before subnet %s", routerName, subnet.Name)
	}
	ls := &ovnnb.LogicalSwitch{
		Name:        logicalSwitch(subnet.VPC, subnet.Name),
		ExternalIDs: logicalSwitchExternalIDs(subnet),
		OtherConfig: logicalSwitchOtherConfig(subnet),
	}
	existingSwitch, ok, err := w.logicalSwitchByName(ctx, ls.Name)
	if err != nil {
		return err
	}
	var ops []ovsdb.Operation
	if !ok {
		ls.UUID = ovsdbNamedUUID(ls.Name)
		ops, err = w.client.Create(ls)
		if err != nil {
			return fmt.Errorf("create logical switch %s: %w", ls.Name, err)
		}
	} else {
		nextExternalIDs := mergeManagedExternalIDs(existingSwitch.ExternalIDs, ls.ExternalIDs)
		nextOtherConfig := replaceLogicalSwitchIPAMConfig(existingSwitch.OtherConfig, ls.OtherConfig)
		if !reflect.DeepEqual(existingSwitch.ExternalIDs, nextExternalIDs) || !reflect.DeepEqual(existingSwitch.OtherConfig, nextOtherConfig) {
			existingSwitch.ExternalIDs = nextExternalIDs
			existingSwitch.OtherConfig = nextOtherConfig
			updateOps, err := w.client.Where(existingSwitch).Update(existingSwitch, &existingSwitch.ExternalIDs, &existingSwitch.OtherConfig)
			if err != nil {
				return fmt.Errorf("update logical switch %s: %w", ls.Name, err)
			}
			ops = append(ops, updateOps...)
		}
	}
	subnetOps, err := w.subnetPortOperations(ctx, router, ls, existingSwitch, subnet)
	if err != nil {
		return err
	}
	ops = append(ops, subnetOps...)
	if len(ops) == 0 {
		return nil
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("transact subnet %s/%s: %w", subnet.VPC, subnet.Name, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("subnet %s/%s operation errors=%+v: %w", subnet.VPC, subnet.Name, opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) EnsureEndpoint(ctx context.Context, endpoint model.Endpoint) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	switchName := logicalSwitch(endpoint.VPC, endpoint.Subnet)
	logicalSwitch, ok, err := w.logicalSwitchByName(ctx, switchName)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("logical switch %s must exist before endpoint %s", switchName, endpoint.ID)
	}
	address := endpointAddress(endpoint)
	port := &ovnnb.LogicalSwitchPort{
		Name:      logicalPort(endpoint.VPC, endpoint.ID),
		Addresses: []string{address},
		ExternalIDs: map[string]string{
			"netloom_owner":    "netloom",
			"netloom_endpoint": endpointExternalID(endpoint.VPC, endpoint.ID),
			"netloom_node":     endpoint.Node,
			"netloom_vpc":      endpoint.VPC,
			"netloom_subnet":   endpoint.Subnet,
		},
	}
	if endpoint.NormalizedMAC() != "" {
		port.PortSecurity = []string{address}
	}
	var ops []ovsdb.Operation
	portUUID, portOps, err := w.ensureEndpointSwitchPort(ctx, logicalSwitch.UUID, logicalSwitch.Ports, port)
	if err != nil {
		return err
	}
	ops = append(ops, portOps...)
	nextPort, ok, err := w.logicalSwitchPortByName(ctx, port.Name)
	if err != nil {
		return err
	}
	if !ok {
		nextPort = &ovnnb.LogicalSwitchPort{UUID: portUUID}
	}
	dhcpOps, err := w.endpointDHCPOptionsOperations(ctx, endpoint, logicalSwitch.ExternalIDs, nextPort)
	if err != nil {
		return err
	}
	ops = append(ops, dhcpOps...)
	if len(ops) == 0 {
		return nil
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("transact endpoint %s/%s: %w", endpoint.VPC, endpoint.ID, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("endpoint %s/%s operation errors=%+v: %w", endpoint.VPC, endpoint.ID, opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) EnsureRouteTable(ctx context.Context, table model.RouteTable) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	router, ok, err := w.logicalRouterByName(ctx, logicalRouter(table.VPC))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("logical router %s must exist before route table %s", logicalRouter(table.VPC), table.Name)
	}
	existing, err := w.staticRoutesByRouteTable(ctx, table)
	if err != nil {
		return err
	}
	existingByKey := make(map[string][]ovnnb.LogicalRouterStaticRoute, len(existing))
	for _, route := range existing {
		key := staticRouteRowKey(route)
		existingByKey[key] = append(existingByKey[key], route)
	}
	var ops []ovsdb.Operation
	desiredKeys := make(map[string]struct{})
	for _, route := range table.Routes {
		for _, desired := range desiredStaticRouteRows(table, route) {
			key := staticRouteRowKey(desired)
			desiredKeys[key] = struct{}{}
			rows := existingByKey[key]
			if len(rows) == 0 {
				desired.UUID = ovsdbNamedUUID("nl_route_" + table.VPC + "_" + table.Name + "_" + key)
				createOps, err := w.client.Create(&desired)
				if err != nil {
					return fmt.Errorf("create static route %s: %w", key, err)
				}
				ops = append(ops, createOps...)
				attachOps, err := w.attachStaticRoute(router, desired.UUID)
				if err != nil {
					return err
				}
				ops = append(ops, attachOps...)
				continue
			}
			keep := rows[0]
			nextExternalIDs := mergeManagedExternalIDs(keep.ExternalIDs, desired.ExternalIDs)
			if !containsString(router.StaticRoutes, keep.UUID) {
				attachOps, err := w.attachStaticRoute(router, keep.UUID)
				if err != nil {
					return err
				}
				ops = append(ops, attachOps...)
			}
			if staticRouteRowChanged(keep, desired, nextExternalIDs) {
				keep.BFD = desired.BFD
				keep.IPPrefix = desired.IPPrefix
				keep.Nexthop = desired.Nexthop
				keep.Options = desired.Options
				keep.OutputPort = desired.OutputPort
				keep.Policy = desired.Policy
				keep.RouteTable = desired.RouteTable
				keep.SelectionFields = desired.SelectionFields
				keep.ExternalIDs = nextExternalIDs
				updateOps, err := w.client.Where(&keep).Update(&keep, &keep.BFD, &keep.IPPrefix, &keep.Nexthop, &keep.Options, &keep.OutputPort, &keep.Policy, &keep.RouteTable, &keep.SelectionFields, &keep.ExternalIDs)
				if err != nil {
					return fmt.Errorf("update static route %s: %w", key, err)
				}
				ops = append(ops, updateOps...)
			}
			for i := 1; i < len(rows); i++ {
				deleteOps, err := w.deleteStaticRoute(router.UUID, &rows[i])
				if err != nil {
					return err
				}
				ops = append(ops, deleteOps...)
			}
		}
	}
	for key, rows := range existingByKey {
		if _, ok := desiredKeys[key]; ok {
			continue
		}
		for i := range rows {
			deleteOps, err := w.deleteStaticRoute(router.UUID, &rows[i])
			if err != nil {
				return err
			}
			ops = append(ops, deleteOps...)
		}
	}
	if len(ops) == 0 {
		return nil
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("transact route table %s/%s: %w", table.VPC, table.Name, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("route table %s/%s operation errors=%+v: %w", table.VPC, table.Name, opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) EnsurePolicyRoute(ctx context.Context, route model.PolicyRoute) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	router, ok, err := w.logicalRouterByName(ctx, logicalRouter(route.VPC))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("logical router %s must exist before policy route %s", logicalRouter(route.VPC), route.Name)
	}
	existing, err := w.policyRoutesByName(ctx, route.VPC, route.Name)
	if err != nil {
		return err
	}
	desired := desiredPolicyRouteRow(route)
	var ops []ovsdb.Operation
	if len(existing) == 0 {
		desired.UUID = ovsdbNamedUUID("nl_policy_route_" + route.VPC + "_" + route.Name)
		createOps, err := w.client.Create(&desired)
		if err != nil {
			return fmt.Errorf("create policy route %s/%s: %w", route.VPC, route.Name, err)
		}
		ops = append(ops, createOps...)
		attachOps, err := w.attachPolicyRoute(router, desired.UUID)
		if err != nil {
			return err
		}
		ops = append(ops, attachOps...)
	} else {
		keep := existing[0]
		nextExternalIDs := mergeManagedExternalIDs(keep.ExternalIDs, desired.ExternalIDs)
		if !containsString(router.Policies, keep.UUID) {
			attachOps, err := w.attachPolicyRoute(router, keep.UUID)
			if err != nil {
				return err
			}
			ops = append(ops, attachOps...)
		}
		if keep.Priority != desired.Priority ||
			keep.Match != desired.Match ||
			keep.Action != desired.Action ||
			!stringPointerValueEqual(keep.Nexthop, pointerStringValue(desired.Nexthop)) ||
			!reflect.DeepEqual(keep.Nexthops, desired.Nexthops) ||
			!reflect.DeepEqual(keep.ExternalIDs, nextExternalIDs) {
			keep.Priority = desired.Priority
			keep.Match = desired.Match
			keep.Action = desired.Action
			keep.Nexthop = desired.Nexthop
			keep.Nexthops = desired.Nexthops
			keep.ExternalIDs = nextExternalIDs
			updateOps, err := w.client.Where(&keep).Update(&keep, &keep.Priority, &keep.Match, &keep.Action, &keep.Nexthop, &keep.Nexthops, &keep.ExternalIDs)
			if err != nil {
				return fmt.Errorf("update policy route %s/%s: %w", route.VPC, route.Name, err)
			}
			ops = append(ops, updateOps...)
		}
		for i := 1; i < len(existing); i++ {
			deleteOps, err := w.deletePolicyRoute(router.UUID, &existing[i])
			if err != nil {
				return err
			}
			ops = append(ops, deleteOps...)
		}
	}
	if len(ops) == 0 {
		return nil
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("transact policy route %s/%s: %w", route.VPC, route.Name, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("policy route %s/%s operation errors=%+v: %w", route.VPC, route.Name, opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) EnsureGateway(ctx context.Context, gateway model.Gateway) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	router, ok, err := w.logicalRouterByName(ctx, logicalRouter(gateway.VPC))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("logical router %s must exist before gateway %s", logicalRouter(gateway.VPC), gateway.Name)
	}
	nextExternalIDs := mergeGatewayExternalIDs(router.ExternalIDs, gatewayExternalIDs(gateway))
	nextOptions := gatewayRouterOptions(router.Options, gateway)
	if reflect.DeepEqual(router.ExternalIDs, nextExternalIDs) && reflect.DeepEqual(router.Options, nextOptions) {
		return nil
	}
	router.ExternalIDs = nextExternalIDs
	router.Options = nextOptions
	ops, err := w.client.Where(router).Update(router, &router.ExternalIDs, &router.Options)
	if err != nil {
		return fmt.Errorf("update gateway router %s: %w", router.Name, err)
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("transact gateway %s/%s: %w", gateway.VPC, gateway.Name, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("gateway %s/%s operation errors=%+v: %w", gateway.VPC, gateway.Name, opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) EnsureNATRule(ctx context.Context, rule model.NATRule) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	router, ok, err := w.logicalRouterByName(ctx, logicalRouter(rule.VPC))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("logical router %s must exist before NAT rule %s", logicalRouter(rule.VPC), rule.Name)
	}
	existing, err := w.natRulesByName(ctx, rule.VPC, rule.Name)
	if err != nil {
		return err
	}
	desired := desiredNATRuleRow(rule)
	var ops []ovsdb.Operation
	if len(existing) == 0 {
		desired.UUID = ovsdbNamedUUID("nl_nat_" + rule.VPC + "_" + rule.Name)
		createOps, err := w.client.Create(&desired)
		if err != nil {
			return fmt.Errorf("create NAT rule %s/%s: %w", rule.VPC, rule.Name, err)
		}
		ops = append(ops, createOps...)
		attachOps, err := w.attachNATRule(router, desired.UUID)
		if err != nil {
			return err
		}
		ops = append(ops, attachOps...)
	} else {
		keepIndex := preferredReferencedRow(router.Nat, existing, func(row ovnnb.NAT) string { return row.UUID })
		keep := existing[keepIndex]
		nextExternalIDs := mergeManagedExternalIDs(keep.ExternalIDs, desired.ExternalIDs)
		if !containsString(router.Nat, keep.UUID) {
			attachOps, err := w.attachNATRule(router, keep.UUID)
			if err != nil {
				return err
			}
			ops = append(ops, attachOps...)
		}
		if natRowChanged(keep, desired, nextExternalIDs) {
			keep.Type = desired.Type
			keep.ExternalIP = desired.ExternalIP
			keep.LogicalIP = desired.LogicalIP
			keep.ExternalPortRange = desired.ExternalPortRange
			keep.Options = desired.Options
			keep.LogicalPort = desired.LogicalPort
			keep.ExternalMAC = desired.ExternalMAC
			keep.ExternalIDs = nextExternalIDs
			updateOps, err := w.client.Where(&keep).Update(&keep, &keep.Type, &keep.ExternalIP, &keep.LogicalIP, &keep.ExternalPortRange, &keep.Options, &keep.LogicalPort, &keep.ExternalMAC, &keep.ExternalIDs)
			if err != nil {
				return fmt.Errorf("update NAT rule %s/%s: %w", rule.VPC, rule.Name, err)
			}
			ops = append(ops, updateOps...)
		}
		for i := range existing {
			if i == keepIndex {
				continue
			}
			deleteOps, err := w.deleteNATRule(router.UUID, &existing[i])
			if err != nil {
				return err
			}
			ops = append(ops, deleteOps...)
		}
	}
	if len(ops) == 0 {
		return nil
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("transact NAT rule %s/%s: %w", rule.VPC, rule.Name, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("NAT rule %s/%s operation errors=%+v: %w", rule.VPC, rule.Name, opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) EnsureLoadBalancer(ctx context.Context, lb model.LoadBalancer) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	router, ok, err := w.logicalRouterByName(ctx, logicalRouter(lb.VPC))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("logical router %s must exist before load balancer %s", logicalRouter(lb.VPC), lb.Name)
	}
	switches, err := w.logicalSwitchesForLoadBalancer(ctx, lb)
	if err != nil {
		return err
	}
	var ops []ovsdb.Operation
	frontendsByProtocol := loadBalancerFrontendsByProtocol(lb)
	desiredLBNames := make(map[string]struct{})
	for _, protocol := range sortedLoadBalancerProtocols(frontendsByProtocol) {
		name := loadBalancerProtocolName(lb.VPC, lb.Name, protocol)
		desiredLBNames[name] = struct{}{}
		desired := desiredLoadBalancerRow(lb, protocol, frontendsByProtocol[protocol])
		lbUUID, lbOps, err := w.ensureLoadBalancerRow(ctx, router, switches, desired)
		if err != nil {
			return err
		}
		ops = append(ops, lbOps...)
		hcOps, err := w.syncLoadBalancerHealthChecks(ctx, lbUUID, lb, frontendsByProtocol[protocol])
		if err != nil {
			return err
		}
		ops = append(ops, hcOps...)
	}
	staleOps, err := w.deleteStaleLoadBalancers(ctx, router.UUID, switches, lb, desiredLBNames)
	if err != nil {
		return err
	}
	ops = append(ops, staleOps...)
	if len(ops) == 0 {
		return nil
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("transact load balancer %s/%s: %w", lb.VPC, lb.Name, err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("load balancer %s/%s operation errors=%+v: %w", lb.VPC, lb.Name, opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) SyncDNSRecords(ctx context.Context, subnets []model.Subnet, records []model.DNSRecord) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("libovsdb topology writer has no client")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	switches, err := w.netloomLogicalSwitches(ctx)
	if err != nil {
		return err
	}
	desiredSwitchNames := make(map[string]struct{}, len(subnets))
	for _, subnet := range subnets {
		desiredSwitchNames[logicalSwitch(subnet.VPC, subnet.Name)] = struct{}{}
	}
	for switchName := range desiredSwitchNames {
		if _, ok := switches[switchName]; !ok {
			return fmt.Errorf("logical switch %s must exist before DNS sync", switchName)
		}
	}
	existingDNS, err := w.netloomDNSRows(ctx)
	if err != nil {
		return err
	}
	desiredRecords := desiredOVNDNSRecords(records)
	var ops []ovsdb.Operation
	if len(desiredRecords) == 0 {
		for i := range existingDNS {
			deleteOps, err := w.deleteDNSRowFromSwitches(switches, &existingDNS[i])
			if err != nil {
				return err
			}
			ops = append(ops, deleteOps...)
		}
	} else {
		keepUUID := ""
		desired := ovnnb.DNS{
			UUID:        ovsdbNamedUUID("nl_dns_records"),
			ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_dns": "desired"},
			Records:     desiredRecords,
		}
		if len(existingDNS) == 0 {
			createOps, err := w.client.Create(&desired)
			if err != nil {
				return fmt.Errorf("create DNS records row: %w", err)
			}
			ops = append(ops, createOps...)
			keepUUID = desired.UUID
		} else {
			keep := existingDNS[0]
			keepUUID = keep.UUID
			nextExternalIDs := mergeManagedExternalIDs(keep.ExternalIDs, desired.ExternalIDs)
			if !reflect.DeepEqual(keep.ExternalIDs, nextExternalIDs) ||
				!reflect.DeepEqual(keep.Records, desired.Records) ||
				len(keep.Options) != 0 {
				keep.ExternalIDs = nextExternalIDs
				keep.Records = desired.Records
				keep.Options = nil
				updateOps, err := w.client.Where(&keep).Update(&keep, &keep.ExternalIDs, &keep.Records, &keep.Options)
				if err != nil {
					return fmt.Errorf("update DNS records row %s: %w", keep.UUID, err)
				}
				ops = append(ops, updateOps...)
			}
			for i := 1; i < len(existingDNS); i++ {
				deleteOps, err := w.deleteDNSRowFromSwitches(switches, &existingDNS[i])
				if err != nil {
					return err
				}
				ops = append(ops, deleteOps...)
			}
		}
		switchOps, err := w.syncDNSRowSwitchReferences(switches, desiredSwitchNames, keepUUID)
		if err != nil {
			return err
		}
		ops = append(ops, switchOps...)
	}
	if len(ops) == 0 {
		return nil
	}
	results, err := w.client.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("transact DNS records: %w", err)
	}
	if opErrors, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		return fmt.Errorf("DNS records operation errors=%+v: %w", opErrors, err)
	}
	return nil
}

func (w *LibOVSDBTopologyWriter) subnetPortOperations(ctx context.Context, router *ovnnb.LogicalRouter, logicalSwitch *ovnnb.LogicalSwitch, existingSwitch *ovnnb.LogicalSwitch, subnet model.Subnet) ([]ovsdb.Operation, error) {
	switchUUID := logicalSwitch.UUID
	switchPorts := logicalSwitch.Ports
	if existingSwitch != nil {
		switchUUID = existingSwitch.UUID
		switchPorts = existingSwitch.Ports
	}
	routerPort := &ovnnb.LogicalRouterPort{
		Name:        routerPortName(router.Name, subnet.Name),
		MAC:         deterministicMAC(subnet),
		Networks:    []string{subnet.Gateway.String() + "/" + fmt.Sprint(subnet.CIDR.Bits())},
		ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_subnet": subnet.Name},
	}
	if subnet.DHCP.Enabled && subnet.CIDR.Addr().Is6() {
		routerPort.Ipv6RaConfigs = map[string]string{"address_mode": "dhcpv6_stateful"}
	}
	switchPort := &ovnnb.LogicalSwitchPort{
		Name:        switchRouterPortName(logicalSwitch.Name, subnet.Name),
		Type:        "router",
		Addresses:   []string{routerPort.MAC},
		Options:     map[string]string{"router-port": routerPort.Name},
		ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_subnet": subnet.Name, "netloom_role": "router"},
	}
	var ops []ovsdb.Operation
	_, routerPortOps, err := w.ensureLogicalRouterPort(ctx, router, routerPort)
	if err != nil {
		return nil, err
	}
	ops = append(ops, routerPortOps...)
	_, switchPortOps, err := w.ensureLogicalSwitchPort(ctx, switchUUID, switchPorts, switchPort)
	if err != nil {
		return nil, err
	}
	ops = append(ops, switchPortOps...)
	if subnet.ProviderNetwork != "" {
		localnetPort := &ovnnb.LogicalSwitchPort{
			Name:        localnetPortName(logicalSwitch.Name, subnet.Name),
			Type:        "localnet",
			Addresses:   []string{"unknown"},
			Options:     map[string]string{"network_name": subnet.ProviderNetwork},
			ExternalIDs: map[string]string{"netloom_owner": "netloom", "netloom_subnet": subnet.Name, "netloom_provider_network": subnet.ProviderNetwork},
		}
		if subnet.VLAN != 0 {
			tag := int(subnet.VLAN)
			localnetPort.Tag = &tag
		}
		_, localnetOps, err := w.ensureLogicalSwitchPort(ctx, switchUUID, switchPorts, localnetPort)
		if err != nil {
			return nil, err
		}
		ops = append(ops, localnetOps...)
	} else {
		localnetName := localnetPortName(logicalSwitch.Name, subnet.Name)
		existingLocalnet, ok, err := w.logicalSwitchPortByName(ctx, localnetName)
		if err != nil {
			return nil, err
		}
		if ok {
			deleteOps, err := w.deleteLogicalSwitchPort(switchUUID, existingLocalnet)
			if err != nil {
				return nil, err
			}
			ops = append(ops, deleteOps...)
		}
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) ensureLogicalRouterPort(ctx context.Context, router *ovnnb.LogicalRouter, desired *ovnnb.LogicalRouterPort) (string, []ovsdb.Operation, error) {
	existing, ok, err := w.logicalRouterPortByName(ctx, desired.Name)
	if err != nil {
		return "", nil, err
	}
	var ops []ovsdb.Operation
	if !ok {
		desired.UUID = ovsdbNamedUUID(desired.Name)
		createOps, err := w.client.Create(desired)
		if err != nil {
			return "", nil, fmt.Errorf("create logical router port %s: %w", desired.Name, err)
		}
		ops = append(ops, createOps...)
		mutateOps, err := w.client.Where(router).Mutate(router, ovsmodel.Mutation{
			Field:   &router.Ports,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{desired.UUID},
		})
		if err != nil {
			return "", nil, fmt.Errorf("attach logical router port %s to router %s: %w", desired.Name, router.Name, err)
		}
		ops = append(ops, mutateOps...)
		return desired.UUID, ops, nil
	}
	nextExternalIDs := mergeManagedExternalIDs(existing.ExternalIDs, desired.ExternalIDs)
	nextIPv6RAConfigs := replaceManagedRouterPortRAConfig(existing.Ipv6RaConfigs, desired.Ipv6RaConfigs)
	if !containsString(router.Ports, existing.UUID) {
		mutateOps, err := w.client.Where(router).Mutate(router, ovsmodel.Mutation{
			Field:   &router.Ports,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{existing.UUID},
		})
		if err != nil {
			return "", nil, fmt.Errorf("attach logical router port %s to router %s: %w", desired.Name, router.Name, err)
		}
		ops = append(ops, mutateOps...)
	}
	if existing.MAC == desired.MAC &&
		reflect.DeepEqual(existing.Networks, desired.Networks) &&
		reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) &&
		reflect.DeepEqual(existing.Ipv6RaConfigs, nextIPv6RAConfigs) {
		return existing.UUID, ops, nil
	}
	existing.MAC = desired.MAC
	existing.Networks = desired.Networks
	existing.ExternalIDs = nextExternalIDs
	existing.Ipv6RaConfigs = nextIPv6RAConfigs
	updateOps, err := w.client.Where(existing).Update(existing, &existing.MAC, &existing.Networks, &existing.ExternalIDs, &existing.Ipv6RaConfigs)
	if err != nil {
		return "", nil, fmt.Errorf("update logical router port %s: %w", desired.Name, err)
	}
	ops = append(ops, updateOps...)
	return existing.UUID, ops, nil
}

func (w *LibOVSDBTopologyWriter) ensureLogicalSwitchPort(ctx context.Context, switchUUID string, switchPorts []string, desired *ovnnb.LogicalSwitchPort) (string, []ovsdb.Operation, error) {
	existing, ok, err := w.logicalSwitchPortByName(ctx, desired.Name)
	if err != nil {
		return "", nil, err
	}
	var ops []ovsdb.Operation
	if !ok {
		desired.UUID = ovsdbNamedUUID(desired.Name)
		createOps, err := w.client.Create(desired)
		if err != nil {
			return "", nil, fmt.Errorf("create logical switch port %s: %w", desired.Name, err)
		}
		ops = append(ops, createOps...)
		switchRow := &ovnnb.LogicalSwitch{UUID: switchUUID}
		mutateOps, err := w.client.Where(switchRow).Mutate(switchRow, ovsmodel.Mutation{
			Field:   &switchRow.Ports,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{desired.UUID},
		})
		if err != nil {
			return "", nil, fmt.Errorf("attach logical switch port %s to switch %s: %w", desired.Name, switchUUID, err)
		}
		ops = append(ops, mutateOps...)
		return desired.UUID, ops, nil
	}
	nextExternalIDs := mergeManagedExternalIDs(existing.ExternalIDs, desired.ExternalIDs)
	nextTag := desired.Tag
	if !containsString(switchPorts, existing.UUID) {
		switchRow := &ovnnb.LogicalSwitch{UUID: switchUUID}
		mutateOps, err := w.client.Where(switchRow).Mutate(switchRow, ovsmodel.Mutation{
			Field:   &switchRow.Ports,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{existing.UUID},
		})
		if err != nil {
			return "", nil, fmt.Errorf("attach logical switch port %s to switch %s: %w", desired.Name, switchUUID, err)
		}
		ops = append(ops, mutateOps...)
	}
	if existing.Type == desired.Type &&
		reflect.DeepEqual(existing.Addresses, desired.Addresses) &&
		reflect.DeepEqual(existing.Options, desired.Options) &&
		reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) &&
		equalIntPointers(existing.Tag, nextTag) {
		return existing.UUID, ops, nil
	}
	existing.Type = desired.Type
	existing.Addresses = desired.Addresses
	existing.Options = desired.Options
	existing.ExternalIDs = nextExternalIDs
	existing.Tag = nextTag
	updateOps, err := w.client.Where(existing).Update(existing, &existing.Type, &existing.Addresses, &existing.Options, &existing.ExternalIDs, &existing.Tag)
	if err != nil {
		return "", nil, fmt.Errorf("update logical switch port %s: %w", desired.Name, err)
	}
	ops = append(ops, updateOps...)
	return existing.UUID, ops, nil
}

func (w *LibOVSDBTopologyWriter) ensureEndpointSwitchPort(ctx context.Context, switchUUID string, switchPorts []string, desired *ovnnb.LogicalSwitchPort) (string, []ovsdb.Operation, error) {
	existing, ok, err := w.logicalSwitchPortByName(ctx, desired.Name)
	if err != nil {
		return "", nil, err
	}
	var ops []ovsdb.Operation
	if !ok {
		desired.UUID = ovsdbNamedUUID(desired.Name)
		createOps, err := w.client.Create(desired)
		if err != nil {
			return "", nil, fmt.Errorf("create endpoint logical switch port %s: %w", desired.Name, err)
		}
		ops = append(ops, createOps...)
		switchRow := &ovnnb.LogicalSwitch{UUID: switchUUID}
		mutateOps, err := w.client.Where(switchRow).Mutate(switchRow, ovsmodel.Mutation{
			Field:   &switchRow.Ports,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{desired.UUID},
		})
		if err != nil {
			return "", nil, fmt.Errorf("attach endpoint logical switch port %s to switch %s: %w", desired.Name, switchUUID, err)
		}
		ops = append(ops, mutateOps...)
		return desired.UUID, ops, nil
	}
	nextExternalIDs := mergeManagedExternalIDs(existing.ExternalIDs, desired.ExternalIDs)
	if !containsString(switchPorts, existing.UUID) {
		switchRow := &ovnnb.LogicalSwitch{UUID: switchUUID}
		mutateOps, err := w.client.Where(switchRow).Mutate(switchRow, ovsmodel.Mutation{
			Field:   &switchRow.Ports,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{existing.UUID},
		})
		if err != nil {
			return "", nil, fmt.Errorf("attach endpoint logical switch port %s to switch %s: %w", desired.Name, switchUUID, err)
		}
		ops = append(ops, mutateOps...)
	}
	if reflect.DeepEqual(existing.Addresses, desired.Addresses) &&
		reflect.DeepEqual(existing.PortSecurity, desired.PortSecurity) &&
		reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) {
		return existing.UUID, ops, nil
	}
	existing.Addresses = desired.Addresses
	existing.PortSecurity = desired.PortSecurity
	existing.ExternalIDs = nextExternalIDs
	updateOps, err := w.client.Where(existing).Update(existing, &existing.Addresses, &existing.PortSecurity, &existing.ExternalIDs)
	if err != nil {
		return "", nil, fmt.Errorf("update endpoint logical switch port %s: %w", desired.Name, err)
	}
	ops = append(ops, updateOps...)
	return existing.UUID, ops, nil
}

func (w *LibOVSDBTopologyWriter) deleteLogicalSwitchPort(switchUUID string, port *ovnnb.LogicalSwitchPort) ([]ovsdb.Operation, error) {
	switchRow := &ovnnb.LogicalSwitch{UUID: switchUUID}
	mutateOps, err := w.client.Where(switchRow).Mutate(switchRow, ovsmodel.Mutation{
		Field:   &switchRow.Ports,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{port.UUID},
	})
	if err != nil {
		return nil, fmt.Errorf("detach logical switch port %s from switch %s: %w", port.Name, switchUUID, err)
	}
	deleteOps, err := w.client.Where(port).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete logical switch port %s: %w", port.Name, err)
	}
	return append(mutateOps, deleteOps...), nil
}

func (w *LibOVSDBTopologyWriter) attachStaticRoute(router *ovnnb.LogicalRouter, routeUUID string) ([]ovsdb.Operation, error) {
	return w.client.Where(router).Mutate(router, ovsmodel.Mutation{
		Field:   &router.StaticRoutes,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{routeUUID},
	})
}

func (w *LibOVSDBTopologyWriter) deleteStaticRoute(routerUUID string, route *ovnnb.LogicalRouterStaticRoute) ([]ovsdb.Operation, error) {
	router := &ovnnb.LogicalRouter{UUID: routerUUID}
	mutateOps, err := w.client.Where(router).Mutate(router, ovsmodel.Mutation{
		Field:   &router.StaticRoutes,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{route.UUID},
	})
	if err != nil {
		return nil, fmt.Errorf("detach static route %s from router %s: %w", route.UUID, routerUUID, err)
	}
	deleteOps, err := w.client.Where(route).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete static route %s: %w", route.UUID, err)
	}
	return append(mutateOps, deleteOps...), nil
}

func (w *LibOVSDBTopologyWriter) attachPolicyRoute(router *ovnnb.LogicalRouter, policyUUID string) ([]ovsdb.Operation, error) {
	return w.client.Where(router).Mutate(router, ovsmodel.Mutation{
		Field:   &router.Policies,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{policyUUID},
	})
}

func (w *LibOVSDBTopologyWriter) deletePolicyRoute(routerUUID string, policy *ovnnb.LogicalRouterPolicy) ([]ovsdb.Operation, error) {
	router := &ovnnb.LogicalRouter{UUID: routerUUID}
	mutateOps, err := w.client.Where(router).Mutate(router, ovsmodel.Mutation{
		Field:   &router.Policies,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{policy.UUID},
	})
	if err != nil {
		return nil, fmt.Errorf("detach policy route %s from router %s: %w", policy.UUID, routerUUID, err)
	}
	deleteOps, err := w.client.Where(policy).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete policy route %s: %w", policy.UUID, err)
	}
	return append(mutateOps, deleteOps...), nil
}

func (w *LibOVSDBTopologyWriter) attachNATRule(router *ovnnb.LogicalRouter, natUUID string) ([]ovsdb.Operation, error) {
	return w.client.Where(router).Mutate(router, ovsmodel.Mutation{
		Field:   &router.Nat,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{natUUID},
	})
}

func (w *LibOVSDBTopologyWriter) deleteNATRule(routerUUID string, nat *ovnnb.NAT) ([]ovsdb.Operation, error) {
	router := &ovnnb.LogicalRouter{UUID: routerUUID}
	mutateOps, err := w.client.Where(router).Mutate(router, ovsmodel.Mutation{
		Field:   &router.Nat,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{nat.UUID},
	})
	if err != nil {
		return nil, fmt.Errorf("detach NAT rule %s from router %s: %w", nat.UUID, routerUUID, err)
	}
	deleteOps, err := w.client.Where(nat).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete NAT rule %s: %w", nat.UUID, err)
	}
	return append(mutateOps, deleteOps...), nil
}

func (w *LibOVSDBTopologyWriter) ensureLoadBalancerRow(ctx context.Context, router *ovnnb.LogicalRouter, switches []ovnnb.LogicalSwitch, desired ovnnb.LoadBalancer) (string, []ovsdb.Operation, error) {
	existing, ok, err := w.loadBalancerByName(ctx, desired.Name)
	if err != nil {
		return "", nil, err
	}
	var ops []ovsdb.Operation
	if !ok {
		desired.UUID = ovsdbNamedUUID(desired.Name)
		createOps, err := w.client.Create(&desired)
		if err != nil {
			return "", nil, fmt.Errorf("create load balancer %s: %w", desired.Name, err)
		}
		ops = append(ops, createOps...)
		attachRouterOps, err := w.attachLoadBalancerToRouter(router, desired.UUID)
		if err != nil {
			return "", nil, err
		}
		ops = append(ops, attachRouterOps...)
		for i := range switches {
			attachSwitchOps, err := w.attachLoadBalancerToSwitch(&switches[i], desired.UUID)
			if err != nil {
				return "", nil, err
			}
			ops = append(ops, attachSwitchOps...)
		}
		return desired.UUID, ops, nil
	}
	nextExternalIDs := mergeManagedExternalIDs(existing.ExternalIDs, desired.ExternalIDs)
	nextOptions := replaceManagedLoadBalancerOptions(existing.Options, desired.Options)
	if !containsString(router.LoadBalancer, existing.UUID) {
		attachOps, err := w.attachLoadBalancerToRouter(router, existing.UUID)
		if err != nil {
			return "", nil, err
		}
		ops = append(ops, attachOps...)
	}
	for i := range switches {
		if containsString(switches[i].LoadBalancer, existing.UUID) {
			continue
		}
		attachOps, err := w.attachLoadBalancerToSwitch(&switches[i], existing.UUID)
		if err != nil {
			return "", nil, err
		}
		ops = append(ops, attachOps...)
	}
	if !reflect.DeepEqual(existing.Vips, desired.Vips) ||
		!reflect.DeepEqual(existing.Protocol, desired.Protocol) ||
		!reflect.DeepEqual(existing.SelectionFields, desired.SelectionFields) ||
		!reflect.DeepEqual(existing.ExternalIDs, nextExternalIDs) ||
		!reflect.DeepEqual(existing.Options, nextOptions) {
		existing.Vips = desired.Vips
		existing.Protocol = desired.Protocol
		existing.SelectionFields = desired.SelectionFields
		existing.ExternalIDs = nextExternalIDs
		existing.Options = nextOptions
		updateOps, err := w.client.Where(existing).Update(existing, &existing.Vips, &existing.Protocol, &existing.SelectionFields, &existing.ExternalIDs, &existing.Options)
		if err != nil {
			return "", nil, fmt.Errorf("update load balancer %s: %w", desired.Name, err)
		}
		ops = append(ops, updateOps...)
	}
	return existing.UUID, ops, nil
}

func (w *LibOVSDBTopologyWriter) attachLoadBalancerToRouter(router *ovnnb.LogicalRouter, lbUUID string) ([]ovsdb.Operation, error) {
	return w.client.Where(router).Mutate(router, ovsmodel.Mutation{
		Field:   &router.LoadBalancer,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{lbUUID},
	})
}

func (w *LibOVSDBTopologyWriter) detachLoadBalancerFromRouter(routerUUID, lbUUID string) ([]ovsdb.Operation, error) {
	router := &ovnnb.LogicalRouter{UUID: routerUUID}
	return w.client.Where(router).Mutate(router, ovsmodel.Mutation{
		Field:   &router.LoadBalancer,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{lbUUID},
	})
}

func (w *LibOVSDBTopologyWriter) attachLoadBalancerToSwitch(sw *ovnnb.LogicalSwitch, lbUUID string) ([]ovsdb.Operation, error) {
	return w.client.Where(sw).Mutate(sw, ovsmodel.Mutation{
		Field:   &sw.LoadBalancer,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{lbUUID},
	})
}

func (w *LibOVSDBTopologyWriter) detachLoadBalancerFromSwitch(switchUUID, lbUUID string) ([]ovsdb.Operation, error) {
	sw := &ovnnb.LogicalSwitch{UUID: switchUUID}
	return w.client.Where(sw).Mutate(sw, ovsmodel.Mutation{
		Field:   &sw.LoadBalancer,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{lbUUID},
	})
}

func (w *LibOVSDBTopologyWriter) syncDNSRowSwitchReferences(switches map[string]ovnnb.LogicalSwitch, desiredSwitchNames map[string]struct{}, dnsUUID string) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	names := make([]string, 0, len(switches))
	for name := range switches {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sw := switches[name]
		_, desired := desiredSwitchNames[name]
		hasRef := containsString(sw.DNSRecords, dnsUUID)
		if desired && !hasRef {
			switchRow := &ovnnb.LogicalSwitch{UUID: sw.UUID}
			mutateOps, err := w.client.Where(switchRow).Mutate(switchRow, ovsmodel.Mutation{
				Field:   &switchRow.DNSRecords,
				Mutator: ovsdb.MutateOperationInsert,
				Value:   []string{dnsUUID},
			})
			if err != nil {
				return nil, fmt.Errorf("attach DNS records row %s to switch %s: %w", dnsUUID, sw.Name, err)
			}
			ops = append(ops, mutateOps...)
			continue
		}
		if !desired && hasRef {
			mutateOps, err := w.detachDNSRowFromSwitch(sw.UUID, dnsUUID)
			if err != nil {
				return nil, err
			}
			ops = append(ops, mutateOps...)
		}
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) deleteDNSRowFromSwitches(switches map[string]ovnnb.LogicalSwitch, dns *ovnnb.DNS) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	names := make([]string, 0, len(switches))
	for name := range switches {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sw := switches[name]
		if !containsString(sw.DNSRecords, dns.UUID) {
			continue
		}
		detachOps, err := w.detachDNSRowFromSwitch(sw.UUID, dns.UUID)
		if err != nil {
			return nil, err
		}
		ops = append(ops, detachOps...)
	}
	deleteOps, err := w.client.Where(dns).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete DNS records row %s: %w", dns.UUID, err)
	}
	ops = append(ops, deleteOps...)
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) detachDNSRowFromSwitch(switchUUID, dnsUUID string) ([]ovsdb.Operation, error) {
	sw := &ovnnb.LogicalSwitch{UUID: switchUUID}
	return w.client.Where(sw).Mutate(sw, ovsmodel.Mutation{
		Field:   &sw.DNSRecords,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{dnsUUID},
	})
}

func (w *LibOVSDBTopologyWriter) syncLoadBalancerHealthChecks(ctx context.Context, lbUUID string, lb model.LoadBalancer, frontends []model.LoadBalancerFrontend) ([]ovsdb.Operation, error) {
	existing, err := w.healthChecksByLoadBalancer(ctx, lb.VPC, lb.Name)
	if err != nil {
		return nil, err
	}
	existingByVIP := make(map[string][]ovnnb.LoadBalancerHealthCheck, len(existing))
	for _, hc := range existing {
		existingByVIP[hc.Vip] = append(existingByVIP[hc.Vip], hc)
	}
	desiredVIPs := make(map[string]struct{})
	var ops []ovsdb.Operation
	lbRow := &ovnnb.LoadBalancer{UUID: lbUUID}
	if lb.HealthCheck.Enabled {
		for _, frontend := range frontends {
			desired := desiredLoadBalancerHealthCheck(lb, frontend)
			desiredVIPs[desired.Vip] = struct{}{}
			rows := existingByVIP[desired.Vip]
			if len(rows) == 0 {
				desired.UUID = ovsdbNamedUUID("nl_lbhc_" + lb.VPC + "_" + lb.Name + "_" + desired.Vip)
				createOps, err := w.client.Create(&desired)
				if err != nil {
					return nil, fmt.Errorf("create load balancer health check %s: %w", desired.Vip, err)
				}
				ops = append(ops, createOps...)
				attachOps, err := w.client.Where(lbRow).Mutate(lbRow, ovsmodel.Mutation{
					Field:   &lbRow.HealthCheck,
					Mutator: ovsdb.MutateOperationInsert,
					Value:   []string{desired.UUID},
				})
				if err != nil {
					return nil, fmt.Errorf("attach load balancer health check %s: %w", desired.UUID, err)
				}
				ops = append(ops, attachOps...)
				continue
			}
			keep := rows[0]
			nextExternalIDs := mergeManagedExternalIDs(keep.ExternalIDs, desired.ExternalIDs)
			if keep.Vip != desired.Vip || !reflect.DeepEqual(keep.Options, desired.Options) || !reflect.DeepEqual(keep.ExternalIDs, nextExternalIDs) {
				keep.Vip = desired.Vip
				keep.Options = desired.Options
				keep.ExternalIDs = nextExternalIDs
				updateOps, err := w.client.Where(&keep).Update(&keep, &keep.Vip, &keep.Options, &keep.ExternalIDs)
				if err != nil {
					return nil, fmt.Errorf("update load balancer health check %s: %w", keep.UUID, err)
				}
				ops = append(ops, updateOps...)
			}
			for i := 1; i < len(rows); i++ {
				deleteOps, err := w.deleteLoadBalancerHealthCheck(lbUUID, &rows[i])
				if err != nil {
					return nil, err
				}
				ops = append(ops, deleteOps...)
			}
		}
	}
	for vip, rows := range existingByVIP {
		if _, ok := desiredVIPs[vip]; ok {
			continue
		}
		for i := range rows {
			deleteOps, err := w.deleteLoadBalancerHealthCheck(lbUUID, &rows[i])
			if err != nil {
				return nil, err
			}
			ops = append(ops, deleteOps...)
		}
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) deleteLoadBalancerHealthCheck(lbUUID string, hc *ovnnb.LoadBalancerHealthCheck) ([]ovsdb.Operation, error) {
	lbRow := &ovnnb.LoadBalancer{UUID: lbUUID}
	detachOps, err := w.client.Where(lbRow).Mutate(lbRow, ovsmodel.Mutation{
		Field:   &lbRow.HealthCheck,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{hc.UUID},
	})
	if err != nil {
		return nil, fmt.Errorf("detach load balancer health check %s: %w", hc.UUID, err)
	}
	deleteOps, err := w.client.Where(hc).Delete()
	if err != nil {
		return nil, fmt.Errorf("delete load balancer health check %s: %w", hc.UUID, err)
	}
	return append(detachOps, deleteOps...), nil
}

func (w *LibOVSDBTopologyWriter) deleteStaleLoadBalancers(ctx context.Context, routerUUID string, switches []ovnnb.LogicalSwitch, lb model.LoadBalancer, desiredNames map[string]struct{}) ([]ovsdb.Operation, error) {
	rows, err := w.loadBalancersByIdentity(ctx, lb.VPC, lb.Name)
	if err != nil {
		return nil, err
	}
	var ops []ovsdb.Operation
	for i := range rows {
		if _, ok := desiredNames[rows[i].Name]; ok {
			continue
		}
		hcRows, err := w.healthChecksByLoadBalancerName(ctx, rows[i].Name, lb.VPC, lb.Name)
		if err != nil {
			return nil, err
		}
		for j := range hcRows {
			deleteOps, err := w.deleteLoadBalancerHealthCheck(rows[i].UUID, &hcRows[j])
			if err != nil {
				return nil, err
			}
			ops = append(ops, deleteOps...)
		}
		detachRouterOps, err := w.detachLoadBalancerFromRouter(routerUUID, rows[i].UUID)
		if err != nil {
			return nil, err
		}
		ops = append(ops, detachRouterOps...)
		for j := range switches {
			detachSwitchOps, err := w.detachLoadBalancerFromSwitch(switches[j].UUID, rows[i].UUID)
			if err != nil {
				return nil, err
			}
			ops = append(ops, detachSwitchOps...)
		}
		deleteOps, err := w.client.Where(&rows[i]).Delete()
		if err != nil {
			return nil, fmt.Errorf("delete stale load balancer %s: %w", rows[i].Name, err)
		}
		ops = append(ops, deleteOps...)
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) endpointDHCPOptionsOperations(ctx context.Context, endpoint model.Endpoint, switchExternalIDs map[string]string, port *ovnnb.LogicalSwitchPort) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	for _, family := range []int{4, 6} {
		desired, enabled, err := w.desiredEndpointDHCPOptions(ctx, endpoint, switchExternalIDs, family)
		if err != nil {
			return nil, err
		}
		currentDHCPUUID := pointerStringValue(port.Dhcpv4Options)
		if family == 6 {
			currentDHCPUUID = pointerStringValue(port.Dhcpv6Options)
		}
		nextOps, dhcpUUID, err := w.ensureEndpointDHCPOptions(ctx, endpoint, family, desired, enabled, currentDHCPUUID)
		if err != nil {
			return nil, err
		}
		ops = append(ops, nextOps...)
		if family == 4 {
			if !stringPointerValueEqual(port.Dhcpv4Options, dhcpUUID) {
				port.Dhcpv4Options = optionalString(dhcpUUID)
				bindOps, err := w.client.Where(port).Update(port, &port.Dhcpv4Options)
				if err != nil {
					return nil, fmt.Errorf("sync DHCPv4 options on port %s: %w", port.UUID, err)
				}
				ops = append(ops, bindOps...)
			}
			continue
		}
		if !stringPointerValueEqual(port.Dhcpv6Options, dhcpUUID) {
			port.Dhcpv6Options = optionalString(dhcpUUID)
			bindOps, err := w.client.Where(port).Update(port, &port.Dhcpv6Options)
			if err != nil {
				return nil, fmt.Errorf("sync DHCPv6 options on port %s: %w", port.UUID, err)
			}
			ops = append(ops, bindOps...)
		}
	}
	return ops, nil
}

func (w *LibOVSDBTopologyWriter) desiredEndpointDHCPOptions(ctx context.Context, endpoint model.Endpoint, switchExternalIDs map[string]string, family int) (*ovnnb.DHCPOptions, bool, error) {
	if switchExternalIDs["netloom_dhcp_enabled"] != "true" {
		return nil, false, nil
	}
	if (family == 4 && !endpoint.IP.Is4()) || (family == 6 && !endpoint.IP.Is6()) {
		return nil, false, nil
	}
	cidr := switchExternalIDs["netloom_cidr"]
	gateway := switchExternalIDs["netloom_gateway"]
	if cidr == "" || gateway == "" {
		return nil, false, fmt.Errorf("logical switch %s/%s missing DHCP CIDR or gateway metadata", endpoint.VPC, endpoint.Subnet)
	}
	routerPort, ok, err := w.logicalRouterPortByName(ctx, routerPortName(logicalRouter(endpoint.VPC), endpoint.Subnet))
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, fmt.Errorf("logical router port for subnet %s/%s must exist before endpoint DHCP", endpoint.VPC, endpoint.Subnet)
	}
	options := map[string]string{}
	if family == 4 {
		options["server_id"] = gateway
		options["server_mac"] = routerPort.MAC
		options["router"] = gateway
		leaseTime := switchExternalIDs["netloom_dhcp_lease_time"]
		if leaseTime == "" || leaseTime == "0" {
			leaseTime = "3600"
		}
		options["lease_time"] = leaseTime
		if mtu := switchExternalIDs["netloom_dhcp_mtu"]; mtu != "" && mtu != "0" {
			options["mtu"] = mtu
		}
		addDHCPDNSOptions(options, switchExternalIDs, 4)
	} else {
		options["server_id"] = routerPort.MAC
		addDHCPDNSOptions(options, switchExternalIDs, 6)
	}
	return &ovnnb.DHCPOptions{
		UUID:    strings.TrimPrefix(dhcpOptionsUUID(endpoint, family), "@"),
		Cidr:    cidr,
		Options: options,
		ExternalIDs: map[string]string{
			"netloom_owner":       "netloom",
			"netloom_subnet":      endpoint.Subnet,
			"netloom_endpoint":    endpointExternalID(endpoint.VPC, endpoint.ID),
			"netloom_vpc":         endpoint.VPC,
			"netloom_dhcp_family": fmt.Sprint(family),
		},
	}, true, nil
}

func (w *LibOVSDBTopologyWriter) ensureEndpointDHCPOptions(ctx context.Context, endpoint model.Endpoint, family int, desired *ovnnb.DHCPOptions, enabled bool, currentUUID string) ([]ovsdb.Operation, string, error) {
	rows, err := w.endpointDHCPOptionsByFamily(ctx, endpoint, family)
	if err != nil {
		return nil, "", err
	}
	var ops []ovsdb.Operation
	if !enabled {
		for i := range rows {
			deleteOps, err := w.client.Where(&rows[i]).Delete()
			if err != nil {
				return nil, "", fmt.Errorf("delete DHCP options %s: %w", rows[i].UUID, err)
			}
			ops = append(ops, deleteOps...)
		}
		return ops, "", nil
	}
	if len(rows) == 0 {
		createOps, err := w.client.Create(desired)
		if err != nil {
			return nil, "", fmt.Errorf("create DHCP options for endpoint %s family %d: %w", endpoint.ID, family, err)
		}
		ops = append(ops, createOps...)
		return ops, desired.UUID, nil
	}
	keepIndex := 0
	for i := range rows {
		if rows[i].UUID == currentUUID {
			keepIndex = i
			break
		}
	}
	keep := rows[keepIndex]
	nextExternalIDs := mergeManagedExternalIDs(keep.ExternalIDs, desired.ExternalIDs)
	if keep.Cidr != desired.Cidr || !reflect.DeepEqual(keep.Options, desired.Options) || !reflect.DeepEqual(keep.ExternalIDs, nextExternalIDs) {
		keep.Cidr = desired.Cidr
		keep.Options = desired.Options
		keep.ExternalIDs = nextExternalIDs
		updateOps, err := w.client.Where(&keep).Update(&keep, &keep.Cidr, &keep.Options, &keep.ExternalIDs)
		if err != nil {
			return nil, "", fmt.Errorf("update DHCP options %s: %w", keep.UUID, err)
		}
		ops = append(ops, updateOps...)
	}
	for i := range rows {
		if i == keepIndex {
			continue
		}
		deleteOps, err := w.client.Where(&rows[i]).Delete()
		if err != nil {
			return nil, "", fmt.Errorf("delete duplicate DHCP options %s: %w", rows[i].UUID, err)
		}
		ops = append(ops, deleteOps...)
	}
	return ops, keep.UUID, nil
}

func (w *LibOVSDBTopologyWriter) logicalRouterByName(ctx context.Context, name string) (*ovnnb.LogicalRouter, bool, error) {
	var routers []ovnnb.LogicalRouter
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouter) bool { return row.Name == name }).List(ctx, &routers); err != nil {
		return nil, false, fmt.Errorf("list logical router %s from libovsdb cache: %w", name, err)
	}
	if len(routers) == 0 {
		return nil, false, nil
	}
	return &routers[0], true, nil
}

func (w *LibOVSDBTopologyWriter) logicalSwitchByName(ctx context.Context, name string) (*ovnnb.LogicalSwitch, bool, error) {
	var switches []ovnnb.LogicalSwitch
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitch) bool { return row.Name == name }).List(ctx, &switches); err != nil {
		return nil, false, fmt.Errorf("list logical switch %s from libovsdb cache: %w", name, err)
	}
	if len(switches) == 0 {
		return nil, false, nil
	}
	return &switches[0], true, nil
}

func (w *LibOVSDBTopologyWriter) netloomLogicalSwitches(ctx context.Context) (map[string]ovnnb.LogicalSwitch, error) {
	var rows []ovnnb.LogicalSwitch
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitch) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom"
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list netloom logical switches from libovsdb cache: %w", err)
	}
	out := make(map[string]ovnnb.LogicalSwitch, len(rows))
	for _, row := range rows {
		out[row.Name] = row
	}
	return out, nil
}

func (w *LibOVSDBTopologyWriter) logicalRouterPortByName(ctx context.Context, name string) (*ovnnb.LogicalRouterPort, bool, error) {
	var ports []ovnnb.LogicalRouterPort
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouterPort) bool { return row.Name == name }).List(ctx, &ports); err != nil {
		return nil, false, fmt.Errorf("list logical router port %s from libovsdb cache: %w", name, err)
	}
	if len(ports) == 0 {
		return nil, false, nil
	}
	return &ports[0], true, nil
}

func (w *LibOVSDBTopologyWriter) logicalSwitchPortByName(ctx context.Context, name string) (*ovnnb.LogicalSwitchPort, bool, error) {
	var ports []ovnnb.LogicalSwitchPort
	if err := w.client.WhereCache(func(row *ovnnb.LogicalSwitchPort) bool { return row.Name == name }).List(ctx, &ports); err != nil {
		return nil, false, fmt.Errorf("list logical switch port %s from libovsdb cache: %w", name, err)
	}
	if len(ports) == 0 {
		return nil, false, nil
	}
	return &ports[0], true, nil
}

func (w *LibOVSDBTopologyWriter) endpointDHCPOptionsByFamily(ctx context.Context, endpoint model.Endpoint, family int) ([]ovnnb.DHCPOptions, error) {
	endpointID := endpointExternalID(endpoint.VPC, endpoint.ID)
	var rows []ovnnb.DHCPOptions
	if err := w.client.WhereCache(func(row *ovnnb.DHCPOptions) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom" &&
			row.ExternalIDs["netloom_vpc"] == endpoint.VPC &&
			row.ExternalIDs["netloom_endpoint"] == endpointID &&
			row.ExternalIDs["netloom_dhcp_family"] == fmt.Sprint(family)
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list DHCP options for endpoint %s family %d from libovsdb cache: %w", endpoint.ID, family, err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) staticRoutesByRouteTable(ctx context.Context, table model.RouteTable) ([]ovnnb.LogicalRouterStaticRoute, error) {
	var rows []ovnnb.LogicalRouterStaticRoute
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouterStaticRoute) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom" &&
			row.ExternalIDs["netloom_vpc"] == table.VPC &&
			row.ExternalIDs["netloom_route_table"] == table.Name
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list static routes for route table %s/%s from libovsdb cache: %w", table.VPC, table.Name, err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) policyRoutesByName(ctx context.Context, vpc, name string) ([]ovnnb.LogicalRouterPolicy, error) {
	var rows []ovnnb.LogicalRouterPolicy
	if err := w.client.WhereCache(func(row *ovnnb.LogicalRouterPolicy) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom" &&
			row.ExternalIDs["netloom_vpc"] == vpc &&
			row.ExternalIDs["netloom_policy_route"] == name
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list policy routes %s/%s from libovsdb cache: %w", vpc, name, err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) natRulesByName(ctx context.Context, vpc, name string) ([]ovnnb.NAT, error) {
	var rows []ovnnb.NAT
	if err := w.client.WhereCache(func(row *ovnnb.NAT) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom" &&
			row.ExternalIDs["netloom_vpc"] == vpc &&
			row.ExternalIDs["netloom_nat"] == name
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list NAT rules %s/%s from libovsdb cache: %w", vpc, name, err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) loadBalancerByName(ctx context.Context, name string) (*ovnnb.LoadBalancer, bool, error) {
	var rows []ovnnb.LoadBalancer
	if err := w.client.WhereCache(func(row *ovnnb.LoadBalancer) bool { return row.Name == name }).List(ctx, &rows); err != nil {
		return nil, false, fmt.Errorf("list load balancer %s from libovsdb cache: %w", name, err)
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return &rows[0], true, nil
}

func (w *LibOVSDBTopologyWriter) netloomDNSRows(ctx context.Context) ([]ovnnb.DNS, error) {
	var rows []ovnnb.DNS
	if err := w.client.WhereCache(func(row *ovnnb.DNS) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom" &&
			row.ExternalIDs["netloom_dns"] == "desired"
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list DNS records rows from libovsdb cache: %w", err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) loadBalancersByIdentity(ctx context.Context, vpc, name string) ([]ovnnb.LoadBalancer, error) {
	var rows []ovnnb.LoadBalancer
	if err := w.client.WhereCache(func(row *ovnnb.LoadBalancer) bool {
		return row.ExternalIDs["netloom_owner"] == "netloom" &&
			row.ExternalIDs["netloom_vpc"] == vpc &&
			row.ExternalIDs["netloom_load_balancer"] == name
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list load balancers %s/%s from libovsdb cache: %w", vpc, name, err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) healthChecksByLoadBalancer(ctx context.Context, vpc, name string) ([]ovnnb.LoadBalancerHealthCheck, error) {
	return w.healthChecksByLoadBalancerName(ctx, "", vpc, name)
}

func (w *LibOVSDBTopologyWriter) healthChecksByLoadBalancerName(ctx context.Context, ovnLBName, vpc, name string) ([]ovnnb.LoadBalancerHealthCheck, error) {
	var rows []ovnnb.LoadBalancerHealthCheck
	if err := w.client.WhereCache(func(row *ovnnb.LoadBalancerHealthCheck) bool {
		if row.ExternalIDs["netloom_owner"] != "netloom" ||
			row.ExternalIDs["netloom_vpc"] != vpc ||
			row.ExternalIDs["netloom_load_balancer"] != name {
			return false
		}
		return ovnLBName == "" || row.ExternalIDs["netloom_ovn_load_balancer"] == ovnLBName
	}).List(ctx, &rows); err != nil {
		return nil, fmt.Errorf("list load balancer health checks %s/%s from libovsdb cache: %w", vpc, name, err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	return rows, nil
}

func (w *LibOVSDBTopologyWriter) logicalSwitchesForLoadBalancer(ctx context.Context, lb model.LoadBalancer) ([]ovnnb.LogicalSwitch, error) {
	switches := make([]ovnnb.LogicalSwitch, 0, len(lb.Subnets))
	for _, subnet := range lb.Subnets {
		name := logicalSwitch(lb.VPC, subnet)
		sw, ok, err := w.logicalSwitchByName(ctx, name)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("logical switch %s must exist before load balancer %s", name, lb.Name)
		}
		switches = append(switches, *sw)
	}
	return switches, nil
}

func mergeManagedExternalIDs(base map[string]string, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for key, value := range base {
		if strings.HasPrefix(key, "netloom_") {
			continue
		}
		out[key] = value
	}
	for key, value := range overlay {
		out[key] = value
	}
	return out
}

func mergeGatewayExternalIDs(base map[string]string, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for key, value := range base {
		if isGatewayExternalID(key) {
			continue
		}
		out[key] = value
	}
	for key, value := range overlay {
		out[key] = value
	}
	return out
}

func isGatewayExternalID(key string) bool {
	switch key {
	case "netloom_gateway", "netloom_gateway_lan_ip", "netloom_gateway_distributed", "netloom_external_if":
		return true
	default:
		return false
	}
}

func mergeStringMap(base map[string]string, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range overlay {
		out[key] = value
	}
	return out
}

func logicalSwitchExternalIDs(subnet model.Subnet) map[string]string {
	out := map[string]string{
		"netloom_owner":             "netloom",
		"netloom_vpc":               subnet.VPC,
		"netloom_subnet":            subnet.Name,
		"netloom_cidr":              subnet.CIDR.String(),
		"netloom_gateway":           subnet.Gateway.String(),
		"netloom_dhcp_enabled":      fmt.Sprintf("%t", subnet.DHCP.Enabled),
		"netloom_dhcp_lease_time":   fmt.Sprint(subnet.DHCP.LeaseTime),
		"netloom_dhcp_mtu":          fmt.Sprint(subnet.DHCP.MTU),
		"netloom_dhcp_dns_servers":  joinAddrs(subnet.DHCP.DNSServers),
		"netloom_dhcp_domain_name":  subnet.DHCP.DomainName,
		"netloom_dhcp_search_paths": strings.Join(subnet.DHCP.SearchDomains, ","),
	}
	return out
}

func desiredStaticRouteRows(table model.RouteTable, route model.Route) []ovnnb.LogicalRouterStaticRoute {
	if route.Blackhole {
		return []ovnnb.LogicalRouterStaticRoute{{
			IPPrefix:   route.Destination.String(),
			Nexthop:    "discard",
			RouteTable: table.Name,
			ExternalIDs: map[string]string{
				"netloom_owner":       "netloom",
				"netloom_vpc":         table.VPC,
				"netloom_route_table": table.Name,
				"netloom_route_key":   staticRouteKey(route.Destination.String(), "discard"),
			},
		}}
	}
	nextHops := route.RouteNextHops()
	rows := make([]ovnnb.LogicalRouterStaticRoute, 0, len(nextHops))
	for _, nextHop := range nextHops {
		nextHopString := nextHop.String()
		rows = append(rows, ovnnb.LogicalRouterStaticRoute{
			IPPrefix:   route.Destination.String(),
			Nexthop:    nextHopString,
			RouteTable: table.Name,
			ExternalIDs: map[string]string{
				"netloom_owner":       "netloom",
				"netloom_vpc":         table.VPC,
				"netloom_route_table": table.Name,
				"netloom_route_key":   staticRouteKey(route.Destination.String(), nextHopString),
			},
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Nexthop < rows[j].Nexthop })
	return rows
}

func staticRouteRowKey(route ovnnb.LogicalRouterStaticRoute) string {
	if key := route.ExternalIDs["netloom_route_key"]; key != "" {
		return key
	}
	return staticRouteKey(route.IPPrefix, route.Nexthop)
}

func staticRouteKey(prefix, nextHop string) string {
	return prefix + "|" + nextHop
}

func staticRouteRowChanged(current, desired ovnnb.LogicalRouterStaticRoute, nextExternalIDs map[string]string) bool {
	return !stringPointerValueEqual(current.BFD, pointerStringValue(desired.BFD)) ||
		current.IPPrefix != desired.IPPrefix ||
		current.Nexthop != desired.Nexthop ||
		!reflect.DeepEqual(current.Options, desired.Options) ||
		!stringPointerValueEqual(current.OutputPort, pointerStringValue(desired.OutputPort)) ||
		!staticRoutePolicyPointerValueEqual(current.Policy, desired.Policy) ||
		current.RouteTable != desired.RouteTable ||
		!reflect.DeepEqual(current.SelectionFields, desired.SelectionFields) ||
		!reflect.DeepEqual(current.ExternalIDs, nextExternalIDs)
}

func staticRoutePolicyPointerValueEqual(current, desired *ovnnb.LogicalRouterStaticRoutePolicy) bool {
	if current == nil || desired == nil {
		return current == desired
	}
	return *current == *desired
}

func desiredPolicyRouteRow(route model.PolicyRoute) ovnnb.LogicalRouterPolicy {
	action := ovnPolicyRouteAction(route.Action.Type)
	row := ovnnb.LogicalRouterPolicy{
		Priority: route.Priority,
		Match:    policyRouteMatch(route.Match),
		Action:   action,
		ExternalIDs: map[string]string{
			"netloom_owner":        "netloom",
			"netloom_vpc":          route.VPC,
			"netloom_policy_route": route.Name,
			"netloom_action":       string(route.Action.Type),
		},
	}
	if route.Action.Type == model.ActionReroute {
		nextHops := route.Action.RerouteNextHops()
		values := make([]string, 0, len(nextHops))
		for _, nextHop := range nextHops {
			values = append(values, nextHop.String())
		}
		sort.Strings(values)
		if len(values) == 1 {
			row.Nexthop = &values[0]
		} else {
			row.Nexthops = values
		}
	}
	return row
}

func ovnPolicyRouteAction(action model.Action) ovnnb.LogicalRouterPolicyAction {
	switch action {
	case model.ActionReject:
		return ovnnb.LogicalRouterPolicyActionDrop
	case model.ActionReroute:
		return ovnnb.LogicalRouterPolicyActionReroute
	case model.ActionAllow:
		return ovnnb.LogicalRouterPolicyActionAllow
	default:
		return ovnnb.LogicalRouterPolicyActionDrop
	}
}

func gatewayExternalIDs(gateway model.Gateway) map[string]string {
	out := map[string]string{
		"netloom_owner":               "netloom",
		"netloom_gateway":             gateway.Name,
		"netloom_gateway_lan_ip":      gateway.LANIP.String(),
		"netloom_gateway_distributed": fmt.Sprintf("%t", gateway.Distributed),
	}
	if gateway.ExternalIF != "" {
		out["netloom_external_if"] = gateway.ExternalIF
	}
	return out
}

func gatewayRouterOptions(base map[string]string, gateway model.Gateway) map[string]string {
	out := cloneStringMap(base)
	if out == nil {
		out = make(map[string]string)
	}
	if gateway.Distributed {
		delete(out, "chassis")
		return out
	}
	out["chassis"] = gateway.Node
	return out
}

func desiredNATRuleRow(rule model.NATRule) ovnnb.NAT {
	row := ovnnb.NAT{
		Type:       ovnNATType(rule.Type),
		ExternalIP: rule.ExternalIP.String(),
		LogicalIP:  natLogicalIP(rule),
		ExternalIDs: map[string]string{
			"netloom_owner": "netloom",
			"netloom_nat":   rule.Name,
			"netloom_vpc":   rule.VPC,
		},
	}
	if rule.ExternalPort != 0 {
		row.ExternalPortRange = fmt.Sprint(rule.ExternalPort)
		row.ExternalIDs["netloom_external_port"] = fmt.Sprint(rule.ExternalPort)
	}
	if rule.TargetPort != 0 {
		row.Options = map[string]string{"netloom_logical_port_range": fmt.Sprint(rule.TargetPort)}
		row.ExternalIDs["netloom_target_port"] = fmt.Sprint(rule.TargetPort)
	}
	if rule.Protocol != "" && rule.Protocol != model.ProtocolAny {
		if row.Options == nil {
			row.Options = make(map[string]string)
		}
		row.Options["netloom_protocol"] = string(rule.Protocol)
		row.ExternalIDs["netloom_protocol"] = string(rule.Protocol)
	}
	if rule.LogicalPort != "" {
		row.LogicalPort = &rule.LogicalPort
	}
	if rule.ExternalMAC != "" {
		row.ExternalMAC = &rule.ExternalMAC
	}
	return row
}

func desiredOVNDNSRecords(records []model.DNSRecord) map[string]string {
	ipsByName := make(map[string]map[string]struct{}, len(records))
	for _, record := range records {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record.Name)), ".")
		if name == "" {
			continue
		}
		if ipsByName[name] == nil {
			ipsByName[name] = map[string]struct{}{}
		}
		for _, ip := range record.IPs {
			if ip.IsValid() {
				ipsByName[name][ip.String()] = struct{}{}
			}
		}
	}
	out := make(map[string]string, len(ipsByName))
	for name, ipSet := range ipsByName {
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		if len(ips) > 0 {
			out[name] = strings.Join(ips, " ")
		}
	}
	return out
}

func natLogicalIP(rule model.NATRule) string {
	if rule.Type == model.ActionSNAT {
		return rule.MatchCIDR.String()
	}
	return rule.TargetIP.String()
}

func ovnNATType(action model.Action) ovnnb.NATType {
	switch action {
	case model.ActionSNAT:
		return ovnnb.NATTypeSNAT
	case model.ActionDNAT:
		return ovnnb.NATTypeDNAT
	case model.ActionDNATSNAT:
		return ovnnb.NATTypeDNATAndSNAT
	default:
		return ovnnb.NATType(action)
	}
}

func natRowChanged(current, desired ovnnb.NAT, nextExternalIDs map[string]string) bool {
	return current.Type != desired.Type ||
		current.ExternalIP != desired.ExternalIP ||
		current.LogicalIP != desired.LogicalIP ||
		current.ExternalPortRange != desired.ExternalPortRange ||
		!reflect.DeepEqual(current.Options, desired.Options) ||
		!stringPointerValueEqual(current.LogicalPort, pointerStringValue(desired.LogicalPort)) ||
		!stringPointerValueEqual(current.ExternalMAC, pointerStringValue(desired.ExternalMAC)) ||
		!reflect.DeepEqual(current.ExternalIDs, nextExternalIDs)
}

func preferredReferencedRow[T any](refs []string, rows []T, uuid func(T) string) int {
	for i, row := range rows {
		if containsString(refs, uuid(row)) {
			return i
		}
	}
	return 0
}

func desiredLoadBalancerRow(lb model.LoadBalancer, protocol model.Protocol, frontends []model.LoadBalancerFrontend) ovnnb.LoadBalancer {
	ovnProtocol := ovnLoadBalancerProtocol(protocol)
	return ovnnb.LoadBalancer{
		Name:            loadBalancerProtocolName(lb.VPC, lb.Name, protocol),
		Protocol:        &ovnProtocol,
		Vips:            loadBalancerVIPMap(frontends),
		Options:         loadBalancerOptionsMap(lb),
		SelectionFields: ovnLoadBalancerSelectionFields(lb.EffectiveSelectionFields()),
		ExternalIDs: map[string]string{
			"netloom_owner":            "netloom",
			"netloom_load_balancer":    lb.Name,
			"netloom_vpc":              lb.VPC,
			"netloom_protocol":         string(protocol),
			"netloom_session_affinity": fmt.Sprintf("%t", lb.SessionAffinity),
		},
	}
}

func loadBalancerVIPMap(frontends []model.LoadBalancerFrontend) map[string]string {
	out := make(map[string]string, len(frontends))
	for _, frontend := range frontends {
		out[loadBalancerFrontendVIP(frontend)] = loadBalancerFrontendBackends(frontend)
	}
	return out
}

func loadBalancerOptionsMap(lb model.LoadBalancer) map[string]string {
	out := make(map[string]string)
	if lb.SessionAffinity {
		timeout := lb.AffinityTimeout
		if timeout == 0 {
			timeout = 10800
		}
		out["affinity_timeout"] = fmt.Sprint(timeout)
	}
	return out
}

func replaceManagedLoadBalancerOptions(base, desired map[string]string) map[string]string {
	out := cloneStringMap(base)
	if out == nil {
		out = make(map[string]string)
	}
	delete(out, "affinity_timeout")
	for key, value := range desired {
		out[key] = value
	}
	return out
}

func ovnLoadBalancerProtocol(protocol model.Protocol) ovnnb.LoadBalancerProtocol {
	if protocol == "" {
		return ovnnb.LoadBalancerProtocolTCP
	}
	return ovnnb.LoadBalancerProtocol(protocol)
}

func ovnLoadBalancerSelectionFields(fields []string) []ovnnb.LoadBalancerSelectionFields {
	out := make([]ovnnb.LoadBalancerSelectionFields, 0, len(fields))
	for _, field := range fields {
		out = append(out, ovnnb.LoadBalancerSelectionFields(field))
	}
	return out
}

func desiredLoadBalancerHealthCheck(lb model.LoadBalancer, frontend model.LoadBalancerFrontend) ovnnb.LoadBalancerHealthCheck {
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
	ovnLBName := loadBalancerProtocolName(lb.VPC, lb.Name, frontend.Protocol)
	return ovnnb.LoadBalancerHealthCheck{
		Vip: loadBalancerFrontendVIP(frontend),
		Options: map[string]string{
			"interval":      fmt.Sprint(interval),
			"timeout":       fmt.Sprint(timeout),
			"success_count": fmt.Sprint(successCount),
			"failure_count": fmt.Sprint(failureCount),
		},
		ExternalIDs: map[string]string{
			"netloom_owner":             "netloom",
			"netloom_load_balancer":     lb.Name,
			"netloom_ovn_load_balancer": ovnLBName,
			"netloom_vpc":               lb.VPC,
		},
	}
}

func logicalSwitchOtherConfig(subnet model.Subnet) map[string]string {
	out := make(map[string]string)
	if subnet.CIDR.Addr().Is4() {
		out["subnet"] = subnet.CIDR.String()
		if excludeIPs := ovnExcludeIPs(subnet); excludeIPs != "" {
			out["exclude_ips"] = excludeIPs
		}
		return out
	}
	out["ipv6_prefix"] = subnet.CIDR.Masked().Addr().String()
	return out
}

func replaceLogicalSwitchIPAMConfig(base, desired map[string]string) map[string]string {
	out := cloneStringMap(base)
	if out == nil {
		out = make(map[string]string)
	}
	for _, key := range []string{"subnet", "exclude_ips", "ipv6_prefix"} {
		delete(out, key)
	}
	for key, value := range desired {
		out[key] = value
	}
	return out
}

func addDHCPDNSOptions(options map[string]string, switchExternalIDs map[string]string, family int) {
	servers := splitCSV(switchExternalIDs["netloom_dhcp_dns_servers"])
	filteredServers := make([]string, 0, len(servers))
	for _, value := range servers {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		if (family == 4 && addr.Is4()) || (family == 6 && addr.Is6()) {
			filteredServers = append(filteredServers, addr.String())
		}
	}
	if len(filteredServers) > 0 {
		options["dns_server"] = ovnStringSetValues(filteredServers)
	}
	if family == 4 {
		if domain := switchExternalIDs["netloom_dhcp_domain_name"]; domain != "" {
			options["domain_name"] = domain
		}
		if domains := splitCSV(switchExternalIDs["netloom_dhcp_search_paths"]); len(domains) > 0 {
			options["domain_search_list"] = ovnStringSetValues(domains)
		}
		return
	}
	domains := splitCSV(switchExternalIDs["netloom_dhcp_search_paths"])
	if domain := switchExternalIDs["netloom_dhcp_domain_name"]; domain != "" && !containsString(domains, domain) {
		domains = append(domains, domain)
	}
	if len(domains) > 0 {
		options["domain_search"] = strings.Join(domains, ",")
	}
}

func replaceManagedRouterPortRAConfig(base, desired map[string]string) map[string]string {
	out := cloneStringMap(base)
	if out == nil {
		out = make(map[string]string)
	}
	delete(out, "address_mode")
	for key, value := range desired {
		out[key] = value
	}
	return out
}

func equalIntPointers(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func stringPointerValueEqual(current *string, desired string) bool {
	if current == nil {
		return desired == ""
	}
	return *current == desired
}

func pointerStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func ovsdbNamedUUID(name string) string {
	replacer := strings.NewReplacer(
		"/", "_",
		":", "_",
		".", "_",
		"|", "_",
		",", "_",
		" ", "_",
		"\x00", "_",
		"-", "_h",
	)
	return ovnIdentifier(replacer.Replace(name))
}

func joinAddrs(addrs []netip.Addr) string {
	values := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		values = append(values, addr.String())
	}
	return strings.Join(values, ",")
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
