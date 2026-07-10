package linuxdatapath

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/vswitch"
)

type ProviderOVSDBDesiredRows struct {
	OpenVSwitch vswitch.OpenvSwitch
	Bridges     []vswitch.Bridge
	Controllers []vswitch.Controller
	Ports       []vswitch.Port
	Interfaces  []vswitch.Interface
	QoS         []vswitch.QoS
	Queues      []vswitch.Queue
}

func desiredProviderOVSDBRows(specs []providerNetworkLinkSpec) ProviderOVSDBDesiredRows {
	return desiredProviderOVSDBRowsForIdentityGroups(specs, nil, nil)
}

func desiredProviderOVSDBRowsForIdentityGroups(specs []providerNetworkLinkSpec, identityGroups []model.IdentityGroup, endpoints []model.Endpoint) ProviderOVSDBDesiredRows {
	bridgeByName := make(map[string]*vswitch.Bridge)
	controllerByName := make(map[string]vswitch.Controller)
	portByName := make(map[string]vswitch.Port)
	interfaceByName := make(map[string]vswitch.Interface)
	qosByName := make(map[string]vswitch.QoS)
	queueByName := make(map[string]vswitch.Queue)
	mappingSet := make(map[string]struct{})

	for _, spec := range specs {
		bridgeName := providerNetworkBridgeName(spec.ProviderNetwork)
		mappingSet[spec.ProviderNetwork+":"+bridgeName] = struct{}{}

		bridge, ok := bridgeByName[bridgeName]
		if !ok {
			bridge = &vswitch.Bridge{
				Name: bridgeName,
				ExternalIDs: map[string]string{
					"netloom_owner":            "netloom",
					"netloom_provider_network": spec.ProviderNetwork,
				},
			}
			if spec.Isolation != "" {
				bridge.ExternalIDs["netloom_provider_isolation"] = spec.Isolation
			}
			bridgeByName[bridgeName] = bridge
		}
		bridge.Ports = appendUniqueString(bridge.Ports, spec.Name)
		for _, target := range spec.ControllerTargets {
			controllerName := providerOVSDBControllerName(spec.ProviderNetwork, target)
			bridge.Controller = appendUniqueString(bridge.Controller, controllerName)
			controllerByName[controllerName] = vswitch.Controller{
				Target: target,
				ExternalIDs: map[string]string{
					"netloom_owner":               "netloom",
					"netloom_provider_network":    spec.ProviderNetwork,
					"netloom_provider_controller": controllerName,
				},
			}
		}

		portByName[spec.Name] = vswitch.Port{
			Name:        spec.Name,
			Interfaces:  []string{spec.Name},
			ExternalIDs: providerOVSDBLinkExternalIDs(spec),
		}
		if spec.QoS.EgressRateBPS != 0 || len(spec.TenantQueues) > 0 {
			qosName := providerOVSDBQoSName(spec)
			port := portByName[spec.Name]
			port.QOS = &qosName
			portByName[spec.Name] = port
			qos := vswitch.QoS{
				ExternalIDs: providerOVSDBQoSExternalIDs(spec),
				Type:        "linux-htb",
				OtherConfig: providerOVSDBQoSOtherConfig(spec),
			}
			if len(spec.TenantQueues) > 0 {
				qos.Queues = make(map[int]string, len(spec.TenantQueues))
				for _, policy := range spec.TenantQueues {
					queueName := providerOVSDBQueueName(spec, policy)
					qos.Queues[policy.QueueID] = queueName
					queueByName[queueName] = vswitch.Queue{
						ExternalIDs: providerOVSDBQueueExternalIDs(spec, policy),
						OtherConfig: providerOVSDBQueueOtherConfig(policy),
					}
				}
			}
			qosByName[qosName] = qos
		}
		interfaceByName[spec.Name] = vswitch.Interface{
			Name:        spec.Name,
			ExternalIDs: providerOVSDBLinkExternalIDs(spec),
		}
	}

	bridges := make([]vswitch.Bridge, 0, len(bridgeByName))
	bridgeNames := make([]string, 0, len(bridgeByName))
	for name := range bridgeByName {
		bridgeNames = append(bridgeNames, name)
	}
	sort.Strings(bridgeNames)
	for _, name := range bridgeNames {
		bridge := *bridgeByName[name]
		sort.Strings(bridge.Ports)
		sort.Strings(bridge.Controller)
		bridges = append(bridges, bridge)
	}

	controllerNames := make([]string, 0, len(controllerByName))
	for name := range controllerByName {
		controllerNames = append(controllerNames, name)
	}
	sort.Strings(controllerNames)
	controllers := make([]vswitch.Controller, 0, len(controllerNames))
	for _, name := range controllerNames {
		controllers = append(controllers, controllerByName[name])
	}

	portNames := make([]string, 0, len(portByName))
	for name := range portByName {
		portNames = append(portNames, name)
	}
	sort.Strings(portNames)
	ports := make([]vswitch.Port, 0, len(portNames))
	interfaces := make([]vswitch.Interface, 0, len(portNames))
	for _, name := range portNames {
		ports = append(ports, portByName[name])
		interfaces = append(interfaces, interfaceByName[name])
	}
	qosNames := make([]string, 0, len(qosByName))
	for name := range qosByName {
		qosNames = append(qosNames, name)
	}
	sort.Strings(qosNames)
	qosRows := make([]vswitch.QoS, 0, len(qosNames))
	for _, name := range qosNames {
		qosRows = append(qosRows, qosByName[name])
	}
	queueNames := make([]string, 0, len(queueByName))
	for name := range queueByName {
		queueNames = append(queueNames, name)
	}
	sort.Strings(queueNames)
	queueRows := make([]vswitch.Queue, 0, len(queueNames))
	for _, name := range queueNames {
		queueRows = append(queueRows, queueByName[name])
	}

	mappings := make([]string, 0, len(mappingSet))
	for mapping := range mappingSet {
		mappings = append(mappings, mapping)
	}
	sort.Strings(mappings)

	rootExternalIDs := map[string]string{
		"netloom_owner":           "netloom",
		"ovn-bridge-mappings":     strings.Join(mappings, ","),
		"netloom_identity_groups": providerOVSDBIdentityGroupsSnapshot(identityGroups, endpoints),
	}

	return ProviderOVSDBDesiredRows{
		OpenVSwitch: vswitch.OpenvSwitch{
			Bridges:     bridgeNames,
			ExternalIDs: rootExternalIDs,
		},
		Bridges:     bridges,
		Controllers: controllers,
		Ports:       ports,
		Interfaces:  interfaces,
		QoS:         qosRows,
		Queues:      queueRows,
	}
}

type providerOVSDBIdentityGroupsSnapshotDoc struct {
	Version int                               `json:"version"`
	Groups  []providerOVSDBIdentityGroupState `json:"groups"`
}

type providerOVSDBIdentityGroupState struct {
	VPC                 string                     `json:"vpc"`
	Name                string                     `json:"name"`
	Source              string                     `json:"source,omitempty"`
	ObservedAt          string                     `json:"observed_at,omitempty"`
	TTLSeconds          uint32                     `json:"ttl_seconds,omitempty"`
	ExpiresAt           string                     `json:"expires_at,omitempty"`
	EndpointIDs         []string                   `json:"endpoint_ids,omitempty"`
	EndpointSelector    model.Labels               `json:"endpoint_selector,omitempty"`
	EndpointExpressions []model.LabelExpr          `json:"endpoint_expressions,omitempty"`
	ResolvedEndpoints   []providerOVSDBEndpointRef `json:"resolved_endpoints,omitempty"`
}

type providerOVSDBEndpointRef struct {
	ID     string `json:"id"`
	Subnet string `json:"subnet,omitempty"`
	IP     string `json:"ip,omitempty"`
	Node   string `json:"node,omitempty"`
}

func providerOVSDBIdentityGroupsSnapshot(groups []model.IdentityGroup, endpoints []model.Endpoint) string {
	if len(groups) == 0 {
		return ""
	}
	out := providerOVSDBIdentityGroupsSnapshotDoc{
		Version: 1,
		Groups:  make([]providerOVSDBIdentityGroupState, 0, len(groups)),
	}
	for _, group := range groups {
		state := providerOVSDBIdentityGroupState{
			VPC:                 group.VPC,
			Name:                group.Name,
			Source:              group.Source,
			TTLSeconds:          group.TTLSeconds,
			EndpointIDs:         append([]string(nil), group.EndpointIDs...),
			EndpointSelector:    cloneLabels(group.EndpointSelector),
			EndpointExpressions: append([]model.LabelExpr(nil), group.EndpointExpressions...),
			ResolvedEndpoints:   providerOVSDBIdentityGroupEndpoints(group, endpoints),
		}
		sort.Strings(state.EndpointIDs)
		if !group.ObservedAt.IsZero() {
			state.ObservedAt = group.ObservedAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		if expiresAt := group.ExpiresAt(); !expiresAt.IsZero() {
			state.ExpiresAt = expiresAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		out.Groups = append(out.Groups, state)
	}
	sort.Slice(out.Groups, func(i, j int) bool {
		if out.Groups[i].VPC != out.Groups[j].VPC {
			return out.Groups[i].VPC < out.Groups[j].VPC
		}
		return out.Groups[i].Name < out.Groups[j].Name
	})
	data, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(data)
}

func providerOVSDBIdentityGroupEndpoints(group model.IdentityGroup, endpoints []model.Endpoint) []providerOVSDBEndpointRef {
	refs := make([]providerOVSDBEndpointRef, 0)
	for _, endpoint := range endpoints {
		if !providerQueueEndpointMatchesIdentityGroup(group, endpoint) {
			continue
		}
		ref := providerOVSDBEndpointRef{
			ID:     endpoint.ID,
			Subnet: endpoint.Subnet,
			Node:   endpoint.Node,
		}
		if endpoint.IP.IsValid() {
			ref.IP = endpoint.IP.String()
		}
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].ID != refs[j].ID {
			return refs[i].ID < refs[j].ID
		}
		return refs[i].IP < refs[j].IP
	})
	return refs
}

func cloneLabels(labels model.Labels) model.Labels {
	if len(labels) == 0 {
		return nil
	}
	out := make(model.Labels, len(labels))
	for key, value := range labels {
		out[key] = value
	}
	return out
}

func providerOVSDBControllerName(providerNetwork, target string) string {
	sum := sha256.Sum256([]byte(providerNetwork + "\x00" + target))
	return "controller-" + sanitizeProviderOVSDBName(providerNetwork) + "-" + hex.EncodeToString(sum[:8])
}

func providerOVSDBQoSName(spec providerNetworkLinkSpec) string {
	return "qos-" + spec.Name
}

func providerOVSDBQoSExternalIDs(spec providerNetworkLinkSpec) map[string]string {
	ids := providerOVSDBLinkExternalIDs(spec)
	ids["netloom_provider_qos"] = providerOVSDBQoSName(spec)
	return ids
}

func providerOVSDBQoSOtherConfig(spec providerNetworkLinkSpec) map[string]string {
	out := make(map[string]string, 2)
	if spec.QoS.EgressRateBPS != 0 {
		out["max-rate"] = strconv.FormatUint(spec.QoS.EgressRateBPS, 10)
	}
	if spec.QoS.EgressBurstBPS != 0 {
		out["burst"] = strconv.FormatUint(spec.QoS.EgressBurstBPS, 10)
	}
	return out
}

func providerOVSDBQueueName(spec providerNetworkLinkSpec, policy model.ProviderNetworkTenantQueuePolicy) string {
	return "queue-" + spec.Name + "-" + strconv.Itoa(policy.QueueID)
}

func providerOVSDBQueueExternalIDs(spec providerNetworkLinkSpec, policy model.ProviderNetworkTenantQueuePolicy) map[string]string {
	ids := providerOVSDBLinkExternalIDs(spec)
	ids["netloom_provider_qos"] = providerOVSDBQoSName(spec)
	ids["netloom_provider_queue"] = providerOVSDBQueueName(spec, policy)
	ids["netloom_tenant"] = policy.Tenant
	ids["netloom_queue_id"] = strconv.Itoa(policy.QueueID)
	if policy.Protocol != "" {
		ids["netloom_queue_protocol"] = string(policy.Protocol)
	}
	if len(policy.Ports) > 0 {
		ids["netloom_queue_ports"] = providerOVSDBQueuePorts(policy.Ports)
	}
	if selector := providerOVSDBQueueLabels(policy.EndpointSelector); selector != "" {
		ids["netloom_queue_endpoint_selector"] = selector
	}
	if expressions := providerOVSDBQueueExpressions(policy.EndpointExpressions); expressions != "" {
		ids["netloom_queue_endpoint_expressions"] = expressions
	}
	if len(policy.IdentityGroups) > 0 {
		groups := append([]string(nil), policy.IdentityGroups...)
		sort.Strings(groups)
		ids["netloom_queue_identity_groups"] = strings.Join(groups, ",")
	}
	if selector := providerOVSDBQueueLabels(policy.IdentitySelector); selector != "" {
		ids["netloom_queue_identity_selector"] = selector
	}
	if expressions := providerOVSDBQueueExpressions(policy.IdentityExpressions); expressions != "" {
		ids["netloom_queue_identity_expressions"] = expressions
	}
	return ids
}

func providerOVSDBQueueOtherConfig(policy model.ProviderNetworkTenantQueuePolicy) map[string]string {
	out := make(map[string]string, 3)
	if policy.MinRateBPS != 0 {
		out["min-rate"] = strconv.FormatUint(policy.MinRateBPS, 10)
	}
	if policy.MaxRateBPS != 0 {
		out["max-rate"] = strconv.FormatUint(policy.MaxRateBPS, 10)
	}
	if policy.BurstBPS != 0 {
		out["burst"] = strconv.FormatUint(policy.BurstBPS, 10)
	}
	return out
}

func providerOVSDBQueuePorts(ports []model.PortRange) string {
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		if port.From == port.To {
			parts = append(parts, strconv.Itoa(int(port.From)))
			continue
		}
		parts = append(parts, strconv.Itoa(int(port.From))+"-"+strconv.Itoa(int(port.To)))
	}
	return strings.Join(parts, ",")
}

func providerOVSDBQueueLabels(labels model.Labels) string {
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
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, ",")
}

func providerOVSDBQueueExpressions(expressions []model.LabelExpr) string {
	if len(expressions) == 0 {
		return ""
	}
	parts := make([]string, 0, len(expressions))
	for _, expression := range expressions {
		values := append([]string(nil), expression.Values...)
		sort.Strings(values)
		parts = append(parts, expression.Key+":"+normalizeProviderQueueExpressionOperator(expression.Operator)+":"+strings.Join(values, ","))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func normalizeProviderQueueExpressionOperator(operator string) string {
	operator = strings.ToLower(strings.TrimSpace(operator))
	operator = strings.ReplaceAll(operator, "_", "")
	operator = strings.ReplaceAll(operator, "-", "")
	return operator
}

func sanitizeProviderOVSDBName(value string) string {
	replacer := strings.NewReplacer("/", "_", ":", "_", ".", "_", ",", "_", " ", "_")
	return replacer.Replace(value)
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
