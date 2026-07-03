package linuxdatapath

import (
	"sort"
	"strconv"
	"strings"

	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/vswitch"
)

type ProviderOVSDBDesiredRows struct {
	OpenVSwitch vswitch.OpenvSwitch
	Bridges     []vswitch.Bridge
	Ports       []vswitch.Port
	Interfaces  []vswitch.Interface
	QoS         []vswitch.QoS
	Queues      []vswitch.Queue
}

func desiredProviderOVSDBRows(specs []providerNetworkLinkSpec) ProviderOVSDBDesiredRows {
	bridgeByName := make(map[string]*vswitch.Bridge)
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
		bridges = append(bridges, bridge)
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

	return ProviderOVSDBDesiredRows{
		OpenVSwitch: vswitch.OpenvSwitch{
			Bridges: bridgeNames,
			ExternalIDs: map[string]string{
				"netloom_owner":       "netloom",
				"ovn-bridge-mappings": strings.Join(mappings, ","),
			},
		},
		Bridges:    bridges,
		Ports:      ports,
		Interfaces: interfaces,
		QoS:        qosRows,
		Queues:     queueRows,
	}
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

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
