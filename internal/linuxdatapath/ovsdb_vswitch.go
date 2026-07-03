package linuxdatapath

import (
	"sort"
	"strconv"
	"strings"

	"github.com/jimyag/netloom/internal/ovn/ovsdb/vswitch"
)

type ProviderOVSDBDesiredRows struct {
	OpenVSwitch vswitch.OpenvSwitch
	Bridges     []vswitch.Bridge
	Ports       []vswitch.Port
	Interfaces  []vswitch.Interface
	QoS         []vswitch.QoS
}

func desiredProviderOVSDBRows(specs []providerNetworkLinkSpec) ProviderOVSDBDesiredRows {
	bridgeByName := make(map[string]*vswitch.Bridge)
	portByName := make(map[string]vswitch.Port)
	interfaceByName := make(map[string]vswitch.Interface)
	qosByName := make(map[string]vswitch.QoS)
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
		if spec.QoS.EgressRateBPS != 0 {
			qosName := providerOVSDBQoSName(spec)
			port := portByName[spec.Name]
			port.QOS = &qosName
			portByName[spec.Name] = port
			qosByName[qosName] = vswitch.QoS{
				ExternalIDs: providerOVSDBQoSExternalIDs(spec),
				Type:        "linux-htb",
				OtherConfig: providerOVSDBQoSOtherConfig(spec),
			}
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
	out := map[string]string{
		"max-rate": strconv.FormatUint(spec.QoS.EgressRateBPS, 10),
	}
	if spec.QoS.EgressBurstBPS != 0 {
		out["burst"] = strconv.FormatUint(spec.QoS.EgressBurstBPS, 10)
	}
	return out
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
