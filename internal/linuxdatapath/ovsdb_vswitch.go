package linuxdatapath

import (
	"sort"
	"strings"

	"github.com/jimyag/netloom/internal/ovn/ovsdb/vswitch"
)

type ProviderOVSDBDesiredRows struct {
	OpenVSwitch vswitch.OpenvSwitch
	Bridges     []vswitch.Bridge
	Ports       []vswitch.Port
	Interfaces  []vswitch.Interface
}

func desiredProviderOVSDBRows(specs []providerNetworkLinkSpec) ProviderOVSDBDesiredRows {
	bridgeByName := make(map[string]*vswitch.Bridge)
	portByName := make(map[string]vswitch.Port)
	interfaceByName := make(map[string]vswitch.Interface)
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
			bridgeByName[bridgeName] = bridge
		}
		bridge.Ports = appendUniqueString(bridge.Ports, spec.Name)

		portByName[spec.Name] = vswitch.Port{
			Name:        spec.Name,
			Interfaces:  []string{spec.Name},
			ExternalIDs: providerOVSDBLinkExternalIDs(spec),
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
	}
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
