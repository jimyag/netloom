package policy

import (
	"fmt"
	"hash/fnv"
	"math"
	"net/netip"
	"sort"

	"github.com/jimyag/netloom/internal/model"
)

type Program struct {
	EndpointID string
	MapEntries []MapEntry
	Rules      []Rule
}

type Rule struct {
	ID            string
	Priority      int
	Direction     model.Direction
	Protocol      model.Protocol
	RemoteCIDR    netip.Prefix
	RemoteGroup   string
	Ports         []model.PortRange
	Action        model.Action
	Stateful      bool
	Log           bool
	SecurityGroup string
}

type MapEntry struct {
	Key    MapKey
	Value  MapValue
	RuleID string
}

type MapKey struct {
	RemoteIdentity uint32
	Direction      model.Direction
	Protocol       model.Protocol
	DestPort       uint16
	L4PrefixBits   uint8
}

type MapValue struct {
	Deny       bool
	Precedence uint32
	Stateful   bool
	Log        bool
}

func CompileForEndpoint(endpoint model.Endpoint, groups map[string]model.SecurityGroup) (Program, error) {
	if err := endpoint.Validate(); err != nil {
		return Program{}, err
	}
	program := Program{EndpointID: endpoint.ID}
	for _, groupName := range endpoint.SecurityGroups {
		group, ok := groups[groupName]
		if !ok {
			return Program{}, fmt.Errorf("endpoint %s references unknown security group %s", endpoint.ID, groupName)
		}
		if group.VPC != endpoint.VPC {
			return Program{}, fmt.Errorf("security group %s belongs to vpc %s, endpoint %s belongs to %s", group.Name, group.VPC, endpoint.ID, endpoint.VPC)
		}
		if err := group.Validate(); err != nil {
			return Program{}, err
		}
		for _, rule := range group.Rules {
			compiledRule := Rule{
				ID:            rule.ID,
				Priority:      rule.Priority,
				Direction:     rule.Direction,
				Protocol:      rule.Protocol,
				RemoteCIDR:    rule.RemoteCIDR,
				RemoteGroup:   rule.RemoteGroup,
				Ports:         append([]model.PortRange(nil), rule.Ports...),
				Action:        rule.Action,
				Stateful:      rule.Stateful,
				Log:           rule.Log,
				SecurityGroup: group.Name,
			}
			program.Rules = append(program.Rules, compiledRule)
			entries, err := compileMapEntries(compiledRule)
			if err != nil {
				return Program{}, err
			}
			program.MapEntries = append(program.MapEntries, entries...)
		}
	}
	sort.SliceStable(program.Rules, func(i, j int) bool {
		return program.Rules[i].Priority > program.Rules[j].Priority
	})
	sort.SliceStable(program.MapEntries, func(i, j int) bool {
		if program.MapEntries[i].Value.Precedence != program.MapEntries[j].Value.Precedence {
			return program.MapEntries[i].Value.Precedence > program.MapEntries[j].Value.Precedence
		}
		return program.MapEntries[i].RuleID < program.MapEntries[j].RuleID
	})
	return program, nil
}

func compileMapEntries(rule Rule) ([]MapEntry, error) {
	portPrefixes, err := l4PortPrefixes(rule.Protocol, rule.Ports)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
	}

	entries := make([]MapEntry, 0, len(portPrefixes))
	for _, port := range portPrefixes {
		entries = append(entries, MapEntry{
			Key: MapKey{
				RemoteIdentity: remoteIdentity(rule),
				Direction:      rule.Direction,
				Protocol:       normalizedProtocol(rule.Protocol),
				DestPort:       port.port,
				L4PrefixBits:   port.l4PrefixBits,
			},
			Value: MapValue{
				Deny:       rule.Action == model.ActionDrop || rule.Action == model.ActionReject,
				Precedence: precedence(rule),
				Stateful:   rule.Stateful,
				Log:        rule.Log,
			},
			RuleID: rule.ID,
		})
	}
	return entries, nil
}

type portPrefix struct {
	port         uint16
	l4PrefixBits uint8
}

func l4PortPrefixes(protocol model.Protocol, ports []model.PortRange) ([]portPrefix, error) {
	protocol = normalizedProtocol(protocol)
	if len(ports) == 0 {
		if protocol == model.ProtocolAny {
			return []portPrefix{{port: 0, l4PrefixBits: 0}}, nil
		}
		return []portPrefix{{port: 0, l4PrefixBits: 8}}, nil
	}
	if protocol == model.ProtocolAny {
		return nil, fmt.Errorf("ports require a concrete L4 protocol")
	}

	var out []portPrefix
	for _, portRange := range ports {
		if err := portRange.Validate(); err != nil {
			return nil, err
		}
		for _, block := range splitPortRange(portRange.From, portRange.To) {
			out = append(out, portPrefix{
				port:         block.port,
				l4PrefixBits: 8 + block.prefixBits,
			})
		}
	}
	return out, nil
}

type portBlock struct {
	port       uint16
	prefixBits uint8
}

func splitPortRange(from, to uint16) []portBlock {
	var blocks []portBlock
	for current := uint32(from); current <= uint32(to); {
		size := current & -current
		if size == 0 {
			size = 1 << 16
		}
		remaining := uint32(to) - current + 1
		for size > remaining {
			size >>= 1
		}
		blocks = append(blocks, portBlock{
			port:       uint16(current),
			prefixBits: uint8(16 - log2(size)),
		})
		current += size
	}
	return blocks
}

func log2(value uint32) uint32 {
	var out uint32
	for value > 1 {
		value >>= 1
		out++
	}
	return out
}

func remoteIdentity(rule Rule) uint32 {
	switch {
	case rule.RemoteCIDR.IsValid():
		return stableIdentity("cidr:" + rule.RemoteCIDR.String())
	case rule.RemoteGroup != "":
		return stableIdentity("sg:" + rule.RemoteGroup)
	default:
		return 0
	}
}

func stableIdentity(value string) uint32 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(value))
	return 1<<31 | hash.Sum32()&0x7fffffff
}

func normalizedProtocol(protocol model.Protocol) model.Protocol {
	if protocol == "" {
		return model.ProtocolAny
	}
	return protocol
}

func l4PrefixBits(protocol model.Protocol, port uint16) uint8 {
	if protocol == "" || protocol == model.ProtocolAny {
		return 0
	}
	if port == 0 {
		return 8
	}
	return 24
}

func precedence(rule Rule) uint32 {
	if rule.Action == model.ActionDrop || rule.Action == model.ActionReject {
		return math.MaxUint32
	}
	if rule.Priority < 0 {
		return 0
	}
	return uint32(rule.Priority)
}
