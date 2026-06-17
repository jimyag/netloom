package dataplane

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
	"golang.org/x/sys/unix"
)

const (
	TCXPass = int32(0)
	TCXDrop = int32(2)

	ipv4L4LookupPrefixLen = int32(112)
	ipv6L4LookupPrefixLen = int32(304)
)

var attachTCX = link.AttachTCX
var newTCXMap = ebpf.NewMap
var newTCXProgram = ebpf.NewProgram

type TCXSelfTestResult struct {
	Interface string
	Direction string
	Action    int32
	Mode      string
}

type TCXAttachment struct {
	Result   TCXSelfTestResult
	aclMap   *ebpf.Map
	program  *ebpf.Program
	link     link.Link
	aclMaps  []*ebpf.Map
	programs []*ebpf.Program
	links    []link.Link
}

func (a *TCXAttachment) Close() error {
	if a == nil {
		return nil
	}
	var firstErr error
	for i := len(a.links) - 1; i >= 0; i-- {
		if a.links[i] == nil {
			continue
		}
		if err := a.links[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		a.links[i] = nil
	}
	for i := len(a.programs) - 1; i >= 0; i-- {
		if a.programs[i] == nil {
			continue
		}
		if err := a.programs[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		a.programs[i] = nil
	}
	for i := len(a.aclMaps) - 1; i >= 0; i-- {
		if a.aclMaps[i] == nil {
			continue
		}
		if err := a.aclMaps[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		a.aclMaps[i] = nil
	}
	if a.link != nil {
		if err := a.link.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		a.link = nil
	}
	if a.program != nil {
		if err := a.program.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		a.program = nil
	}
	if a.aclMap != nil {
		if err := a.aclMap.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		a.aclMap = nil
	}
	return firstErr
}

type IPv4L4Key struct {
	PrefixLen uint32
	LocalIP   [4]byte
	Protocol  uint8
	Pad       [3]byte
	PeerIP    [4]byte
	DestPort  uint16
	TailPad   [2]byte
}

type IPv4L4ACLRule struct {
	Local              netip.Addr
	LocalCIDR          netip.Prefix
	Source             netip.Addr
	SourceCIDR         netip.Prefix
	Protocol           uint8
	DestPort           uint16
	DestPortPrefixBits uint8
	Action             int32
	Precedence         uint32
	RuleCookie         uint32
}

type TCXL4ACLValue struct {
	Action     int32
	RuleCookie uint32
	Packets    uint64
	Bytes      uint64
}

type IPv6L4Key struct {
	PrefixLen uint32
	LocalIP   [16]byte
	Protocol  uint8
	Pad       [3]byte
	PeerIP    [16]byte
	DestPort  uint16
	TailPad   [2]byte
}

type IPv6L4ACLRule struct {
	Local              netip.Addr
	LocalCIDR          netip.Prefix
	Source             netip.Addr
	SourceCIDR         netip.Prefix
	Protocol           uint8
	DestPort           uint16
	DestPortPrefixBits uint8
	Action             int32
	Precedence         uint32
	RuleCookie         uint32
}

func NewConstantTCXProgram(action int32) (*ebpf.Program, error) {
	if action != TCXPass && action != TCXDrop {
		return nil, fmt.Errorf("unsupported tcx action %d", action)
	}
	return newTCXProgram(&ebpf.ProgramSpec{
		Name:    "netloom_tcx_const",
		Type:    ebpf.SchedCLS,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, action),
			asm.Return(),
		},
	})
}

func NewVerdictMap(action int32) (*ebpf.Map, error) {
	if action != TCXPass && action != TCXDrop {
		return nil, fmt.Errorf("unsupported tcx action %d", action)
	}
	verdictMap, err := newTCXMap(&ebpf.MapSpec{
		Name:       "netloom_tcx_verdict",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		return nil, err
	}
	key := uint32(0)
	value := uint32(action)
	if err := verdictMap.Put(key, value); err != nil {
		verdictMap.Close()
		return nil, err
	}
	return verdictMap, nil
}

func NewMapBackedTCXProgram(verdictMap *ebpf.Map) (*ebpf.Program, error) {
	return newTCXProgram(&ebpf.ProgramSpec{
		Name:    "netloom_tcx_map",
		Type:    ebpf.SchedCLS,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.StoreMem(asm.RFP, -4, asm.R0, asm.Word),
			asm.LoadMapPtr(asm.R1, verdictMap.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "pass"),
			asm.LoadMem(asm.R0, asm.R0, 0, asm.Word),
			asm.Return(),
			asm.Mov.Imm(asm.R0, TCXPass).WithSymbol("pass"),
			asm.Return(),
		},
	})
}

func NewIPv4SourceACLMap(source netip.Addr, action int32) (*ebpf.Map, error) {
	if !source.Is4() {
		return nil, fmt.Errorf("source address must be IPv4")
	}
	if action != TCXPass && action != TCXDrop {
		return nil, fmt.Errorf("unsupported tcx action %d", action)
	}
	aclMap, err := newTCXMap(&ebpf.MapSpec{
		Name:       "netloom_tcx_src4",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 256,
	})
	if err != nil {
		return nil, err
	}
	key := binary.BigEndian.Uint32(source.AsSlice())
	value := uint32(action)
	if err := aclMap.Put(key, value); err != nil {
		aclMap.Close()
		return nil, err
	}
	return aclMap, nil
}

func NewIPv4SourceACLTCXProgram(aclMap *ebpf.Map) (*ebpf.Program, error) {
	return newTCXProgram(&ebpf.ProgramSpec{
		Name:    "netloom_tcx_src4",
		Type:    ebpf.SchedCLS,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.LoadAbs(12, asm.Half),
			asm.JNE.Imm(asm.R0, 0x0800, "pass"),
			asm.LoadAbs(26, asm.Word),
			asm.StoreMem(asm.RFP, -4, asm.R0, asm.Word),
			asm.LoadMapPtr(asm.R1, aclMap.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "pass"),
			asm.LoadMem(asm.R0, asm.R0, 0, asm.Word),
			asm.Return(),
			asm.Mov.Imm(asm.R0, TCXPass).WithSymbol("pass"),
			asm.Return(),
		},
	})
}

func NewIPv4L4ACLMap(source netip.Addr, protocol uint8, destPort uint16, action int32) (*ebpf.Map, error) {
	return NewIPv4L4ACLMapFromRules([]IPv4L4ACLRule{{
		Source:   source,
		Protocol: protocol,
		DestPort: destPort,
		Action:   action,
	}})
}

func NewIPv4L4ACLMapFromRules(rules []IPv4L4ACLRule) (*ebpf.Map, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("at least one IPv4 L4 ACL rule is required")
	}
	aclMap, err := newTCXMap(ipv4L4ACLMapSpec(len(rules)))
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		if err := putIPv4L4ACLRule(aclMap, rule); err != nil {
			aclMap.Close()
			return nil, err
		}
	}
	return aclMap, nil
}

func NewIPv6L4ACLMapFromRules(rules []IPv6L4ACLRule) (*ebpf.Map, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("at least one IPv6 L4 ACL rule is required")
	}
	aclMap, err := newTCXMap(ipv6L4ACLMapSpec(len(rules)))
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		if err := putIPv6L4ACLRule(aclMap, rule); err != nil {
			aclMap.Close()
			return nil, err
		}
	}
	return aclMap, nil
}

func ipv4L4ACLMapSpec(ruleCount int) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       "netloom_tcx_l4",
		Type:       ebpf.LPMTrie,
		KeySize:    20,
		ValueSize:  uint32(binary.Size(TCXL4ACLValue{})),
		MaxEntries: uint32(max(256, ruleCount)),
		Flags:      unix.BPF_F_NO_PREALLOC,
	}
}

func ipv6L4ACLMapSpec(ruleCount int) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       "netloom_tcx_l4_v6",
		Type:       ebpf.LPMTrie,
		KeySize:    44,
		ValueSize:  uint32(binary.Size(TCXL4ACLValue{})),
		MaxEntries: uint32(max(256, ruleCount)),
		Flags:      unix.BPF_F_NO_PREALLOC,
	}
}

func putIPv4L4ACLRule(aclMap *ebpf.Map, rule IPv4L4ACLRule) error {
	localCIDR, err := ipv4LocalCIDR(rule)
	if err != nil {
		return err
	}
	sourceCIDR, err := ruleSourceCIDR(rule)
	if err != nil {
		return err
	}
	if rule.Protocol == 0 {
		return fmt.Errorf("protocol is required")
	}
	destPortPrefixBits := normalizedDestPortPrefixBits(rule)
	if rule.DestPort == 0 && rule.Protocol != 1 && destPortPrefixBits != 0 {
		return fmt.Errorf("destination port is required")
	}
	if rule.Action != TCXPass && rule.Action != TCXDrop {
		return fmt.Errorf("unsupported tcx action %d", rule.Action)
	}
	key := IPv4L4Key{
		PrefixLen: ipv4L4PrefixLen(localCIDR, sourceCIDR, destPortPrefixBits),
		LocalIP:   ipv4L4PeerKey(localCIDR.Addr()),
		Protocol:  rule.Protocol,
		DestPort:  rule.DestPort,
		PeerIP:    ipv4L4PeerKey(sourceCIDR.Addr()),
	}
	value := TCXL4ACLValue{Action: rule.Action, RuleCookie: rule.RuleCookie}
	return aclMap.Put(key, value)
}

func putIPv6L4ACLRule(aclMap *ebpf.Map, rule IPv6L4ACLRule) error {
	localCIDR, err := ipv6LocalCIDR(rule)
	if err != nil {
		return err
	}
	sourceCIDR, err := ipv6RuleSourceCIDR(rule)
	if err != nil {
		return err
	}
	if rule.Protocol == 0 {
		return fmt.Errorf("protocol is required")
	}
	destPortPrefixBits := normalizedIPv6DestPortPrefixBits(rule)
	if rule.DestPort == 0 && rule.Protocol != 58 && destPortPrefixBits != 0 {
		return fmt.Errorf("destination port is required")
	}
	if rule.Action != TCXPass && rule.Action != TCXDrop {
		return fmt.Errorf("unsupported tcx action %d", rule.Action)
	}
	key := IPv6L4Key{
		PrefixLen: ipv6L4PrefixLen(localCIDR, sourceCIDR, destPortPrefixBits),
		LocalIP:   ipv6L4PeerKey(localCIDR.Addr()),
		Protocol:  rule.Protocol,
		DestPort:  rule.DestPort,
		PeerIP:    ipv6L4PeerKey(sourceCIDR.Addr()),
	}
	value := TCXL4ACLValue{Action: rule.Action, RuleCookie: rule.RuleCookie}
	return aclMap.Put(key, value)
}

func ruleSourceCIDR(rule IPv4L4ACLRule) (netip.Prefix, error) {
	if rule.SourceCIDR.IsValid() {
		if !rule.SourceCIDR.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("source cidr must be IPv4")
		}
		return rule.SourceCIDR.Masked(), nil
	}
	if !rule.Source.Is4() {
		return netip.Prefix{}, fmt.Errorf("source address must be IPv4")
	}
	return netip.PrefixFrom(rule.Source, 32), nil
}

func ipv4LocalCIDR(rule IPv4L4ACLRule) (netip.Prefix, error) {
	if rule.LocalCIDR.IsValid() {
		if !rule.LocalCIDR.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("local cidr must be IPv4")
		}
		return rule.LocalCIDR.Masked(), nil
	}
	if !rule.Local.IsValid() {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 32), nil
	}
	if !rule.Local.Is4() {
		return netip.Prefix{}, fmt.Errorf("local address must be IPv4")
	}
	return netip.PrefixFrom(rule.Local, 32), nil
}

func ipv6RuleSourceCIDR(rule IPv6L4ACLRule) (netip.Prefix, error) {
	if rule.SourceCIDR.IsValid() {
		if !rule.SourceCIDR.Addr().Is6() || rule.SourceCIDR.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("source cidr must be IPv6")
		}
		return rule.SourceCIDR.Masked(), nil
	}
	if !rule.Source.Is6() || rule.Source.Is4() {
		return netip.Prefix{}, fmt.Errorf("source address must be IPv6")
	}
	return netip.PrefixFrom(rule.Source, 128), nil
}

func ipv6LocalCIDR(rule IPv6L4ACLRule) (netip.Prefix, error) {
	if rule.LocalCIDR.IsValid() {
		if !rule.LocalCIDR.Addr().Is6() || rule.LocalCIDR.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("local cidr must be IPv6")
		}
		return rule.LocalCIDR.Masked(), nil
	}
	if !rule.Local.IsValid() {
		return netip.PrefixFrom(netip.IPv6Unspecified(), 128), nil
	}
	if !rule.Local.Is6() || rule.Local.Is4() {
		return netip.Prefix{}, fmt.Errorf("local address must be IPv6")
	}
	return netip.PrefixFrom(rule.Local, 128), nil
}

func IPv4L4ACLRulesFromProgram(program policy.Program) ([]IPv4L4ACLRule, error) {
	return IPv4L4ACLRulesFromProgramForDirection(program, model.DirectionIngress)
}

func IPv4L4ACLRulesFromProgramForDirection(program policy.Program, direction model.Direction) ([]IPv4L4ACLRule, error) {
	rules := make([]IPv4L4ACLRule, 0, len(program.Rules))
	seen := make(map[IPv4L4Key]int32)
	if err := appendIPv4L4ACLRulesFromProgram(&rules, seen, program, direction); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("program %s has no IPv4 L4 %s ACL rules for TCX", program.EndpointID, direction)
	}
	if !hasEnforcingIPv4TCXRule(rules) {
		return nil, fmt.Errorf("program %s has no enforcing IPv4 L4 %s ACL rules for TCX", program.EndpointID, direction)
	}
	return rules, nil
}

func IPv4L4ACLRulesFromPrograms(programs []policy.Program) ([]IPv4L4ACLRule, error) {
	return IPv4L4ACLRulesFromProgramsForDirection(programs, model.DirectionIngress)
}

func IPv4L4ACLRulesFromProgramsForDirection(programs []policy.Program, direction model.Direction) ([]IPv4L4ACLRule, error) {
	rules := make([]IPv4L4ACLRule, 0, len(programs))
	seen := make(map[IPv4L4Key]int32)
	for _, program := range programs {
		if err := appendIPv4L4ACLRulesFromProgram(&rules, seen, program, direction); err != nil {
			return nil, err
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("programs have no IPv4 L4 %s ACL rules for TCX", direction)
	}
	if !hasEnforcingIPv4TCXRule(rules) {
		return nil, fmt.Errorf("programs have no enforcing IPv4 L4 %s ACL rules for TCX", direction)
	}
	return rules, nil
}

func IPv6L4ACLRulesFromProgram(program policy.Program) ([]IPv6L4ACLRule, error) {
	return IPv6L4ACLRulesFromProgramForDirection(program, model.DirectionIngress)
}

func IPv6L4ACLRulesFromProgramForDirection(program policy.Program, direction model.Direction) ([]IPv6L4ACLRule, error) {
	rules := make([]IPv6L4ACLRule, 0, len(program.Rules))
	seen := make(map[IPv6L4Key]int32)
	if err := appendIPv6L4ACLRulesFromProgram(&rules, seen, program, direction); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("program %s has no IPv6 L4 %s ACL rules for TCX", program.EndpointID, direction)
	}
	if !hasEnforcingIPv6TCXRule(rules) {
		return nil, fmt.Errorf("program %s has no enforcing IPv6 L4 %s ACL rules for TCX", program.EndpointID, direction)
	}
	return rules, nil
}

func IPv6L4ACLRulesFromPrograms(programs []policy.Program) ([]IPv6L4ACLRule, error) {
	return IPv6L4ACLRulesFromProgramsForDirection(programs, model.DirectionIngress)
}

func IPv6L4ACLRulesFromProgramsForDirection(programs []policy.Program, direction model.Direction) ([]IPv6L4ACLRule, error) {
	rules := make([]IPv6L4ACLRule, 0, len(programs))
	seen := make(map[IPv6L4Key]int32)
	for _, program := range programs {
		if err := appendIPv6L4ACLRulesFromProgram(&rules, seen, program, direction); err != nil {
			return nil, err
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("programs have no IPv6 L4 %s ACL rules for TCX", direction)
	}
	if !hasEnforcingIPv6TCXRule(rules) {
		return nil, fmt.Errorf("programs have no enforcing IPv6 L4 %s ACL rules for TCX", direction)
	}
	return rules, nil
}

func hasEnforcingIPv4TCXRule(rules []IPv4L4ACLRule) bool {
	for _, rule := range rules {
		if rule.Action == TCXDrop {
			return true
		}
	}
	return false
}

func hasEnforcingIPv6TCXRule(rules []IPv6L4ACLRule) bool {
	for _, rule := range rules {
		if rule.Action == TCXDrop {
			return true
		}
	}
	return false
}

func ValidateIPv4L4ACLProgramSupport(program policy.Program) error {
	for _, rule := range program.Rules {
		if err := validateIPv4L4ACLRuleSupport(rule); err != nil {
			return fmt.Errorf("rule %s: %w", rule.ID, err)
		}
	}
	return nil
}

func ValidateIPv6L4ACLProgramSupport(program policy.Program) error {
	for _, rule := range program.Rules {
		if err := validateIPv6L4ACLRuleSupport(rule); err != nil {
			return fmt.Errorf("rule %s: %w", rule.ID, err)
		}
	}
	return nil
}

func ValidateL4ACLProgramSupport(program policy.Program) error {
	if err := ValidateIPv4L4ACLProgramSupport(program); err != nil {
		return err
	}
	return ValidateIPv6L4ACLProgramSupport(program)
}

func appendIPv4L4ACLRulesFromProgram(rules *[]IPv4L4ACLRule, seen map[IPv4L4Key]int32, program policy.Program, direction model.Direction) error {
	localCIDR := programIPv4CIDR(program)
	for _, rule := range program.Rules {
		if rule.Direction != direction {
			continue
		}
		protocol, err := protocolNumber(rule.Protocol)
		if err != nil {
			return fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		if protocol != 1 && protocol != 6 && protocol != 17 {
			continue
		}
		if !rule.RemoteCIDR.IsValid() {
			continue
		}
		if err := validateIPv4L4ACLRuleSupport(rule); err != nil {
			return fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		action, ok := tcxAction(rule.Action)
		if !ok {
			continue
		}
		sourceCIDR, ok := ipv4Prefix(rule.RemoteCIDR)
		if !ok {
			continue
		}
		if protocol == 1 && len(rule.Ports) > 0 {
			return fmt.Errorf("rule %s: ICMP TCX ACL does not support destination ports", rule.ID)
		}
		if protocol == 1 && len(rule.Ports) == 0 {
			icmpValue, icmpPrefixBits := icmpTCXMatch(rule)
			if err := appendIPv4ProjectedRule(rules, seen, IPv4L4ACLRule{
				Local:              program.EndpointIP,
				LocalCIDR:          localCIDR,
				Source:             sourceCIDR.Addr(),
				SourceCIDR:         sourceCIDR,
				Protocol:           protocol,
				DestPort:           icmpValue,
				DestPortPrefixBits: icmpPrefixBits,
				Action:             action,
				Precedence:         tcxRulePrecedence(rule),
				RuleCookie:         stableCookie(rule.ID),
			}); err != nil {
				return fmt.Errorf("rule %s: %w", rule.ID, err)
			}
			continue
		}
		if len(rule.Ports) == 0 {
			if err := appendIPv4ProjectedRule(rules, seen, IPv4L4ACLRule{
				Local:              program.EndpointIP,
				LocalCIDR:          localCIDR,
				Source:             sourceCIDR.Addr(),
				SourceCIDR:         sourceCIDR,
				Protocol:           protocol,
				DestPort:           0,
				DestPortPrefixBits: 0,
				Action:             action,
				Precedence:         tcxRulePrecedence(rule),
				RuleCookie:         stableCookie(rule.ID),
			}); err != nil {
				return fmt.Errorf("rule %s: %w", rule.ID, err)
			}
			continue
		}
		for _, port := range rule.Ports {
			if err := port.Validate(); err != nil {
				return fmt.Errorf("rule %s: %w", rule.ID, err)
			}
			for _, block := range splitTCXPortRange(port.From, port.To) {
				if err := appendIPv4ProjectedRule(rules, seen, IPv4L4ACLRule{
					Local:              program.EndpointIP,
					LocalCIDR:          localCIDR,
					Source:             sourceCIDR.Addr(),
					SourceCIDR:         sourceCIDR,
					Protocol:           protocol,
					DestPort:           block.port,
					DestPortPrefixBits: block.prefixBits,
					Action:             action,
					Precedence:         tcxRulePrecedence(rule),
					RuleCookie:         stableCookie(rule.ID),
				}); err != nil {
					return fmt.Errorf("rule %s: %w", rule.ID, err)
				}
			}
		}
	}
	return nil
}

func appendIPv6L4ACLRulesFromProgram(rules *[]IPv6L4ACLRule, seen map[IPv6L4Key]int32, program policy.Program, direction model.Direction) error {
	localCIDR := programIPv6CIDR(program)
	for _, rule := range program.Rules {
		if rule.Direction != direction {
			continue
		}
		protocol, err := ipv6ProtocolNumber(rule.Protocol)
		if err != nil {
			return fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		if protocol != 6 && protocol != 17 && protocol != 58 {
			continue
		}
		if !rule.RemoteCIDR.IsValid() {
			continue
		}
		if err := validateIPv6L4ACLRuleSupport(rule); err != nil {
			return fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		action, ok := tcxAction(rule.Action)
		if !ok {
			continue
		}
		sourceCIDR, ok := ipv6Prefix(rule.RemoteCIDR)
		if !ok {
			continue
		}
		if protocol == 58 && len(rule.Ports) > 0 {
			return fmt.Errorf("rule %s: ICMPv6 TCX ACL does not support destination ports", rule.ID)
		}
		if protocol == 58 && len(rule.Ports) == 0 {
			icmpValue, icmpPrefixBits := icmpTCXMatch(rule)
			if err := appendIPv6ProjectedRule(rules, seen, IPv6L4ACLRule{
				Local:              program.EndpointIP,
				LocalCIDR:          localCIDR,
				Source:             sourceCIDR.Addr(),
				SourceCIDR:         sourceCIDR,
				Protocol:           protocol,
				DestPort:           icmpValue,
				DestPortPrefixBits: icmpPrefixBits,
				Action:             action,
				Precedence:         tcxRulePrecedence(rule),
				RuleCookie:         stableCookie(rule.ID),
			}); err != nil {
				return fmt.Errorf("rule %s: %w", rule.ID, err)
			}
			continue
		}
		if len(rule.Ports) == 0 {
			if err := appendIPv6ProjectedRule(rules, seen, IPv6L4ACLRule{
				Local:              program.EndpointIP,
				LocalCIDR:          localCIDR,
				Source:             sourceCIDR.Addr(),
				SourceCIDR:         sourceCIDR,
				Protocol:           protocol,
				DestPort:           0,
				DestPortPrefixBits: 0,
				Action:             action,
				Precedence:         tcxRulePrecedence(rule),
				RuleCookie:         stableCookie(rule.ID),
			}); err != nil {
				return fmt.Errorf("rule %s: %w", rule.ID, err)
			}
			continue
		}
		for _, port := range rule.Ports {
			if err := port.Validate(); err != nil {
				return fmt.Errorf("rule %s: %w", rule.ID, err)
			}
			for _, block := range splitTCXPortRange(port.From, port.To) {
				if err := appendIPv6ProjectedRule(rules, seen, IPv6L4ACLRule{
					Local:              program.EndpointIP,
					LocalCIDR:          localCIDR,
					Source:             sourceCIDR.Addr(),
					SourceCIDR:         sourceCIDR,
					Protocol:           protocol,
					DestPort:           block.port,
					DestPortPrefixBits: block.prefixBits,
					Action:             action,
					Precedence:         tcxRulePrecedence(rule),
					RuleCookie:         stableCookie(rule.ID),
				}); err != nil {
					return fmt.Errorf("rule %s: %w", rule.ID, err)
				}
			}
		}
	}
	return nil
}

func appendIPv4ProjectedRule(rules *[]IPv4L4ACLRule, seen map[IPv4L4Key]int32, candidate IPv4L4ACLRule) error {
	current := *rules
	out := current[:0]
	for i, existing := range current {
		if ipv4L4RuleKey(existing.LocalCIDR, existing.SourceCIDR, existing.Protocol, existing.DestPort, existing.DestPortPrefixBits) ==
			ipv4L4RuleKey(candidate.LocalCIDR, candidate.SourceCIDR, candidate.Protocol, candidate.DestPort, candidate.DestPortPrefixBits) &&
			existing.Precedence == candidate.Precedence && existing.Action != candidate.Action {
			return fmt.Errorf("conflicting TCX ACL actions for identical match key")
		}
		if ipv4RuleCovers(existing, candidate) && existing.Precedence >= candidate.Precedence {
			*rules = append(out, current[i:]...)
			return nil
		}
		if ipv4RuleCovers(candidate, existing) && candidate.Precedence > existing.Precedence {
			delete(seen, ipv4L4RuleKey(existing.LocalCIDR, existing.SourceCIDR, existing.Protocol, existing.DestPort, existing.DestPortPrefixBits))
			continue
		}
		out = append(out, existing)
	}
	*rules = append(out, candidate)
	seen[ipv4L4RuleKey(candidate.LocalCIDR, candidate.SourceCIDR, candidate.Protocol, candidate.DestPort, candidate.DestPortPrefixBits)] = candidate.Action
	return nil
}

func appendIPv6ProjectedRule(rules *[]IPv6L4ACLRule, seen map[IPv6L4Key]int32, candidate IPv6L4ACLRule) error {
	current := *rules
	out := current[:0]
	for i, existing := range current {
		if ipv6L4RuleKey(existing.LocalCIDR, existing.SourceCIDR, existing.Protocol, existing.DestPort, existing.DestPortPrefixBits) ==
			ipv6L4RuleKey(candidate.LocalCIDR, candidate.SourceCIDR, candidate.Protocol, candidate.DestPort, candidate.DestPortPrefixBits) &&
			existing.Precedence == candidate.Precedence && existing.Action != candidate.Action {
			return fmt.Errorf("conflicting TCX ACL actions for identical match key")
		}
		if ipv6RuleCovers(existing, candidate) && existing.Precedence >= candidate.Precedence {
			*rules = append(out, current[i:]...)
			return nil
		}
		if ipv6RuleCovers(candidate, existing) && candidate.Precedence > existing.Precedence {
			delete(seen, ipv6L4RuleKey(existing.LocalCIDR, existing.SourceCIDR, existing.Protocol, existing.DestPort, existing.DestPortPrefixBits))
			continue
		}
		out = append(out, existing)
	}
	*rules = append(out, candidate)
	seen[ipv6L4RuleKey(candidate.LocalCIDR, candidate.SourceCIDR, candidate.Protocol, candidate.DestPort, candidate.DestPortPrefixBits)] = candidate.Action
	return nil
}

func ipv4RuleCovers(candidate, selected IPv4L4ACLRule) bool {
	return prefixCovers(candidate.LocalCIDR, selected.LocalCIDR) &&
		candidate.Protocol == selected.Protocol &&
		prefixCovers(candidate.SourceCIDR, selected.SourceCIDR) &&
		portPrefixCovers(candidate.DestPort, candidate.DestPortPrefixBits, selected.DestPort, selected.DestPortPrefixBits)
}

func ipv6RuleCovers(candidate, selected IPv6L4ACLRule) bool {
	return prefixCovers(candidate.LocalCIDR, selected.LocalCIDR) &&
		candidate.Protocol == selected.Protocol &&
		prefixCovers(candidate.SourceCIDR, selected.SourceCIDR) &&
		portPrefixCovers(candidate.DestPort, candidate.DestPortPrefixBits, selected.DestPort, selected.DestPortPrefixBits)
}

func prefixCovers(candidate, selected netip.Prefix) bool {
	candidate = candidate.Masked()
	selected = selected.Masked()
	return candidate.IsValid() &&
		selected.IsValid() &&
		candidate.Addr().Is4() == selected.Addr().Is4() &&
		candidate.Bits() <= selected.Bits() &&
		candidate.Contains(selected.Addr())
}

func portPrefixCovers(candidatePort uint16, candidateBits uint8, selectedPort uint16, selectedBits uint8) bool {
	if candidateBits > selectedBits {
		return false
	}
	if candidateBits == 0 {
		return true
	}
	mask := uint16(0xffff << (16 - candidateBits))
	return candidatePort&mask == selectedPort&mask
}

func tcxRulePrecedence(rule policy.Rule) uint32 {
	tier := rule.Tier
	if tier < 0 {
		tier = 0
	}
	if tier > 1 {
		tier = 1
	}
	priority := rule.Priority
	if priority < 0 {
		priority = 0
	}
	if priority > model.SecurityGroupPriorityMax {
		priority = model.SecurityGroupPriorityMax
	}
	priorityScore := 0
	if priority != 0 {
		priorityScore = model.SecurityGroupPriorityMax - priority + 1
	}
	precedence := uint32(1-tier) << 31
	precedence |= uint32(priorityScore) << 1
	if rule.Action == model.ActionDrop || rule.Action == model.ActionReject {
		precedence |= 1
	}
	return precedence
}

func validateIPv4L4ACLRuleSupport(rule policy.Rule) error {
	protocol, err := protocolNumber(rule.Protocol)
	if err != nil {
		return err
	}
	if protocol != 1 && protocol != 6 && protocol != 17 {
		return nil
	}
	if _, ok := tcxAction(rule.Action); !ok {
		return nil
	}
	return nil
}

func validateIPv6L4ACLRuleSupport(rule policy.Rule) error {
	protocol, err := ipv6ProtocolNumber(rule.Protocol)
	if err != nil {
		return err
	}
	if protocol != 6 && protocol != 17 && protocol != 58 {
		return nil
	}
	if _, ok := tcxAction(rule.Action); !ok {
		return nil
	}
	return nil
}

func icmpTCXMatch(rule policy.Rule) (uint16, uint8) {
	if rule.ICMPType == nil {
		return 0, 0
	}
	value := uint16(*rule.ICMPType) << 8
	prefixBits := uint8(8)
	if rule.ICMPCode != nil {
		value |= uint16(*rule.ICMPCode)
		prefixBits = 16
	}
	return value, prefixBits
}

func ipv4L4RuleKey(localCIDR, sourceCIDR netip.Prefix, protocol uint8, destPort uint16, destPortPrefixBits uint8) IPv4L4Key {
	return IPv4L4Key{
		PrefixLen: ipv4L4PrefixLen(localCIDR, sourceCIDR, destPortPrefixBits),
		LocalIP:   ipv4L4PeerKey(localCIDR.Addr()),
		Protocol:  protocol,
		PeerIP:    ipv4L4PeerKey(sourceCIDR.Addr()),
		DestPort:  destPort,
	}
}

func ipv6L4RuleKey(localCIDR, sourceCIDR netip.Prefix, protocol uint8, destPort uint16, destPortPrefixBits uint8) IPv6L4Key {
	return IPv6L4Key{
		PrefixLen: ipv6L4PrefixLen(localCIDR, sourceCIDR, destPortPrefixBits),
		LocalIP:   ipv6L4PeerKey(localCIDR.Addr()),
		Protocol:  protocol,
		PeerIP:    ipv6L4PeerKey(sourceCIDR.Addr()),
		DestPort:  destPort,
	}
}

func ipv4L4PrefixLen(localPrefix, peerPrefix netip.Prefix, destPortPrefixBits uint8) uint32 {
	return uint32(localPrefix.Bits() + 32 + peerPrefix.Bits() + int(destPortPrefixBits))
}

func ipv6L4PrefixLen(localPrefix, peerPrefix netip.Prefix, destPortPrefixBits uint8) uint32 {
	return uint32(localPrefix.Bits() + 32 + peerPrefix.Bits() + int(destPortPrefixBits))
}

func normalizedDestPortPrefixBits(rule IPv4L4ACLRule) uint8 {
	if rule.DestPortPrefixBits == 0 && rule.DestPort != 0 {
		return 16
	}
	return rule.DestPortPrefixBits
}

func normalizedIPv6DestPortPrefixBits(rule IPv6L4ACLRule) uint8 {
	if rule.DestPortPrefixBits == 0 && rule.DestPort != 0 {
		return 16
	}
	return rule.DestPortPrefixBits
}

func programIPv4CIDR(program policy.Program) netip.Prefix {
	if program.EndpointIP.Is4() {
		return netip.PrefixFrom(program.EndpointIP, 32)
	}
	return netip.PrefixFrom(netip.IPv4Unspecified(), 32)
}

func programIPv6CIDR(program policy.Program) netip.Prefix {
	if program.EndpointIP.Is6() && !program.EndpointIP.Is4() {
		return netip.PrefixFrom(program.EndpointIP, 128)
	}
	return netip.PrefixFrom(netip.IPv6Unspecified(), 128)
}

func ipv4L4PeerKey(addr netip.Addr) [4]byte {
	return addr.As4()
}

func ipv6L4PeerKey(addr netip.Addr) [16]byte {
	return addr.As16()
}

func ipv4Prefix(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}

func ipv6Prefix(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4() {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}

func ipv6ProtocolNumber(protocol model.Protocol) (uint8, error) {
	if protocol == model.ProtocolICMP {
		return 58, nil
	}
	return protocolNumber(protocol)
}

func tcxAction(action model.Action) (int32, bool) {
	switch action {
	case model.ActionAllow, model.ActionLog:
		return TCXPass, true
	case model.ActionDrop, model.ActionReject:
		return TCXDrop, true
	default:
		return 0, false
	}
}

type tcxPortBlock struct {
	port       uint16
	prefixBits uint8
}

func splitTCXPortRange(from, to uint16) []tcxPortBlock {
	var blocks []tcxPortBlock
	for current := uint32(from); current <= uint32(to); {
		size := current & -current
		if size == 0 {
			size = 1 << 16
		}
		remaining := uint32(to) - current + 1
		for size > remaining {
			size >>= 1
		}
		blocks = append(blocks, tcxPortBlock{
			port:       uint16(current),
			prefixBits: uint8(16 - log2TCXPortBlock(size)),
		})
		current += size
	}
	return blocks
}

func log2TCXPortBlock(value uint32) uint32 {
	var out uint32
	for value > 1 {
		value >>= 1
		out++
	}
	return out
}

func NewIPv4L4ACLTCXProgram(aclMap *ebpf.Map) (*ebpf.Program, error) {
	return NewIPv4L4ACLTCXProgramForDirection(aclMap, model.DirectionIngress)
}

func NewIPv4L4ACLTCXProgramForDirection(aclMap *ebpf.Map, direction model.Direction) (*ebpf.Program, error) {
	peerOffset, err := ipv4PeerOffset(direction)
	if err != nil {
		return nil, err
	}
	instructions := ipv4L4ACLTCXInstructions(aclMap.FD(), peerOffset)
	return newTCXProgram(&ebpf.ProgramSpec{
		Name:         "netloom_tcx_l4",
		Type:         ebpf.SchedCLS,
		License:      "MIT",
		Instructions: instructions,
	})
}

func ipv4L4ACLTCXInstructions(aclMapFD int, peerOffset int32) asm.Instructions {
	localOffset := localOffsetForIPv4Peer(peerOffset)
	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Imm(asm.R0, ipv4L4LookupPrefixLen),
		asm.StoreMem(asm.RFP, -20, asm.R0, asm.Word),
		asm.Mov.Imm(asm.R0, 0),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -4, asm.R0, asm.Word),
		asm.LoadAbs(12, asm.Half),
		asm.JNE.Imm(asm.R0, 0x0800, "pass"),
		asm.LoadAbs(localOffset, asm.Word),
		asm.HostTo(asm.BE, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.Word),
		asm.LoadAbs(23, asm.Byte),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Byte),
		asm.Mov.Reg(asm.R8, asm.R0),
		asm.LoadAbs(peerOffset, asm.Word),
		asm.HostTo(asm.BE, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.Word),
		asm.LoadAbs(20, asm.Half),
		asm.And.Imm(asm.R0, 0x1fff),
		asm.JNE.Imm(asm.R0, 0, "pass"),
		asm.LoadAbs(14, asm.Byte),
		asm.And.Imm(asm.R0, 0x0f),
		asm.LSh.Imm(asm.R0, 2),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.JEq.Imm(asm.R8, 1, "load_icmp"),
		asm.LoadInd(asm.R0, asm.R7, 16, asm.Half),
		asm.StoreMem(asm.RFP, -4, asm.R0, asm.Half),
		asm.LoadMapPtr(asm.R1, aclMapFD).WithSymbol("lookup"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -20),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "pass"),
		asm.Mov.Reg(asm.R9, asm.R0),
	}
	instructions = append(instructions, tcxL4CounterInstructions()...)
	instructions = append(instructions,
		asm.LoadMem(asm.R0, asm.R9, 0, asm.Word),
		asm.Return(),
		asm.LoadInd(asm.R0, asm.R7, 14, asm.Half).WithSymbol("load_icmp"),
		asm.JEq.Imm(asm.R0, 0x0304, "pass"),
		asm.StoreMem(asm.RFP, -4, asm.R0, asm.Half),
		asm.Ja.Label("lookup"),
		asm.Mov.Imm(asm.R0, TCXPass).WithSymbol("pass"),
		asm.Return(),
	)
	return instructions
}

func NewIPv6L4ACLTCXProgramForDirection(aclMap *ebpf.Map, direction model.Direction) (*ebpf.Program, error) {
	peerOffset, err := ipv6PeerOffset(direction)
	if err != nil {
		return nil, err
	}
	instructions := ipv6L4ACLTCXInstructions(aclMap.FD(), peerOffset)
	return newTCXProgram(&ebpf.ProgramSpec{
		Name:         "netloom_tcx_l4_v6",
		Type:         ebpf.SchedCLS,
		License:      "MIT",
		Instructions: instructions,
	})
}

func ipv6L4ACLTCXInstructions(aclMapFD int, peerOffset int32) asm.Instructions {
	localOffset := localOffsetForIPv6Peer(peerOffset)
	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Imm(asm.R0, ipv6L4LookupPrefixLen),
		asm.StoreMem(asm.RFP, -44, asm.R0, asm.Word),
		asm.Mov.Imm(asm.R0, 0),
		asm.StoreMem(asm.RFP, -40, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -36, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -32, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -28, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -24, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -20, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -4, asm.R0, asm.Word),
		asm.LoadAbs(12, asm.Half),
		asm.JNE.Imm(asm.R0, 0x86dd, "pass"),
		asm.LoadAbs(localOffset, asm.Word),
		asm.HostTo(asm.BE, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -40, asm.R0, asm.Word),
		asm.LoadAbs(localOffset+4, asm.Word),
		asm.HostTo(asm.BE, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -36, asm.R0, asm.Word),
		asm.LoadAbs(localOffset+8, asm.Word),
		asm.HostTo(asm.BE, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -32, asm.R0, asm.Word),
		asm.LoadAbs(localOffset+12, asm.Word),
		asm.HostTo(asm.BE, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -28, asm.R0, asm.Word),
		asm.LoadAbs(20, asm.Byte),
		asm.StoreMem(asm.RFP, -24, asm.R0, asm.Byte),
		asm.Mov.Reg(asm.R8, asm.R0),
		asm.LoadAbs(peerOffset, asm.Word),
		asm.HostTo(asm.BE, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -20, asm.R0, asm.Word),
		asm.LoadAbs(peerOffset+4, asm.Word),
		asm.HostTo(asm.BE, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.Word),
		asm.LoadAbs(peerOffset+8, asm.Word),
		asm.HostTo(asm.BE, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
		asm.LoadAbs(peerOffset+12, asm.Word),
		asm.HostTo(asm.BE, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.Word),
		asm.JEq.Imm(asm.R8, 58, "load_icmpv6"),
		asm.LoadAbs(56, asm.Half),
		asm.StoreMem(asm.RFP, -4, asm.R0, asm.Half),
		asm.LoadMapPtr(asm.R1, aclMapFD).WithSymbol("lookup"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -44),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "pass"),
		asm.Mov.Reg(asm.R9, asm.R0),
	}
	instructions = append(instructions, tcxL4CounterInstructions()...)
	instructions = append(instructions,
		asm.LoadMem(asm.R0, asm.R9, 0, asm.Word),
		asm.Return(),
		asm.LoadAbs(54, asm.Half).WithSymbol("load_icmpv6"),
		asm.JEq.Imm(asm.R0, 0x0200, "pass"),
		asm.JEq.Imm(asm.R0, 0x8500, "pass"),
		asm.JEq.Imm(asm.R0, 0x8600, "pass"),
		asm.JEq.Imm(asm.R0, 0x8700, "pass"),
		asm.JEq.Imm(asm.R0, 0x8800, "pass"),
		asm.StoreMem(asm.RFP, -4, asm.R0, asm.Half),
		asm.Ja.Label("lookup"),
		asm.Mov.Imm(asm.R0, TCXPass).WithSymbol("pass"),
		asm.Return(),
	)
	return instructions
}

func tcxL4CounterInstructions() asm.Instructions {
	return asm.Instructions{
		asm.Mov.Imm(asm.R1, 1),
		asm.AddAtomic.Mem(asm.R9, asm.R1, asm.DWord, 8),
		asm.LoadMem(asm.R1, asm.R6, 0, asm.Word),
		asm.AddAtomic.Mem(asm.R9, asm.R1, asm.DWord, 16),
	}
}

func NewIPv6L4ACLTCXProgram(aclMap *ebpf.Map) (*ebpf.Program, error) {
	return NewIPv6L4ACLTCXProgramForDirection(aclMap, model.DirectionIngress)
}

func ipv4PeerOffset(direction model.Direction) (int32, error) {
	switch direction {
	case model.DirectionIngress:
		return 26, nil
	case model.DirectionEgress:
		return 30, nil
	default:
		return 0, fmt.Errorf("unsupported policy direction %q", direction)
	}
}

func localOffsetForIPv4Peer(peerOffset int32) int32 {
	if peerOffset == 26 {
		return 30
	}
	return 26
}

func ipv6PeerOffset(direction model.Direction) (int32, error) {
	switch direction {
	case model.DirectionIngress:
		return 22, nil
	case model.DirectionEgress:
		return 38, nil
	default:
		return 0, fmt.Errorf("unsupported policy direction %q", direction)
	}
}

func localOffsetForIPv6Peer(peerOffset int32) int32 {
	if peerOffset == 22 {
		return 38
	}
	return 22
}

func fillMissingIPv4LocalCIDRs(ifName string, rules []IPv4L4ACLRule) error {
	local, ok, err := interfacePrimaryAddr(ifName, false)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	localCIDR := netip.PrefixFrom(local, 32)
	for i := range rules {
		if rules[i].LocalCIDR.IsValid() && !rules[i].LocalCIDR.Addr().IsUnspecified() {
			continue
		}
		rules[i].Local = local
		rules[i].LocalCIDR = localCIDR
	}
	return nil
}

func fillMissingIPv6LocalCIDRs(ifName string, rules []IPv6L4ACLRule) error {
	local, ok, err := interfacePrimaryAddr(ifName, true)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	localCIDR := netip.PrefixFrom(local, 128)
	for i := range rules {
		if rules[i].LocalCIDR.IsValid() && !rules[i].LocalCIDR.Addr().IsUnspecified() {
			continue
		}
		rules[i].Local = local
		rules[i].LocalCIDR = localCIDR
	}
	return nil
}

func interfacePrimaryAddr(ifName string, ipv6 bool) (netip.Addr, bool, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return netip.Addr{}, false, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, false, err
	}
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil {
			continue
		}
		ip := prefix.Addr()
		if ipv6 {
			if ip.Is6() && !ip.Is4() {
				return ip, true, nil
			}
			continue
		}
		if ip.Is4() {
			return ip, true, nil
		}
	}
	return netip.Addr{}, false, nil
}

func AttachTCX(ctx context.Context, ifName string, program *ebpf.Program, attach ebpf.AttachType) (link.Link, error) {
	return AttachTCXWithAnchor(ctx, ifName, program, attach, nil)
}

func AttachTCXWithAnchor(ctx context.Context, ifName string, program *ebpf.Program, attach ebpf.AttachType, anchor link.Anchor) (link.Link, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, err
	}
	return attachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   program,
		Attach:    attach,
		Anchor:    anchor,
	})
}

func RunTCXSelfTest(ctx context.Context, ifName string) (TCXSelfTestResult, error) {
	return RunTCXVerdict(ctx, ifName, TCXPass, 0)
}

func RunTCXVerdict(ctx context.Context, ifName string, action int32, hold time.Duration) (TCXSelfTestResult, error) {
	verdictMap, err := NewVerdictMap(action)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	defer verdictMap.Close()

	program, err := NewMapBackedTCXProgram(verdictMap)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	defer program.Close()

	tcxLink, err := AttachTCX(ctx, ifName, program, ebpf.AttachTCXIngress)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	defer tcxLink.Close()
	if hold > 0 {
		timer := time.NewTimer(hold)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return TCXSelfTestResult{}, ctx.Err()
		case <-timer.C:
		}
	}

	return TCXSelfTestResult{
		Interface: ifName,
		Direction: "ingress",
		Action:    action,
		Mode:      "verdict",
	}, nil
}

func RunTCXIPv4SourceACL(ctx context.Context, ifName string, source netip.Addr, action int32, hold time.Duration) (TCXSelfTestResult, error) {
	aclMap, err := NewIPv4SourceACLMap(source, action)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	defer aclMap.Close()

	program, err := NewIPv4SourceACLTCXProgram(aclMap)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	defer program.Close()

	tcxLink, err := AttachTCX(ctx, ifName, program, ebpf.AttachTCXIngress)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	defer tcxLink.Close()
	if hold > 0 {
		timer := time.NewTimer(hold)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return TCXSelfTestResult{}, ctx.Err()
		case <-timer.C:
		}
	}

	return TCXSelfTestResult{
		Interface: ifName,
		Direction: "ingress",
		Action:    action,
		Mode:      "src4",
	}, nil
}

func RunTCXIPv4L4ACL(ctx context.Context, ifName string, source netip.Addr, protocol uint8, destPort uint16, action int32, hold time.Duration) (TCXSelfTestResult, error) {
	aclMap, err := NewIPv4L4ACLMap(source, protocol, destPort, action)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	defer aclMap.Close()

	program, err := NewIPv4L4ACLTCXProgram(aclMap)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	defer program.Close()

	tcxLink, err := AttachTCX(ctx, ifName, program, ebpf.AttachTCXIngress)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	defer tcxLink.Close()
	if hold > 0 {
		timer := time.NewTimer(hold)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return TCXSelfTestResult{}, ctx.Err()
		case <-timer.C:
		}
	}

	return TCXSelfTestResult{
		Interface: ifName,
		Direction: "ingress",
		Action:    action,
		Mode:      "l4",
	}, nil
}

func RunTCXIPv4L4Policy(ctx context.Context, ifName string, program policy.Program, hold time.Duration) (TCXSelfTestResult, error) {
	rules, err := IPv4L4ACLRulesFromProgram(program)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	return RunTCXIPv4L4Rules(ctx, ifName, rules, hold)
}

func RunTCXIPv4L4Programs(ctx context.Context, ifName string, programs []policy.Program, hold time.Duration) (TCXSelfTestResult, error) {
	rules, err := IPv4L4ACLRulesFromPrograms(programs)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	return RunTCXIPv4L4Rules(ctx, ifName, rules, hold)
}

func RunTCXIPv4L4Rules(ctx context.Context, ifName string, rules []IPv4L4ACLRule, hold time.Duration) (TCXSelfTestResult, error) {
	return RunTCXIPv4L4RulesAttach(ctx, ifName, rules, ebpf.AttachTCXIngress, hold)
}

func RunTCXIPv4L4ProgramsAttach(ctx context.Context, ifName string, programs []policy.Program, attach ebpf.AttachType, hold time.Duration) (TCXSelfTestResult, error) {
	return RunTCXIPv4L4ProgramsAttachForDirection(ctx, ifName, programs, attach, model.DirectionIngress, hold)
}

func RunTCXIPv4L4ProgramsAttachForDirection(ctx context.Context, ifName string, programs []policy.Program, attach ebpf.AttachType, direction model.Direction, hold time.Duration) (TCXSelfTestResult, error) {
	rules, err := IPv4L4ACLRulesFromProgramsForDirection(programs, direction)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	if err := fillMissingIPv4LocalCIDRs(ifName, rules); err != nil {
		return TCXSelfTestResult{}, err
	}
	return RunTCXIPv4L4RulesAttachForDirection(ctx, ifName, rules, attach, direction, hold)
}

func RunTCXIPv4L4RulesAttach(ctx context.Context, ifName string, rules []IPv4L4ACLRule, attach ebpf.AttachType, hold time.Duration) (TCXSelfTestResult, error) {
	return RunTCXIPv4L4RulesAttachForDirection(ctx, ifName, rules, attach, model.DirectionIngress, hold)
}

func RunTCXIPv4L4RulesAttachForDirection(ctx context.Context, ifName string, rules []IPv4L4ACLRule, attach ebpf.AttachType, direction model.Direction, hold time.Duration) (TCXSelfTestResult, error) {
	attachment, err := AttachTCXIPv4L4RulesForDirection(ctx, ifName, rules, attach, direction)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	defer attachment.Close()
	if hold > 0 {
		timer := time.NewTimer(hold)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return TCXSelfTestResult{}, ctx.Err()
		case <-timer.C:
		}
	}
	return attachment.Result, nil
}

func AttachTCXIPv4L4Programs(ctx context.Context, ifName string, programs []policy.Program, attach ebpf.AttachType) (*TCXAttachment, error) {
	return AttachTCXIPv4L4ProgramsForDirection(ctx, ifName, programs, attach, model.DirectionIngress)
}

func AttachTCXL4ProgramsForDirection(ctx context.Context, ifName string, programs []policy.Program, attach ebpf.AttachType, direction model.Direction) (*TCXAttachment, error) {
	v4Rules, v4Err := IPv4L4ACLRulesFromProgramsForDirection(programs, direction)
	v6Rules, v6Err := IPv6L4ACLRulesFromProgramsForDirection(programs, direction)
	if v4Err == nil {
		if err := fillMissingIPv4LocalCIDRs(ifName, v4Rules); err != nil {
			return nil, err
		}
	}
	if v6Err == nil {
		if err := fillMissingIPv6LocalCIDRs(ifName, v6Rules); err != nil {
			return nil, err
		}
	}
	switch {
	case v4Err != nil && v6Err != nil:
		return nil, fmt.Errorf("programs have no IPv4 or IPv6 L4 %s ACL rules for TCX", direction)
	case v4Err == nil && v6Err != nil:
		return AttachTCXIPv4L4RulesForDirection(ctx, ifName, v4Rules, attach, direction)
	case v4Err != nil && v6Err == nil:
		return AttachTCXIPv6L4RulesForDirection(ctx, ifName, v6Rules, attach, direction)
	default:
		return AttachTCXL4RulesForDirection(ctx, ifName, v4Rules, v6Rules, attach, direction)
	}
}

func AttachTCXIPv4L4ProgramsForDirection(ctx context.Context, ifName string, programs []policy.Program, attach ebpf.AttachType, direction model.Direction) (*TCXAttachment, error) {
	rules, err := IPv4L4ACLRulesFromProgramsForDirection(programs, direction)
	if err != nil {
		return nil, err
	}
	if err := fillMissingIPv4LocalCIDRs(ifName, rules); err != nil {
		return nil, err
	}
	return AttachTCXIPv4L4RulesForDirection(ctx, ifName, rules, attach, direction)
}

func AttachTCXIPv4L4Rules(ctx context.Context, ifName string, rules []IPv4L4ACLRule, attach ebpf.AttachType) (*TCXAttachment, error) {
	return AttachTCXIPv4L4RulesForDirection(ctx, ifName, rules, attach, model.DirectionIngress)
}

func AttachTCXIPv4L4RulesForDirection(ctx context.Context, ifName string, rules []IPv4L4ACLRule, attach ebpf.AttachType, direction model.Direction) (*TCXAttachment, error) {
	attachment, err := attachTCXIPv4L4RulesForDirection(ctx, ifName, rules, attach, direction, nil)
	if err != nil {
		return nil, err
	}
	attachment.Result.Mode = "policy-l4"
	return attachment, nil
}

func AttachTCXIPv6L4Programs(ctx context.Context, ifName string, programs []policy.Program, attach ebpf.AttachType) (*TCXAttachment, error) {
	return AttachTCXIPv6L4ProgramsForDirection(ctx, ifName, programs, attach, model.DirectionIngress)
}

func AttachTCXIPv6L4ProgramsForDirection(ctx context.Context, ifName string, programs []policy.Program, attach ebpf.AttachType, direction model.Direction) (*TCXAttachment, error) {
	rules, err := IPv6L4ACLRulesFromProgramsForDirection(programs, direction)
	if err != nil {
		return nil, err
	}
	return AttachTCXIPv6L4RulesForDirection(ctx, ifName, rules, attach, direction)
}

func AttachTCXIPv6L4Rules(ctx context.Context, ifName string, rules []IPv6L4ACLRule, attach ebpf.AttachType) (*TCXAttachment, error) {
	return AttachTCXIPv6L4RulesForDirection(ctx, ifName, rules, attach, model.DirectionIngress)
}

func AttachTCXIPv6L4RulesForDirection(ctx context.Context, ifName string, rules []IPv6L4ACLRule, attach ebpf.AttachType, direction model.Direction) (*TCXAttachment, error) {
	attachment, err := attachTCXIPv6L4RulesForDirection(ctx, ifName, rules, attach, direction, nil)
	if err != nil {
		return nil, err
	}
	attachment.Result.Mode = "policy-l4-v6"
	return attachment, nil
}

func AttachTCXL4RulesForDirection(ctx context.Context, ifName string, v4Rules []IPv4L4ACLRule, v6Rules []IPv6L4ACLRule, attach ebpf.AttachType, direction model.Direction) (*TCXAttachment, error) {
	if len(v4Rules) == 0 || len(v6Rules) == 0 {
		return nil, fmt.Errorf("both IPv4 and IPv6 L4 ACL rules are required for dual-stack TCX attach")
	}
	v4Attachment, err := attachTCXIPv4L4RulesForDirection(ctx, ifName, v4Rules, attach, direction, nil)
	if err != nil {
		return nil, err
	}
	v6Attachment, err := attachTCXIPv6L4RulesForDirection(ctx, ifName, v6Rules, attach, direction, link.Tail())
	if err != nil {
		v4Attachment.Close()
		return nil, err
	}
	attachment := &TCXAttachment{
		Result: TCXSelfTestResult{
			Interface: ifName,
			Direction: tcxDirection(attach),
			Action:    v4Rules[0].Action,
			Mode:      "policy-l4-dual",
		},
		aclMaps:  []*ebpf.Map{v4Attachment.aclMap, v6Attachment.aclMap},
		programs: []*ebpf.Program{v4Attachment.program, v6Attachment.program},
		links:    []link.Link{v4Attachment.link, v6Attachment.link},
	}
	v4Attachment.aclMap, v4Attachment.program, v4Attachment.link = nil, nil, nil
	v6Attachment.aclMap, v6Attachment.program, v6Attachment.link = nil, nil, nil
	return attachment, nil
}

func attachTCXIPv4L4RulesForDirection(ctx context.Context, ifName string, rules []IPv4L4ACLRule, attach ebpf.AttachType, direction model.Direction, anchor link.Anchor) (*TCXAttachment, error) {
	aclMap, err := NewIPv4L4ACLMapFromRules(rules)
	if err != nil {
		return nil, err
	}

	tcxProgram, err := NewIPv4L4ACLTCXProgramForDirection(aclMap, direction)
	if err != nil {
		aclMap.Close()
		return nil, err
	}

	tcxLink, err := AttachTCXWithAnchor(ctx, ifName, tcxProgram, attach, anchor)
	if err != nil {
		tcxProgram.Close()
		aclMap.Close()
		return nil, err
	}

	return &TCXAttachment{
		Result: TCXSelfTestResult{
			Interface: ifName,
			Direction: tcxDirection(attach),
			Action:    rules[0].Action,
		},
		aclMap:  aclMap,
		program: tcxProgram,
		link:    tcxLink,
	}, nil
}

func attachTCXIPv6L4RulesForDirection(ctx context.Context, ifName string, rules []IPv6L4ACLRule, attach ebpf.AttachType, direction model.Direction, anchor link.Anchor) (*TCXAttachment, error) {
	aclMap, err := NewIPv6L4ACLMapFromRules(rules)
	if err != nil {
		return nil, err
	}

	tcxProgram, err := NewIPv6L4ACLTCXProgramForDirection(aclMap, direction)
	if err != nil {
		aclMap.Close()
		return nil, err
	}

	tcxLink, err := AttachTCXWithAnchor(ctx, ifName, tcxProgram, attach, anchor)
	if err != nil {
		tcxProgram.Close()
		aclMap.Close()
		return nil, err
	}

	return &TCXAttachment{
		Result: TCXSelfTestResult{
			Interface: ifName,
			Direction: tcxDirection(attach),
			Action:    rules[0].Action,
		},
		aclMap:  aclMap,
		program: tcxProgram,
		link:    tcxLink,
	}, nil
}

func tcxDirection(attach ebpf.AttachType) string {
	switch attach {
	case ebpf.AttachTCXIngress:
		return "ingress"
	case ebpf.AttachTCXEgress:
		return "egress"
	default:
		return fmt.Sprintf("attach-%d", attach)
	}
}
