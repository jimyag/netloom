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

	ipv4L4LookupPrefixLen = int32(64)
)

type TCXSelfTestResult struct {
	Interface string
	Direction string
	Action    int32
	Mode      string
}

type TCXAttachment struct {
	Result  TCXSelfTestResult
	aclMap  *ebpf.Map
	program *ebpf.Program
	link    link.Link
}

func (a *TCXAttachment) Close() error {
	if a == nil {
		return nil
	}
	var firstErr error
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
	Protocol  uint8
	Pad       uint8
	DestPort  uint16
	PeerIP    [4]byte
}

type IPv4L4ACLRule struct {
	Source     netip.Addr
	SourceCIDR netip.Prefix
	Protocol   uint8
	DestPort   uint16
	Action     int32
}

func NewConstantTCXProgram(action int32) (*ebpf.Program, error) {
	if action != TCXPass && action != TCXDrop {
		return nil, fmt.Errorf("unsupported tcx action %d", action)
	}
	return ebpf.NewProgram(&ebpf.ProgramSpec{
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
	verdictMap, err := ebpf.NewMap(&ebpf.MapSpec{
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
	return ebpf.NewProgram(&ebpf.ProgramSpec{
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
	aclMap, err := ebpf.NewMap(&ebpf.MapSpec{
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
	return ebpf.NewProgram(&ebpf.ProgramSpec{
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
	aclMap, err := ebpf.NewMap(ipv4L4ACLMapSpec(len(rules)))
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

func ipv4L4ACLMapSpec(ruleCount int) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       "netloom_tcx_l4",
		Type:       ebpf.LPMTrie,
		KeySize:    12,
		ValueSize:  4,
		MaxEntries: uint32(max(256, ruleCount)),
		Flags:      unix.BPF_F_NO_PREALLOC,
	}
}

func putIPv4L4ACLRule(aclMap *ebpf.Map, rule IPv4L4ACLRule) error {
	sourceCIDR, err := ruleSourceCIDR(rule)
	if err != nil {
		return err
	}
	if rule.Protocol == 0 {
		return fmt.Errorf("protocol is required")
	}
	if rule.DestPort == 0 && rule.Protocol != 1 {
		return fmt.Errorf("destination port is required")
	}
	if rule.Action != TCXPass && rule.Action != TCXDrop {
		return fmt.Errorf("unsupported tcx action %d", rule.Action)
	}
	key := IPv4L4Key{
		PrefixLen: ipv4L4PrefixLen(sourceCIDR),
		Protocol:  rule.Protocol,
		DestPort:  rule.DestPort,
		PeerIP:    ipv4L4PeerKey(sourceCIDR.Addr()),
	}
	value := uint32(rule.Action)
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

func IPv4L4ACLRulesFromProgram(program policy.Program) ([]IPv4L4ACLRule, error) {
	return IPv4L4ACLRulesFromProgramForDirection(program, model.DirectionIngress)
}

func IPv4L4ACLRulesFromProgramForDirection(program policy.Program, direction model.Direction) ([]IPv4L4ACLRule, error) {
	rules := make([]IPv4L4ACLRule, 0, len(program.Rules))
	seen := make(map[IPv4L4Key]struct{})
	if err := appendIPv4L4ACLRulesFromProgram(&rules, seen, program, direction); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("program %s has no exact IPv4 TCP/UDP L4 %s ACL rules for TCX", program.EndpointID, direction)
	}
	return rules, nil
}

func IPv4L4ACLRulesFromPrograms(programs []policy.Program) ([]IPv4L4ACLRule, error) {
	return IPv4L4ACLRulesFromProgramsForDirection(programs, model.DirectionIngress)
}

func IPv4L4ACLRulesFromProgramsForDirection(programs []policy.Program, direction model.Direction) ([]IPv4L4ACLRule, error) {
	rules := make([]IPv4L4ACLRule, 0, len(programs))
	seen := make(map[IPv4L4Key]struct{})
	for _, program := range programs {
		if err := appendIPv4L4ACLRulesFromProgram(&rules, seen, program, direction); err != nil {
			return nil, err
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("programs have no exact IPv4 TCP/UDP L4 %s ACL rules for TCX", direction)
	}
	return rules, nil
}

func appendIPv4L4ACLRulesFromProgram(rules *[]IPv4L4ACLRule, seen map[IPv4L4Key]struct{}, program policy.Program, direction model.Direction) error {
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
		sourceCIDR, ok := ipv4Prefix(rule.RemoteCIDR)
		if !ok {
			continue
		}
		action, ok := tcxAction(rule.Action)
		if !ok {
			continue
		}
		if protocol == 1 && len(rule.Ports) > 0 {
			return fmt.Errorf("rule %s: ICMP TCX ACL does not support destination ports", rule.ID)
		}
		if protocol == 1 && len(rule.Ports) == 0 {
			key := IPv4L4Key{
				PrefixLen: ipv4L4PrefixLen(sourceCIDR),
				Protocol:  protocol,
				DestPort:  0,
				PeerIP:    ipv4L4PeerKey(sourceCIDR.Addr()),
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			*rules = append(*rules, IPv4L4ACLRule{
				Source:     sourceCIDR.Addr(),
				SourceCIDR: sourceCIDR,
				Protocol:   protocol,
				DestPort:   0,
				Action:     action,
			})
			continue
		}
		for _, port := range rule.Ports {
			if err := port.Validate(); err != nil {
				return fmt.Errorf("rule %s: %w", rule.ID, err)
			}
			if port.From != port.To || port.From == 0 {
				continue
			}
			key := IPv4L4Key{
				PrefixLen: ipv4L4PrefixLen(sourceCIDR),
				Protocol:  protocol,
				DestPort:  port.From,
				PeerIP:    ipv4L4PeerKey(sourceCIDR.Addr()),
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			*rules = append(*rules, IPv4L4ACLRule{
				Source:     sourceCIDR.Addr(),
				SourceCIDR: sourceCIDR,
				Protocol:   protocol,
				DestPort:   port.From,
				Action:     action,
			})
		}
	}
	return nil
}

func ipv4L4PrefixLen(prefix netip.Prefix) uint32 {
	return uint32(32 + prefix.Bits())
}

func ipv4L4PeerKey(addr netip.Addr) [4]byte {
	return addr.As4()
}

func ipv4Prefix(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
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

func NewIPv4L4ACLTCXProgram(aclMap *ebpf.Map) (*ebpf.Program, error) {
	return NewIPv4L4ACLTCXProgramForDirection(aclMap, model.DirectionIngress)
}

func NewIPv4L4ACLTCXProgramForDirection(aclMap *ebpf.Map, direction model.Direction) (*ebpf.Program, error) {
	peerOffset, err := ipv4PeerOffset(direction)
	if err != nil {
		return nil, err
	}
	return ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:    "netloom_tcx_l4",
		Type:    ebpf.SchedCLS,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.Mov.Imm(asm.R0, ipv4L4LookupPrefixLen),
			asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
			asm.Mov.Imm(asm.R0, 0),
			asm.StoreMem(asm.RFP, -7, asm.R0, asm.Byte),
			asm.StoreMem(asm.RFP, -6, asm.R0, asm.Half),
			asm.LoadAbs(12, asm.Half),
			asm.JNE.Imm(asm.R0, 0x0800, "pass"),
			asm.LoadAbs(23, asm.Byte),
			asm.StoreMem(asm.RFP, -8, asm.R0, asm.Byte),
			asm.Mov.Reg(asm.R8, asm.R0),
			asm.LoadAbs(peerOffset, asm.Word),
			asm.HostTo(asm.BE, asm.R0, asm.Word),
			asm.StoreMem(asm.RFP, -4, asm.R0, asm.Word),
			asm.LoadAbs(20, asm.Half),
			asm.And.Imm(asm.R0, 0x1fff),
			asm.JNE.Imm(asm.R0, 0, "pass"),
			asm.LoadAbs(14, asm.Byte),
			asm.And.Imm(asm.R0, 0x0f),
			asm.LSh.Imm(asm.R0, 2),
			asm.Mov.Reg(asm.R7, asm.R0),
			asm.JEq.Imm(asm.R8, 1, "lookup"),
			asm.LoadInd(asm.R0, asm.R7, 16, asm.Half),
			asm.StoreMem(asm.RFP, -6, asm.R0, asm.Half),
			asm.LoadMapPtr(asm.R1, aclMap.FD()).WithSymbol("lookup"),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -12),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "pass"),
			asm.LoadMem(asm.R0, asm.R0, 0, asm.Word),
			asm.Return(),
			asm.Mov.Imm(asm.R0, TCXPass).WithSymbol("pass"),
			asm.Return(),
		},
	})
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

func AttachTCX(ctx context.Context, ifName string, program *ebpf.Program, attach ebpf.AttachType) (link.Link, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, err
	}
	return link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   program,
		Attach:    attach,
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
		Action:    TCXPass,
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

func AttachTCXIPv4L4ProgramsForDirection(ctx context.Context, ifName string, programs []policy.Program, attach ebpf.AttachType, direction model.Direction) (*TCXAttachment, error) {
	rules, err := IPv4L4ACLRulesFromProgramsForDirection(programs, direction)
	if err != nil {
		return nil, err
	}
	return AttachTCXIPv4L4RulesForDirection(ctx, ifName, rules, attach, direction)
}

func AttachTCXIPv4L4Rules(ctx context.Context, ifName string, rules []IPv4L4ACLRule, attach ebpf.AttachType) (*TCXAttachment, error) {
	return AttachTCXIPv4L4RulesForDirection(ctx, ifName, rules, attach, model.DirectionIngress)
}

func AttachTCXIPv4L4RulesForDirection(ctx context.Context, ifName string, rules []IPv4L4ACLRule, attach ebpf.AttachType, direction model.Direction) (*TCXAttachment, error) {
	aclMap, err := NewIPv4L4ACLMapFromRules(rules)
	if err != nil {
		return nil, err
	}

	tcxProgram, err := NewIPv4L4ACLTCXProgramForDirection(aclMap, direction)
	if err != nil {
		aclMap.Close()
		return nil, err
	}

	tcxLink, err := AttachTCX(ctx, ifName, tcxProgram, attach)
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
			Mode:      "policy-l4",
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
