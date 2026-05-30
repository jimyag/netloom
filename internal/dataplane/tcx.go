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
)

const (
	TCXPass = int32(0)
	TCXDrop = int32(2)
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
	SourceIP uint32
	Protocol uint8
	Pad      uint8
	DestPort uint16
}

type IPv4L4ACLRule struct {
	Source   netip.Addr
	Protocol uint8
	DestPort uint16
	Action   int32
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
	aclMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "netloom_tcx_l4",
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: uint32(max(256, len(rules))),
	})
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

func putIPv4L4ACLRule(aclMap *ebpf.Map, rule IPv4L4ACLRule) error {
	source := rule.Source
	if !source.Is4() {
		return fmt.Errorf("source address must be IPv4")
	}
	if rule.Protocol == 0 {
		return fmt.Errorf("protocol is required")
	}
	if rule.DestPort == 0 {
		return fmt.Errorf("destination port is required")
	}
	if rule.Action != TCXPass && rule.Action != TCXDrop {
		return fmt.Errorf("unsupported tcx action %d", rule.Action)
	}
	key := IPv4L4Key{
		SourceIP: binary.BigEndian.Uint32(source.AsSlice()),
		Protocol: rule.Protocol,
		DestPort: rule.DestPort,
	}
	value := uint32(rule.Action)
	return aclMap.Put(key, value)
}

func IPv4L4ACLRulesFromProgram(program policy.Program) ([]IPv4L4ACLRule, error) {
	rules := make([]IPv4L4ACLRule, 0, len(program.Rules))
	seen := make(map[IPv4L4Key]struct{})
	if err := appendIPv4L4ACLRulesFromProgram(&rules, seen, program); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("program %s has no exact IPv4 TCP/UDP L4 ACL rules for TCX", program.EndpointID)
	}
	return rules, nil
}

func IPv4L4ACLRulesFromPrograms(programs []policy.Program) ([]IPv4L4ACLRule, error) {
	rules := make([]IPv4L4ACLRule, 0, len(programs))
	seen := make(map[IPv4L4Key]struct{})
	for _, program := range programs {
		if err := appendIPv4L4ACLRulesFromProgram(&rules, seen, program); err != nil {
			return nil, err
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("programs have no exact IPv4 TCP/UDP L4 ACL rules for TCX")
	}
	return rules, nil
}

func appendIPv4L4ACLRulesFromProgram(rules *[]IPv4L4ACLRule, seen map[IPv4L4Key]struct{}, program policy.Program) error {
	for _, rule := range program.Rules {
		if rule.Direction != model.DirectionIngress {
			continue
		}
		protocol, err := protocolNumber(rule.Protocol)
		if err != nil {
			return fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		if protocol != 6 && protocol != 17 {
			continue
		}
		if !rule.RemoteCIDR.IsValid() {
			continue
		}
		source, ok := exactIPv4PrefixAddr(rule.RemoteCIDR)
		if !ok {
			continue
		}
		action, ok := tcxAction(rule.Action)
		if !ok {
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
				SourceIP: binary.BigEndian.Uint32(source.AsSlice()),
				Protocol: protocol,
				DestPort: port.From,
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			*rules = append(*rules, IPv4L4ACLRule{
				Source:   source,
				Protocol: protocol,
				DestPort: port.From,
				Action:   action,
			})
		}
	}
	return nil
}

func exactIPv4PrefixAddr(prefix netip.Prefix) (netip.Addr, bool) {
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() != 32 {
		return netip.Addr{}, false
	}
	return prefix.Addr(), true
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
	return ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:    "netloom_tcx_l4",
		Type:    ebpf.SchedCLS,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.LoadAbs(12, asm.Half),
			asm.JNE.Imm(asm.R0, 0x0800, "pass"),
			asm.LoadAbs(23, asm.Byte),
			asm.StoreMem(asm.RFP, -4, asm.R0, asm.Byte),
			asm.LoadAbs(26, asm.Word),
			asm.StoreMem(asm.RFP, -8, asm.R0, asm.Word),
			asm.LoadAbs(20, asm.Half),
			asm.And.Imm(asm.R0, 0x1fff),
			asm.JNE.Imm(asm.R0, 0, "pass"),
			asm.LoadAbs(14, asm.Byte),
			asm.And.Imm(asm.R0, 0x0f),
			asm.LSh.Imm(asm.R0, 2),
			asm.Mov.Reg(asm.R7, asm.R0),
			asm.LoadInd(asm.R0, asm.R7, 16, asm.Half),
			asm.StoreMem(asm.RFP, -2, asm.R0, asm.Half),
			asm.LoadMapPtr(asm.R1, aclMap.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -8),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "pass"),
			asm.LoadMem(asm.R0, asm.R0, 0, asm.Word),
			asm.Return(),
			asm.Mov.Imm(asm.R0, TCXPass).WithSymbol("pass"),
			asm.Return(),
		},
	})
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
	rules, err := IPv4L4ACLRulesFromPrograms(programs)
	if err != nil {
		return TCXSelfTestResult{}, err
	}
	return RunTCXIPv4L4RulesAttach(ctx, ifName, rules, attach, hold)
}

func RunTCXIPv4L4RulesAttach(ctx context.Context, ifName string, rules []IPv4L4ACLRule, attach ebpf.AttachType, hold time.Duration) (TCXSelfTestResult, error) {
	attachment, err := AttachTCXIPv4L4Rules(ctx, ifName, rules, attach)
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
	rules, err := IPv4L4ACLRulesFromPrograms(programs)
	if err != nil {
		return nil, err
	}
	return AttachTCXIPv4L4Rules(ctx, ifName, rules, attach)
}

func AttachTCXIPv4L4Rules(ctx context.Context, ifName string, rules []IPv4L4ACLRule, attach ebpf.AttachType) (*TCXAttachment, error) {
	aclMap, err := NewIPv4L4ACLMapFromRules(rules)
	if err != nil {
		return nil, err
	}

	tcxProgram, err := NewIPv4L4ACLTCXProgram(aclMap)
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
