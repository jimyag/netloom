package dataplane

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"
)

type Packet struct {
	SourcePort     uint16
	RemoteIdentity uint32
	RemoteIP       netip.Addr
	Direction      uint8
	Protocol       uint8
	DestPort       uint16
	ICMPType       uint8
	ICMPCode       uint8
	Bytes          uint32
}

type Verdict string

const (
	VerdictAllow  Verdict = "allow"
	VerdictDrop   Verdict = "drop"
	VerdictReject Verdict = "reject"
)

type Decision struct {
	Verdict     Verdict
	Match       *PolicyMapEntry
	Conntrack   bool
	Established bool
}

type DropReason string

const (
	DropReasonPolicyDeny   DropReason = "policy-deny"
	DropReasonPolicyReject DropReason = "policy-reject"
	DropReasonNoMatch      DropReason = "no-policy-match"
)

type DropEvent struct {
	EndpointID     string
	Reason         DropReason
	RemoteIdentity uint32
	RemoteIP       netip.Addr
	Direction      uint8
	Protocol       uint8
	DestPort       uint16
	RuleCookie     uint32
}

type PolicyEvent struct {
	EndpointID     string
	Verdict        Verdict
	RemoteIdentity uint32
	RemoteIP       netip.Addr
	Direction      uint8
	Protocol       uint8
	DestPort       uint16
	RuleCookie     uint32
	Conntrack      bool
	Established    bool
}

type TraceEvent struct {
	EndpointID     string
	Verdict        Verdict
	RemoteIdentity uint32
	RemoteIP       netip.Addr
	Direction      uint8
	Protocol       uint8
	DestPort       uint16
	ICMPType       uint8
	ICMPCode       uint8
	RuleCookie     uint32
	Conntrack      bool
	Established    bool
	NoMatchDrop    bool
	DenyDrop       bool
	RejectDrop     bool
}

type PolicyMetrics struct {
	Allowed      uint64
	Dropped      uint64
	Conntrack    uint64
	Established  uint64
	NoMatchDrops uint64
	DenyDrops    uint64
	RejectDrops  uint64
	Logged       uint64
}

type RuleMetrics struct {
	EndpointID   string
	RuleCookie   uint32
	Packets      uint64
	Bytes        uint64
	Allowed      uint64
	Dropped      uint64
	Rejected     uint64
	NoMatchDrops uint64
	DenyDrops    uint64
	RejectDrops  uint64
	Conntrack    uint64
	Established  uint64
	Logged       uint64
}

type PolicyObserver interface {
	Observe(endpointID string, packet Packet, decision Decision)
}

type PolicyRecorder struct {
	mu      sync.Mutex
	metrics map[string]PolicyMetrics
	rules   map[string]RuleMetrics
	drops   []DropEvent
	events  []PolicyEvent
	traces  []TraceEvent
}

func NewPolicyRecorder() *PolicyRecorder {
	return &PolicyRecorder{
		metrics: make(map[string]PolicyMetrics),
		rules:   make(map[string]RuleMetrics),
	}
}

func (r *PolicyRecorder) Observe(endpointID string, packet Packet, decision Decision) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.traces = append(r.traces, traceEvent(endpointID, packet, decision))
	metrics := r.metrics[endpointID]
	ruleKey := ruleMetricsKey(endpointID, decision)
	ruleMetrics := r.rules[ruleKey]
	if ruleMetrics.EndpointID == "" {
		ruleMetrics.EndpointID = endpointID
		ruleMetrics.RuleCookie = ruleCookie(decision)
	}
	ruleMetrics.Packets++
	ruleMetrics.Bytes += observedPacketBytes(packet)
	if decision.Verdict == VerdictAllow {
		metrics.Allowed++
		ruleMetrics.Allowed++
		if decision.Conntrack {
			metrics.Conntrack++
			ruleMetrics.Conntrack++
		}
		if decision.Established {
			metrics.Established++
			ruleMetrics.Established++
		}
		if shouldLogPolicy(decision) {
			metrics.Logged++
			ruleMetrics.Logged++
			r.events = append(r.events, policyEvent(endpointID, packet, decision))
		}
		r.metrics[endpointID] = metrics
		r.rules[ruleKey] = ruleMetrics
		return
	}
	metrics.Dropped++
	ruleMetrics.Dropped++
	event := DropEvent{
		EndpointID:     endpointID,
		RemoteIdentity: packet.RemoteIdentity,
		RemoteIP:       packet.RemoteIP,
		Direction:      packet.Direction,
		Protocol:       packet.Protocol,
		DestPort:       packet.DestPort,
	}
	if decision.Match == nil {
		metrics.NoMatchDrops++
		ruleMetrics.NoMatchDrops++
		event.Reason = DropReasonNoMatch
	} else if decision.Verdict == VerdictReject {
		metrics.RejectDrops++
		ruleMetrics.Rejected++
		ruleMetrics.RejectDrops++
		event.Reason = DropReasonPolicyReject
		event.RuleCookie = decision.Match.Value.RuleCookie
	} else {
		metrics.DenyDrops++
		ruleMetrics.DenyDrops++
		event.Reason = DropReasonPolicyDeny
		event.RuleCookie = decision.Match.Value.RuleCookie
	}
	if shouldLogPolicy(decision) {
		metrics.Logged++
		ruleMetrics.Logged++
		r.events = append(r.events, policyEvent(endpointID, packet, decision))
	}
	r.metrics[endpointID] = metrics
	r.rules[ruleKey] = ruleMetrics
	r.drops = append(r.drops, event)
}

func (r *PolicyRecorder) Metrics(endpointID string) PolicyMetrics {
	if r == nil {
		return PolicyMetrics{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.metrics[endpointID]
}

func (r *PolicyRecorder) DropEvents() []DropEvent {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]DropEvent(nil), r.drops...)
}

func (r *PolicyRecorder) RuleMetrics(endpointID string) []RuleMetrics {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RuleMetrics, 0, len(r.rules))
	for _, metrics := range r.rules {
		if metrics.EndpointID != endpointID {
			continue
		}
		out = append(out, metrics)
	}
	slices.SortFunc(out, func(a, b RuleMetrics) int {
		if a.RuleCookie < b.RuleCookie {
			return -1
		}
		if a.RuleCookie > b.RuleCookie {
			return 1
		}
		return 0
	})
	return out
}

func (r *PolicyRecorder) AllRuleMetrics() []RuleMetrics {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RuleMetrics, 0, len(r.rules))
	for _, metrics := range r.rules {
		out = append(out, metrics)
	}
	slices.SortFunc(out, func(a, b RuleMetrics) int {
		if a.EndpointID < b.EndpointID {
			return -1
		}
		if a.EndpointID > b.EndpointID {
			return 1
		}
		if a.RuleCookie < b.RuleCookie {
			return -1
		}
		if a.RuleCookie > b.RuleCookie {
			return 1
		}
		return 0
	})
	return out
}

func (r *PolicyRecorder) PolicyEvents() []PolicyEvent {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]PolicyEvent(nil), r.events...)
}

func (r *PolicyRecorder) TraceEvents() []TraceEvent {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]TraceEvent(nil), r.traces...)
}

func shouldLogPolicy(decision Decision) bool {
	return decision.Match != nil && decision.Match.Value.Log != 0
}

func policyEvent(endpointID string, packet Packet, decision Decision) PolicyEvent {
	event := PolicyEvent{
		EndpointID:     endpointID,
		Verdict:        decision.Verdict,
		RemoteIdentity: packet.RemoteIdentity,
		RemoteIP:       packet.RemoteIP,
		Direction:      packet.Direction,
		Protocol:       packet.Protocol,
		DestPort:       packet.DestPort,
		Conntrack:      decision.Conntrack,
		Established:    decision.Established,
	}
	if decision.Match != nil {
		event.RuleCookie = decision.Match.Value.RuleCookie
	}
	return event
}

func traceEvent(endpointID string, packet Packet, decision Decision) TraceEvent {
	event := TraceEvent{
		EndpointID:     endpointID,
		Verdict:        decision.Verdict,
		RemoteIdentity: packet.RemoteIdentity,
		RemoteIP:       packet.RemoteIP,
		Direction:      packet.Direction,
		Protocol:       packet.Protocol,
		DestPort:       packet.DestPort,
		ICMPType:       packet.ICMPType,
		ICMPCode:       packet.ICMPCode,
		Conntrack:      decision.Conntrack,
		Established:    decision.Established,
	}
	if decision.Match != nil {
		event.RuleCookie = decision.Match.Value.RuleCookie
	}
	if decision.Verdict == VerdictDrop || decision.Verdict == VerdictReject {
		event.NoMatchDrop = decision.Match == nil
		event.RejectDrop = decision.Match != nil && decision.Verdict == VerdictReject
		event.DenyDrop = decision.Match != nil && !event.RejectDrop
	}
	return event
}

func ruleMetricsKey(endpointID string, decision Decision) string {
	return fmt.Sprintf("%s|%d", endpointID, ruleCookie(decision))
}

func ruleCookie(decision Decision) uint32 {
	if decision.Match == nil {
		return 0
	}
	return decision.Match.Value.RuleCookie
}

func observedPacketBytes(packet Packet) uint64 {
	if packet.Bytes != 0 {
		return uint64(packet.Bytes)
	}
	return 64
}

func Evaluate(entries []PolicyMapEntry, packet Packet) Decision {
	return evaluate(entries, packet)
}

func EvaluateObserved(endpointID string, entries []PolicyMapEntry, packet Packet, observer PolicyObserver) Decision {
	decision := evaluate(entries, packet)
	if observer != nil {
		observer.Observe(endpointID, packet, decision)
	}
	return decision
}

func evaluate(entries []PolicyMapEntry, packet Packet) Decision {
	if isIPv4FragmentationNeeded(packet) || isIPv6PacketTooBig(packet) || isIPv6NeighborDiscovery(packet) {
		return Decision{Verdict: VerdictAllow}
	}
	var selected *PolicyMapEntry
	for i := range entries {
		entry := &entries[i]
		if !matches(*entry, packet) {
			continue
		}
		if selected == nil || betterMatch(*entry, *selected, packet) {
			selected = entry
		}
	}
	if selected == nil {
		return Decision{Verdict: VerdictDrop}
	}
	if selected.Value.Reject != 0 {
		return Decision{Verdict: VerdictReject, Match: selected}
	}
	if selected.Value.Deny != 0 {
		return Decision{Verdict: VerdictDrop, Match: selected}
	}
	return Decision{Verdict: VerdictAllow, Match: selected}
}

type ConntrackKey struct {
	EndpointID     string
	RemoteIdentity uint32
	RemoteIP       netip.Addr
	Direction      uint8
	Protocol       uint8
	ICMPType       uint8
	ICMPCode       uint8
	SourcePort     uint16
	DestPort       uint16
}

type ConntrackStore interface {
	Has(ConntrackKey) bool
	Add(ConntrackKey)
	DeleteEndpoint(endpointID string)
	Len() int
}

const DefaultConntrackMaxIdle = 5 * time.Minute

type ConntrackEntry struct {
	LastSeen time.Time
}

type InMemoryConntrackStore struct {
	mu      sync.Mutex
	entries map[ConntrackKey]ConntrackEntry
	maxIdle time.Duration
	now     func() time.Time
}

func NewInMemoryConntrackStore() *InMemoryConntrackStore {
	return NewInMemoryConntrackStoreWithIdleTimeout(DefaultConntrackMaxIdle)
}

func NewInMemoryConntrackStoreWithIdleTimeout(maxIdle time.Duration) *InMemoryConntrackStore {
	return newInMemoryConntrackStoreWithClock(maxIdle, time.Now)
}

func newInMemoryConntrackStoreWithClock(maxIdle time.Duration, now func() time.Time) *InMemoryConntrackStore {
	if now == nil {
		now = time.Now
	}
	return &InMemoryConntrackStore{
		entries: make(map[ConntrackKey]ConntrackEntry),
		maxIdle: maxIdle,
		now:     now,
	}
}

func (s *InMemoryConntrackStore) Has(key ConntrackKey) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok {
		return false
	}
	now := s.now()
	if conntrackEntryExpired(entry, now, s.maxIdle) {
		delete(s.entries, key)
		return false
	}
	entry.LastSeen = now
	s.entries[key] = entry
	return true
}

func (s *InMemoryConntrackStore) Add(key ConntrackKey) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = ConntrackEntry{LastSeen: s.now()}
}

func (s *InMemoryConntrackStore) DeleteEndpoint(endpointID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.entries {
		if key.EndpointID == endpointID {
			delete(s.entries, key)
		}
	}
}

func (s *InMemoryConntrackStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *InMemoryConntrackStore) SweepIdle(maxIdle time.Duration) int {
	if s == nil || maxIdle <= 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	deleted := 0
	for key, entry := range s.entries {
		if conntrackEntryExpired(entry, now, maxIdle) {
			delete(s.entries, key)
			deleted++
		}
	}
	return deleted
}

func conntrackEntryExpired(entry ConntrackEntry, now time.Time, maxIdle time.Duration) bool {
	return maxIdle > 0 && !entry.LastSeen.IsZero() && now.Sub(entry.LastSeen) > maxIdle
}

func EvaluateStateful(endpointID string, entries []PolicyMapEntry, packet Packet, conntrack ConntrackStore) Decision {
	return EvaluateStatefulObserved(endpointID, entries, packet, conntrack, nil)
}

func EvaluateStatefulObserved(endpointID string, entries []PolicyMapEntry, packet Packet, conntrack ConntrackStore, observer PolicyObserver) Decision {
	decision := evaluate(entries, packet)
	if decision.Match != nil && (decision.Verdict == VerdictDrop || decision.Verdict == VerdictReject) {
		if observer != nil {
			observer.Observe(endpointID, packet, decision)
		}
		return decision
	}
	if endpointID != "" && conntrack != nil && conntrack.Has(conntrackKey(endpointID, packet)) {
		decision := Decision{Verdict: VerdictAllow, Conntrack: true}
		if observer != nil {
			observer.Observe(endpointID, packet, decision)
		}
		return decision
	}
	if decision.Verdict != VerdictAllow || decision.Match == nil || decision.Match.Value.Stateful == 0 || conntrack == nil {
		if observer != nil {
			observer.Observe(endpointID, packet, decision)
		}
		return decision
	}
	reverse := reverseConntrackKey(endpointID, packet)
	if reverse.EndpointID != "" {
		conntrack.Add(reverse)
		decision.Established = true
	}
	if observer != nil {
		observer.Observe(endpointID, packet, decision)
	}
	return decision
}

func matches(entry PolicyMapEntry, packet Packet) bool {
	key := entry.Key
	if key.Direction != packet.Direction {
		return false
	}
	if entry.RemoteCIDR.IsValid() && !remoteCIDRMatches(entry.RemoteCIDR, packet.RemoteIP) {
		return false
	}
	if key.RemoteIdentity != 0 {
		if key.RemoteIdentity != packet.RemoteIdentity && (entry.Value.RequireIdentity != 0 || !entry.RemoteCIDR.IsValid()) {
			return false
		}
	}

	l4PrefixLen := uint8(key.PrefixLen - StaticPrefixBits)
	if l4PrefixLen == 0 {
		return true
	}
	if key.Protocol != packet.Protocol {
		return false
	}
	if l4PrefixLen <= 8 {
		return true
	}

	if packet.Protocol == 1 || packet.Protocol == 58 {
		icmpPrefixLen := l4PrefixLen - 8
		if icmpPrefixLen == 0 {
			return true
		}
		packetICMP := uint16(packet.ICMPType) << 8
		if icmpPrefixLen > 8 {
			packetICMP |= uint16(packet.ICMPCode)
		}
		mask := uint16(0xffff << (16 - icmpPrefixLen))
		return networkToHost16(key.DestPortBE)&mask == packetICMP&mask
	}

	portPrefixLen := l4PrefixLen - 8
	mask := uint16(0xffff << (16 - portPrefixLen))
	return networkToHost16(key.DestPortBE)&mask == packet.DestPort&mask
}

func remoteCIDRMatches(prefix netip.Prefix, remoteIP netip.Addr) bool {
	return prefix.IsValid() && remoteIP.IsValid() && prefix.Contains(remoteIP)
}

func isIPv4FragmentationNeeded(packet Packet) bool {
	return packet.Protocol == 1 && packet.ICMPType == 3 && packet.ICMPCode == 4
}

func isIPv6PacketTooBig(packet Packet) bool {
	return packet.Protocol == 58 && packet.ICMPType == 2
}

func isIPv6NeighborDiscovery(packet Packet) bool {
	return packet.Protocol == 58 && packet.ICMPCode == 0 && packet.ICMPType >= 133 && packet.ICMPType <= 136
}

func betterMatch(candidate, selected PolicyMapEntry, packet Packet) bool {
	if candidate.Value.Precedence != selected.Value.Precedence {
		return candidate.Value.Precedence > selected.Value.Precedence
	}
	if candidate.Value.L4PrefixLen != selected.Value.L4PrefixLen {
		return candidate.Value.L4PrefixLen > selected.Value.L4PrefixLen
	}
	candidateExact := candidate.Key.RemoteIdentity != 0 && candidate.Key.RemoteIdentity == packet.RemoteIdentity
	selectedExact := selected.Key.RemoteIdentity != 0 && selected.Key.RemoteIdentity == packet.RemoteIdentity
	if candidateExact != selectedExact {
		return candidateExact
	}
	if candidateBits, selectedBits := remoteCIDRBits(candidate.RemoteCIDR), remoteCIDRBits(selected.RemoteCIDR); candidateBits != selectedBits {
		return candidateBits > selectedBits
	}
	return false
}

func remoteCIDRBits(prefix netip.Prefix) int {
	if !prefix.IsValid() {
		return -1
	}
	return prefix.Bits()
}

func networkToHost16(value uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], value)
	return binary.BigEndian.Uint16(b[:])
}

func conntrackKey(endpointID string, packet Packet) ConntrackKey {
	icmpType, icmpCode := conntrackICMP(packet.Protocol, packet.ICMPType, packet.ICMPCode)
	return ConntrackKey{
		EndpointID:     endpointID,
		RemoteIdentity: packet.RemoteIdentity,
		RemoteIP:       packet.RemoteIP,
		Direction:      packet.Direction,
		Protocol:       packet.Protocol,
		ICMPType:       icmpType,
		ICMPCode:       icmpCode,
		SourcePort:     packet.SourcePort,
		DestPort:       packet.DestPort,
	}
}

func reverseConntrackKey(endpointID string, packet Packet) ConntrackKey {
	port := packet.SourcePort
	if port == 0 {
		port = packet.DestPort
	}
	icmpType, icmpCode := reverseConntrackICMP(packet.Protocol, packet.ICMPType, packet.ICMPCode)
	return ConntrackKey{
		EndpointID:     endpointID,
		RemoteIdentity: packet.RemoteIdentity,
		RemoteIP:       packet.RemoteIP,
		Direction:      reverseDirection(packet.Direction),
		Protocol:       packet.Protocol,
		ICMPType:       icmpType,
		ICMPCode:       icmpCode,
		SourcePort:     packet.DestPort,
		DestPort:       port,
	}
}

func conntrackICMP(protocol, icmpType, icmpCode uint8) (uint8, uint8) {
	if !isICMPProtocol(protocol) {
		return 0, 0
	}
	return icmpType, icmpCode
}

func reverseConntrackICMP(protocol, icmpType, icmpCode uint8) (uint8, uint8) {
	if !isICMPProtocol(protocol) {
		return 0, 0
	}
	switch protocol {
	case 1:
		switch icmpType {
		case 8:
			return 0, icmpCode
		case 0:
			return 8, icmpCode
		}
	case 58:
		switch icmpType {
		case 128:
			return 129, icmpCode
		case 129:
			return 128, icmpCode
		}
	}
	return icmpType, icmpCode
}

func isICMPProtocol(protocol uint8) bool {
	return protocol == 1 || protocol == 58
}

func reverseDirection(direction uint8) uint8 {
	switch direction {
	case DirectionIngress:
		return DirectionEgress
	case DirectionEgress:
		return DirectionIngress
	default:
		return direction
	}
}
