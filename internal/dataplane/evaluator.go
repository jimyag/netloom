package dataplane

import "encoding/binary"

type Packet struct {
	RemoteIdentity uint32
	Direction      uint8
	Protocol       uint8
	DestPort       uint16
}

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDrop  Verdict = "drop"
)

type Decision struct {
	Verdict Verdict
	Match   *PolicyMapEntry
}

func Evaluate(entries []PolicyMapEntry, packet Packet) Decision {
	var selected *PolicyMapEntry
	for i := range entries {
		entry := &entries[i]
		if !matches(entry.Key, packet) {
			continue
		}
		if selected == nil || betterMatch(*entry, *selected) {
			selected = entry
		}
	}
	if selected == nil {
		return Decision{Verdict: VerdictDrop}
	}
	if selected.Value.Deny != 0 {
		return Decision{Verdict: VerdictDrop, Match: selected}
	}
	return Decision{Verdict: VerdictAllow, Match: selected}
}

func matches(key PolicyKey, packet Packet) bool {
	if key.Direction != packet.Direction {
		return false
	}
	if key.RemoteIdentity != 0 && key.RemoteIdentity != packet.RemoteIdentity {
		return false
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

	portPrefixLen := l4PrefixLen - 8
	mask := uint16(0xffff << (16 - portPrefixLen))
	return networkToHost16(key.DestPortBE)&mask == packet.DestPort&mask
}

func betterMatch(candidate, selected PolicyMapEntry) bool {
	if candidate.Value.Precedence != selected.Value.Precedence {
		return candidate.Value.Precedence > selected.Value.Precedence
	}
	if candidate.Value.L4PrefixLen != selected.Value.L4PrefixLen {
		return candidate.Value.L4PrefixLen > selected.Value.L4PrefixLen
	}
	if candidate.Key.RemoteIdentity != selected.Key.RemoteIdentity {
		return candidate.Key.RemoteIdentity != 0
	}
	return false
}

func networkToHost16(value uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], value)
	return binary.BigEndian.Uint16(b[:])
}
