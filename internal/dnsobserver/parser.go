package dnsobserver

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jimyag/netloom/internal/model"
)

const (
	dnsTypeA     uint16 = 1
	dnsTypeCNAME uint16 = 5
	dnsTypeAAAA  uint16 = 28
	dnsClassIN   uint16 = 1
)

type rrset struct {
	ips []netip.Addr
	ttl uint32
}

func RecordsFromResponse(packet []byte, observedAt time.Time) ([]model.DNSRecord, error) {
	if len(packet) < 12 {
		return nil, fmt.Errorf("dns response too short")
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	if flags&0x8000 == 0 {
		return nil, fmt.Errorf("dns packet is not a response")
	}
	qdCount := int(binary.BigEndian.Uint16(packet[4:6]))
	anCount := int(binary.BigEndian.Uint16(packet[6:8]))
	offset := 12
	var err error
	for i := 0; i < qdCount; i++ {
		_, offset, err = readName(packet, offset)
		if err != nil {
			return nil, fmt.Errorf("read question %d name: %w", i, err)
		}
		if offset+4 > len(packet) {
			return nil, fmt.Errorf("question %d is truncated", i)
		}
		offset += 4
	}

	records := make(map[string]rrset)
	cnames := make(map[string]string)
	for i := 0; i < anCount; i++ {
		name, next, err := readName(packet, offset)
		if err != nil {
			return nil, fmt.Errorf("read answer %d name: %w", i, err)
		}
		if next+10 > len(packet) {
			return nil, fmt.Errorf("answer %d header is truncated", i)
		}
		rrType := binary.BigEndian.Uint16(packet[next : next+2])
		class := binary.BigEndian.Uint16(packet[next+2 : next+4])
		ttl := binary.BigEndian.Uint32(packet[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(packet[next+8 : next+10]))
		rdata := next + 10
		if rdata+rdLen > len(packet) {
			return nil, fmt.Errorf("answer %d rdata is truncated", i)
		}
		offset = rdata + rdLen
		if class != dnsClassIN {
			continue
		}
		name = canonicalName(name)
		switch rrType {
		case dnsTypeA:
			if rdLen != 4 {
				return nil, fmt.Errorf("answer %d A rdata length = %d", i, rdLen)
			}
			appendRecord(records, name, netip.AddrFrom4([4]byte{packet[rdata], packet[rdata+1], packet[rdata+2], packet[rdata+3]}), ttl)
		case dnsTypeAAAA:
			if rdLen != 16 {
				return nil, fmt.Errorf("answer %d AAAA rdata length = %d", i, rdLen)
			}
			var raw [16]byte
			copy(raw[:], packet[rdata:rdata+16])
			appendRecord(records, name, netip.AddrFrom16(raw), ttl)
		case dnsTypeCNAME:
			target, _, err := readName(packet, rdata)
			if err != nil {
				return nil, fmt.Errorf("read answer %d cname target: %w", i, err)
			}
			cnames[name] = canonicalName(target)
		}
	}
	for alias, target := range cnames {
		seen := map[string]struct{}{alias: {}}
		for {
			rrs, ok := records[target]
			if ok {
				for _, ip := range rrs.ips {
					appendRecord(records, alias, ip, rrs.ttl)
				}
				break
			}
			next, ok := cnames[target]
			if !ok {
				break
			}
			if _, ok := seen[next]; ok {
				break
			}
			seen[next] = struct{}{}
			target = next
		}
	}
	return dnsRecords(records, observedAt), nil
}

func readName(packet []byte, offset int) (string, int, error) {
	var labels []string
	next := offset
	jumped := false
	seen := make(map[int]struct{})
	for {
		if offset >= len(packet) {
			return "", 0, fmt.Errorf("name exceeds packet")
		}
		length := int(packet[offset])
		switch length & 0xc0 {
		case 0xc0:
			if offset+1 >= len(packet) {
				return "", 0, fmt.Errorf("compressed pointer is truncated")
			}
			ptr := ((length & 0x3f) << 8) | int(packet[offset+1])
			if ptr >= len(packet) {
				return "", 0, fmt.Errorf("compressed pointer exceeds packet")
			}
			if _, ok := seen[ptr]; ok {
				return "", 0, fmt.Errorf("compressed pointer loop")
			}
			seen[ptr] = struct{}{}
			if !jumped {
				next = offset + 2
				jumped = true
			}
			offset = ptr
		case 0:
			if length == 0 {
				if !jumped {
					next = offset + 1
				}
				return strings.Join(labels, "."), next, nil
			}
			if offset+1+length > len(packet) {
				return "", 0, fmt.Errorf("label exceeds packet")
			}
			labels = append(labels, string(packet[offset+1:offset+1+length]))
			offset += 1 + length
		default:
			return "", 0, fmt.Errorf("unsupported label pointer bits")
		}
	}
}

func appendRecord(records map[string]rrset, name string, ip netip.Addr, ttl uint32) {
	set := records[name]
	for _, existing := range set.ips {
		if existing == ip {
			return
		}
	}
	set.ips = append(set.ips, ip)
	if set.ttl == 0 || (ttl != 0 && ttl < set.ttl) {
		set.ttl = ttl
	}
	records[name] = set
}

func dnsRecords(records map[string]rrset, observedAt time.Time) []model.DNSRecord {
	names := make([]string, 0, len(records))
	for name, set := range records {
		if len(set.ips) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	out := make([]model.DNSRecord, 0, len(names))
	for _, name := range names {
		set := records[name]
		sort.SliceStable(set.ips, func(i, j int) bool {
			return set.ips[i].String() < set.ips[j].String()
		})
		record := model.DNSRecord{Name: name, IPs: set.ips}
		if set.ttl > 0 {
			record.TTLSeconds = set.ttl
			record.ObservedAt = observedAt
		}
		out = append(out, record)
	}
	return out
}

func canonicalName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}
