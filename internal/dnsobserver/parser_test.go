package dnsobserver

import (
	"net/netip"
	"testing"
	"time"
)

func TestRecordsFromResponseParsesCompressedAAndAAAAAnswers(t *testing.T) {
	observedAt := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	packet := dnsResponse(
		dnsQuestion("api.example.com", dnsTypeA),
		dnsAnswerPtr(12, dnsTypeA, 60, []byte{203, 0, 113, 10}),
		dnsAnswerPtr(12, dnsTypeAAAA, 120, netip.MustParseAddr("2001:db8::10").AsSlice()),
	)

	records, err := RecordsFromResponse(packet, observedAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1: %+v", len(records), records)
	}
	record := records[0]
	if record.Name != "api.example.com" {
		t.Fatalf("name = %s", record.Name)
	}
	if record.TTLSeconds != 60 || !record.ObservedAt.Equal(observedAt) {
		t.Fatalf("ttl/observed_at = %d/%s", record.TTLSeconds, record.ObservedAt)
	}
	if len(record.IPs) != 2 || record.IPs[0] != netip.MustParseAddr("2001:db8::10") || record.IPs[1] != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("ips = %+v", record.IPs)
	}
}

func TestRecordsFromResponseProjectsCNAMEAnswersToAlias(t *testing.T) {
	packet := dnsResponse(
		dnsQuestion("api.example.com", dnsTypeA),
		dnsAnswerPtr(12, dnsTypeCNAME, 60, dnsName("service.example.com")),
		dnsAnswerName("service.example.com", dnsTypeA, 60, []byte{203, 0, 113, 20}),
	)

	records, err := RecordsFromResponse(packet, time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want alias and canonical records: %+v", len(records), records)
	}
	if records[0].Name != "api.example.com" || records[0].IPs[0] != netip.MustParseAddr("203.0.113.20") {
		t.Fatalf("alias record = %+v", records[0])
	}
	if records[1].Name != "service.example.com" || records[1].IPs[0] != netip.MustParseAddr("203.0.113.20") {
		t.Fatalf("canonical record = %+v", records[1])
	}
}

func TestRecordsFromResponseParsesAdditionalAddressRecords(t *testing.T) {
	observedAt := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	packet := dnsResponseWithSections(
		dnsQuestion("api.example.com", dnsTypeA),
		[][]byte{
			dnsAnswerPtr(12, dnsTypeCNAME, 60, dnsName("service.example.com")),
		},
		nil,
		[][]byte{
			dnsAnswerName("service.example.com", dnsTypeA, 45, []byte{203, 0, 113, 20}),
			dnsAnswerName("service.example.com", dnsTypeAAAA, 30, netip.MustParseAddr("2001:db8::20").AsSlice()),
		},
	)

	records, err := RecordsFromResponse(packet, observedAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want alias and canonical records: %+v", len(records), records)
	}
	if records[0].Name != "api.example.com" || records[0].TTLSeconds != 30 || len(records[0].IPs) != 2 {
		t.Fatalf("alias record = %+v, want projected additional A/AAAA with min TTL", records[0])
	}
	if records[1].Name != "service.example.com" || records[1].TTLSeconds != 30 || len(records[1].IPs) != 2 {
		t.Fatalf("canonical record = %+v, want additional A/AAAA with min TTL", records[1])
	}
}

func TestRecordsFromResponseRejectsTruncatedPacket(t *testing.T) {
	_, err := RecordsFromResponse([]byte{0, 1, 0x81}, time.Time{})
	if err == nil {
		t.Fatal("expected truncated packet to fail")
	}
}

func dnsResponse(question []byte, answers ...[]byte) []byte {
	return dnsResponseWithSections(question, answers, nil, nil)
}

func dnsResponseWithSections(question []byte, answers, authority, additional [][]byte) []byte {
	packet := []byte{
		0x12, 0x34,
		0x81, 0x80,
		0x00, 0x01,
		0x00, byte(len(answers)),
		0x00, byte(len(authority)),
		0x00, byte(len(additional)),
	}
	packet = append(packet, question...)
	for _, section := range [][][]byte{answers, authority, additional} {
		for _, rr := range section {
			packet = append(packet, rr...)
		}
	}
	return packet
}

func dnsQuestion(name string, rrType uint16) []byte {
	out := dnsName(name)
	out = appendUint16(out, rrType)
	out = appendUint16(out, dnsClassIN)
	return out
}

func dnsAnswerPtr(ptr int, rrType uint16, ttl uint32, rdata []byte) []byte {
	out := []byte{byte(0xc0 | ((ptr >> 8) & 0x3f)), byte(ptr)}
	return appendRR(out, rrType, ttl, rdata)
}

func dnsAnswerName(name string, rrType uint16, ttl uint32, rdata []byte) []byte {
	return appendRR(dnsName(name), rrType, ttl, rdata)
}

func appendRR(out []byte, rrType uint16, ttl uint32, rdata []byte) []byte {
	out = appendUint16(out, rrType)
	out = appendUint16(out, dnsClassIN)
	out = append(out, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
	out = appendUint16(out, uint16(len(rdata)))
	out = append(out, rdata...)
	return out
}

func dnsName(name string) []byte {
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i != len(name) && name[i] != '.' {
			continue
		}
		out = append(out, byte(i-start))
		out = append(out, name[start:i]...)
		start = i + 1
	}
	return append(out, 0)
}

func appendUint16(out []byte, value uint16) []byte {
	return append(out, byte(value>>8), byte(value))
}
