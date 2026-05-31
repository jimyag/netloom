package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jimyag/netloom/internal/model"
)

type dnsObservationDocument struct {
	DNSRecords []model.DNSRecord `json:"dns_records"`
}

func LoadDNSObservationsJSON(r io.Reader) ([]model.DNSRecord, error) {
	var raw json.RawMessage
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode dns observations: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode dns observations: multiple JSON documents")
	}

	var records []model.DNSRecord
	if err := json.Unmarshal(raw, &records); err == nil {
		return validateDNSRecords(records)
	}
	var document dnsObservationDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("decode dns observations: %w", err)
	}
	return validateDNSRecords(document.DNSRecords)
}

func MergeDNSRecords(base, observed []model.DNSRecord) ([]model.DNSRecord, error) {
	merged := make([]model.DNSRecord, 0, len(base)+len(observed))
	records, err := validateDNSRecords(base)
	if err != nil {
		return nil, err
	}
	merged = append(merged, records...)
	records, err = validateDNSRecords(observed)
	if err != nil {
		return nil, err
	}
	merged = append(merged, records...)
	sort.SliceStable(merged, func(i, j int) bool {
		left, right := canonicalDNSName(merged[i].Name), canonicalDNSName(merged[j].Name)
		if left != right {
			return left < right
		}
		return merged[i].ObservedAt.Before(merged[j].ObservedAt)
	})
	return merged, nil
}

func PruneExpiredDNSRecords(records []model.DNSRecord, now time.Time) ([]model.DNSRecord, error) {
	validated, err := validateDNSRecords(records)
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	pruned := validated[:0]
	for _, record := range validated {
		if record.IsExpired(now) {
			continue
		}
		pruned = append(pruned, record)
	}
	return pruned, nil
}

func validateDNSRecords(records []model.DNSRecord) ([]model.DNSRecord, error) {
	out := append([]model.DNSRecord(nil), records...)
	for i := range out {
		if err := out[i].Validate(); err != nil {
			return nil, fmt.Errorf("dns record %d: %w", i, err)
		}
	}
	return out, nil
}

func canonicalDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}
