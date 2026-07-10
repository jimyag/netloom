package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/database/inmemory"
	ovsmodel "github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"github.com/ovn-kubernetes/libovsdb/server"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn/ovsdb/vswitch"
)

func TestRunParsesBase64DNSResponsesAndMergesObservations(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "dns-observations.json")
	existing := `{"dns_records":[{"name":"static.example.com","ips":["203.0.113.30"]}]}`
	if err := os.WriteFile(output, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	packet := dnsResponse(
		dnsQuestion("api.example.com", 1),
		dnsAnswerPtr(12, 1, 60, []byte{203, 0, 113, 10}),
		dnsAnswerPtr(12, 28, 120, netip.MustParseAddr("2001:db8::10").AsSlice()),
	)
	input := strings.NewReader(base64.StdEncoding.EncodeToString(packet) + "\n")
	var stdout bytes.Buffer
	now := func() time.Time { return time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC) }

	if err := run(t.Context(), []string{"-observations", output}, input, &stdout, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "packets=1 records=1 written=2") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	file, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	records, err := control.LoadDNSObservationsJSON(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2: %+v", len(records), records)
	}
	if records[0].Name != "api.example.com" || records[0].TTLSeconds != 60 || !records[0].ObservedAt.Equal(now()) {
		t.Fatalf("observed record = %+v", records[0])
	}
	if records[1].Name != "static.example.com" {
		t.Fatalf("existing record = %+v", records[1])
	}
}

func TestRunAppliesDefaultTTLToZeroTTLAnswers(t *testing.T) {
	output := filepath.Join(t.TempDir(), "dns-observations.json")
	packet := dnsResponse(
		dnsQuestion("api.example.com", 1),
		dnsAnswerPtr(12, 1, 0, []byte{203, 0, 113, 10}),
	)
	input := strings.NewReader(base64.StdEncoding.EncodeToString(packet) + "\n")
	now := func() time.Time { return time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC) }

	if err := run(t.Context(), []string{"-observations", output, "-default-ttl", "30"}, input, ioDiscard{}, now); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		DNSRecords []model.DNSRecord `json:"dns_records"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.DNSRecords) != 1 {
		t.Fatalf("records = %d", len(document.DNSRecords))
	}
	if document.DNSRecords[0].TTLSeconds != 30 || !document.DNSRecords[0].ObservedAt.Equal(now()) {
		t.Fatalf("record = %+v", document.DNSRecords[0])
	}
}

func TestRunPrunesExpiredExistingObservations(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "dns-observations.json")
	existing := `{"dns_records":[
		{"name":"expired.example.com","ips":["203.0.113.30"],"ttl_seconds":30,"observed_at":"2026-05-30T11:59:30Z"},
		{"name":"active.example.com","ips":["203.0.113.40"],"ttl_seconds":31,"observed_at":"2026-05-30T11:59:30Z"},
		{"name":"static.example.com","ips":["203.0.113.50"]}
	]}`
	if err := os.WriteFile(output, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	packet := dnsResponse(
		dnsQuestion("api.example.com", 1),
		dnsAnswerPtr(12, 1, 60, []byte{203, 0, 113, 10}),
	)
	input := strings.NewReader(base64.StdEncoding.EncodeToString(packet) + "\n")
	now := func() time.Time { return time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC) }

	if err := run(t.Context(), []string{"-observations", output}, input, ioDiscard{}, now); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	records, err := control.LoadDNSObservationsJSON(file)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(records))
	for _, record := range records {
		names = append(names, record.Name)
	}
	want := []string{"active.example.com", "api.example.com", "static.example.com"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("record names = %v, want %v", names, want)
	}
}

func TestRunUpsertsRepeatedExistingObservations(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "dns-observations.json")
	existing := `{"dns_records":[{"name":"api.example.com","ips":["203.0.113.10"],"ttl_seconds":30,"observed_at":"2026-05-30T11:59:00Z"}]}`
	if err := os.WriteFile(output, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	packet := dnsResponse(
		dnsQuestion("api.example.com", 1),
		dnsAnswerPtr(12, 1, 60, []byte{203, 0, 113, 10}),
	)
	input := strings.NewReader(base64.StdEncoding.EncodeToString(packet) + "\n")
	var stdout bytes.Buffer
	now := func() time.Time { return time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC) }

	if err := run(t.Context(), []string{"-observations", output}, input, &stdout, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "packets=1 records=1 written=1") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	file, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	records, err := control.LoadDNSObservationsJSON(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1: %+v", len(records), records)
	}
	if records[0].TTLSeconds != 60 || !records[0].ObservedAt.Equal(now()) {
		t.Fatalf("record was not refreshed: %+v", records[0])
	}
}

func TestOVSDBDNSObservationStoreSavesAndLoadsExternalID(t *testing.T) {
	ovsdb := &fakeOpenVSwitchExternalIDStore{}
	store := ovsdbDNSObservationStore{syncer: ovsdb}

	err := store.Save(t.Context(), []model.DNSRecord{{
		Name: "api.example.com",
		IPs:  []netip.Addr{netip.MustParseAddr("203.0.113.10")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw := ovsdb.values[control.DNSObservationsOpenVSwitchExternalID]
	if raw == "" {
		t.Fatalf("missing %s external_id", control.DNSObservationsOpenVSwitchExternalID)
	}

	records, err := store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Name != "api.example.com" {
		t.Fatalf("records = %+v", records)
	}
}

func TestRunWritesDNSObservationsToOpenVSwitchOVSDB(t *testing.T) {
	endpoint, client, cleanup := newTestVSwitchOVSDB(t)
	defer cleanup()
	insertVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{})
	packet := dnsResponse(
		dnsQuestion("api.example.com", 1),
		dnsAnswerPtr(12, 1, 60, []byte{203, 0, 113, 10}),
	)
	input := strings.NewReader(base64.StdEncoding.EncodeToString(packet) + "\n")
	var stdout bytes.Buffer
	now := func() time.Time { return time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC) }

	if err := run(t.Context(), []string{"-ovsdb", endpoint}, input, &stdout, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "packets=1 records=1 written=1") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	root := singleVSwitchRoot(t, t.Context(), client)
	raw := root.ExternalIDs[control.DNSObservationsOpenVSwitchExternalID]
	if raw == "" {
		t.Fatalf("root external IDs = %+v, want DNS observations", root.ExternalIDs)
	}
	records, err := control.LoadDNSObservationsJSON(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Name != "api.example.com" || records[0].IPs[0].String() != "203.0.113.10" {
		t.Fatalf("records = %+v", records)
	}
}

func TestRunRejectsEmptyInput(t *testing.T) {
	err := run(t.Context(), []string{"-observations", filepath.Join(t.TempDir(), "dns.json")}, strings.NewReader("\n# ignored\n"), ioDiscard{}, time.Now)
	if err == nil {
		t.Fatal("expected empty input to fail")
	}
}

type fakeOpenVSwitchExternalIDStore struct {
	values map[string]string
}

func (s *fakeOpenVSwitchExternalIDStore) OpenVSwitchExternalID(_ context.Context, key string) (string, bool, error) {
	if s.values == nil {
		return "", false, nil
	}
	value, ok := s.values[key]
	return value, ok, nil
}

func (s *fakeOpenVSwitchExternalIDStore) SetOpenVSwitchExternalID(_ context.Context, key, value string) error {
	if s.values == nil {
		s.values = map[string]string{}
	}
	s.values[key] = value
	return nil
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func newTestVSwitchOVSDB(t *testing.T) (string, libovsdbclient.Client, func()) {
	t.Helper()
	clientModel, err := vswitch.FullDatabaseModel()
	if err != nil {
		t.Fatal(err)
	}
	schema := vswitch.Schema()
	databaseModel, errs := ovsmodel.NewDatabaseModel(schema, clientModel)
	if len(errs) > 0 {
		t.Fatalf("database model errors: %+v", errs)
	}
	logger := logr.Discard()
	db := inmemory.NewDatabase(map[string]ovsmodel.ClientDBModel{vswitch.DatabaseName: clientModel}, &logger)
	ovsServer, err := server.NewOvsdbServer(db, &logger, databaseModel)
	if err != nil {
		t.Fatal(err)
	}
	socket := fmt.Sprintf("/tmp/netloom-dns-vswitch-%d.sock", rand.Int())
	_ = os.Remove(socket)
	go func() {
		if err := ovsServer.Serve("unix", socket); err != nil {
			t.Logf("libovsdb test server stopped: %v", err)
		}
	}()
	requireEventually(t, ovsServer.Ready)

	client, err := libovsdbclient.NewOVSDBClient(clientModel, libovsdbclient.WithEndpoint("unix:"+socket))
	if err != nil {
		ovsServer.Close()
		t.Fatal(err)
	}
	if err := client.Connect(t.Context()); err != nil {
		ovsServer.Close()
		t.Fatal(err)
	}
	if _, err := client.MonitorAll(t.Context()); err != nil {
		ovsServer.Close()
		t.Fatal(err)
	}
	return "unix:" + socket, client, func() {
		client.Disconnect()
		client.Close()
		ovsServer.Close()
		_ = os.Remove(socket)
	}
}

func requireEventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not satisfied")
}

func insertVSwitchRows(t *testing.T, ctx context.Context, client libovsdbclient.Client, rows ...ovsmodel.Model) {
	t.Helper()
	var ops []ovsdb.Operation
	for _, row := range rows {
		next, err := client.Create(row)
		if err != nil {
			t.Fatal(err)
		}
		ops = append(ops, next...)
	}
	results, err := client.Transact(ctx, ops...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ovsdb.CheckOperationResults(results, ops); err != nil {
		t.Fatalf("ovsdb transact results = %+v: %v", results, err)
	}
}

func singleVSwitchRoot(t *testing.T, ctx context.Context, client libovsdbclient.Client) vswitch.OpenvSwitch {
	t.Helper()
	var rows []vswitch.OpenvSwitch
	if err := client.List(ctx, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("Open_vSwitch rows = %d, want 1: %+v", len(rows), rows)
	}
	return rows[0]
}

func dnsResponse(question []byte, answers ...[]byte) []byte {
	packet := []byte{
		0x12, 0x34,
		0x81, 0x80,
		0x00, 0x01,
		0x00, byte(len(answers)),
		0x00, 0x00,
		0x00, 0x00,
	}
	packet = append(packet, question...)
	for _, answer := range answers {
		packet = append(packet, answer...)
	}
	return packet
}

func dnsQuestion(name string, rrType uint16) []byte {
	out := dnsName(name)
	out = appendUint16(out, rrType)
	out = appendUint16(out, 1)
	return out
}

func dnsAnswerPtr(ptr int, rrType uint16, ttl uint32, rdata []byte) []byte {
	out := []byte{byte(0xc0 | ((ptr >> 8) & 0x3f)), byte(ptr)}
	return appendRR(out, rrType, ttl, rdata)
}

func appendRR(out []byte, rrType uint16, ttl uint32, rdata []byte) []byte {
	out = appendUint16(out, rrType)
	out = appendUint16(out, 1)
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
