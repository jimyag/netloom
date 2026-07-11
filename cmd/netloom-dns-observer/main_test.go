package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
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
	endpoint, client, cleanup := newTestVSwitchOVSDB(t)
	defer cleanup()
	insertVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{ExternalIDs: map[string]string{
		control.DNSObservationsOpenVSwitchExternalID: `{"dns_records":[{"name":"static.example.com","ips":["203.0.113.30"]}]}`,
	}})
	packet := dnsResponse(
		dnsQuestion("api.example.com", 1),
		dnsAnswerPtr(12, 1, 60, []byte{203, 0, 113, 10}),
		dnsAnswerPtr(12, 28, 120, netip.MustParseAddr("2001:db8::10").AsSlice()),
	)
	input := strings.NewReader(base64.StdEncoding.EncodeToString(packet) + "\n")
	var stdout bytes.Buffer
	now := func() time.Time { return time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC) }

	if err := run(t.Context(), []string{"-ovsdb", endpoint}, input, &stdout, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "packets=1 records=1 written=2") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	records, err := loadDNSObservationsFromVSwitch(t, client)
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
	endpoint, client, cleanup := newTestVSwitchOVSDB(t)
	defer cleanup()
	insertVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{})
	packet := dnsResponse(
		dnsQuestion("api.example.com", 1),
		dnsAnswerPtr(12, 1, 0, []byte{203, 0, 113, 10}),
	)
	input := strings.NewReader(base64.StdEncoding.EncodeToString(packet) + "\n")
	now := func() time.Time { return time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC) }

	if err := run(t.Context(), []string{"-ovsdb", endpoint, "-default-ttl", "30"}, input, ioDiscard{}, now); err != nil {
		t.Fatal(err)
	}
	records, err := loadDNSObservationsFromVSwitch(t, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d", len(records))
	}
	if records[0].TTLSeconds != 30 || !records[0].ObservedAt.Equal(now()) {
		t.Fatalf("record = %+v", records[0])
	}
}

func TestRunPrunesExpiredExistingObservations(t *testing.T) {
	endpoint, client, cleanup := newTestVSwitchOVSDB(t)
	defer cleanup()
	existing := `{"dns_records":[
		{"name":"expired.example.com","ips":["203.0.113.30"],"ttl_seconds":30,"observed_at":"2026-05-30T11:59:30Z"},
		{"name":"active.example.com","ips":["203.0.113.40"],"ttl_seconds":31,"observed_at":"2026-05-30T11:59:30Z"},
		{"name":"static.example.com","ips":["203.0.113.50"]}
	]}`
	insertVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{ExternalIDs: map[string]string{
		control.DNSObservationsOpenVSwitchExternalID: existing,
	}})
	packet := dnsResponse(
		dnsQuestion("api.example.com", 1),
		dnsAnswerPtr(12, 1, 60, []byte{203, 0, 113, 10}),
	)
	input := strings.NewReader(base64.StdEncoding.EncodeToString(packet) + "\n")
	now := func() time.Time { return time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC) }

	if err := run(t.Context(), []string{"-ovsdb", endpoint}, input, ioDiscard{}, now); err != nil {
		t.Fatal(err)
	}
	records, err := loadDNSObservationsFromVSwitch(t, client)
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
	endpoint, client, cleanup := newTestVSwitchOVSDB(t)
	defer cleanup()
	existing := `{"dns_records":[{"name":"api.example.com","ips":["203.0.113.10"],"ttl_seconds":30,"observed_at":"2026-05-30T11:59:00Z"}]}`
	insertVSwitchRows(t, t.Context(), client, &vswitch.OpenvSwitch{ExternalIDs: map[string]string{
		control.DNSObservationsOpenVSwitchExternalID: existing,
	}})
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
	records, err := loadDNSObservationsFromVSwitch(t, client)
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

func TestUDPProxyForwardsResponsesAndWritesDNSObservations(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		buf := make([]byte, 1500)
		n, addr, err := upstream.ReadFrom(buf)
		if err != nil {
			return
		}
		if n == 0 || addr == nil {
			return
		}
		response := dnsResponse(
			dnsQuestion("api.example.com", 1),
			dnsAnswerPtr(12, 1, 60, []byte{203, 0, 113, 10}),
		)
		_, _ = upstream.WriteTo(response, addr)
	}()

	ovsdb := &fakeOpenVSwitchExternalIDStore{}
	store := ovsdbDNSObservationStore{syncer: ovsdb}
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	proxy := dnsUDPProxy{
		store:         store,
		upstream:      upstream.LocalAddr().String(),
		timeout:       time.Second,
		mergeExisting: true,
		now:           func() time.Time { return time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC) },
	}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Serve(ctx, listener)
	}()
	client, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write(dnsQuery("api.example.com", 1)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1500)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("empty DNS response from proxy")
	}
	requireEventually(t, func() bool {
		records, err := store.Load(t.Context())
		if err != nil {
			return false
		}
		return len(records) == 1 && records[0].Name == "api.example.com" && records[0].IPs[0] == netip.MustParseAddr("203.0.113.10")
	})
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy did not stop after cancel")
	}
}

func TestTCPProxyForwardsResponsesAndWritesDNSObservations(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		answers := []struct {
			name string
			ip   []byte
		}{
			{name: "api.example.com", ip: []byte{203, 0, 113, 11}},
			{name: "db.example.com", ip: []byte{203, 0, 113, 12}},
		}
		for _, answer := range answers {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			query, err := readTCPDNSMessage(conn)
			if err != nil || len(query) == 0 {
				_ = conn.Close()
				return
			}
			response := dnsResponse(
				dnsQuestion(answer.name, 1),
				dnsAnswerPtr(12, 1, 60, answer.ip),
			)
			_ = writeTCPDNSMessage(conn, response)
			_ = conn.Close()
		}
	}()

	ovsdb := &fakeOpenVSwitchExternalIDStore{}
	store := ovsdbDNSObservationStore{syncer: ovsdb}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	proxy := dnsTCPProxy{
		store:         store,
		upstream:      upstream.Addr().String(),
		timeout:       time.Second,
		mergeExisting: true,
		now:           func() time.Time { return time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC) },
	}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Serve(ctx, listener)
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := writeTCPDNSMessage(client, dnsQuery("api.example.com", 1)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	response, err := readTCPDNSMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) == 0 {
		t.Fatal("empty DNS response from TCP proxy")
	}
	if err := writeTCPDNSMessage(client, dnsQuery("db.example.com", 1)); err != nil {
		t.Fatal(err)
	}
	response, err = readTCPDNSMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) == 0 {
		t.Fatal("empty second DNS response from TCP proxy")
	}
	requireEventually(t, func() bool {
		records, err := store.Load(t.Context())
		if err != nil {
			return false
		}
		seen := map[string]netip.Addr{}
		for _, record := range records {
			if len(record.IPs) > 0 {
				seen[record.Name] = record.IPs[0]
			}
		}
		return len(records) == 2 &&
			seen["api.example.com"] == netip.MustParseAddr("203.0.113.11") &&
			seen["db.example.com"] == netip.MustParseAddr("203.0.113.12")
	})
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP proxy did not stop after cancel")
	}
}

func TestRunRejectsEmptyInput(t *testing.T) {
	endpoint, _, cleanup := newTestVSwitchOVSDB(t)
	defer cleanup()
	err := run(t.Context(), []string{"-ovsdb", endpoint}, strings.NewReader("\n# ignored\n"), ioDiscard{}, time.Now)
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

func loadDNSObservationsFromVSwitch(t *testing.T, client libovsdbclient.Client) ([]model.DNSRecord, error) {
	t.Helper()
	root := singleVSwitchRoot(t, t.Context(), client)
	raw := root.ExternalIDs[control.DNSObservationsOpenVSwitchExternalID]
	if raw == "" {
		t.Fatalf("root external IDs = %+v, want DNS observations", root.ExternalIDs)
	}
	return control.LoadDNSObservationsJSON(strings.NewReader(raw))
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

func dnsQuery(name string, rrType uint16) []byte {
	packet := []byte{
		0x12, 0x34,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	packet = append(packet, dnsQuestion(name, rrType)...)
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
