package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dnsobserver"
	"github.com/jimyag/netloom/internal/linuxdatapath"
	"github.com/jimyag/netloom/internal/model"
)

type options struct {
	inputPath       string
	outputPath      string
	ovsdbEndpoint   string
	format          string
	mergeExisting   bool
	defaultTTL      uint
	observedAtValue string
	listenUDP       string
	upstreamUDP     string
	udpTimeout      time.Duration
}

type result struct {
	Packets int
	Records int
	Written int
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, time.Now); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, now func() time.Time) error {
	flags := flag.NewFlagSet("netloom-dns-observer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	opts := options{}
	flags.StringVar(&opts.inputPath, "in", "-", "DNS response input path, or '-' for stdin")
	flags.StringVar(&opts.outputPath, "observations", os.Getenv("NETLOOM_DNS_OBSERVATIONS_FILE"), "DNS observations JSON output path")
	flags.StringVar(&opts.ovsdbEndpoint, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint for DNS observations")
	flags.StringVar(&opts.format, "format", "base64-lines", "input format: base64-lines, hex-lines, or raw")
	flags.BoolVar(&opts.mergeExisting, "merge", true, "merge records with an existing observations file")
	flags.UintVar(&opts.defaultTTL, "default-ttl", 0, "TTL seconds to apply to answers that do not carry a positive TTL")
	flags.StringVar(&opts.observedAtValue, "observed-at", "", "observation time in RFC3339; defaults to current time")
	flags.StringVar(&opts.listenUDP, "listen-udp", os.Getenv("NETLOOM_DNS_OBSERVER_LISTEN_UDP"), "UDP address to listen on as a DNS proxy/capture path")
	flags.StringVar(&opts.upstreamUDP, "upstream-udp", os.Getenv("NETLOOM_DNS_OBSERVER_UPSTREAM_UDP"), "upstream UDP DNS server used with -listen-udp")
	flags.DurationVar(&opts.udpTimeout, "udp-timeout", 2*time.Second, "UDP upstream timeout used with -listen-udp")
	if err := flags.Parse(args); err != nil {
		return err
	}
	store, closeStore, err := dnsObservationStoreFromOptions(ctx, opts)
	if err != nil {
		return err
	}
	defer closeStore()
	if store == nil {
		return fmt.Errorf("-ovsdb/NETLOOM_OVSDB_ENDPOINT or -observations/NETLOOM_DNS_OBSERVATIONS_FILE is required")
	}
	if opts.defaultTTL > uint(^uint32(0)) {
		return fmt.Errorf("-default-ttl exceeds uint32")
	}
	if strings.TrimSpace(opts.listenUDP) != "" {
		return runUDPProxy(ctx, opts, store, stdout, now)
	}

	observedAt, err := observedAt(opts.observedAtValue, now)
	if err != nil {
		return err
	}
	input := stdin
	if opts.inputPath != "-" {
		file, err := os.Open(opts.inputPath)
		if err != nil {
			return err
		}
		defer file.Close()
		input = file
	}

	packets, err := readPackets(input, opts.format)
	if err != nil {
		return err
	}
	records := make([]model.DNSRecord, 0, len(packets))
	for i, packet := range packets {
		parsed, err := dnsobserver.RecordsFromResponse(packet, observedAt)
		if err != nil {
			return fmt.Errorf("parse dns response %d: %w", i, err)
		}
		for _, record := range parsed {
			if record.TTLSeconds == 0 && opts.defaultTTL > 0 {
				record.TTLSeconds = uint32(opts.defaultTTL)
				record.ObservedAt = observedAt
			}
			records = append(records, record)
		}
	}
	merged, err := mergeAndSaveDNSObservations(ctx, store, records, observedAt, opts.mergeExisting)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "netloom-dns-observer observed packets=%d records=%d written=%d\n", len(packets), len(records), len(merged))
	return nil
}

func runUDPProxy(ctx context.Context, opts options, store dnsObservationStore, stdout io.Writer, now func() time.Time) error {
	upstream := strings.TrimSpace(opts.upstreamUDP)
	if upstream == "" {
		return fmt.Errorf("-upstream-udp/NETLOOM_DNS_OBSERVER_UPSTREAM_UDP is required with -listen-udp")
	}
	if opts.udpTimeout <= 0 {
		return fmt.Errorf("-udp-timeout must be positive")
	}
	listener, err := net.ListenPacket("udp", strings.TrimSpace(opts.listenUDP))
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Fprintf(stdout, "netloom-dns-observer listening udp=%s upstream=%s\n", listener.LocalAddr(), upstream)
	proxy := dnsUDPProxy{
		store:         store,
		upstream:      upstream,
		timeout:       opts.udpTimeout,
		mergeExisting: opts.mergeExisting,
		defaultTTL:    uint32(opts.defaultTTL),
		now:           now,
	}
	return proxy.Serve(ctx, listener)
}

type dnsUDPProxy struct {
	store         dnsObservationStore
	upstream      string
	timeout       time.Duration
	mergeExisting bool
	defaultTTL    uint32
	now           func() time.Time
	mu            sync.Mutex
}

func (p *dnsUDPProxy) Serve(ctx context.Context, listener net.PacketConn) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()
	defer close(done)
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := listener.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		query := append([]byte(nil), buf[:n]...)
		go p.handleQuery(ctx, listener, clientAddr, query)
	}
}

func (p *dnsUDPProxy) handleQuery(ctx context.Context, listener net.PacketConn, clientAddr net.Addr, query []byte) {
	response, err := p.exchange(ctx, query)
	if err != nil {
		return
	}
	_, _ = listener.WriteTo(response, clientAddr)
	observedAt := p.now().UTC()
	records, err := dnsobserver.RecordsFromResponse(response, observedAt)
	if err != nil || len(records) == 0 {
		return
	}
	for i := range records {
		if records[i].TTLSeconds == 0 && p.defaultTTL > 0 {
			records[i].TTLSeconds = p.defaultTTL
			records[i].ObservedAt = observedAt
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, _ = mergeAndSaveDNSObservations(ctx, p.store, records, observedAt, p.mergeExisting)
}

func (p *dnsUDPProxy) exchange(ctx context.Context, query []byte) ([]byte, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", p.upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(p.timeout)
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), response[:n]...), nil
}

func mergeAndSaveDNSObservations(ctx context.Context, store dnsObservationStore, records []model.DNSRecord, now time.Time, mergeExisting bool) ([]model.DNSRecord, error) {
	merged := records
	if mergeExisting {
		existing, err := store.Load(ctx)
		if err != nil {
			return nil, err
		}
		merged, err = control.MergeDNSRecords(existing, records)
		if err != nil {
			return nil, err
		}
	}
	merged, err := control.PruneExpiredDNSRecords(merged, now)
	if err != nil {
		return nil, err
	}
	if err := store.Save(ctx, merged); err != nil {
		return nil, err
	}
	return merged, nil
}

type dnsObservationStore interface {
	Load(context.Context) ([]model.DNSRecord, error)
	Save(context.Context, []model.DNSRecord) error
}

type openVSwitchExternalIDStore interface {
	OpenVSwitchExternalID(context.Context, string) (string, bool, error)
	SetOpenVSwitchExternalID(context.Context, string, string) error
}

type fileDNSObservationStore struct {
	path string
}

type ovsdbDNSObservationStore struct {
	syncer openVSwitchExternalIDStore
}

func dnsObservationStoreFromOptions(ctx context.Context, opts options) (dnsObservationStore, func(), error) {
	endpoint := strings.TrimSpace(opts.ovsdbEndpoint)
	if endpoint != "" {
		client, closeClient, err := linuxdatapath.NewOpenVSwitchClient(ctx, endpoint)
		if err != nil {
			return nil, func() {}, err
		}
		return ovsdbDNSObservationStore{
			syncer: linuxdatapath.NewLibOVSDBProviderSyncer(client),
		}, closeClient, nil
	}
	if strings.TrimSpace(opts.outputPath) == "" {
		return nil, func() {}, nil
	}
	return fileDNSObservationStore{path: opts.outputPath}, func() {}, nil
}

func observedAt(value string, now func() time.Time) (time.Time, error) {
	if value == "" {
		return now().UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid -observed-at: %w", err)
	}
	return t.UTC(), nil
}

func readPackets(r io.Reader, format string) ([][]byte, error) {
	switch format {
	case "base64-lines":
		return readEncodedLines(r, base64.StdEncoding.DecodeString)
	case "hex-lines":
		return readEncodedLines(r, hex.DecodeString)
	case "raw":
		packet, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		if len(packet) == 0 {
			return nil, fmt.Errorf("raw DNS response input is empty")
		}
		return [][]byte{packet}, nil
	default:
		return nil, fmt.Errorf("unsupported -format %q", format)
	}
}

func readEncodedLines(r io.Reader, decode func(string) ([]byte, error)) ([][]byte, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 1024*1024)
	var packets [][]byte
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		packet, err := decode(line)
		if err != nil {
			return nil, fmt.Errorf("decode line %d: %w", lineNo, err)
		}
		if len(packet) == 0 {
			return nil, fmt.Errorf("decode line %d: empty packet", lineNo)
		}
		packets = append(packets, packet)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(packets) == 0 {
		return nil, fmt.Errorf("DNS response input is empty")
	}
	return packets, nil
}

func (s fileDNSObservationStore) Load(_ context.Context) ([]model.DNSRecord, error) {
	file, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return control.LoadDNSObservationsJSON(file)
}

func (s fileDNSObservationStore) Save(_ context.Context, records []model.DNSRecord) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(struct {
		DNSRecords []model.DNSRecord `json:"dns_records"`
	}{DNSRecords: records}); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.path)
}

func (s ovsdbDNSObservationStore) Load(ctx context.Context) ([]model.DNSRecord, error) {
	if s.syncer == nil {
		return nil, nil
	}
	raw, ok, err := s.syncer.OpenVSwitchExternalID(ctx, control.DNSObservationsOpenVSwitchExternalID)
	if err != nil {
		return nil, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	return control.LoadDNSObservationsJSON(strings.NewReader(raw))
}

func (s ovsdbDNSObservationStore) Save(ctx context.Context, records []model.DNSRecord) error {
	if s.syncer == nil {
		return nil
	}
	raw, err := control.MarshalDNSObservationsJSON(records)
	if err != nil {
		return err
	}
	return s.syncer.SetOpenVSwitchExternalID(ctx, control.DNSObservationsOpenVSwitchExternalID, string(raw))
}
