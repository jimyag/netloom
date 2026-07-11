package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dnsobserver"
	"github.com/jimyag/netloom/internal/linuxdatapath"
	"github.com/jimyag/netloom/internal/model"
	"golang.org/x/sys/unix"
)

type options struct {
	inputPath       string
	ovsdbEndpoint   string
	format          string
	mergeExisting   bool
	defaultTTL      uint
	observedAtValue string
	listenUDP       string
	upstreamUDP     string
	udpTimeout      time.Duration
	listenTCP       string
	upstreamTCP     string
	tcpTimeout      time.Duration
	captureIface    string
	captureCount    uint
	captureDuration time.Duration
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
	flags.StringVar(&opts.ovsdbEndpoint, "ovsdb", os.Getenv("NETLOOM_OVSDB_ENDPOINT"), "Open_vSwitch OVSDB endpoint for DNS observations")
	flags.StringVar(&opts.format, "format", "base64-lines", "input format: base64-lines, hex-lines, or raw")
	flags.BoolVar(&opts.mergeExisting, "merge", true, "merge records with existing OVSDB observations")
	flags.UintVar(&opts.defaultTTL, "default-ttl", 0, "TTL seconds to apply to answers that do not carry a positive TTL")
	flags.StringVar(&opts.observedAtValue, "observed-at", "", "observation time in RFC3339; defaults to current time")
	flags.StringVar(&opts.listenUDP, "listen-udp", os.Getenv("NETLOOM_DNS_OBSERVER_LISTEN_UDP"), "UDP address to listen on as a DNS proxy/capture path")
	flags.StringVar(&opts.upstreamUDP, "upstream-udp", os.Getenv("NETLOOM_DNS_OBSERVER_UPSTREAM_UDP"), "upstream UDP DNS server used with -listen-udp")
	flags.DurationVar(&opts.udpTimeout, "udp-timeout", 2*time.Second, "UDP upstream timeout used with -listen-udp")
	flags.StringVar(&opts.listenTCP, "listen-tcp", os.Getenv("NETLOOM_DNS_OBSERVER_LISTEN_TCP"), "TCP address to listen on as a DNS proxy/capture path")
	flags.StringVar(&opts.upstreamTCP, "upstream-tcp", os.Getenv("NETLOOM_DNS_OBSERVER_UPSTREAM_TCP"), "upstream TCP DNS server used with -listen-tcp")
	flags.DurationVar(&opts.tcpTimeout, "tcp-timeout", 2*time.Second, "TCP upstream timeout used with -listen-tcp")
	flags.StringVar(&opts.captureIface, "capture-iface", os.Getenv("NETLOOM_DNS_OBSERVER_CAPTURE_IFACE"), "interface name to passively capture UDP DNS responses with AF_PACKET")
	flags.UintVar(&opts.captureCount, "capture-count", 0, "number of DNS response packets to capture before exiting; 0 means unlimited")
	flags.DurationVar(&opts.captureDuration, "capture-duration", 0, "maximum AF_PACKET capture duration; 0 means run until context cancellation or -capture-count")
	if err := flags.Parse(args); err != nil {
		return err
	}
	store, closeStore, err := dnsObservationStoreFromOptions(ctx, opts)
	if err != nil {
		return err
	}
	defer closeStore()
	if store == nil {
		return fmt.Errorf("-ovsdb/NETLOOM_OVSDB_ENDPOINT is required")
	}
	if opts.defaultTTL > uint(^uint32(0)) {
		return fmt.Errorf("-default-ttl exceeds uint32")
	}
	activeInputs := 0
	for _, value := range []string{opts.listenUDP, opts.listenTCP, opts.captureIface} {
		if strings.TrimSpace(value) != "" {
			activeInputs++
		}
	}
	if activeInputs > 1 {
		return fmt.Errorf("-listen-udp, -listen-tcp, and -capture-iface are mutually exclusive")
	}
	if strings.TrimSpace(opts.listenUDP) != "" {
		return runUDPProxy(ctx, opts, store, stdout, now)
	}
	if strings.TrimSpace(opts.listenTCP) != "" {
		return runTCPProxy(ctx, opts, store, stdout, now)
	}
	if strings.TrimSpace(opts.captureIface) != "" {
		return runPacketCapture(ctx, opts, store, stdout, now)
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

func runTCPProxy(ctx context.Context, opts options, store dnsObservationStore, stdout io.Writer, now func() time.Time) error {
	upstream := strings.TrimSpace(opts.upstreamTCP)
	if upstream == "" {
		return fmt.Errorf("-upstream-tcp/NETLOOM_DNS_OBSERVER_UPSTREAM_TCP is required with -listen-tcp")
	}
	if opts.tcpTimeout <= 0 {
		return fmt.Errorf("-tcp-timeout must be positive")
	}
	listener, err := net.Listen("tcp", strings.TrimSpace(opts.listenTCP))
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Fprintf(stdout, "netloom-dns-observer listening tcp=%s upstream=%s\n", listener.Addr(), upstream)
	proxy := dnsTCPProxy{
		store:         store,
		upstream:      upstream,
		timeout:       opts.tcpTimeout,
		mergeExisting: opts.mergeExisting,
		defaultTTL:    uint32(opts.defaultTTL),
		now:           now,
	}
	return proxy.Serve(ctx, listener)
}

func runPacketCapture(ctx context.Context, opts options, store dnsObservationStore, stdout io.Writer, now func() time.Time) error {
	if opts.captureDuration < 0 {
		return fmt.Errorf("-capture-duration must not be negative")
	}
	captureCtx := ctx
	cancel := func() {}
	if opts.captureDuration > 0 {
		captureCtx, cancel = context.WithTimeout(ctx, opts.captureDuration)
	}
	defer cancel()
	capture, err := newAFPacketDNSCapture(strings.TrimSpace(opts.captureIface))
	if err != nil {
		return err
	}
	defer capture.Close()
	fmt.Fprintf(stdout, "netloom-dns-observer capturing iface=%s\n", strings.TrimSpace(opts.captureIface))
	result, err := capture.Serve(captureCtx, passiveDNSObserver{
		store:         store,
		mergeExisting: opts.mergeExisting,
		defaultTTL:    uint32(opts.defaultTTL),
		now:           now,
	}, int(opts.captureCount))
	if err != nil && !(opts.captureDuration > 0 && errorsIsContextDeadline(err)) {
		return err
	}
	fmt.Fprintf(stdout, "netloom-dns-observer captured packets=%d records=%d written=%d\n", result.Packets, result.Records, result.Written)
	return nil
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

type passiveDNSObserver struct {
	store         dnsObservationStore
	mergeExisting bool
	defaultTTL    uint32
	now           func() time.Time
	mu            sync.Mutex
}

func (o passiveDNSObserver) Observe(ctx context.Context, packet []byte) (int, int, error) {
	observedAt := o.now().UTC()
	records, err := dnsobserver.RecordsFromResponse(packet, observedAt)
	if err != nil || len(records) == 0 {
		return 0, 0, err
	}
	for i := range records {
		if records[i].TTLSeconds == 0 && o.defaultTTL > 0 {
			records[i].TTLSeconds = o.defaultTTL
			records[i].ObservedAt = observedAt
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	merged, err := mergeAndSaveDNSObservations(ctx, o.store, records, observedAt, o.mergeExisting)
	if err != nil {
		return 0, 0, err
	}
	return len(records), len(merged), nil
}

type dnsPacketObserver interface {
	Observe(context.Context, []byte) (records int, written int, err error)
}

type afPacketDNSCapture struct {
	fd int
}

func newAFPacketDNSCapture(ifaceName string) (*afPacketDNSCapture, error) {
	if ifaceName == "" {
		return nil, fmt.Errorf("-capture-iface is required")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &afPacketDNSCapture{fd: fd}, nil
}

func (c *afPacketDNSCapture) Close() error {
	if c == nil || c.fd < 0 {
		return nil
	}
	err := unix.Close(c.fd)
	c.fd = -1
	return err
}

func (c *afPacketDNSCapture) Serve(ctx context.Context, observer dnsPacketObserver, maxPackets int) (result, error) {
	if c == nil || c.fd < 0 {
		return result{}, fmt.Errorf("AF_PACKET capture is closed")
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
	defer close(done)
	buf := make([]byte, 65535)
	var out result
	for {
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			return out, err
		}
		packet, ok := dnsResponseFromEthernetFrame(buf[:n])
		if !ok {
			continue
		}
		records, written, err := observer.Observe(ctx, packet)
		if err != nil {
			continue
		}
		out.Packets++
		out.Records += records
		out.Written = written
		if maxPackets > 0 && out.Packets >= maxPackets {
			return out, nil
		}
	}
}

func dnsResponseFromEthernetFrame(frame []byte) ([]byte, bool) {
	if len(frame) < 14 {
		return nil, false
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	offset := 14
	for etherType == 0x8100 || etherType == 0x88a8 {
		if len(frame) < offset+4 {
			return nil, false
		}
		etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	switch etherType {
	case 0x0800:
		return dnsResponseFromIPv4Packet(frame[offset:])
	case 0x86dd:
		return dnsResponseFromIPv6Packet(frame[offset:])
	default:
		return nil, false
	}
}

func dnsResponseFromIPv4Packet(packet []byte) ([]byte, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return nil, false
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl || totalLen > len(packet) {
		return nil, false
	}
	if packet[9] != unix.IPPROTO_UDP {
		return nil, false
	}
	return dnsResponseFromUDPPacket(packet[ihl:totalLen])
}

func dnsResponseFromIPv6Packet(packet []byte) ([]byte, bool) {
	if len(packet) < 40 || packet[0]>>4 != 6 {
		return nil, false
	}
	payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	if payloadLen+40 > len(packet) {
		return nil, false
	}
	nextHeader := packet[6]
	offset := 40
	end := 40 + payloadLen
	for {
		switch nextHeader {
		case unix.IPPROTO_UDP:
			return dnsResponseFromUDPPacket(packet[offset:end])
		case 0, 43, 60:
			if offset+2 > end {
				return nil, false
			}
			nextHeader = packet[offset]
			headerLen := (int(packet[offset+1]) + 1) * 8
			if offset+headerLen > end {
				return nil, false
			}
			offset += headerLen
		case 44:
			if offset+8 > end {
				return nil, false
			}
			nextHeader = packet[offset]
			offset += 8
		default:
			return nil, false
		}
	}
}

func dnsResponseFromUDPPacket(packet []byte) ([]byte, bool) {
	if len(packet) < 8 {
		return nil, false
	}
	srcPort := binary.BigEndian.Uint16(packet[0:2])
	udpLen := int(binary.BigEndian.Uint16(packet[4:6]))
	if srcPort != 53 || udpLen < 8 || udpLen > len(packet) {
		return nil, false
	}
	payload := packet[8:udpLen]
	if len(payload) < 12 || payload[2]&0x80 == 0 {
		return nil, false
	}
	return append([]byte(nil), payload...), true
}

func htons(value uint16) uint16 {
	return (value << 8) | (value >> 8)
}

func errorsIsContextDeadline(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}

type dnsTCPProxy struct {
	store         dnsObservationStore
	upstream      string
	timeout       time.Duration
	mergeExisting bool
	defaultTTL    uint32
	now           func() time.Time
	mu            sync.Mutex
}

func (p *dnsTCPProxy) Serve(ctx context.Context, listener net.Listener) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()
	defer close(done)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go p.handleConn(ctx, conn)
	}
}

func (p *dnsTCPProxy) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	for {
		query, err := readTCPDNSMessage(conn)
		if err != nil {
			return
		}
		response, err := p.exchange(ctx, query)
		if err != nil {
			return
		}
		if err := writeTCPDNSMessage(conn, response); err != nil {
			return
		}
		observedAt := p.now().UTC()
		records, err := dnsobserver.RecordsFromResponse(response, observedAt)
		if err != nil || len(records) == 0 {
			continue
		}
		for i := range records {
			if records[i].TTLSeconds == 0 && p.defaultTTL > 0 {
				records[i].TTLSeconds = p.defaultTTL
				records[i].ObservedAt = observedAt
			}
		}
		p.mu.Lock()
		_, _ = mergeAndSaveDNSObservations(ctx, p.store, records, observedAt, p.mergeExisting)
		p.mu.Unlock()
	}
}

func (p *dnsTCPProxy) exchange(ctx context.Context, query []byte) ([]byte, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", p.upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(p.timeout)
	_ = conn.SetDeadline(deadline)
	if err := writeTCPDNSMessage(conn, query); err != nil {
		return nil, err
	}
	return readTCPDNSMessage(conn)
}

func readTCPDNSMessage(reader io.Reader) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(length[:])
	if n == 0 {
		return nil, fmt.Errorf("empty TCP DNS message")
	}
	packet := make([]byte, int(n))
	if _, err := io.ReadFull(reader, packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func writeTCPDNSMessage(writer io.Writer, packet []byte) error {
	if len(packet) == 0 {
		return fmt.Errorf("empty TCP DNS message")
	}
	if len(packet) > 65535 {
		return fmt.Errorf("TCP DNS message exceeds 65535 bytes")
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(packet)))
	if _, err := writer.Write(length[:]); err != nil {
		return err
	}
	_, err := writer.Write(packet)
	return err
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
	return nil, func() {}, nil
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
