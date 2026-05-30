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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/dnsobserver"
	"github.com/jimyag/netloom/internal/model"
)

type options struct {
	inputPath       string
	outputPath      string
	format          string
	mergeExisting   bool
	defaultTTL      uint
	observedAtValue string
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

func run(_ context.Context, args []string, stdin io.Reader, stdout io.Writer, now func() time.Time) error {
	flags := flag.NewFlagSet("netloom-dns-observer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	opts := options{}
	flags.StringVar(&opts.inputPath, "in", "-", "DNS response input path, or '-' for stdin")
	flags.StringVar(&opts.outputPath, "observations", os.Getenv("NETLOOM_DNS_OBSERVATIONS_FILE"), "DNS observations JSON output path")
	flags.StringVar(&opts.format, "format", "base64-lines", "input format: base64-lines, hex-lines, or raw")
	flags.BoolVar(&opts.mergeExisting, "merge", true, "merge records with an existing observations file")
	flags.UintVar(&opts.defaultTTL, "default-ttl", 0, "TTL seconds to apply to answers that do not carry a positive TTL")
	flags.StringVar(&opts.observedAtValue, "observed-at", "", "observation time in RFC3339; defaults to current time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if opts.outputPath == "" {
		return fmt.Errorf("-observations or NETLOOM_DNS_OBSERVATIONS_FILE is required")
	}
	if opts.defaultTTL > uint(^uint32(0)) {
		return fmt.Errorf("-default-ttl exceeds uint32")
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

	merged := records
	if opts.mergeExisting {
		existing, err := loadExisting(opts.outputPath)
		if err != nil {
			return err
		}
		merged, err = control.MergeDNSRecords(existing, records)
		if err != nil {
			return err
		}
	}
	if err := writeObservations(opts.outputPath, merged); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "netloom-dns-observer observed packets=%d records=%d written=%d\n", len(packets), len(records), len(merged))
	return nil
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

func loadExisting(path string) ([]model.DNSRecord, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return control.LoadDNSObservationsJSON(file)
}

func writeObservations(path string, records []model.DNSRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
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
	return os.Rename(tmpPath, path)
}
