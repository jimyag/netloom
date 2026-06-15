package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jimyag/netloom/internal/agent"
)

func TestPrintReconcileResultReportsPolicyMapUsageSummary(t *testing.T) {
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = oldStdout
	}()

	printReconcileResult(agent.ReconcileResult{
		Node:                       "node-a",
		Endpoints:                  1,
		Programs:                   1,
		Entries:                    3,
		PolicyMapEntries:           12,
		PolicyMapCapacity:          16,
		PolicyMapPressureMax:       75,
		PolicyMapPressureEndpoints: 0,
		ProviderNetworks:           1,
		ProviderLinks:              2,
		Datapath:                   "not-requested",
		TCX:                        "not-requested",
	}, "ebpf")

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	for _, expected := range []string{
		"policy_map_entries=12",
		"policy_map_capacity=16",
		"policy_map_pressure_max=75",
		"policy_map_pressure_endpoints=0",
		"provider_networks=1",
		"provider_links=2",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output missing %q:\n%s", expected, output)
		}
	}
}
