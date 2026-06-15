package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jimyag/netloom/internal/agent"
	"github.com/jimyag/netloom/internal/linuxdatapath"
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
		ProviderReady:              1,
		ProviderDegraded:           1,
		ProviderStatus: []linuxdatapath.ProviderLinkStatus{
			{ProviderNetwork: "physnet-a", ParentDevice: "eth1", VLAN: 100, LinkName: "nlv-a", Ready: true, ParentState: "up", LinkState: "up"},
			{ProviderNetwork: "physnet-b", ParentDevice: "bond0", VLAN: 200, LinkName: "nlv-b", Ready: false, ParentState: "up", LinkState: "down"},
		},
		Datapath: "not-requested",
		TCX:      "not-requested",
	}, "ebpf", 250*time.Millisecond)

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
		"provider_ready=1",
		"provider_degraded=1",
		"provider_status=physnet-a:eth1:100:nlv-a:ready:up:up,physnet-b:bond0:200:nlv-b:pending:up:down",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output missing %q:\n%s", expected, output)
		}
	}
}
