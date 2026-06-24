package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jimyag/netloom/internal/agent"
	"github.com/jimyag/netloom/internal/dataplane"
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
		PolicyMapPressureEndpoint:  "prod\x00pod-a",
		PolicyMapPressureEndpoints: 0,
		PolicyPressureMitigated:    2,
		PolicyMapDriftEndpoints:    1,
		PolicyMapDriftMissing:      2,
		PolicyMapDriftExtra:        3,
		PolicyMapDriftChanged:      4,
		PolicyFailedEndpoint:       "prod\x00pod-b",
		PolicyFailedRevision:       3,
		PolicyRulePackets:          3,
		PolicyRuleBytes:            384,
		PolicyRuleAllowed:          2,
		PolicyRuleDropped:          1,
		PolicyRuleLogged:           1,
		PolicyRuleStats: []dataplane.RuleMetrics{
			{EndpointID: "prod\x00pod-a", RuleCookie: 7, Packets: 1, Bytes: 256, Dropped: 1, DenyDrops: 1},
			{EndpointID: "prod\x00pod-a", RuleCookie: 42, Packets: 2, Bytes: 128, Allowed: 2, Logged: 1},
		},
		TCXFailedTarget:  "iface=eth0 direction=ingress attach=2",
		ProviderNetworks: 1,
		ProviderLinks:    2,
		ProviderReady:    1,
		ProviderDegraded: 1,
		ProviderStatus: []linuxdatapath.ProviderLinkStatus{
			{ProviderNetwork: "physnet-a", ParentDevice: "eth1", VLAN: 100, LinkName: "nlv-a", Ready: true, ParentState: "up", LinkState: "up"},
			{ProviderNetwork: "physnet-b", ParentDevice: "bond0", VLAN: 200, LinkName: "nlv-b", Ready: false, ParentState: "up", LinkState: "down"},
		},
		ProviderNetworkStatus: []linuxdatapath.ProviderNetworkStatus{
			{ProviderNetwork: "physnet-a", Ready: true, LinkCount: 1, ReadyLinks: 1, IssueCount: 0},
			{ProviderNetwork: "physnet-b", Ready: false, LinkCount: 1, ReadyLinks: 0, IssueCount: 1, Reasons: []string{"type-mismatch"}},
		},
		ProviderInventoryTotal:    3,
		ProviderInventoryReady:    2,
		ProviderInventoryDegraded: 1,
		ProviderInventoryStatus: []linuxdatapath.ProviderInterface{
			{Name: "eth1", Ready: true, State: "up"},
			{Name: "bond0", Ready: true, State: "up"},
			{Name: "ens5", Ready: false, State: "down"},
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
		`policy_map_pressure_endpoint="prod\x00pod-a"`,
		"policy_map_pressure_endpoints=0",
		"policy_pressure_mitigated=2",
		"policy_map_drift_endpoints=1",
		"policy_map_drift_missing=2",
		"policy_map_drift_extra=3",
		"policy_map_drift_changed=4",
		`policy_failed_endpoint="prod\x00pod-b"`,
		"policy_failed_revision=3",
		"policy_rule_packets=3",
		"policy_rule_bytes=384",
		"policy_rule_allowed=2",
		"policy_rule_dropped=1",
		"policy_rule_rejected=0",
		"policy_rule_logged=1",
		`policy_rule_stats="prod\x00pod-a"/7:p=1,b=256,a=0,d=1,r=0,nm=0,ct=0,est=0,log=0;"prod\x00pod-a"/42:p=2,b=128,a=2,d=0,r=0,nm=0,ct=0,est=0,log=1`,
		`tcx_failed_target="iface=eth0 direction=ingress attach=2"`,
		"provider_networks=1",
		"provider_links=2",
		"provider_ready=1",
		"provider_degraded=1",
		"provider_status=physnet-a:eth1:100:nlv-a:ready:up:up,physnet-b:bond0:200:nlv-b:pending:up:down",
		"provider_network_status=physnet-a:ready:1/1:0:none,physnet-b:degraded:0/1:1:type-mismatch",
		"provider_inventory_total=3",
		"provider_inventory_ready=2",
		"provider_inventory_degraded=1",
		"provider_inventory_status=eth1:up,bond0:up,ens5:down",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output missing %q:\n%s", expected, output)
		}
	}
}
