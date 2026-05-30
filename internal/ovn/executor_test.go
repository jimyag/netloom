package ovn_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimyag/netloom/internal/control"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/ovn"
)

func TestRecorderExecutorRecordsDeepCopies(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	ops := []ovn.Operation{{Command: "lr-add", Args: []string{"lr0"}}}
	if err := recorder.Execute(context.Background(), ops); err != nil {
		t.Fatal(err)
	}
	ops[0].Args[0] = "mutated"

	recorded := recorder.Operations()
	if recorded[0].Args[0] != "lr0" {
		t.Fatalf("recorded op was mutated: %+v", recorded[0])
	}
}

func TestBackendExecutesPlannedOperations(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	if err := backend.EnsureVPC(context.Background(), model.VPC{Name: "prod"}); err != nil {
		t.Fatal(err)
	}
	recorded := recorder.Operations()
	if len(recorded) != 2 {
		t.Fatalf("recorded ops = %d, want 2", len(recorded))
	}
	if recorded[0].Command != "lr-add" || recorded[0].Flags[0] != "--may-exist" || recorded[0].Args[0] != "nl_lr_prod" {
		t.Fatalf("recorded op = %+v, want --may-exist lr-add nl_lr_prod", recorded[0])
	}
	if recorded[1].Command != "set" || recorded[1].Args[2] != "external_ids:netloom_owner=netloom" {
		t.Fatalf("recorded ownership op = %+v", recorded[1])
	}
}

func TestBackendPropagatesExecutorFailure(t *testing.T) {
	backend := ovn.NewBackend(failingExecutor{})
	err := backend.EnsureVPC(context.Background(), model.VPC{Name: "prod"})
	if err == nil {
		t.Fatal("expected executor failure")
	}
}

func TestBackendCleanupEmitsDeletesForStaleDesiredObjects(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.Endpoints = nil
	second.NATRules = nil
	second.LoadBalancers = nil
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--if-exists destroy DHCP_Options nl_lp_pod-a",
		"--if-exists lsp-del nl_lp_pod-a",
		"--if-exists lr-nat-del nl_lr_prod snat 10.10.0.0/24",
		"--if-exists lr-lb-del nl_lr_prod nl_lb_web",
		"--if-exists ls-lb-del nl_ls_apps nl_lb_web",
		"--if-exists lb-del nl_lb_web",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("cleanup operations missing %q:\n%s", expected, joined)
		}
	}
}

func TestBackendCleanupConvergesChangedLoadBalancerBindings(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.Subnets = append(first.Subnets, model.Subnet{
		Name:    "dmz",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("10.20.0.0/24"),
		Gateway: netip.MustParseAddr("10.20.0.1"),
	})
	first.LoadBalancers[0].Subnets = []string{"apps", "dmz"}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.LoadBalancers[0].VIP = netip.MustParseAddr("10.96.0.20")
	second.LoadBalancers[0].Backends = []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.12"), Port: 8080}}
	second.LoadBalancers[0].Subnets = []string{"apps"}
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--if-exists lb-del nl_lb_web 10.96.0.20:80",
		"--may-exist lb-add nl_lb_web 10.96.0.20:80 10.10.0.12:8080 tcp",
		"--if-exists lb-del nl_lb_web 10.96.0.10:80",
		"--if-exists ls-lb-del nl_ls_dmz nl_lb_web",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("load balancer convergence operation missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "--if-exists lb-del nl_lb_web\n") {
		t.Fatalf("changed load balancer must not delete the whole LB object:\n%s", joined)
	}
}

func TestBackendCleanupConvergesChangedNATRule(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.NATRules[0].ExternalIP = netip.MustParseAddr("198.51.100.50")
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--if-exists lr-nat-del nl_lr_prod snat 10.10.0.0/24",
		"--may-exist lr-nat-add nl_lr_prod snat 198.51.100.50 10.10.0.0/24",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("nat convergence operation missing %q:\n%s", expected, joined)
		}
	}
	if strings.Count(joined, "--if-exists lr-nat-del nl_lr_prod snat 10.10.0.0/24") < 2 {
		t.Fatalf("changed nat rule should clear the managed key before each add:\n%s", joined)
	}
}

func TestBackendCleanupConvergesChangedPolicyRoute(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.PolicyRoutes = []model.PolicyRoute{{
		Name:     "https-via-fw",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("172.16.0.0/16"),
			Protocol:    model.ProtocolTCP,
			DstPorts:    []model.PortRange{{From: 443, To: 443}},
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHop: netip.MustParseAddr("10.10.0.253")},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.PolicyRoutes[0].Action.NextHop = netip.MustParseAddr("10.10.0.252")
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--if-exists lr-policy-del nl_lr_prod 100",
		"--may-exist lr-policy-add nl_lr_prod 100",
		"reroute 10.10.0.252",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("policy route convergence operation missing %q:\n%s", expected, joined)
		}
	}
	if strings.Count(joined, "--if-exists lr-policy-del nl_lr_prod 100") < 2 {
		t.Fatalf("changed policy route should clear the managed key before each add:\n%s", joined)
	}
}

func TestBackendCleanupConvergesChangedStaticRoute(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.RouteTables = []model.RouteTable{{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			NextHop:     netip.MustParseAddr("10.10.0.254"),
		}},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.RouteTables[0].Routes[0].NextHop = netip.MustParseAddr("10.10.0.253")
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--if-exists lr-route-del nl_lr_prod 0.0.0.0/0",
		"--may-exist lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.253",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("static route convergence operation missing %q:\n%s", expected, joined)
		}
	}
	if strings.Count(joined, "--if-exists lr-route-del nl_lr_prod 0.0.0.0/0") < 2 {
		t.Fatalf("changed static route should clear the managed destination before each add:\n%s", joined)
	}
}

func TestBackendCleanupConvergesChangedStaticRouteToECMP(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.RouteTables = []model.RouteTable{{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			NextHop:     netip.MustParseAddr("10.10.0.254"),
		}},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.RouteTables[0].Routes[0].NextHop = netip.Addr{}
	second.RouteTables[0].Routes[0].NextHops = []netip.Addr{
		netip.MustParseAddr("10.10.0.253"),
		netip.MustParseAddr("10.10.0.254"),
	}
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--if-exists lr-route-del nl_lr_prod 0.0.0.0/0",
		"--may-exist --ecmp lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.253",
		"--may-exist --ecmp lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.254",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("static ECMP convergence operation missing %q:\n%s", expected, joined)
		}
	}
}

func TestBackendCleanupRemovesGatewayMetadata(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.Gateways = nil
	second.Endpoints = nil
	second.NATRules = nil
	second.LoadBalancers = nil
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"remove logical_router nl_lr_prod external_ids netloom_gateway",
		"remove logical_router nl_lr_prod external_ids netloom_external_if",
		"remove logical_router nl_lr_prod external_ids netloom_gateway_lan_ip",
		"remove logical_router nl_lr_prod external_ids netloom_gateway_distributed",
		"remove logical_router nl_lr_prod options chassis",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("cleanup operations missing %q:\n%s", expected, joined)
		}
	}
}

func TestBackendCleanupDeletesLocalnetPortWithSubnet(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.Subnets = nil
	second.Endpoints = nil
	second.NATRules = nil
	second.LoadBalancers = nil
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--if-exists lsp-del nl_ls_apps_to_apps_localnet",
		"--if-exists ls-del nl_ls_apps",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("cleanup operations missing %q:\n%s", expected, joined)
		}
	}
}

func TestNBCTLExecutorBatchesOperationsIntoTransaction(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{
		{Command: "lr-add", Flags: []string{"--may-exist"}, Args: []string{"nl_lr_prod"}},
		{Command: "set", Args: []string{"logical_router", "nl_lr_prod", "external_ids:netloom_owner=netloom"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(raw)), "\n")
	want := []string{
		"--db=unix:/tmp/ovnnb.sock",
		"--may-exist",
		"lr-add",
		"nl_lr_prod",
		"--",
		"set",
		"logical_router",
		"nl_lr_prod",
		"external_ids:netloom_owner=netloom",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestNBCTLExecutorSplitsNATAddAfterDelete(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := "#!/bin/sh\nprintf '%s\\n' '---' >> " + argsFile + "\nprintf '%s\\n' \"$@\" >> " + argsFile + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{
		{Command: "lr-nat-del", Flags: []string{"--if-exists"}, Args: []string{"nl_lr_prod", "snat", "10.10.0.0/24"}},
		{Command: "lr-nat-add", Flags: []string{"--may-exist"}, Args: []string{"nl_lr_prod", "snat", "198.51.100.50", "10.10.0.0/24"}},
		{Command: "set", Args: []string{"logical_router", "nl_lr_prod", "external_ids:netloom_owner=netloom"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimPrefix(strings.TrimSpace(string(raw)), "---\n"), "\n---\n")
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want delete and add batches:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "lr-nat-del\nnl_lr_prod\nsnat\n10.10.0.0/24") {
		t.Fatalf("first call should delete NAT before add:\n%s", calls[0])
	}
	if strings.Contains(calls[0], "lr-nat-add") {
		t.Fatalf("first transaction must not include lr-nat-add:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "lr-nat-add\nnl_lr_prod\nsnat\n198.51.100.50\n10.10.0.0/24") {
		t.Fatalf("second call should add replacement NAT:\n%s", calls[1])
	}
	if !strings.Contains(calls[1], "--\nset\nlogical_router\nnl_lr_prod") {
		t.Fatalf("second transaction should keep following operations batched:\n%s", calls[1])
	}
}

type failingExecutor struct{}

func (failingExecutor) Execute(context.Context, []ovn.Operation) error {
	return errors.New("boom")
}

func controlStateWithEndpoint(endpointID string) control.DesiredState {
	return control.DesiredState{
		VPCs: []model.VPC{{Name: "prod"}},
		Subnets: []model.Subnet{{
			Name:            "apps",
			VPC:             "prod",
			CIDR:            netip.MustParsePrefix("10.10.0.0/24"),
			Gateway:         netip.MustParseAddr("10.10.0.1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
			DHCP:            model.DHCPOptions{Enabled: true, LeaseTime: 7200, MTU: 1400},
		}},
		Endpoints: []model.Endpoint{{
			ID:     endpointID,
			VPC:    "prod",
			Subnet: "apps",
			IP:     netip.MustParseAddr("10.10.0.10"),
			Node:   "node-a",
		}},
		NATRules: []model.NATRule{{
			Name:       "egress",
			VPC:        "prod",
			Type:       model.ActionSNAT,
			MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
			ExternalIP: netip.MustParseAddr("198.51.100.10"),
		}},
		Gateways: []model.Gateway{{
			Name:       "gw-a",
			VPC:        "prod",
			Node:       "node-a",
			ExternalIF: "eth0",
			LANIP:      netip.MustParseAddr("10.10.0.254"),
		}},
		LoadBalancers: []model.LoadBalancer{{
			Name:     "web",
			VPC:      "prod",
			VIP:      netip.MustParseAddr("10.96.0.10"),
			Port:     80,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{
				IP:   netip.MustParseAddr("10.10.0.10"),
				Port: 8080,
			}},
			Subnets: []string{"apps"},
		}},
	}
}

func stringifyOVNOps(ops []ovn.Operation) string {
	lines := make([]string, 0, len(ops))
	for _, op := range ops {
		lines = append(lines, op.String())
	}
	return strings.Join(lines, "\n")
}
