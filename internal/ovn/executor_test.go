package ovn_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestBackendSerializesConcurrentApplyBatches(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	var wg sync.WaitGroup
	for _, vpc := range []string{"prod", "stage", "dev"} {
		wg.Add(1)
		go func(vpc string) {
			defer wg.Done()
			if err := backend.EnsureVPC(context.Background(), model.VPC{Name: vpc}); err != nil {
				t.Errorf("ensure vpc %s: %v", vpc, err)
			}
		}(vpc)
	}
	wg.Wait()

	joined := stringifyOVNOps(recorder.Operations())
	for _, router := range []string{"nl_lr_prod", "nl_lr_stage", "nl_lr_dev"} {
		if got := strings.Count(joined, "--may-exist lr-add "+router); got != 1 {
			t.Fatalf("router %s lr-add count = %d, want 1:\n%s", router, got, joined)
		}
	}
	if got := len(backend.Operations()); got != len(recorder.Operations()) {
		t.Fatalf("backend operations = %d, recorder operations = %d", got, len(recorder.Operations()))
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
		"gc-dhcp-options pod-a",
		"--if-exists lsp-del nl_lp_pod-a",
		"--if-exists lr-nat-del nl_lr_prod snat 10.10.0.0/24",
		"gc-load-balancer-health-checks web",
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
	second.LoadBalancers[0].Ports[0].Backends = []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.12"), Port: 8080}}
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

func TestBackendCleanupDoesNotReapplyUnchangedLoadBalancer(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--if-exists lb-del nl_lb_web 10.96.0.10:80",
		"--may-exist lb-add nl_lb_web 10.96.0.10:80 10.10.0.10:8080 tcp",
		"--may-exist lr-lb-add nl_lr_prod nl_lb_web",
		"--may-exist ls-lb-add nl_ls_apps nl_lb_web",
	} {
		if got := strings.Count(joined, expected); got != 1 {
			t.Fatalf("unchanged load balancer op %q count = %d, want one initial apply:\n%s", expected, got, joined)
		}
	}
}

func TestBackendReappliesLoadBalancerWhenDefaultHealthCheckEnabled(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.LoadBalancers[0].HealthCheck = model.LoadBalancerHealthCheck{Enabled: true}
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	if got := strings.Count(joined, "create Load_Balancer_Health_Check"); got != 1 {
		t.Fatalf("health check create count = %d, want one enable apply:\n%s", got, joined)
	}
	if !strings.Contains(joined, "--id=@nl_lbhc_web_tcp_80 create Load_Balancer_Health_Check vip=10.96.0.10:80") {
		t.Fatalf("default health check create missing:\n%s", joined)
	}
	if got := strings.Count(joined, "--may-exist lb-add nl_lb_web 10.96.0.10:80 10.10.0.10:8080 tcp"); got != 2 {
		t.Fatalf("load balancer frontend apply count = %d, want initial and health-check enable apply:\n%s", got, joined)
	}
}

func TestBackendCleanupReappliesChangedLoadBalancerBackends(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.LoadBalancers[0].Ports[0].Backends = []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.12"), Port: 8080}}
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--may-exist lb-add nl_lb_web 10.96.0.10:80 10.10.0.10:8080 tcp",
		"--may-exist lb-add nl_lb_web 10.96.0.10:80 10.10.0.12:8080 tcp",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("changed load balancer backend operation missing %q:\n%s", expected, joined)
		}
	}
	if got := strings.Count(joined, "--if-exists lb-del nl_lb_web 10.96.0.10:80"); got != 2 {
		t.Fatalf("changed load balancer frontend delete count = %d, want initial and changed apply:\n%s", got, joined)
	}
}

func TestBackendSnapshotIsNotMutatedByCallerAfterReconcile(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.RouteTables = []model.RouteTable{{
		Name: "default",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
		}},
	}}
	second.PolicyRoutes = []model.PolicyRoute{{
		Name:     "force-private",
		VPC:      "prod",
		Priority: 100,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("172.16.0.0/16"),
		},
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	}}
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	third := second
	third.RouteTables[0].Routes[0].NextHops[0] = netip.MustParseAddr("10.10.0.252")
	third.PolicyRoutes[0].Action.NextHops[0] = netip.MustParseAddr("10.10.0.252")
	third.LoadBalancers[0].Ports[0].Backends[0].IP = netip.MustParseAddr("10.10.0.12")
	if err := controller.Reconcile(context.Background(), third); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--if-exists lr-route-del nl_lr_prod 0.0.0.0/0",
		"--if-exists lr-policy-del nl_lr_prod 100",
		"--may-exist lb-add nl_lb_web 10.96.0.10:80 10.10.0.12:8080 tcp",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("snapshot mutation regression operation missing %q:\n%s", expected, joined)
		}
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
	if got := strings.Count(joined, "--if-exists lr-nat-del nl_lr_prod snat 10.10.0.0/24"); got != 1 {
		t.Fatalf("changed nat rule delete count = %d, want one lifecycle cleanup before replacement:\n%s", got, joined)
	}
}

func TestBackendCleanupDoesNotReapplyUnchangedNATRule(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	if strings.Contains(joined, "lr-nat-del") {
		t.Fatalf("unchanged nat rule should not be deleted:\n%s", joined)
	}
	expected := "--may-exist lr-nat-add nl_lr_prod snat 198.51.100.10 10.10.0.0/24"
	if got := strings.Count(joined, expected); got != 1 {
		t.Fatalf("unchanged nat rule add count = %d, want one initial add for %q:\n%s", got, expected, joined)
	}
}

func TestBackendCleanupDoesNotRecreateUnchangedTranslatedDNATRule(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	state.NATRules = []model.NATRule{{
		Name:         "web-translate",
		VPC:          "prod",
		Type:         model.ActionDNAT,
		ExternalIP:   netip.MustParseAddr("198.51.100.80"),
		TargetIP:     netip.MustParseAddr("10.10.0.10"),
		Protocol:     model.ProtocolTCP,
		ExternalPort: 8443,
		TargetPort:   443,
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	if !strings.Contains(joined, "gc-nat-rule web-translate\n--id=@nl_nat_web_htranslate create NAT") {
		t.Fatalf("translated dnat should GC existing managed NAT before create:\n%s", joined)
	}
	expected := "--id=@nl_nat_web_htranslate create NAT type=dnat external_ip=198.51.100.80 logical_ip=10.10.0.10 external_port_range=8443 logical_port_range=443 protocol=tcp"
	if got := strings.Count(joined, expected); got != 1 {
		t.Fatalf("unchanged translated dnat create count = %d, want one initial create:\n%s", got, joined)
	}
	if got := strings.Count(joined, "gc-nat-rule web-translate"); got != 1 {
		t.Fatalf("unchanged translated dnat GC count = %d, want one initial GC before create:\n%s", got, joined)
	}
	if strings.Contains(joined, "lr-nat-del") {
		t.Fatalf("unchanged translated dnat should not be deleted:\n%s", joined)
	}
}

func TestBackendCleanupReplacesChangedTranslatedDNATRule(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.NATRules = []model.NATRule{{
		Name:         "web-translate",
		VPC:          "prod",
		Type:         model.ActionDNAT,
		ExternalIP:   netip.MustParseAddr("198.51.100.80"),
		TargetIP:     netip.MustParseAddr("10.10.0.10"),
		Protocol:     model.ProtocolTCP,
		ExternalPort: 8443,
		TargetPort:   443,
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.NATRules[0].TargetIP = netip.MustParseAddr("10.10.0.11")
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"gc-nat-rule web-translate",
		"create NAT type=dnat external_ip=198.51.100.80 logical_ip=10.10.0.10",
		"create NAT type=dnat external_ip=198.51.100.80 logical_ip=10.10.0.11",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("changed translated dnat operation missing %q:\n%s", expected, joined)
		}
	}
	if got := strings.Count(joined, "gc-nat-rule web-translate"); got != 3 {
		t.Fatalf("changed translated dnat GC count = %d, want initial create, lifecycle cleanup, and replacement create GC:\n%s", got, joined)
	}
	if strings.Contains(joined, "lr-nat-del nl_lr_prod dnat 198.51.100.80") {
		t.Fatalf("translated dnat cleanup must not delete all NAT entries for the external IP:\n%s", joined)
	}
}

func TestBackendCleanupRemovesTranslatedDNATRule(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.NATRules = []model.NATRule{{
		Name:         "web-translate",
		VPC:          "prod",
		Type:         model.ActionDNAT,
		ExternalIP:   netip.MustParseAddr("198.51.100.80"),
		TargetIP:     netip.MustParseAddr("10.10.0.10"),
		Protocol:     model.ProtocolTCP,
		ExternalPort: 8443,
		TargetPort:   443,
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.NATRules = nil
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--id=@nl_nat_web_htranslate create NAT type=dnat external_ip=198.51.100.80 logical_ip=10.10.0.10 external_port_range=8443 logical_port_range=443 protocol=tcp",
		"add logical_router nl_lr_prod nat @nl_nat_web_htranslate",
		"gc-nat-rule web-translate",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("translated DNAT cleanup operation missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "nl_natlb_web_translate") {
		t.Fatalf("translated DNAT must not create load balancer cleanup operations:\n%s", joined)
	}
}

func TestBackendCleanupChangedPortDNATDoesNotDeleteSiblingExternalIPRules(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.NATRules = []model.NATRule{{
		Name:         "web",
		VPC:          "prod",
		Type:         model.ActionDNAT,
		ExternalIP:   netip.MustParseAddr("198.51.100.80"),
		TargetIP:     netip.MustParseAddr("10.10.0.10"),
		Protocol:     model.ProtocolTCP,
		ExternalPort: 8443,
		TargetPort:   8443,
	}, {
		Name:         "ssh",
		VPC:          "prod",
		Type:         model.ActionDNAT,
		ExternalIP:   netip.MustParseAddr("198.51.100.80"),
		TargetIP:     netip.MustParseAddr("10.10.0.10"),
		Protocol:     model.ProtocolTCP,
		ExternalPort: 2222,
		TargetPort:   22,
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.NATRules[0].TargetIP = netip.MustParseAddr("10.10.0.11")
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	if strings.Contains(joined, "lr-nat-del nl_lr_prod dnat 198.51.100.80") {
		t.Fatalf("changed port DNAT should not delete sibling DNAT rules sharing the external IP:\n%s", joined)
	}
	if got := strings.Count(joined, "gc-nat-rule web"); got != 3 {
		t.Fatalf("changed port DNAT GC count = %d, want initial create, lifecycle cleanup, and replacement create GC:\n%s", got, joined)
	}
	if got := strings.Count(joined, "external_ids:netloom_nat=ssh"); got != 1 {
		t.Fatalf("unchanged sibling DNAT should not be recreated or removed, create count = %d:\n%s", got, joined)
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
		Action: model.RouteAction{Type: model.ActionReroute, NextHops: []netip.Addr{netip.MustParseAddr("10.10.0.253")}},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.PolicyRoutes[0].Action.NextHops = []netip.Addr{netip.MustParseAddr("10.10.0.252")}
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
	if strings.Count(joined, "--if-exists lr-policy-del nl_lr_prod 100") != 1 {
		t.Fatalf("changed policy route should clear the managed key once:\n%s", joined)
	}
}

func TestBackendCleanupDoesNotDeleteUnchangedPolicyRoute(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	state.PolicyRoutes = []model.PolicyRoute{{
		Name:     "allow-api",
		VPC:      "prod",
		Priority: 300,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("198.51.100.10/32"),
			Protocol:    model.ProtocolTCP,
			DstPorts:    []model.PortRange{{From: 443, To: 443}},
		},
		Action: model.RouteAction{Type: model.ActionAllow},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	if strings.Contains(joined, "lr-policy-del nl_lr_prod 300") {
		t.Fatalf("unchanged allow policy route should not be deleted:\n%s", joined)
	}
	if got := strings.Count(joined, "--may-exist lr-policy-add nl_lr_prod 300"); got != 1 {
		t.Fatalf("unchanged policy route add count = %d, want one initial apply:\n%s", got, joined)
	}
}

func TestBackendCleanupDoesNotRecreateUnchangedECMPPolicyRoute(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	state.PolicyRoutes = []model.PolicyRoute{{
		Name:     "centralized-egress",
		VPC:      "prod",
		Priority: 300,
		Match:    model.RouteMatch{Source: netip.MustParsePrefix("10.10.0.0/24")},
		Action: model.RouteAction{
			Type: model.ActionReroute,
			NextHops: []netip.Addr{
				netip.MustParseAddr("10.10.0.253"),
				netip.MustParseAddr("10.10.0.254"),
			},
		},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	if got := strings.Count(joined, "create Logical_Router_Policy priority=300"); got != 1 {
		t.Fatalf("unchanged ECMP policy route create count = %d, want one initial apply:\n%s", got, joined)
	}
	if got := strings.Count(joined, "lr-policy-del nl_lr_prod 300 ip4.src == 10.10.0.0/24"); got != 1 {
		t.Fatalf("unchanged ECMP policy route delete count = %d, want one initial planner guard:\n%s", got, joined)
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
			NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
		}},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.RouteTables[0].Routes[0].NextHops = []netip.Addr{netip.MustParseAddr("10.10.0.253")}
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
	if strings.Count(joined, "--if-exists lr-route-del nl_lr_prod 0.0.0.0/0") != 1 {
		t.Fatalf("changed static route should clear the managed destination once:\n%s", joined)
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
			NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
		}},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.RouteTables[0].Routes[0].NextHops = nil
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

func TestBackendCleanupAddsECMPNextHopWithoutDeletingExistingRoutes(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.RouteTables = []model.RouteTable{{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			NextHops: []netip.Addr{
				netip.MustParseAddr("10.10.0.253"),
				netip.MustParseAddr("10.10.0.254"),
			},
		}},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.RouteTables[0].Routes[0].NextHops = append(second.RouteTables[0].Routes[0].NextHops, netip.MustParseAddr("10.10.0.252"))
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	if strings.Contains(joined, "lr-route-del nl_lr_prod 0.0.0.0/0") {
		t.Fatalf("adding ECMP next hop should not delete existing route destination:\n%s", joined)
	}
	expected := "--may-exist --ecmp lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.252"
	if !strings.Contains(joined, expected) {
		t.Fatalf("added ECMP next hop operation missing %q:\n%s", expected, joined)
	}
}

func TestBackendCleanupRemovesOnlyStaleECMPNextHop(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.RouteTables = []model.RouteTable{{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			NextHops: []netip.Addr{
				netip.MustParseAddr("10.10.0.252"),
				netip.MustParseAddr("10.10.0.253"),
				netip.MustParseAddr("10.10.0.254"),
			},
		}},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.RouteTables[0].Routes[0].NextHops = []netip.Addr{
		netip.MustParseAddr("10.10.0.253"),
		netip.MustParseAddr("10.10.0.254"),
	}
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	expected := "--if-exists lr-route-del nl_lr_prod 0.0.0.0/0 10.10.0.252"
	if !strings.Contains(joined, expected) {
		t.Fatalf("stale ECMP next hop delete missing %q:\n%s", expected, joined)
	}
	if strings.Contains(joined, "--if-exists lr-route-del nl_lr_prod 0.0.0.0/0\n") {
		t.Fatalf("removing one ECMP next hop should not delete the whole destination:\n%s", joined)
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

func TestNBCTLExecutorDestroysRecordsMatchedByExternalIDs(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"--columns=_uuid find DHCP_Options"*) printf 'uuid-a\nuuid-b\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{
		{Command: "set", Args: []string{"logical_switch_port", "nl_lp_pod-a", "dhcpv4_options=[]"}},
		{Command: "gc-dhcp-options", Args: []string{"pod-a"}},
		{Command: "lsp-del", Flags: []string{"--if-exists"}, Args: []string{"nl_lp_pod-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimPrefix(strings.TrimSpace(string(raw)), "---\n"), "\n---\n")
	if len(calls) != 5 {
		t.Fatalf("calls = %d, want clear, find, two destroys, lsp-del:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "set\nlogical_switch_port\nnl_lp_pod-a") {
		t.Fatalf("first call should clear references before GC:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "--columns=_uuid\nfind\nDHCP_Options") ||
		!strings.Contains(calls[1], "external_ids:netloom_endpoint=pod-a") {
		t.Fatalf("second call should find DHCP options by ownership:\n%s", calls[1])
	}
	if !strings.Contains(calls[2], "destroy\nDHCP_Options\nuuid-a") ||
		!strings.Contains(calls[3], "destroy\nDHCP_Options\nuuid-b") {
		t.Fatalf("matching DHCP options should be destroyed:\n%s", raw)
	}
	if !strings.Contains(calls[4], "lsp-del\nnl_lp_pod-a") {
		t.Fatalf("final call should delete logical switch port:\n%s", calls[4])
	}
}

func TestNBCTLExecutorDestroysLoadBalancerHealthChecksMatchedByExternalIDs(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"--columns=_uuid find Load_Balancer_Health_Check"*) printf 'hc-a\nhc-b\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{
		{Command: "clear", Args: []string{"load_balancer", "nl_lb_web", "health_check"}},
		{Command: "gc-load-balancer-health-checks", Args: []string{"web"}},
		{Command: "lb-del", Flags: []string{"--if-exists"}, Args: []string{"nl_lb_web"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimPrefix(strings.TrimSpace(string(raw)), "---\n"), "\n---\n")
	if len(calls) != 5 {
		t.Fatalf("calls = %d, want clear, find, two destroys, lb-del:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "clear\nload_balancer\nnl_lb_web\nhealth_check") {
		t.Fatalf("first call should clear health check references before GC:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "--columns=_uuid\nfind\nLoad_Balancer_Health_Check") ||
		!strings.Contains(calls[1], "external_ids:netloom_load_balancer=web") {
		t.Fatalf("second call should find LB health checks by ownership:\n%s", calls[1])
	}
	if !strings.Contains(calls[2], "destroy\nLoad_Balancer_Health_Check\nhc-a") ||
		!strings.Contains(calls[3], "destroy\nLoad_Balancer_Health_Check\nhc-b") {
		t.Fatalf("matching LB health checks should be destroyed:\n%s", raw)
	}
	if !strings.Contains(calls[4], "lb-del\nnl_lb_web") {
		t.Fatalf("final call should delete load balancer:\n%s", calls[4])
	}
}

func TestNBCTLExecutorDestroysNATRulesMatchedByExternalIDs(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"--columns=_uuid find NAT"*) printf 'nat-a\nnat-b\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{
		{Command: "gc-nat-rule", Args: []string{"web"}},
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
	if len(calls) != 4 {
		t.Fatalf("calls = %d, want find, two destroys, trailing set:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "--columns=_uuid\nfind\nNAT") ||
		!strings.Contains(calls[0], "external_ids:netloom_nat=web") {
		t.Fatalf("first call should find NAT records by ownership:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "destroy\nNAT\nnat-a") ||
		!strings.Contains(calls[2], "destroy\nNAT\nnat-b") {
		t.Fatalf("matching NAT records should be destroyed:\n%s", raw)
	}
	if !strings.Contains(calls[3], "set\nlogical_router\nnl_lr_prod") {
		t.Fatalf("trailing regular operation should still execute:\n%s", calls[3])
	}
}

func TestNBCTLExecutorAppliesDefaultCommandTimeout(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "ovn-nbctl")
	script := "#!/bin/sh\nexec sleep 1\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary)
	executor.Timeout = 20 * time.Millisecond
	start := time.Now()
	err := executor.Execute(context.Background(), []ovn.Operation{{Command: "show"}})
	if err == nil {
		t.Fatal("expected nbctl timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("timeout took %s, want command to be canceled promptly", elapsed)
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
			Name: "web",
			VPC:  "prod",
			VIP:  netip.MustParseAddr("10.96.0.10"),
			Ports: []model.LoadBalancerPort{{
				Port:     80,
				Protocol: model.ProtocolTCP,
				Backends: []model.LoadBalancerBackend{{
					IP:   netip.MustParseAddr("10.10.0.10"),
					Port: 8080,
				}},
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
