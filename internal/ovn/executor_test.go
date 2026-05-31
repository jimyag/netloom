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
		"lsp-set-dhcpv4-options nl_lp_pod-a",
		"lsp-set-dhcpv6-options nl_lp_pod-a",
		"gc-dhcp-options pod-a",
		"--if-exists lsp-del nl_lp_pod-a",
		"--if-exists lr-nat-del nl_lr_prod snat 10.10.0.0/24",
		"gc-load-balancer-health-checks web prod",
		"--if-exists lr-lb-del nl_lr_prod nl_lb_prod_web_tcp",
		"--if-exists ls-lb-del nl_ls_apps nl_lb_prod_web_tcp",
		"--if-exists lb-del nl_lb_prod_web_tcp",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("cleanup operations missing %q:\n%s", expected, joined)
		}
	}
	clear := strings.Index(joined, "lsp-set-dhcpv4-options nl_lp_pod-a")
	gc := strings.Index(joined, "gc-dhcp-options pod-a")
	del := strings.Index(joined, "--if-exists lsp-del nl_lp_pod-a")
	if clear < 0 || gc < 0 || del < 0 || !(clear < gc && gc < del) {
		t.Fatalf("endpoint DHCP cleanup should clear references, GC options, then delete port:\n%s", joined)
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
		"--may-exist lb-add nl_lb_prod_web_tcp 10.96.0.20:80 10.10.0.12:8080 tcp",
		"--if-exists lb-del nl_lb_prod_web_tcp 10.96.0.10:80",
		"--if-exists ls-lb-del nl_ls_dmz nl_lb_prod_web_tcp",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("load balancer convergence operation missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "--if-exists lb-del nl_lb_prod_web_tcp\n") {
		t.Fatalf("changed load balancer must not delete the whole LB object:\n%s", joined)
	}
}

func TestBackendCleanupRemovesStaleLoadBalancerProtocolRows(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.LoadBalancers[0].HealthCheck = model.LoadBalancerHealthCheck{Enabled: true}
	first.LoadBalancers[0].Ports = append(first.LoadBalancers[0].Ports, model.LoadBalancerPort{
		Name:     "dns",
		Port:     53,
		Protocol: model.ProtocolUDP,
		Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 5353}},
	})
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.LoadBalancers[0].Ports = second.LoadBalancers[0].Ports[:1]
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--may-exist lb-add nl_lb_prod_web_tcp 10.96.0.10:80 10.10.0.10:8080 tcp",
		"--may-exist lb-add nl_lb_prod_web_udp 10.96.0.10:53 10.10.0.10:5353 udp",
		"clear load_balancer nl_lb_prod_web_udp health_check",
		"--if-exists lr-lb-del nl_lr_prod nl_lb_prod_web_udp",
		"--if-exists ls-lb-del nl_ls_apps nl_lb_prod_web_udp",
		"--if-exists lb-del nl_lb_prod_web_udp",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("load balancer protocol cleanup operation missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "--if-exists lb-del nl_lb_prod_web_tcp\n") {
		t.Fatalf("removing udp frontend must not delete tcp LB row:\n%s", joined)
	}
}

func TestBackendCleanupFailureDoesNotAdvanceSnapshot(t *testing.T) {
	executor := &failOnCommandExecutor{command: "lr-lb-del", fail: true}
	backend := ovn.NewBackend(executor)
	first := controlStateWithEndpoint("pod-a")
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.LoadBalancers = nil
	if err := controller.Reconcile(context.Background(), second); err == nil {
		t.Fatal("expected cleanup failure")
	}
	if got := executor.Count("lr-lb-del", "nl_lr_prod", "nl_lb_prod_web_tcp"); got != 1 {
		t.Fatalf("failed cleanup lr-lb-del count = %d, want 1", got)
	}

	executor.fail = false
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if got := executor.Count("lr-lb-del", "nl_lr_prod", "nl_lb_prod_web_tcp"); got != 2 {
		t.Fatalf("cleanup retry lr-lb-del count = %d, want failed attempt plus retry", got)
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
		"--may-exist lb-add nl_lb_prod_web_tcp 10.96.0.10:80 10.10.0.10:8080 tcp",
		"--may-exist lr-lb-add nl_lr_prod nl_lb_prod_web_tcp",
		"--may-exist ls-lb-add nl_ls_apps nl_lb_prod_web_tcp",
	} {
		if got := strings.Count(joined, expected); got != 1 {
			t.Fatalf("unchanged load balancer op %q count = %d, want one initial apply:\n%s", expected, got, joined)
		}
	}
}

func TestBackendDoesNotReapplyLoadBalancerWhenOnlyPortNameChanges(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.LoadBalancers[0].Ports[0].Name = "http"
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.LoadBalancers = append([]model.LoadBalancer(nil), first.LoadBalancers...)
	second.LoadBalancers[0].Ports = append([]model.LoadBalancerPort(nil), first.LoadBalancers[0].Ports...)
	second.LoadBalancers[0].Ports[0].Name = "public-http"
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--may-exist lb-add nl_lb_prod_web_tcp 10.96.0.10:80 10.10.0.10:8080 tcp",
		"--may-exist lr-lb-add nl_lr_prod nl_lb_prod_web_tcp",
		"--may-exist ls-lb-add nl_ls_apps nl_lb_prod_web_tcp",
	} {
		if got := strings.Count(joined, expected); got != 1 {
			t.Fatalf("port-name-only load balancer op %q count = %d, want one initial apply:\n%s", expected, got, joined)
		}
	}
}

func TestBackendDoesNotReapplyHealthCheckedLoadBalancerWhenPortsReordered(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.LoadBalancers[0].HealthCheck = model.LoadBalancerHealthCheck{Enabled: true}
	first.LoadBalancers[0].Ports = []model.LoadBalancerPort{
		{
			Name:     "http",
			Port:     80,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 8080}},
		},
		{
			Name:     "metrics",
			Port:     9090,
			Protocol: model.ProtocolTCP,
			Backends: []model.LoadBalancerBackend{{IP: netip.MustParseAddr("10.10.0.10"), Port: 9091}},
		},
	}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.LoadBalancers = append([]model.LoadBalancer(nil), first.LoadBalancers...)
	second.LoadBalancers[0].Ports = []model.LoadBalancerPort{
		first.LoadBalancers[0].Ports[1],
		first.LoadBalancers[0].Ports[0],
	}
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"--may-exist lb-add nl_lb_prod_web_tcp 10.96.0.10:80 10.10.0.10:8080 tcp",
		"--may-exist lb-add nl_lb_prod_web_tcp 10.96.0.10:9090 10.10.0.10:9091 tcp",
	} {
		if got := strings.Count(joined, expected); got != 1 {
			t.Fatalf("load balancer op %q count = %d, want one initial apply:\n%s", expected, got, joined)
		}
	}
	if got := strings.Count(joined, "ensure-load-balancer-health-check"); got != 2 {
		t.Fatalf("health check ensure count = %d, want one per frontend from initial apply:\n%s", got, joined)
	}
	if got := strings.Count(joined, "gc-stale-load-balancer-health-checks web"); got != 1 {
		t.Fatalf("stale health check GC count = %d, want one initial apply:\n%s", got, joined)
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
	if got := strings.Count(joined, "ensure-load-balancer-health-check"); got != 1 {
		t.Fatalf("health check ensure count = %d, want one enable apply:\n%s", got, joined)
	}
	if !strings.Contains(joined, "ensure-load-balancer-health-check nl_lb_prod_web_tcp web prod vip=10.96.0.10:80") {
		t.Fatalf("default health check ensure missing:\n%s", joined)
	}
	if got := strings.Count(joined, "--may-exist lb-add nl_lb_prod_web_tcp 10.96.0.10:80 10.10.0.10:8080 tcp"); got != 2 {
		t.Fatalf("load balancer frontend apply count = %d, want initial and health-check enable apply:\n%s", got, joined)
	}
	if strings.Contains(joined, "--if-exists lb-del nl_lb_prod_web_tcp 10.96.0.10:80") {
		t.Fatalf("health-check-only update should not delete unchanged LB VIP:\n%s", joined)
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
		"--may-exist lb-add nl_lb_prod_web_tcp 10.96.0.10:80 10.10.0.10:8080 tcp",
		"--may-exist lb-add nl_lb_prod_web_tcp 10.96.0.10:80 10.10.0.12:8080 tcp",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("changed load balancer backend operation missing %q:\n%s", expected, joined)
		}
	}
	if got := strings.Count(joined, "--if-exists lb-del nl_lb_prod_web_tcp 10.96.0.10:80"); got != 1 {
		t.Fatalf("changed load balancer frontend delete count = %d, want one lifecycle diff delete:\n%s", got, joined)
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
		"--may-exist lb-add nl_lb_prod_web_tcp 10.96.0.10:80 10.10.0.12:8080 tcp",
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

func TestBackendCleanupReplacesChangedTranslatedFloatingIPRule(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.NATRules = []model.NATRule{{
		Name:         "fip-translate",
		VPC:          "prod",
		Type:         model.ActionDNATSNAT,
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
	second.NATRules[0].TargetPort = 444
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	for _, expected := range []string{
		"gc-nat-rule fip-translate",
		"create NAT type=dnat_and_snat external_ip=198.51.100.80 logical_ip=10.10.0.10 external_port_range=8443 logical_port_range=443 protocol=tcp",
		"create NAT type=dnat_and_snat external_ip=198.51.100.80 logical_ip=10.10.0.10 external_port_range=8443 logical_port_range=444 protocol=tcp",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("changed translated floating ip operation missing %q:\n%s", expected, joined)
		}
	}
	if got := strings.Count(joined, "gc-nat-rule fip-translate"); got != 3 {
		t.Fatalf("changed translated floating ip GC count = %d, want initial create, lifecycle cleanup, and replacement create GC:\n%s", got, joined)
	}
	if strings.Contains(joined, "lr-nat-del nl_lr_prod dnat_and_snat 198.51.100.80") {
		t.Fatalf("translated floating ip cleanup must use managed NAT GC, not broad lr-nat-del:\n%s", joined)
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

func TestBackendFirstReconcileCleansStaleManagedNATRules(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	state.NATRules = []model.NATRule{{
		Name:         "web",
		VPC:          "prod",
		Type:         model.ActionDNAT,
		ExternalIP:   netip.MustParseAddr("198.51.100.80"),
		TargetIP:     netip.MustParseAddr("10.10.0.10"),
		Protocol:     model.ProtocolTCP,
		ExternalPort: 8443,
		TargetPort:   8443,
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	if !strings.Contains(joined, "gc-stale-nat-rules web") {
		t.Fatalf("first reconcile should clean stale managed NAT rules while keeping desired names:\n%s", joined)
	}
	staleGC := strings.Index(joined, "gc-stale-nat-rules web")
	createGC := strings.Index(joined, "gc-nat-rule web")
	if createGC < 0 || staleGC > createGC {
		t.Fatalf("stale NAT cleanup should run before per-rule create GC:\n%s", joined)
	}
}

func TestBackendFirstReconcileCleansStaleManagedPolicyRoutes(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	state.PolicyRoutes = []model.PolicyRoute{{
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
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	if !strings.Contains(joined, "gc-stale-policy-routes prod https-via-fw") {
		t.Fatalf("first reconcile should clean stale managed policy routes while keeping desired names:\n%s", joined)
	}
	staleGC := strings.Index(joined, "gc-stale-policy-routes prod https-via-fw")
	tag := strings.Index(joined, "tag-policy-route prod https-via-fw 100")
	if tag < 0 || staleGC > tag {
		t.Fatalf("stale policy route cleanup should run before desired policy tagging:\n%s", joined)
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
	second.Gateways = nil
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
		{Command: "clear", Args: []string{"load_balancer", "nl_lb_prod_web_tcp", "health_check"}},
		{Command: "gc-load-balancer-health-checks", Args: []string{"web", "prod"}},
		{Command: "lb-del", Flags: []string{"--if-exists"}, Args: []string{"nl_lb_prod_web_tcp"}},
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
	if !strings.Contains(calls[0], "clear\nload_balancer\nnl_lb_prod_web_tcp\nhealth_check") {
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
	if !strings.Contains(calls[4], "lb-del\nnl_lb_prod_web_tcp") {
		t.Fatalf("final call should delete load balancer:\n%s", calls[4])
	}
}

func TestNBCTLExecutorEnsuresExistingLoadBalancerHealthCheck(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"--columns=_uuid find Load_Balancer_Health_Check"*"vip=10.96.0.10:80"*) printf 'hc-existing\nhc-duplicate\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{
		Command: "ensure-load-balancer-health-check",
		Args: []string{
			"nl_lb_prod_web_tcp",
			"web",
			"prod",
			"vip=10.96.0.10:80",
			"options:interval=5",
			"options:timeout=20",
			"options:success_count=3",
			"options:failure_count=3",
			"external_ids:netloom_owner=netloom",
			"external_ids:netloom_load_balancer=web",
			"external_ids:netloom_vpc=prod",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimPrefix(strings.TrimSpace(string(raw)), "---\n"), "\n---\n")
	if len(calls) != 4 {
		t.Fatalf("calls = %d, want find, set, destroy duplicate, add:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "--columns=_uuid\nfind\nLoad_Balancer_Health_Check") ||
		!strings.Contains(calls[0], "external_ids:netloom_load_balancer=web") ||
		!strings.Contains(calls[0], "vip=10.96.0.10:80") {
		t.Fatalf("first call should find health check by owner and vip:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "set\nLoad_Balancer_Health_Check\nhc-existing") ||
		!strings.Contains(calls[1], "options:timeout=20") {
		t.Fatalf("second call should update existing health check:\n%s", calls[1])
	}
	if !strings.Contains(calls[2], "destroy\nLoad_Balancer_Health_Check\nhc-duplicate") {
		t.Fatalf("third call should destroy duplicate health check:\n%s", calls[2])
	}
	if !strings.Contains(calls[3], "add\nload_balancer\nnl_lb_prod_web_tcp\nhealth_check\nhc-existing") {
		t.Fatalf("final call should attach existing health check:\n%s", calls[3])
	}
}

func TestNBCTLExecutorCreatesMissingLoadBalancerHealthCheck(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"create Load_Balancer_Health_Check"*) printf 'hc-new\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{
		Command: "ensure-load-balancer-health-check",
		Args: []string{
			"nl_lb_prod_web_tcp",
			"web",
			"prod",
			"vip=10.96.0.10:80",
			"options:interval=5",
			"options:timeout=20",
			"options:success_count=3",
			"options:failure_count=3",
			"external_ids:netloom_owner=netloom",
			"external_ids:netloom_load_balancer=web",
			"external_ids:netloom_vpc=prod",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimPrefix(strings.TrimSpace(string(raw)), "---\n"), "\n---\n")
	if len(calls) != 3 {
		t.Fatalf("calls = %d, want find, create, add:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[1], "create\nLoad_Balancer_Health_Check") ||
		!strings.Contains(calls[1], "vip=10.96.0.10:80") {
		t.Fatalf("second call should create missing health check:\n%s", calls[1])
	}
	if !strings.Contains(calls[2], "add\nload_balancer\nnl_lb_prod_web_tcp\nhealth_check\nhc-new") {
		t.Fatalf("final call should attach created health check:\n%s", calls[2])
	}
}

func TestNBCTLExecutorDestroysStaleLoadBalancerHealthChecksByVIP(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"--columns=_uuid,vip find Load_Balancer_Health_Check"*) printf 'hc-keep,10.96.0.10:80\nhc-stale,10.96.0.10:9090\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{
		Command: "gc-stale-load-balancer-health-checks",
		Args:    []string{"web", "prod", "10.96.0.10:80"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimPrefix(strings.TrimSpace(string(raw)), "---\n"), "\n---\n")
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want find and one stale destroy:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "--columns=_uuid,vip\nfind\nLoad_Balancer_Health_Check") ||
		!strings.Contains(calls[0], "external_ids:netloom_load_balancer=web") {
		t.Fatalf("first call should find health checks by load balancer:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "destroy\nLoad_Balancer_Health_Check\nhc-stale") ||
		strings.Contains(calls[1], "hc-keep") {
		t.Fatalf("second call should destroy only stale health check:\n%s", calls[1])
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

func TestNBCTLExecutorDestroysOnlyStaleManagedNATRules(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"--columns=_uuid,external_ids find NAT"*)
    printf 'nat-keep,"{netloom_owner=netloom,netloom_nat=web}"\n'
    printf 'nat-stale,"{netloom_owner=netloom,netloom_nat=old}"\n'
    printf 'nat-missing,"{netloom_owner=netloom}"\n'
    ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{
		{Command: "gc-stale-nat-rules", Args: []string{"web"}},
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
	if len(calls) != 3 {
		t.Fatalf("calls = %d, want find, stale destroy, trailing set:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "--columns=_uuid,external_ids\nfind\nNAT") ||
		!strings.Contains(calls[0], "external_ids:netloom_owner=netloom") {
		t.Fatalf("first call should find managed NAT records with external IDs:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "destroy\nNAT\nnat-stale") {
		t.Fatalf("stale managed NAT should be destroyed:\n%s", raw)
	}
	if strings.Contains(string(raw), "destroy\nNAT\nnat-keep") {
		t.Fatalf("desired managed NAT must not be destroyed:\n%s", raw)
	}
	if strings.Contains(string(raw), "destroy\nNAT\nnat-missing") {
		t.Fatalf("managed NAT without netloom_nat identity must not be destroyed:\n%s", raw)
	}
	if !strings.Contains(calls[2], "set\nlogical_router\nnl_lr_prod") {
		t.Fatalf("trailing regular operation should still execute:\n%s", calls[2])
	}
}

func TestNBCTLExecutorTagsSingleHopPolicyRoutesByRouterPolicyMatch(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"get logical_router nl_lr_prod policies"*) printf '[policy-a, policy-b]\n' ;;
  *"get Logical_Router_Policy policy-a priority"*) printf '100\n' ;;
  *"get Logical_Router_Policy policy-a match"*) printf '"ip4.src == 10.10.0.0/24 && tcp && tcp.dst == 443"\n' ;;
  *"get Logical_Router_Policy policy-b priority"*) printf '100\n' ;;
  *"get Logical_Router_Policy policy-b match"*) printf '"ip4.src == 10.20.0.0/24"\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{
		{Command: "lr-policy-add", Flags: []string{"--may-exist"}, Args: []string{"nl_lr_prod", "100", "ip4.src == 10.10.0.0/24 && tcp && tcp.dst == 443", "reroute", "10.10.0.253"}},
		{Command: "tag-policy-route", Args: []string{"prod", "https-via-fw", "100", "ip4.src == 10.10.0.0/24 && tcp && tcp.dst == 443"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimPrefix(strings.TrimSpace(string(raw)), "---\n"), "\n---\n")
	if len(calls) != 7 {
		t.Fatalf("calls = %d, want add, router policies, two identity reads per policy, matching set:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "--may-exist\nlr-policy-add\nnl_lr_prod\n100") {
		t.Fatalf("first call should add policy before tagging:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "get\nlogical_router\nnl_lr_prod\npolicies") {
		t.Fatalf("second call should read router policy UUIDs:\n%s", calls[1])
	}
	if !strings.Contains(string(raw), "set\nLogical_Router_Policy\npolicy-a") ||
		!strings.Contains(string(raw), "external_ids:netloom_policy_route=https-via-fw") ||
		!strings.Contains(string(raw), "external_ids:netloom_vpc=prod") {
		t.Fatalf("matching policy should be tagged with netloom ownership:\n%s", raw)
	}
	if strings.Contains(string(raw), "set\nLogical_Router_Policy\npolicy-b") {
		t.Fatalf("non-matching router policy must not be tagged:\n%s", raw)
	}
}

func TestNBCTLExecutorDestroysOnlyStaleManagedPolicyRoutes(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"--columns=_uuid,external_ids find Logical_Router_Policy"*)
    printf 'policy-keep,"{netloom_owner=netloom,netloom_policy_route=https-via-fw,netloom_vpc=prod}"\n'
    printf 'policy-stale,"{netloom_owner=netloom,netloom_policy_route=old-fw,netloom_vpc=prod}"\n'
    printf 'policy-missing,"{netloom_owner=netloom,netloom_vpc=prod}"\n'
    ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{
		{Command: "gc-stale-policy-routes", Args: []string{"prod", "https-via-fw"}},
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
		t.Fatalf("calls = %d, want find, stale remove, stale destroy, trailing set:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "--columns=_uuid,external_ids\nfind\nLogical_Router_Policy") ||
		!strings.Contains(calls[0], "external_ids:netloom_owner=netloom") {
		t.Fatalf("first call should find managed logical router policies:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "remove\nlogical_router\nnl_lr_prod\npolicies\npolicy-stale") ||
		!strings.Contains(calls[2], "destroy\nLogical_Router_Policy\npolicy-stale") {
		t.Fatalf("stale managed policy should be removed from router and destroyed:\n%s", raw)
	}
	if strings.Contains(string(raw), "destroy\nLogical_Router_Policy\npolicy-keep") ||
		strings.Contains(string(raw), "destroy\nLogical_Router_Policy\npolicy-missing") {
		t.Fatalf("desired or unidentified policies must not be destroyed:\n%s", raw)
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

type failOnCommandExecutor struct {
	command string
	fail    bool
	ops     []ovn.Operation
}

func (e *failOnCommandExecutor) Execute(_ context.Context, ops []ovn.Operation) error {
	e.ops = append(e.ops, cloneTestOperations(ops)...)
	if !e.fail {
		return nil
	}
	for _, op := range ops {
		if op.Command == e.command {
			return errors.New("boom")
		}
	}
	return nil
}

func (e *failOnCommandExecutor) Count(command string, args ...string) int {
	count := 0
	for _, op := range e.ops {
		if op.Command != command {
			continue
		}
		if len(args) > len(op.Args) {
			continue
		}
		matched := true
		for i, arg := range args {
			if op.Args[i] != arg {
				matched = false
				break
			}
		}
		if matched {
			count++
		}
	}
	return count
}

func cloneTestOperations(ops []ovn.Operation) []ovn.Operation {
	cloned := make([]ovn.Operation, len(ops))
	for i, op := range ops {
		cloned[i] = ovn.Operation{
			Command: op.Command,
			Flags:   append([]string(nil), op.Flags...),
			Args:    append([]string(nil), op.Args...),
		}
	}
	return cloned
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
