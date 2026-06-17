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

func TestBackendRetainsPlannedOperationsWhenExecutorFails(t *testing.T) {
	backend := ovn.NewBackend(failingExecutor{})
	err := backend.EnsureVPC(context.Background(), model.VPC{Name: "prod"})
	if err == nil {
		t.Fatal("expected executor failure")
	}
	joined := stringifyOVNOps(backend.Operations())
	for _, expected := range []string{
		"--may-exist lr-add nl_lr_prod",
		"set logical_router nl_lr_prod external_ids:netloom_owner=netloom",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("failed planner state missing %q:\n%s", expected, joined)
		}
	}
}

func TestBackendCapsRecordedOperationHistory(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	for i := 0; i < 2500; i++ {
		if err := backend.EnsureVPC(context.Background(), model.VPC{Name: fmt.Sprintf("vpc-%d", i)}); err != nil {
			t.Fatalf("ensure vpc %d: %v", i, err)
		}
	}
	if got := len(recorder.Operations()); got != 5000 {
		t.Fatalf("recorder ops = %d, want 5000", got)
	}
	if got := len(backend.Operations()); got != 4096 {
		t.Fatalf("backend history ops = %d, want capped 4096", got)
	}
	joined := stringifyOVNOps(backend.Operations())
	if strings.Contains(joined, "nl_lr_vpc-0") {
		t.Fatalf("capped history should drop oldest operations:\n%s", joined)
	}
	if !strings.Contains(joined, "nl_lr_vpc-2499") {
		t.Fatalf("capped history should retain newest operations:\n%s", joined)
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
		"lsp-set-dhcpv4-options nl_lp_prod_pod-a",
		"lsp-set-dhcpv6-options nl_lp_prod_pod-a",
		"gc-dhcp-options " + endpointExternalID("prod", "pod-a") + " prod",
		"--if-exists lsp-del nl_lp_prod_pod-a",
		"--if-exists lr-nat-del nl_lr_prod snat 10.10.0.0/24",
		"gc-load-balancer-health-checks web prod",
		"--if-exists lr-lb-del nl_lr_prod nl_lb_prod_web_tcp",
		"--if-exists ls-lb-del nl_ls_prod_apps nl_lb_prod_web_tcp",
		"--if-exists lb-del nl_lb_prod_web_tcp",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("cleanup operations missing %q:\n%s", expected, joined)
		}
	}
	clear := strings.Index(joined, "lsp-set-dhcpv4-options nl_lp_prod_pod-a")
	gc := strings.Index(joined, "gc-dhcp-options "+endpointExternalID("prod", "pod-a")+" prod")
	del := strings.Index(joined, "--if-exists lsp-del nl_lp_prod_pod-a")
	if clear < 0 || gc < 0 || del < 0 || !(clear < gc && gc < del) {
		t.Fatalf("endpoint DHCP cleanup should clear references, GC options, then delete port:\n%s", joined)
	}
	stats := backend.LastCleanupStats()
	if stats.FirstReconcileGC {
		t.Fatalf("cleanup stats first reconcile GC = true after second reconcile: %+v", stats)
	}
	if stats.StaleEndpoints != 1 || stats.StaleNATRules != 1 || stats.StaleLoadBalancers != 1 {
		t.Fatalf("cleanup stats = %+v, want stale endpoint/nat/lb", stats)
	}
	if stats.TotalStaleObjects() < 3 {
		t.Fatalf("cleanup total stale objects = %d, want at least 3: %+v", stats.TotalStaleObjects(), stats)
	}
	if stats.Operations == 0 {
		t.Fatalf("cleanup operations = 0, want destructive cleanup stats: %+v", stats)
	}
}

func TestBackendCleanupStatsTrackChangedRoutesAndNATRules(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	first := controlStateWithEndpoint("pod-a")
	first.RouteTables = []model.RouteTable{{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("203.0.113.0/24"),
			NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
		}},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.RouteTables[0].Routes[0].NextHops = []netip.Addr{netip.MustParseAddr("10.10.0.253")}
	second.NATRules[0].ExternalIP = netip.MustParseAddr("198.51.100.20")
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	stats := backend.LastCleanupStats()
	if stats.ChangedRoutes != 1 || stats.ChangedNATRules != 1 {
		t.Fatalf("cleanup stats = %+v, want changed route and NAT rule", stats)
	}
	if stats.TotalChangedObjects() < 2 {
		t.Fatalf("cleanup total changed objects = %d, want at least 2: %+v", stats.TotalChangedObjects(), stats)
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
		"--if-exists ls-lb-del nl_ls_prod_dmz nl_lb_prod_web_tcp",
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
	forbidden := []string{
		"--if-exists lb-del nl_lb_prod_web_udp 10.96.0.10:53",
	}
	for _, expected := range []string{
		"--may-exist lb-add nl_lb_prod_web_tcp 10.96.0.10:80 10.10.0.10:8080 tcp",
		"--may-exist lb-add nl_lb_prod_web_udp 10.96.0.10:53 10.10.0.10:5353 udp",
		"clear load_balancer nl_lb_prod_web_udp health_check",
		"--if-exists lr-lb-del nl_lr_prod nl_lb_prod_web_udp",
		"--if-exists ls-lb-del nl_ls_prod_apps nl_lb_prod_web_udp",
		"--if-exists lb-del nl_lb_prod_web_udp",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("load balancer protocol cleanup operation missing %q:\n%s", expected, joined)
		}
	}
	for _, unexpected := range forbidden {
		if strings.Contains(joined, unexpected) {
			t.Fatalf("unexpected stale front-end delete for removed protocol: %q\n%s", unexpected, joined)
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
		"--may-exist ls-lb-add nl_ls_prod_apps nl_lb_prod_web_tcp",
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
		"--may-exist ls-lb-add nl_ls_prod_apps nl_lb_prod_web_tcp",
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
	if !strings.Contains(joined, "ensure-load-balancer-health-check nl_lb_prod_web_tcp web prod vip=\"10.96.0.10:80\"") {
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

func TestBackendReconcileIsIdempotentAcrossUnchangedTopology(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	baselineLen := len(recorder.Operations())
	if baselineLen == 0 {
		t.Fatal("expected first reconcile to produce operations")
	}

	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	secondPass := recorder.Operations()[baselineLen:]
	secondPassOperations := stringifyOVNOps(secondPass)
	for _, line := range strings.Split(strings.TrimSpace(secondPassOperations), "\n") {
		cmd := strings.TrimSpace(line)
		switch {
		case cmd == "":
			continue
		case strings.HasPrefix(cmd, "create "):
			t.Fatalf("idempotent reconcile should not emit create:\n%s", secondPassOperations)
		case strings.HasPrefix(cmd, "destroy "):
			t.Fatalf("idempotent reconcile should not emit destroy:\n%s", secondPassOperations)
		case strings.HasPrefix(cmd, "lsp-del "):
			t.Fatalf("idempotent reconcile should not emit unconditional lsp-del:\n%s", secondPassOperations)
		case strings.HasPrefix(cmd, "ls-del "):
			t.Fatalf("idempotent reconcile should not emit ls-del:\n%s", secondPassOperations)
		case strings.HasPrefix(cmd, "lrp-del "):
			t.Fatalf("idempotent reconcile should not emit lrp-del:\n%s", secondPassOperations)
		case strings.Contains(cmd, "lr-route-del "):
			t.Fatalf("idempotent reconcile should not emit lr-route-del:\n%s", secondPassOperations)
		case strings.Contains(cmd, "lr-nat-del "):
			t.Fatalf("idempotent reconcile should not emit lr-nat-del:\n%s", secondPassOperations)
		case strings.Contains(cmd, "lb-del "):
			t.Fatalf("idempotent reconcile should not emit lb-del:\n%s", secondPassOperations)
		case strings.Contains(cmd, "lr-lb-del "):
			t.Fatalf("idempotent reconcile should not emit lr-lb-del:\n%s", secondPassOperations)
		case strings.Contains(cmd, "ls-lb-del "):
			t.Fatalf("idempotent reconcile should not emit ls-lb-del:\n%s", secondPassOperations)
		case strings.HasPrefix(cmd, "gc-"):
			t.Fatalf("idempotent reconcile should not emit gc command:\n%s", secondPassOperations)
		case strings.Contains(cmd, "tag-policy-route "):
			t.Fatalf("idempotent reconcile should not emit route cleanup:\n%s", secondPassOperations)
		}
	}
}

func TestBackendFirstReconcileCleanupGCNotRepeatedOnUnchangedState(t *testing.T) {
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
	state.PolicyRoutes = []model.PolicyRoute{{
		Name:     "egress-egress",
		VPC:      "prod",
		Priority: 300,
		Match: model.RouteMatch{
			Source:      netip.MustParsePrefix("10.10.0.0/24"),
			Destination: netip.MustParsePrefix("10.245.0.0/24"),
			Protocol:    model.ProtocolTCP,
			DstPorts:    []model.PortRange{{From: 443, To: 443}},
		},
		Action: model.RouteAction{Type: model.ActionAllow},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	firstPass := stringifyOVNOps(recorder.Operations())
	if got := strings.Count(firstPass, "gc-stale-nat-rules prod web"); got != 1 {
		t.Fatalf("first reconcile stale NAT GC count = %d, want 1", got)
	}
	if got := strings.Count(firstPass, "gc-stale-policy-routes prod egress-egress"); got != 1 {
		t.Fatalf("first reconcile stale policy GC count = %d, want 1:\n%s", got, firstPass)
	}
	baselineLen := len(recorder.Operations())

	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	secondPass := stringifyOVNOps(recorder.Operations()[baselineLen:])
	if strings.Contains(secondPass, "gc-stale-nat-rules") {
		t.Fatalf("second reconcile must not rerun stale NAT GC:\n%s", secondPass)
	}
	if strings.Contains(secondPass, "gc-stale-policy-routes") {
		t.Fatalf("second reconcile must not rerun stale policy GC:\n%s", secondPass)
	}
}

func TestBackendRestoresTopologyStateForWarmRestart(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	topologyBackend := control.NewMemoryBackend()
	topologyController := control.NewController(topologyBackend, control.NewMemoryBackend())
	desired := controlStateWithEndpoint("pod-a")
	if err := topologyController.Reconcile(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	snapshot := topologyBackend.TopologyState()

	recovered := ovn.NewBackend(recorder)
	recovered.RestoreTopologyState(snapshot)
	recoveredController := control.NewController(recovered, control.NewMemoryBackend())
	if err := recoveredController.Reconcile(context.Background(), desired); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recovered.Operations())
	for _, forbidden := range []string{
		"lb-del",
		"lr-route-del",
		"lr-policy-del",
		"lr-nat-del",
		"ls-del",
		"lr-del",
		"gc-",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("restored topology should not emit destructive cleanup op %q:\n%s", forbidden, joined)
		}
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
		"--may-exist lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.252",
		"sync-policy-route-nexthop prod force-private 100 ip4.dst == 172.16.0.0/16 && ip4.src == 10.10.0.0/24 10.10.0.252",
		"--may-exist lb-add nl_lb_prod_web_tcp 10.96.0.10:80 10.10.0.12:8080 tcp",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("snapshot mutation regression operation missing %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "--if-exists lr-route-del nl_lr_prod 0.0.0.0/0") {
		t.Fatalf("snapshot mutation regression should not reintroduce route delete-before-add churn:\n%s", joined)
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

func TestBackendCleanupDoesNotReapplyUnchangedNATRuleAcrossVPCs(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	state.VPCs = append(state.VPCs, model.VPC{Name: "blue"})
	state.Subnets = append(state.Subnets,
		model.Subnet{
			Name:            "shared",
			VPC:             "blue",
			CIDR:            netip.MustParsePrefix("10.11.0.0/24"),
			Gateway:         netip.MustParseAddr("10.11.0.1"),
			ProviderNetwork: "physnet-a",
			VLAN:            100,
			DHCP:            model.DHCPOptions{Enabled: true, LeaseTime: 7200, MTU: 1400},
		},
	)
	state.Endpoints = append(state.Endpoints, model.Endpoint{
		ID:     "pod-b",
		VPC:    "blue",
		Subnet: "shared",
		IP:     netip.MustParseAddr("10.11.0.10"),
		Node:   "node-b",
	})
	state.Gateways = append(state.Gateways, model.Gateway{
		Name:       "gw-b",
		VPC:        "blue",
		Node:       "node-b",
		ExternalIF: "eth0",
		LANIP:      netip.MustParseAddr("10.11.0.254"),
	})
	state.NATRules = []model.NATRule{
		{
			Name:       "shared-egress",
			VPC:        "prod",
			Type:       model.ActionSNAT,
			MatchCIDR:  netip.MustParsePrefix("10.10.0.0/24"),
			ExternalIP: netip.MustParseAddr("198.51.100.10"),
		},
		{
			Name:       "shared-egress",
			VPC:        "blue",
			Type:       model.ActionSNAT,
			MatchCIDR:  netip.MustParsePrefix("10.11.0.0/24"),
			ExternalIP: netip.MustParseAddr("198.51.101.10"),
		},
	}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	if strings.Contains(joined, "lr-nat-del") {
		t.Fatalf("unchanged nat rules should not be deleted:\n%s", joined)
	}
	prodRule := "--may-exist lr-nat-add nl_lr_prod snat 198.51.100.10 10.10.0.0/24"
	if got := strings.Count(joined, prodRule); got != 1 {
		t.Fatalf("prod unchanged nat rule add count = %d, want one initial add:\n%s", got, joined)
	}
	blueRule := "--may-exist lr-nat-add nl_lr_blue snat 198.51.101.10 10.11.0.0/24"
	if got := strings.Count(joined, blueRule); got != 1 {
		t.Fatalf("blue unchanged nat rule add count = %d, want one initial add:\n%s", got, joined)
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
	if !strings.Contains(joined, "gc-nat-rule web-translate prod\n--id=@nl_nat_prod_web_htranslate create NAT") {
		t.Fatalf("translated dnat should GC existing managed NAT before create:\n%s", joined)
	}
	expected := "--id=@nl_nat_prod_web_htranslate create NAT type=dnat external_ip=198.51.100.80 logical_ip=10.10.0.10 external_port_range=8443 logical_port_range=443 protocol=tcp"
	if got := strings.Count(joined, expected); got != 1 {
		t.Fatalf("unchanged translated dnat create count = %d, want one initial create:\n%s", got, joined)
	}
	if got := strings.Count(joined, "gc-nat-rule web-translate prod"); got != 1 {
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
		"gc-nat-rule web-translate prod",
		"create NAT type=dnat external_ip=198.51.100.80 logical_ip=10.10.0.10",
		"create NAT type=dnat external_ip=198.51.100.80 logical_ip=10.10.0.11",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("changed translated dnat operation missing %q:\n%s", expected, joined)
		}
	}
	if got := strings.Count(joined, "gc-nat-rule web-translate prod"); got != 3 {
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
		"gc-nat-rule fip-translate prod",
		"create NAT type=dnat_and_snat external_ip=198.51.100.80 logical_ip=10.10.0.10 external_port_range=8443 logical_port_range=443 protocol=tcp",
		"create NAT type=dnat_and_snat external_ip=198.51.100.80 logical_ip=10.10.0.10 external_port_range=8443 logical_port_range=444 protocol=tcp",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("changed translated floating ip operation missing %q:\n%s", expected, joined)
		}
	}
	if got := strings.Count(joined, "gc-nat-rule fip-translate prod"); got != 3 {
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
		"--id=@nl_nat_prod_web_htranslate create NAT type=dnat external_ip=198.51.100.80 logical_ip=10.10.0.10 external_port_range=8443 logical_port_range=443 protocol=tcp",
		"add logical_router nl_lr_prod nat @nl_nat_prod_web_htranslate",
		"gc-nat-rule web-translate prod",
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
	if got := strings.Count(joined, "gc-nat-rule web prod"); got != 3 {
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
	if !strings.Contains(joined, "gc-stale-nat-rules prod web") {
		t.Fatalf("first reconcile should clean stale managed NAT rules while keeping desired names:\n%s", joined)
	}
	staleGC := strings.Index(joined, "gc-stale-nat-rules prod web")
	createGC := strings.Index(joined, "gc-nat-rule web prod")
	if createGC < 0 || staleGC > createGC {
		t.Fatalf("stale NAT cleanup should run before per-rule create GC:\n%s", joined)
	}
}

func TestBackendFirstReconcileCleansStaleDHCPOptions(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	expected := "gc-stale-dhcp-options " + endpointExternalID("prod", "pod-a") + " prod"
	if !strings.Contains(joined, expected) {
		t.Fatalf("first reconcile should clean stale DHCP options while keeping desired endpoint rows:\n%s", joined)
	}
	staleGC := strings.Index(joined, expected)
	createGC := strings.Index(joined, "gc-dhcp-options "+endpointExternalID("prod", "pod-a")+" prod")
	if createGC < 0 || staleGC > createGC {
		t.Fatalf("stale DHCP cleanup should run before per-endpoint DHCP GC/create:\n%s", joined)
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
		"sync-policy-route-nexthop prod https-via-fw 100 ip4.dst == 172.16.0.0/16 && ip4.src == 10.10.0.0/24 && tcp && tcp.dst == 443 10.10.0.252",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("policy route convergence operation missing %q:\n%s", expected, joined)
		}
	}
	if strings.Count(joined, "--if-exists lr-policy-del nl_lr_prod 100 ip4.src == 10.10.0.0/24") != 0 {
		t.Fatalf("changed single-hop policy route should not be deleted, should sync nexthop:\n%s", joined)
	}
}

func TestBackendCleanupConvergesChangedECMPPolicyRouteNexthops(t *testing.T) {
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

	second := state
	second.PolicyRoutes[0].Action.NextHops[0] = netip.MustParseAddr("10.10.0.252")
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	if strings.Contains(joined, "--if-exists lr-policy-del nl_lr_prod 300 ip4.src == 10.10.0.0/24") {
		t.Fatalf("changed ECMP policy route should not be deleted, should sync nexthops:\n%s", joined)
	}
	if !strings.Contains(joined, "sync-policy-route-nexthops prod centralized-egress 300") {
		t.Fatalf("changed ECMP policy route convergence operation missing sync op:\n%s", joined)
	}
	if !strings.Contains(joined, "[\"10.10.0.252\",\"10.10.0.254\"]") {
		t.Fatalf("ECMP policy route nexthops set should target 252 and 254:\n%s", joined)
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
	if got := strings.Count(joined, "ensure-policy-route-nexthops prod centralized-egress 300 ip4.src == 10.10.0.0/24 [\"10.10.0.253\",\"10.10.0.254\"]"); got != 1 {
		t.Fatalf("unchanged ECMP policy route ensure count = %d, want one initial apply:\n%s", got, joined)
	}
	if strings.Contains(joined, "create Logical_Router_Policy priority=300") || strings.Contains(joined, "lr-policy-del nl_lr_prod 300 ip4.src == 10.10.0.0/24") {
		t.Fatalf("unchanged ECMP policy route should not be deleted and recreated on first reconcile:\n%s", joined)
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
	expected := "--may-exist lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.253"
	if !strings.Contains(joined, expected) {
		t.Fatalf("static route convergence operation missing %q:\n%s", expected, joined)
	}
	if strings.Contains(joined, "--if-exists lr-route-del nl_lr_prod 0.0.0.0/0") {
		t.Fatalf("single static route change should use lr-route-add --may-exist update without deleting the destination:\n%s", joined)
	}
}

func TestBackendCleanupConvergesChangedStaticRouteToECMPByReplacingAll(t *testing.T) {
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
	if strings.Contains(joined, "--if-exists lr-route-del nl_lr_prod 0.0.0.0/0\n") {
		t.Fatalf("changing single route to ECMP should prefer additive conversion, not full destination delete:\n%s", joined)
	}
	for _, expected := range []string{
		"--may-exist --ecmp lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.253",
		"--may-exist --ecmp lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.254",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("static ECMP convergence operation missing %q:\n%s", expected, joined)
		}
	}
}

func TestBackendCleanupConvergesSingleRouteToECMPByReplacingHop(t *testing.T) {
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
	second.RouteTables[0].Routes[0].NextHops = []netip.Addr{
		netip.MustParseAddr("10.10.0.252"),
	}
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	expected := "--may-exist lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.252"
	if !strings.Contains(joined, expected) {
		t.Fatalf("single-to-single replacement route conversion missing %q:\n%s", expected, joined)
	}
	if strings.Contains(joined, "--if-exists lr-route-del nl_lr_prod 0.0.0.0/0") {
		t.Fatalf("single-to-single replacement should not delete the destination before update:\n%s", joined)
	}
}

func TestBackendCleanupConvergesECMPRouteToSingleByRemovingStaleNexthop(t *testing.T) {
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
			},
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
	expectedDelete := "--if-exists lr-route-del nl_lr_prod 0.0.0.0/0 10.10.0.252"
	if !strings.Contains(joined, expectedDelete) {
		t.Fatalf("stale nexthop delete operation missing %q:\n%s", expectedDelete, joined)
	}
	if strings.Contains(joined, "--if-exists lr-route-del nl_lr_prod 0.0.0.0/0\n") {
		t.Fatalf("ecmp to single route converge should not delete destination once stale nexthops can be removed:\n%s", joined)
	}
	if strings.Count(joined, expectedDelete) != 1 {
		t.Fatalf("stale nexthop delete count = %d, want 1:\n%s", strings.Count(joined, expectedDelete), joined)
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

func TestBackendDoesNotReapplyUnchangedStaticRouteTable(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	state.RouteTables = []model.RouteTable{{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			NextHops:    []netip.Addr{netip.MustParseAddr("10.10.0.254")},
		}},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	baseline := len(recorder.Operations())
	if baseline == 0 {
		t.Fatal("first reconcile should emit operations")
	}

	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	joined := stringifyOVNOps(recorder.Operations()[baseline:])
	forbidden := []string{
		"--may-exist lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.254",
		"--if-exists lr-route-del nl_lr_prod 0.0.0.0/0",
		"--if-exists lr-route-del nl_lr_prod 0.0.0.0/0 10.10.0.254",
	}
	for _, op := range forbidden {
		if strings.Contains(joined, op) {
			t.Fatalf("unchanged static route table should not be replayed, found: %q\n%s", op, joined)
		}
	}
}

func TestBackendDoesNotReapplyUnchangedECMPStaticRouteTable(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	state.RouteTables = []model.RouteTable{{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			NextHops: []netip.Addr{
				netip.MustParseAddr("10.10.0.252"),
				netip.MustParseAddr("10.10.0.253"),
			},
		}},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	baseline := len(recorder.Operations())

	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	joined := stringifyOVNOps(recorder.Operations()[baseline:])
	forbidden := []string{
		"--may-exist --ecmp lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.252",
		"--may-exist --ecmp lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.253",
		"--if-exists lr-route-del nl_lr_prod 0.0.0.0/0",
	}
	for _, op := range forbidden {
		if strings.Contains(joined, op) {
			t.Fatalf("unchanged ECMP static route table should not be replayed, found: %q\n%s", op, joined)
		}
	}
}

func TestBackendDoesNotReapplyReorderedECMPNextHops(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	state.RouteTables = []model.RouteTable{{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			NextHops: []netip.Addr{
				netip.MustParseAddr("10.10.0.252"),
				netip.MustParseAddr("10.10.0.253"),
			},
		}},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	baseline := len(recorder.Operations())
	if baseline == 0 {
		t.Fatal("first reconcile should emit operations")
	}

	state.RouteTables[0].Routes[0].NextHops = []netip.Addr{
		netip.MustParseAddr("10.10.0.253"),
		netip.MustParseAddr("10.10.0.252"),
	}
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	joined := stringifyOVNOps(recorder.Operations()[baseline:])
	forbidden := []string{
		"--may-exist --ecmp lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.252",
		"--may-exist --ecmp lr-route-add nl_lr_prod 0.0.0.0/0 10.10.0.253",
		"--if-exists lr-route-del nl_lr_prod 0.0.0.0/0 ",
		"--if-exists lr-route-del nl_lr_prod 0.0.0.0/0 10.10.0.252",
		"--if-exists lr-route-del nl_lr_prod 0.0.0.0/0 10.10.0.253",
	}
	for _, op := range forbidden {
		if strings.Contains(joined, op) {
			t.Fatalf("reordered ECMP next hops should be treated unchanged, found: %q\n%s", op, joined)
		}
	}
}

func TestBackendDoesNotReapplyUnchangedIPv6ECMPStaticRouteTable(t *testing.T) {
	recorder := ovn.NewRecorderExecutor()
	backend := ovn.NewBackend(recorder)
	state := controlStateWithEndpoint("pod-a")
	state.Subnets = append(state.Subnets, model.Subnet{
		Name:    "vip6",
		VPC:     "prod",
		CIDR:    netip.MustParsePrefix("2001:db8::/64"),
		Gateway: netip.MustParseAddr("2001:db8::1"),
	})
	state.RouteTables = []model.RouteTable{{
		Name: "main",
		VPC:  "prod",
		Routes: []model.Route{{
			Destination: netip.MustParsePrefix("2001:db8::/64"),
			NextHops: []netip.Addr{
				netip.MustParseAddr("2001:db8::252"),
				netip.MustParseAddr("2001:db8::253"),
			},
		}},
	}}
	controller := control.NewController(backend, control.NewMemoryBackend())
	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	baseline := len(recorder.Operations())
	if baseline == 0 {
		t.Fatal("first reconcile should emit operations")
	}

	if err := controller.Reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	joined := stringifyOVNOps(recorder.Operations()[baseline:])
	forbidden := []string{
		"--may-exist --ecmp lr-route-add nl_lr_prod 2001:db8::/64 2001:db8::252",
		"--may-exist --ecmp lr-route-add nl_lr_prod 2001:db8::/64 2001:db8::253",
		"--if-exists lr-route-del nl_lr_prod 2001:db8::/64",
	}
	for _, op := range forbidden {
		if strings.Contains(joined, op) {
			t.Fatalf("unchanged IPv6 ECMP static route table should not be replayed, found: %q\n%s", op, joined)
		}
	}
}

func TestBackendDeletesRoutesThatAreRemovedFromRouteTable(t *testing.T) {
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
	second.RouteTables = nil
	if err := controller.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	joined := stringifyOVNOps(recorder.Operations())
	expected := "--if-exists lr-route-del nl_lr_prod 0.0.0.0/0"
	if !strings.Contains(joined, expected) {
		t.Fatalf("route removal should delete stale route entry, expected %q in operations\n%s", expected, joined)
	}

	if got := strings.Count(joined, expected); got != 1 {
		t.Fatalf("route removal should emit one stale delete, got %d", got)
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
		"--if-exists lsp-del nl_ls_prod_apps_to_apps_localnet",
		"--if-exists ls-del nl_ls_prod_apps",
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

func TestNBCTLExecutorFallsBackFromRangeToPortColumns(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
if printf '%%s\n' "$*" | grep -q 'logical_port_range'; then
	echo "ovn-nbctl: Error: NAT does not contain a column whose name matches \"logical_port_range\"" >&2
	exit 1
fi
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{
		Command: "create",
		Flags:   []string{"--id=nat-ssh"},
		Args: []string{
			"NAT",
			"type=dnat",
			"external_ip=198.51.100.40",
			"logical_ip=10.10.0.12",
			"external_port_range=2222",
			"logical_port_range=2222",
			"protocol=tcp",
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
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want first failed attempt plus fallback retry:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "logical_port_range=2222") {
		t.Fatalf("first call should use managed NAT range columns:\n%s", calls[0])
	}
	if strings.Contains(calls[0], "logical_port=") {
		t.Fatalf("first call must not already use fallback names:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "external_port=2222") ||
		!strings.Contains(calls[1], "logical_port=2222") {
		t.Fatalf("retry call should fall back to legacy NAT column names:\n%s", calls[1])
	}
	if strings.Contains(calls[1], "external_port_range=2222") || strings.Contains(calls[1], "logical_port_range=2222") {
		t.Fatalf("retry call should not contain range column names:\n%s", calls[1])
	}
}

func TestNBCTLExecutorFallsBackWhenProtocolIsUnsupported(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
if printf '%%s\n' "$*" | grep -q 'logical_port_range'; then
	echo "ovn-nbctl: Error: NAT does not contain a column whose name matches \"logical_port_range\"" >&2
	exit 1
fi
if printf '%%s\n' "$*" | grep -q 'protocol='; then
	echo "ovn-nbctl: Error: column \"protocol\" not found in table NAT" >&2
	exit 1
fi
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{
		Command: "create",
		Flags:   []string{"--id=nat-ssh"},
		Args: []string{
			"NAT",
			"type=dnat",
			"external_ip=198.51.100.40",
			"logical_ip=10.10.0.12",
			"external_port_range=2222",
			"logical_port_range=2222",
			"protocol=tcp",
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
		t.Fatalf("calls = %d, want range fallback then protocol fallback:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[1], "external_port=2222") ||
		!strings.Contains(calls[1], "logical_port=2222") {
		t.Fatalf("first retry should convert ranges:\n%s", calls[1])
	}
	if !strings.Contains(calls[2], "external_port=2222") ||
		!strings.Contains(calls[2], "logical_port=2222") {
		t.Fatalf("second retry should keep translated ports:\n%s", calls[2])
	}
	if strings.Contains(calls[2], "protocol=") {
		t.Fatalf("second retry should drop unsupported protocol:\n%s", calls[2])
	}
}

func TestNBCTLExecutorRetriesTransientErrors(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	stateFile := filepath.Join(dir, "state")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
state="%s"
attempt=0
if [ -f "$state" ]; then
  attempt=$(cat "$state")
fi
attempt=$((attempt + 1))
echo "$attempt" > "$state"
printf '%%s\n' "$attempt" >> %q
printf '%%s\n' "$@" >> %q
if [ "$attempt" -eq 1 ]; then
  echo "ovn-nbctl: Error: database is busy" >&2
  exit 1
fi
`, stateFile, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	executor.Timeout = 5 * time.Second
	executor.RetryPolicy = ovn.NBCTLRetryPolicy{Attempts: 2, InitialBackoff: 1 * time.Millisecond, MaxBackoff: 1 * time.Millisecond}
	err := executor.Execute(context.Background(), []ovn.Operation{{Command: "show"}})
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	raw, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "2" {
		t.Fatalf("retry attempts did not run correctly: %s", raw)
	}
	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimSpace(string(args)), "\n")
	if len(calls) != 6 {
		t.Fatalf("commands = %d, want 2 attempts with 3 output lines each (attempt + 2 args): %v", len(calls), calls)
	}
}

func TestNBCTLExecutorRetriesSocketReconnectErrors(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	stateFile := filepath.Join(dir, "state")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
state="%s"
attempt=0
if [ -f "$state" ]; then
  attempt=$(cat "$state")
fi
attempt=$((attempt + 1))
echo "$attempt" > "$state"
printf '%%s\n' "$attempt" >> %q
printf '%%s\n' "$@" >> %q
if [ "$attempt" -eq 1 ]; then
  echo "ovn-nbctl: unix:/var/run/ovn/ovnnb_db.sock: database connection failed (No such file or directory)" >&2
  exit 1
fi
`, stateFile, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	executor.Timeout = 5 * time.Second
	executor.RetryPolicy = ovn.NBCTLRetryPolicy{Attempts: 2, InitialBackoff: 1 * time.Millisecond, MaxBackoff: 1 * time.Millisecond}
	err := executor.Execute(context.Background(), []ovn.Operation{{Command: "show"}})
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	raw, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "2" {
		t.Fatalf("retry attempts did not run correctly: %s", raw)
	}
	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimSpace(string(args)), "\n")
	if len(calls) != 6 {
		t.Fatalf("commands = %d, want 2 attempts with 3 output lines each (attempt + 2 args): %v", len(calls), calls)
	}
}

func TestNBCTLExecutorStopsRetryingOnNonRetryableErrors(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	stateFile := filepath.Join(dir, "state")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
state="%s"
attempt=0
if [ -f "$state" ]; then
  attempt=$(cat "$state")
fi
attempt=$((attempt + 1))
echo "$attempt" > "$state"
printf '%%s\n' "$attempt" >> %q
printf '%%s\n' "$@" >> %q
echo "ovn-nbctl: Error: table Route already has field no such column" >&2
exit 1
`, stateFile, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	executor.Timeout = 5 * time.Second
	executor.RetryPolicy = ovn.NBCTLRetryPolicy{Attempts: 3, InitialBackoff: 1 * time.Millisecond, MaxBackoff: 1 * time.Millisecond}
	err := executor.Execute(context.Background(), []ovn.Operation{{Command: "show"}})
	if err == nil {
		t.Fatal("expected non-retryable error")
	}
	state, readErr := os.ReadFile(stateFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.TrimSpace(string(state)) != "1" {
		t.Fatalf("expected command to run once, got state: %q", strings.TrimSpace(string(state)))
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
		{Command: "set", Args: []string{"logical_switch_port", "nl_lp_prod_pod-a", "dhcpv4_options=[]"}},
		{Command: "gc-dhcp-options", Args: []string{endpointExternalID("prod", "pod-a"), "prod"}},
		{Command: "lsp-del", Flags: []string{"--if-exists"}, Args: []string{"nl_lp_prod_pod-a"}},
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
	if !strings.Contains(calls[0], "set\nlogical_switch_port\nnl_lp_prod_pod-a") {
		t.Fatalf("first call should clear references before GC:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "--columns=_uuid\nfind\nDHCP_Options") ||
		!strings.Contains(calls[1], "external_ids:netloom_endpoint="+endpointExternalID("prod", "pod-a")) ||
		!strings.Contains(calls[1], "external_ids:netloom_vpc=prod") {
		t.Fatalf("second call should find DHCP options by ownership:\n%s", calls[1])
	}
	if !strings.Contains(calls[2], "destroy\nDHCP_Options\nuuid-a") ||
		!strings.Contains(calls[3], "destroy\nDHCP_Options\nuuid-b") {
		t.Fatalf("matching DHCP options should be destroyed:\n%s", raw)
	}
	if !strings.Contains(calls[4], "lsp-del\nnl_lp_prod_pod-a") {
		t.Fatalf("final call should delete logical switch port:\n%s", calls[4])
	}
}

func TestNBCTLExecutorDestroysOnlyStaleManagedDHCPOptions(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	keepEndpoint := endpointExternalID("prod", "pod-a")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"--columns=_uuid,external_ids find DHCP_Options"*)
    printf 'dhcp-keep,{netloom_owner=netloom netloom_endpoint=%s netloom_vpc=prod}\n'
    printf 'dhcp-other-vpc,{netloom_owner=netloom netloom_endpoint=%s netloom_vpc=dev}\n'
    printf 'dhcp-stale,{netloom_owner=netloom netloom_endpoint=stale netloom_vpc=prod}\n'
    printf 'dhcp-missing,{netloom_owner=netloom}\n'
    ;;
esac
`, argsFile, argsFile, keepEndpoint, keepEndpoint)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{
		{Command: "gc-stale-dhcp-options", Args: []string{keepEndpoint, "prod"}},
		{Command: "set", Args: []string{"logical_switch_port", "nl_lp_prod_pod-a", "dhcpv4_options=[]"}},
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
	if !strings.Contains(calls[0], "--columns=_uuid,external_ids\nfind\nDHCP_Options") ||
		!strings.Contains(calls[0], "external_ids:netloom_owner=netloom") {
		t.Fatalf("first call should find managed DHCP options with external IDs:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "destroy\nDHCP_Options\ndhcp-other-vpc") ||
		!strings.Contains(calls[2], "destroy\nDHCP_Options\ndhcp-stale") {
		t.Fatalf("other-vpc same-endpoint and stale managed DHCP options should be destroyed:\n%s", raw)
	}
	if strings.Contains(string(raw), "destroy\nDHCP_Options\ndhcp-keep") {
		t.Fatalf("desired managed DHCP options must not be destroyed:\n%s", raw)
	}
	if strings.Contains(string(raw), "destroy\nDHCP_Options\ndhcp-missing") {
		t.Fatalf("managed DHCP options without endpoint identity must not be destroyed:\n%s", raw)
	}
	if !strings.Contains(calls[3], "set\nlogical_switch_port\nnl_lp_prod_pod-a") {
		t.Fatalf("trailing regular operation should still execute:\n%s", calls[3])
	}
}

func TestNBCTLExecutorDestroysDuplicateManagedDHCPOptionsEvenWhenKept(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	keepEndpoint := endpointExternalID("prod", "pod-a")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"--columns=_uuid,external_ids find DHCP_Options"*)
    printf 'dhcp-keep-a,{netloom_owner=netloom netloom_endpoint=%s netloom_vpc=prod}\n'
    printf 'dhcp-keep-b,{netloom_owner=netloom netloom_endpoint=%s netloom_vpc=prod}\n'
    ;;
esac
`, argsFile, argsFile, keepEndpoint, keepEndpoint)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{Command: "gc-stale-dhcp-options", Args: []string{keepEndpoint, "prod"}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "destroy\nDHCP_Options\ndhcp-keep-a") {
		t.Fatalf("first desired DHCP options row should be retained:\n%s", raw)
	}
	if !strings.Contains(text, "destroy\nDHCP_Options\ndhcp-keep-b") {
		t.Fatalf("duplicate desired DHCP options row should be destroyed:\n%s", raw)
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
			"vip=\"10.96.0.10:80\"",
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
			"vip=\"10.96.0.10:80\"",
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
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want find and create+add:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[1], "create\nLoad_Balancer_Health_Check") ||
		!strings.Contains(calls[1], "vip=\"10.96.0.10:80\"") ||
		!strings.Contains(calls[1], "--\nadd\nload_balancer\nnl_lb_prod_web_tcp\nhealth_check\n@netloom_lbhc") {
		t.Fatalf("second call should create and attach missing health check in one transaction:\n%s", calls[1])
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
		{Command: "gc-nat-rule", Args: []string{"web", "prod"}},
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
	if len(calls) != 6 {
		t.Fatalf("calls = %d, want find, two removes+destroys, trailing set:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "--columns=_uuid\nfind\nNAT") ||
		!strings.Contains(calls[0], "external_ids:netloom_nat=web") ||
		!strings.Contains(calls[0], "external_ids:netloom_vpc=prod") {
		t.Fatalf("first call should find NAT records by ownership:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "remove\nlogical_router\nnl_lr_prod\nnat\nnat-a") ||
		!strings.Contains(calls[2], "destroy\nNAT\nnat-a") ||
		!strings.Contains(calls[3], "remove\nlogical_router\nnl_lr_prod\nnat\nnat-b") ||
		!strings.Contains(calls[4], "destroy\nNAT\nnat-b") {
		t.Fatalf("matching NAT records should be destroyed:\n%s", raw)
	}
	if !strings.Contains(calls[5], "set\nlogical_router\nnl_lr_prod") {
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
    printf 'nat-keep,{netloom_owner=netloom netloom_nat=web netloom_vpc=prod}\n'
    printf 'nat-other-vpc,{netloom_owner=netloom netloom_nat=web netloom_vpc=dev}\n'
    printf 'nat-stale,{netloom_owner=netloom netloom_nat=old netloom_vpc=prod}\n'
    printf 'nat-missing,{netloom_owner=netloom}\n'
    ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{
		{Command: "gc-stale-nat-rules", Args: []string{"prod", "web"}},
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
	if len(calls) != 6 {
		t.Fatalf("calls = %d, want find, stale remove+destroy, trailing set:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "--columns=_uuid,external_ids\nfind\nNAT") ||
		!strings.Contains(calls[0], "external_ids:netloom_owner=netloom") {
		t.Fatalf("first call should find managed NAT records with external IDs:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "remove\nlogical_router\nnl_lr_dev\nnat\nnat-other-vpc") ||
		!strings.Contains(calls[2], "destroy\nNAT\nnat-other-vpc") ||
		!strings.Contains(calls[3], "remove\nlogical_router\nnl_lr_prod\nnat\nnat-stale") ||
		!strings.Contains(calls[4], "destroy\nNAT\nnat-stale") {
		t.Fatalf("other-vpc same-name and stale managed NAT should be destroyed:\n%s", raw)
	}
	if strings.Contains(string(raw), "destroy\nNAT\nnat-keep") {
		t.Fatalf("desired managed NAT must not be destroyed:\n%s", raw)
	}
	if strings.Contains(string(raw), "destroy\nNAT\nnat-missing") {
		t.Fatalf("managed NAT without netloom_nat identity must not be destroyed:\n%s", raw)
	}
	if strings.Contains(string(raw), "remove\nlogical_router\nnl_lr_prod\nnat\nnat-keep") {
		t.Fatalf("desired managed NAT must not be detached:\n%s", raw)
	}
	if strings.Contains(string(raw), "remove\nlogical_router\nnl_lr_prod\nnat\nnat-missing") {
		t.Fatalf("managed NAT without identity must not be detached:\n%s", raw)
	}
	if !strings.Contains(calls[5], "set\nlogical_router\nnl_lr_prod") {
		t.Fatalf("trailing regular operation should still execute:\n%s", calls[3])
	}
}

func TestNBCTLExecutorDestroysDuplicateManagedNATRulesEvenWhenKept(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"--columns=_uuid,external_ids find NAT"*)
    printf 'nat-keep-a,{netloom_owner=netloom netloom_nat=web netloom_vpc=prod}\n'
    printf 'nat-keep-b,{netloom_owner=netloom netloom_nat=web netloom_vpc=prod}\n'
    ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{Command: "gc-stale-nat-rules", Args: []string{"prod", "web"}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "destroy\nNAT\nnat-keep-a") {
		t.Fatalf("first desired managed NAT should be retained:\n%s", raw)
	}
	if !strings.Contains(text, "remove\nlogical_router\nnl_lr_prod\nnat\nnat-keep-b") ||
		!strings.Contains(text, "destroy\nNAT\nnat-keep-b") {
		t.Fatalf("duplicate desired managed NAT should be removed and destroyed:\n%s", raw)
	}
}

func TestNBCTLExecutorTagsPlainNATRulesAndDestroysDuplicates(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"find NAT type=snat external_ip=198.51.100.10 logical_ip=10.10.0.0/24"*) printf 'nat-a\nnat-b\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{
		Command: "tag-nat-rule",
		Args:    []string{"shared-egress", "prod", "snat", "198.51.100.10", "10.10.0.0/24"},
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
		t.Fatalf("calls = %d, want find, set, duplicate remove+destroy:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "--columns=_uuid\nfind\nNAT") ||
		!strings.Contains(calls[0], "type=snat") ||
		!strings.Contains(calls[0], "external_ip=198.51.100.10") ||
		!strings.Contains(calls[0], "logical_ip=10.10.0.0/24") {
		t.Fatalf("first call should find plain NAT by OVN identity:\n%s", calls[0])
	}
	if !strings.Contains(calls[1], "set\nNAT\nnat-a") ||
		!strings.Contains(calls[1], "external_ids:netloom_owner=netloom") ||
		!strings.Contains(calls[1], "external_ids:netloom_nat=shared-egress") ||
		!strings.Contains(calls[1], "external_ids:netloom_vpc=prod") {
		t.Fatalf("canonical plain NAT should be tagged:\n%s", calls[1])
	}
	if !strings.Contains(calls[2], "remove\nlogical_router\nnl_lr_prod\nnat\nnat-b") ||
		!strings.Contains(calls[3], "destroy\nNAT\nnat-b") {
		t.Fatalf("duplicate plain NAT should be removed and destroyed:\n%s", raw)
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

func TestNBCTLExecutorTagsOnlyOneMatchingPolicyRouteAndDestroysDuplicates(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"get logical_router nl_lr_prod policies"*) printf '[policy-a, policy-b]\n' ;;
  *"get Logical_Router_Policy policy-a priority"*) printf '100\n' ;;
  *"get Logical_Router_Policy policy-a match"*) printf '"ip4.src == 10.10.0.0/24"\n' ;;
  *"get Logical_Router_Policy policy-b priority"*) printf '100\n' ;;
  *"get Logical_Router_Policy policy-b match"*) printf '"ip4.src == 10.10.0.0/24"\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{
		Command: "tag-policy-route",
		Args:    []string{"prod", "https-via-fw", "100", "ip4.src == 10.10.0.0/24"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Count(text, "set\nLogical_Router_Policy\npolicy-a") != 1 {
		t.Fatalf("expected one canonical tagged policy:\n%s", raw)
	}
	if strings.Contains(text, "set\nLogical_Router_Policy\npolicy-b") {
		t.Fatalf("duplicate matching policy must not also be tagged:\n%s", raw)
	}
	if !strings.Contains(text, "remove\nlogical_router\nnl_lr_prod\npolicies\npolicy-b") ||
		!strings.Contains(text, "destroy\nLogical_Router_Policy\npolicy-b") {
		t.Fatalf("duplicate matching policy should be removed and destroyed:\n%s", raw)
	}
}

func TestNBCTLExecutorSyncsPolicyRouteECMPNexthops(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"find Logical_Router_Policy external_ids:netloom_owner=netloom external_ids:netloom_vpc=prod external_ids:netloom_policy_route=https-via-fw"*) printf 'policy-a\npolicy-b\n' ;;
  *"get Logical_Router_Policy policy-a priority"*) printf '100\n' ;;
  *"get Logical_Router_Policy policy-a match"*) printf '"ip4.src == 10.10.0.0/24"\n' ;;
  *"get Logical_Router_Policy policy-b priority"*) printf '200\n' ;;
  *"get Logical_Router_Policy policy-b match"*) printf '"ip4.src == 10.20.0.0/24"\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{
		Command: "sync-policy-route-nexthops",
		Args: []string{
			"prod",
			"https-via-fw",
			"100",
			"ip4.src == 10.10.0.0/24",
			"[\"10.10.0.252\",\"10.10.0.254\"]",
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
	if len(calls) != 6 {
		t.Fatalf("calls = %d, want find, identity reads, set, and remaining identity reads:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "--columns=_uuid\nfind\nLogical_Router_Policy") {
		t.Fatalf("first call should find managed policy UUIDs by identity:\n%s", calls[0])
	}
	hasPolicyASet := false
	hasPolicyBSet := false
	for _, call := range calls {
		if strings.Contains(call, "set\nLogical_Router_Policy\npolicy-a") {
			hasPolicyASet = true
			if !strings.Contains(call, "nexthops=[\"10.10.0.252\",\"10.10.0.254\"]") {
				t.Fatalf("matching policy update should include nexthops set:\n%s", call)
			}
		}
		if strings.Contains(call, "set\nLogical_Router_Policy\npolicy-b") {
			hasPolicyBSet = true
		}
	}
	if !hasPolicyASet {
		t.Fatalf("final call should update matching ECMP policy nexthops:\n%s", raw)
	}
	if hasPolicyBSet {
		t.Fatalf("non-matching policy must not be updated:\n%s", raw)
	}
}

func TestNBCTLExecutorSyncsSingleHopPolicyRouteNexthop(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"find Logical_Router_Policy external_ids:netloom_owner=netloom external_ids:netloom_vpc=prod external_ids:netloom_policy_route=https-via-fw"*) printf 'policy-a\npolicy-b\n' ;;
  *"get Logical_Router_Policy policy-a priority"*) printf '100\n' ;;
  *"get Logical_Router_Policy policy-a match"*) printf '"ip4.src == 10.10.0.0/24"\n' ;;
  *"get Logical_Router_Policy policy-b priority"*) printf '200\n' ;;
  *"get Logical_Router_Policy policy-b match"*) printf '"ip4.src == 10.20.0.0/24"\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{
		Command: "sync-policy-route-nexthop",
		Args: []string{
			"prod",
			"https-via-fw",
			"100",
			"ip4.src == 10.10.0.0/24",
			"10.10.0.252",
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
	if len(calls) != 6 {
		t.Fatalf("calls = %d, want find, identity reads, set, and remaining identity reads:\n%s", len(calls), raw)
	}
	if !strings.Contains(calls[0], "--columns=_uuid\nfind\nLogical_Router_Policy") {
		t.Fatalf("first call should find managed policy UUIDs by identity:\n%s", calls[0])
	}
	hasPolicyASet := false
	hasPolicyBSet := false
	for _, call := range calls {
		if strings.Contains(call, "set\nLogical_Router_Policy\npolicy-a") {
			hasPolicyASet = true
			if !strings.Contains(call, "nexthops=[\"10.10.0.252\"]") {
				t.Fatalf("matching policy update should include nexthops set:\n%s", call)
			}
		}
		if strings.Contains(call, "set\nLogical_Router_Policy\npolicy-b") {
			hasPolicyBSet = true
		}
	}
	if !hasPolicyASet {
		t.Fatalf("final call should update matching single-hop policy route nexthop:\n%s", raw)
	}
	if hasPolicyBSet {
		t.Fatalf("non-matching policy must not be updated:\n%s", raw)
	}
}

func TestNBCTLExecutorSyncsCanonicalSingleHopPolicyRouteNexthopAndDestroysDuplicates(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"find Logical_Router_Policy external_ids:netloom_owner=netloom external_ids:netloom_vpc=prod external_ids:netloom_policy_route=https-via-fw"*) printf 'policy-a\npolicy-b\n' ;;
  *"get Logical_Router_Policy policy-a priority"*) printf '100\n' ;;
  *"get Logical_Router_Policy policy-a match"*) printf '"ip4.src == 10.10.0.0/24"\n' ;;
  *"get Logical_Router_Policy policy-b priority"*) printf '100\n' ;;
  *"get Logical_Router_Policy policy-b match"*) printf '"ip4.src == 10.10.0.0/24"\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{
		Command: "sync-policy-route-nexthop",
		Args: []string{
			"prod",
			"https-via-fw",
			"100",
			"ip4.src == 10.10.0.0/24",
			"10.10.0.252",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Count(text, "set\nLogical_Router_Policy\npolicy-a\nnexthops=[\"10.10.0.252\"]") != 1 {
		t.Fatalf("canonical policy should be updated exactly once:\n%s", raw)
	}
	if strings.Contains(text, "set\nLogical_Router_Policy\npolicy-b") {
		t.Fatalf("duplicate matching policy must not also be updated:\n%s", raw)
	}
	if !strings.Contains(text, "remove\nlogical_router\nnl_lr_prod\npolicies\npolicy-b") ||
		!strings.Contains(text, "destroy\nLogical_Router_Policy\npolicy-b") {
		t.Fatalf("duplicate matching policy should be removed and destroyed:\n%s", raw)
	}
}

func TestNBCTLExecutorSyncsCanonicalPolicyRouteECMPNexthopsAndDestroysDuplicates(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"find Logical_Router_Policy external_ids:netloom_owner=netloom external_ids:netloom_vpc=prod external_ids:netloom_policy_route=https-via-fw"*) printf 'policy-a\npolicy-b\n' ;;
  *"get Logical_Router_Policy policy-a priority"*) printf '100\n' ;;
  *"get Logical_Router_Policy policy-a match"*) printf '"ip4.src == 10.10.0.0/24"\n' ;;
  *"get Logical_Router_Policy policy-b priority"*) printf '100\n' ;;
  *"get Logical_Router_Policy policy-b match"*) printf '"ip4.src == 10.10.0.0/24"\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{
		Command: "sync-policy-route-nexthops",
		Args: []string{
			"prod",
			"https-via-fw",
			"100",
			"ip4.src == 10.10.0.0/24",
			"[\"10.10.0.252\",\"10.10.0.254\"]",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Count(text, "set\nLogical_Router_Policy\npolicy-a\nnexthops=[\"10.10.0.252\",\"10.10.0.254\"]") != 1 {
		t.Fatalf("canonical policy should be updated exactly once:\n%s", raw)
	}
	if strings.Contains(text, "set\nLogical_Router_Policy\npolicy-b") {
		t.Fatalf("duplicate matching policy must not also be updated:\n%s", raw)
	}
	if !strings.Contains(text, "remove\nlogical_router\nnl_lr_prod\npolicies\npolicy-b") ||
		!strings.Contains(text, "destroy\nLogical_Router_Policy\npolicy-b") {
		t.Fatalf("duplicate matching policy should be removed and destroyed:\n%s", raw)
	}
}

func TestNBCTLExecutorEnsurePolicyRouteECMPNexthopsCreatesMissingPolicy(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"get logical_router nl_lr_prod policies"*) printf '[]\n' ;;
  *"find Logical_Router_Policy external_ids:netloom_owner=netloom external_ids:netloom_vpc=prod external_ids:netloom_policy_route=https-via-fw"*) ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{
		Command: "ensure-policy-route-nexthops",
		Args: []string{
			"prod",
			"https-via-fw",
			"100",
			"ip4.src == 10.10.0.0/24",
			"[\"10.10.0.252\",\"10.10.0.254\"]",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "create\nLogical_Router_Policy\npriority=100\nmatch=\"ip4.src == 10.10.0.0/24\"\naction=reroute\nnexthops=[\"10.10.0.252\",\"10.10.0.254\"]") {
		t.Fatalf("missing policy should be created with requested nexthops:\n%s", raw)
	}
	if !strings.Contains(text, "add\nlogical_router\nnl_lr_prod\npolicies\n@netloom_lrp") {
		t.Fatalf("missing policy should be attached to router:\n%s", raw)
	}
}

func TestNBCTLExecutorEnsurePolicyRouteECMPNexthopsUpdatesExistingPolicyWithoutRecreate(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"get logical_router nl_lr_prod policies"*) printf '["policy-a"]\n' ;;
  *"find Logical_Router_Policy external_ids:netloom_owner=netloom external_ids:netloom_vpc=prod external_ids:netloom_policy_route=https-via-fw"*) printf 'policy-a\n' ;;
  *"get Logical_Router_Policy policy-a priority"*) printf '100\n' ;;
  *"get Logical_Router_Policy policy-a match"*) printf '"ip4.src == 10.10.0.0/24"\n' ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{
		Command: "ensure-policy-route-nexthops",
		Args: []string{
			"prod",
			"https-via-fw",
			"100",
			"ip4.src == 10.10.0.0/24",
			"[\"10.10.0.252\",\"10.10.0.254\"]",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "set\nLogical_Router_Policy\npolicy-a\nnexthops=[\"10.10.0.252\",\"10.10.0.254\"]") {
		t.Fatalf("existing matching policy should be updated in place:\n%s", raw)
	}
	if strings.Contains(text, "create\nLogical_Router_Policy") {
		t.Fatalf("existing matching policy should not be recreated:\n%s", raw)
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
    printf 'policy-keep,{netloom_owner=netloom netloom_policy_route=https-via-fw netloom_vpc=prod}\n'
    printf 'policy-stale,{netloom_owner=netloom netloom_policy_route=old-fw netloom_vpc=prod}\n'
    printf 'policy-missing,{netloom_owner=netloom netloom_vpc=prod}\n'
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

func TestNBCTLExecutorDestroysDuplicateManagedPolicyRoutesEvenWhenKept(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"--columns=_uuid,external_ids find Logical_Router_Policy"*)
    printf 'policy-keep-a,{netloom_owner=netloom netloom_policy_route=https-via-fw netloom_vpc=prod}\n'
    printf 'policy-keep-b,{netloom_owner=netloom netloom_policy_route=https-via-fw netloom_vpc=prod}\n'
    ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	err := executor.Execute(context.Background(), []ovn.Operation{{Command: "gc-stale-policy-routes", Args: []string{"prod", "https-via-fw"}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "destroy\nLogical_Router_Policy\npolicy-keep-a") {
		t.Fatalf("first desired managed policy should be retained:\n%s", raw)
	}
	if !strings.Contains(text, "remove\nlogical_router\nnl_lr_prod\npolicies\npolicy-keep-b") ||
		!strings.Contains(text, "destroy\nLogical_Router_Policy\npolicy-keep-b") {
		t.Fatalf("duplicate desired managed policy should be removed and destroyed:\n%s", raw)
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

func TestNBCTLExecutorHealthCheckUsesShow(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "ovn-nbctl")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' '---' >> %q
printf '%%s\n' "$@" >> %q
case "$*" in
  *"show"*) exit 0 ;;
esac
`, argsFile, argsFile)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	executor := ovn.NewNBCTLExecutor(binary, "--db=unix:/tmp/ovnnb.sock")
	latency, err := executor.HealthCheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if latency < 0 {
		t.Fatalf("latency = %s, want non-negative", latency)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "--db=unix:/tmp/ovnnb.sock\nshow") {
		t.Fatalf("health check should execute ovn-nbctl show:\n%s", text)
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
		ProviderNetworks: []model.ProviderNetwork{{
			Name: "physnet-a",
			Nodes: []model.ProviderNetworkNode{{
				Node:      "node-a",
				Interface: "eth1",
			}},
		}},
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
