package control

import (
	"context"
	"net/netip"
	"testing"
)

func TestRunSelfTestReconcilesTopologyAndResolvesRouting(t *testing.T) {
	result, err := RunSelfTest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyRouteNextHop != netip.MustParseAddr("10.244.0.253") {
		t.Fatalf("policy route next hop = %s", result.PolicyRouteNextHop)
	}
	if result.SNATAddress != netip.MustParseAddr("198.51.100.10") {
		t.Fatalf("snat address = %s", result.SNATAddress)
	}
	if result.Gateway != "gw-a" {
		t.Fatalf("gateway = %s", result.Gateway)
	}
	if result.ServiceBackend != netip.MustParseAddr("10.244.0.10") || result.ServiceBackendPort != 8080 {
		t.Fatalf("service backend = %s:%d, want 10.244.0.10:8080", result.ServiceBackend, result.ServiceBackendPort)
	}
	if result.DNATTarget != netip.MustParseAddr("10.244.0.10") {
		t.Fatalf("dnat target = %s, want 10.244.0.10", result.DNATTarget)
	}
	if result.FloatingIPTarget != netip.MustParseAddr("10.244.0.10") {
		t.Fatalf("floating ip target = %s, want 10.244.0.10", result.FloatingIPTarget)
	}
	if result.OVNOperations == 0 {
		t.Fatal("expected OVN operations to be planned")
	}
	if result.OVNExecuted != result.OVNOperations {
		t.Fatalf("executed ovn ops = %d, want %d", result.OVNExecuted, result.OVNOperations)
	}
}

func TestRunTopologySelfTestAcceptsGenericTopologyBackend(t *testing.T) {
	result, err := RunTopologySelfTest(context.Background(), NewMemoryBackend())
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyRouteNextHop != netip.MustParseAddr("10.244.0.253") {
		t.Fatalf("policy route next hop = %s", result.PolicyRouteNextHop)
	}
	if result.OVNOperations != 1 || result.OVNExecuted != 1 {
		t.Fatalf("topology operation summary = %d/%d, want generic backend marker 1/1", result.OVNOperations, result.OVNExecuted)
	}
}
