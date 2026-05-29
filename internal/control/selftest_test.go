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
	if result.OVNOperations == 0 {
		t.Fatal("expected OVN operations to be planned")
	}
	if result.OVNExecuted != result.OVNOperations {
		t.Fatalf("executed ovn ops = %d, want %d", result.OVNExecuted, result.OVNOperations)
	}
}
