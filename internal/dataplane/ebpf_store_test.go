package dataplane

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf/rlimit"
)

func TestMapNameSanitizesEndpointID(t *testing.T) {
	got := mapName("pod/a:b")
	if len(got) != 15 {
		t.Fatalf("map name length = %d, want 15", len(got))
	}
	if !strings.HasPrefix(got, "nlp") {
		t.Fatalf("map name = %q, want nlp prefix", got)
	}
}

func TestMapNameAvoidsSanitizeAndTruncationCollisions(t *testing.T) {
	cases := []struct {
		left  string
		right string
	}{
		{left: "pod/a:b", right: "pod_a_b"},
		{left: "very-long-endpoint-name-a", right: "very-long-endpoint-name-b"},
	}
	for _, tc := range cases {
		left := mapName(tc.left)
		right := mapName(tc.right)
		if left == right {
			t.Fatalf("map names collide for %q and %q: %q", tc.left, tc.right, left)
		}
		if len(left) > 15 || len(right) > 15 {
			t.Fatalf("map names exceed eBPF limit: %q/%d %q/%d", left, len(left), right, len(right))
		}
	}
}

func TestEBPFPolicyStoreDeleteEndpointRejectsEmptyID(t *testing.T) {
	store := NewEBPFPolicyStore(16)
	err := store.DeleteEndpoint(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "endpoint id is required") {
		t.Fatalf("error = %v, want endpoint id validation", err)
	}
}

func TestEBPFPolicyStorePrivileged(t *testing.T) {
	if os.Getenv("NETLOOM_EBPF_TEST") != "1" {
		t.Skip("set NETLOOM_EBPF_TEST=1 to create kernel eBPF maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot adjust memlock rlimit for eBPF test: %v", err)
	}

	store := NewEBPFPolicyStore(16)
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	})

	err := store.ReplaceEndpoint(context.Background(), "pod-a", []PolicyMapEntry{{
		Key: PolicyKey{
			PrefixLen:      StaticPrefixBits,
			RemoteIdentity: 0,
			Direction:      DirectionIngress,
		},
		Value: PolicyEntry{
			Deny:       1,
			Precedence: ^uint32(0),
		},
	}})
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("kernel eBPF map creation is not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
}
