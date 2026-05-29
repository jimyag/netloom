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
	if got != "nl_pol_pod_a_b" {
		t.Fatalf("map name = %q, want nl_pol_pod_a_b", got)
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
