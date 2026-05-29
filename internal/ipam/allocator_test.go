package ipam

import (
	"net/netip"
	"testing"
)

func TestAllocatorAllocatesDeterministicallyAndReusesOwner(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/29")
	gateway := netip.MustParseAddr("10.0.0.1")
	allocator, err := NewAllocator(prefix, gateway)
	if err != nil {
		t.Fatal(err)
	}

	first, err := allocator.Allocate("endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddr("10.0.0.2"); first != want {
		t.Fatalf("first allocation = %s, want %s", first, want)
	}

	again, err := allocator.Allocate("endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatalf("second allocation for same owner = %s, want %s", again, first)
	}
}

func TestAllocatorReserveAndRelease(t *testing.T) {
	allocator, err := NewAllocator(netip.MustParsePrefix("10.0.1.0/29"))
	if err != nil {
		t.Fatal(err)
	}
	staticIP := netip.MustParseAddr("10.0.1.4")
	if err := allocator.Reserve("endpoint-a", staticIP); err != nil {
		t.Fatal(err)
	}
	if err := allocator.Reserve("endpoint-b", staticIP); err == nil {
		t.Fatal("expected duplicate reserve to fail")
	}

	allocator.Release("endpoint-a")
	if err := allocator.Reserve("endpoint-b", staticIP); err != nil {
		t.Fatal(err)
	}
}
