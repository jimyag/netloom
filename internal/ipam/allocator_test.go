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

func TestAllocatorSkipsExcludedPrefixes(t *testing.T) {
	allocator, err := NewAllocatorWithExcludedPrefixes(
		netip.MustParsePrefix("10.0.2.0/29"),
		[]netip.Prefix{netip.MustParsePrefix("10.0.2.2/31")},
		netip.MustParseAddr("10.0.2.1"),
	)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := allocator.Allocate("endpoint-a")
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddr("10.0.2.4"); ip != want {
		t.Fatalf("allocated ip = %s, want %s", ip, want)
	}
	if err := allocator.Reserve("endpoint-b", netip.MustParseAddr("10.0.2.2")); err == nil {
		t.Fatal("expected excluded static reservation to fail")
	}
}

func TestAllocatorRejectsInvalidExcludedPrefixes(t *testing.T) {
	_, err := NewAllocatorWithExcludedPrefixes(
		netip.MustParsePrefix("10.0.2.0/24"),
		[]netip.Prefix{netip.MustParsePrefix("10.0.3.0/24")},
	)
	if err == nil {
		t.Fatal("expected excluded prefix outside allocator prefix to fail")
	}

	_, err = NewAllocatorWithExcludedPrefixes(
		netip.MustParsePrefix("10.0.2.0/24"),
		[]netip.Prefix{netip.MustParsePrefix("fd00:10::/64")},
	)
	if err == nil {
		t.Fatal("expected excluded prefix family mismatch to fail")
	}
}
