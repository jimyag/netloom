package ipam

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sync"
)

type Allocator struct {
	mu        sync.Mutex
	prefix    netip.Prefix
	reserved  map[netip.Addr]struct{}
	excluded  []netip.Prefix
	allocated map[string]netip.Addr
	owners    map[netip.Addr]string
}

func NewAllocator(prefix netip.Prefix, reserved ...netip.Addr) (*Allocator, error) {
	return NewAllocatorWithExcludedPrefixes(prefix, nil, reserved...)
}

func NewAllocatorWithExcludedPrefixes(prefix netip.Prefix, excluded []netip.Prefix, reserved ...netip.Addr) (*Allocator, error) {
	if !prefix.IsValid() {
		return nil, errors.New("prefix is required")
	}
	a := &Allocator{
		prefix:    prefix.Masked(),
		reserved:  make(map[netip.Addr]struct{}),
		excluded:  make([]netip.Prefix, 0, len(excluded)),
		allocated: make(map[string]netip.Addr),
		owners:    make(map[netip.Addr]string),
	}
	for _, exclude := range excluded {
		exclude = exclude.Masked()
		if !exclude.IsValid() {
			return nil, errors.New("excluded prefix is invalid")
		}
		if exclude.Addr().Is4() != prefix.Addr().Is4() {
			return nil, fmt.Errorf("excluded prefix %s family must match prefix %s", exclude, prefix)
		}
		if !prefix.Contains(exclude.Addr()) || !prefix.Contains(prefixLastAddr(exclude)) {
			return nil, fmt.Errorf("excluded prefix %s is outside prefix %s", exclude, prefix)
		}
		a.excluded = append(a.excluded, exclude)
	}
	for _, ip := range reserved {
		if !prefix.Contains(ip) {
			return nil, fmt.Errorf("reserved ip %s is outside prefix %s", ip, prefix)
		}
		if prefixContainsAny(a.excluded, ip) {
			return nil, fmt.Errorf("reserved ip %s is excluded", ip)
		}
		a.reserved[ip] = struct{}{}
	}
	return a, nil
}

func (a *Allocator) Allocate(owner string) (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if owner == "" {
		return netip.Addr{}, errors.New("owner is required")
	}
	if ip, ok := a.allocated[owner]; ok {
		return ip, nil
	}
	for ip := a.firstUsable(); a.prefix.Contains(ip); ip = nextAddr(ip) {
		if a.isUnavailable(ip) {
			continue
		}
		a.allocated[owner] = ip
		a.owners[ip] = owner
		return ip, nil
	}
	return netip.Addr{}, fmt.Errorf("no available ip in %s", a.prefix)
}

func (a *Allocator) Reserve(owner string, ip netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if owner == "" {
		return errors.New("owner is required")
	}
	if !a.prefix.Contains(ip) {
		return fmt.Errorf("ip %s is outside prefix %s", ip, a.prefix)
	}
	if _, ok := a.reserved[ip]; ok {
		return fmt.Errorf("ip %s is reserved", ip)
	}
	if prefixContainsAny(a.excluded, ip) {
		return fmt.Errorf("ip %s is excluded", ip)
	}
	if existing, ok := a.owners[ip]; ok && existing != owner {
		return fmt.Errorf("ip %s already allocated to %s", ip, existing)
	}
	if existing, ok := a.allocated[owner]; ok && existing != ip {
		return fmt.Errorf("owner %s already allocated %s", owner, existing)
	}
	a.allocated[owner] = ip
	a.owners[ip] = owner
	return nil
}

func (a *Allocator) Release(owner string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	ip, ok := a.allocated[owner]
	if !ok {
		return
	}
	delete(a.allocated, owner)
	delete(a.owners, ip)
}

func (a *Allocator) isUnavailable(ip netip.Addr) bool {
	if _, ok := a.reserved[ip]; ok {
		return true
	}
	if prefixContainsAny(a.excluded, ip) {
		return true
	}
	if _, ok := a.owners[ip]; ok {
		return true
	}
	return false
}

func prefixContainsAny(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func prefixLastAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr()
	bits := prefix.Bits()
	if addr.Is4() {
		raw := addr.As4()
		value := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
		hostBits := 32 - bits
		if hostBits > 0 {
			value |= uint32(1<<hostBits) - 1
		}
		return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
	}
	raw := addr.As16()
	hostBits := 128 - bits
	for i := 15; i >= 0 && hostBits > 0; i-- {
		if hostBits >= 8 {
			raw[i] = 0xff
			hostBits -= 8
			continue
		}
		raw[i] |= byte((1 << hostBits) - 1)
		hostBits = 0
	}
	return netip.AddrFrom16(raw)
}

func (a *Allocator) firstUsable() netip.Addr {
	return nextAddr(a.prefix.Addr())
}

func nextAddr(addr netip.Addr) netip.Addr {
	n := addrToBig(addr)
	n.Add(n, big.NewInt(1))
	return bigToAddr(n, addr.Is4())
}

func addrToBig(addr netip.Addr) *big.Int {
	b := addr.As16()
	return new(big.Int).SetBytes(b[:])
}

func bigToAddr(n *big.Int, v4 bool) netip.Addr {
	buf := n.FillBytes(make([]byte, 16))
	var raw [16]byte
	copy(raw[:], buf)
	addr := netip.AddrFrom16(raw)
	if v4 {
		return netip.AddrFrom4(addr.As4())
	}
	return addr
}
