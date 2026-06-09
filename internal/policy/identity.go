package policy

import "sync"

type IdentityResolver interface {
	Identity(value string) uint32
}

type IdentityCache struct {
	mu      sync.Mutex
	next    uint32
	entries map[string]uint32
}

func NewIdentityCache() *IdentityCache {
	return &IdentityCache{
		next:    1,
		entries: make(map[string]uint32),
	}
}

func (c *IdentityCache) Identity(value string) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if id, ok := c.entries[value]; ok {
		return id
	}

	id := c.next
	c.next++
	c.entries[value] = id
	return id
}
