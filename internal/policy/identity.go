package policy

import "sync"

type IdentityResolver interface {
	Identity(value string) uint32
}

type IdentityCache struct {
	mu      sync.Mutex
	entries map[string]uint32
}

func NewIdentityCache() *IdentityCache {
	return &IdentityCache{
		entries: make(map[string]uint32),
	}
}

func (c *IdentityCache) Identity(value string) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if id, ok := c.entries[value]; ok {
		return id
	}

	id := stableIdentity(value)
	c.entries[value] = id
	return id
}
