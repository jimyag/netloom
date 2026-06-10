package dataplane

import "fmt"

func (s *EBPFPolicyStore) validatePolicyMapCapacity(endpointID string, entries []PolicyMapEntry) error {
	if s.maxEntries == 0 {
		return nil
	}
	unique := make(map[PolicyKey]struct{}, len(entries))
	for _, entry := range entries {
		unique[entry.Key] = struct{}{}
	}
	if uint32(len(unique)) <= s.maxEntries {
		return nil
	}
	return fmt.Errorf("policy map capacity exceeded for endpoint %s: desired_entries=%d capacity=%d", endpointID, len(unique), s.maxEntries)
}
