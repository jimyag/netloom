package dataplane

import (
	"fmt"
	"sort"
	"strings"
)

const policyMapCapacityHotspotLimit = 5

type policyMapCapacityHotspot struct {
	RuleRef string
	Entries int
}

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
	if hotspots := policyMapCapacityHotspots(entries, policyMapCapacityHotspotLimit); len(hotspots) != 0 {
		return fmt.Errorf("policy map capacity exceeded for endpoint %s: desired_entries=%d capacity=%d top_rules=%s", endpointID, len(unique), s.maxEntries, formatPolicyMapCapacityHotspots(hotspots))
	}
	return fmt.Errorf("policy map capacity exceeded for endpoint %s: desired_entries=%d capacity=%d", endpointID, len(unique), s.maxEntries)
}

func policyMapCapacityHotspots(entries []PolicyMapEntry, limit int) []policyMapCapacityHotspot {
	if limit <= 0 {
		return nil
	}
	uniqueKeysByRule := make(map[string]map[PolicyKey]struct{})
	for _, entry := range entries {
		ruleRef := strings.TrimSpace(entry.RuleRef)
		if ruleRef == "" {
			if entry.Value.RuleCookie == 0 {
				continue
			}
			ruleRef = fmt.Sprintf("cookie:%d", entry.Value.RuleCookie)
		}
		if uniqueKeysByRule[ruleRef] == nil {
			uniqueKeysByRule[ruleRef] = make(map[PolicyKey]struct{})
		}
		uniqueKeysByRule[ruleRef][entry.Key] = struct{}{}
	}
	hotspots := make([]policyMapCapacityHotspot, 0, len(uniqueKeysByRule))
	for ruleRef, keys := range uniqueKeysByRule {
		hotspots = append(hotspots, policyMapCapacityHotspot{RuleRef: ruleRef, Entries: len(keys)})
	}
	sort.Slice(hotspots, func(i, j int) bool {
		if hotspots[i].Entries != hotspots[j].Entries {
			return hotspots[i].Entries > hotspots[j].Entries
		}
		return hotspots[i].RuleRef < hotspots[j].RuleRef
	})
	if len(hotspots) > limit {
		hotspots = hotspots[:limit]
	}
	return hotspots
}

func formatPolicyMapCapacityHotspots(hotspots []policyMapCapacityHotspot) string {
	parts := make([]string, 0, len(hotspots))
	for _, hotspot := range hotspots {
		parts = append(parts, fmt.Sprintf("%s:%d", hotspot.RuleRef, hotspot.Entries))
	}
	return strings.Join(parts, ",")
}
