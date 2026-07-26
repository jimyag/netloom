package dataplane

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const policyMapCapacityHotspotLimit = 5

type PolicyMapCapacityError struct {
	EndpointID     string
	DesiredEntries int
	Capacity       uint32
	Hotspots       []PolicyMapCapacityHotspot
}

func (e *PolicyMapCapacityError) Error() string {
	if e == nil {
		return ""
	}
	if len(e.Hotspots) != 0 {
		return fmt.Sprintf("policy map capacity exceeded for endpoint %s: desired_entries=%d capacity=%d top_rules=%s", e.EndpointID, e.DesiredEntries, e.Capacity, formatPolicyMapCapacityHotspots(e.Hotspots))
	}
	return fmt.Sprintf("policy map capacity exceeded for endpoint %s: desired_entries=%d capacity=%d", e.EndpointID, e.DesiredEntries, e.Capacity)
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
	return &PolicyMapCapacityError{
		EndpointID:     endpointID,
		DesiredEntries: len(unique),
		Capacity:       s.maxEntries,
		Hotspots:       policyMapCapacityHotspots(entries, policyMapCapacityHotspotLimit),
	}
}

func policyMapCapacityHotspots(entries []PolicyMapEntry, limit int) []PolicyMapCapacityHotspot {
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
	hotspots := make([]PolicyMapCapacityHotspot, 0, len(uniqueKeysByRule))
	for ruleRef, keys := range uniqueKeysByRule {
		hotspots = append(hotspots, PolicyMapCapacityHotspot{RuleRef: ruleRef, Entries: len(keys)})
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

func formatPolicyMapCapacityHotspots(hotspots []PolicyMapCapacityHotspot) string {
	parts := make([]string, 0, len(hotspots))
	for _, hotspot := range hotspots {
		parts = append(parts, fmt.Sprintf("%s:%d", hotspot.RuleRef, hotspot.Entries))
	}
	return strings.Join(parts, ",")
}

func policyMapCapacityHotspotsFromError(err error) []PolicyMapCapacityHotspot {
	var capacityErr *PolicyMapCapacityError
	if !errors.As(err, &capacityErr) || capacityErr == nil || len(capacityErr.Hotspots) == 0 {
		return nil
	}
	return append([]PolicyMapCapacityHotspot(nil), capacityErr.Hotspots...)
}
