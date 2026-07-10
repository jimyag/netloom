package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/jimyag/netloom/internal/model"
)

type identityGroupObservationDocument struct {
	IdentityGroups []model.IdentityGroup `json:"identity_groups"`
}

func LoadIdentityGroupObservationsJSON(r io.Reader) ([]model.IdentityGroup, error) {
	var raw json.RawMessage
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode identity group observations: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode identity group observations: multiple JSON documents")
	}

	var groups []model.IdentityGroup
	if err := json.Unmarshal(raw, &groups); err == nil {
		return validateIdentityGroups(groups)
	}
	var document identityGroupObservationDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("decode identity group observations: %w", err)
	}
	return validateIdentityGroups(document.IdentityGroups)
}

func MergeIdentityGroups(base, observed []model.IdentityGroup) ([]model.IdentityGroup, error) {
	merged := make([]model.IdentityGroup, 0, len(base)+len(observed))
	groups, err := validateIdentityGroups(base)
	if err != nil {
		return nil, err
	}
	merged = append(merged, groups...)
	groups, err = validateIdentityGroups(observed)
	if err != nil {
		return nil, err
	}
	merged = append(merged, groups...)
	merged = compactIdentityGroups(merged)
	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i].VPC != merged[j].VPC {
			return merged[i].VPC < merged[j].VPC
		}
		return merged[i].Name < merged[j].Name
	})
	return merged, nil
}

func PruneExpiredIdentityGroups(groups []model.IdentityGroup, now time.Time) ([]model.IdentityGroup, error) {
	validated, err := validateIdentityGroups(groups)
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	pruned := validated[:0]
	for _, group := range validated {
		if group.Expired(now) {
			continue
		}
		pruned = append(pruned, group)
	}
	return pruned, nil
}

func compactIdentityGroups(groups []model.IdentityGroup) []model.IdentityGroup {
	index := make(map[string]int, len(groups))
	out := make([]model.IdentityGroup, 0, len(groups))
	for _, group := range groups {
		key := group.VPC + "\x00" + group.Name
		if pos, ok := index[key]; ok {
			out[pos] = preferredIdentityGroup(out[pos], group)
			continue
		}
		index[key] = len(out)
		out = append(out, group)
	}
	return out
}

func preferredIdentityGroup(current, candidate model.IdentityGroup) model.IdentityGroup {
	if current.TTLSeconds == 0 {
		return current
	}
	if candidate.TTLSeconds == 0 {
		return candidate
	}
	if candidate.ObservedAt.After(current.ObservedAt) {
		return candidate
	}
	return current
}

func validateIdentityGroups(groups []model.IdentityGroup) ([]model.IdentityGroup, error) {
	out := append([]model.IdentityGroup(nil), groups...)
	for i := range out {
		if err := out[i].Validate(); err != nil {
			return nil, fmt.Errorf("identity group %d: %w", i, err)
		}
	}
	return out, nil
}
