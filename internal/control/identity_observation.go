package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jimyag/netloom/internal/model"
)

type IdentityGroupObservationOptions struct {
	FilePath    string
	URL         string
	BearerToken string
	Timeout     time.Duration
	Now         time.Time
	HTTPClient  *http.Client
}

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

func LoadIdentityGroupObservationsHTTP(ctx context.Context, feedURL, bearerToken string, timeout time.Duration, client *http.Client) ([]model.IdentityGroup, error) {
	feedURL = strings.TrimSpace(feedURL)
	if feedURL == "" {
		return nil, errors.New("identity group observations url is required")
	}
	parsed, err := url.Parse(feedURL)
	if err != nil {
		return nil, fmt.Errorf("parse identity group observations url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("identity group observations url scheme %q is not supported", parsed.Scheme)
	}
	if client == nil {
		client = http.DefaultClient
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create identity group observations request: %w", err)
	}
	if strings.TrimSpace(bearerToken) != "" {
		request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearerToken))
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch identity group observations: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch identity group observations returned status %d", response.StatusCode)
	}
	return LoadIdentityGroupObservationsJSON(response.Body)
}

func MergeIdentityGroupObservations(ctx context.Context, state DesiredState, opts IdentityGroupObservationOptions) (DesiredState, error) {
	groups := append([]model.IdentityGroup(nil), state.IdentityGroups...)
	if strings.TrimSpace(opts.FilePath) != "" {
		observed, err := loadIdentityGroupObservationsFile(opts.FilePath)
		if err != nil {
			return DesiredState{}, err
		}
		groups, err = MergeIdentityGroups(groups, observed)
		if err != nil {
			return DesiredState{}, err
		}
	}
	if strings.TrimSpace(opts.URL) != "" {
		observed, err := LoadIdentityGroupObservationsHTTP(ctx, opts.URL, opts.BearerToken, opts.Timeout, opts.HTTPClient)
		if err != nil {
			return DesiredState{}, err
		}
		groups, err = MergeIdentityGroups(groups, observed)
		if err != nil {
			return DesiredState{}, err
		}
	}
	pruned, err := PruneExpiredIdentityGroups(groups, opts.Now)
	if err != nil {
		return DesiredState{}, err
	}
	state.IdentityGroups = pruned
	return state, nil
}

func loadIdentityGroupObservationsFile(path string) ([]model.IdentityGroup, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return LoadIdentityGroupObservationsJSON(file)
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
