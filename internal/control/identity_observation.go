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
	BackoffBase time.Duration
	BackoffMax  time.Duration
	Cache       *IdentityGroupObservationCache
	HTTPClient  *http.Client
}

type IdentityGroupObservationCache struct {
	URL                 string
	ETag                string
	LastModified        string
	Groups              []model.IdentityGroup
	ConsecutiveFailures int
	NextAttempt         time.Time
	LastError           string
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
	groups, _, err := loadIdentityGroupObservationsHTTP(ctx, identityGroupHTTPOptions{
		URL:         feedURL,
		BearerToken: bearerToken,
		Timeout:     timeout,
		Client:      client,
	})
	return groups, err
}

type identityGroupHTTPOptions struct {
	URL             string
	BearerToken     string
	Timeout         time.Duration
	Client          *http.Client
	IfNoneMatch     string
	IfModifiedSince string
}

type identityGroupHTTPResult struct {
	NotModified  bool
	ETag         string
	LastModified string
}

func loadIdentityGroupObservationsHTTP(ctx context.Context, opts identityGroupHTTPOptions) ([]model.IdentityGroup, identityGroupHTTPResult, error) {
	feedURL := opts.URL
	feedURL = strings.TrimSpace(feedURL)
	if feedURL == "" {
		return nil, identityGroupHTTPResult{}, errors.New("identity group observations url is required")
	}
	parsed, err := url.Parse(feedURL)
	if err != nil {
		return nil, identityGroupHTTPResult{}, fmt.Errorf("parse identity group observations url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, identityGroupHTTPResult{}, fmt.Errorf("identity group observations url scheme %q is not supported", parsed.Scheme)
	}
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, identityGroupHTTPResult{}, fmt.Errorf("create identity group observations request: %w", err)
	}
	if strings.TrimSpace(opts.BearerToken) != "" {
		request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(opts.BearerToken))
	}
	if strings.TrimSpace(opts.IfNoneMatch) != "" {
		request.Header.Set("If-None-Match", strings.TrimSpace(opts.IfNoneMatch))
	}
	if strings.TrimSpace(opts.IfModifiedSince) != "" {
		request.Header.Set("If-Modified-Since", strings.TrimSpace(opts.IfModifiedSince))
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, identityGroupHTTPResult{}, fmt.Errorf("fetch identity group observations: %w", err)
	}
	defer response.Body.Close()
	result := identityGroupHTTPResult{
		ETag:         response.Header.Get("ETag"),
		LastModified: response.Header.Get("Last-Modified"),
	}
	if response.StatusCode == http.StatusNotModified {
		result.NotModified = true
		return nil, result, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, result, fmt.Errorf("fetch identity group observations returned status %d", response.StatusCode)
	}
	groups, err := LoadIdentityGroupObservationsJSON(response.Body)
	return groups, result, err
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
		observed, err := loadIdentityGroupObservationsURL(ctx, opts)
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

func loadIdentityGroupObservationsURL(ctx context.Context, opts IdentityGroupObservationOptions) ([]model.IdentityGroup, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	cache := opts.Cache
	url := strings.TrimSpace(opts.URL)
	if cache != nil {
		if cache.URL != "" && cache.URL != url {
			*cache = IdentityGroupObservationCache{}
		}
		cache.URL = url
		if !cache.NextAttempt.IsZero() && now.Before(cache.NextAttempt) {
			return append([]model.IdentityGroup(nil), cache.Groups...), nil
		}
	}
	etag, lastModified := "", ""
	if cache != nil {
		etag = cache.ETag
		lastModified = cache.LastModified
	}
	groups, result, err := loadIdentityGroupObservationsHTTP(ctx, identityGroupHTTPOptions{
		URL:             url,
		BearerToken:     opts.BearerToken,
		Timeout:         opts.Timeout,
		Client:          opts.HTTPClient,
		IfNoneMatch:     etag,
		IfModifiedSince: lastModified,
	})
	if err != nil {
		if cache != nil && len(cache.Groups) > 0 {
			recordIdentityGroupFeedFailure(cache, now, opts, err)
			return append([]model.IdentityGroup(nil), cache.Groups...), nil
		}
		return nil, err
	}
	if result.NotModified {
		if cache == nil {
			return nil, errors.New("identity group observations returned 304 without cached groups")
		}
		recordIdentityGroupFeedSuccess(cache, url, result, cache.Groups)
		return append([]model.IdentityGroup(nil), cache.Groups...), nil
	}
	if cache != nil {
		recordIdentityGroupFeedSuccess(cache, url, result, groups)
	}
	return groups, nil
}

func recordIdentityGroupFeedSuccess(cache *IdentityGroupObservationCache, url string, result identityGroupHTTPResult, groups []model.IdentityGroup) {
	cache.URL = url
	cache.ETag = result.ETag
	cache.LastModified = result.LastModified
	cache.Groups = append([]model.IdentityGroup(nil), groups...)
	cache.ConsecutiveFailures = 0
	cache.NextAttempt = time.Time{}
	cache.LastError = ""
}

func recordIdentityGroupFeedFailure(cache *IdentityGroupObservationCache, now time.Time, opts IdentityGroupObservationOptions, err error) {
	cache.ConsecutiveFailures++
	cache.LastError = err.Error()
	backoff := identityGroupFeedBackoff(opts.BackoffBase, opts.BackoffMax, cache.ConsecutiveFailures)
	cache.NextAttempt = now.Add(backoff)
}

func identityGroupFeedBackoff(base, max time.Duration, failures int) time.Duration {
	if base <= 0 {
		base = time.Second
	}
	if max <= 0 {
		max = time.Minute
	}
	if max < base {
		max = base
	}
	if failures < 1 {
		failures = 1
	}
	backoff := base
	for i := 1; i < failures; i++ {
		if backoff >= max/2 {
			return max
		}
		backoff *= 2
	}
	if backoff > max {
		return max
	}
	return backoff
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
