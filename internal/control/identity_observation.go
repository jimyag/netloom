package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	TLSCAFile   string
	TLSCertFile string
	TLSKeyFile  string
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

type IdentityGroupObservationPatch struct {
	Op    string              `json:"op"`
	VPC   string              `json:"vpc,omitempty"`
	Name  string              `json:"name,omitempty"`
	Group model.IdentityGroup `json:"group,omitempty"`
}

type IdentityGroupObservationFeed struct {
	Snapshot bool
	Groups   []model.IdentityGroup
	Patches  []IdentityGroupObservationPatch
}

type identityGroupObservationDocument struct {
	IdentityGroups  *[]model.IdentityGroup          `json:"identity_groups,omitempty"`
	IdentityPatches []IdentityGroupObservationPatch `json:"identity_group_patches,omitempty"`
}

func LoadIdentityGroupObservationsJSON(r io.Reader) ([]model.IdentityGroup, error) {
	feed, err := LoadIdentityGroupObservationFeedJSON(r)
	if err != nil {
		return nil, err
	}
	if !feed.Snapshot {
		return nil, errors.New("identity group observations patch feed requires cached groups")
	}
	return feed.Groups, nil
}

func LoadIdentityGroupObservationFeedJSON(r io.Reader) (IdentityGroupObservationFeed, error) {
	var raw json.RawMessage
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return IdentityGroupObservationFeed{}, fmt.Errorf("decode identity group observations: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return IdentityGroupObservationFeed{}, fmt.Errorf("decode identity group observations: multiple JSON documents")
	}

	var groups []model.IdentityGroup
	if err := json.Unmarshal(raw, &groups); err == nil {
		groups, err = validateIdentityGroups(groups)
		if err != nil {
			return IdentityGroupObservationFeed{}, err
		}
		return IdentityGroupObservationFeed{Snapshot: true, Groups: groups}, nil
	}
	var document identityGroupObservationDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return IdentityGroupObservationFeed{}, fmt.Errorf("decode identity group observations: %w", err)
	}
	if document.IdentityGroups == nil && len(document.IdentityPatches) == 0 {
		return IdentityGroupObservationFeed{}, errors.New("identity group observations require identity_groups or identity_group_patches")
	}
	patches, err := validateIdentityGroupObservationPatches(document.IdentityPatches)
	if err != nil {
		return IdentityGroupObservationFeed{}, err
	}
	if document.IdentityGroups == nil {
		return IdentityGroupObservationFeed{Patches: patches}, nil
	}
	groups, err = validateIdentityGroups(*document.IdentityGroups)
	if err != nil {
		return IdentityGroupObservationFeed{}, err
	}
	if len(patches) != 0 {
		groups, err = ApplyIdentityGroupObservationPatches(groups, patches)
		if err != nil {
			return IdentityGroupObservationFeed{}, err
		}
	}
	return IdentityGroupObservationFeed{Snapshot: true, Groups: groups, Patches: patches}, nil
}

func LoadIdentityGroupObservationsHTTP(ctx context.Context, feedURL, bearerToken string, timeout time.Duration, client *http.Client) ([]model.IdentityGroup, error) {
	feed, _, err := loadIdentityGroupObservationsHTTP(ctx, identityGroupHTTPOptions{
		URL:         feedURL,
		BearerToken: bearerToken,
		Timeout:     timeout,
		Client:      client,
	})
	if err != nil {
		return nil, err
	}
	if !feed.Snapshot {
		return nil, errors.New("identity group observations patch feed requires cached groups")
	}
	return feed.Groups, nil
}

type identityGroupHTTPOptions struct {
	URL             string
	BearerToken     string
	Timeout         time.Duration
	Client          *http.Client
	IfNoneMatch     string
	IfModifiedSince string
	TLSCAFile       string
	TLSCertFile     string
	TLSKeyFile      string
}

type identityGroupHTTPResult struct {
	NotModified  bool
	ETag         string
	LastModified string
}

func loadIdentityGroupObservationsHTTP(ctx context.Context, opts identityGroupHTTPOptions) (IdentityGroupObservationFeed, identityGroupHTTPResult, error) {
	feedURL := opts.URL
	feedURL = strings.TrimSpace(feedURL)
	if feedURL == "" {
		return IdentityGroupObservationFeed{}, identityGroupHTTPResult{}, errors.New("identity group observations url is required")
	}
	parsed, err := url.Parse(feedURL)
	if err != nil {
		return IdentityGroupObservationFeed{}, identityGroupHTTPResult{}, fmt.Errorf("parse identity group observations url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return IdentityGroupObservationFeed{}, identityGroupHTTPResult{}, fmt.Errorf("identity group observations url scheme %q is not supported", parsed.Scheme)
	}
	client := opts.Client
	if client == nil {
		client, err = identityGroupHTTPClient(opts)
		if err != nil {
			return IdentityGroupObservationFeed{}, identityGroupHTTPResult{}, err
		}
	}
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return IdentityGroupObservationFeed{}, identityGroupHTTPResult{}, fmt.Errorf("create identity group observations request: %w", err)
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
		return IdentityGroupObservationFeed{}, identityGroupHTTPResult{}, fmt.Errorf("fetch identity group observations: %w", err)
	}
	defer response.Body.Close()
	result := identityGroupHTTPResult{
		ETag:         response.Header.Get("ETag"),
		LastModified: response.Header.Get("Last-Modified"),
	}
	if response.StatusCode == http.StatusNotModified {
		result.NotModified = true
		return IdentityGroupObservationFeed{}, result, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return IdentityGroupObservationFeed{}, result, fmt.Errorf("fetch identity group observations returned status %d", response.StatusCode)
	}
	feed, err := LoadIdentityGroupObservationFeedJSON(response.Body)
	return feed, result, err
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
	feed, result, err := loadIdentityGroupObservationsHTTP(ctx, identityGroupHTTPOptions{
		URL:             url,
		BearerToken:     opts.BearerToken,
		Timeout:         opts.Timeout,
		Client:          opts.HTTPClient,
		IfNoneMatch:     etag,
		IfModifiedSince: lastModified,
		TLSCAFile:       opts.TLSCAFile,
		TLSCertFile:     opts.TLSCertFile,
		TLSKeyFile:      opts.TLSKeyFile,
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
	groups := feed.Groups
	if !feed.Snapshot {
		if cache == nil || len(cache.Groups) == 0 {
			return nil, errors.New("identity group observations patch feed requires cached groups")
		}
		groups, err = ApplyIdentityGroupObservationPatches(cache.Groups, feed.Patches)
		if err != nil {
			return nil, err
		}
	}
	if cache != nil {
		recordIdentityGroupFeedSuccess(cache, url, result, groups)
	}
	return groups, nil
}

func identityGroupHTTPClient(opts identityGroupHTTPOptions) (*http.Client, error) {
	caFile := strings.TrimSpace(opts.TLSCAFile)
	certFile := strings.TrimSpace(opts.TLSCertFile)
	keyFile := strings.TrimSpace(opts.TLSKeyFile)
	if caFile == "" && certFile == "" && keyFile == "" {
		return http.DefaultClient, nil
	}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("identity group observations TLS client cert and key must be configured together")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("load identity group observations TLS CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("load identity group observations TLS CA file: no PEM certificates found")
		}
		tlsConfig.RootCAs = pool
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load identity group observations TLS client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Transport: transport}, nil
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

func ApplyIdentityGroupObservationPatches(base []model.IdentityGroup, patches []IdentityGroupObservationPatch) ([]model.IdentityGroup, error) {
	groups, err := validateIdentityGroups(base)
	if err != nil {
		return nil, err
	}
	patches, err = validateIdentityGroupObservationPatches(patches)
	if err != nil {
		return nil, err
	}
	out := append([]model.IdentityGroup(nil), groups...)
	index := make(map[string]int, len(out))
	for i, group := range out {
		index[group.VPC+"\x00"+group.Name] = i
	}
	for _, patch := range patches {
		switch normalizedIdentityGroupPatchOp(patch.Op) {
		case "upsert":
			key := patch.Group.VPC + "\x00" + patch.Group.Name
			if pos, ok := index[key]; ok {
				out[pos] = patch.Group
				continue
			}
			index[key] = len(out)
			out = append(out, patch.Group)
		case "delete":
			vpc, name := identityGroupPatchTarget(patch)
			key := vpc + "\x00" + name
			pos, ok := index[key]
			if !ok {
				continue
			}
			out = append(out[:pos], out[pos+1:]...)
			index = make(map[string]int, len(out))
			for i, group := range out {
				index[group.VPC+"\x00"+group.Name] = i
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].VPC != out[j].VPC {
			return out[i].VPC < out[j].VPC
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
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

func validateIdentityGroupObservationPatches(patches []IdentityGroupObservationPatch) ([]IdentityGroupObservationPatch, error) {
	out := append([]IdentityGroupObservationPatch(nil), patches...)
	for i := range out {
		op := normalizedIdentityGroupPatchOp(out[i].Op)
		out[i].Op = op
		switch op {
		case "upsert":
			if err := out[i].Group.Validate(); err != nil {
				return nil, fmt.Errorf("identity group patch %d: upsert group: %w", i, err)
			}
			if strings.TrimSpace(out[i].VPC) != "" && strings.TrimSpace(out[i].VPC) != out[i].Group.VPC {
				return nil, fmt.Errorf("identity group patch %d: vpc does not match upsert group", i)
			}
			if strings.TrimSpace(out[i].Name) != "" && strings.TrimSpace(out[i].Name) != out[i].Group.Name {
				return nil, fmt.Errorf("identity group patch %d: name does not match upsert group", i)
			}
		case "delete":
			vpc, name := identityGroupPatchTarget(out[i])
			if strings.TrimSpace(vpc) == "" {
				return nil, fmt.Errorf("identity group patch %d: delete vpc is required", i)
			}
			if strings.TrimSpace(name) == "" {
				return nil, fmt.Errorf("identity group patch %d: delete name is required", i)
			}
			out[i].VPC = strings.TrimSpace(vpc)
			out[i].Name = strings.TrimSpace(name)
		default:
			return nil, fmt.Errorf("identity group patch %d: unsupported op %q", i, out[i].Op)
		}
	}
	return out, nil
}

func normalizedIdentityGroupPatchOp(op string) string {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "add", "replace", "update", "upsert":
		return "upsert"
	case "delete", "remove":
		return "delete"
	default:
		return strings.ToLower(strings.TrimSpace(op))
	}
}

func identityGroupPatchTarget(patch IdentityGroupObservationPatch) (string, string) {
	vpc := strings.TrimSpace(patch.VPC)
	name := strings.TrimSpace(patch.Name)
	if vpc == "" {
		vpc = patch.Group.VPC
	}
	if name == "" {
		name = patch.Group.Name
	}
	return vpc, name
}
