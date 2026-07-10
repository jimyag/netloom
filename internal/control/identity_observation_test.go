package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimyag/netloom/internal/model"
)

func TestLoadIdentityGroupObservationsJSONAcceptsDocumentAndArray(t *testing.T) {
	groups, err := LoadIdentityGroupObservationsJSON(strings.NewReader(`{"identity_groups":[{"name":"frontend","vpc":"prod","endpoint_ids":["pod-a"],"source":"cmdb"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Name != "frontend" || groups[0].Source != "cmdb" {
		t.Fatalf("groups = %+v, want frontend cmdb", groups)
	}

	groups, err = LoadIdentityGroupObservationsJSON(strings.NewReader(`[{"name":"backend","vpc":"prod","endpoint_ids":["pod-b"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Name != "backend" {
		t.Fatalf("groups = %+v, want backend array input", groups)
	}
}

func TestLoadIdentityGroupObservationFeedJSONAcceptsIncrementalPatches(t *testing.T) {
	feed, err := LoadIdentityGroupObservationFeedJSON(strings.NewReader(`{"identity_group_patches":[{"op":"upsert","group":{"name":"frontend","vpc":"prod","source":"cmdb","endpoint_ids":["pod-a"]}},{"op":"delete","vpc":"prod","name":"old"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if feed.Snapshot || len(feed.Patches) != 2 || feed.Patches[0].Op != "upsert" || feed.Patches[1].Op != "delete" {
		t.Fatalf("feed = %+v, want incremental upsert/delete patches", feed)
	}

	_, err = LoadIdentityGroupObservationsJSON(strings.NewReader(`{"identity_group_patches":[{"op":"delete","vpc":"prod","name":"old"}]}`))
	if err == nil || !strings.Contains(err.Error(), "requires cached groups") {
		t.Fatalf("err = %v, want cached groups error for legacy snapshot loader", err)
	}
}

func TestLoadIdentityGroupObservationsHTTPUsesBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Fatalf("authorization = %q, want bearer token", got)
		}
		_, _ = w.Write([]byte(`{"identity_groups":[{"name":"frontend","vpc":"prod","source":"cmdb","endpoint_ids":["pod-a"]}]}`))
	}))
	defer server.Close()

	groups, err := LoadIdentityGroupObservationsHTTP(context.Background(), server.URL, "secret-token", time.Second, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Name != "frontend" || groups[0].Source != "cmdb" {
		t.Fatalf("groups = %+v, want remote frontend group", groups)
	}
}

func TestMergeIdentityGroupObservationsAppliesRemotePatchFeedToCache(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&requests, 1) == 1 {
			w.Header().Set("ETag", `"snapshot"`)
			_, _ = w.Write([]byte(`{"identity_groups":[{"name":"frontend","vpc":"prod","source":"cmdb","endpoint_ids":["pod-a"]},{"name":"backend","vpc":"prod","source":"cmdb","endpoint_ids":["pod-b"]}]}`))
			return
		}
		w.Header().Set("ETag", `"patch-1"`)
		_, _ = w.Write([]byte(`{"identity_group_patches":[{"op":"upsert","group":{"name":"frontend","vpc":"prod","source":"cmdb","endpoint_ids":["pod-c"]}},{"op":"delete","vpc":"prod","name":"backend"},{"op":"add","group":{"name":"worker","vpc":"prod","source":"cmdb","endpoint_ids":["pod-d"]}}]}`))
	}))
	defer server.Close()

	cache := &IdentityGroupObservationCache{}
	state, err := MergeIdentityGroupObservations(context.Background(), DesiredState{}, IdentityGroupObservationOptions{
		URL:        server.URL,
		HTTPClient: server.Client(),
		Cache:      cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.IdentityGroups) != 2 || cache.ETag != `"snapshot"` {
		t.Fatalf("state = %+v cache = %+v, want initial snapshot", state.IdentityGroups, cache)
	}

	state, err = MergeIdentityGroupObservations(context.Background(), DesiredState{}, IdentityGroupObservationOptions{
		URL:        server.URL,
		HTTPClient: server.Client(),
		Cache:      cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.IdentityGroups) != 2 || state.IdentityGroups[0].Name != "frontend" || state.IdentityGroups[0].EndpointIDs[0] != "pod-c" || state.IdentityGroups[1].Name != "worker" {
		t.Fatalf("identity groups = %+v, want patched frontend and worker only", state.IdentityGroups)
	}
	if cache.ETag != `"patch-1"` || len(cache.Groups) != 2 {
		t.Fatalf("cache = %+v, want patched cache and patch etag", cache)
	}
}

func TestMergeIdentityGroupObservationsRejectsRemotePatchFeedWithoutCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"identity_group_patches":[{"op":"delete","vpc":"prod","name":"backend"}]}`))
	}))
	defer server.Close()

	_, err := MergeIdentityGroupObservations(context.Background(), DesiredState{}, IdentityGroupObservationOptions{
		URL:        server.URL,
		HTTPClient: server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "requires cached groups") {
		t.Fatalf("err = %v, want cached groups error", err)
	}
}

func TestLoadIdentityGroupObservationsHTTPRejectsBadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := LoadIdentityGroupObservationsHTTP(context.Background(), server.URL, "", time.Second, server.Client())
	if err == nil || !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("err = %v, want status 401", err)
	}
}

func TestMergeIdentityGroupObservationsFetchesRemoteFeedWithMTLS(t *testing.T) {
	caPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM := identityGroupTestCertificates(t)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	serverCertPath := filepath.Join(dir, "server.pem")
	serverKeyPath := filepath.Join(dir, "server-key.pem")
	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client-key.pem")
	writeTestFile(t, caPath, caPEM)
	writeTestFile(t, serverCertPath, serverCertPEM)
	writeTestFile(t, serverKeyPath, serverKeyPEM)
	writeTestFile(t, clientCertPath, clientCertPEM)
	writeTestFile(t, clientKeyPath, clientKeyPEM)

	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("append client ca")
	}
	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != "netloom-client" {
			t.Fatalf("client certificate = %+v, want netloom-client", r.TLS)
		}
		_, _ = w.Write([]byte(`{"identity_groups":[{"name":"frontend","vpc":"prod","source":"cmdb","endpoint_ids":["pod-a"]}]}`))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	state, err := MergeIdentityGroupObservations(context.Background(), DesiredState{}, IdentityGroupObservationOptions{
		URL:         server.URL,
		Timeout:     time.Second,
		TLSCAFile:   caPath,
		TLSCertFile: clientCertPath,
		TLSKeyFile:  clientKeyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.IdentityGroups) != 1 || state.IdentityGroups[0].Name != "frontend" || state.IdentityGroups[0].Source != "cmdb" {
		t.Fatalf("identity groups = %+v, want mtls remote frontend group", state.IdentityGroups)
	}
}

func TestMergeIdentityGroupObservationsRejectsIncompleteMTLSConfig(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.pem")
	writeTestFile(t, certPath, []byte("not used"))
	_, err := MergeIdentityGroupObservations(context.Background(), DesiredState{}, IdentityGroupObservationOptions{
		URL:         "https://example.invalid/groups.json",
		TLSCertFile: certPath,
	})
	if err == nil || !strings.Contains(err.Error(), "cert and key must be configured together") {
		t.Fatalf("err = %v, want incomplete TLS config error", err)
	}
}

func TestMergeIdentityGroupObservationsUsesConditionalHTTPPolling(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&requests, 1) == 1 {
			w.Header().Set("ETag", `"v1"`)
			w.Header().Set("Last-Modified", "Fri, 10 Jul 2026 01:00:00 GMT")
			_, _ = w.Write([]byte(`{"identity_groups":[{"name":"frontend","vpc":"prod","endpoint_ids":["pod-a"]}]}`))
			return
		}
		if got := r.Header.Get("If-None-Match"); got != `"v1"` {
			t.Fatalf("If-None-Match = %q, want v1 etag", got)
		}
		if got := r.Header.Get("If-Modified-Since"); got != "Fri, 10 Jul 2026 01:00:00 GMT" {
			t.Fatalf("If-Modified-Since = %q, want cached last-modified", got)
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	cache := &IdentityGroupObservationCache{}
	state, err := MergeIdentityGroupObservations(context.Background(), DesiredState{}, IdentityGroupObservationOptions{
		URL:        server.URL,
		Now:        time.Date(2026, 7, 10, 1, 1, 0, 0, time.UTC),
		HTTPClient: server.Client(),
		Cache:      cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cache.ETag != `"v1"` || cache.LastModified == "" {
		t.Fatalf("cache = %+v, want etag and last-modified", cache)
	}
	state, err = MergeIdentityGroupObservations(context.Background(), state, IdentityGroupObservationOptions{
		URL:        server.URL,
		Now:        time.Date(2026, 7, 10, 1, 1, 30, 0, time.UTC),
		HTTPClient: server.Client(),
		Cache:      cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.IdentityGroups) != 1 || state.IdentityGroups[0].Name != "frontend" {
		t.Fatalf("identity groups = %+v, want cached frontend after 304", state.IdentityGroups)
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Fatalf("requests = %d, want initial request and conditional request", got)
	}
}

func TestMergeIdentityGroupObservationsBacksOffAfterRemoteFailure(t *testing.T) {
	var fail bool
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		if fail {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"identity_groups":[{"name":"frontend","vpc":"prod","endpoint_ids":["pod-a"]}]}`))
	}))
	defer server.Close()

	cache := &IdentityGroupObservationCache{}
	_, err := MergeIdentityGroupObservations(context.Background(), DesiredState{}, IdentityGroupObservationOptions{
		URL:         server.URL,
		Now:         time.Date(2026, 7, 10, 1, 0, 0, 0, time.UTC),
		HTTPClient:  server.Client(),
		Cache:       cache,
		BackoffBase: 30 * time.Second,
		BackoffMax:  time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	state, err := MergeIdentityGroupObservations(context.Background(), DesiredState{}, IdentityGroupObservationOptions{
		URL:         server.URL,
		Now:         time.Date(2026, 7, 10, 1, 0, 5, 0, time.UTC),
		HTTPClient:  server.Client(),
		Cache:       cache,
		BackoffBase: 30 * time.Second,
		BackoffMax:  time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.IdentityGroups) != 1 || state.IdentityGroups[0].Name != "frontend" {
		t.Fatalf("identity groups = %+v, want cached frontend after failure", state.IdentityGroups)
	}
	if cache.ConsecutiveFailures != 1 || !cache.NextAttempt.Equal(time.Date(2026, 7, 10, 1, 0, 35, 0, time.UTC)) {
		t.Fatalf("cache = %+v, want one failure and 30s backoff", cache)
	}
	state, err = MergeIdentityGroupObservations(context.Background(), DesiredState{}, IdentityGroupObservationOptions{
		URL:         server.URL,
		Now:         time.Date(2026, 7, 10, 1, 0, 20, 0, time.UTC),
		HTTPClient:  server.Client(),
		Cache:       cache,
		BackoffBase: 30 * time.Second,
		BackoffMax:  time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Fatalf("requests = %d, want no extra request during backoff", got)
	}
	if len(state.IdentityGroups) != 1 || state.IdentityGroups[0].Name != "frontend" {
		t.Fatalf("identity groups = %+v, want cached frontend during backoff", state.IdentityGroups)
	}
}

func TestMergeIdentityGroupObservationsMergesLocalAndRemoteFeeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"identity_groups":[{"name":"remote-group","vpc":"prod","endpoint_ids":["pod-remote"]}]}`))
	}))
	defer server.Close()

	state, err := MergeIdentityGroupObservations(context.Background(), DesiredState{}, IdentityGroupObservationOptions{
		LocalGroups: []model.IdentityGroup{{
			Name:        "local-group",
			VPC:         "prod",
			EndpointIDs: []string{"pod-local"},
		}},
		URL:        server.URL,
		Timeout:    time.Second,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.IdentityGroups) != 2 || state.IdentityGroups[0].Name != "local-group" || state.IdentityGroups[1].Name != "remote-group" {
		t.Fatalf("identity groups = %+v, want local and remote groups", state.IdentityGroups)
	}
}

func TestMergeIdentityGroupsUpsertsLatestObservedGroup(t *testing.T) {
	base := []model.IdentityGroup{{
		Name:        "frontend",
		VPC:         "prod",
		Source:      "cmdb",
		ObservedAt:  time.Date(2026, 7, 10, 1, 0, 0, 0, time.UTC),
		TTLSeconds:  60,
		EndpointIDs: []string{"pod-a"},
	}}
	observed := []model.IdentityGroup{{
		Name:        "frontend",
		VPC:         "prod",
		Source:      "cmdb",
		ObservedAt:  time.Date(2026, 7, 10, 1, 1, 0, 0, time.UTC),
		TTLSeconds:  60,
		EndpointIDs: []string{"pod-b"},
	}, {
		Name:        "backend",
		VPC:         "prod",
		EndpointIDs: []string{"pod-c"},
	}}

	merged, err := MergeIdentityGroups(base, observed)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 2 {
		t.Fatalf("groups = %d, want 2: %+v", len(merged), merged)
	}
	if merged[1].Name != "frontend" || len(merged[1].EndpointIDs) != 1 || merged[1].EndpointIDs[0] != "pod-b" {
		t.Fatalf("frontend group = %+v, want latest observed pod-b", merged[1])
	}
}

func TestMergeIdentityGroupsKeepsStaticDesiredGroupOverObservedGroup(t *testing.T) {
	merged, err := MergeIdentityGroups([]model.IdentityGroup{{
		Name:        "frontend",
		VPC:         "prod",
		EndpointIDs: []string{"pod-static"},
	}}, []model.IdentityGroup{{
		Name:        "frontend",
		VPC:         "prod",
		Source:      "cmdb",
		ObservedAt:  time.Date(2026, 7, 10, 1, 0, 0, 0, time.UTC),
		TTLSeconds:  60,
		EndpointIDs: []string{"pod-observed"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 1 || merged[0].EndpointIDs[0] != "pod-static" {
		t.Fatalf("groups = %+v, want static desired group to win", merged)
	}
}

func TestPruneExpiredIdentityGroups(t *testing.T) {
	groups, err := PruneExpiredIdentityGroups([]model.IdentityGroup{{
		Name:        "expired",
		VPC:         "prod",
		ObservedAt:  time.Date(2026, 7, 10, 1, 0, 0, 0, time.UTC),
		TTLSeconds:  60,
		EndpointIDs: []string{"pod-a"},
	}, {
		Name:        "active",
		VPC:         "prod",
		ObservedAt:  time.Date(2026, 7, 10, 1, 0, 1, 0, time.UTC),
		TTLSeconds:  60,
		EndpointIDs: []string{"pod-b"},
	}, {
		Name:        "static",
		VPC:         "prod",
		EndpointIDs: []string{"pod-c"},
	}}, time.Date(2026, 7, 10, 1, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0].Name != "active" || groups[1].Name != "static" {
		t.Fatalf("groups = %+v, want active and static", groups)
	}
}

func identityGroupTestCertificates(t *testing.T) ([]byte, []byte, []byte, []byte, []byte) {
	t.Helper()
	caKey, caPEM, caCert := identityGroupTestCA(t)
	serverCertPEM, serverKeyPEM := identityGroupTestSignedCertificate(t, caCert, caKey, x509.ExtKeyUsageServerAuth, "netloom-server", []string{"127.0.0.1"})
	clientCertPEM, clientKeyPEM := identityGroupTestSignedCertificate(t, caCert, caKey, x509.ExtKeyUsageClientAuth, "netloom-client", nil)
	return caPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM
}

func identityGroupTestCA(t *testing.T) (*ecdsa.PrivateKey, []byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "netloom-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), template
}

func identityGroupTestSignedCertificate(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, usage x509.ExtKeyUsage, commonName string, ips []string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	for _, ip := range ips {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
