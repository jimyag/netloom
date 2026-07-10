package control

import (
	"strings"
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
