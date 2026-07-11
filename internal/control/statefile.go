package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const DesiredStateOpenVSwitchExternalID = "netloom_desired_state"
const DesiredStateRevisionOpenVSwitchExternalID = "netloom_desired_state_revision"
const DesiredStateSummaryOpenVSwitchExternalID = "netloom_desired_state_summary"

type DesiredStateSummary struct {
	VPCs             int `json:"vpcs"`
	ProviderNetworks int `json:"provider_networks"`
	IdentityGroups   int `json:"identity_groups"`
	Subnets          int `json:"subnets"`
	Endpoints        int `json:"endpoints"`
	RouteTables      int `json:"route_tables"`
	PolicyRoutes     int `json:"policy_routes"`
	Gateways         int `json:"gateways"`
	NATRules         int `json:"nat_rules"`
	LoadBalancers    int `json:"load_balancers"`
	SecurityGroups   int `json:"security_groups"`
	CIDRGroups       int `json:"cidr_groups"`
	DNSRecords       int `json:"dns_records"`
	PolicyRollouts   int `json:"policy_rollouts"`
}

func LoadDesiredStateJSON(r io.Reader) (DesiredState, error) {
	var state DesiredState
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return DesiredState{}, fmt.Errorf("decode desired state: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return DesiredState{}, fmt.Errorf("decode desired state: multiple JSON documents")
	}
	return state, nil
}

func MarshalDesiredStateJSON(state DesiredState) ([]byte, error) {
	return json.Marshal(state)
}

func DesiredStateRevision(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ValidateDesiredStateRevision(raw []byte, revision string) error {
	revision = strings.TrimSpace(revision)
	if revision == "" {
		return nil
	}
	if got := DesiredStateRevision(raw); got != revision {
		return fmt.Errorf("desired state revision mismatch: got %s, want %s", got, revision)
	}
	return nil
}

func SummarizeDesiredState(state DesiredState) DesiredStateSummary {
	return DesiredStateSummary{
		VPCs:             len(state.VPCs),
		ProviderNetworks: len(state.ProviderNetworks),
		IdentityGroups:   len(state.IdentityGroups),
		Subnets:          len(state.Subnets),
		Endpoints:        len(state.Endpoints),
		RouteTables:      len(state.RouteTables),
		PolicyRoutes:     len(state.PolicyRoutes),
		Gateways:         len(state.Gateways),
		NATRules:         len(state.NATRules),
		LoadBalancers:    len(state.LoadBalancers),
		SecurityGroups:   len(state.SecurityGroups),
		CIDRGroups:       len(state.CIDRGroups),
		DNSRecords:       len(state.DNSRecords),
		PolicyRollouts:   len(state.PolicyRollouts),
	}
}

func MarshalDesiredStateSummaryJSON(state DesiredState) ([]byte, error) {
	return json.Marshal(SummarizeDesiredState(state))
}
