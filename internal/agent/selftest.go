package agent

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/jimyag/netloom/internal/dataplane"
	"github.com/jimyag/netloom/internal/model"
	"github.com/jimyag/netloom/internal/policy"
)

type SelfTestResult struct {
	EndpointID   string
	Entries      int
	Allowed      dataplane.Verdict
	Denied       dataplane.Verdict
	PolicyStats  dataplane.PolicyMetrics
	DropEvents   int
	PolicyEvents int
	TCX          string
}

func RunSelfTest(ctx context.Context) (SelfTestResult, error) {
	endpoint := model.Endpoint{
		ID:             "selftest-pod",
		VPC:            "default",
		Subnet:         "default-subnet",
		IP:             netip.MustParseAddr("10.244.0.10"),
		Node:           "selftest-node",
		SecurityGroups: []string{"web"},
	}
	program, err := policy.CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"web": {
			Name: "web",
			VPC:  "default",
			Rules: []model.SecurityGroupRule{
				{
					ID:         "allow-https",
					Priority:   100,
					Direction:  model.DirectionIngress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("10.244.1.0/24"),
					Ports:      []model.PortRange{{From: 443, To: 443}},
					Action:     model.ActionAllow,
					Stateful:   true,
					Log:        true,
				},
				{
					ID:         "deny-range",
					Priority:   1,
					Direction:  model.DirectionIngress,
					Protocol:   model.ProtocolTCP,
					RemoteCIDR: netip.MustParsePrefix("10.244.2.0/24"),
					Ports:      []model.PortRange{{From: 30000, To: 30015}},
					Action:     model.ActionDrop,
					Log:        true,
				},
			},
		},
	})
	if err != nil {
		return SelfTestResult{}, err
	}

	store := dataplane.NewInMemoryPolicyStore()
	backend := dataplane.NewPolicyBackend(store)
	if err := backend.ApplyEndpointProgram(ctx, program); err != nil {
		return SelfTestResult{}, err
	}
	entries := store.Entries(endpoint.ID)
	var allowedIdentity, deniedIdentity uint32
	for _, entry := range program.MapEntries {
		switch entry.RuleID {
		case "allow-https":
			allowedIdentity = entry.Key.RemoteIdentity
		case "deny-range":
			deniedIdentity = entry.Key.RemoteIdentity
		}
	}
	if allowedIdentity == 0 || deniedIdentity == 0 {
		return SelfTestResult{}, fmt.Errorf("selftest policy did not compile expected remote identities")
	}

	recorder := dataplane.NewPolicyRecorder()
	allowed := dataplane.EvaluateObserved(endpoint.ID, entries, dataplane.Packet{
		RemoteIdentity: allowedIdentity,
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	}, recorder)
	denied := dataplane.EvaluateObserved(endpoint.ID, entries, dataplane.Packet{
		RemoteIdentity: deniedIdentity,
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		DestPort:       30008,
	}, recorder)

	if allowed.Verdict != dataplane.VerdictAllow {
		return SelfTestResult{}, fmt.Errorf("expected https packet to be allowed, got %s", allowed.Verdict)
	}
	if denied.Verdict != dataplane.VerdictDrop {
		return SelfTestResult{}, fmt.Errorf("expected denied range packet to be dropped, got %s", denied.Verdict)
	}

	tcxStatus := "not-requested"
	if iface := os.Getenv("NETLOOM_TCX_SELFTEST_IFACE"); iface != "" {
		action := dataplane.TCXPass
		actionName := "pass"
		if os.Getenv("NETLOOM_TCX_VERDICT") == "drop" {
			action = dataplane.TCXDrop
			actionName = "drop"
		}
		hold := time.Duration(0)
		if raw := os.Getenv("NETLOOM_TCX_HOLD_MS"); raw != "" {
			ms, err := strconv.Atoi(raw)
			if err != nil {
				return SelfTestResult{}, fmt.Errorf("invalid NETLOOM_TCX_HOLD_MS: %w", err)
			}
			hold = time.Duration(ms) * time.Millisecond
		}
		var tcxResult dataplane.TCXSelfTestResult
		var err error
		if rawSource := os.Getenv("NETLOOM_TCX_SRC4"); rawSource != "" {
			source, parseErr := netip.ParseAddr(rawSource)
			if parseErr != nil {
				return SelfTestResult{}, fmt.Errorf("invalid NETLOOM_TCX_SRC4: %w", parseErr)
			}
			if rawPort := os.Getenv("NETLOOM_TCX_DPORT"); rawPort != "" {
				port, parseErr := strconv.Atoi(rawPort)
				if parseErr != nil {
					return SelfTestResult{}, fmt.Errorf("invalid NETLOOM_TCX_DPORT: %w", parseErr)
				}
				protocol := uint8(6)
				if rawProtocol := os.Getenv("NETLOOM_TCX_PROTO"); rawProtocol != "" {
					parsed, parseErr := strconv.Atoi(rawProtocol)
					if parseErr != nil {
						return SelfTestResult{}, fmt.Errorf("invalid NETLOOM_TCX_PROTO: %w", parseErr)
					}
					protocol = uint8(parsed)
				}
				if os.Getenv("NETLOOM_TCX_POLICY_SELFTEST") == "1" {
					tcxProgram, compileErr := compileTCXPolicySelfTest(source, protocol, uint16(port), action)
					if compileErr != nil {
						return SelfTestResult{}, compileErr
					}
					tcxResult, err = dataplane.RunTCXIPv4L4Policy(ctx, iface, tcxProgram, hold)
				} else {
					tcxResult, err = dataplane.RunTCXIPv4L4ACL(ctx, iface, source, protocol, uint16(port), action, hold)
				}
			} else {
				tcxResult, err = dataplane.RunTCXIPv4SourceACL(ctx, iface, source, action, hold)
			}
		} else {
			tcxResult, err = dataplane.RunTCXVerdict(ctx, iface, action, hold)
		}
		if err != nil {
			return SelfTestResult{}, fmt.Errorf("tcx selftest: %w", err)
		}
		tcxStatus = fmt.Sprintf("attached:%s:%s:%s:%s", tcxResult.Interface, tcxResult.Direction, tcxResult.Mode, actionName)
	}

	return SelfTestResult{
		EndpointID:   endpoint.ID,
		Entries:      len(entries),
		Allowed:      allowed.Verdict,
		Denied:       denied.Verdict,
		PolicyStats:  recorder.Metrics(endpoint.ID),
		DropEvents:   len(recorder.DropEvents()),
		PolicyEvents: len(recorder.PolicyEvents()),
		TCX:          tcxStatus,
	}, nil
}

func compileTCXPolicySelfTest(source netip.Addr, protocol uint8, port uint16, action int32) (policy.Program, error) {
	modelProtocol, err := modelProtocolNumber(protocol)
	if err != nil {
		return policy.Program{}, err
	}
	modelAction := model.ActionAllow
	if action == dataplane.TCXDrop {
		modelAction = model.ActionDrop
	}
	endpoint := model.Endpoint{
		ID:             "tcx-policy-selftest-pod",
		VPC:            "default",
		Subnet:         "default-subnet",
		IP:             netip.MustParseAddr("10.244.0.10"),
		Node:           "selftest-node",
		SecurityGroups: []string{"tcx-policy"},
	}
	return policy.CompileForEndpoint(endpoint, map[string]model.SecurityGroup{
		"tcx-policy": {
			Name: "tcx-policy",
			VPC:  "default",
			Rules: []model.SecurityGroupRule{
				{
					ID:         "tcx-policy-l4",
					Priority:   100,
					Direction:  model.DirectionIngress,
					Protocol:   modelProtocol,
					RemoteCIDR: netip.PrefixFrom(source, 32),
					Ports:      []model.PortRange{{From: port, To: port}},
					Action:     modelAction,
				},
			},
		},
	})
}

func modelProtocolNumber(protocol uint8) (model.Protocol, error) {
	switch protocol {
	case 6:
		return model.ProtocolTCP, nil
	case 17:
		return model.ProtocolUDP, nil
	default:
		return "", fmt.Errorf("unsupported TCX policy protocol %d", protocol)
	}
}
