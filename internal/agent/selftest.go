package agent

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
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
	TraceEvents  int
	TCX          string
}

func selftestVPC() string {
	if value := strings.TrimSpace(os.Getenv("NETLOOM_SELFTEST_VPC")); value != "" {
		return value
	}
	return "default"
}

func RunSelfTest(ctx context.Context) (SelfTestResult, error) {
	vpc := selftestVPC()
	endpoint := model.Endpoint{
		ID:             "selftest-pod",
		VPC:            vpc,
		Subnet:         "default-subnet",
		IP:             netip.MustParseAddr("10.244.0.10"),
		Node:           "selftest-node",
		SecurityGroups: []string{"web"},
	}
	program, err := policy.CompileForEndpointWithContext(endpoint, map[string]model.SecurityGroup{
		"web": {
			Name: "web",
			VPC:  vpc,
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
	}, policy.CompileContext{
		IdentityResolver: policy.NewIdentityCache(),
	})
	if err != nil {
		return SelfTestResult{}, err
	}

	store := dataplane.NewInMemoryPolicyStore()
	backend := dataplane.NewPolicyBackend(store)
	if err := backend.ApplyEndpointProgram(ctx, program); err != nil {
		return SelfTestResult{}, err
	}
	endpointKey := program.EndpointID
	entries := store.Entries(endpointKey)
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
	allowed := dataplane.EvaluateObserved(endpointKey, entries, dataplane.Packet{
		RemoteIdentity: allowedIdentity,
		RemoteIP:       netip.MustParseAddr("10.244.1.10"),
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		DestPort:       443,
	}, recorder)
	denied := dataplane.EvaluateObserved(endpointKey, entries, dataplane.Packet{
		RemoteIdentity: deniedIdentity,
		RemoteIP:       netip.MustParseAddr("10.244.2.10"),
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
	conntrack := dataplane.NewInMemoryConntrackStore()
	statefulAllowed := dataplane.EvaluateStatefulObserved(endpointKey, entries, dataplane.Packet{
		RemoteIdentity: allowedIdentity,
		RemoteIP:       netip.MustParseAddr("10.244.1.10"),
		Direction:      dataplane.DirectionIngress,
		Protocol:       6,
		SourcePort:     55500,
		DestPort:       443,
	}, conntrack, recorder)
	if statefulAllowed.Verdict != dataplane.VerdictAllow || !statefulAllowed.Established {
		return SelfTestResult{}, fmt.Errorf("expected stateful allow packet to establish conntrack, got %+v", statefulAllowed)
	}
	statefulReply := dataplane.EvaluateStatefulObserved(endpointKey, nil, dataplane.Packet{
		RemoteIdentity: allowedIdentity,
		RemoteIP:       netip.MustParseAddr("10.244.1.10"),
		Direction:      dataplane.DirectionEgress,
		Protocol:       6,
		SourcePort:     443,
		DestPort:       55500,
	}, conntrack, recorder)
	if statefulReply.Verdict != dataplane.VerdictAllow || !statefulReply.Conntrack {
		return SelfTestResult{}, fmt.Errorf("expected stateful reverse packet to match conntrack, got %+v", statefulReply)
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
			protocol, hasProtocol, parseErr := tcxSelfTestProtocol()
			if parseErr != nil {
				return SelfTestResult{}, parseErr
			}
			rawPort := os.Getenv("NETLOOM_TCX_DPORT")
			if rawPort != "" || hasProtocol {
				port, parseErr := tcxSelfTestPort(protocol, rawPort)
				if parseErr != nil {
					return SelfTestResult{}, parseErr
				}
				if os.Getenv("NETLOOM_TCX_POLICY_SELFTEST") == "1" {
					tcxProgram, compileErr := compileTCXPolicySelfTest(source, protocol, port, action)
					if compileErr != nil {
						return SelfTestResult{}, compileErr
					}
					tcxResult, err = dataplane.RunTCXIPv4L4Policy(ctx, iface, tcxProgram, hold)
				} else {
					destPort := uint16(0)
					if port != nil {
						destPort = *port
					}
					tcxResult, err = dataplane.RunTCXIPv4L4ACL(ctx, iface, source, protocol, destPort, action, hold)
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
		EndpointID:   endpointKey,
		Entries:      len(entries),
		Allowed:      allowed.Verdict,
		Denied:       denied.Verdict,
		PolicyStats:  recorder.Metrics(endpointKey),
		DropEvents:   len(recorder.DropEvents()),
		PolicyEvents: len(recorder.PolicyEvents()),
		TraceEvents:  len(recorder.TraceEvents()),
		TCX:          tcxStatus,
	}, nil
}

func tcxSelfTestProtocol() (uint8, bool, error) {
	rawProtocol := os.Getenv("NETLOOM_TCX_PROTO")
	if rawProtocol == "" {
		return 6, false, nil
	}
	parsed, err := strconv.Atoi(rawProtocol)
	if err != nil {
		return 0, false, fmt.Errorf("invalid NETLOOM_TCX_PROTO: %w", err)
	}
	return uint8(parsed), true, nil
}

func tcxSelfTestPort(protocol uint8, rawPort string) (*uint16, error) {
	if rawPort == "" {
		if protocol == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("NETLOOM_TCX_DPORT is required for TCX protocol %d", protocol)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return nil, fmt.Errorf("invalid NETLOOM_TCX_DPORT: %w", err)
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid NETLOOM_TCX_DPORT: %d", port)
	}
	out := uint16(port)
	return &out, nil
}

func compileTCXPolicySelfTest(source netip.Addr, protocol uint8, port *uint16, action int32) (policy.Program, error) {
	modelProtocol, err := modelProtocolNumber(protocol)
	if err != nil {
		return policy.Program{}, err
	}
	modelAction := model.ActionAllow
	if action == dataplane.TCXDrop {
		modelAction = model.ActionDrop
	}
	vpc := selftestVPC()
	endpoint := model.Endpoint{
		ID:             "tcx-policy-selftest-pod",
		VPC:            vpc,
		Subnet:         "default-subnet",
		IP:             netip.MustParseAddr("10.244.0.10"),
		Node:           "selftest-node",
		SecurityGroups: []string{"tcx-policy"},
	}
	ports := []model.PortRange(nil)
	if port != nil {
		ports = []model.PortRange{{From: *port, To: *port}}
	}
	return policy.CompileForEndpointWithContext(endpoint, map[string]model.SecurityGroup{
		"tcx-policy": {
			Name: "tcx-policy",
			VPC:  vpc,
			Rules: []model.SecurityGroupRule{
				{
					ID:         "tcx-policy-l4",
					Priority:   100,
					Direction:  model.DirectionIngress,
					Protocol:   modelProtocol,
					RemoteCIDR: netip.PrefixFrom(source, 32),
					Ports:      ports,
					Action:     modelAction,
				},
			},
		},
	}, policy.CompileContext{
		IdentityResolver: policy.NewIdentityCache(),
	})
}

func modelProtocolNumber(protocol uint8) (model.Protocol, error) {
	switch protocol {
	case 6:
		return model.ProtocolTCP, nil
	case 17:
		return model.ProtocolUDP, nil
	case 1:
		return model.ProtocolICMP, nil
	default:
		return "", fmt.Errorf("unsupported TCX policy protocol %d", protocol)
	}
}
