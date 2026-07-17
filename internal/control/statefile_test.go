package control

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jimyag/netloom/internal/model"
)

func TestLoadDesiredStateJSONDecodesSnakeCaseState(t *testing.T) {
	state, err := LoadDesiredStateJSON(strings.NewReader(`{
		"vpcs": [{"name": "prod"}],
		"identity_groups": [{"name": "frontend-api", "vpc": "prod", "source": "cmdb/team-a", "observed_at": "2026-07-10T01:02:03Z", "ttl_seconds": 300, "endpoint_ids": ["pod-a"], "endpoint_selector": {"tier": "frontend"}, "endpoint_expressions": [{"key": "role", "operator": "In", "values": ["api"]}]}],
		"provider_networks": [{"name": "physnet-a", "isolation": "exclusive", "controller_targets": ["tcp:192.0.2.10:6653"], "qos": {"egress_rate_bps": 1000000000, "egress_burst_bps": 64000}, "tenant_quotas": [{"tenant": "prod", "max_subnets": 2, "max_endpoints": 10}], "tenant_queues": [{"tenant": "prod", "queue_id": 10, "protocol": "tcp", "ports": [{"from": 443, "to": 443}], "endpoint_selector": {"app": "web"}, "endpoint_expressions": [{"key": "env", "operator": "In", "values": ["prod"]}], "identity_groups": ["frontend-api"], "identity_selector": {"tier": "frontend"}, "identity_expressions": [{"key": "role", "operator": "In", "values": ["api"]}], "min_rate_bps": 100000000, "max_rate_bps": 500000000, "burst_bps": 64000}], "nodes": [{"node": "node-a", "interface": "bond0.100"}, {"node": "node-b", "interfaces": ["ens5", "eth1"]}]}],
		"subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1", "exclude_cidrs": ["10.10.0.128/25"]}],
		"endpoints": [{"id": "pod-a", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.10", "node": "node-a", "security_groups": ["web"], "named_ports": [{"name": "http", "protocol": "tcp", "port": 8080}], "labels": {"app": "web", "env": "prod"}}],
		"route_tables": [{"name": "main", "vpc": "prod", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.10.0.253", "10.10.0.254"]}]}],
		"policy_routes": [{"name": "fw", "vpc": "prod", "priority": 100, "match": {"source": "10.10.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "src_ports": [{"from": 32000, "to": 32010}], "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.10.0.253"]}}],
		"gateways": [{"name": "gw-a", "vpc": "prod", "node": "node-a", "external_if": "eth0", "lan_ip": "10.10.0.254"}],
		"nat_rules": [{"name": "egress", "vpc": "prod", "type": "snat", "match_cidr": "10.10.0.0/24", "external_ip": "198.51.100.10"}],
		"load_balancers": [{"name": "web", "vpc": "prod", "vip": "10.96.0.10", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.10.0.10", "port": 8080, "healthy": true}]}, {"name": "metrics", "port": 9090, "protocol": "tcp", "backends": [{"ip": "10.10.0.10", "port": 9091}]}], "subnets": ["apps"], "health_check": {"enabled": true, "interval": 10, "timeout": 30, "success_count": 2, "failure_count": 4}}],
		"security_groups": [{"name": "web", "vpc": "prod", "tier": 1, "rules": [{"id": "allow-web", "priority": 10, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.10.1.0/24", "except_cidrs": ["10.10.1.128/25"], "ports": [{"from": 443, "to": 443}], "action": "allow", "stateful": true}, {"id": "allow-api", "priority": 20, "direction": "egress", "protocol": "tcp", "remote_fqdns": [{"match_name": "api.example.com"}, {"match_pattern": "*.svc.example.com"}], "ports": [{"from": 443, "to": 443}], "action": "allow"}, {"id": "allow-corp", "priority": 30, "direction": "egress", "protocol": "tcp", "remote_cidr_group": "corp", "ports": [{"from": 8443, "to": 8443}], "action": "allow"}, {"id": "allow-icmp-echo", "priority": 40, "direction": "egress", "protocol": "icmp", "remote_cidr": "198.51.100.0/24", "icmp_type": 8, "icmp_code": 0, "action": "allow"}, {"id": "allow-named-http", "priority": 50, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.10.1.0/24", "named_ports": ["http"], "action": "allow"}, {"id": "allow-world", "priority": 60, "direction": "egress", "protocol": "tcp", "remote_entities": ["world"], "ports": [{"from": 443, "to": 443}], "action": "allow"}, {"id": "allow-selector", "priority": 70, "direction": "ingress", "protocol": "tcp", "remote_endpoint_selector": {"app": "client"}, "remote_endpoint_expressions": [{"key": "env", "operator": "In", "values": ["prod"]}], "ports": [{"from": 9443, "to": 9443}], "action": "allow"}, {"id": "allow-service", "priority": 80, "direction": "egress", "protocol": "any", "remote_service": "web", "action": "allow"}]}],
		"cidr_groups": [{"name": "corp", "vpc": "prod", "cidrs": ["10.20.0.0/16", "2001:db8::/64"], "entries": [{"cidr": "198.51.100.0/24", "except_cidrs": ["198.51.100.128/25"]}]}],
		"dns_records": [{"name": "api.example.com", "ips": ["203.0.113.10"], "ttl_seconds": 60, "observed_at": "2026-05-30T12:00:00Z"}],
		"policy_rollouts": [{"name": "web-canary", "node": "node-a", "endpoints": ["prod/pod-a"], "batch_size": 1, "pressure_aware": true, "pressure_threshold_percent": 80, "pressure_aware_min_batch_size": 1, "slo_gated": true, "slo_drop_threshold_percent": 5, "slo_min_packets": 100, "slo_window_count": 2, "slo_window_interval_ms": 250, "approval_required": true, "approved": true, "approval_ref": "chg-1234", "approval_signature": "sha256=abc123", "approval_expires_at": "2026-07-10T12:00:00Z", "approval_callback_url": "http://127.0.0.1:8081/approve", "approval_callback_timeout_ms": 750, "ack_required": true, "acknowledged": true, "ack_ref": "ack-1234", "ack_expires_at": "2026-07-10T12:30:00Z", "risk_ack_required": true, "risk_acknowledged": true, "risk_ack_ref": "risk-1234", "finalize_required": true, "finalized": true, "finalize_ref": "final-1234", "finalize_expires_at": "2026-07-10T13:00:00Z", "change_poll_url": "http://127.0.0.1:8081/poll", "change_poll_timeout_ms": 800, "change_status_url": "http://127.0.0.1:8081/status", "change_status_timeout_ms": 900, "pause_after_batches": 1, "promotion_percent": 50, "probes": [{"name": "web-ready", "type": "http", "url": "http://127.0.0.1:8080/healthz", "expected_status": 200, "expected_body_contains": "ready", "timeout_ms": 1000}]}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := state.VPCs[0].Name; got != "prod" {
		t.Fatalf("vpc = %s, want prod", got)
	}
	if got := state.Endpoints[0].SecurityGroups[0]; got != "web" {
		t.Fatalf("security group = %s, want web", got)
	}
	if got := state.ProviderNetworks[0].Nodes[0].Interface; got != "bond0.100" {
		t.Fatalf("provider network node interface = %s, want bond0.100", got)
	}
	if got := state.ProviderNetworks[0].Isolation; got != "exclusive" {
		t.Fatalf("provider network isolation = %s, want exclusive", got)
	}
	if got := state.ProviderNetworks[0].ControllerTargets[0]; got != "tcp:192.0.2.10:6653" {
		t.Fatalf("provider network controller target = %s, want tcp:192.0.2.10:6653", got)
	}
	if got := state.ProviderNetworks[0].QoS.EgressRateBPS; got != 1000000000 {
		t.Fatalf("provider network qos egress rate = %d, want 1000000000", got)
	}
	if got := state.ProviderNetworks[0].QoS.EgressBurstBPS; got != 64000 {
		t.Fatalf("provider network qos egress burst = %d, want 64000", got)
	}
	if got := state.ProviderNetworks[0].TenantQuotas[0]; got.Tenant != "prod" || got.MaxSubnets != 2 || got.MaxEndpoints != 10 {
		t.Fatalf("provider network tenant quota = %+v, want prod 2/10", got)
	}
	if got := state.ProviderNetworks[0].TenantQueues[0]; got.Tenant != "prod" || got.QueueID != 10 || got.Protocol != "tcp" || got.Ports[0].From != 443 || got.Ports[0].To != 443 || got.MinRateBPS != 100000000 || got.MaxRateBPS != 500000000 || got.BurstBPS != 64000 {
		t.Fatalf("provider network tenant queue = %+v, want prod queue 10", got)
	}
	if got := state.ProviderNetworks[0].TenantQueues[0]; got.EndpointSelector["app"] != "web" || len(got.EndpointExpressions) != 1 || got.EndpointExpressions[0].Key != "env" {
		t.Fatalf("provider network tenant queue selector = %+v expressions=%+v, want app/web env expression", got.EndpointSelector, got.EndpointExpressions)
	}
	if got := state.ProviderNetworks[0].TenantQueues[0]; len(got.IdentityGroups) != 1 || got.IdentityGroups[0] != "frontend-api" {
		t.Fatalf("provider network tenant queue identity groups = %+v, want frontend-api", got.IdentityGroups)
	}
	if got := state.ProviderNetworks[0].TenantQueues[0]; got.IdentitySelector["tier"] != "frontend" || len(got.IdentityExpressions) != 1 || got.IdentityExpressions[0].Key != "role" {
		t.Fatalf("provider network tenant queue identity selector = %+v expressions=%+v, want frontend/api identity selector", got.IdentitySelector, got.IdentityExpressions)
	}
	if got := state.IdentityGroups[0]; got.Name != "frontend-api" || got.VPC != "prod" || len(got.EndpointIDs) != 1 || got.EndpointIDs[0] != "pod-a" {
		t.Fatalf("identity group = %+v, want frontend-api with pod-a", got)
	}
	if got := state.IdentityGroups[0]; got.Source != "cmdb/team-a" || got.TTLSeconds != 300 || !got.ObservedAt.Equal(time.Date(2026, 7, 10, 1, 2, 3, 0, time.UTC)) {
		t.Fatalf("identity group feed metadata = %+v, want cmdb source and ttl", got)
	}
	if got := state.ProviderNetworks[0].Nodes[1].Interfaces[1]; got != "eth1" {
		t.Fatalf("provider network node candidate interface = %s, want eth1", got)
	}
	if got := state.Endpoints[0].NamedPorts[0].Name; got != "http" {
		t.Fatalf("named port = %s, want http", got)
	}
	if got := state.Endpoints[0].Labels["app"]; got != "web" {
		t.Fatalf("endpoint label app = %s, want web", got)
	}
	if got := state.Subnets[0].ExcludeCIDRs[0].String(); got != "10.10.0.128/25" {
		t.Fatalf("exclude cidr = %s, want 10.10.0.128/25", got)
	}
	if got := state.PolicyRoutes[0].Action.NextHops[0].String(); got != "10.10.0.253" {
		t.Fatalf("policy route next hop = %s", got)
	}
	if got := state.PolicyRoutes[0].Match.SrcPorts[0]; got.From != 32000 || got.To != 32010 {
		t.Fatalf("policy route src port = %+v", got)
	}
	if got := state.RouteTables[0].Routes[0].NextHops[1].String(); got != "10.10.0.254" {
		t.Fatalf("static route ecmp next hop = %s, want 10.10.0.254", got)
	}
	if got := state.LoadBalancers[0].Ports[0].Backends[0].Port; got != 8080 {
		t.Fatalf("load balancer backend port = %d, want 8080", got)
	}
	if got := state.LoadBalancers[0].Ports[1].Backends[0].Port; got != 9091 {
		t.Fatalf("load balancer multi-port backend port = %d, want 9091", got)
	}
	if state.LoadBalancers[0].Ports[0].Backends[0].Healthy == nil || !*state.LoadBalancers[0].Ports[0].Backends[0].Healthy {
		t.Fatalf("load balancer backend healthy = %v, want true", state.LoadBalancers[0].Ports[0].Backends[0].Healthy)
	}
	if got := state.LoadBalancers[0].HealthCheck.Interval; got != 10 {
		t.Fatalf("load balancer health check interval = %d, want 10", got)
	}
	if got := state.SecurityGroups[0].Rules[1].RemoteFQDNs[0].MatchName; got != "api.example.com" {
		t.Fatalf("remote fqdn match name = %s, want api.example.com", got)
	}
	if got := state.SecurityGroups[0].Tier; got != 1 {
		t.Fatalf("security group tier = %d, want 1", got)
	}
	if got := state.SecurityGroups[0].Rules[0].ExceptCIDRs[0].String(); got != "10.10.1.128/25" {
		t.Fatalf("except cidr = %s, want 10.10.1.128/25", got)
	}
	if got := state.SecurityGroups[0].Rules[2].RemoteCIDRGroup; got != "corp" {
		t.Fatalf("remote cidr group = %s, want corp", got)
	}
	if state.SecurityGroups[0].Rules[3].ICMPType == nil || *state.SecurityGroups[0].Rules[3].ICMPType != 8 {
		t.Fatalf("icmp type = %v, want 8", state.SecurityGroups[0].Rules[3].ICMPType)
	}
	if state.SecurityGroups[0].Rules[3].ICMPCode == nil || *state.SecurityGroups[0].Rules[3].ICMPCode != 0 {
		t.Fatalf("icmp code = %v, want 0", state.SecurityGroups[0].Rules[3].ICMPCode)
	}
	if got := state.SecurityGroups[0].Rules[4].NamedPorts[0]; got != "http" {
		t.Fatalf("rule named port = %s, want http", got)
	}
	if got := state.SecurityGroups[0].Rules[5].RemoteEntities[0]; got != "world" {
		t.Fatalf("remote entity = %s, want world", got)
	}
	if got := state.SecurityGroups[0].Rules[6].RemoteEndpointSelector["app"]; got != "client" {
		t.Fatalf("remote endpoint selector app = %s, want client", got)
	}
	if got := state.SecurityGroups[0].Rules[6].RemoteEndpointExprs[0].Values[0]; got != "prod" {
		t.Fatalf("remote endpoint expression value = %s, want prod", got)
	}
	if got := state.SecurityGroups[0].Rules[7].RemoteService; got != "web" {
		t.Fatalf("remote service = %s, want web", got)
	}
	if got := state.CIDRGroups[0].CIDRs[1].String(); got != "2001:db8::/64" {
		t.Fatalf("cidr group cidr = %s, want 2001:db8::/64", got)
	}
	if got := state.CIDRGroups[0].Entries[0].ExceptCIDRs[0].String(); got != "198.51.100.128/25" {
		t.Fatalf("cidr group except cidr = %s, want 198.51.100.128/25", got)
	}
	if got := state.DNSRecords[0].IPs[0].String(); got != "203.0.113.10" {
		t.Fatalf("dns record ip = %s, want 203.0.113.10", got)
	}
	if got := state.DNSRecords[0].TTLSeconds; got != 60 {
		t.Fatalf("dns record ttl = %d, want 60", got)
	}
	if got := state.DNSRecords[0].ObservedAt.Format("2006-01-02T15:04:05Z"); got != "2026-05-30T12:00:00Z" {
		t.Fatalf("dns record observed_at = %s, want 2026-05-30T12:00:00Z", got)
	}
	if got := state.PolicyRollouts[0].Name; got != "web-canary" {
		t.Fatalf("policy rollout name = %s, want web-canary", got)
	}
	if !state.PolicyRollouts[0].PressureAware || state.PolicyRollouts[0].PressureThresholdPercent != 80 {
		t.Fatalf("policy rollout pressure settings = %+v", state.PolicyRollouts[0])
	}
	if !state.PolicyRollouts[0].SLOGated || state.PolicyRollouts[0].SLODropThresholdPercent != 5 || state.PolicyRollouts[0].SLOMinPackets != 100 || state.PolicyRollouts[0].SLOWindowCount != 2 || state.PolicyRollouts[0].SLOWindowIntervalMS != 250 {
		t.Fatalf("policy rollout SLO settings = %+v", state.PolicyRollouts[0])
	}
	if len(state.PolicyRollouts[0].Probes) != 1 || state.PolicyRollouts[0].Probes[0].Name != "web-ready" || state.PolicyRollouts[0].Probes[0].ExpectedStatus != 200 || state.PolicyRollouts[0].Probes[0].ExpectedBodyContains != "ready" {
		t.Fatalf("policy rollout probes = %+v", state.PolicyRollouts[0].Probes)
	}
	if !state.PolicyRollouts[0].ApprovalRequired || !state.PolicyRollouts[0].Approved {
		t.Fatalf("policy rollout approval settings = %+v", state.PolicyRollouts[0])
	}
	if got := state.PolicyRollouts[0].ApprovalRef; got != "chg-1234" {
		t.Fatalf("policy rollout approval_ref = %s, want chg-1234", got)
	}
	if got := state.PolicyRollouts[0].ApprovalSignature; got != "sha256=abc123" {
		t.Fatalf("policy rollout approval_signature = %s, want sha256=abc123", got)
	}
	if got := state.PolicyRollouts[0].ApprovalExpiresAt; got != "2026-07-10T12:00:00Z" {
		t.Fatalf("policy rollout approval_expires_at = %s, want RFC3339 deadline", got)
	}
	if got := state.PolicyRollouts[0].ApprovalCallbackURL; got != "http://127.0.0.1:8081/approve" {
		t.Fatalf("policy rollout approval_callback_url = %s, want callback URL", got)
	}
	if got := state.PolicyRollouts[0].ApprovalCallbackTimeoutMS; got != 750 {
		t.Fatalf("policy rollout approval_callback_timeout_ms = %d, want 750", got)
	}
	if !state.PolicyRollouts[0].AckRequired || !state.PolicyRollouts[0].Acknowledged {
		t.Fatalf("policy rollout ack settings = %+v", state.PolicyRollouts[0])
	}
	if got := state.PolicyRollouts[0].AckRef; got != "ack-1234" {
		t.Fatalf("policy rollout ack_ref = %s, want ack-1234", got)
	}
	if got := state.PolicyRollouts[0].AckExpiresAt; got != "2026-07-10T12:30:00Z" {
		t.Fatalf("policy rollout ack_expires_at = %s, want RFC3339 deadline", got)
	}
	if !state.PolicyRollouts[0].RiskAckRequired || !state.PolicyRollouts[0].RiskAcknowledged {
		t.Fatalf("policy rollout risk ack settings = %+v", state.PolicyRollouts[0])
	}
	if got := state.PolicyRollouts[0].RiskAckRef; got != "risk-1234" {
		t.Fatalf("policy rollout risk_ack_ref = %s, want risk-1234", got)
	}
	if !state.PolicyRollouts[0].FinalizeRequired || !state.PolicyRollouts[0].Finalized {
		t.Fatalf("policy rollout finalize settings = %+v", state.PolicyRollouts[0])
	}
	if got := state.PolicyRollouts[0].FinalizeRef; got != "final-1234" {
		t.Fatalf("policy rollout finalize_ref = %s, want final-1234", got)
	}
	if got := state.PolicyRollouts[0].FinalizeExpiresAt; got != "2026-07-10T13:00:00Z" {
		t.Fatalf("policy rollout finalize_expires_at = %s, want RFC3339 deadline", got)
	}
	if got := state.PolicyRollouts[0].ChangePollURL; got != "http://127.0.0.1:8081/poll" {
		t.Fatalf("policy rollout change_poll_url = %s, want poll URL", got)
	}
	if got := state.PolicyRollouts[0].ChangePollTimeoutMS; got != 800 {
		t.Fatalf("policy rollout change_poll_timeout_ms = %d, want 800", got)
	}
	if got := state.PolicyRollouts[0].ChangeStatusURL; got != "http://127.0.0.1:8081/status" {
		t.Fatalf("policy rollout change_status_url = %s, want status URL", got)
	}
	if got := state.PolicyRollouts[0].ChangeStatusTimeoutMS; got != 900 {
		t.Fatalf("policy rollout change_status_timeout_ms = %d, want 900", got)
	}
	if state.PolicyRollouts[0].PauseAfterBatches != 1 {
		t.Fatalf("policy rollout pause_after_batches = %d, want 1", state.PolicyRollouts[0].PauseAfterBatches)
	}
	if state.PolicyRollouts[0].PromotionPercent != 50 {
		t.Fatalf("policy rollout promotion_percent = %d, want 50", state.PolicyRollouts[0].PromotionPercent)
	}
}

func TestLoadDesiredStateJSONRejectsUnknownFields(t *testing.T) {
	_, err := LoadDesiredStateJSON(strings.NewReader(`{"vpcs": [], "surprise": true}`))
	if err == nil {
		t.Fatal("expected unknown field to fail")
	}
}

func TestDesiredStateRevisionAndSummary(t *testing.T) {
	state := DesiredState{
		VPCs:             []model.VPC{{Name: "prod"}},
		ProviderNetworks: []model.ProviderNetwork{{Name: "physnet-a"}},
		IdentityGroups:   []model.IdentityGroup{{Name: "frontend", VPC: "prod"}},
		Subnets: []model.Subnet{{
			Name:    "apps",
			VPC:     "prod",
			CIDR:    netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("10.10.0.1"),
		}},
		Endpoints:      []model.Endpoint{{ID: "pod-a", VPC: "prod", Subnet: "apps"}},
		RouteTables:    []model.RouteTable{{Name: "main", VPC: "prod"}},
		PolicyRoutes:   []model.PolicyRoute{{Name: "via-fw", VPC: "prod", Priority: 100}},
		Gateways:       []model.Gateway{{Name: "gw-a", VPC: "prod"}},
		NATRules:       []model.NATRule{{Name: "snat", VPC: "prod"}},
		LoadBalancers:  []model.LoadBalancer{{Name: "api", VPC: "prod"}},
		SecurityGroups: []model.SecurityGroup{{Name: "web", VPC: "prod"}},
		CIDRGroups:     []model.CIDRGroup{{Name: "corp", VPC: "prod"}},
		DNSRecords:     []model.DNSRecord{{Name: "api.example.com"}},
		PolicyRollouts: []PolicyRollout{{Name: "canary", BatchSize: 1}},
	}
	raw, err := MarshalDesiredStateJSON(state)
	if err != nil {
		t.Fatal(err)
	}
	revision := DesiredStateRevision(raw)
	if !strings.HasPrefix(revision, "sha256:") {
		t.Fatalf("revision = %q, want sha256 prefix", revision)
	}
	if err := ValidateDesiredStateRevision(raw, revision); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDesiredStateRevision(raw, "sha256:bad"); err == nil {
		t.Fatal("expected revision mismatch to fail")
	}
	summary := SummarizeDesiredState(state)
	if summary.VPCs != 1 || summary.ProviderNetworks != 1 || summary.IdentityGroups != 1 ||
		summary.Subnets != 1 || summary.Endpoints != 1 || summary.RouteTables != 1 ||
		summary.PolicyRoutes != 1 || summary.Gateways != 1 || summary.NATRules != 1 ||
		summary.LoadBalancers != 1 || summary.SecurityGroups != 1 || summary.CIDRGroups != 1 ||
		summary.DNSRecords != 1 || summary.PolicyRollouts != 1 {
		t.Fatalf("summary = %+v, want every count populated", summary)
	}
}

func TestLoadDNSObservationsJSONDecodesArrayAndDocument(t *testing.T) {
	records, err := LoadDNSObservationsJSON(strings.NewReader(`[{"name": "api.example.com", "ips": ["203.0.113.10"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Name != "api.example.com" {
		t.Fatalf("array records = %+v", records)
	}

	records, err = LoadDNSObservationsJSON(strings.NewReader(`{"dns_records": [{"name": "db.example.com", "ips": ["203.0.113.20"], "ttl_seconds": 60, "observed_at": "2026-05-30T12:00:00Z"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Name != "db.example.com" || records[0].TTLSeconds != 60 {
		t.Fatalf("document records = %+v", records)
	}
}

func TestLoadDNSObservationsJSONRejectsInvalidRecord(t *testing.T) {
	_, err := LoadDNSObservationsJSON(strings.NewReader(`[{"name": "api.example.com"}]`))
	if err == nil {
		t.Fatal("expected invalid DNS observation to fail")
	}
}

func TestMergeDNSRecordsAppendsObservedRecordsDeterministically(t *testing.T) {
	base, err := LoadDNSObservationsJSON(strings.NewReader(`[{"name": "static.example.com", "ips": ["203.0.113.10"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := LoadDNSObservationsJSON(strings.NewReader(`[{"name": "api.example.com", "ips": ["203.0.113.20"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeDNSRecords(base, observed)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 2 {
		t.Fatalf("merged records = %d, want 2", len(merged))
	}
	if merged[0].Name != "api.example.com" || merged[1].Name != "static.example.com" {
		t.Fatalf("merged order = %+v", merged)
	}
}

func TestMergeDNSRecordsUpsertsRepeatedObservations(t *testing.T) {
	base, err := LoadDNSObservationsJSON(strings.NewReader(`{"dns_records": [
		{"name": "api.example.com", "ips": ["203.0.113.20", "203.0.113.21"], "ttl_seconds": 30, "observed_at": "2026-05-30T11:59:00Z"},
		{"name": "static.example.com", "ips": ["203.0.113.30"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := LoadDNSObservationsJSON(strings.NewReader(`{"dns_records": [
		{"name": "API.EXAMPLE.COM.", "ips": ["203.0.113.21", "203.0.113.20"], "ttl_seconds": 60, "observed_at": "2026-05-30T12:00:00Z"},
		{"name": "static.example.com", "ips": ["203.0.113.30"], "ttl_seconds": 60, "observed_at": "2026-05-30T12:00:00Z"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeDNSRecords(base, observed)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 2 {
		t.Fatalf("merged records = %d, want 2: %+v", len(merged), merged)
	}
	if merged[0].Name != "API.EXAMPLE.COM." || merged[0].TTLSeconds != 60 || !merged[0].ObservedAt.Equal(time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("observed record was not updated: %+v", merged[0])
	}
	if merged[1].Name != "static.example.com" || merged[1].TTLSeconds != 0 {
		t.Fatalf("static record should remain non-expiring: %+v", merged[1])
	}
}

func TestPruneExpiredDNSRecordsDropsOnlyExpiredTTLRecords(t *testing.T) {
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	records, err := LoadDNSObservationsJSON(strings.NewReader(`{"dns_records": [
		{"name": "expired.example.com", "ips": ["203.0.113.10"], "ttl_seconds": 30, "observed_at": "2026-05-30T11:59:30Z"},
		{"name": "active.example.com", "ips": ["203.0.113.20"], "ttl_seconds": 31, "observed_at": "2026-05-30T11:59:30Z"},
		{"name": "static.example.com", "ips": ["203.0.113.30"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	pruned, err := PruneExpiredDNSRecords(records, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 2 {
		t.Fatalf("records = %d, want 2: %+v", len(pruned), pruned)
	}
	if pruned[0].Name != "active.example.com" || pruned[1].Name != "static.example.com" {
		t.Fatalf("records = %+v", pruned)
	}
}
