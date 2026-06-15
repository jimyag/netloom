package control

import (
	"strings"
	"testing"
	"time"
)

func TestLoadDesiredStateJSONDecodesSnakeCaseState(t *testing.T) {
	state, err := LoadDesiredStateJSON(strings.NewReader(`{
		"vpcs": [{"name": "prod"}],
		"provider_networks": [{"name": "physnet-a", "nodes": [{"node": "node-a", "interface": "bond0.100"}]}],
		"subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1", "exclude_cidrs": ["10.10.0.128/25"]}],
		"endpoints": [{"id": "pod-a", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.10", "node": "node-a", "security_groups": ["web"], "named_ports": [{"name": "http", "protocol": "tcp", "port": 8080}], "labels": {"app": "web", "env": "prod"}}],
		"route_tables": [{"name": "main", "vpc": "prod", "routes": [{"destination": "0.0.0.0/0", "next_hops": ["10.10.0.253", "10.10.0.254"]}]}],
		"policy_routes": [{"name": "fw", "vpc": "prod", "priority": 100, "match": {"source": "10.10.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "src_ports": [{"from": 32000, "to": 32010}], "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hops": ["10.10.0.253"]}}],
		"gateways": [{"name": "gw-a", "vpc": "prod", "node": "node-a", "external_if": "eth0", "lan_ip": "10.10.0.254"}],
		"nat_rules": [{"name": "egress", "vpc": "prod", "type": "snat", "match_cidr": "10.10.0.0/24", "external_ip": "198.51.100.10"}],
		"load_balancers": [{"name": "web", "vpc": "prod", "vip": "10.96.0.10", "ports": [{"name": "http", "port": 80, "protocol": "tcp", "backends": [{"ip": "10.10.0.10", "port": 8080, "healthy": true}]}, {"name": "metrics", "port": 9090, "protocol": "tcp", "backends": [{"ip": "10.10.0.10", "port": 9091}]}], "subnets": ["apps"], "health_check": {"enabled": true, "interval": 10, "timeout": 30, "success_count": 2, "failure_count": 4}}],
		"security_groups": [{"name": "web", "vpc": "prod", "tier": 1, "rules": [{"id": "allow-web", "priority": 10, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.10.1.0/24", "except_cidrs": ["10.10.1.128/25"], "ports": [{"from": 443, "to": 443}], "action": "allow", "stateful": true}, {"id": "allow-api", "priority": 20, "direction": "egress", "protocol": "tcp", "remote_fqdns": [{"match_name": "api.example.com"}, {"match_pattern": "*.svc.example.com"}], "ports": [{"from": 443, "to": 443}], "action": "allow"}, {"id": "allow-corp", "priority": 30, "direction": "egress", "protocol": "tcp", "remote_cidr_group": "corp", "ports": [{"from": 8443, "to": 8443}], "action": "allow"}, {"id": "allow-icmp-echo", "priority": 40, "direction": "egress", "protocol": "icmp", "remote_cidr": "198.51.100.0/24", "icmp_type": 8, "icmp_code": 0, "action": "allow"}, {"id": "allow-named-http", "priority": 50, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.10.1.0/24", "named_ports": ["http"], "action": "allow"}, {"id": "allow-world", "priority": 60, "direction": "egress", "protocol": "tcp", "remote_entities": ["world"], "ports": [{"from": 443, "to": 443}], "action": "allow"}, {"id": "allow-selector", "priority": 70, "direction": "ingress", "protocol": "tcp", "remote_endpoint_selector": {"app": "client"}, "remote_endpoint_expressions": [{"key": "env", "operator": "In", "values": ["prod"]}], "ports": [{"from": 9443, "to": 9443}], "action": "allow"}, {"id": "allow-service", "priority": 80, "direction": "egress", "protocol": "any", "remote_service": "web", "action": "allow"}]}],
		"cidr_groups": [{"name": "corp", "vpc": "prod", "cidrs": ["10.20.0.0/16", "2001:db8::/64"], "entries": [{"cidr": "198.51.100.0/24", "except_cidrs": ["198.51.100.128/25"]}]}],
		"dns_records": [{"name": "api.example.com", "ips": ["203.0.113.10"], "ttl_seconds": 60, "observed_at": "2026-05-30T12:00:00Z"}]
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
}

func TestLoadDesiredStateJSONRejectsUnknownFields(t *testing.T) {
	_, err := LoadDesiredStateJSON(strings.NewReader(`{"vpcs": [], "surprise": true}`))
	if err == nil {
		t.Fatal("expected unknown field to fail")
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
