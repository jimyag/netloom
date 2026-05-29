package control

import (
	"strings"
	"testing"
)

func TestLoadDesiredStateJSONDecodesSnakeCaseState(t *testing.T) {
	state, err := LoadDesiredStateJSON(strings.NewReader(`{
		"vpcs": [{"name": "prod"}],
		"subnets": [{"name": "apps", "vpc": "prod", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1"}],
		"endpoints": [{"id": "pod-a", "vpc": "prod", "subnet": "apps", "ip": "10.10.0.10", "node": "node-a", "security_groups": ["web"]}],
		"route_tables": [{"name": "main", "vpc": "prod", "routes": [{"destination": "0.0.0.0/0", "next_hop": "10.10.0.254"}]}],
		"policy_routes": [{"name": "fw", "vpc": "prod", "priority": 100, "match": {"source": "10.10.0.0/24", "destination": "172.16.0.0/16", "protocol": "tcp", "dst_ports": [{"from": 443, "to": 443}]}, "action": {"type": "reroute", "next_hop": "10.10.0.253"}}],
		"gateways": [{"name": "gw-a", "vpc": "prod", "node": "node-a", "external_if": "eth0", "lan_ip": "10.10.0.254"}],
		"nat_rules": [{"name": "egress", "vpc": "prod", "type": "snat", "match_cidr": "10.10.0.0/24", "external_ip": "198.51.100.10"}],
		"security_groups": [{"name": "web", "vpc": "prod", "rules": [{"id": "allow-web", "priority": 10, "direction": "ingress", "protocol": "tcp", "remote_cidr": "10.10.1.0/24", "ports": [{"from": 443, "to": 443}], "action": "allow", "stateful": true}]}]
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
	if got := state.PolicyRoutes[0].Action.NextHop.String(); got != "10.10.0.253" {
		t.Fatalf("policy route next hop = %s", got)
	}
}

func TestLoadDesiredStateJSONRejectsUnknownFields(t *testing.T) {
	_, err := LoadDesiredStateJSON(strings.NewReader(`{"vpcs": [], "surprise": true}`))
	if err == nil {
		t.Fatal("expected unknown field to fail")
	}
}
