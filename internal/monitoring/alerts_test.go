package monitoring

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type prometheusRuleFile struct {
	Groups []prometheusRuleGroup `yaml:"groups"`
}

type prometheusRuleGroup struct {
	Name  string            `yaml:"name"`
	Rules []prometheusAlert `yaml:"rules"`
}

type prometheusAlert struct {
	Alert       string            `yaml:"alert"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

func TestPrometheusAlertsCoverCriticalNetloomSignals(t *testing.T) {
	rules := loadPrometheusRules(t)
	alerts := map[string]prometheusAlert{}
	expressions := strings.Builder{}
	for _, group := range rules.Groups {
		if group.Name == "" {
			t.Fatal("alert group missing name")
		}
		if len(group.Rules) == 0 {
			t.Fatalf("alert group %q has no rules", group.Name)
		}
		for _, rule := range group.Rules {
			if rule.Alert == "" {
				t.Fatalf("alert group %q has unnamed rule", group.Name)
			}
			if _, ok := alerts[rule.Alert]; ok {
				t.Fatalf("duplicate alert name %q", rule.Alert)
			}
			if strings.TrimSpace(rule.Expr) == "" {
				t.Fatalf("alert %q has empty expr", rule.Alert)
			}
			if strings.TrimSpace(rule.For) == "" {
				t.Fatalf("alert %q has empty for duration", rule.Alert)
			}
			if rule.Labels["severity"] == "" {
				t.Fatalf("alert %q missing severity label", rule.Alert)
			}
			if rule.Labels["component"] == "" {
				t.Fatalf("alert %q missing component label", rule.Alert)
			}
			if rule.Annotations["summary"] == "" {
				t.Fatalf("alert %q missing summary annotation", rule.Alert)
			}
			if rule.Annotations["runbook_url"] == "" {
				t.Fatalf("alert %q missing runbook_url annotation", rule.Alert)
			}
			if _, err := os.Stat(filepath.Join("..", "..", rule.Annotations["runbook_url"])); err != nil {
				t.Fatalf("alert %q references missing runbook_url %q: %v", rule.Alert, rule.Annotations["runbook_url"], err)
			}
			alerts[rule.Alert] = rule
			expressions.WriteString(rule.Expr)
			expressions.WriteByte('\n')
		}
	}

	for _, name := range []string{
		"NetloomControllerReconcileFailing",
		"NetloomOVNHealthFailing",
		"NetloomOVNClusterQuorumDegraded",
		"NetloomOVNLeaderProbeFailing",
		"NetloomOVNEndpointConnectErrors",
		"NetloomOVNEndpointCooldownActive",
		"NetloomOVNManagedRowsMissing",
		"NetloomOVNManagedRowsUnexpected",
		"NetloomOVNManagedRowsDrifted",
		"NetloomOVNStaleAdvisoryActive",
		"NetloomOVNMaintenanceFailing",
		"NetloomAgentRuntimePreflightFailing",
		"NetloomTCXAttachFailing",
		"NetloomPolicyMapPressureCritical",
		"NetloomPolicyMapCapacityExceeded",
		"NetloomPolicyCanonicalizationFailed",
		"NetloomPolicyApplyFailed",
		"NetloomPolicyActionHistoryFailures",
		"NetloomPolicyEndpointActionFailed",
		"NetloomPolicyEndpointActionFrozen",
		"NetloomPolicyRolloutFailed",
		"NetloomPolicyRolloutRollbackFailed",
		"NetloomPolicyRolloutPaused",
		"NetloomPolicyRolloutStateLoadFailing",
		"NetloomPolicyRolloutStateFailedEndpoints",
		"NetloomPolicyRolloutStatePaused",
		"NetloomProviderNetworkDegraded",
		"NetloomProviderNetworkIssueReported",
	} {
		if _, ok := alerts[name]; !ok {
			t.Fatalf("missing alert %q", name)
		}
	}

	joined := expressions.String()
	for _, metric := range []string{
		"netloom_controller_reconcile_success",
		"netloom_controller_ovn_health_consecutive_failures",
		"netloom_controller_ovn_cluster_quorum_status",
		"netloom_controller_ovn_cluster_leader_probe_status",
		"netloom_controller_ovn_cluster_connect_error_endpoints",
		"netloom_controller_ovn_cluster_cooldown_endpoints",
		"netloom_controller_ovn_live_missing_managed_rows",
		"netloom_controller_ovn_live_unexpected_managed_rows",
		"netloom_controller_ovn_live_drifted_managed_rows",
		"netloom_controller_ovn_stale_advisory_active",
		"netloom_controller_ovn_maintenance_failed",
		"netloom_agent_runtime_failed_checks",
		"netloom_agent_tcx_failed",
		"netloom_agent_policy_endpoint_pressure_severity",
		"netloom_agent_policy_endpoint_last_event_failure_reason",
		"netloom_agent_policy_action_history_failure_events",
		"netloom_agent_policy_action_history_endpoint_last_success",
		"netloom_agent_policy_action_history_endpoint_last_reason",
		"netloom_agent_policy_rollout_failed_endpoints",
		"netloom_agent_policy_rollout_rollback_failed_endpoints",
		"netloom_agent_policy_rollout_paused",
		"netloom_agent_policy_rollout_state_load_error",
		"netloom_agent_policy_rollout_state_failed_endpoints",
		"netloom_agent_policy_rollout_state_paused_rollouts",
		"netloom_agent_provider_network_ready",
		"netloom_agent_provider_network_issue_reason",
	} {
		if !strings.Contains(joined, metric) {
			t.Fatalf("alert expressions do not cover metric %q", metric)
		}
	}
	for _, reason := range []string{"capacity_exceeded", "canonicalization_failed", "apply_failed", "frozen"} {
		if !strings.Contains(joined, `reason="`+reason+`"`) {
			t.Fatalf("alert expressions do not cover failure reason %q", reason)
		}
	}
	if !strings.Contains(joined, `status="error"`) {
		t.Fatal("alert expressions do not cover OVN leader probe error status")
	}
}

func loadPrometheusRules(t *testing.T) prometheusRuleFile {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "operations", "prometheus-alerts.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rules prometheusRuleFile
	if err := yaml.Unmarshal(data, &rules); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(rules.Groups) == 0 {
		t.Fatalf("%s has no alert groups", path)
	}
	return rules
}
