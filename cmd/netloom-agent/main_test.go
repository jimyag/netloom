package main

import (
	"testing"
	"time"
)

func TestReconcileIntervalParsesMilliseconds(t *testing.T) {
	t.Setenv("NETLOOM_RECONCILE_INTERVAL_MS", "250")
	interval, err := reconcileInterval()
	if err != nil {
		t.Fatal(err)
	}
	if interval != 250*time.Millisecond {
		t.Fatalf("interval = %s, want 250ms", interval)
	}
}

func TestReconcileIntervalRejectsInvalidValue(t *testing.T) {
	t.Setenv("NETLOOM_RECONCILE_INTERVAL_MS", "soon")
	_, err := reconcileInterval()
	if err == nil {
		t.Fatal("expected invalid interval to fail")
	}
}

func TestLinuxDatapathOptionsParsesBackend(t *testing.T) {
	t.Setenv("NETLOOM_LINUX_DATAPATH", "1")
	t.Setenv("NETLOOM_LINUX_DATAPATH_MODE", "netns")
	t.Setenv("NETLOOM_LINUX_DATAPATH_BACKEND", "netlink")
	t.Setenv("NETLOOM_POLICY_ROUTE_TABLE_BASE", "22000")

	options := linuxDatapathOptions()
	if options == nil {
		t.Fatal("expected linux datapath options")
	}
	if options.Mode != "netns" {
		t.Fatalf("mode = %s, want netns", options.Mode)
	}
	if options.Backend != "netlink" {
		t.Fatalf("backend = %s, want netlink", options.Backend)
	}
	if options.PolicyTableBase != 22000 {
		t.Fatalf("policy table base = %d, want 22000", options.PolicyTableBase)
	}
}
