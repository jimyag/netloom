//go:build !linux || !cgo || !netloom_nfqueue

package main

import (
	"strings"
	"testing"
)

func TestNFQueueCaptureRequiresBuildTagByDefault(t *testing.T) {
	_, err := newNFQueueDNSCapture(0)
	if err == nil || !strings.Contains(err.Error(), "netloom_nfqueue") {
		t.Fatalf("err = %v, want build tag guidance", err)
	}
}
