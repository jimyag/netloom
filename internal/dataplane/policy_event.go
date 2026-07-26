package dataplane

import (
	"errors"
	"strings"
)

const (
	PolicyUpdateFailureCanonicalization = "canonicalization_failed"
	PolicyUpdateFailureCapacityExceeded = "capacity_exceeded"
	PolicyUpdateFailureApplyFailed      = "apply_failed"
)

func PolicyUpdateFailureReason(err error) string {
	if err == nil {
		return ""
	}
	var capacityErr *PolicyMapCapacityError
	if errors.As(err, &capacityErr) {
		return PolicyUpdateFailureCapacityExceeded
	}
	message := err.Error()
	if strings.Contains(message, "canonicalize policy map entries") ||
		strings.Contains(message, "conflicting policy map entries") {
		return PolicyUpdateFailureCanonicalization
	}
	return PolicyUpdateFailureApplyFailed
}
