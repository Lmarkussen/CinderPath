//go:build !windows

package cred2

import (
	"context"
	"strings"
	"testing"
)

func TestRecoverLocalForTechniqueReportsTechniqueSpecificPrerequisite(t *testing.T) {
	_, err := RecoverLocalForTechnique(context.Background(), "CRED-3")
	if err == nil || !strings.Contains(err.Error(), "CRED-3") || !strings.Contains(err.Error(), "Windows") {
		t.Fatalf("unexpected unsupported-platform error: %v", err)
	}
}
