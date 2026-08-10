package app

import (
	"context"
	"testing"
)

func TestParentRunContextPreservesFamilyCommand(t *testing.T) {
	ctx := WithParentRun(context.Background(), "assess RECON-ALL")
	if got := runCommand(ctx, "assess RECON-3"); got != "assess RECON-ALL" {
		t.Fatalf("run command=%q", got)
	}
	if got := runCommand(context.Background(), "assess RECON-3"); got != "assess RECON-3" {
		t.Fatalf("fallback command=%q", got)
	}
}
