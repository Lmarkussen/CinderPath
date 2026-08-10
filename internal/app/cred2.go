package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/cred2"
	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/version"
)

// CRED2Outcome keeps the recovered credential transient. The database record
// written by AssessCRED2 contains metadata only.
type CRED2Outcome struct {
	Run        models.Run
	Host       string
	Credential cred2.Credential
}

// AssessCRED2 executes the local-client adapter. target is informational and
// must identify the current host when supplied; no remote execution occurs.
func (a *Application) AssessCRED2(ctx context.Context, target string) (CRED2Outcome, error) {
	out, err := a.assessLocalNAA(ctx, target, "CRED-2")
	return CRED2Outcome(out), err
}

// CRED3Outcome keeps the recovered credential transient. The database record
// written by AssessCRED3 contains metadata only.
type CRED3Outcome struct {
	Run        models.Run
	Host       string
	Credential cred2.Credential
}

// AssessCRED3 executes the independent currently-deployed-NAA technique. It
// shares the local recovery primitive with CRED-2 but writes technique-specific
// evidence and run attribution.
func (a *Application) AssessCRED3(ctx context.Context, target string) (CRED3Outcome, error) {
	out, err := a.assessLocalNAA(ctx, target, "CRED-3")
	return CRED3Outcome(out), err
}

func (a *Application) assessLocalNAA(ctx context.Context, target, technique string) (CRED2Outcome, error) {
	var out CRED2Outcome
	host, err := os.Hostname()
	if err != nil || host == "" {
		return out, fmt.Errorf("%s cannot identify the local SCCM client: %w", technique, err)
	}
	if target != "" && !strings.EqualFold(target, "localhost") && !strings.EqualFold(target, host) {
		return out, fmt.Errorf("%s is local-only: run on the SCCM client itself; target %q is not this host", technique, target)
	}
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return out, err
	}
	defer store.Close()
	run, err := store.CreateRun(ctx, "assess "+technique, string(a.Config.Profile), version.Current().Version, []string{"assess", technique})
	if err != nil {
		return out, err
	}
	credential, err := cred2.RecoverLocalForTechnique(ctx, technique)
	if err != nil {
		_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunFailed, map[string]any{"stage": "local_naa_recovery", "error": err.Error()})
		return out, err
	}
	now := time.Now().UTC()
	fp := sha256.Sum256([]byte(host + "|" + now.Format(time.RFC3339Nano)))
	ev := &models.Evidence{Type: strings.ToLower(strings.ReplaceAll(technique, "-", "")) + "_local_naa_recovery", Title: technique + " local NAA recovery", Summary: "Current CCM_NetworkAccessAccount recovered locally", Data: map[string]any{"host": host, "sccm_client_detected": true, "namespace": cred2.NAANamespace, "class": cred2.NAAClass, "username_protected": true, "password_protected": true, "recovery_status": "completed", "credential_type": "network_access_account", "plaintext_persisted": false, "captured_at": now.Format(time.RFC3339Nano)}, SourceModule: strings.ToLower(technique), CollectedAt: now, Sensitivity: models.SensitivitySensitive, RunID: run.ID, Fingerprint: fmt.Sprintf("%x", fp[:])}
	if _, err := store.UpsertEvidence(ctx, ev); err != nil {
		_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunFailed, map[string]any{"stage": "persist_metadata", "error": err.Error()})
		return out, err
	}
	_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunCompleted, map[string]any{"evidence": ev.ID, "technique": technique, "plaintext_persisted": false})
	return CRED2Outcome{Run: *run, Host: host, Credential: credential}, nil
}
