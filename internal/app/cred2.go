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
	var out CRED2Outcome
	host, err := os.Hostname()
	if err != nil || host == "" {
		return out, fmt.Errorf("CRED-2 cannot identify the local SCCM client: %w", err)
	}
	if target != "" && !strings.EqualFold(target, "localhost") && !strings.EqualFold(target, host) {
		return out, fmt.Errorf("CRED-2 is local-only: run on the SCCM client itself; target %q is not this host", target)
	}
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return out, err
	}
	defer store.Close()
	run, err := store.CreateRun(ctx, "assess CRED-2", string(a.Config.Profile), version.Current().Version, []string{"assess", "CRED-2"})
	if err != nil {
		return out, err
	}
	credential, err := cred2.RecoverLocal(ctx)
	if err != nil {
		_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunFailed, map[string]any{"stage": "local_naa_recovery", "error": err.Error()})
		return out, err
	}
	now := time.Now().UTC()
	fp := sha256.Sum256([]byte(host + "|" + now.Format(time.RFC3339Nano)))
	ev := &models.Evidence{Type: "cred2_local_naa_recovery", Title: "CRED-2 local NAA recovery", Summary: "Current CCM_NetworkAccessAccount recovered locally", Data: map[string]any{"host": host, "sccm_client_detected": true, "namespace": cred2.NAANamespace, "class": cred2.NAAClass, "username_protected": true, "password_protected": true, "recovery_status": "completed", "credential_type": "network_access_account", "plaintext_persisted": false, "captured_at": now.Format(time.RFC3339Nano)}, SourceModule: "cred2", CollectedAt: now, Sensitivity: models.SensitivitySensitive, RunID: run.ID, Fingerprint: fmt.Sprintf("%x", fp[:])}
	if _, err := store.UpsertEvidence(ctx, ev); err != nil {
		_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunFailed, map[string]any{"stage": "persist_metadata", "error": err.Error()})
		return out, err
	}
	_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunCompleted, map[string]any{"cred2": ev.ID, "plaintext_persisted": false})
	return CRED2Outcome{Run: *run, Host: host, Credential: credential}, nil
}
