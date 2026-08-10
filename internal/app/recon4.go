package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/recon4"
	"github.com/Lmarkussen/CinderPath/internal/version"
)

type RECON4Outcome struct {
	Run    models.Run
	Result recon4.Result
}

// AssessRECON4 executes the bounded, fixed OperatingSystem CMPivot query. The
// AdminService authority/transport are explicit configuration, never inferred
// from ambient DNS or credentials.
func (a *Application) AssessRECON4(ctx context.Context, target string) (RECON4Outcome, error) {
	authority, ip := os.Getenv("CINDERPATH_CONFIGMGR_AUTHORITY"), os.Getenv("CINDERPATH_CONFIGMGR_TRANSPORT_IP")
	if authority == "" || ip == "" {
		return RECON4Outcome{}, errors.New("RECON-4 requires explicit ConfigMgr authority and transport IP configuration")
	}
	realm := a.Config.WorkflowScope.Domain
	if realm == "" {
		realm = os.Getenv("CINDERPATH_CONFIGMGR_REALM")
	}
	kdc := a.Config.WorkflowScope.DomainController
	if kdc == "" {
		kdc = os.Getenv("CINDERPATH_CONFIGMGR_KDC")
	}
	if realm == "" || kdc == "" {
		return RECON4Outcome{}, errors.New("RECON-4 requires explicit Kerberos realm and KDC configuration")
	}
	if a.Config.Identity.Username == "" {
		return RECON4Outcome{}, errors.New("RECON-4 requires an explicit ConfigMgr Kerberos identity")
	}
	passwordRef := ""
	if a.Config.Identity.PasswordEnv != "" {
		passwordRef = "env:" + a.Config.Identity.PasswordEnv
	} else if a.Config.Identity.PasswordFile != "" {
		passwordRef = "file:" + a.Config.Identity.PasswordFile
	}
	if passwordRef == "" && a.Config.Identity.KerberosCache == "" {
		return RECON4Outcome{}, errors.New("RECON-4 requires an explicit Kerberos password reference or ccache")
	}
	insecure := os.Getenv("CINDERPATH_CONFIGMGR_INSECURE_TLS") == "1"
	client, err := recon4.New(ctx, recon4.Options{Authority: authority, TransportIP: ip, Realm: realm, KDC: kdc, Username: a.Config.Identity.Username, PasswordRef: passwordRef, CCachePath: a.Config.Identity.KerberosCache, TLSConfig: &tls.Config{InsecureSkipVerify: insecure}})
	if err != nil {
		return RECON4Outcome{}, fmt.Errorf("RECON-4 ConfigMgr authentication unavailable: %w", err)
	}
	result, err := client.Assess(ctx, target)
	if err != nil {
		return RECON4Outcome{}, err
	}
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return RECON4Outcome{}, err
	}
	defer store.Close()
	run, err := store.CreateRun(ctx, "assess RECON-4", string(a.Config.Profile), version.Current().Version, []string{"assess", "RECON-4"})
	if err != nil {
		return RECON4Outcome{}, err
	}
	now := time.Now().UTC()
	ev := &models.Evidence{Type: "recon4_cmpivot_device", Title: "RECON-4 CMPivot client device", Summary: "Current bounded OperatingSystem CMPivot result", Data: map[string]any{"target": result.Device.Name, "machine_id": result.Device.MachineID, "site_code": result.Device.SiteCode, "client_version": result.Device.ClientVersion, "is_client": result.Device.IsClient, "online": result.Device.Online, "operation_id": result.OperationID, "query": recon4.FixedQuery, "status": result.Status, "rows": result.Rows, "captured_at": now.Format(time.RFC3339Nano)}, SourceModule: "recon4.cmpivot", CollectedAt: now, Sensitivity: models.SensitivityInternal, RunID: run.ID}
	if _, err = store.UpsertEvidence(ctx, ev); err != nil {
		_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunFailed, map[string]any{"error": "persist evidence"})
		return RECON4Outcome{}, err
	}
	_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunCompleted, map[string]any{"technique": "RECON-4", "evidence": ev.ID, "query": recon4.FixedQuery})
	return RECON4Outcome{Run: *run, Result: result}, nil
}
