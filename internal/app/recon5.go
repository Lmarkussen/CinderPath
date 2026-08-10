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
	"github.com/Lmarkussen/CinderPath/internal/recon5"
	"github.com/Lmarkussen/CinderPath/internal/version"
)

type RECON5Outcome struct {
	Run    models.Run
	Result recon5.Result
}

func (a *Application) recon5Client(ctx context.Context) (*recon5.Client, error) {
	authority, ip := os.Getenv("CINDERPATH_CONFIGMGR_AUTHORITY"), os.Getenv("CINDERPATH_CONFIGMGR_TRANSPORT_IP")
	if authority == "" || ip == "" {
		return nil, errors.New("RECON-5 requires explicit ConfigMgr authority and transport IP configuration")
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
		return nil, errors.New("RECON-5 requires explicit Kerberos realm and KDC configuration")
	}
	if a.Config.Identity.Username == "" {
		return nil, errors.New("RECON-5 requires an explicit ConfigMgr-authorized identity")
	}
	passwordRef := ""
	if a.Config.Identity.PasswordEnv != "" {
		passwordRef = "env:" + a.Config.Identity.PasswordEnv
	} else if a.Config.Identity.PasswordFile != "" {
		passwordRef = "file:" + a.Config.Identity.PasswordFile
	}
	if passwordRef == "" && a.Config.Identity.KerberosCache == "" {
		return nil, errors.New("RECON-5 requires an explicit Kerberos password reference or ccache")
	}
	insecure := os.Getenv("CINDERPATH_CONFIGMGR_INSECURE_TLS") == "1"
	client, err := recon5.New(ctx, recon5.Options{Authority: authority, TransportIP: ip, Realm: realm, KDC: kdc, Username: a.Config.Identity.Username, PasswordRef: passwordRef, CCachePath: a.Config.Identity.KerberosCache, TLSConfig: &tls.Config{InsecureSkipVerify: insecure}, Timeout: a.Config.Timeout})
	if err != nil {
		return nil, fmt.Errorf("RECON-5 ConfigMgr authentication unavailable: %w", err)
	}
	return client, nil
}

func (a *Application) AssessRECON5(ctx context.Context, _, lookupUser string) (RECON5Outcome, error) {
	client, err := a.recon5Client(ctx)
	if err != nil {
		return RECON5Outcome{}, err
	}
	result, err := client.LocateUsersFor(ctx, lookupUser)
	if err != nil {
		return RECON5Outcome{}, err
	}
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return RECON5Outcome{}, err
	}
	defer store.Close()
	run, err := store.CreateRun(ctx, "assess RECON-5", string(a.Config.Profile), version.Current().Version, []string{"assess", "RECON-5"})
	if err != nil {
		return RECON5Outcome{}, err
	}
	now := time.Now().UTC()
	ev := &models.Evidence{Type: "recon5_sms_provider_user_device", Title: "RECON-5 SMS Provider user/device inventory", Summary: "Current bounded SMS Provider user/device relationship result", Data: map[string]any{"authority": os.Getenv("CINDERPATH_CONFIGMGR_AUTHORITY"), "query": result.Query, "records": result.Records, "record_count": len(result.Records), "truncated": result.Truncated, "captured_at": now.Format(time.RFC3339Nano)}, SourceModule: "recon5.sms_provider", CollectedAt: now, Sensitivity: models.SensitivityInternal, RunID: run.ID}
	if _, err = store.UpsertEvidence(ctx, ev); err != nil {
		_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunFailed, map[string]any{"error": "persist evidence"})
		return RECON5Outcome{}, err
	}
	_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunCompleted, map[string]any{"technique": "RECON-5", "evidence": ev.ID, "record_count": len(result.Records), "truncated": result.Truncated})
	return RECON5Outcome{Run: *run, Result: result}, nil
}
