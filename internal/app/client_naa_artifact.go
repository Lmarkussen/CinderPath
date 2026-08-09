package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/policy"
)

type ClientNAAArtifactResolution struct {
	Artifact   policy.ClientNAAArtifact
	ObservedAt time.Time
}

// ImportClientNAAArtifact persists reviewed metadata only. It never contacts a
// client, requests policy, or stores protected strings.
func (a *Application) ImportClientNAAArtifact(ctx context.Context, artifact policy.ClientNAAArtifact) error {
	raw, err := json.Marshal(artifact)
	if err != nil {
		return err
	}
	artifact, err = policy.ParseClientNAAArtifact(raw)
	if err != nil {
		return err
	}
	s := sha256.Sum256([]byte(artifact.Domain + "|" + artifact.SourceHost + "|" + artifact.Namespace + "|" + artifact.Class))
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()
	data := map[string]any{"source_type": "client_artifact_import", "artifact": artifact, "credential_type": "network_access_account", "recovery_state": "not_recovered", "plaintext_recovered": false, "live_policy_requests": 0}
	return store.UpsertPolicyRecord(ctx, "policy_candidates", database.PolicyRecord{ID: "client_naa_" + hex.EncodeToString(s[:10]), Fingerprint: artifact.Fingerprint(), ObservedAt: artifact.ObservedAt(), Data: data})
}

// StoredClientNAAArtifact returns one fresh, verified artifact for a domain.
func (a *Application) StoredClientNAAArtifact(ctx context.Context, domain string, maxAge time.Duration) (ClientNAAArtifactResolution, error) {
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return ClientNAAArtifactResolution{}, err
	}
	defer store.Close()
	records, err := store.ListPolicyRecords(ctx, "policy_candidates")
	if err != nil {
		return ClientNAAArtifactResolution{}, err
	}
	var matches []ClientNAAArtifactResolution
	for _, r := range records {
		if r.Data["source_type"] != "client_artifact_import" {
			continue
		}
		raw, ok := r.Data["artifact"]
		if !ok {
			continue
		}
		b, _ := json.Marshal(raw)
		a, e := policy.ParseClientNAAArtifact(b)
		if e != nil {
			continue
		}
		if !strings.EqualFold(a.Domain, domain) || (maxAge > 0 && time.Since(r.ObservedAt) > maxAge) {
			continue
		}
		matches = append(matches, ClientNAAArtifactResolution{Artifact: a, ObservedAt: r.ObservedAt})
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return ClientNAAArtifactResolution{}, errors.New("multiple current NAA client artifacts are imported")
	}
	return ClientNAAArtifactResolution{}, errors.New("no current verified NAA client artifact is available")
}
