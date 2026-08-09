package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/policy"
)

// ClientIdentityResolution is persisted operator-provided metadata, not a
// credential or proof that CinderPath has registered or authenticated a client.
type ClientIdentityResolution struct {
	Identity   policy.ClientIdentity
	ObservedAt time.Time
}

// ImportClientIdentity records reviewed metadata for an already-existing SCCM
// client. It never contacts SCCM, imports certificate contents, or registers a
// client.
func (a *Application) ImportClientIdentity(ctx context.Context, identity policy.ClientIdentity) error {
	raw, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	identity, err = policy.ParseClientIdentity(raw)
	if err != nil {
		return err
	}
	if strings.TrimSpace(identity.Domain) == "" {
		return errors.New("client identity domain is required for reusable CRED-2 planning")
	}
	if strings.TrimSpace(identity.Source.Type) == "" {
		return errors.New("client identity source.type is required")
	}
	identity.Domain = strings.ToUpper(strings.TrimSpace(identity.Domain))
	identity.Certificate.Reference = filepath.Base(identity.Certificate.Reference)
	observedAt := time.Now().UTC()
	if identity.Source.CapturedAt != "" {
		parsed, err := time.Parse(time.RFC3339, identity.Source.CapturedAt)
		if err != nil {
			return fmt.Errorf("client identity source.captured_at must be RFC3339: %w", err)
		}
		observedAt = parsed.UTC()
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(identity.Domain + "|" + identity.ClientID))
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.UpsertPolicyRecord(ctx, "client_identity_metadata", database.PolicyRecord{
		ID:          "client_identity_" + hex.EncodeToString(sum[:10]),
		Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		ObservedAt:  observedAt,
		Data:        map[string]any{"identity": json.RawMessage(data), "source_type": identity.Source.Type, "source_verified": identity.Source.Verified},
	})
}

// StoredClientIdentity returns one fresh, domain-compatible, explicitly
// verified existing-client record. Ambiguous, stale, and cross-domain records
// never satisfy a technique prerequisite.
func (a *Application) StoredClientIdentity(ctx context.Context, domain string, maxAge time.Duration) (ClientIdentityResolution, error) {
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return ClientIdentityResolution{}, err
	}
	defer store.Close()
	records, err := store.ListPolicyRecords(ctx, "client_identity_metadata")
	if err != nil {
		return ClientIdentityResolution{}, err
	}
	wantDomain := strings.ToUpper(strings.TrimSpace(domain))
	var matches []ClientIdentityResolution
	wrongDomain, stale, unverified := false, false, false
	for _, record := range records {
		raw, ok := record.Data["identity"]
		if !ok {
			continue
		}
		data, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		identity, err := policy.ParseClientIdentity(data)
		if err != nil {
			continue
		}
		if !strings.EqualFold(identity.Domain, wantDomain) {
			wrongDomain = true
			continue
		}
		if !identity.Source.Verified {
			unverified = true
			continue
		}
		if maxAge > 0 && time.Since(record.ObservedAt) > maxAge {
			stale = true
			continue
		}
		matches = append(matches, ClientIdentityResolution{Identity: identity, ObservedAt: record.ObservedAt})
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return ClientIdentityResolution{}, errors.New("multiple compatible existing SCCM client identities are imported; select one through reviewed metadata")
	}
	switch {
	case wrongDomain:
		return ClientIdentityResolution{}, fmt.Errorf("imported client identity is not in domain %s", wantDomain)
	case stale:
		return ClientIdentityResolution{}, errors.New("imported client identity metadata is stale")
	case unverified:
		return ClientIdentityResolution{}, errors.New("imported client identity requires source.verified: true")
	default:
		return ClientIdentityResolution{}, errors.New("no imported existing SCCM client identity is available")
	}
}
