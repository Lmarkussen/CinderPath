package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

func StableFingerprint(parts ...string) string {
	normalized := make([]string, len(parts))
	for i, part := range parts {
		normalized[i] = strings.ToLower(strings.TrimSpace(part))
	}
	sum := sha256.Sum256([]byte(strings.Join(normalized, "\x00")))
	return hex.EncodeToString(sum[:])
}

func StableID(prefix, fingerprint string) string {
	if len(fingerprint) > 20 {
		fingerprint = fingerprint[:20]
	}
	return prefix + "_" + fingerprint
}

func canonicalJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func (a *Asset) Prepare(now time.Time) {
	a.FQDN = strings.ToUpper(strings.TrimSpace(a.FQDN))
	a.Hostname = strings.ToUpper(strings.TrimSpace(a.Hostname))
	a.Domain = strings.ToUpper(strings.TrimSpace(a.Domain))
	a.SiteCode = strings.ToUpper(strings.TrimSpace(a.SiteCode))
	if a.FQDN == "" && a.Hostname == "" {
		a.Fingerprint = StableFingerprint(string(a.Kind), a.FQDN, a.Hostname, a.Domain, a.SiteCode, canonicalJSON(sortedCopy(a.IPAddresses)))
	} else {
		// Preserve the schema-v1 identity strategy for named assets.
		a.Fingerprint = StableFingerprint(string(a.Kind), a.FQDN, a.Hostname, a.Domain, a.SiteCode)
	}
	a.ID = StableID("ast", a.Fingerprint)
	if a.FirstSeen.IsZero() {
		a.FirstSeen = now.UTC()
	}
	a.LastSeen = now.UTC()
}

func (c *Credential) Prepare() {
	var fp string
	if c.Kind == "" {
		// Preserve the schema-v1 fingerprint for legacy discovery credentials.
		fp = StableFingerprint(c.Domain, c.Username, string(c.Type), c.Source)
	} else {
		// Identity references are keyed only by logical identity. Secret values and
		// reference locations intentionally cannot rotate the ID.
		fp = StableFingerprint(c.Domain, c.Username, c.Principal, c.MachineName, string(c.Kind))
	}
	c.ID = StableID("cred", fp)
}

func (c *Capability) Prepare() {
	fp := StableFingerprint(c.Name, c.Source, c.CredentialID, c.AssetID)
	c.ID = StableID("cap", fp)
}

func (e *Evidence) Prepare(now time.Time) {
	if e.CollectedAt.IsZero() {
		e.CollectedAt = now.UTC()
	}
	stableData := stableEvidenceData(e.Data)
	if stableData == nil {
		stableData = map[string]any{}
	}
	e.Fingerprint = StableFingerprint(e.SourceModule, e.Type, e.AssetID, e.CredentialID, e.Title, canonicalJSON(stableData))
	e.ID = StableID("ev", e.Fingerprint)
}

func stableEvidenceData(data map[string]any) map[string]any {
	out := make(map[string]any, len(data))
	for key, value := range data {
		switch strings.ToLower(key) {
		case "duration", "duration_ms", "observed_at", "collected_at":
			continue
		}
		out[key] = value
	}
	return out
}

func (f *Finding) Prepare(now time.Time) {
	f.Fingerprint = StableFingerprint(f.RuleID, canonicalJSON(sortedCopy(f.AssetIDs)), canonicalJSON(sortedCopy(f.CredentialIDs)))
	f.ID = StableID("fnd", f.Fingerprint)
	if f.Status == "" {
		f.Status = FindingOpen
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = now.UTC()
	}
	f.UpdatedAt = now.UTC()
}

func (r *Relationship) Prepare() {
	if r.Properties["role"] != "" || r.Properties["port"] != "" {
		r.Fingerprint = StableFingerprint(r.FromID, r.ToID, string(r.Type), r.Properties["role"], r.Properties["port"])
	} else {
		r.Fingerprint = StableFingerprint(r.FromID, r.ToID, string(r.Type))
	}
	r.ID = StableID("rel", r.Fingerprint)
}

func (p *AttackPath) Prepare() {
	keys := make([]string, 0, len(p.Steps))
	for _, step := range p.Steps {
		keys = append(keys, strings.Join([]string{step.FromID, step.ToID, string(step.RelationshipType)}, ":"))
	}
	p.Fingerprint = StableFingerprint(p.StartNodeID, p.EndNodeID, canonicalJSON(keys))
	p.ID = StableID("path", p.Fingerprint)
}
