package live

import (
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
)

func correlationAsset(name string, ips ...string) models.Asset {
	a := models.Asset{Kind: models.AssetUnknown, FQDN: name, IPAddresses: ips, Properties: map[string]string{"observation_origin": "live", "normalized_target": name}, Source: "test", Confidence: models.ConfidenceLow}
	if name != "" {
		a.Hostname = splitHost(name)
	}
	a.Prepare(time.Unix(1, 0))
	return a
}
func splitHost(v string) string {
	for i, r := range v {
		if r == '.' {
			return v[:i]
		}
	}
	return v
}
func correlationEvidence(kind, assetID string, data map[string]any) models.Evidence {
	e := models.Evidence{Type: kind, Title: kind, Data: data, SourceModule: "test", AssetID: assetID, Sensitivity: models.SensitivityInternal}
	e.Prepare(time.Unix(1, 0))
	return e
}
func hasEvidence(items []models.Evidence, kind string) bool {
	for _, e := range items {
		if e.Type == kind {
			return true
		}
	}
	return false
}
func hasRelationship(items []models.Relationship, kind models.RelationshipType) bool {
	for _, r := range items {
		if r.Type == kind {
			return true
		}
	}
	return false
}

func TestCorrelationFQDNShortIPAndCertificateAliases(t *testing.T) {
	named := correlationAsset("sccm01.lab.local")
	ip := correlationAsset("", "192.0.2.10")
	dns := correlationEvidence("dns_resolution", named.ID, map[string]any{"answers": []string{"192.0.2.10"}})
	tls := correlationEvidence("http_profile", named.ID, map[string]any{"tls": map[string]any{"dns_names": []string{"sccm01.lab.local", "sccm01"}}})
	result := correlateSCCMEvidence([]models.Asset{named, ip}, []models.Evidence{dns, tls}, time.Unix(2, 0))
	if !hasRelationship(result.Relationships, models.RelationshipSameLogicalHost) {
		t.Fatalf("relationships=%+v", result.Relationships)
	}
	if hasEvidence(result.Evidence, "identity_conflict") {
		t.Fatalf("unexpected conflict: %+v", result.Evidence)
	}
}

func TestCorrelationPreservesAmbiguousSharedIP(t *testing.T) {
	a := correlationAsset("one.lab.local", "192.0.2.20")
	b := correlationAsset("two.lab.local", "192.0.2.20")
	r := correlateSCCMEvidence([]models.Asset{a, b}, nil, time.Unix(2, 0))
	if hasRelationship(r.Relationships, models.RelationshipSameLogicalHost) {
		t.Fatal("ambiguous assets were merged")
	}
	if !hasEvidence(r.Evidence, "identity_conflict") {
		t.Fatal("missing shared-IP conflict")
	}
}

func TestCorrelationUnresolvedLDAPAndMPListReferences(t *testing.T) {
	a := correlationAsset("mp01.lab.local")
	ldap := correlationEvidence("ldap_sccm_object", "", map[string]any{"distinguished_name": "CN=MP", "referenced_hosts": []string{"missing.lab.local"}})
	mp := correlationEvidence("sccm_mp_protocol", a.ID, map[string]any{"classification": "protocol_validated_management_point", "site_codes": []string{"ABC"}, "referenced_hosts": []string{"other.lab.local"}})
	r := correlateSCCMEvidence([]models.Asset{a}, []models.Evidence{ldap, mp}, time.Unix(2, 0))
	if !hasEvidence(r.Evidence, "unresolved_directory_reference") || !hasEvidence(r.Evidence, "unmatched_mp_list_reference") {
		t.Fatalf("evidence=%+v", r.Evidence)
	}
	if !hasEvidence(r.Evidence, "identity_conflict") {
		t.Fatal("missing validated MP absent-from-LDAP conflict")
	}
}

func TestCorrelationCertificateMismatchMPMatchAndSiteConflict(t *testing.T) {
	a := correlationAsset("mp01.lab.local")
	a.SiteCode = "AAA"
	tls := correlationEvidence("http_profile", a.ID, map[string]any{"tls": map[string]any{"dns_names": []string{"wrong.lab.local"}}})
	mp := correlationEvidence("sccm_mp_protocol", a.ID, map[string]any{"classification": "protocol_validated_management_point", "site_codes": []string{"BBB"}, "referenced_hosts": []string{"mp01"}})
	ldap := correlationEvidence("ldap_sccm_object", "", map[string]any{"distinguished_name": "CN=MP", "referenced_hosts": []string{"mp01.lab.local"}})
	r := correlateSCCMEvidence([]models.Asset{a}, []models.Evidence{tls, mp, ldap}, time.Unix(2, 0))
	if !hasRelationship(r.Relationships, models.RelationshipMPListReferencesHost) {
		t.Fatal("MP-list reference did not match")
	}
	conflicts := 0
	for _, e := range r.Evidence {
		if e.Type == "identity_conflict" {
			conflicts++
		}
	}
	if conflicts < 2 {
		t.Fatalf("expected certificate and site conflicts, got %d", conflicts)
	}
}

func TestCorrelationDuplicateRunsAndFingerprintsAreStable(t *testing.T) {
	a := correlationAsset("mp01.lab.local")
	e := correlationEvidence("sccm_mp_protocol", a.ID, map[string]any{"classification": "protocol_validated_management_point", "referenced_hosts": []string{"mp01.lab.local"}})
	one := correlateSCCMEvidence([]models.Asset{a}, []models.Evidence{e}, time.Unix(2, 0))
	two := correlateSCCMEvidence([]models.Asset{a}, []models.Evidence{e}, time.Unix(3, 0))
	ids := map[string]bool{}
	for _, v := range one.Evidence {
		ids[v.ID] = true
	}
	for _, v := range two.Evidence {
		if !ids[v.ID] {
			t.Fatalf("unstable evidence fingerprint: %s", v.ID)
		}
	}
	before := a.ID
	a.Prepare(time.Unix(4, 0))
	if a.ID != before {
		t.Fatalf("asset fingerprint changed: %s != %s", a.ID, before)
	}
}
