package live

import (
	"github.com/Lmarkussen/CinderPath/internal/models"
	"testing"
	"time"
)

func TestRoleInferenceConfidence(t *testing.T) {
	a := models.Asset{FQDN: "sccm01.lab.local", Properties: map[string]string{"open_ports": "1433"}}
	r := inferRoles(a, RoleHints{}, nil)
	seen := map[string]models.Confidence{}
	for _, v := range r {
		seen[v.Role] = v.Confidence
	}
	if seen["site_server"] != models.ConfidenceLow || seen["sql_server"] != models.ConfidenceLow {
		t.Fatalf("roles=%+v", r)
	}
	r = inferRoles(a, RoleHints{SiteServers: []string{"sccm01.lab.local"}}, nil)
	for _, v := range r {
		if v.Role == "site_server" && v.Confidence != models.ConfidenceMedium {
			t.Fatalf("role=%+v", v)
		}
	}
}

func TestProtocolRoleEvidenceOutranksLDAPAndGenericMetadata(t *testing.T) {
	a := models.Asset{Kind: models.AssetUnknown, FQDN: "sccm01.lab.local", Roles: []string{"management_point"}, Properties: map[string]string{"open_ports": "80", "role_basis": "ldap_sccm_object"}}
	a.Prepare(time.Now())
	ldap := models.Evidence{Type: "ldap_sccm_object", Title: "LDAP", Data: map[string]any{"inferred_roles": []string{"management_point"}, "referenced_hosts": []string{"sccm01.lab.local"}}}
	ldap.Prepare(time.Now())
	protocol := models.Evidence{Type: "sccm_mp_protocol", Title: "MP", AssetID: a.ID, Data: map[string]any{"classification": "protocol_validated_management_point"}}
	protocol.Prepare(time.Now())
	httpEvidence := models.Evidence{Type: "http_profile", Title: "HTTP", AssetID: a.ID, Data: map[string]any{"page_title": "Configuration Manager"}}
	httpEvidence.Prepare(time.Now())
	conclusions := inferRoles(a, RoleHints{ManagementPoints: []string{"sccm01.lab.local"}}, []models.Evidence{ldap, protocol, httpEvidence})
	for _, conclusion := range conclusions {
		if conclusion.Role == "management_point" {
			if conclusion.Confidence != models.ConfidenceHigh || conclusion.Precedence != 6 || len(conclusion.EvidenceIDs) != 1 || conclusion.EvidenceIDs[0] != protocol.ID {
				t.Fatalf("conclusion=%+v", conclusion)
			}
			if _, _, finding := roleFinding("management_point"); finding {
				t.Fatal("generic role inference should not create an MP endpoint finding")
			}
			return
		}
	}
	t.Fatal("management point conclusion missing")
}
