package live

import (
	"github.com/Lmarkussen/CinderPath/internal/models"
	"testing"
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
