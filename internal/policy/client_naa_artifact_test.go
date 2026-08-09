package policy

import (
	"strings"
	"testing"
)

const validNAAArtifact = `kind: sccm_client_naa_artifact
source_host: CLIENT
domain: sccm.lab
site_code: p01
namespace: root\ccm\policy\machine\actualconfig
class: CCM_NetworkAccessAccount
captured_at: "2026-08-09T20:40:44Z"
source:
  type: local_sccm_client_artifact
  verified: true
network_access_username:
  present: true
  material_state: protected
  length: 585
network_access_password:
  present: true
  material_state: protected
  length: 585
`

func TestParseClientNAAArtifactPositive(t *testing.T) {
	a, err := ParseClientNAAArtifact([]byte(validNAAArtifact))
	if err != nil {
		t.Fatal(err)
	}
	if a.Domain != "SCCM.LAB" || a.SiteCode != "P01" || a.Username.State != "protected" || a.Password.Length != 585 {
		t.Fatalf("%+v", a)
	}
	if a.Fingerprint() == "" {
		t.Fatal("missing fingerprint")
	}
}

func TestParseClientNAAArtifactRejectsInvalidForms(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"class_absent": func(s string) string { return strings.Replace(s, "class: CCM_NetworkAccessAccount", "class: ", 1) },
		"username_absent": func(s string) string {
			return strings.Replace(s, "present: true\n  material_state: protected\n  length: 585\nnetwork_access_password", "present: false\n  material_state: protected\n  length: 585\nnetwork_access_password", 1)
		},
		"empty_protected": func(s string) string { return strings.Replace(s, "length: 585", "length: 0", 1) },
		"wrong_namespace": func(s string) string {
			return strings.Replace(s, "root\\ccm\\policy\\machine\\actualconfig", "root\\ccm", 1)
		},
		"wrong_class": func(s string) string { return strings.Replace(s, "CCM_NetworkAccessAccount", "CCM_TaskSequence", 1) },
		"oversized":   func(s string) string { return strings.Replace(s, "length: 585", "length: 1048577", 1) },
		"unverified":  func(s string) string { return strings.Replace(s, "verified: true", "verified: false", 1) },
		"raw_value":   func(s string) string { return strings.Replace(s, "length: 585", "length: 585\n  value: secret", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseClientNAAArtifact([]byte(mutate(validNAAArtifact))); err == nil {
				t.Fatal("accepted invalid artifact")
			}
		})
	}
}
