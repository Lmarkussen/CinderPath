package policy

import "testing"

func TestParseClientIdentityNormalizesGUID(t *testing.T) {
	id, err := ParseClientIdentity([]byte("kind: existing_sccm_client\nclient_id: '{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}'\ndomain: sccm.lab\nsource:\n  type: local_sccm_client_artifact\n  verified: true\n"))
	if err != nil || id.ClientID != "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" {
		t.Fatalf("identity=%+v err=%v", id, err)
	}
}

func TestParseClientIdentityRejectsNonGUIDText(t *testing.T) {
	if _, err := ParseClientIdentity([]byte("kind: existing_sccm_client\nclient_id: prefix-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")); err == nil {
		t.Fatal("non-canonical GUID text accepted")
	}
}
