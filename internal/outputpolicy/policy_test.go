package outputpolicy

import (
	"encoding/json"
	"testing"
)

func TestDefaultPolicyKeepsOperationalValues(t *testing.T) {
	p := Policy{}
	if p.Secret("ExampleRecoveredPassword!123") != "ExampleRecoveredPassword!123" {
		t.Fatal("default policy redacted a secret")
	}
	if got := p.RedactValue(map[string]any{"hostname": "MECM.SCCM.LAB", "username": "SCCMLAB\\svc-naa", "password": "ExampleRecoveredPassword!123"}).(map[string]any); got["hostname"] != "MECM.SCCM.LAB" || got["password"] != "ExampleRecoveredPassword!123" {
		t.Fatalf("default values changed: %#v", got)
	}
}

func TestSecretRedactionKeepsNonSecretsAndReportsPolicy(t *testing.T) {
	p := Policy{RedactSecrets: true}
	got := p.RedactValue(map[string]any{
		"hostname":      "MECM.SCCM.LAB",
		"site_code":     "P01",
		"username":      "SCCMLAB\\svc-naa",
		"password":      "ExampleRecoveredPassword!123",
		"private_key":   "PRIVATE KEY",
		"secret_source": "policy.xml",
	}).(map[string]any)
	if got["hostname"] != "MECM.SCCM.LAB" || got["site_code"] != "P01" || got["username"] != "SCCMLAB\\svc-naa" {
		t.Fatalf("non-secret operational values changed: %#v", got)
	}
	if got["password"] != RedactedMarker || got["private_key"] != RedactedMarker || got["secret_source"] != "policy.xml" {
		t.Fatalf("secret policy did not apply correctly: %#v", got)
	}
	b, err := json.Marshal(p.Metadata())
	if err != nil || string(b) != `{"secrets_redacted":true}` {
		t.Fatal("redaction metadata missing")
	}
}
