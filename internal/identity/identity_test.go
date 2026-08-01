package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
)

func TestIdentityParsingAndStableLogicalID(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t.Setenv("PASS_ONE", "synthetic-one")
	t.Setenv("PASS_TWO", "synthetic-two")
	a, err := Parse(Input{Kind: "username_password_reference", User: `LAB\alice`, PasswordEnv: "PASS_ONE"}, now, 30)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(Input{Kind: "username_password_reference", User: "alice", Domain: "lab", PasswordEnv: "PASS_TWO"}, now, 30)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID {
		t.Fatalf("logical ID changed with reference rotation: %s != %s", a.ID, b.ID)
	}
	if a.Domain != "LAB" || a.Username != "alice" || a.SecretReference != "env:PASS_ONE" {
		t.Fatalf("unexpected normalization: %#v", a)
	}
	upn, _ := Parse(Input{User: "alice@lab.local"}, now, 30)
	if upn.Principal != "alice@lab.local" || upn.Domain != "LAB.LOCAL" {
		t.Fatalf("UPN not normalized: %#v", upn)
	}
	machine, err := Parse(Input{MachineAccount: "SCCM01$"}, now, 30)
	if err != nil || machine.Kind != models.CredentialMachineAccount {
		t.Fatalf("machine: %#v %v", machine, err)
	}
	if _, err = Parse(Input{Kind: "bogus"}, now, 30); err == nil {
		t.Fatal("expected invalid kind error")
	}
}

func TestReferenceValidationAndRedaction(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "deep", "password.txt")
	if err := os.Mkdir(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("synthetic-secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	present, readable, warn, _ := ValidateReference("file:"+p, MaxSecretBytes)
	if !present || !readable || warn == "" {
		t.Fatalf("validation %v %v %q", present, readable, warn)
	}
	if got := RedactReference("file:" + p); got != "file:password.txt" {
		t.Fatalf("redaction %q", got)
	}
	if _, readable, _, _ := ValidateReference("file:"+d, MaxSecretBytes); readable {
		t.Fatal("directory accepted")
	}
	large := filepath.Join(d, "large")
	if err := os.WriteFile(large, make([]byte, MaxSecretBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, _, _ := ValidateReference("file:"+large, MaxSecretBytes); ok {
		t.Fatal("oversized file accepted")
	}
}

func TestNTLMHashReferenceFormat(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t.Setenv("GOOD_HASH", "0123456789abcdef0123456789abcdef")
	good, err := Parse(Input{Kind: "ntlm_hash_reference", User: "alice", Domain: "lab", NTLMHashEnv: "GOOD_HASH"}, now, 30)
	if err != nil || !good.Validated {
		t.Fatalf("valid hash reference rejected: %#v %v", good, err)
	}
	t.Setenv("BAD_HASH", "not-a-hash")
	bad, err := Parse(Input{Kind: "ntlm_hash_reference", User: "alice", Domain: "lab", NTLMHashEnv: "BAD_HASH"}, now, 30)
	if err != nil || bad.Validated {
		t.Fatalf("invalid hash reference accepted: %#v %v", bad, err)
	}
}

func TestCertificatePEMAndDERMetadata(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "client.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(20 * 24 * time.Hour), DNSNames: []string{"client.example"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{{"cert.der", der}, {"cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), tc.name)
			if err := os.WriteFile(p, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			md, err := InspectCertificate(p, now, 30)
			if err != nil {
				t.Fatal(err)
			}
			if !md.HasClientAuthEKU || !md.NearExpiry || md.Expired || md.SHA256Fingerprint == "" {
				t.Fatalf("metadata %#v", md)
			}
		})
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("not a certificate"), 0o600)
	if _, err := InspectCertificate(bad, now, 30); err == nil {
		t.Fatal("malformed certificate accepted")
	}
}

func TestChallengeModelAndPlannerNeverAuthenticate(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := models.Evidence{ID: "ev_1", Type: "sccm_http_route", AssetID: "ast_1", CollectedAt: now, Data: map[string]any{"origin": "https://mp.lab", "route_id": "mp_list", "authentication_schemes": []string{"Negotiate", "NTLM"}, "access_state": map[string]any{"http_response_received": true, "authentication_requested": true, "authentication_attempted": false, "authenticated": false, "protocol_validated": true}}}
	r := Requirements([]models.Evidence{e}, now, 30)
	if len(r) != 1 || r[0].AuthenticatedObservation || !r[0].AuthenticationRequested || strings.Join(r[0].AdvertisedSchemes, ",") != "negotiate,ntlm" {
		t.Fatalf("requirements %#v", r)
	}
	t.Setenv("PASS_REF", "placeholder")
	id, _ := Parse(Input{Kind: "username_password_reference", User: `LAB\alice`, PasswordEnv: "PASS_REF"}, now, 30)
	caps := Plan([]models.Credential{id}, r)
	found := false
	for _, c := range caps {
		if c.Name == "integrated_auth_potentially_available" {
			found = true
			if c.State != models.CapabilityBlockedBySafety || !c.SafetyBlocked {
				t.Fatalf("unsafe state %#v", c)
			}
		}
	}
	if !found {
		t.Fatal("missing integrated auth potential")
	}
}

func TestStaleEvidenceDowngradesCapability(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	e := models.Evidence{ID: "ev", Type: "sccm_http_route", CollectedAt: now.Add(-31 * 24 * time.Hour), Data: map[string]any{"origin": "https://mp", "authentication_schemes": []string{"Negotiate"}, "access_state": map[string]any{"authentication_requested": true}}}
	id, _ := Parse(Input{Kind: "domain_user", User: "alice", Domain: "lab"}, now, 30)
	caps := Plan([]models.Credential{id}, Requirements([]models.Evidence{e}, now, 30))
	for _, c := range caps {
		if c.Name == "integrated_auth_potentially_available" && (!c.Stale || c.State != models.CapabilityRequiresValidation) {
			t.Fatalf("not downgraded %#v", c)
		}
	}
}
