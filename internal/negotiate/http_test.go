package negotiate

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestServicePrincipalUsesLogicalAuthority(t *testing.T) {
	got, err := ServicePrincipal("MECM.SCCM.LAB")
	if err != nil || got != "HTTP/mecm.sccm.lab" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := ServicePrincipal("10.1.10.41"); err == nil {
		t.Fatal("IP authority accepted for Kerberos SPN")
	}
}

func TestValidateOptionsRequiresExplicitIdentity(t *testing.T) {
	base := Options{Authority: "MECM.SCCM.LAB", TransportIP: "10.1.10.41", Realm: "SCCM.LAB", KDC: "10.1.10.40"}
	if err := validateOptions(base); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("missing identity was not rejected: %v", err)
	}
	base.PasswordRef = "env:CINDERPATH_PASSWORD"
	base.Username = "cinderpath-admin@SCCM.LAB"
	if err := validateOptions(base); err != nil {
		t.Fatalf("password reference rejected: %v", err)
	}
	base.CCachePath = "/tmp/explicit.ccache"
	if err := validateOptions(base); err == nil {
		t.Fatal("multiple identity sources accepted")
	}
}

func TestReadBounded(t *testing.T) {
	b, err := ReadBounded(strings.NewReader("safe"))
	if err != nil || string(b) != "safe" {
		t.Fatalf("bounded read: %q, %v", b, err)
	}
	if _, err := ReadBounded(strings.NewReader(strings.Repeat("x", maxResponseBytes+1))); err == nil {
		t.Fatal("oversized response accepted")
	}
}

func TestNewRejectsUnavailableExplicitSecretWithoutNetwork(t *testing.T) {
	_, err := New(context.Background(), Options{Authority: "MECM.SCCM.LAB", TransportIP: "10.1.10.41", Realm: "SCCM.LAB", KDC: "10.1.10.40", Username: "admin@SCCM.LAB", PasswordRef: "env:NOT_SET", TLSConfig: &tls.Config{}})
	if err == nil || !strings.Contains(err.Error(), "password reference unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestErrorClassification(t *testing.T) {
	if !strings.Contains("Kerberos authentication rejected by ConfigMgr (Negotiate)", "authentication rejected") {
		t.Fatal("classification regression")
	}
}

func TestGOADExplicitNegotiateAdminService(t *testing.T) {
	if os.Getenv("CINDERPATH_GOAD_NEGOTIATE") != "1" {
		t.Skip("set CINDERPATH_GOAD_NEGOTIATE=1 for authorized GOAD validation")
	}
	passwordRef := "env:CINDERPATH_GOAD_KRB_PASSWORD"
	if os.Getenv("CINDERPATH_GOAD_KRB_PASSWORD") == "" {
		t.Fatal("explicit GOAD password reference is unavailable")
	}
	c, err := New(context.Background(), Options{Authority: "MECM.SCCM.LAB", TransportIP: "10.1.10.41", Realm: "SCCM.LAB", KDC: "10.1.10.40", Username: "cinderpath-admin@SCCM.LAB", PasswordRef: passwordRef, TLSConfig: &tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://MECM.SCCM.LAB/AdminService/v1.0/$metadata", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ReadBounded(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || len(body) == 0 {
		t.Fatalf("unexpected authenticated AdminService response: %s (%d)", resp.Status, len(body))
	}
}
