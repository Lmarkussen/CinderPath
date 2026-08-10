package recon6

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestCanonicalAllowlist(t *testing.T) {
	if SMSRoot != `SOFTWARE\Microsoft\SMS` || SiteDB != `SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers` {
		t.Fatalf("unexpected registry allowlist: %q %q", SMSRoot, SiteDB)
	}
	if MaxSubkeys <= 0 || MaxValueBytes <= 0 || MaxValues <= 0 {
		t.Fatal("bounds must be positive")
	}
}

func TestPrincipalForms(t *testing.T) {
	tests := []struct{ in, domain, user, wantDomain string }{
		{"user@SCCM.LAB", "", "user", "SCCM.LAB"},
		{`SCCMLAB\user`, "fallback", "user", "SCCMLAB"},
		{"user", "SCCM.LAB", "user", "SCCM.LAB"},
	}
	for _, tt := range tests {
		if got := principalUser(tt.in); got != tt.user || principalDomain(tt.in, tt.domain) != tt.wantDomain {
			t.Errorf("principal %q => %q/%q", tt.in, principalUser(tt.in), principalDomain(tt.in, tt.domain))
		}
	}
}

func TestReadOnlyTargetValidation(t *testing.T) {
	_, err := Enumerate(context.Background(), Options{LogicalHost: "MECM.SCCM.LAB", Transport: "10.1.10.41", Timeout: time.Millisecond})
	if err == nil || err.Error() != "explicit SMB identity is required" {
		t.Fatalf("missing identity error=%v", err)
	}
}

func TestFixedDialerUsesEvidenceTransport(t *testing.T) {
	d := fixedDialer{transport: "127.0.0.1", timeout: time.Millisecond}
	if _, err := d.DialContext(context.Background(), "tcp", "203.0.113.1:445"); err == nil {
		t.Fatal("expected loopback connection refusal; dialer may have used caller address")
	}
	var _ interface {
		Dial(string, string) (net.Conn, error)
	} = d
}

func TestContainsIsDeterministic(t *testing.T) {
	if !contains([]string{"MP", "DP"}, "dp") || contains([]string{"MP"}, "DP") {
		t.Fatal("case-insensitive role matching failed")
	}
}
