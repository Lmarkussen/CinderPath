package live

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/progress"
)

type fakeSMBSession struct {
	names     []string
	loggedOff bool
}

func (f *fakeSMBSession) ListSharenames() ([]string, error) {
	return append([]string(nil), f.names...), nil
}
func (f *fakeSMBSession) Logoff() error { f.loggedOff = true; return nil }

func TestClassifySMBShare(t *testing.T) {
	tests := map[string]string{
		"SCCMContentLib$": "content_library_candidate",
		"SMS_DP_SMSPKG$":  "distribution_point_share_candidate",
		"SMSPKGQ$":        "distribution_point_share_candidate",
		"SMSSIG$":         "signature_share_candidate",
		"SMS_P01":         "sccm_site_share_candidate",
		"ADMIN$":          "generic_administrative_share",
		"IPC$":            "generic_administrative_share",
		"Public":          "unclassified_share",
	}
	for input, want := range tests {
		if got := classifySMBShare(input); got != want {
			t.Errorf("classifySMBShare(%q)=%q, want %q", input, got, want)
		}
	}
}

func TestSMBPrincipalForms(t *testing.T) {
	for _, tc := range []struct{ in, fallback, user, domain string }{
		{`SCCMLAB\alice`, "fallback", "alice", "SCCMLAB"},
		{"alice@SCCM.LAB", "fallback", "alice", "SCCM.LAB"},
		{"alice", "SCCM.LAB", "alice", "SCCM.LAB"},
	} {
		user, domain := splitSMBPrincipal(tc.in, tc.fallback)
		if user != tc.user || domain != tc.domain {
			t.Errorf("splitSMBPrincipal(%q)=(%q,%q)", tc.in, user, domain)
		}
	}
}

func TestSMBOnlySelectsOnlyShareModule(t *testing.T) {
	mods := SMBOnly(Options{SMB: SMBOptions{Enabled: true, Server: "host", User: "u", Password: "p"}})
	if len(mods) != 1 || mods[0].Metadata().Name != "live.smb.share_metadata" {
		t.Fatalf("unexpected SMB modules: %v", mods)
	}
	ok, reason := mods[0].Applicable(context.Background(), modules.RunContext{}, &models.Asset{})
	if !ok || reason != "" {
		t.Fatalf("module should apply: %v %s", ok, reason)
	}
}

func TestSanitizeSMBTextBounded(t *testing.T) {
	got := sanitizeSMBText("a\x00b\n"+string(make([]byte, 300)), 8)
	if len(got) > 8 || got != "ab" {
		t.Fatalf("unexpected sanitized value %q", got)
	}
}

func TestSMBModuleUsesBoundedShareMetadataInterface(t *testing.T) {
	originalTCP, originalSession := dialSMBTCP, dialSMBSession
	defer func() { dialSMBTCP, dialSMBSession = originalTCP, originalSession }()
	client, server := net.Pipe()
	defer server.Close()
	dialSMBTCP = func(context.Context, string, time.Duration) (net.Conn, error) { return client, nil }
	fake := &fakeSMBSession{names: []string{"ADMIN$", "SCCMContentLib$"}}
	dialSMBSession = func(context.Context, net.Conn, string, string, string) (smbSession, error) { return fake, nil }
	m := &smbShareMetadataModule{opts: Options{Domain: "SCCM.LAB", SMB: SMBOptions{Enabled: true, Server: "mecm", User: "u", Password: "p", PasswordReference: "env:X", MaxShares: 128}}}
	out, err := m.Run(context.Background(), modules.RunContext{Progress: progress.Nop{}}, nil)
	if err != nil || len(out.Evidence) != 1 || !fake.loggedOff {
		t.Fatalf("unexpected result: err=%v evidence=%d loggedoff=%v", err, len(out.Evidence), fake.loggedOff)
	}
	shares, ok := out.Evidence[0].Data["shares"].([]map[string]any)
	if !ok || len(shares) != 2 {
		t.Fatalf("unexpected bounded shares: %#v", out.Evidence[0].Data["shares"])
	}
	raw, _ := json.Marshal(out)
	if bytes.Contains(raw, []byte(`"p"`)) {
		// The result model must not carry the resolved password in evidence or output.
		t.Fatalf("resolved password leaked into module result")
	}
}
