package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sentinel = "SyntheticPassword123!"

func TestImportParseClassifyAndOutput(t *testing.T) {
	f, c, e := ImportDirectory("testdata/example01")
	if e != nil {
		t.Fatal(e)
	}
	if c.VerificationState != FixtureOnly {
		t.Fatal(c.VerificationState)
	}
	if e = c.LiveAllowed(); e == nil {
		t.Fatal("live allowed")
	}
	p, cs, e := ParsePolicy(context.Background(), f.ResponseBody)
	if e != nil {
		t.Fatal(e)
	}
	if p.PolicyID != "POL_SYNTHETIC_001" {
		t.Fatal(p.PolicyID)
	}
	confirmed := false
	for _, x := range cs {
		if x.State == "confirmed_plaintext" && x.Value == sentinel {
			confirmed = true
		}
		r := Redacted(x)
		b, _ := jsonBytes(r)
		if strings.Contains(string(b), sentinel) {
			t.Fatal("redacted candidate leaked")
		}
	}
	if !confirmed {
		t.Fatal("confirmed synthetic credential missing")
	}
	var hidden bytes.Buffer
	_, e = OutputSecrets(&hidden, cs, SecretOptions{Profile: "safe", Show: true})
	if e != nil || strings.Contains(hidden.String(), sentinel) {
		t.Fatal("safe leaked")
	}
	var shown bytes.Buffer
	_, e = OutputSecrets(&shown, cs, SecretOptions{Profile: "standard", Show: true})
	if e != nil || !strings.Contains(shown.String(), sentinel) {
		t.Fatal("explicit output missing")
	}
	out := filepath.Join(t.TempDir(), "secrets.txt")
	_, e = OutputSecrets(&hidden, cs, SecretOptions{Profile: "yolo", Path: out, Format: "text"})
	if e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), sentinel) {
		t.Fatal("secure output missing")
	}
	st, _ := os.Stat(out)
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}
func jsonBytes(v any) ([]byte, error) { return json.Marshal(v) }
func TestParserBoundsAndEntities(t *testing.T) {
	for _, b := range [][]byte{[]byte("not xml"), []byte("<!DOCTYPE x [<!ENTITY y 'z'>]><Policy>&y;</Policy>")} {
		if _, _, e := ParsePolicy(context.Background(), b); e == nil {
			t.Fatal("unsafe input accepted")
		}
	}
}
func TestContractCannotPromote(t *testing.T) {
	c := Contract{ID: "x", VerificationState: ApprovedLive}
	if SaveContract(t.TempDir(), c) == nil {
		t.Fatal("approved_live persisted")
	}
}
func TestLoopbackReplay(t *testing.T) {
	f, c, e := ImportDirectory("testdata/example01")
	if e != nil {
		t.Fatal(e)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CCM_POST" || r.URL.Path != "/ccm_system/request" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Fatal("sensitive header")
		}
		_, _ = w.Write(f.ResponseBody)
	}))
	defer srv.Close()
	b, e := Replay(context.Background(), c, f, srv.URL)
	if e != nil || !bytes.Contains(b, []byte("POL_SYNTHETIC_001")) {
		t.Fatalf("replay: %v", e)
	}
	if _, e = Replay(context.Background(), c, f, "http://192.0.2.1"); e == nil {
		t.Fatal("non-loopback accepted")
	}
}
func TestSanitizeDoesNotModifySource(t *testing.T) {
	src := "testdata/example01"
	before, _ := os.ReadFile(filepath.Join(src, "request.body"))
	out := filepath.Join(t.TempDir(), "out")
	if e := Sanitize(src, out); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(filepath.Join(src, "request.body"))
	if !bytes.Equal(before, after) {
		t.Fatal("source changed")
	}
	if _, e := os.Stat(filepath.Join(out, "sanitization-manifest.json")); e != nil {
		t.Fatal(e)
	}
}
func FuzzPolicyParser(f *testing.F) {
	f.Add([]byte(`<Policy PolicyID="P"><Setting Name="Password" Value="x"/></Policy>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxFixtureBytes {
			return
		}
		_, _, _ = ParsePolicy(context.Background(), b)
	})
}
func FuzzBinaryInspection(f *testing.F) {
	f.Add([]byte("<?xml synthetic?>"))
	f.Add([]byte{0x1f, 0x8b, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxFixtureBytes {
			return
		}
		_, _ = InspectBinary(b)
	})
}
