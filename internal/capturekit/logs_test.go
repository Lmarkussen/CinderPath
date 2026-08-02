package capturekit

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func TestInspectLogsBoundedRedactedAndDeterministic(t *testing.T) {
	p := testKit(t)
	line := `2026-08-02 10:01:02 [PolicyAgent] ERROR thread=42 URL https://mp01.lab.local/path GUID 11111111-2222-3333-4444-555555555555 SID S-1-5-21-123 HTTP 401 C:\Windows\CCM\Logs\x.log \\server\share Authorization: Bearer LOG_SECRET`
	if e := os.WriteFile(filepath.Join(p, "raw", "client.log"), []byte(line+"\npassword=not-a-recovered-secret\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	r, e := InspectLogs(p, time.Unix(1, 0).UTC(), DefaultLogLimits())
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Files) != 1 || r.SensitiveIndicators != 1 {
		t.Fatalf("%+v", r)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "LOG_SECRET") || strings.Contains(string(raw), "mp01.lab.local") {
		t.Fatal("log output leaked source value")
	}
	foundPassword := false
	for _, o := range r.Observations {
		if o.Category == "password_like_field" && o.Classification == "heuristic" {
			foundPassword = true
		}
	}
	if !foundPassword {
		t.Fatal("password-like field classification missing")
	}
	r2, _ := InspectLogs(p, time.Unix(1, 0).UTC(), DefaultLogLimits())
	if !reflect.DeepEqual(r, r2) {
		t.Fatal("inspection not deterministic")
	}
}

func TestInspectLogsUTF16AndOpaque(t *testing.T) {
	p := testKit(t)
	encode := func(s string, order binary.ByteOrder, bom []byte) []byte {
		u := utf16.Encode([]rune(s))
		b := append([]byte{}, bom...)
		for _, x := range u {
			z := make([]byte, 2)
			order.PutUint16(z, x)
			b = append(b, z...)
		}
		return b
	}
	_ = os.WriteFile(filepath.Join(p, "raw", "le.log"), encode("2026-08-02 10:01:02 WARN", binary.LittleEndian, []byte{0xff, 0xfe}), 0o600)
	_ = os.WriteFile(filepath.Join(p, "raw", "be.log"), encode("2026-08-02 10:01:02 ERROR", binary.BigEndian, []byte{0xfe, 0xff}), 0o600)
	_ = os.WriteFile(filepath.Join(p, "raw", "opaque.log"), []byte{0, 1, 2, 3}, 0o600)
	r, e := InspectLogs(p, time.Unix(1, 0), DefaultLogLimits())
	if e != nil {
		t.Fatal(e)
	}
	enc := map[string]string{}
	for _, f := range r.Files {
		enc[f.SafeName] = f.Encoding
	}
	if enc["le.log"] != "utf-16le" || enc["be.log"] != "utf-16be" || enc["opaque.log"] != "binary" {
		t.Fatalf("%v", enc)
	}
}

func TestInspectLogsLimitsAndSymlink(t *testing.T) {
	p := testKit(t)
	_ = os.WriteFile(filepath.Join(p, "raw", "a.log"), []byte(strings.Repeat("x", 100)), 0o600)
	if e := os.Symlink(filepath.Join(p, "raw", "a.log"), filepath.Join(p, "raw", "link.log")); e == nil {
		r, e := InspectLogs(p, time.Unix(1, 0), LogLimits{MaxFiles: 1, MaxBytesPerFile: 10, MaxTotalBytes: 10, MaxLines: 1, MaxLineLength: 4, MaxObservations: 1})
		if e != nil {
			t.Fatal(e)
		}
		if !r.Truncated && len(r.Warnings) == 0 {
			t.Fatal("limits/symlink not reported")
		}
	}
}

func FuzzLogDecoder(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{0xff, 0xfe, 65, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_, _, _ = decodeLog(b)
	})
}
func FuzzLogLineInspector(f *testing.F) {
	f.Add("Authorization: Bearer X")
	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > 1<<16 {
			return
		}
		r := LogInspection{}
		lf := LogFileInspection{LogFileID: "log_file_test"}
		inspectLine(&r, &lf, 1, line)
		if len(r.Observations) > len(logPatterns)+2 {
			t.Fatal("unbounded observations")
		}
	})
}
