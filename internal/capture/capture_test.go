package capture

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestHARImportRedactsAndDeterministic(t *testing.T) {
	const h = `{"log":{"version":"1.2","entries":[{"startedDateTime":"2026-01-01T00:00:00Z","request":{"method":"POST","url":"http://synthetic.invalid/route?token=SECRET_SENTINEL","httpVersion":"HTTP/1.1","headers":[{"Name":"Authorization","Value":"Bearer SECRET_SENTINEL"}],"postData":{"mimeType":"application/xml","text":"<x>SECRET_SENTINEL</x>"}},"response":{"status":200,"httpVersion":"HTTP/1.1","headers":[{"Name":"Set-Cookie","Value":"s=SECRET_SENTINEL"}],"content":{"size":2,"mimeType":"text/plain","text":"ok"}}}]}}`
	a, e := Import(strings.NewReader(h), "x.har", "", DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	b, e := Import(strings.NewReader(h), "x.har", "", DefaultLimits())
	if e != nil || a.Source.ID != b.Source.ID {
		t.Fatalf("nondeterministic: %v", e)
	}
	raw, _ := json.Marshal(a)
	if bytes.Contains(raw, []byte("SECRET_SENTINEL")) {
		t.Fatal("secret persisted")
	}
	if a.Exchanges[0].Request.Route != "/route" || a.Sequence.Classification != "single_exchange" {
		t.Fatalf("bad normalize: %+v", a)
	}
}
func TestPCAPBoundsAndOpaqueTLS(t *testing.T) {
	b := make([]byte, 24+16+8)
	binary.LittleEndian.PutUint32(b, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(b[24+8:], 8)
	copy(b[40:], []byte{0x16, 0x03, 1, 2, 3, 4, 5, 6})
	c, e := Import(bytes.NewReader(b), "x.pcap", "", DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(strings.Join(c.Source.Warnings, " "), "opaque TLS") {
		t.Fatal(c.Source.Warnings)
	}
}
func TestMatrixAndCandidateConservative(t *testing.T) {
	h := `{"log":{"version":"1.2","entries":[{"request":{"method":"GET","url":"http://x.invalid/a","httpVersion":"HTTP/1.1"},"response":{"status":200,"httpVersion":"HTTP/1.1"}}]}}`
	a, _ := Import(strings.NewReader(h), "a.har", "", DefaultLimits())
	b := a
	b.Source.ID = "capture_other"
	b.Source.Fingerprint = "other"
	r := ValidateMatrix(Matrix{Members: []MatrixMember{{Label: "a"}, {Label: "b"}}}, map[string]NormalizedCapture{"a": a, "b": b})
	if r.Quality != "suitable" {
		t.Fatal(r)
	}
	p := DeriveCandidates([]NormalizedCapture{a, b}, 2)
	if len(p) != 1 || p[0].LiveExecution {
		t.Fatalf("candidate: %+v", p)
	}
}
func TestBinaryObservationsAreStructural(t *testing.T) {
	o := InspectBinary(append([]byte("MSCFhello"), 0, 0, 0, 0), 1024)
	if len(o) == 0 {
		t.Fatal("none")
	}
	for _, x := range o {
		if !x.Structural || strings.Contains(x.Interpretation, "client GUID") {
			t.Fatal(x)
		}
	}
}
func FuzzHAR(f *testing.F) {
	f.Add([]byte(`{"log":{"version":"1.2","entries":[]}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			return
		}
		_, _ = Import(bytes.NewReader(b), "x.har", "har", Limits{MaxCaptureBytes: 1 << 16, MaxPackets: 32, MaxBodyBytes: 1 << 14, MaxStreamBytes: 1 << 14, MaxCompressionRatio: 16})
	})
}
func FuzzBinaryObservations(f *testing.F) {
	f.Add([]byte("MSCFtest"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4096 {
			return
		}
		_ = InspectBinary(b, 4096)
	})
}
