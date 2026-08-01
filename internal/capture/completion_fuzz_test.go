package capture

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func bounded(b []byte) bool { return len(b) <= 1<<16 }
func FuzzPCAPNGBlocks(f *testing.F) {
	f.Add(syntheticPCAPNG())
	f.Fuzz(func(t *testing.T, b []byte) {
		if bounded(b) {
			_, _ = Import(bytes.NewReader(b), "x.pcapng", "pcapng", DefaultLimits())
		}
	})
}
func FuzzPacketDecoder(f *testing.F) {
	f.Add([]byte{0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 4096 {
			_, _, _, _ = tcpPayload(b)
		}
	})
}
func FuzzHTTPFraming(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if bounded(b) {
			_ = looksRequest(b)
		}
	})
}
func FuzzSequenceGraph(f *testing.F) {
	f.Add("GET", "/x")
	f.Fuzz(func(t *testing.T, m, p string) {
		if len(m)+len(p) < 1024 {
			_ = CompareSequences([]NormalizedCapture{{Source: Source{ID: "x"}, Exchanges: []Exchange{{ID: "e", Request: &Message{Method: m, Route: p}}}}})
		}
	})
}
func FuzzXMLStructural(f *testing.F) {
	f.Add([]byte("<x/>"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if bounded(b) {
			_, _ = ParseStructured("application/xml", b, DefaultLimits())
		}
	})
}
func FuzzJSONStructural(f *testing.F) {
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if bounded(b) {
			_, _ = ParseStructured("application/json", b, DefaultLimits())
		}
	})
}
func FuzzMultipartStructural(f *testing.F) {
	f.Add([]byte("--x--\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if bounded(b) {
			_, _ = ParseStructured("multipart/mixed; boundary=x", b, DefaultLimits())
		}
	})
}
func FuzzMatrixValidator(f *testing.F) {
	f.Add("x")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) < 1024 {
			_ = ValidateMatrix(Matrix{Name: s}, map[string]NormalizedCapture{})
		}
	})
}
func FuzzCorpusManifest(f *testing.F) {
	f.Add([]byte("schema_version: 1\nfixtures: []\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if !bounded(b) {
			return
		}
		d := t.TempDir()
		_ = os.WriteFile(filepath.Join(d, "corpus.yaml"), b, 0600)
		_, _ = ReplayCorpus(d, DefaultLimits())
	})
}
