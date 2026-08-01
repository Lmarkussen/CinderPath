package capture

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ngBlock(o binary.ByteOrder, typ uint32, body []byte) []byte {
	n := (12 + len(body) + 3) &^ 3
	b := make([]byte, n)
	o.PutUint32(b, typ)
	o.PutUint32(b[4:], uint32(n))
	copy(b[8:], body)
	o.PutUint32(b[n-4:], uint32(n))
	return b
}
func syntheticPCAPNG() []byte {
	o := binary.LittleEndian
	sh := make([]byte, 16)
	copy(sh, []byte{0x4d, 0x3c, 0x2b, 0x1a})
	o.PutUint16(sh[4:], 1)
	for i := 8; i < 16; i++ {
		sh[i] = 0xff
	}
	idb := make([]byte, 8)
	o.PutUint16(idb, 1)
	o.PutUint32(idb[4:], 65535)
	pkt := make([]byte, 54)
	pkt[12] = 8
	pkt[14] = 0x45
	pkt[23] = 6
	copy(pkt[26:30], []byte{10, 0, 0, 1})
	copy(pkt[30:34], []byte{10, 0, 0, 2})
	tcp := pkt[34:]
	o.PutUint16(tcp, 0x5000)
	binary.BigEndian.PutUint16(tcp, 1234)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	tcp[12] = 0x50
	ep := make([]byte, 20+len(pkt))
	o.PutUint32(ep, 0)
	o.PutUint32(ep[8:], 1)
	o.PutUint32(ep[12:], uint32(len(pkt)))
	o.PutUint32(ep[16:], uint32(len(pkt)))
	copy(ep[20:], pkt)
	return append(append(ngBlock(o, pcapngSection, sh), ngBlock(o, pcapngInterface, idb)...), ngBlock(o, pcapngEnhanced, ep)...)
}
func TestPCAPNGDecodesPacketsAndInterface(t *testing.T) {
	c, e := Import(bytes.NewReader(syntheticPCAPNG()), "synthetic.pcapng", "", DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Interfaces) != 1 || len(c.Packets) != 1 || c.Packets[0].CapturedLength != 54 {
		t.Fatalf("decode: %+v %+v", c.Interfaces, c.Packets)
	}
}
func TestPCAPNGRejectsTrailingMismatch(t *testing.T) {
	b := syntheticPCAPNG()
	b[len(b)-1] ^= 1
	if _, e := Import(bytes.NewReader(b), "x.pcapng", "", DefaultLimits()); e == nil {
		t.Fatal("expected rejection")
	}
}
func TestStructuredXMLJSONMultipart(t *testing.T) {
	l := DefaultLimits()
	x, w := ParseStructured("application/xml", []byte(`<r xmlns="urn:x"><a>secret</a><a>two</a></r>`), l)
	if len(w) > 0 || len(x) < 4 {
		t.Fatalf("xml %v %v", x, w)
	}
	if _, w = ParseStructured("application/xml", []byte(`<!DOCTYPE x><x/>`), l); len(w) == 0 {
		t.Fatal("DTD accepted")
	}
	j, w := ParseStructured("application/json", []byte(`{"a":[1,"secret"]}`), l)
	if len(w) > 0 || len(j) != 2 {
		t.Fatalf("json %v %v", j, w)
	}
	if _, w = ParseStructured("application/json", []byte(`{"a":1,"a":2}`), l); len(w) == 0 {
		t.Fatal("duplicate key accepted")
	}
	m, w := ParseStructured("multipart/mixed; boundary=abc", []byte("--abc\r\nContent-Type: application/json\r\n\r\n{\"x\":1}\r\n--abc--\r\n"), l)
	if len(w) > 0 || len(m) < 3 {
		t.Fatalf("multipart %v %v", m, w)
	}
	raw, _ := json.Marshal([]any{x, j, m})
	if strings.Contains(string(raw), "secret") {
		t.Fatal("plaintext leaked")
	}
}
func TestPartialOrderComparison(t *testing.T) {
	a := NormalizedCapture{Source: Source{ID: "a"}, Exchanges: []Exchange{{ID: "a1", Request: &Message{Method: "GET", Route: "/a"}}, {ID: "a2", Request: &Message{Method: "GET", Route: "/b"}}}, Sequence: Sequence{Edges: []SequenceEdge{{From: "a1", To: "a2"}}}}
	b := a
	b.Source.ID = "b"
	r := CompareSequences([]NormalizedCapture{a, b})
	if r.Classification != "partial_order" || len(r.Edges) != 1 || r.Edges[0].Kind != "strict_order" {
		t.Fatal(r)
	}
}
func TestCorpusReplayAndDossier(t *testing.T) {
	d := t.TempDir()
	har := `{"log":{"version":"1.2","entries":[]}}`
	if e := os.WriteFile(filepath.Join(d, "x.har"), []byte(har), 0600); e != nil {
		t.Fatal(e)
	}
	manifest := "schema_version: 1\nalgorithm_version: capture-analysis-v1\nfixtures:\n  - id: empty\n    path: x.har\n    format: har\n    expected:\n      flows: 0\n      exchanges: 0\n      observations: 0\n      parser_candidates: 0\n      sequence_state: incomplete\n"
	if e := os.WriteFile(filepath.Join(d, "corpus.yaml"), []byte(manifest), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := ReplayCorpus(d, DefaultLimits())
	if e != nil || r.Failed != 0 {
		t.Fatalf("%+v %v", r, e)
	}
	c, _ := Import(strings.NewReader(har), "x.har", "", DefaultLimits())
	out := filepath.Join(d, "dossier")
	if e = GenerateDossier(out, Analyze(c), false); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(out, "README.txt"))
	if e != nil || !bytes.Contains(raw, []byte("Live SCCM execution is blocked")) {
		t.Fatal(e)
	}
}
