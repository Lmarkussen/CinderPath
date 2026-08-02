package buildtool

import (
	"bytes"
	"encoding/json"
	"github.com/Lmarkussen/CinderPath/internal/cli"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/capture"
)

func runCLI(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	c := cli.New(&out, &errOut)
	c.SetArgs(args)
	e := c.Execute()
	return out.String(), errOut.String(), e
}

func TestCaptureCorrelationCLIOffline(t *testing.T) {
	d := t.TempDir()
	at := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	c := capture.NormalizedCapture{SchemaVersion: capture.SchemaVersion, AlgorithmVersion: capture.AlgorithmVersion, Source: capture.Source{ID: "capture_synthetic", Format: "normalized_json", Fingerprint: "synthetic"}, Interfaces: []capture.Interface{{ID: 0, LinkType: 1, Supported: true, TimestampResolution: 1_000_000}}, Packets: []capture.Packet{{ID: "packet_synthetic", Timestamp: at, CapturedLength: 64, OriginalLength: 64}}, Flows: []capture.Flow{{ID: "flow_synthetic", TLS: true, StartedAt: at.Add(time.Second), EndedAt: at.Add(2 * time.Second), DirectionConfidence: "medium", PacketIDs: []string{"packet_synthetic"}}}}
	b, _ := json.Marshal(c)
	capturePath := filepath.Join(d, "capture.json")
	if e := os.WriteFile(capturePath, b, 0600); e != nil {
		t.Fatal(e)
	}
	logs := filepath.Join(d, "logs")
	_ = os.Mkdir(logs, 0700)
	line := `<![LOG[Requesting machine policy assignments]LOG]!><time="10:00:00.000+000" date="07-01-2026" component="PolicyAgent" context="" type="1" thread="1" file="x">`
	if e := os.WriteFile(filepath.Join(logs, "synthetic.log"), []byte(line+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	trigger := filepath.Join(d, "trigger.json")
	tb, _ := json.Marshal(capture.Trigger{SchemaVersion: 1, Timestamp: at, Action: "machine_policy_cycle"})
	if e := os.WriteFile(trigger, tb, 0600); e != nil {
		t.Fatal(e)
	}
	out, stderr, e := runCLI(t, "--db", filepath.Join(d, "correlation.db"), "capture", "correlate", "--capture", capturePath, "--logs", logs, "--trigger", trigger, "--output", filepath.Join(d, "dossier"), "--format", "text")
	if e != nil {
		t.Fatalf("correlate: %v stderr=%s", e, stderr)
	}
	for _, want := range []string{"Offline SCCM capture correlation", "Candidate TLS flows: 1", "Live SCCM policy requests: 0", "timing alone does not prove"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
	if strings.Contains(out, "synthetic.invalid") {
		t.Fatal("endpoint leaked")
	}
	jsonOut, _, e := runCLI(t, "--db", filepath.Join(d, "correlation-json.db"), "capture", "correlate", "--capture", capturePath, "--logs", logs, "--trigger", trigger, "--output", filepath.Join(d, "dossier-json"), "--format", "json")
	if e != nil {
		t.Fatal(e)
	}
	var parsed any
	if e = json.Unmarshal([]byte(jsonOut), &parsed); e != nil {
		t.Fatal(e)
	}
	dbBytes, _ := os.ReadFile(filepath.Join(d, "correlation.db"))
	for _, forbidden := range []string{"Requesting machine policy assignments", "Authorization:", "Bearer ", "PRIVATE KEY"} {
		if bytes.Contains(dbBytes, []byte(forbidden)) {
			t.Fatalf("correlation persistence leak: %s", forbidden)
		}
	}
}
func TestCaptureCLIIntegrationOffline(t *testing.T) {
	d := t.TempDir()
	har := `{"log":{"version":"1.2","entries":[{"request":{"method":"GET","url":"http://synthetic.invalid/x?token=CLI_SECRET_SENTINEL","httpVersion":"HTTP/1.1","headers":[{"Name":"Authorization","Value":"Bearer CLI_SECRET_SENTINEL"}]},"response":{"status":200,"httpVersion":"HTTP/1.1"}}]}}`
	p := filepath.Join(d, "synthetic.har")
	if e := os.WriteFile(p, []byte(har), 0600); e != nil {
		t.Fatal(e)
	}
	db := filepath.Join(d, "capture.db")
	out, stderr, e := runCLI(t, "--db", db, "capture", "import", "--input", p)
	if e != nil {
		t.Fatalf("import: %v %s", e, stderr)
	}
	if strings.Contains(out, "CLI_SECRET_SENTINEL") {
		t.Fatal("stdout leak")
	}
	list, _, e := runCLI(t, "--db", db, "capture", "list")
	if e != nil || !strings.Contains(list, "capture_") {
		t.Fatalf("list %v %s", e, list)
	}
	id := strings.Fields(list)[0]
	shown, _, e := runCLI(t, "--db", db, "capture", "show", id)
	if e != nil {
		t.Fatal(e)
	}
	var v any
	if e = json.Unmarshal([]byte(shown), &v); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(shown, "CLI_SECRET_SENTINEL") {
		t.Fatal("JSON leak")
	}
	html := filepath.Join(d, "analysis.html")
	if _, _, e = runCLI(t, "analysis", "replay", "--input", p, "--output", html); e != nil {
		t.Fatal(e)
	}
	hb, _ := os.ReadFile(html)
	if bytes.Contains(hb, []byte("CLI_SECRET_SENTINEL")) {
		t.Fatal("HTML leak")
	}
	dossier := filepath.Join(d, "dossier")
	if _, _, e = runCLI(t, "analysis", "dossier", "--input", p, "--output", dossier); e != nil {
		t.Fatal(e)
	}
	if e = filepath.Walk(dossier, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if !info.IsDir() {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			if bytes.Contains(b, []byte("CLI_SECRET_SENTINEL")) {
				t.Fatalf("dossier leak in %s", filepath.Base(path))
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if _, _, e = runCLI(t, "capture", "import", "--unknown"); e == nil {
		t.Fatal("unknown flag accepted")
	}
	for _, args := range [][]string{{"capture", "--help"}, {"matrix", "--help"}, {"sequence", "--help"}, {"parser", "--help"}, {"analysis", "--help"}, {"research", "--help"}} {
		if _, _, e = runCLI(t, args...); e != nil {
			t.Fatalf("help %v: %v", args, e)
		}
	}
	raw, _ := os.ReadFile(db)
	if bytes.Contains(raw, []byte("CLI_SECRET_SENTINEL")) {
		t.Fatal("SQLite leak")
	}
}
