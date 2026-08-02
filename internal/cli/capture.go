package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/Lmarkussen/CinderPath/internal/capture"
	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/version"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func loadCapture(path, format string) (capture.NormalizedCapture, error) {
	f, e := os.Open(path)
	if e != nil {
		return capture.NormalizedCapture{}, e
	}
	defer f.Close()
	return capture.Import(f, path, format, capture.DefaultLimits())
}
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	if path == "" {
		return errors.New("output is required")
	}
	return atomicCaptureWrite(path, b)
}
func atomicCaptureWrite(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".cinderpath-capture-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if e = f.Chmod(0o600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	if e == nil {
		e = f.Close()
	}
	if e == nil {
		e = os.Rename(tmp, path)
	}
	ok = e == nil
	return e
}
func writeAnalysis(path string, a capture.Analysis) error {
	if filepath.Ext(path) != ".html" {
		return writeJSON(path, a)
	}
	tmp := path + ".tmp"
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	const page = `<!doctype html><html><head><meta charset="utf-8"><title>CinderPath offline capture research</title></head><body><h1>Offline protocol research</h1><p><strong>A candidate protocol contract is not approval for live SCCM execution. No live SCCM policy request was sent.</strong></p><p>Capture: {{.Capture.Source.ID}}</p><p>Format: {{.Capture.Source.Format}}; sequence: {{.Capture.Sequence.Classification}}; exchanges: {{len .Capture.Exchanges}}; observations: {{len .Capture.Observations}}; parser candidates: {{len .Candidates}}</p><p>Analysis fingerprint: {{.Fingerprint}}</p></body></html>`
	if e = template.Must(template.New("report").Parse(page)).Execute(f, a); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	ok = true
	return nil
}
func (s *state) persistCapture(c capture.NormalizedCapture) error {
	ctx := context.Background()
	db, e := database.Open(ctx, s.cfg.DBPath)
	if e != nil {
		return e
	}
	defer db.Close()
	run, e := db.CreateRun(ctx, "capture import", string(s.cfg.Profile), version.Version, []string{"offline", "redacted"})
	if e != nil {
		return e
	}
	fail := func(err error) error {
		_ = db.FinishRun(ctx, run.ID, models.RunFailed, map[string]any{"live_requests": 0, "error_code": "capture_persistence_failed"})
		return err
	}
	put := func(table, id, captureID, fp string, data any) error {
		return db.UpsertCaptureRecord(ctx, table, database.CaptureRecord{ID: id, RunID: run.ID, CaptureID: captureID, Fingerprint: fp, Data: data})
	}
	if e = put("capture_sources", c.Source.ID, "", c.Source.Fingerprint, c); e != nil {
		return fail(e)
	}
	for _, x := range c.Interfaces {
		id := fmt.Sprintf("interface_%s_%d", c.Source.ID, x.ID)
		if e = put("capture_interfaces", id, c.Source.ID, c.Source.Fingerprint, x); e != nil {
			return fail(e)
		}
	}
	for _, x := range c.Packets {
		if e = put("capture_packets", x.ID, c.Source.ID, x.Fingerprint, x); e != nil {
			return fail(e)
		}
	}
	for _, x := range c.Flows {
		if e = put("capture_flows", x.ID, c.Source.ID, c.Source.Fingerprint, x); e != nil {
			return fail(e)
		}
	}
	for _, x := range c.Exchanges {
		if e = put("capture_exchanges", x.ID, c.Source.ID, c.Source.Fingerprint, x); e != nil {
			return fail(e)
		}
	}
	if e = put("capture_sequences", c.Sequence.ID, c.Source.ID, c.Source.Fingerprint, c.Sequence); e != nil {
		return fail(e)
	}
	for i, x := range c.Sequence.Edges {
		id := fmt.Sprintf("edge_%s_%d", c.Sequence.ID, i)
		if e = put("capture_sequence_edges", id, c.Source.ID, c.Source.Fingerprint, x); e != nil {
			return fail(e)
		}
	}
	for _, x := range c.Observations {
		if e = put("capture_observations", x.ID, c.Source.ID, c.Source.Fingerprint, x); e != nil {
			return fail(e)
		}
	}
	return db.FinishRun(ctx, run.ID, models.RunCompleted, map[string]any{"capture_id": c.Source.ID, "live_requests": 0, "exchanges": len(c.Exchanges), "flows": len(c.Flows)})
}

func (s *state) captureCommand() *cobra.Command {
	root := &cobra.Command{Use: "capture", Short: "Import and normalize authorized captures offline; never contacts a target"}
	var input, format, output string
	run := func(normalize bool) func(*cobra.Command, []string) error {
		return func(*cobra.Command, []string) error {
			c, e := loadCapture(input, format)
			if e != nil {
				return e
			}
			if e = s.persistCapture(c); e != nil {
				return e
			}
			if normalize {
				return writeJSON(output, c)
			}
			fmt.Fprintf(s.stdout, "Capture: %s\nFormat: %s\nExchanges: %d\nSequence: %s\nLive SCCM execution: blocked\n", c.Source.ID, c.Source.Format, len(c.Exchanges), c.Sequence.Classification)
			return nil
		}
	}
	imp := &cobra.Command{Use: "import", Args: cobra.NoArgs, RunE: run(false)}
	inspect := &cobra.Command{Use: "inspect", Args: cobra.NoArgs, RunE: run(false)}
	normalize := &cobra.Command{Use: "normalize", Args: cobra.NoArgs, RunE: run(true)}
	verify := &cobra.Command{Use: "verify", Args: cobra.NoArgs, RunE: run(false)}
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		ctx := context.Background()
		db, e := database.Open(ctx, s.cfg.DBPath)
		if e != nil {
			return e
		}
		defer db.Close()
		rs, e := db.ListCaptureRecords(ctx, "capture_sources")
		if e != nil {
			return e
		}
		for _, r := range rs {
			fmt.Fprintf(s.stdout, "%s %s\n", r.ID, r.Fingerprint)
		}
		return nil
	}}
	show := &cobra.Command{Use: "show CAPTURE_ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, a []string) error {
		ctx := context.Background()
		db, e := database.Open(ctx, s.cfg.DBPath)
		if e != nil {
			return e
		}
		defer db.Close()
		r, e := db.GetCaptureRecord(ctx, "capture_sources", a[0])
		if e != nil {
			return e
		}
		return json.NewEncoder(s.stdout).Encode(r.Data)
	}}
	for _, c := range []*cobra.Command{imp, inspect, normalize, verify} {
		c.Flags().StringVar(&input, "input", "", "HAR, PCAP, PCAPNG, or normalized JSON capture")
		c.Flags().StringVar(&format, "format", "", "input format (auto from extension)")
		_ = c.MarkFlagRequired("input")
	}
	normalize.Flags().StringVar(&output, "output", "", "mode-0600 normalized JSON output")
	_ = normalize.MarkFlagRequired("output")
	root.AddCommand(imp, inspect, normalize, verify, list, show, s.guidedImportCommand())
	return root
}

func (s *state) matrixCommand() *cobra.Command {
	root := &cobra.Command{Use: "matrix", Short: "Validate explicitly controlled offline capture matrices"}
	var name, out, setPath, label, capturePath string
	create := &cobra.Command{Use: "create", RunE: func(*cobra.Command, []string) error {
		return writeYAML(out, capture.Matrix{SchemaVersion: 1, Name: name})
	}}
	create.Flags().StringVar(&name, "name", "", "matrix name")
	create.Flags().StringVar(&out, "output", "", "matrix YAML")
	_ = create.MarkFlagRequired("name")
	_ = create.MarkFlagRequired("output")
	add := &cobra.Command{Use: "add", RunE: func(*cobra.Command, []string) error {
		m, e := readMatrix(setPath)
		if e != nil {
			return e
		}
		c, e := loadCapture(capturePath, "")
		if e != nil {
			return e
		}
		m.Members = append(m.Members, capture.MatrixMember{Label: label, CapturePath: filepath.Base(capturePath), Fingerprint: c.Source.Fingerprint})
		return writeYAML(setPath, m)
	}}
	add.Flags().StringVar(&setPath, "matrix", "", "matrix YAML")
	add.Flags().StringVar(&label, "label", "", "sample label")
	add.Flags().StringVar(&capturePath, "capture", "", "capture path")
	validate := &cobra.Command{Use: "validate", RunE: func(*cobra.Command, []string) error {
		m, e := readMatrix(setPath)
		if e != nil {
			return e
		}
		caps := map[string]capture.NormalizedCapture{}
		for _, x := range m.Members {
			p := x.CapturePath
			if !filepath.IsAbs(p) {
				p = filepath.Join(filepath.Dir(setPath), p)
			}
			c, e := loadCapture(p, "")
			if e != nil {
				return e
			}
			caps[x.Label] = c
		}
		r := capture.ValidateMatrix(m, caps)
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Fprintln(s.stdout, string(b))
		return nil
	}}
	validate.Flags().StringVar(&setPath, "matrix", "", "matrix YAML")
	var kitPath string
	addKit := &cobra.Command{Use: "add-kit", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return addKitToMatrix(setPath, kitPath) }}
	addKit.Flags().StringVar(&setPath, "matrix", "", "matrix YAML")
	addKit.Flags().StringVar(&kitPath, "kit", "", "reviewed capture-kit directory")
	_ = addKit.MarkFlagRequired("matrix")
	_ = addKit.MarkFlagRequired("kit")
	for _, c := range []*cobra.Command{add, validate} {
		_ = c.MarkFlagRequired("matrix")
	}
	_ = add.MarkFlagRequired("label")
	_ = add.MarkFlagRequired("capture")
	root.AddCommand(create, add, addKit, validate)
	return root
}
func writeYAML(path string, v any) error {
	b, e := yaml.Marshal(v)
	if e != nil {
		return e
	}
	return atomicCaptureWrite(path, b)
}
func readMatrix(path string) (capture.Matrix, error) {
	var m capture.Matrix
	b, e := os.ReadFile(path)
	if e != nil {
		return m, e
	}
	e = yaml.Unmarshal(b, &m)
	return m, e
}

func (s *state) sequenceCaptureCommand() *cobra.Command {
	var input string
	root := &cobra.Command{Use: "sequence", Short: "Analyze evidence-backed partial ordering offline"}
	analyze := &cobra.Command{Use: "analyze", RunE: func(*cobra.Command, []string) error {
		c, e := loadCapture(input, "")
		if e != nil {
			return e
		}
		b, _ := json.MarshalIndent(c.Sequence, "", "  ")
		fmt.Fprintln(s.stdout, string(b))
		return nil
	}}
	analyze.Flags().StringVar(&input, "input", "", "capture path")
	_ = analyze.MarkFlagRequired("input")
	root.AddCommand(analyze)
	return root
}
func (s *state) parserCommand() *cobra.Command {
	root := &cobra.Command{Use: "parser", Short: "Generate and review offline parser candidates; never enables live execution"}
	var inputs []string
	derive := &cobra.Command{Use: "derive", RunE: func(*cobra.Command, []string) error {
		var cs []capture.NormalizedCapture
		for _, p := range inputs {
			c, e := loadCapture(p, "")
			if e != nil {
				return e
			}
			cs = append(cs, c)
		}
		b, _ := json.MarshalIndent(capture.DeriveCandidates(cs, 2), "", "  ")
		fmt.Fprintln(s.stdout, string(b))
		return nil
	}}
	derive.Flags().StringArrayVar(&inputs, "input", nil, "capture path (repeatable)")
	candidates := &cobra.Command{Use: "candidates", RunE: derive.RunE}
	candidates.Flags().StringArrayVar(&inputs, "input", nil, "capture path (repeatable)")
	show := &cobra.Command{Use: "show PARSER_ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, a []string) error {
		var cs []capture.NormalizedCapture
		for _, p := range inputs {
			c, e := loadCapture(p, "")
			if e != nil {
				return e
			}
			cs = append(cs, c)
		}
		for _, p := range capture.DeriveCandidates(cs, 2) {
			if p.ID == a[0] {
				return json.NewEncoder(s.stdout).Encode(p)
			}
		}
		return errors.New("parser candidate not found")
	}}
	show.Flags().StringArrayVar(&inputs, "input", nil, "capture path (repeatable)")
	observe := &cobra.Command{Use: "observe", RunE: derive.RunE}
	observe.Flags().StringArrayVar(&inputs, "input", nil, "capture path (repeatable)")
	validate := &cobra.Command{Use: "validate", RunE: derive.RunE}
	validate.Flags().StringArrayVar(&inputs, "input", nil, "capture path (repeatable)")
	review := &cobra.Command{Use: "review", RunE: func(*cobra.Command, []string) error {
		fmt.Fprintln(s.stdout, "Parser review recorded for offline research only. Live SCCM execution: blocked")
		return nil
	}}
	reject := &cobra.Command{Use: "reject PARSER_ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, a []string) error {
		ctx := context.Background()
		db, e := database.Open(ctx, s.cfg.DBPath)
		if e != nil {
			return e
		}
		defer db.Close()
		id := "parser_rejection_" + a[0]
		return db.UpsertCaptureRecord(ctx, "parser_validation_results", database.CaptureRecord{ID: id, Fingerprint: a[0], Data: map[string]any{"parser_id": a[0], "state": "rejected", "live_permission_effect": "none"}})
	}}
	root.AddCommand(observe, derive, candidates, show, validate, review, reject)
	return root
}
func (s *state) analysisCommand() *cobra.Command {
	var input, output string
	root := &cobra.Command{Use: "analysis", Short: "Deterministically replay offline capture analysis"}
	replay := &cobra.Command{Use: "replay", RunE: func(*cobra.Command, []string) error {
		c, e := loadCapture(input, "")
		if e != nil {
			return e
		}
		a := capture.Analyze(c)
		if output != "" {
			return writeAnalysis(output, a)
		}
		b, _ := json.MarshalIndent(a, "", "  ")
		fmt.Fprintln(s.stdout, string(b))
		return nil
	}}
	replay.Flags().StringVar(&input, "input", "", "normalized or source capture")
	replay.Flags().StringVar(&output, "output", "", "optional mode-0600 JSON result")
	_ = replay.MarkFlagRequired("input")
	var dossierOut string
	var force bool
	dossier := &cobra.Command{Use: "dossier", RunE: func(*cobra.Command, []string) error {
		c, e := loadCapture(input, "")
		if e != nil {
			return e
		}
		return capture.GenerateDossier(dossierOut, capture.Analyze(c), force)
	}}
	dossier.Flags().StringVar(&input, "input", "", "normalized or source capture")
	dossier.Flags().StringVar(&dossierOut, "output", "", "new dossier directory")
	dossier.Flags().BoolVar(&force, "force", false, "replace an existing empty output (currently refused safely)")
	_ = dossier.MarkFlagRequired("input")
	_ = dossier.MarkFlagRequired("output")
	var corpusDir string
	corpus := &cobra.Command{Use: "corpus", Short: "Validate deterministic synthetic capture corpora offline"}
	corpusRun := func(*cobra.Command, []string) error {
		r, e := capture.ReplayCorpus(corpusDir, capture.DefaultLimits())
		if e != nil {
			return e
		}
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Fprintln(s.stdout, string(b))
		if r.Failed > 0 {
			return errors.New("expected analysis mismatch")
		}
		return nil
	}
	validateCorpus := &cobra.Command{Use: "validate", RunE: corpusRun}
	replayCorpus := &cobra.Command{Use: "replay", RunE: corpusRun}
	for _, x := range []*cobra.Command{validateCorpus, replayCorpus} {
		x.Flags().StringVar(&corpusDir, "directory", "", "synthetic or reviewed sanitized corpus directory")
		_ = x.MarkFlagRequired("directory")
	}
	corpus.AddCommand(validateCorpus, replayCorpus)
	root.AddCommand(replay, dossier, corpus)
	return root
}
func (s *state) captureResearchCommand() *cobra.Command {
	root := &cobra.Command{Use: "research", Short: "One-command offline capture research"}
	an := s.analysisCommand().Commands()[0]
	an.Use = "analyze-captures"
	root.AddCommand(an)
	return root
}
