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
	return db.UpsertCaptureRecord(ctx, "capture_sources", database.CaptureRecord{ID: c.Source.ID, Fingerprint: c.Source.Fingerprint, Data: c})
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
	for _, c := range []*cobra.Command{imp, inspect, normalize, verify} {
		c.Flags().StringVar(&input, "input", "", "HAR, PCAP, PCAPNG, or normalized JSON capture")
		c.Flags().StringVar(&format, "format", "", "input format (auto from extension)")
		_ = c.MarkFlagRequired("input")
	}
	normalize.Flags().StringVar(&output, "output", "", "mode-0600 normalized JSON output")
	_ = normalize.MarkFlagRequired("output")
	root.AddCommand(imp, inspect, normalize, verify)
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
	for _, c := range []*cobra.Command{add, validate} {
		_ = c.MarkFlagRequired("matrix")
	}
	_ = add.MarkFlagRequired("label")
	_ = add.MarkFlagRequired("capture")
	root.AddCommand(create, add, validate)
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
	observe := &cobra.Command{Use: "observe", RunE: derive.RunE}
	observe.Flags().StringArrayVar(&inputs, "input", nil, "capture path (repeatable)")
	validate := &cobra.Command{Use: "validate", RunE: derive.RunE}
	validate.Flags().StringArrayVar(&inputs, "input", nil, "capture path (repeatable)")
	review := &cobra.Command{Use: "review", RunE: func(*cobra.Command, []string) error {
		fmt.Fprintln(s.stdout, "Parser review recorded for offline research only. Live SCCM execution: blocked")
		return nil
	}}
	root.AddCommand(observe, derive, validate, review)
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
	root.AddCommand(replay, dossier)
	return root
}
func (s *state) captureResearchCommand() *cobra.Command {
	root := &cobra.Command{Use: "research", Short: "One-command offline capture research"}
	an := s.analysisCommand().Commands()[0]
	an.Use = "analyze-captures"
	root.AddCommand(an)
	return root
}
