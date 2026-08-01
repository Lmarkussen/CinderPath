package capture

import (
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Corpus struct {
	SchemaVersion    int             `yaml:"schema_version"`
	ParserVersion    string          `yaml:"parser_version"`
	AlgorithmVersion string          `yaml:"algorithm_version"`
	Fixtures         []CorpusFixture `yaml:"fixtures"`
}
type CorpusFixture struct {
	ID       string         `yaml:"id"`
	Path     string         `yaml:"path"`
	Format   string         `yaml:"format"`
	Expected CorpusExpected `yaml:"expected"`
}
type CorpusExpected struct {
	CaptureID           string   `yaml:"capture_id"`
	SequenceState       string   `yaml:"sequence_state"`
	AnalysisFingerprint string   `yaml:"analysis_fingerprint"`
	Flows               int      `yaml:"flows"`
	Exchanges           int      `yaml:"exchanges"`
	Observations        int      `yaml:"observations"`
	ParserCandidates    int      `yaml:"parser_candidates"`
	Warnings            []string `yaml:"warnings"`
}
type CorpusFixtureResult struct {
	ID, State   string
	Differences []string
}
type CorpusResult struct {
	State, ParserVersion, AlgorithmVersion string
	Fixtures                               []CorpusFixtureResult
	Passed, Failed                         int
	Fingerprint                            string
	LiveRequests                           int
}

func ReplayCorpus(dir string, l Limits) (CorpusResult, error) {
	b, e := os.ReadFile(filepath.Join(dir, "corpus.yaml"))
	if e != nil {
		return CorpusResult{}, e
	}
	if int64(len(b)) > l.MaxCaptureBytes {
		return CorpusResult{}, errors.New("corpus manifest exceeds limit")
	}
	var m Corpus
	if e = yaml.Unmarshal(b, &m); e != nil {
		return CorpusResult{}, fmt.Errorf("parse corpus manifest: %w", e)
	}
	r := CorpusResult{State: "passed", ParserVersion: m.ParserVersion, AlgorithmVersion: AlgorithmVersion}
	if m.SchemaVersion != 1 {
		return r, errors.New("unsupported corpus schema")
	}
	if m.AlgorithmVersion != "" && m.AlgorithmVersion != AlgorithmVersion {
		r.State = "algorithm_version_mismatch"
	}
	for _, f := range m.Fixtures {
		p := filepath.Clean(filepath.Join(dir, f.Path))
		rel, e := filepath.Rel(dir, p)
		if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(f.Path) {
			return r, errors.New("corpus fixture path escapes directory")
		}
		fh, e := os.Open(p)
		if e != nil {
			return r, e
		}
		c, e := Import(fh, p, f.Format, l)
		_ = fh.Close()
		fr := CorpusFixtureResult{ID: f.ID, State: "passed"}
		if e != nil {
			fr.State = "malformed_fixture"
			fr.Differences = append(fr.Differences, "fixture parsing failed")
		} else {
			a := Analyze(c)
			cmp := func(n, w int, label string) {
				if w >= 0 && n != w {
					fr.Differences = append(fr.Differences, fmt.Sprintf("%s: got %d want %d", label, n, w))
				}
			}
			cmp(len(c.Flows), f.Expected.Flows, "flows")
			cmp(len(c.Exchanges), f.Expected.Exchanges, "exchanges")
			cmp(len(c.Observations), f.Expected.Observations, "observations")
			cmp(len(a.Candidates), f.Expected.ParserCandidates, "parser candidates")
			if f.Expected.SequenceState != "" && c.Sequence.Classification != f.Expected.SequenceState {
				fr.Differences = append(fr.Differences, "sequence state mismatch")
			}
			if f.Expected.AnalysisFingerprint != "" && a.Fingerprint != f.Expected.AnalysisFingerprint {
				fr.Differences = append(fr.Differences, "analysis fingerprint mismatch")
			}
			if len(fr.Differences) > 0 {
				fr.State = "analysis_mismatch"
			}
		}
		if fr.State == "passed" {
			r.Passed++
		} else {
			r.Failed++
			r.State = "failed"
		}
		r.Fixtures = append(r.Fixtures, fr)
	}
	sort.Slice(r.Fixtures, func(i, j int) bool { return r.Fixtures[i].ID < r.Fixtures[j].ID })
	raw, _ := json.Marshal(r)
	r.Fingerprint = fingerprint(raw)
	return r, nil
}
func ValidateCandidate(p ParserCandidate, positive, negative []NormalizedCapture, corpus bool) ParserCandidate {
	p.PositiveExamples = nil
	p.NegativeExamples = nil
	p.FailureExamples = nil
	for _, c := range positive {
		if candidateMatches(p, c) {
			p.PositiveExamples = append(p.PositiveExamples, c.Source.ID)
		} else {
			p.FailureExamples = append(p.FailureExamples, c.Source.ID)
		}
	}
	for _, c := range negative {
		if candidateMatches(p, c) {
			p.FailureExamples = append(p.FailureExamples, c.Source.ID)
		} else {
			p.NegativeExamples = append(p.NegativeExamples, c.Source.ID)
		}
	}
	switch {
	case len(p.FailureExamples) > 0:
		p.State = "conflicting"
	case len(p.PositiveExamples) > 0 && len(p.NegativeExamples) > 0 && corpus:
		p.State = "corpus_validated"
	case len(p.PositiveExamples) > 0 && len(p.NegativeExamples) > 0:
		p.State = "fixture_validated"
	default:
		p.State = "candidate_parser"
	}
	p.LiveExecution = false
	return p
}
func candidateMatches(p ParserCandidate, c NormalizedCapture) bool {
	for _, e := range c.Exchanges {
		shape := exchangeShape(e)
		for _, x := range p.Constraints {
			if shape == x {
				return true
			}
		}
	}
	return false
}
