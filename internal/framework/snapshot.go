package framework

import (
	"crypto/sha256"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

//go:embed data/misconfiguration-manager.json
var snapshotFS embed.FS

type SupportState string

const (
	Unsupported   SupportState = "unsupported"
	Planned       SupportState = "planned"
	Partial       SupportState = "partial"
	Supported     SupportState = "supported"
	Experimental  SupportState = "experimental"
	Blocked       SupportState = "blocked"
	NotApplicable SupportState = "not_applicable"
)

type Technique struct {
	ID           string   `json:"id"`
	Family       string   `json:"family"`
	Kind         string   `json:"kind"`
	Title        string   `json:"title"`
	Summary      string   `json:"summary,omitempty"`
	Requirements []string `json:"requirements,omitempty"`
	Impact       []string `json:"impact,omitempty"`
	MITRE        []string `json:"mitre,omitempty"`
	References   []string `json:"references,omitempty"`
	SourceFiles  []string `json:"source_files,omitempty"`
	Fingerprint  string   `json:"fingerprint"`
}

type MatrixMapping struct {
	AttackID  string `json:"attack_id"`
	DefenseID string `json:"defense_id"`
}

type CoverageRecord struct {
	TechniqueID       string       `json:"technique_id"`
	Documentation     SupportState `json:"documentation"`
	Prerequisites     SupportState `json:"prerequisites"`
	Discovery         SupportState `json:"discovery"`
	Assessment        SupportState `json:"assessment"`
	Validation        SupportState `json:"validation"`
	Execution         SupportState `json:"execution"`
	Cleanup           SupportState `json:"cleanup"`
	DefenseAssessment SupportState `json:"defense_assessment,omitempty"`
	LabValidation     SupportState `json:"lab_validation"`
	Reason            string       `json:"reason,omitempty"`
	Modules           []string     `json:"modules,omitempty"`
	Limitations       []string     `json:"limitations,omitempty"`
}

type FrameworkSnapshot struct {
	SchemaVersion     int              `json:"schema_version"`
	FrameworkID       string           `json:"framework_id"`
	UpstreamRevision  string           `json:"upstream_revision"`
	SnapshotDate      string           `json:"snapshot_date"`
	MatrixFingerprint string           `json:"matrix_fingerprint"`
	Techniques        []Technique      `json:"techniques"`
	MatrixMappings    []MatrixMapping  `json:"matrix_mappings,omitempty"`
	Coverage          []CoverageRecord `json:"coverage"`
	Warnings          []string         `json:"warnings,omitempty"`
}

// Provenance describes the independent implementation's relationship to the
// upstream framework without changing the embedded snapshot schema.
type Provenance struct {
	Name               string `json:"name"`
	UpstreamRepository string `json:"upstream_repository"`
	UpstreamRevision   string `json:"upstream_revision"`
	Implementation     string `json:"implementation"`
}

const misconfigurationManagerRepository = "https://github.com/subat0mik/Misconfiguration-Manager"

func SnapshotProvenance(s FrameworkSnapshot) Provenance {
	name := s.FrameworkID
	if s.FrameworkID == "misconfiguration-manager" {
		name = "Misconfiguration Manager"
	}
	return Provenance{Name: name, UpstreamRepository: misconfigurationManagerRepository, UpstreamRevision: s.UpstreamRevision, Implementation: "CinderPath independent adapter"}
}

func EmbeddedSnapshot() (FrameworkSnapshot, error) {
	b, err := snapshotFS.ReadFile("data/misconfiguration-manager.json")
	if err != nil {
		return FrameworkSnapshot{}, err
	}
	var s FrameworkSnapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	normalizeSnapshot(&s)
	if err := ValidateSnapshot(s); err != nil {
		return s, err
	}
	return s, nil
}

func ValidateSnapshot(s FrameworkSnapshot) error {
	if s.SchemaVersion < 1 || s.FrameworkID == "" {
		return errors.New("invalid framework snapshot header")
	}
	ids := make(map[string]Technique, len(s.Techniques))
	for _, t := range s.Techniques {
		if t.ID == "" || t.Family == "" || t.Kind == "" {
			return fmt.Errorf("incomplete technique %q", t.ID)
		}
		if _, ok := ids[t.ID]; ok {
			return fmt.Errorf("duplicate technique %s", t.ID)
		}
		if !validFamily(t.Family) {
			return fmt.Errorf("unknown family %s", t.Family)
		}
		if t.Kind != "attack" && t.Kind != "defense" {
			return fmt.Errorf("invalid technique kind %s", t.Kind)
		}
		ids[t.ID] = t
	}
	seen := map[string]bool{}
	for _, m := range s.MatrixMappings {
		if ids[m.AttackID].Kind != "attack" {
			return fmt.Errorf("unknown attack mapping %s", m.AttackID)
		}
		if ids[m.DefenseID].Kind != "defense" {
			return fmt.Errorf("unknown defense mapping %s", m.DefenseID)
		}
		k := m.AttackID + "\x00" + m.DefenseID
		if seen[k] {
			return fmt.Errorf("duplicate matrix mapping %s/%s", m.AttackID, m.DefenseID)
		}
		seen[k] = true
	}
	for _, c := range s.Coverage {
		if _, ok := ids[c.TechniqueID]; !ok {
			return fmt.Errorf("coverage references unknown technique %s", c.TechniqueID)
		}
		for _, x := range []SupportState{c.Documentation, c.Prerequisites, c.Discovery, c.Assessment, c.Validation, c.Execution, c.Cleanup, c.DefenseAssessment, c.LabValidation} {
			if !validState(x) {
				return fmt.Errorf("invalid support state %q", x)
			}
		}
	}
	return nil
}

func validState(s SupportState) bool {
	switch s {
	case Unsupported, Planned, Partial, Supported, Experimental, Blocked, NotApplicable:
		return true
	}
	return false
}
func validFamily(f string) bool {
	switch f {
	case "CRED", "ELEVATE", "EXEC", "RECON", "TAKEOVER", "COERCE", "CANARY", "DETECT", "PREVENT":
		return true
	}
	return false
}

func SnapshotFingerprint(s FrameworkSnapshot) string {
	normalizeSnapshot(&s)
	s.MatrixFingerprint = ""
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type ImportOptions struct{ Source, Revision, SnapshotDate string }

func LoadSnapshot(path string) (FrameworkSnapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return FrameworkSnapshot{}, err
	}
	var s FrameworkSnapshot
	if err = json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	normalizeSnapshot(&s)
	return s, ValidateSnapshot(s)
}
func SaveSnapshot(path string, s FrameworkSnapshot) error {
	normalizeSnapshot(&s)
	if err := ValidateSnapshot(s); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func normalizeSnapshot(s *FrameworkSnapshot) {
	for i := range s.Techniques {
		if s.Techniques[i].Fingerprint == "" {
			s.Techniques[i].Fingerprint = techniqueFingerprint(s.Techniques[i])
		}
	}
	if s.MatrixFingerprint == "" {
		b, _ := json.Marshal(s.MatrixMappings)
		h := sha256.Sum256(b)
		s.MatrixFingerprint = hex.EncodeToString(h[:])
	}
}

func Import(opts ImportOptions) (FrameworkSnapshot, error) {
	if opts.Source == "" {
		return FrameworkSnapshot{}, errors.New("source is required")
	}
	if opts.SnapshotDate == "" {
		opts.SnapshotDate = time.Now().UTC().Format("2006-01-02")
	}
	var techniques []Technique
	var parseWarnings []string
	err := filepath.WalkDir(opts.Source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".md") || !strings.HasSuffix(strings.ToLower(filepath.Base(path)), "_description.md") {
			return nil
		}
		rel, _ := filepath.Rel(opts.Source, path)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 4 || (parts[0] != "attack-techniques" && parts[0] != "defense-techniques") {
			return nil
		}
		t, ok, e := parseTechnique(path)
		if e != nil {
			return e
		}
		if ok {
			t.SourceFiles = []string{filepath.ToSlash(rel)}
			contents, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			parseWarnings = append(parseWarnings, unknownSections(string(contents), filepath.ToSlash(rel))...)
			techniques = append(techniques, t)
		}
		return nil
	})
	if err != nil {
		return FrameworkSnapshot{}, err
	}
	if len(techniques) == 0 {
		return FrameworkSnapshot{}, errors.New("no technique markdown files found")
	}
	sort.Slice(techniques, func(i, j int) bool { return techniques[i].ID < techniques[j].ID })
	seen := map[string]bool{}
	for _, t := range techniques {
		if seen[t.ID] {
			return FrameworkSnapshot{}, fmt.Errorf("duplicate technique %s", t.ID)
		}
		seen[t.ID] = true
	}
	mappings, matrixFP, warnings := parseMatrix(opts.Source, seen)
	warnings = append(parseWarnings, warnings...)
	for _, warning := range warnings {
		if strings.HasPrefix(warning, "unknown matrix reference") {
			return FrameworkSnapshot{}, errors.New(warning)
		}
	}
	s := FrameworkSnapshot{SchemaVersion: 1, FrameworkID: "misconfiguration-manager", UpstreamRevision: opts.Revision, SnapshotDate: opts.SnapshotDate, Techniques: techniques, MatrixMappings: mappings, Warnings: warnings}
	s.MatrixFingerprint = matrixFP
	for i := range techniques {
		techniques[i].Fingerprint = techniqueFingerprint(techniques[i])
	}
	s.Techniques = techniques
	for _, t := range techniques {
		s.Coverage = append(s.Coverage, defaultCoverage(t.ID))
	}
	if err := ValidateSnapshot(s); err != nil {
		return FrameworkSnapshot{}, err
	}
	return s, nil
}

var idRE = regexp.MustCompile(`(?i)\b((?:CRED|ELEVATE|EXEC|RECON|TAKEOVER|COERCE|CANARY|DETECT|PREVENT)[-_][0-9]+)\b`)

func parseTechnique(path string) (Technique, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Technique{}, false, err
	}
	text := string(b)
	parentID := filepath.Base(filepath.Dir(path))
	m := idRE.FindStringSubmatch(parentID)
	if m == nil {
		m = idRE.FindStringSubmatch(filepath.Base(path) + "\n" + text)
	}
	if m == nil {
		return Technique{}, false, nil
	}
	id := strings.ToUpper(strings.ReplaceAll(m[1], "_", "-"))
	parts := strings.Split(id, "-")
	family := parts[0]
	kind := "attack"
	if map[string]bool{"CANARY": true, "DETECT": true, "PREVENT": true}[family] {
		kind = "defense"
	}
	title := sectionFirst(text, "Description")
	if title == "" {
		title = id
	}
	summary := sectionText(text, "Summary")
	if summary == "" {
		summary = firstParagraph(text)
	}
	return Technique{ID: id, Family: family, Kind: kind, Title: title, Summary: summary, Requirements: sectionBullets(text, "Requirements"), Impact: sectionBullets(text, "Impact"), MITRE: sectionIDs(text, "MITRE ATT&CK TTPs"), References: sectionURLs(text, "References")}, true, nil
}

func sectionText(s, name string) string {
	lines := strings.Split(s, "\n")
	active := false
	var out []string
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "## ") {
			active = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(t, "## ")), name)
			continue
		}
		if active && t != "" && !strings.HasPrefix(t, "#") {
			out = append(out, t)
		}
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}
func sectionFirst(s, name string) string {
	t := sectionText(s, name)
	if i := strings.Index(t, "\n"); i >= 0 {
		return t[:i]
	}
	return t
}
func sectionBullets(s, name string) []string {
	t := sectionText(s, name)
	var out []string
	for _, line := range strings.Split(t, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "-"))
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}
func sectionIDs(s, name string) []string {
	t := sectionText(s, name)
	ms := regexp.MustCompile(`\bT[0-9]{4}(?:\.[0-9]{3})?\b`).FindAllString(t, -1)
	return uniqueSorted(ms)
}
func sectionURLs(s, name string) []string {
	t := sectionText(s, name)
	ms := regexp.MustCompile(`https?://[^)\s]+`).FindAllString(t, -1)
	return uniqueSorted(ms)
}
func uniqueSorted(xs []string) []string {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	out := make([]string, 0, len(m))
	for x := range m {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}
func firstHeading(s string) string {
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") {
			return strings.TrimSpace(strings.TrimLeft(l, "#"))
		}
	}
	return ""
}
func firstParagraph(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			if len(out) > 0 {
				break
			}
			continue
		}
		if strings.HasPrefix(l, "#") || strings.HasPrefix(l, "-") || strings.HasPrefix(l, "|") {
			continue
		}
		out = append(out, l)
		if len(strings.Join(out, " ")) > 400 {
			break
		}
	}
	return strings.TrimSpace(strings.Join(out, " "))
}
func techniqueFingerprint(t Technique) string {
	t.Fingerprint = ""
	b, _ := json.Marshal(t)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func unknownSections(s, source string) []string {
	known := map[string]bool{"Description": true, "Summary": true, "MITRE ATT&CK TTPs": true, "Requirements": true, "Impact": true, "Defensive IDs": true, "Linked Defensive IDs": true, "Associated Offensive IDs": true, "References": true, "Examples": true, "Notes": true}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "## ") {
			name := strings.TrimSpace(strings.TrimPrefix(t, "## "))
			if !known[name] {
				out = append(out, fmt.Sprintf("unknown section %s in %s", name, source))
			}
		}
	}
	return out
}

func parseMatrix(root string, ids map[string]bool) ([]MatrixMapping, string, []string) {
	var out []MatrixMapping
	var warnings []string
	var file string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
		if e == nil && !d.IsDir() && strings.Contains(strings.ToLower(filepath.Base(p)), "matrix") && strings.EqualFold(filepath.Ext(p), ".csv") && file == "" {
			file = p
		}
		return nil
	})
	if file == "" {
		return out, "", []string{"attack-defense matrix CSV not found"}
	}
	f, e := os.Open(file)
	if e != nil {
		return out, "", []string{e.Error()}
	}
	defer f.Close()
	rows, e := csv.NewReader(f).ReadAll()
	if e != nil {
		return out, "", []string{e.Error()}
	}
	raw, _ := os.ReadFile(file)
	h := sha256.Sum256(raw)
	for i, row := range rows {
		if i == 0 {
			continue
		}
		for j, v := range row {
			a := strings.TrimSpace(v)
			if a == "" {
				continue
			}
			if j == 0 {
				continue
			}
			left, top := normalizeID(strings.TrimSpace(row[0])), normalizeID(strings.TrimSpace(rows[0][j]))
			attack, defense := left, top
			if !isAttackID(left) && isAttackID(top) {
				attack, defense = top, left
			}
			if !ids[attack] {
				warnings = append(warnings, fmt.Sprintf("unknown matrix reference %s", attack))
				continue
			}
			if !ids[defense] {
				warnings = append(warnings, fmt.Sprintf("unknown matrix reference %s", defense))
				continue
			}
			if ids[attack] && ids[defense] {
				out = append(out, MatrixMapping{AttackID: attack, DefenseID: defense})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AttackID == out[j].AttackID {
			return out[i].DefenseID < out[j].DefenseID
		}
		return out[i].AttackID < out[j].AttackID
	})
	return out, hex.EncodeToString(h[:]), warnings
}

func isAttackID(id string) bool {
	for _, family := range []string{"CRED-", "ELEVATE-", "EXEC-", "RECON-", "TAKEOVER-", "COERCE-"} {
		if strings.HasPrefix(id, family) {
			return true
		}
	}
	return false
}

func normalizeID(id string) string {
	return strings.NewReplacer("‑", "-", "–", "-", "—", "-").Replace(strings.ToUpper(strings.TrimSpace(id)))
}
func defaultCoverage(id string) CoverageRecord {
	c := CoverageRecord{TechniqueID: id, Documentation: Supported, Prerequisites: Partial, Discovery: Unsupported, Assessment: Unsupported, Validation: Unsupported, Execution: Unsupported, Cleanup: NotApplicable, DefenseAssessment: Unsupported, LabValidation: Unsupported, Reason: "No CinderPath module mapping has been asserted for this imported technique."}
	switch id {
	case "CRED-1", "CRED-2":
		c.Discovery, c.Assessment, c.LabValidation = Partial, Partial, Partial
		c.Reason = "Existing SCCM capture, PXE posture, and targeted policy metadata support only bounded discovery and assessment; recovery and execution remain unsupported."
		c.Modules = []string{"capture", "pxe", "localartifact"}
		c.Limitations = []string{"No policy payload recovery", "No PXE/media retrieval", "No live client action"}
	case "RECON-1", "RECON-2", "RECON-3", "RECON-4":
		c.Prerequisites, c.Discovery, c.Assessment, c.LabValidation = Supported, Partial, Partial, Partial
		c.Reason = "Existing bounded SCCM discovery and offline evidence modules provide partial reconnaissance coverage."
		c.Modules = []string{"discovery", "capture", "report"}
	}
	return c
}
