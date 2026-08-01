package policy

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type BinaryMode string

const (
	BinaryMetadataOnly    BinaryMode = "metadata_only"
	BinaryTextRegions     BinaryMode = "text_regions"
	BinaryStructuredKnown BinaryMode = "structured_known"
)
const SanitizerVersion = "fixture-sanitizer-v2"

type Replacement struct {
	Original, Replacement, Category string `yaml:",omitempty"`
}
type ModifiedRegion struct {
	File                   string `json:"file" yaml:"file"`
	Encoding               string `json:"encoding" yaml:"encoding"`
	Offset                 int    `json:"offset" yaml:"offset"`
	Length                 int    `json:"length" yaml:"length"`
	ReplacementCategory    string `json:"replacement_category" yaml:"replacement_category"`
	ReplacementFingerprint string `json:"replacement_fingerprint" yaml:"replacement_fingerprint"`
}
type BodyReview struct {
	File              string    `json:"file" yaml:"file"`
	Approved          bool      `json:"approved" yaml:"approved"`
	ReviewerReference string    `json:"reviewer_reference" yaml:"reviewer_reference"`
	ReviewTimestamp   time.Time `json:"review_timestamp" yaml:"review_timestamp"`
}
type SanitizationManifest struct {
	ManifestID             string           `json:"manifest_id" yaml:"manifest_id"`
	InputFingerprint       string           `json:"input_fingerprint" yaml:"input_fingerprint"`
	OutputFingerprint      string           `json:"output_fingerprint" yaml:"output_fingerprint"`
	SanitizerVersion       string           `json:"sanitizer_version" yaml:"sanitizer_version"`
	BinaryMode             BinaryMode       `json:"binary_mode" yaml:"binary_mode"`
	FilesProcessed         int              `json:"files_processed" yaml:"files_processed"`
	BodiesSanitized        int              `json:"bodies_sanitized" yaml:"bodies_sanitized"`
	BodiesUntouched        int              `json:"bodies_untouched" yaml:"bodies_untouched"`
	RegionsInspected       int              `json:"regions_inspected" yaml:"regions_inspected"`
	RegionsModified        int              `json:"regions_modified" yaml:"regions_modified"`
	ModifiedRegions        []ModifiedRegion `json:"modified_regions" yaml:"modified_regions"`
	ManualReviewRequired   bool             `json:"manual_review_required" yaml:"manual_review_required"`
	ManualReviewCompleted  bool             `json:"manual_review_completed" yaml:"manual_review_completed"`
	Reviews                []BodyReview     `json:"reviews,omitempty" yaml:"reviews,omitempty"`
	UnclassifiedIndicators []string         `json:"unclassified_indicators" yaml:"unclassified_indicators"`
	Warnings               []string         `json:"warnings" yaml:"warnings"`
}
type SanitizeOptions struct {
	Input, Output string
	BinaryMode    BinaryMode
	Replacements  []Replacement
}

func SanitizeDirectory(o SanitizeOptions) (SanitizationManifest, error) {
	if o.BinaryMode == "" {
		o.BinaryMode = BinaryMetadataOnly
	}
	if o.BinaryMode != BinaryMetadataOnly && o.BinaryMode != BinaryTextRegions && o.BinaryMode != BinaryStructuredKnown {
		return SanitizationManifest{}, errors.New("binary mode must be metadata_only, text_regions, or structured_known")
	}
	if filepath.Clean(o.Input) == filepath.Clean(o.Output) {
		return SanitizationManifest{}, errors.New("sanitization output must differ from source")
	}
	if _, e := os.Lstat(o.Output); e == nil {
		return SanitizationManifest{}, errors.New("sanitization output already exists")
	}
	mb, e := safeRead(o.Input, "metadata.yaml", true)
	if e != nil {
		return SanitizationManifest{}, e
	}
	var meta Metadata
	if e = yaml.Unmarshal(mb, &meta); e != nil {
		return SanitizationManifest{}, e
	}
	req, e := safeRead(o.Input, "request.body", true)
	if e != nil {
		return SanitizationManifest{}, e
	}
	resp, e := safeRead(o.Input, "response.body", true)
	if e != nil {
		return SanitizationManifest{}, e
	}
	source := sha256.Sum256(bytes.Join([][]byte{mb, req, resp}, nil))
	man := SanitizationManifest{InputFingerprint: "sha256:" + hex.EncodeToString(source[:]), SanitizerVersion: SanitizerVersion, BinaryMode: o.BinaryMode, FilesProcessed: 5, RegionsInspected: 2}
	cleanHeaders := func(name string) ([]byte, error) {
		b, e := safeRead(o.Input, name, false)
		if e != nil {
			return nil, e
		}
		var out strings.Builder
		s := bufio.NewScanner(bytes.NewReader(b))
		for s.Scan() {
			line := s.Text()
			i := strings.IndexByte(line, ':')
			if i < 1 {
				return nil, errors.New("unclassified fixture header")
			}
			k := http.CanonicalHeaderKey(strings.TrimSpace(line[:i]))
			lk := strings.ToLower(k)
			if forbiddenHeader(k) || strings.Contains(lk, "token") || strings.Contains(lk, "certificate") {
				continue
			}
			fmt.Fprintf(&out, "%s: %s\n", k, strings.TrimSpace(line[i+1:]))
		}
		return []byte(out.String()), s.Err()
	}
	reqH, e := cleanHeaders("request.headers")
	if e != nil {
		return man, e
	}
	respH, e := cleanHeaders("response.headers")
	if e != nil {
		return man, e
	}
	switch o.BinaryMode {
	case BinaryMetadataOnly:
		man.BodiesUntouched = 2
		man.ManualReviewRequired = true
		man.Warnings = []string{"opaque bodies unchanged byte-for-byte; body_sanitized=false"}
	case BinaryTextRegions:
		var mods []ModifiedRegion
		req, mods, e = replaceText("request.body", req, o.Replacements)
		if e != nil {
			return man, e
		}
		man.ModifiedRegions = append(man.ModifiedRegions, mods...)
		resp, mods, e = replaceText("response.body", resp, o.Replacements)
		if e != nil {
			return man, e
		}
		man.ModifiedRegions = append(man.ModifiedRegions, mods...)
		man.RegionsModified = len(man.ModifiedRegions)
		man.BodiesSanitized = 2
		man.ManualReviewRequired = true
	case BinaryStructuredKnown:
		for _, x := range []struct {
			name string
			b    []byte
		}{{"request.body", req}, {"response.body", resp}} {
			trim := bytes.TrimSpace(x.b)
			if len(trim) > 0 && trim[0] == '<' {
				var mods []ModifiedRegion
				x.b, mods, e = replaceText(x.name, x.b, o.Replacements)
				if e != nil {
					return man, e
				}
				if x.name == "request.body" {
					req = x.b
				} else {
					resp = x.b
				}
				man.ModifiedRegions = append(man.ModifiedRegions, mods...)
				man.BodiesSanitized++
			} else {
				man.BodiesUntouched++
				man.ManualReviewRequired = true
			}
		}
		man.RegionsModified = len(man.ModifiedRegions)
	}
	meta.Sanitized = !man.ManualReviewRequired && man.BodiesUntouched == 0
	meta.Synthetic = false
	meta.Transport.Host = "HOST_REDACTED"
	meta.Contract.VerificationState = FixtureOnly
	meta.Sanitization.IdentifiersReplaced = man.RegionsModified > 0
	meta.Sanitization.CertificatesRemoved = true
	meta.Sanitization.SecretsRemoved = false
	meta.Sanitization.BodySanitized = man.BodiesSanitized == 2
	meta.Sanitization.ManualReviewRequired = man.ManualReviewRequired
	meta.Sanitization.ManualReviewCompleted = false
	mb, _ = yaml.Marshal(meta)
	outsum := sha256.Sum256(bytes.Join([][]byte{mb, req, resp}, nil))
	man.OutputFingerprint = "sha256:" + hex.EncodeToString(outsum[:])
	id := sha256.Sum256([]byte(man.InputFingerprint + string(o.BinaryMode) + man.OutputFingerprint))
	man.ManifestID = "sanitization_" + hex.EncodeToString(id[:10])
	parent := filepath.Dir(o.Output)
	if e = os.MkdirAll(parent, 0700); e != nil {
		return man, e
	}
	tmp, e := os.MkdirTemp(parent, ".cinderpath-sanitize-*")
	if e != nil {
		return man, e
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	files := map[string][]byte{"metadata.yaml": mb, "request.body": req, "response.body": resp, "request.headers": reqH, "response.headers": respH}
	for n, b := range files {
		if e = atomicWrite(filepath.Join(tmp, n), b, 0600, false); e != nil {
			return man, e
		}
	}
	jb, _ := json.MarshalIndent(man, "", "  ")
	if e = atomicWrite(filepath.Join(tmp, "sanitization-manifest.json"), jb, 0600, false); e != nil {
		return man, e
	}
	if e = os.Rename(tmp, o.Output); e != nil {
		return man, e
	}
	ok = true
	return man, nil
}
func replaceText(file string, b []byte, repls []Replacement) ([]byte, []ModifiedRegion, error) {
	out := append([]byte(nil), b...)
	type edit struct {
		s, e         int
		v            []byte
		enc, cat, fp string
	}
	var edits []edit
	regions := detectTextRegions(b)
	for _, r := range regions {
		for _, rp := range repls {
			if rp.Original == "" {
				continue
			}
			old, newv, e := encoded(rp.Original, rp.Replacement, r.Encoding)
			if e != nil {
				return nil, nil, e
			}
			at := 0
			for {
				j := bytes.Index(b[r.Offset+at:r.Offset+r.Length], old)
				if j < 0 {
					break
				}
				s := r.Offset + at + j
				if len(old) != len(newv) {
					return nil, nil, fmt.Errorf("replacement for %s is not length-preserving in %s", rp.Category, r.Encoding)
				}
				sum := sha256.Sum256(newv)
				edits = append(edits, edit{s, s + len(old), newv, r.Encoding, rp.Category, "sha256:" + hex.EncodeToString(sum[:])})
				at += j + len(old)
			}
		}
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].s < edits[j].s })
	for i, x := range edits {
		if i > 0 && x.s < edits[i-1].e {
			return nil, nil, errors.New("overlapping sanitization transformations rejected")
		}
		copy(out[x.s:x.e], x.v)
	}
	mods := make([]ModifiedRegion, 0, len(edits))
	for _, x := range edits {
		mods = append(mods, ModifiedRegion{file, x.enc, x.s, x.e - x.s, x.cat, x.fp})
	}
	return out, mods, nil
}
func encoded(s string, repl string, enc string) ([]byte, []byte, error) {
	if enc == "ascii" || enc == "utf-8" {
		return []byte(s), []byte(repl), nil
	}
	conv := func(v string, be bool) []byte {
		rr := []rune(v)
		x := make([]byte, len(rr)*2)
		for i, r := range rr {
			if be {
				binary.BigEndian.PutUint16(x[i*2:], uint16(r))
			} else {
				binary.LittleEndian.PutUint16(x[i*2:], uint16(r))
			}
		}
		return x
	}
	if enc == "utf-16le" {
		return conv(s, false), conv(repl, false), nil
	}
	if enc == "utf-16be" {
		return conv(s, true), conv(repl, true), nil
	}
	return nil, nil, errors.New("unsupported text encoding")
}
func LoadReplacementMap(path string) ([]Replacement, error) {
	st, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("replacement map must have mode 0600")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(b) > 1<<20 {
		return nil, errors.New("replacement map exceeds limit")
	}
	var m map[string]string
	if e = yaml.Unmarshal(b, &m); e != nil {
		return nil, e
	}
	out := make([]Replacement, 0, len(m))
	for k, v := range m {
		out = append(out, Replacement{k, v, "operator_literal"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Original < out[j].Original })
	return out, nil
}
func LoadSanitizationManifest(dir string) (SanitizationManifest, error) {
	var m SanitizationManifest
	b, e := safeRead(dir, "sanitization-manifest.json", true)
	if e != nil {
		return m, e
	}
	e = json.Unmarshal(b, &m)
	return m, e
}
func ReviewSanitization(dir string, bodies []string, ref string) (SanitizationManifest, error) {
	if ref == "" || len(ref) > 128 {
		return SanitizationManifest{}, errors.New("bounded reviewer reference is required")
	}
	m, e := LoadSanitizationManifest(dir)
	if e != nil {
		return m, e
	}
	approved := map[string]bool{}
	for _, r := range m.Reviews {
		approved[r.File] = r.Approved
	}
	now := time.Now().UTC()
	for _, name := range bodies {
		if filepath.Base(name) != name || (name != "request.body" && name != "response.body") {
			return m, errors.New("review body must be request.body or response.body")
		}
		if _, e = os.Stat(filepath.Join(dir, name)); e != nil {
			return m, e
		}
		approved[name] = true
		m.Reviews = append(m.Reviews, BodyReview{name, true, ref, now})
	}
	m.ManualReviewCompleted = approved["request.body"] && approved["response.body"]
	b, _ := json.MarshalIndent(m, "", "  ")
	e = atomicWrite(filepath.Join(dir, "sanitization-manifest.json"), b, 0600, true)
	return m, e
}
