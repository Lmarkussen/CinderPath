package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
)

func Observe(c *NormalizedCapture) []Observation {
	var out []Observation
	add := func(m *Message, kind, evidence, rep, confidence string, structural bool) {
		if m == nil {
			return
		}
		o := Observation{MessageID: m.ID, Kind: kind, Evidence: evidence, Representation: rep, Confidence: confidence, Structural: structural, Interpretation: "observation_only"}
		o.ID = stableID("observation", m.ID, kind, evidence)
		out = append(out, o)
	}
	for i := range c.Exchanges {
		e := &c.Exchanges[i]
		for _, m := range []*Message{e.Request, e.Response} {
			if m == nil {
				continue
			}
			if m.Method != "" {
				add(m, "http_method", m.Method, "text", "high", true)
			}
			if m.Route != "" {
				add(m, "http_route", m.Route, "text", "high", true)
			}
			if m.MediaType != "" {
				add(m, "media_type", m.MediaType, "text", "high", true)
			}
			if m.Body.Length > 0 {
				add(m, "body_length", fmt.Sprint(m.Body.Length), "integer", "high", true)
			}
		}
	}
	return out
}

func ValidateMatrix(m Matrix, captures map[string]NormalizedCapture) MatrixResult {
	r := MatrixResult{SampleCount: len(m.Members)}
	if len(m.Members) < 2 {
		r.Quality = "insufficient_samples"
		r.Limitations = append(r.Limitations, "at least two samples are required")
	}
	seen := map[string]string{}
	formats := map[string]bool{}
	for _, x := range m.Members {
		c, ok := captures[x.Label]
		if !ok {
			r.Warnings = append(r.Warnings, "missing capture: "+x.Label)
			continue
		}
		formats[c.Source.Format] = true
		if prior, ok := seen[c.Source.Fingerprint]; ok {
			r.Duplicates = append(r.Duplicates, prior+" and "+x.Label)
		} else {
			seen[c.Source.Fingerprint] = x.Label
		}
	}
	if len(formats) > 1 {
		r.Confounders = append(r.Confounders, "capture formats differ")
	}
	if len(r.Duplicates) > 0 {
		r.Confounders = append(r.Confounders, "duplicate source fingerprints")
	}
	if r.Quality == "" {
		if len(r.Confounders) > 0 || len(r.Warnings) > 0 {
			r.Quality = "suitable_with_limitations"
		} else {
			r.Quality = "suitable"
		}
	}
	sort.Strings(r.Confounders)
	sort.Strings(r.Duplicates)
	sort.Strings(r.Warnings)
	return r
}

func DeriveCandidates(captures []NormalizedCapture, minimum int) []ParserCandidate {
	if minimum < 2 {
		minimum = 2
	}
	if len(captures) < minimum {
		return nil
	}
	counts := map[string]int{}
	examples := map[string][]string{}
	for _, c := range captures {
		seen := map[string]bool{}
		for _, e := range c.Exchanges {
			if e.Request == nil {
				continue
			}
			k := strings.ToUpper(e.Request.Method) + " " + e.Request.Route
			if !seen[k] {
				counts[k]++
				seen[k] = true
				examples[k] = append(examples[k], c.Source.ID)
			}
		}
	}
	var out []ParserCandidate
	for k, n := range counts {
		if n < minimum {
			continue
		}
		p := ParserCandidate{State: "candidate", AlgorithmVersion: AlgorithmVersion, Constraints: []string{k}, Preconditions: []string{"visible plaintext HTTP"}, SampleCoverage: n, PositiveExamples: examples[k], Unknowns: []string{"semantic body fields remain unknown"}, LiveExecution: false}
		raw, _ := json.Marshal(p)
		h := sha256.Sum256(raw)
		p.Fingerprint = hex.EncodeToString(h[:])
		p.ID = "parser_" + p.Fingerprint[:20]
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}

func Analyze(c NormalizedCapture) Analysis {
	a := Analysis{Capture: c, Candidates: DeriveCandidates([]NormalizedCapture{c}, 2), LivePolicyCollectionBlocked: true}
	raw, _ := json.Marshal(a)
	a.Fingerprint = fingerprint(raw)
	return a
}

// InspectBinary returns bounded structural observations. Shape matches never assign protocol semantics.
func InspectBinary(body []byte, max int) []Observation {
	if max <= 0 || max > 4096 {
		max = 4096
	}
	if len(body) > max {
		body = body[:max]
	}
	var out []Observation
	add := func(kind string, off, n int, rep, evidence, confidence string) {
		o := Observation{Kind: kind, Offset: off, Length: n, Representation: rep, Evidence: evidence, Confidence: confidence, Structural: true, Interpretation: "structural observation only"}
		o.ID = stableID("observation", kind, fmt.Sprint(off), fmt.Sprint(n), evidence)
		out = append(out, o)
	}
	if len(body) >= 4 {
		add("prefix_bytes", 0, 4, "hex", fmt.Sprintf("%x", body[:4]), "high")
	}
	for i := 0; i < len(body); {
		if body[i] >= 0x20 && body[i] <= 0x7e {
			j := i
			for j < len(body) && body[j] >= 0x20 && body[j] <= 0x7e {
				j++
			}
			if j-i >= 4 {
				add("ascii_region", i, j-i, "utf-8", "bounded printable region", "high")
			}
			i = j
		} else {
			i++
		}
	}
	for i := 0; i+7 < len(body); i += 2 {
		var u []uint16
		j := i
		for j+1 < len(body) {
			v := uint16(body[j]) | uint16(body[j+1])<<8
			if v < 0x20 || v > 0x7e {
				break
			}
			u = append(u, v)
			j += 2
		}
		if len(u) >= 4 {
			_ = string(utf16.Decode(u))
			add("utf16le_region", i, j-i, "utf-16le", "bounded printable region", "high")
			i = j - 2
		}
	}
	for _, magic := range []struct {
		name string
		b    []byte
	}{{"gzip_magic", []byte{0x1f, 0x8b}}, {"zip_magic", []byte{'P', 'K', 3, 4}}, {"cab_magic", []byte("MSCF")}} {
		if i := bytes.Index(body, magic.b); i >= 0 {
			add(magic.name, i, len(magic.b), "binary", "recognized file-format magic", "high")
		}
	}
	for width := 4; width <= 8; width += 4 {
		for i := 0; i+width <= len(body) && i < 64; i += width {
			var v uint64
			if width == 4 {
				v = uint64(body[i]) | uint64(body[i+1])<<8 | uint64(body[i+2])<<16 | uint64(body[i+3])<<24
			} else {
				for j := 0; j < 8; j++ {
					v |= uint64(body[i+j]) << uint(8*j)
				}
			}
			if v > 0 && v <= uint64(len(body)) {
				add("candidate_length", i, width, "little-endian integer", "value falls within bounded body length", "low")
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Offset != out[j].Offset {
			return out[i].Offset < out[j].Offset
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}
