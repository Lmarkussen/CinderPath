package capturekit

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Lmarkussen/CinderPath/internal/policy"
	"gopkg.in/yaml.v3"
)

const EvidenceBundleSchemaVersion = 1
const maxEvidenceMembers = 512
const maxEvidenceMemberBytes int64 = 64 << 20
const maxEvidenceTotalBytes int64 = 256 << 20

type ExportOptions struct {
	Directory, Output, ToolVersion string
	Force                          bool
}
type ImportOptions struct {
	Input, Output string
	Force         bool
}

func ExportEvidenceBundle(o ExportOptions) (EvidenceBundleInfo, error) {
	if o.Directory == "" || o.Output == "" {
		return EvidenceBundleInfo{}, errors.New("directory and output are required")
	}
	kit, _ := filepath.Abs(o.Directory)
	out, _ := filepath.Abs(o.Output)
	if out == kit || strings.HasPrefix(out, kit+string(filepath.Separator)) {
		return EvidenceBundleInfo{}, errors.New("bundle output must be outside the source kit")
	}
	v, e := Validate(kit)
	if e != nil {
		return EvidenceBundleInfo{}, e
	}
	if v.State != ReadyForEvidenceBundle {
		return EvidenceBundleInfo{}, fmt.Errorf("capture-evidence bundle export blocked: kit state is %s: %s", v.State, strings.Join(v.Blockers, "; "))
	}
	m, e := LoadMetadata(kit)
	if e != nil {
		return EvidenceBundleInfo{}, e
	}
	members := map[string][]byte{}
	addTree := func(sub string) error {
		return filepath.WalkDir(filepath.Join(kit, sub), func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("symlink rejected: %s", d.Name())
			}
			if d.IsDir() {
				return nil
			}
			if d.Name() == ".gitignore" || d.Name() == "README.txt" {
				return nil
			}
			rel, _ := filepath.Rel(kit, p)
			if !safeRelative(rel) {
				return errors.New("unsafe bundle member path")
			}
			lower := strings.ToLower(rel)
			if strings.Contains(lower, "replacement") || strings.Contains(lower, "secret") || strings.HasSuffix(lower, ".key") || strings.HasSuffix(lower, ".pfx") || strings.HasSuffix(lower, ".p12") || strings.Contains(lower, "raw-sensitive") {
				return fmt.Errorf("prohibited bundle member: %s", filepath.Base(rel))
			}
			b, e := readRegularBounded(p, maxEvidenceMemberBytes)
			if e != nil {
				return e
			}
			members[filepath.ToSlash(filepath.Join("kit", rel))] = b
			return nil
		})
	}
	for _, sub := range []string{"metadata", "sanitized", "review"} {
		if e = addTree(sub); e != nil {
			return EvidenceBundleInfo{}, e
		}
	}
	for _, rel := range []string{"manifest.yaml", "output/windows-log-inspection.json", "output/guided-import.json"} {
		p := filepath.Join(kit, rel)
		if regularExists(p) {
			b, e := readRegularBounded(p, maxEvidenceMemberBytes)
			if e != nil {
				return EvidenceBundleInfo{}, e
			}
			members[filepath.ToSlash(filepath.Join("kit", rel))] = b
		}
	}
	if len(members) > maxEvidenceMembers {
		return EvidenceBundleInfo{}, errors.New("bundle member count limit exceeded")
	}
	var total int64
	ems := make([]EvidenceMember, 0, len(members))
	formats := map[string]bool{}
	for p, b := range members {
		total += int64(len(b))
		if total > maxEvidenceTotalBytes {
			return EvidenceBundleInfo{}, errors.New("bundle total size limit exceeded")
		}
		s := sha256.Sum256(b)
		ems = append(ems, EvidenceMember{Path: p, Size: int64(len(b)), SHA256: hex.EncodeToString(s[:])})
		if strings.HasPrefix(p, "kit/sanitized/") {
			if kind := classify(strings.ToLower(p)); kind != "unsupported" {
				formats[kind] = true
			}
		}
	}
	sort.Slice(ems, func(i, j int) bool { return ems[i].Path < ems[j].Path })
	sourceFormats := make([]string, 0, len(formats))
	for f := range formats {
		sourceFormats = append(sourceFormats, f)
	}
	sort.Strings(sourceFormats)
	seed, _ := json.Marshal(ems)
	sum := sha256.Sum256(append([]byte(v.Fingerprint), seed...))
	man := EvidenceManifest{SchemaVersion: 1, BundleType: "capture_evidence", BundleID: "capture_evidence_" + hex.EncodeToString(sum[:8]), CreatedAt: readManifestCreatedAt(kit), ToolVersion: o.ToolVersion, KitID: v.KitID, KitFingerprint: v.Fingerprint, CaptureLabel: m.Capture.Label, ClientLabel: m.Client.Label, MetadataSchemaVersion: m.SchemaVersion, ReviewState: "manual_review_complete", SanitizationState: "sanitized", LeakageCheckState: "passed", Members: ems, SourceFormats: sourceFormats, TLSVisibility: "operator_declared_unknown", LogInspectionState: logState(members), SignatureState: "unsigned", SafetyNotes: []string{"offline capture evidence only", "not protocol-contract validation", "live policy requests: 0"}}
	mb, e := yaml.Marshal(man)
	if e != nil {
		return EvidenceBundleInfo{}, e
	}
	members["bundle.yaml"] = mb
	if e = writeEvidenceArchive(o.Output, members, o.Force); e != nil {
		return EvidenceBundleInfo{}, e
	}
	return EvidenceBundleInfo{Manifest: man, SignatureState: "unsigned", Integrity: "all members verified", TrustEffect: "none", ContractPromotion: "none", LivePolicyRequests: 0}, nil
}
func readManifestCreatedAt(dir string) string {
	b, _ := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	var m Manifest
	_ = yaml.Unmarshal(b, &m)
	return m.CreatedAt
}
func logState(m map[string][]byte) string {
	if _, ok := m["kit/output/windows-log-inspection.json"]; ok {
		return "structurally_inspected"
	}
	return "not_run"
}
func readRegularBounded(p string, max int64) ([]byte, error) {
	st, e := os.Lstat(p)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("bundle member must be a regular file")
	}
	if st.Size() > max {
		return nil, errors.New("bundle member size limit exceeded")
	}
	return os.ReadFile(p)
}
func writeEvidenceArchive(path string, members map[string][]byte, force bool) error {
	if !force {
		if _, e := os.Lstat(path); e == nil {
			return errors.New("bundle output already exists")
		}
	}
	tmp, e := os.CreateTemp(filepath.Dir(path), ".capture-evidence-")
	if e != nil {
		return e
	}
	name := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if e = tmp.Chmod(0o600); e != nil {
		return e
	}
	gz := gzip.NewWriter(tmp)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b := members[n]
		h := &tar.Header{Name: n, Mode: 0o600, Size: int64(len(b)), Typeflag: tar.TypeReg}
		if e = tw.WriteHeader(h); e == nil {
			_, e = tw.Write(b)
		}
		if e != nil {
			return e
		}
	}
	if e = tw.Close(); e != nil {
		return e
	}
	if e = gz.Close(); e != nil {
		return e
	}
	if e = tmp.Sync(); e != nil {
		return e
	}
	if e = tmp.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	ok = true
	return nil
}

func InspectEvidenceBundle(path string) (EvidenceBundleInfo, map[string][]byte, error) {
	members, e := readEvidenceArchive(path)
	if e != nil {
		return EvidenceBundleInfo{}, nil, e
	}
	mb, ok := members["bundle.yaml"]
	if !ok {
		return EvidenceBundleInfo{}, nil, errors.New("capture-evidence bundle manifest missing")
	}
	var m EvidenceManifest
	d := yaml.NewDecoder(bytes.NewReader(mb))
	d.KnownFields(true)
	if e = d.Decode(&m); e != nil {
		return EvidenceBundleInfo{}, nil, e
	}
	if m.SchemaVersion != 1 || m.BundleType != "capture_evidence" {
		return EvidenceBundleInfo{}, nil, errors.New("wrong bundle type or schema")
	}
	decl := map[string]EvidenceMember{}
	for _, x := range m.Members {
		if !safeBundlePath(x.Path) || x.Path == "bundle.yaml" {
			return EvidenceBundleInfo{}, nil, errors.New("unsafe declared member path")
		}
		if _, ok := decl[x.Path]; ok {
			return EvidenceBundleInfo{}, nil, errors.New("duplicate declared member path")
		}
		decl[x.Path] = x
	}
	for p, x := range decl {
		b, ok := members[p]
		if !ok {
			return EvidenceBundleInfo{}, nil, fmt.Errorf("bundle member missing: %s", p)
		}
		s := sha256.Sum256(b)
		if int64(len(b)) != x.Size || hex.EncodeToString(s[:]) != x.SHA256 {
			return EvidenceBundleInfo{}, nil, fmt.Errorf("bundle member fingerprint mismatch: %s", p)
		}
	}
	for p := range members {
		if p != "bundle.yaml" && p != "signature.yaml" {
			if _, ok := decl[p]; !ok {
				return EvidenceBundleInfo{}, nil, fmt.Errorf("undeclared bundle member: %s", p)
			}
		}
	}
	info := EvidenceBundleInfo{Manifest: m, SignatureState: "unsigned", Integrity: "all members verified", TrustEffect: "none", ContractPromotion: "none", LivePolicyRequests: 0}
	if sb, ok := members["signature.yaml"]; ok {
		var env policy.SignatureEnvelope
		if yaml.Unmarshal(sb, &env) != nil {
			return info, nil, errors.New("invalid bundle signature envelope")
		}
		canonical, _ := json.Marshal(m)
		vr, e := policy.VerifyCanonicalPayload(canonical, env)
		info.SignatureState, info.SignerKeyID, info.Integrity, info.TrustEffect, info.ContractPromotion = vr.State, vr.SignerKeyID, vr.Integrity, vr.TrustEffect, vr.ContractPromotion
		if e != nil {
			return info, nil, e
		}
	}
	return info, members, nil
}
func readEvidenceArchive(path string) (map[string][]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return readEvidenceArchiveReader(f)
}
func readEvidenceArchiveReader(r io.Reader) (map[string][]byte, error) {
	gz, e := gzip.NewReader(r)
	if e != nil {
		return nil, e
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	var total int64
	for len(out) <= maxEvidenceMembers {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		if h.Typeflag != tar.TypeReg {
			return nil, errors.New("bundle contains non-regular member")
		}
		if !safeBundlePath(h.Name) || h.Size < 0 || h.Size > maxEvidenceMemberBytes {
			return nil, errors.New("unsafe or oversized bundle member")
		}
		if _, ok := out[h.Name]; ok {
			return nil, errors.New("duplicate bundle member path")
		}
		total += h.Size
		if total > maxEvidenceTotalBytes {
			return nil, errors.New("bundle total size limit exceeded")
		}
		b, e := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if e != nil || int64(len(b)) != h.Size {
			return nil, errors.New("truncated bundle member")
		}
		out[h.Name] = b
	}
	if len(out) > maxEvidenceMembers {
		return nil, errors.New("bundle member count limit exceeded")
	}
	return out, nil
}
func safeBundlePath(p string) bool {
	return p != "" && !strings.Contains(p, "\\") && !filepath.IsAbs(p) && filepath.ToSlash(filepath.Clean(p)) == p && p != ".." && !strings.HasPrefix(p, "../")
}

func ImportEvidenceBundle(o ImportOptions) (EvidenceBundleInfo, error) {
	info, members, e := InspectEvidenceBundle(o.Input)
	if e != nil {
		return info, e
	}
	out, _ := filepath.Abs(o.Output)
	if _, e = os.Lstat(out); e == nil && !o.Force {
		return info, errors.New("bundle import output already exists")
	}
	tmp, e := os.MkdirTemp(filepath.Dir(out), ".capture-evidence-import-")
	if e != nil {
		return info, e
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	if e = os.Chmod(tmp, 0o700); e != nil {
		return info, e
	}
	for p, b := range members {
		if p == "bundle.yaml" || p == "signature.yaml" {
			continue
		}
		rel := strings.TrimPrefix(p, "kit/")
		if rel == p || !safeRelative(rel) {
			return info, errors.New("invalid capture-evidence kit member")
		}
		dest := filepath.Join(tmp, filepath.FromSlash(rel))
		if e = os.MkdirAll(filepath.Dir(dest), 0o700); e != nil {
			return info, e
		}
		if e = os.WriteFile(dest, b, 0o600); e != nil {
			return info, e
		}
	}
	if o.Force {
		if st, e := os.Lstat(out); e == nil {
			if !st.IsDir() {
				return info, errors.New("refuse to replace non-directory output")
			}
			backup := out + ".previous"
			if _, e = os.Lstat(backup); e == nil {
				return info, errors.New("bundle import backup already exists")
			}
			if e = os.Rename(out, backup); e != nil {
				return info, e
			}
			if e = os.Rename(tmp, out); e != nil {
				_ = os.Rename(backup, out)
				return info, e
			}
			_ = os.RemoveAll(backup)
			ok = true
			return info, nil
		}
	}
	if e = os.Rename(tmp, out); e != nil {
		return info, e
	}
	ok = true
	return info, nil
}

func SignEvidenceBundle(input, key, output string, force bool) (EvidenceBundleInfo, error) {
	info, members, e := InspectEvidenceBundle(input)
	if e != nil {
		return info, e
	}
	if info.SignatureState != "unsigned" {
		return info, errors.New("capture-evidence bundle is already signed")
	}
	canonical, _ := json.Marshal(info.Manifest)
	env, e := policy.SignCanonicalPayload(canonical, key)
	if e != nil {
		return info, e
	}
	b, _ := yaml.Marshal(env)
	members["signature.yaml"] = b
	if e = writeEvidenceArchive(output, members, force); e != nil {
		return info, e
	}
	info.SignatureState = "signature_valid"
	info.SignerKeyID = env.KeyID
	return info, nil
}

func ValidateImportedEvidence(dir string, info EvidenceBundleInfo) (Validation, error) {
	v := Validation{State: Imported, KitID: info.Manifest.KitID, Fingerprint: info.Manifest.KitFingerprint, LiveRequests: 0}
	root := filepath.Join(dir, "sanitized")
	e := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink in imported evidence")
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		b, e := readRegularBounded(p, maxEvidenceMemberBytes)
		if e != nil {
			return e
		}
		s := sha256.Sum256(b)
		v.Sanitized = append(v.Sanitized, File{Path: rel, Size: int64(len(b)), SHA256: hex.EncodeToString(s[:]), Kind: classify(strings.ToLower(p)), Redacted: true, Reviewed: true})
		return nil
	})
	if e != nil {
		return v, e
	}
	sort.Slice(v.Sanitized, func(i, j int) bool { return v.Sanitized[i].Path < v.Sanitized[j].Path })
	return v, nil
}
