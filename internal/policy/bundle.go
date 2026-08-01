package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	BundleSchemaVersion  = 1
	MaxBundleMembers     = 256
	MaxBundleMemberBytes = MaxFixtureBytes
	MaxBundleBytes       = 32 << 20
)

type BundleManifest struct {
	SchemaVersion                int               `yaml:"schema_version" json:"schema_version"`
	BundleID                     string            `yaml:"bundle_id" json:"bundle_id"`
	CreatedAt                    time.Time         `yaml:"created_at" json:"created_at"`
	ToolVersion                  string            `yaml:"tool_version" json:"tool_version"`
	ContractIDs                  []string          `yaml:"contract_ids,flow" json:"contract_ids"`
	FixtureIDs                   []string          `yaml:"fixture_ids,flow" json:"fixture_ids"`
	SanitizerVersions            []string          `yaml:"sanitizer_versions,flow" json:"sanitizer_versions"`
	ParserVersions               []string          `yaml:"parser_versions,flow" json:"parser_versions"`
	SyntheticOnly                bool              `yaml:"synthetic_only" json:"synthetic_only"`
	Sanitized                    bool              `yaml:"sanitized" json:"sanitized"`
	ManualReviewComplete         bool              `yaml:"manual_review_complete" json:"manual_review_complete"`
	MemberFingerprints           map[string]string `yaml:"member_fingerprints" json:"member_fingerprints"`
	ExpectedAnalysisFingerprints map[string]string `yaml:"expected_analysis_fingerprints" json:"expected_analysis_fingerprints"`
	SafetyNotes                  []string          `yaml:"safety_notes" json:"safety_notes"`
}
type BundleInfo struct {
	Manifest BundleManifest
	Members  []string
}
type BundleExportOptions struct {
	Contract            Contract
	FixtureDirectories  []string
	Output, ToolVersion string
}

func ExportBundle(o BundleExportOptions) (BundleManifest, error) {
	if o.Contract.VerificationState == ApprovedLive {
		return BundleManifest{}, errors.New("approved_live contracts cannot be exported by normal workflow")
	}
	members := map[string][]byte{}
	members["schemas/README.txt"] = []byte("No inferred protocol schema is included. Only positively observed fixture metadata is bundled.\n")
	members["expected-results/README.txt"] = []byte("Expected analysis fingerprints are recorded only when a reviewed parser result is available.\n")
	c := o.Contract
	c.VerificationState = FixtureOnly
	c.VerifiedAt = nil
	cb, _ := yaml.Marshal(c)
	members["contracts/"+c.ID+".yaml"] = cb
	m := BundleManifest{SchemaVersion: BundleSchemaVersion, CreatedAt: time.Now().UTC(), ToolVersion: o.ToolVersion, ContractIDs: []string{c.ID}, MemberFingerprints: map[string]string{}, ExpectedAnalysisFingerprints: map[string]string{}, SafetyNotes: []string{"offline research bundle; live execution remains blocked", "imported verification state is not trusted"}, SyntheticOnly: true, Sanitized: true, ManualReviewComplete: true, ParserVersions: []string{"policy-xml-v1"}}
	for _, dir := range o.FixtureDirectories {
		f, _, e := ImportDirectory(dir)
		if e != nil {
			return m, e
		}
		man, me := LoadSanitizationManifest(dir)
		if !f.Metadata.Synthetic {
			if me != nil {
				return m, errors.New("sanitized fixture requires a sanitization manifest")
			}
			if man.ManualReviewRequired && !man.ManualReviewCompleted {
				return m, errors.New("manual review is incomplete")
			}
			m.SanitizerVersions = append(m.SanitizerVersions, man.SanitizerVersion)
			m.SyntheticOnly = false
		}
		if !f.Metadata.Synthetic {
			if e = scanExportSafety(dir); e != nil {
				return m, e
			}
		}
		m.FixtureIDs = append(m.FixtureIDs, f.ID)
		base := "fixtures/" + f.ID + "/"
		for _, n := range []string{"metadata.yaml", "request.headers", "request.body", "response.headers", "response.body", "sanitization-manifest.json"} {
			b, e := safeRead(dir, n, false)
			if e != nil {
				return m, e
			}
			if b != nil {
				target := base + n
				if n == "sanitization-manifest.json" {
					target = "manifests/" + f.ID + ".json"
				}
				members[target] = b
			}
		}
	}
	if len(m.FixtureIDs) == 0 {
		return m, errors.New("bundle export requires at least one explicit fixture directory")
	}
	sort.Strings(m.FixtureIDs)
	sort.Strings(m.SanitizerVersions)
	for n, b := range members {
		x := sha256.Sum256(b)
		m.MemberFingerprints[n] = "sha256:" + hex.EncodeToString(x[:])
	}
	seed, _ := yaml.Marshal(m)
	id := sha256.Sum256(seed)
	m.BundleID = "bundle_" + hex.EncodeToString(id[:10])
	mb, _ := yaml.Marshal(m)
	members["bundle.yaml"] = mb
	if e := writeBundle(o.Output, members); e != nil {
		return m, e
	}
	return m, nil
}
func scanExportSafety(dir string) error {
	for _, n := range []string{"request.headers", "response.headers", "request.body", "response.body"} {
		b, e := safeRead(dir, n, false)
		if e != nil {
			return e
		}
		l := strings.ToLower(string(b))
		for _, bad := range []string{"authorization:", "proxy-authorization:", "cookie:", "set-cookie:", "private key-----", "password=", "bearer ", "syntheticpassword123!", "cinderpath_synthetic_sanitizer_sentinel"} {
			if strings.Contains(l, bad) {
				return fmt.Errorf("bundle export blocked: sensitive indicator in %s", n)
			}
		}
	}
	return nil
}
func writeBundle(path string, members map[string][]byte) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b := members[n]
		if e := tw.WriteHeader(&tar.Header{Name: n, Mode: 0600, Size: int64(len(b)), ModTime: time.Unix(0, 0)}); e != nil {
			return e
		}
		if _, e := tw.Write(b); e != nil {
			return e
		}
	}
	if e := tw.Close(); e != nil {
		return e
	}
	if e := gz.Close(); e != nil {
		return e
	}
	return atomicWrite(path, buf.Bytes(), 0600, false)
}
func InspectBundle(path string) (BundleInfo, error) {
	f, e := os.Open(path)
	if e != nil {
		return BundleInfo{}, e
	}
	defer f.Close()
	lr := io.LimitReader(f, MaxBundleBytes+1)
	gz, e := gzip.NewReader(lr)
	if e != nil {
		return BundleInfo{}, e
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	data := map[string][]byte{}
	var total int64
	for len(data) < MaxBundleMembers {
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return BundleInfo{}, e
		}
		n := filepath.ToSlash(h.Name)
		if h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > MaxBundleMemberBytes || unsafeMember(n) {
			return BundleInfo{}, errors.New("unsafe or oversized bundle member")
		}
		if _, ok := data[n]; ok {
			return BundleInfo{}, errors.New("duplicate bundle member")
		}
		total += h.Size
		if total > MaxBundleBytes {
			return BundleInfo{}, errors.New("bundle total size limit exceeded")
		}
		b, e := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if e != nil || int64(len(b)) != h.Size {
			return BundleInfo{}, errors.New("invalid bundle member")
		}
		data[n] = b
	}
	if len(data) >= MaxBundleMembers {
		return BundleInfo{}, errors.New("bundle member count limit exceeded")
	}
	mb, ok := data["bundle.yaml"]
	if !ok {
		return BundleInfo{}, errors.New("bundle manifest missing")
	}
	var m BundleManifest
	if e = yaml.Unmarshal(mb, &m); e != nil || m.SchemaVersion != BundleSchemaVersion {
		return BundleInfo{}, errors.New("invalid bundle manifest")
	}
	for n, fp := range m.MemberFingerprints {
		b, ok := data[n]
		if !ok {
			return BundleInfo{}, fmt.Errorf("manifest member missing: %s", n)
		}
		x := sha256.Sum256(b)
		if fp != "sha256:"+hex.EncodeToString(x[:]) {
			return BundleInfo{}, fmt.Errorf("fingerprint mismatch: %s", n)
		}
	}
	names := make([]string, 0, len(data))
	for n := range data {
		names = append(names, n)
	}
	sort.Strings(names)
	return BundleInfo{m, names}, nil
}
func unsafeMember(n string) bool {
	return n == "" || strings.HasPrefix(n, "/") || filepath.IsAbs(n) || strings.Contains(n, "\\") || strings.Contains(n, "../") || filepath.Clean(n) != n
}
func ImportBundle(path, root string) (BundleInfo, error) {
	info, e := InspectBundle(path)
	if e != nil {
		return info, e
	}
	dest := filepath.Join(root, info.Manifest.BundleID)
	if _, e = os.Lstat(dest); e == nil {
		return info, errors.New("bundle already imported")
	}
	parent := filepath.Dir(dest)
	if e = os.MkdirAll(parent, 0700); e != nil {
		return info, e
	}
	tmp, e := os.MkdirTemp(parent, ".bundle-import-*")
	if e != nil {
		return info, e
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	f, _ := os.Open(path)
	defer f.Close()
	gz, _ := gzip.NewReader(f)
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return info, e
		}
		n := filepath.ToSlash(h.Name)
		if unsafeMember(n) || h.Typeflag != tar.TypeReg {
			return info, errors.New("unsafe bundle member")
		}
		b, e := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if e != nil {
			return info, e
		}
		if strings.HasPrefix(n, "contracts/") {
			var c Contract
			if yaml.Unmarshal(b, &c) != nil {
				return info, errors.New("invalid imported contract")
			}
			if c.VerificationState != FixtureOnly && c.VerificationState != CapturedUnverified && c.VerificationState != Unknown {
				return info, errors.New("imported contract verification state is not trusted")
			}
		}
		target := filepath.Join(tmp, filepath.FromSlash(n))
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return info, e
		}
		if e = atomicWrite(target, b, 0600, false); e != nil {
			return info, e
		}
	}
	if e = os.Rename(tmp, dest); e != nil {
		return info, e
	}
	ok = true
	return info, nil
}
