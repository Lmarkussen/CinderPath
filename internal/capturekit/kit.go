package capturekit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var labelRE = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
var required = []string{"README-FIRST.txt", "SAFETY.txt", "WINDOWS-CHECKLIST.txt", "LINUX-CHECKLIST.txt", "metadata/capture.template.yaml", "metadata/client-inventory.template.json", "metadata/tool-inventory.template.json", "metadata/review-state.template.yaml", "windows/Collect-CinderPathInventory.ps1", "windows/Prepare-CinderPathCapture.ps1", "windows/Finalize-CinderPathCapture.ps1", "windows/commands-manual.txt", "windows/event-log-notes.txt", "linux/inspect.sh", "linux/sanitize.sh", "linux/review.sh", "linux/import.sh", "linux/bundle.sh", "review/PRE-CAPTURE.md", "review/POST-CAPTURE.md", "review/IDENTIFIER-REVIEW.md", "review/BINARY-REVIEW.md", "review/LEAKAGE-CHECK.md", "raw/.gitignore", "raw/README.txt", "sanitized/.gitignore", "sanitized/README.txt", "output/.gitignore", "manifest.yaml"}

func cleanLabel(v string) (string, error) {
	v = strings.Trim(labelRE.ReplaceAllString(strings.TrimSpace(v), "-"), "-.")
	if len(v) > 128 {
		return "", errors.New("metadata label exceeds 128 characters")
	}
	return v, nil
}
func Create(o CreateOptions) error {
	if o.Output == "" {
		return errors.New("output is required")
	}
	for _, p := range []*string{&o.SiteCode, &o.ManagementPoint, &o.ClientLabel, &o.CaptureLabel, &o.CaptureAction} {
		v, e := cleanLabel(*p)
		if e != nil {
			return e
		}
		*p = v
	}
	if o.CaptureAction == "" {
		o.CaptureAction = "normal_policy_retrieval"
	}
	if o.CaptureLabel == "" {
		o.CaptureLabel = "baseline-01"
	}
	if o.ClientLabel == "" {
		o.ClientLabel = "windows-client"
	}
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	out, e := filepath.Abs(o.Output)
	if e != nil {
		return e
	}
	parent := filepath.Dir(out)
	if st, e := os.Stat(out); e == nil {
		if !o.Force {
			return errors.New("capture-kit output already exists")
		}
		if !st.IsDir() {
			return errors.New("capture-kit output is not a directory")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	tmp, e := os.MkdirTemp(parent, ".cinderpath-capture-kit-")
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	if e = os.Chmod(tmp, 0o700); e != nil {
		return e
	}
	for _, d := range []string{"metadata", "windows", "linux", "review", "raw", "sanitized", "output"} {
		if e = os.Mkdir(filepath.Join(tmp, d), 0o700); e != nil {
			return e
		}
	}
	m := Metadata{SchemaVersion: 1, Capture: Capture{Label: o.CaptureLabel, Action: o.CaptureAction, AuthorizedLab: true, OperatorReference: "LAB_OPERATOR_001"}, Client: Client{Label: o.ClientLabel, SiteCode: o.SiteCode, ManagementPoint: o.ManagementPoint, IdentityReference: "existing-client-a"}, Environment: Environment{Disposable: true, SnapshotReference: "SNAPSHOT_001"}, Tools: Tools{PacketCapture: "operator_supplied", LogCollection: "local_copy", HARCapture: "none"}, Review: Review{RawSensitive: true}}
	mb, _ := yaml.Marshal(m)
	files := map[string]string{
		"README-FIRST.txt": readmeFirst, "SAFETY.txt": safety, "WINDOWS-CHECKLIST.txt": windowsChecklist, "LINUX-CHECKLIST.txt": linuxChecklist,
		"metadata/capture.template.yaml": string(mb), "metadata/client-inventory.template.json": "{\n  \"schema_version\": 1,\n  \"status\": \"not_collected\"\n}\n", "metadata/tool-inventory.template.json": "{\n  \"schema_version\": 1,\n  \"tools\": []\n}\n", "metadata/review-state.template.yaml": "schema_version: 1\nmetadata_reviewed: false\nbinary_reviewed: false\nsanitized: false\nleakage_checks_passed: false\nbundle_export_approved: false\nreview_failed: false\n",
		"windows/Collect-CinderPathInventory.ps1": inventoryPS, "windows/Prepare-CinderPathCapture.ps1": preparePS, "windows/Finalize-CinderPathCapture.ps1": finalizePS, "windows/commands-manual.txt": manualCommands, "windows/event-log-notes.txt": eventNotes,
		"linux/inspect.sh": inspectSH, "linux/sanitize.sh": sanitizeSH, "linux/review.sh": reviewSH, "linux/import.sh": importSH, "linux/bundle.sh": bundleSH,
		"review/PRE-CAPTURE.md": preReview, "review/POST-CAPTURE.md": postReview, "review/IDENTIFIER-REVIEW.md": identifierReview, "review/BINARY-REVIEW.md": binaryReview, "review/LEAKAGE-CHECK.md": leakageReview,
		"raw/.gitignore": protectGitignore, "raw/README.txt": "RAW AND SENSITIVE. Place operator-created evidence here. Never share without sanitization and review.\n", "sanitized/.gitignore": protectGitignore, "sanitized/README.txt": "Only reviewed sanitized or synthetic inputs belong here.\n", "output/.gitignore": protectGitignore,
	}
	for p, b := range files {
		mode := fs.FileMode(0o600)
		if strings.HasPrefix(p, "linux/") || strings.HasSuffix(p, ".ps1") {
			mode = 0o700
		}
		if e = writeFile(filepath.Join(tmp, p), []byte(b), mode); e != nil {
			return e
		}
	}
	kitSeed := strings.Join([]string{o.CaptureLabel, o.ClientLabel, o.SiteCode, o.ManagementPoint, o.CaptureAction}, "\x00")
	sum := sha256.Sum256([]byte(kitSeed))
	fp := hex.EncodeToString(sum[:])
	man := Manifest{SchemaVersion: 1, KitID: "capture_kit_" + fp[:16], Fingerprint: fp, CreatedAt: o.Now.UTC().Format(time.RFC3339), RequiredFiles: required, Safety: "passive_preparation_only", SetupComplete: true}
	b, _ := yaml.Marshal(man)
	if e = writeFile(filepath.Join(tmp, "manifest.yaml"), b, 0o600); e != nil {
		return e
	}
	if o.Force {
		if _, e = os.Stat(out); e == nil {
			backup := out + ".previous"
			if _, x := os.Stat(backup); x == nil {
				return errors.New("capture-kit backup already exists")
			}
			if e = os.Rename(out, backup); e != nil {
				return e
			}
			if e = os.Rename(tmp, out); e != nil {
				_ = os.Rename(backup, out)
				return e
			}
			_ = os.RemoveAll(backup)
			ok = true
			return nil
		}
	}
	if e = os.Rename(tmp, out); e != nil {
		return e
	}
	ok = true
	return nil
}
func writeFile(path string, b []byte, mode fs.FileMode) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	return f.Sync()
}

func LoadMetadata(dir string) (Metadata, error) {
	var m Metadata
	b, e := os.ReadFile(filepath.Join(dir, "metadata", "capture.template.yaml"))
	if e != nil {
		return m, e
	}
	d := yaml.NewDecoder(strings.NewReader(string(b)))
	d.KnownFields(true)
	e = d.Decode(&m)
	if e != nil {
		return m, e
	}
	return m, validateMetadata(m)
}
func validateMetadata(m Metadata) error {
	if m.SchemaVersion != 1 {
		return errors.New("unsupported capture metadata schema version")
	}
	vals := []string{m.Capture.Label, m.Capture.Action, m.Capture.OperatorReference, m.Client.Label, m.Client.SiteCode, m.Client.ManagementPoint, m.Client.IdentityReference, m.Environment.SnapshotReference}
	for _, v := range vals {
		if len(v) > 256 {
			return errors.New("metadata string exceeds 256 characters")
		}
	}
	for _, v := range []string{m.Capture.StartedAt, m.Capture.StoppedAt} {
		if v != "" {
			if _, e := time.Parse(time.RFC3339, v); e != nil {
				return fmt.Errorf("invalid capture timestamp: %w", e)
			}
		}
	}
	for _, f := range m.Files {
		if !safeRelative(f.Path) {
			return fmt.Errorf("unsafe file reference: %q", f.Path)
		}
		if len(f.Path) > 512 {
			return errors.New("file reference too long")
		}
	}
	return nil
}
func safeRelative(p string) bool {
	return p != "" && !filepath.IsAbs(p) && filepath.Clean(p) == p && p != ".." && !strings.HasPrefix(p, ".."+string(filepath.Separator))
}
func Validate(dir string) (Validation, error) {
	v := Validation{State: Invalid, LiveRequests: 0}
	abs, e := filepath.Abs(dir)
	if e != nil {
		return v, e
	}
	var man Manifest
	b, e := os.ReadFile(filepath.Join(abs, "manifest.yaml"))
	if e != nil {
		v.Errors = append(v.Errors, "missing manifest.yaml")
		return v, nil
	}
	if e = yaml.Unmarshal(b, &man); e != nil {
		v.Errors = append(v.Errors, "invalid manifest: "+e.Error())
		return v, nil
	}
	v.KitID, v.Fingerprint = man.KitID, man.Fingerprint
	if man.SchemaVersion != 1 {
		v.Errors = append(v.Errors, "unsupported manifest schema version")
	}
	for _, p := range required {
		if !safeRelative(p) {
			v.Errors = append(v.Errors, "unsafe required path: "+p)
			continue
		}
		st, e := os.Lstat(filepath.Join(abs, p))
		if e != nil {
			v.Errors = append(v.Errors, "missing required file: "+p)
			continue
		}
		if st.Mode()&os.ModeSymlink != 0 {
			v.Errors = append(v.Errors, "symlink not allowed: "+p)
		}
		if st.Mode().Perm()&0o077 != 0 {
			v.Warnings = append(v.Warnings, "permissions are broader than owner-only: "+p)
		}
	}
	m, e := LoadMetadata(abs)
	if e != nil {
		v.Errors = append(v.Errors, e.Error())
		return v, nil
	}
	if !m.Capture.AuthorizedLab {
		v.Errors = append(v.Errors, "authorized_lab must be true")
	}
	if !m.Environment.Disposable {
		v.Errors = append(v.Errors, "disposable must be true")
	}
	v.RawFiles = inventory(abs, "raw", &v)
	v.Sanitized = inventory(abs, "sanitized", &v)
	declared := map[string]File{}
	for _, f := range m.Files {
		declared[f.Path] = f
	}
	for _, f := range append(append([]File{}, v.RawFiles...), v.Sanitized...) {
		if d, ok := declared[f.Path]; ok && d.SHA256 != "" && !strings.EqualFold(d.SHA256, f.SHA256) {
			v.Errors = append(v.Errors, "SHA-256 mismatch: "+f.Path)
		}
	}
	for _, f := range v.Sanitized {
		p := filepath.Join(abs, f.Path)
		b, err := os.ReadFile(p)
		if err != nil || len(b) > 8<<20 {
			continue
		}
		lower := strings.ToLower(string(b))
		for _, marker := range []string{"cinderpath_synthetic_leak_sentinel", "authorization:", "bearer ", "set-cookie:", "cookie:", "private key"} {
			if strings.Contains(lower, marker) {
				v.Errors = append(v.Errors, "leakage marker in sanitized file: "+f.Path)
				break
			}
		}
	}
	if m.Review.BundleExportApproved && regularExists(filepath.Join(abs, "raw", "CINDERPATH_SYNTHETIC_LEAK_SENTINEL.txt")) {
		v.Errors = append(v.Errors, "synthetic leakage sentinel remains in raw/")
	}
	if len(v.Errors) > 0 {
		v.Blockers = append(v.Blockers, v.Errors...)
		return v, nil
	}
	started := m.Capture.StartedAt != ""
	stopped := m.Capture.StoppedAt != ""
	imported := regularExists(filepath.Join(abs, "output", "guided-import.json"))
	exported := regularExists(filepath.Join(abs, "output", "evidence-bundle.json"))
	switch {
	case !man.SetupComplete:
		v.State = Created
	case !started:
		v.State = ReadyForCapture
	case started && !stopped:
		v.State = CaptureInProgress
	case stopped && len(v.RawFiles) == 0 && len(v.Sanitized) == 0:
		v.State = RawCaptureComplete
	case len(v.RawFiles) > 0 && len(v.Sanitized) == 0:
		v.State = RequiresSanitization
	case m.Review.ReviewFailed:
		v.State = ReviewFailed
	case !m.Review.MetadataReviewed || !m.Review.BinaryReviewed || !m.Review.LeakageChecksPassed:
		v.State = RequiresManualReview
	case exported:
		v.State = EvidenceBundleExported
	case imported && m.Review.BundleExportApproved:
		v.State = ReadyForEvidenceBundle
	case imported:
		v.State = Imported
	case m.Review.BundleExportApproved:
		v.State = ReadyForEvidenceBundle
	default:
		v.State = ReadyForImport
	}
	v.Blockers, v.AllowedNextActions = explain(v.State, m, v)
	return v, nil
}
func regularExists(path string) bool {
	st, e := os.Lstat(path)
	return e == nil && st.Mode().IsRegular()
}
func explain(s State, m Metadata, v Validation) ([]string, []string) {
	var b, a []string
	switch s {
	case Created:
		b = append(b, "capture-kit setup is incomplete")
		a = append(a, "complete generated kit setup")
	case ReadyForCapture:
		a = append(a, "run the passive Windows preparation script", "start and stop an approved capture tool manually")
	case CaptureInProgress:
		b = append(b, "capture stop timestamp is missing")
		a = append(a, "stop the operator-controlled capture and finalize raw evidence")
	case RawCaptureComplete, RequiresSanitization:
		b = append(b, "raw evidence is sensitive and sanitized evidence is absent")
		a = append(a, "sanitize copies into sanitized/ without modifying raw/")
	case RequiresManualReview:
		if !m.Review.MetadataReviewed {
			b = append(b, "metadata review is incomplete")
		}
		if !m.Review.BinaryReviewed {
			b = append(b, "binary review is incomplete")
		}
		if !m.Review.LeakageChecksPassed {
			b = append(b, "leakage checks are incomplete")
		}
		a = append(a, "inspect binary and log evidence", "record manual review after sensitive content is removed")
	case ReviewFailed:
		b = append(b, "operator review is marked failed")
		a = append(a, "remove or safely transform unresolved sensitive content and repeat review")
	case ReadyForImport:
		a = append(a, "run cinderpath capture guided-import --kit <kit>")
	case Imported:
		b = append(b, "import does not imply evidence-bundle approval")
		a = append(a, "approve capture-evidence export only after review and leakage checks")
	case ReadyForEvidenceBundle:
		a = append(a, "export a dedicated capture-evidence bundle")
	case EvidenceBundleExported:
		a = append(a, "inspect or sign the capture-evidence bundle; integrity does not imply protocol approval")
	}
	return b, a
}
func inventory(root, sub string, v *Validation) []File {
	var out []File
	_ = filepath.WalkDir(filepath.Join(root, sub), func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			v.Errors = append(v.Errors, e.Error())
			return nil
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), ".") || d.Name() == "README.txt" {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if !safeRelative(rel) {
			v.Errors = append(v.Errors, "unsafe path: "+rel)
			return nil
		}
		lower := strings.ToLower(d.Name())
		if strings.HasSuffix(lower, ".key") || strings.HasSuffix(lower, ".pfx") || strings.HasSuffix(lower, ".p12") || strings.Contains(lower, "replacement") || strings.Contains(lower, "secrets") {
			v.Errors = append(v.Errors, "prohibited sensitive file: "+rel)
		}
		f, e := os.Open(p)
		if e != nil {
			return nil
		}
		h := sha256.New()
		n, _ := io.CopyN(h, f, 64<<20)
		_ = f.Close()
		st, _ := d.Info()
		out = append(out, File{Path: rel, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n, Kind: classify(lower), ModifiedAt: st.ModTime().UTC().Format(time.RFC3339)})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
func classify(n string) string {
	switch filepath.Ext(n) {
	case ".har":
		return "har"
	case ".pcap":
		return "pcap"
	case ".pcapng":
		return "pcapng"
	case ".json":
		return "normalized_json"
	case ".log":
		return "windows_log"
	case ".etl":
		return "event_trace"
	}
	return "unsupported"
}
