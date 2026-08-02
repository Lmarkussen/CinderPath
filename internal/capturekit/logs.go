package capturekit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const LogInspectorVersion = "windows-log-structural-v1"

func DefaultLogLimits() LogLimits {
	return LogLimits{MaxFiles: 64, MaxBytesPerFile: 8 << 20, MaxTotalBytes: 32 << 20, MaxLines: 100000, MaxLineLength: 16384, MaxObservations: 4096}
}

var logPatterns = []struct {
	category, class, confidence, reason string
	re                                  *regexp.Regexp
}{
	{"timestamp", "observed", "high", "timestamp-like prefix", regexp.MustCompile(`(?i)^\s*(?:<!\[LOG\[)?(?:\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}|\d{2}:\d{2}:\d{2})`)},
	{"severity", "heuristic", "medium", "severity-like token", regexp.MustCompile(`(?i)\b(error|warning|warn|fatal|info|debug|failed)\b`)},
	{"url", "redacted_sensitive", "high", "URL-like identifier", regexp.MustCompile(`(?i)https?://[^\s<>"']+`)},
	{"ipv4", "redacted_sensitive", "medium", "IPv4-like identifier", regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)},
	{"ipv6", "redacted_sensitive", "low", "IPv6-like identifier", regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b`)},
	{"guid", "redacted_sensitive", "high", "GUID-like identifier", regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)},
	{"sid", "redacted_sensitive", "high", "SID-like identifier", regexp.MustCompile(`(?i)\bS-1-(?:\d+-){1,14}\d+\b`)},
	{"unc_path", "redacted_sensitive", "high", "UNC path", regexp.MustCompile(`\\\\[^\\\s]+\\[^\s]+`)},
	{"windows_path", "redacted_sensitive", "medium", "Windows path", regexp.MustCompile(`(?i)\b[A-Z]:\\[^\r\n<>"|?*]+`)},
	{"http_status", "observed", "medium", "HTTP status-like value", regexp.MustCompile(`(?i)\bHTTP(?:/\d(?:\.\d)?)?\s+[1-5]\d\d\b`)},
	{"thread_or_process", "heuristic", "low", "thread/process identifier", regexp.MustCompile(`(?i)\b(?:thread|pid|process)\s*[=:]\s*\d+\b`)},
	{"component", "heuristic", "low", "component/source prefix", regexp.MustCompile(`^\s*\[[A-Za-z0-9_.-]{1,64}\]`)},
	{"site_code", "heuristic", "low", "short uppercase identifier; not confirmed as an SCCM site", regexp.MustCompile(`\b[A-Z][A-Z0-9]{2}\b`)},
}
var sensitiveLine = regexp.MustCompile(`(?i)(authorization\s*:|proxy-authorization\s*:|bearer\s+|set-cookie\s*:|cookie\s*:|-----BEGIN [A-Z ]*PRIVATE KEY-----)`)
var passwordLike = regexp.MustCompile(`(?i)\b(pass(word)?|pwd)\s*[=:]`)

func InspectLogs(dir string, now time.Time, limits LogLimits) (LogInspection, error) {
	if limits.MaxFiles <= 0 || limits.MaxBytesPerFile <= 0 || limits.MaxTotalBytes <= 0 || limits.MaxLines <= 0 || limits.MaxLineLength <= 0 || limits.MaxObservations <= 0 {
		return LogInspection{}, errors.New("invalid log inspection limits")
	}
	v, e := Validate(dir)
	if e != nil {
		return LogInspection{}, e
	}
	if v.State == Invalid {
		return LogInspection{}, errors.New("cannot inspect logs in invalid kit")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	r := LogInspection{SchemaVersion: 1, KitID: v.KitID, InspectorVersion: LogInspectorVersion, InspectedAt: now.UTC()}
	var paths []string
	for _, root := range []string{"raw", "sanitized"} {
		_ = filepath.WalkDir(filepath.Join(dir, root), func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				r.Warnings = append(r.Warnings, "symlink rejected: "+d.Name())
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if strings.EqualFold(filepath.Ext(d.Name()), ".log") {
				paths = append(paths, p)
			}
			return nil
		})
	}
	sort.Strings(paths)
	if len(paths) > limits.MaxFiles {
		paths = paths[:limits.MaxFiles]
		r.Truncated = true
		r.Warnings = append(r.Warnings, "log file limit reached")
	}
	var total int64
	lines := 0
	for _, p := range paths {
		st, e := os.Lstat(p)
		if e != nil || !st.Mode().IsRegular() {
			continue
		}
		if total >= limits.MaxTotalBytes {
			r.Truncated = true
			break
		}
		max := limits.MaxBytesPerFile
		if remain := limits.MaxTotalBytes - total; remain < max {
			max = remain
		}
		b, e := readBounded(p, max)
		if e != nil {
			return r, e
		}
		total += int64(len(b))
		enc, text, opaque := decodeLog(b)
		sum := sha256.Sum256(b)
		rel, _ := filepath.Rel(dir, p)
		lf := LogFileInspection{LogFileID: stable("log_file", v.KitID, rel, hex.EncodeToString(sum[:])), KitID: v.KitID, SafeName: filepath.Base(rel), Encoding: enc, Size: st.Size(), SHA256: hex.EncodeToString(sum[:]), InspectedAt: now.UTC(), InspectorVersion: LogInspectorVersion}
		if st.Size() > int64(len(b)) {
			lf.Truncated = true
			lf.Warnings = append(lf.Warnings, "file byte limit reached")
		}
		if opaque {
			lf.Classification = "unsupported"
			lf.Warnings = append(lf.Warnings, "opaque binary log")
			r.Files = append(r.Files, lf)
			continue
		}
		lf.Classification = "observed"
		rawLines := strings.Split(text, "\n")
		for i, line := range rawLines {
			if lines >= limits.MaxLines || len(r.Observations) >= limits.MaxObservations {
				lf.Truncated = true
				r.Truncated = true
				break
			}
			lines++
			lf.LinesInspected++
			if len(line) > limits.MaxLineLength {
				line = line[:limits.MaxLineLength]
				lf.Truncated = true
				addObs(&r, &lf, i+1, "line", "truncated", "[line truncated]", "high", "line length limit reached")
				continue
			}
			inspectLine(&r, &lf, i+1, line)
		}
		r.Files = append(r.Files, lf)
	}
	sort.Slice(r.Observations, func(i, j int) bool {
		if r.Observations[i].LogFileID == r.Observations[j].LogFileID {
			return r.Observations[i].ObservationID < r.Observations[j].ObservationID
		}
		return r.Observations[i].LogFileID < r.Observations[j].LogFileID
	})
	return r, nil
}
func readBounded(p string, max int64) ([]byte, error) {
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}
func decodeLog(b []byte) (string, string, bool) {
	if bytes.HasPrefix(b, []byte{0xff, 0xfe}) {
		return "utf-16le", decode16(b[2:], binary.LittleEndian), false
	}
	if bytes.HasPrefix(b, []byte{0xfe, 0xff}) {
		return "utf-16be", decode16(b[2:], binary.BigEndian), false
	}
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return "binary", "", true
	}
	return "utf-8", string(b), false
}
func decode16(b []byte, order binary.ByteOrder) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = order.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}
func inspectLine(r *LogInspection, f *LogFileInspection, n int, line string) {
	if sensitiveLine.MatchString(line) {
		r.SensitiveIndicators++
		addObs(r, f, n, "sensitive_indicator", "redacted_sensitive", "[sensitive value redacted]", "high", "authorization, token, cookie, or private-key marker")
		return
	}
	if passwordLike.MatchString(line) {
		addObs(r, f, n, "password_like_field", "heuristic", "[password-like field; value not recovered]", "low", "generic text is not structured secret evidence")
	}
	for _, p := range logPatterns {
		if m := p.re.FindString(line); m != "" {
			preview := p.category + ":" + shortFingerprint(m)
			addObs(r, f, n, p.category, p.class, preview, p.confidence, p.reason)
		}
	}
}
func addObs(r *LogInspection, f *LogFileInspection, line int, cat, class, preview, confidence, reason string) {
	fp := shortFingerprint(fmt.Sprintf("%s\x00%d\x00%s\x00%s", f.LogFileID, line, cat, preview))
	o := LogObservation{ObservationID: "log_observation_" + fp[:16], LogFileID: f.LogFileID, LineNumber: line, Category: cat, Classification: class, RedactedPreview: preview, Fingerprint: fp, Confidence: confidence, Reason: reason}
	r.Observations = append(r.Observations, o)
	f.ObservationCount++
}
func shortFingerprint(v string) string {
	s := sha256.Sum256([]byte(v))
	return hex.EncodeToString(s[:])
}
func stable(prefix string, parts ...string) string {
	return prefix + "_" + shortFingerprint(strings.Join(parts, "\x00"))[:16]
}
