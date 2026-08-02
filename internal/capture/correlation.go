package capture

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const CorrelationAlgorithmVersion = "capture-correlation-v1"

const (
	MaxTimelineEvents  = 10000
	MaxCorrelationLogs = 32
	MaxLogBytes        = 8 << 20
	MaxLogLineBytes    = 16 << 10
)

type TimelineEvent struct {
	EventID                  string    `json:"event_id"`
	SourceType               string    `json:"source_type"`
	SourceID                 string    `json:"source_id"`
	Timestamp                time.Time `json:"timestamp,omitempty"`
	OriginalTimezone         string    `json:"original_timezone,omitempty"`
	TimestampPrecision       string    `json:"timestamp_precision"`
	SequenceIndex            int       `json:"sequence_index"`
	Category                 string    `json:"category"`
	RedactedSummary          string    `json:"redacted_summary"`
	EndpointFingerprint      string    `json:"endpoint_fingerprint,omitempty"`
	CorrelationIDFingerprint string    `json:"correlation_id_fingerprint,omitempty"`
	Confidence               string    `json:"confidence"`
	EvidenceRefs             []string  `json:"evidence_refs,omitempty"`
	Warnings                 []string  `json:"warnings,omitempty"`
}

type SemanticLogEvent struct {
	EventID                    string    `json:"event_id"`
	SafeName                   string    `json:"safe_name"`
	Component                  string    `json:"component,omitempty"`
	ThreadID                   string    `json:"thread_id,omitempty"`
	MessageTemplateFingerprint string    `json:"message_template_fingerprint"`
	Timestamp                  time.Time `json:"timestamp,omitempty"`
	OriginalTimezone           string    `json:"original_timezone,omitempty"`
	TimestampPrecision         string    `json:"timestamp_precision"`
	EndpointFingerprint        string    `json:"endpoint_fingerprint,omitempty"`
	CorrelationIDFingerprint   string    `json:"correlation_id_fingerprint,omitempty"`
	SemanticState              string    `json:"semantic_state"`
	Confidence                 string    `json:"confidence"`
	Reason                     string    `json:"reason"`
	SupportingFixture          string    `json:"supporting_fixture,omitempty"`
	LineNumber                 int       `json:"line_number"`
	Warnings                   []string  `json:"warnings,omitempty"`
}

type Trigger struct {
	SchemaVersion int       `json:"schema_version"`
	Timestamp     time.Time `json:"timestamp"`
	Action        string    `json:"action"`
	SourceID      string    `json:"source_id,omitempty"`
}

type CorrelationWindow struct {
	PreTrigger  time.Duration
	PostTrigger time.Duration
	Maximum     time.Duration
}

func DefaultCorrelationWindow() CorrelationWindow {
	return CorrelationWindow{PreTrigger: 30 * time.Second, PostTrigger: 180 * time.Second, Maximum: 15 * time.Minute}
}

type TLSFlowCandidate struct {
	CandidateID           string   `json:"candidate_id"`
	FlowID                string   `json:"flow_id"`
	Score                 int      `json:"score"`
	Confidence            string   `json:"confidence"`
	SupportingEvidence    []string `json:"supporting_evidence"`
	ContradictingEvidence []string `json:"contradicting_evidence"`
	Warnings              []string `json:"warnings,omitempty"`
}

type CaptureQuality struct {
	PacketCount            int      `json:"packet_count"`
	FlowCount              int      `json:"flow_count"`
	TCPSegmentCount        int      `json:"tcp_segment_count"`
	MissingRangeCount      int      `json:"missing_range_count"`
	RetransmissionCount    int      `json:"retransmission_count"`
	OverlapConflictCount   int      `json:"overlap_conflict_count"`
	TruncatedPacketCount   int      `json:"truncated_packet_count"`
	SnapLength             uint32   `json:"snap_length"`
	LinkTypes              []uint16 `json:"link_types"`
	ReportedDrops          *int     `json:"reported_drops,omitempty"`
	ReassemblyCompleteness string   `json:"reassembly_completeness"`
	DirectionConfidence    string   `json:"direction_confidence"`
	TimestampResolution    string   `json:"timestamp_resolution"`
	Classification         string   `json:"classification"`
	Warnings               []string `json:"warnings,omitempty"`
}

type CorrelationResult struct {
	SchemaVersion      int                `json:"schema_version"`
	AlgorithmVersion   string             `json:"algorithm_version"`
	Trigger            Trigger            `json:"trigger"`
	Window             map[string]string  `json:"window"`
	Timeline           []TimelineEvent    `json:"timeline"`
	LogEvents          []SemanticLogEvent `json:"log_events"`
	Candidates         []TLSFlowCandidate `json:"tls_flow_candidates"`
	Quality            CaptureQuality     `json:"capture_quality"`
	Classification     string             `json:"classification"`
	Findings           []ResearchFinding  `json:"findings"`
	Capabilities       []string           `json:"capabilities"`
	Warnings           []string           `json:"warnings"`
	LivePolicyRequests int                `json:"live_policy_requests"`
}

var (
	cmTrace       = regexp.MustCompile(`^<!\[LOG\[(.*?)\]LOG\]!><time="([0-9:.]+)([+-][0-9]+)?" date="([0-9-]+)" component="([^"]*)"[^>]*thread="([^"]*)"`)
	isoLog        = regexp.MustCompile(`^\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)\s*(?:\[([^]]+)\])?\s*(.*)$`)
	urlHint       = regexp.MustCompile(`(?i)https?://([^/\s<>"]+)`)
	guidHint      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	spaceRun      = regexp.MustCompile(`\s+`)
	safeAction    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	safeComponent = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	safeThread    = regexp.MustCompile(`^[0-9]{1,16}$`)
)

func ParseSemanticLogLine(safeName string, lineNumber int, line string) (SemanticLogEvent, bool) {
	if len(line) > MaxLogLineBytes {
		return SemanticLogEvent{}, false
	}
	var e SemanticLogEvent
	var msg string
	if m := cmTrace.FindStringSubmatch(line); m != nil {
		msg, e.Component, e.ThreadID = m[1], safeMetadata(m[5], safeComponent, "component"), safeMetadata(m[6], safeThread, "thread")
		t, zone, precision, err := parseCMTraceTime(m[4], m[2], m[3])
		if err != nil {
			e.Warnings = append(e.Warnings, "malformed timestamp")
		} else {
			e.Timestamp, e.OriginalTimezone, e.TimestampPrecision = t, zone, precision
		}
	} else if m := isoLog.FindStringSubmatch(line); m != nil {
		msg, e.Component = m[3], safeMetadata(m[2], safeComponent, "component")
		t, err := parseFlexibleTime(m[1])
		if err != nil {
			return SemanticLogEvent{}, false
		}
		e.Timestamp, e.OriginalTimezone, e.TimestampPrecision = t.UTC(), timezoneOf(t), precisionOf(m[1])
	} else {
		return SemanticLogEvent{}, false
	}
	e.SafeName, e.LineNumber = redactedLogName(safeName), lineNumber
	normalized := normalizeTemplate(msg)
	e.MessageTemplateFingerprint = shortHash(normalized)
	if m := urlHint.FindStringSubmatch(msg); m != nil {
		e.EndpointFingerprint = shortHash(strings.ToLower(m[1]))
	}
	if m := guidHint.FindString(msg); m != "" {
		e.CorrelationIDFingerprint = shortHash(strings.ToLower(m))
	}
	lower := asciiLower(msg)
	switch {
	case strings.Contains(lower, "requesting machine policy assignments") || strings.Contains(lower, "request machine policy assignments"):
		e.SemanticState, e.Confidence, e.Reason, e.SupportingFixture = "machine_policy_assignment_request", "high", "fixture-supported machine-policy assignment request marker", "synthetic-cmtrace-machine-policy-v1"
	case strings.Contains(lower, "no new assignments"):
		e.SemanticState, e.Confidence, e.Reason, e.SupportingFixture = "machine_policy_no_new_assignments", "high", "fixture-supported no-new-assignments marker", "synthetic-cmtrace-machine-policy-v1"
	case strings.Contains(lower, "sending message") || strings.Contains(lower, "message send started"):
		e.SemanticState, e.Confidence, e.Reason, e.SupportingFixture = "message_send_started", "medium", "fixture-supported generic message-send marker", "synthetic-cmtrace-messaging-v1"
	case strings.Contains(lower, "message sent") || strings.Contains(lower, "send completed"):
		e.SemanticState, e.Confidence, e.Reason, e.SupportingFixture = "message_send_completed", "medium", "fixture-supported generic completion marker", "synthetic-cmtrace-messaging-v1"
	case strings.Contains(lower, "response received") || strings.Contains(lower, "received reply"):
		e.SemanticState, e.Confidence, e.Reason, e.SupportingFixture = "message_response_received", "medium", "fixture-supported generic response marker", "synthetic-cmtrace-messaging-v1"
	default:
		e.SemanticState, e.Confidence, e.Reason = "unknown_policy_event", "low", "timestamped structure observed; no fixture-supported semantic marker"
	}
	e.EventID = stableID("logevent", e.SafeName, strconv.Itoa(lineNumber), e.Timestamp.Format(time.RFC3339Nano), e.MessageTemplateFingerprint)
	return e, true
}

func parseCMTraceTime(date, clock, offset string) (time.Time, string, string, error) {
	parts := strings.Split(clock, ".")
	base, err := time.Parse("01-02-2006 15:04:05", date+" "+parts[0])
	if err != nil {
		return time.Time{}, "", "", err
	}
	precision := "second"
	nanos := 0
	if len(parts) == 2 {
		precision = precisionDigits(len(parts[1]))
		frac := parts[1]
		if len(frac) > 9 {
			frac = frac[:9]
		}
		frac += strings.Repeat("0", 9-len(frac))
		nanos, _ = strconv.Atoi(frac)
	}
	zone := "local_unspecified"
	if offset != "" {
		minutes, err := strconv.Atoi(offset)
		if err != nil {
			return time.Time{}, "", "", err
		}
		zone = fmt.Sprintf("%+03d:%02d", minutes/60, abs(minutes%60))
		base = time.Date(base.Year(), base.Month(), base.Day(), base.Hour(), base.Minute(), base.Second(), nanos, time.FixedZone(zone, minutes*60))
	} else {
		base = time.Date(base.Year(), base.Month(), base.Day(), base.Hour(), base.Minute(), base.Second(), nanos, time.UTC)
	}
	return base.UTC(), zone, precision, nil
}

func parseFlexibleTime(v string) (time.Time, error) {
	v = strings.Replace(v, " ", "T", 1)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05"} {
		if t, e := time.Parse(layout, v); e == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("unsupported timestamp")
}
func precisionOf(v string) string {
	if i := strings.IndexByte(v, '.'); i >= 0 {
		n := 0
		for _, c := range v[i+1:] {
			if c < '0' || c > '9' {
				break
			}
			n++
		}
		return precisionDigits(n)
	}
	return "second"
}
func precisionDigits(n int) string {
	switch {
	case n >= 9:
		return "nanosecond"
	case n >= 6:
		return "microsecond"
	case n >= 3:
		return "millisecond"
	default:
		return "fractional_second"
	}
}
func timezoneOf(t time.Time) string {
	_, n := t.Zone()
	sign := "+"
	if n < 0 {
		sign = "-"
		n = -n
	}
	return fmt.Sprintf("%s%02d:%02d", sign, n/3600, n%3600/60)
}
func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
func boundText(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}
func safeMetadata(v string, re *regexp.Regexp, prefix string) string {
	if v == "" {
		return ""
	}
	if re.MatchString(v) {
		return v
	}
	return prefix + ":" + shortHash(v)
}
func redactedLogName(v string) string {
	base := filepath.Base(v)
	switch strings.ToLower(base) {
	case "ccmmessaging.log", "policyagent.log", "synthetic.log":
		return base
	}
	return "log_" + shortHash(base) + ".log"
}
func redactWarnings(xs []string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, redactWarning(x))
	}
	return out
}
func redactWarning(v string) string {
	if v == "" {
		return ""
	}
	for _, prefix := range []string{"missing TCP segment bytes", "conflicting overlapping TCP segment", "duplicate retransmitted TCP segment", "out-of-order TCP segment observed", "opaque TLS stream", "malformed or incomplete visible HTTP", "unsupported pcap", "unsupported pcapng", "truncated", "packet exceeds"} {
		if strings.HasPrefix(v, prefix) {
			return boundText(v, 256)
		}
	}
	return "warning:" + shortHash(v)
}
func shortHash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:8]) }
func asciiLower(v string) string {
	b := []byte(v)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
func normalizeTemplate(v string) string {
	v = guidHint.ReplaceAllString(v, "<guid>")
	v = urlHint.ReplaceAllString(v, "https://<endpoint>")
	return boundText(spaceRun.ReplaceAllString(strings.TrimSpace(v), " "), 512)
}

func ReadSemanticLogs(dir string) ([]SemanticLogEvent, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	var names []string
	for _, x := range entries {
		if !x.IsDir() && x.Type()&os.ModeSymlink == 0 && strings.EqualFold(filepath.Ext(x.Name()), ".log") {
			names = append(names, x.Name())
		}
	}
	sort.Strings(names)
	warnings := []string{}
	if len(names) > MaxCorrelationLogs {
		names = names[:MaxCorrelationLogs]
		warnings = append(warnings, "log file limit reached")
	}
	var out []SemanticLogEvent
	for _, name := range names {
		f, e := os.Open(filepath.Join(dir, name))
		if e != nil {
			return nil, warnings, e
		}
		b, e := io.ReadAll(io.LimitReader(f, MaxLogBytes+1))
		_ = f.Close()
		if e != nil {
			return nil, warnings, e
		}
		if len(b) > MaxLogBytes {
			b = b[:MaxLogBytes]
			warnings = append(warnings, "log byte limit reached: "+filepath.Base(name))
		}
		text, ok := decodeSemanticLog(b)
		if !ok {
			warnings = append(warnings, "unsupported binary log: "+filepath.Base(name))
			continue
		}
		s := bufio.NewScanner(strings.NewReader(text))
		s.Buffer(make([]byte, 4096), MaxLogLineBytes)
		line := 0
		for s.Scan() {
			line++
			if e, ok := ParseSemanticLogLine(name, line, s.Text()); ok {
				out = append(out, e)
				if len(out) >= MaxTimelineEvents {
					warnings = append(warnings, "event limit reached")
					break
				}
			}
		}
		if e := s.Err(); e != nil {
			warnings = append(warnings, "oversized or malformed line in "+filepath.Base(name))
		}
	}
	return out, warnings, nil
}

func decodeSemanticLog(b []byte) (string, bool) {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		return decodeSemanticUTF16(b[2:], binary.LittleEndian), true
	}
	if len(b) >= 2 && b[0] == 0xfe && b[1] == 0xff {
		return decodeSemanticUTF16(b[2:], binary.BigEndian), true
	}
	if !utf8.Valid(b) || strings.IndexByte(string(b), 0) >= 0 {
		return "", false
	}
	return string(b), true
}
func decodeSemanticUTF16(b []byte, o binary.ByteOrder) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = o.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func Correlate(c NormalizedCapture, logs []SemanticLogEvent, trigger Trigger, w CorrelationWindow) (CorrelationResult, error) {
	if trigger.Timestamp.IsZero() {
		return CorrelationResult{}, errors.New("trigger timestamp is required")
	}
	if !safeAction.MatchString(trigger.Action) {
		return CorrelationResult{}, errors.New("trigger action must be a bounded safe label")
	}
	if w.PreTrigger < 0 || w.PostTrigger <= 0 || w.Maximum <= 0 || w.PreTrigger+w.PostTrigger > w.Maximum {
		return CorrelationResult{}, errors.New("invalid correlation window")
	}
	trigger.Timestamp = trigger.Timestamp.UTC()
	trigger.SourceID = safeMetadata(trigger.SourceID, safeAction, "source")
	logsTruncated := false
	if len(logs) > MaxTimelineEvents/2 {
		logs = logs[:MaxTimelineEvents/2]
		logsTruncated = true
	}
	r := CorrelationResult{SchemaVersion: 1, AlgorithmVersion: CorrelationAlgorithmVersion, Trigger: trigger, Window: map[string]string{"pre_trigger": w.PreTrigger.String(), "post_trigger": w.PostTrigger.String(), "maximum": w.Maximum.String()}, LogEvents: logs, LivePolicyRequests: 0}
	if logsTruncated {
		r.Warnings = append(r.Warnings, "semantic log event limit reached")
	}
	r.Timeline = append(r.Timeline, TimelineEvent{EventID: stableID("event", "trigger", trigger.Timestamp.Format(time.RFC3339Nano)), SourceType: "policy_trigger", SourceID: trigger.SourceID, Timestamp: trigger.Timestamp, TimestampPrecision: "nanosecond", Category: trigger.Action, RedactedSummary: "controlled local client action", Confidence: "high"})
	for _, x := range logs {
		if len(r.Timeline) >= MaxTimelineEvents/2 {
			r.Warnings = append(r.Warnings, "log timeline event limit reached")
			break
		}
		r.Timeline = append(r.Timeline, TimelineEvent{EventID: x.EventID, SourceType: "log_event", SourceID: x.SafeName, Timestamp: x.Timestamp.UTC(), OriginalTimezone: x.OriginalTimezone, TimestampPrecision: x.TimestampPrecision, Category: x.SemanticState, RedactedSummary: x.SemanticState, EndpointFingerprint: x.EndpointFingerprint, CorrelationIDFingerprint: x.CorrelationIDFingerprint, Confidence: x.Confidence, EvidenceRefs: []string{x.MessageTemplateFingerprint}, Warnings: x.Warnings})
	}
	for _, p := range c.Packets {
		if len(r.Timeline) >= MaxTimelineEvents-1000 {
			r.Warnings = append(r.Warnings, "packet timeline event limit reached")
			break
		}
		r.Timeline = append(r.Timeline, TimelineEvent{EventID: stableID("event", p.ID), SourceType: "packet", SourceID: p.ID, Timestamp: p.Timestamp.UTC(), TimestampPrecision: interfacePrecision(c.Interfaces, p.InterfaceID), SequenceIndex: p.Index, Category: "packet_metadata", RedactedSummary: fmt.Sprintf("captured=%d original=%d", p.CapturedLength, p.OriginalLength), Confidence: "high", Warnings: compactStrings(redactWarning(p.Warning))})
	}
	for _, f := range c.Flows {
		if len(r.Timeline) >= MaxTimelineEvents-3 {
			r.Warnings = append(r.Warnings, "flow timeline event limit reached")
			break
		}
		r.Timeline = append(r.Timeline, TimelineEvent{EventID: stableID("event", f.ID, "start"), SourceType: "flow_start", SourceID: f.ID, Timestamp: f.StartedAt.UTC(), TimestampPrecision: "capture_interface", Category: tlsCategory(f), RedactedSummary: "redacted TCP flow start", Confidence: f.DirectionConfidence, Warnings: redactWarnings(f.Warnings)})
		if !f.EndedAt.IsZero() {
			r.Timeline = append(r.Timeline, TimelineEvent{EventID: stableID("event", f.ID, "end"), SourceType: "flow_end", SourceID: f.ID, Timestamp: f.EndedAt.UTC(), TimestampPrecision: "capture_interface", Category: tlsCategory(f), RedactedSummary: "redacted TCP flow end", Confidence: f.DirectionConfidence})
		}
		if f.TLS {
			r.Timeline = append(r.Timeline, TimelineEvent{EventID: stableID("event", f.ID, "tls"), SourceType: "tls_session", SourceID: f.ID, Timestamp: f.StartedAt.UTC(), TimestampPrecision: "capture_interface", Category: "opaque_tls", RedactedSummary: "opaque TLS metadata", EndpointFingerprint: f.SNI, Confidence: "medium", Warnings: []string{"payload not visible"}})
		}
	}
	for _, x := range c.Exchanges {
		if len(r.Timeline) >= MaxTimelineEvents {
			r.Warnings = append(r.Warnings, "exchange timeline event limit reached")
			break
		}
		r.Timeline = append(r.Timeline, TimelineEvent{EventID: stableID("event", x.ID), SourceType: "http_exchange", SourceID: x.ID, Timestamp: x.StartedAt.UTC(), TimestampPrecision: "capture_interface", SequenceIndex: x.Index, Category: safeMetadata(x.State, safeAction, "state"), RedactedSummary: "redacted HTTP exchange metadata", Confidence: safeMetadata(x.AssociationConfidence, safeAction, "confidence"), Warnings: redactWarnings(x.Ambiguities)})
	}
	for i, warn := range c.Source.Warnings {
		if len(r.Timeline) >= MaxTimelineEvents {
			r.Warnings = append(r.Warnings, "warning timeline event limit reached")
			break
		}
		safe := redactWarning(warn)
		r.Timeline = append(r.Timeline, TimelineEvent{EventID: stableID("event", "warning", strconv.Itoa(i), safe), SourceType: "capture_warning", SourceID: c.Source.ID, SequenceIndex: i, Category: "capture_warning", RedactedSummary: safe, Confidence: "high"})
	}
	if len(r.Timeline) > MaxTimelineEvents {
		r.Timeline = r.Timeline[:MaxTimelineEvents]
		r.Warnings = append(r.Warnings, "timeline event limit reached")
	}
	SortTimeline(r.Timeline)
	r.Quality = AssessCaptureQuality(c)
	r.Candidates = scoreTLSCandidates(c.Flows, logs, trigger, w, r.Quality)
	r.Classification = classifyCandidates(r.Candidates, r.Quality)
	r.Findings = correlationFindings(logs, r)
	r.Capabilities = []string{"capture_timeline_correlation_available", "sccm_log_semantic_events_available", "opaque_tls_flow_attribution_available", "pktmon_capture_quality_assessment_available", "live_policy_collection_blocked"}
	return r, nil
}

func SortTimeline(xs []TimelineEvent) {
	sort.SliceStable(xs, func(i, j int) bool {
		a, b := xs[i], xs[j]
		if a.Timestamp.IsZero() != b.Timestamp.IsZero() {
			return !a.Timestamp.IsZero()
		}
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.Before(b.Timestamp)
		}
		if a.SequenceIndex != b.SequenceIndex {
			return a.SequenceIndex < b.SequenceIndex
		}
		return a.EventID < b.EventID
	})
}
func interfacePrecision(xs []Interface, id int) string {
	for _, x := range xs {
		if x.ID == id {
			if x.TimestampResolution == 0 {
				return "unknown"
			}
			return fmt.Sprintf("1/%d_second", x.TimestampResolution)
		}
	}
	return "unknown"
}
func compactStrings(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}
func tlsCategory(f Flow) string {
	if f.TLS {
		return "tls_session"
	}
	return "tcp_flow"
}

func scoreTLSCandidates(flows []Flow, logs []SemanticLogEvent, t Trigger, w CorrelationWindow, q CaptureQuality) []TLSFlowCandidate {
	endpoints := map[string]bool{}
	for _, x := range logs {
		if x.EndpointFingerprint != "" {
			endpoints[x.EndpointFingerprint] = true
		}
	}
	var out []TLSFlowCandidate
	for _, f := range flows {
		if !f.TLS {
			continue
		}
		c := TLSFlowCandidate{FlowID: f.ID}
		delta := f.StartedAt.Sub(t.Timestamp)
		if delta < -w.PreTrigger || delta > w.PostTrigger {
			c.ContradictingEvidence = append(c.ContradictingEvidence, "flow start outside trigger window")
		} else {
			d := absDuration(delta)
			switch {
			case d <= 2*time.Second:
				c.Score += 35
				c.SupportingEvidence = append(c.SupportingEvidence, "flow activity within 2 seconds of trigger")
			case d <= 10*time.Second:
				c.Score += 25
				c.SupportingEvidence = append(c.SupportingEvidence, "flow activity within 10 seconds of trigger")
			case d <= 60*time.Second:
				c.Score += 10
				c.SupportingEvidence = append(c.SupportingEvidence, "flow activity within 60 seconds of trigger")
			}
		}
		if f.SNI != "" && endpoints[f.SNI] {
			c.Score += 35
			c.SupportingEvidence = append(c.SupportingEvidence, "TLS endpoint fingerprint matches log-derived endpoint")
		}
		if f.Client.Port == 443 || f.Server.Port == 443 {
			c.Score += 5
			c.SupportingEvidence = append(c.SupportingEvidence, "TLS flow uses a common HTTPS port; non-specific supporting evidence")
		}
		if f.StartedAt.IsZero() {
			c.Warnings = append(c.Warnings, "flow timestamp unavailable")
		}
		if f.Gaps > 0 || f.Conflicts > 0 {
			c.Score -= 10
			c.Warnings = append(c.Warnings, "partial reconstruction reduces confidence")
		}
		if q.Classification == "insufficient_for_flow_attribution" {
			c.Score -= 20
			c.Warnings = append(c.Warnings, "capture quality insufficient for confident attribution")
		}
		if c.Score < 0 {
			c.Score = 0
		}
		if c.Score > 100 {
			c.Score = 100
		}
		switch {
		case c.Score >= 70:
			c.Confidence = "high"
		case c.Score >= 40:
			c.Confidence = "medium"
		default:
			c.Confidence = "low"
		}
		independent := false
		for _, e := range c.SupportingEvidence {
			if strings.Contains(e, "matches log-derived endpoint") {
				independent = true
			}
		}
		if !independent {
			c.Confidence = "low"
			c.Warnings = append(c.Warnings, "timing alone cannot establish SCCM protocol identity; common ports are non-specific")
		}
		c.CandidateID = stableID("tls_candidate", f.ID, t.Timestamp.Format(time.RFC3339Nano))
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].CandidateID < out[j].CandidateID
	})
	return out
}
func absDuration(v time.Duration) time.Duration {
	if v < 0 {
		return -v
	}
	return v
}
func classifyCandidates(cs []TLSFlowCandidate, q CaptureQuality) string {
	if q.Classification == "invalid_capture" || q.Classification == "insufficient_for_flow_attribution" {
		return "insufficient_capture_quality"
	}
	if len(cs) == 0 {
		return "no_correlatable_tls_flow"
	}
	if len(cs) > 1 && cs[0].Score == cs[1].Score {
		return "multiple_indistinguishable_candidates"
	}
	switch cs[0].Confidence {
	case "high":
		return "high_confidence_sccm_tls_candidate"
	case "medium":
		return "medium_confidence_sccm_tls_candidate"
	default:
		return "low_confidence_sccm_tls_candidate"
	}
}

func AssessCaptureQuality(c NormalizedCapture) CaptureQuality {
	return AssessCaptureQualityWithDrops(c, nil)
}

func AssessCaptureQualityWithDrops(c NormalizedCapture, reportedDrops *int) CaptureQuality {
	q := CaptureQuality{PacketCount: len(c.Packets), FlowCount: len(c.Flows), TimestampResolution: "unknown"}
	q.ReportedDrops = reportedDrops
	dirs := map[string]int{}
	links := map[uint16]bool{}
	for _, i := range c.Interfaces {
		links[i.LinkType] = true
		if q.SnapLength == 0 || i.SnapLength < q.SnapLength {
			q.SnapLength = i.SnapLength
		}
		if i.TimestampResolution > 0 {
			q.TimestampResolution = fmt.Sprintf("1/%d second", i.TimestampResolution)
		}
	}
	for x := range links {
		q.LinkTypes = append(q.LinkTypes, x)
	}
	sort.Slice(q.LinkTypes, func(i, j int) bool { return q.LinkTypes[i] < q.LinkTypes[j] })
	for _, p := range c.Packets {
		if p.Truncated {
			q.TruncatedPacketCount++
		}
	}
	for _, f := range c.Flows {
		q.TCPSegmentCount += len(f.PacketIDs)
		q.MissingRangeCount += f.Gaps
		q.RetransmissionCount += f.Retransmissions
		q.OverlapConflictCount += f.Conflicts
		dirs[f.DirectionConfidence]++
	}
	q.DirectionConfidence = "unknown"
	for _, x := range []string{"low", "medium", "high"} {
		if dirs[x] > 0 {
			q.DirectionConfidence = x
			break
		}
	}
	if q.FlowCount == 0 {
		q.ReassemblyCompleteness = "none"
	} else if q.MissingRangeCount > 0 || q.OverlapConflictCount > 0 {
		q.ReassemblyCompleteness = "partial"
	} else {
		q.ReassemblyCompleteness = "complete"
	}
	switch {
	case q.PacketCount == 0:
		q.Classification = "invalid_capture"
	case len(q.LinkTypes) == 0 || containsUnsupported(c.Interfaces):
		q.Classification = "insufficient_for_flow_attribution"
	case q.TruncatedPacketCount > 0 || q.MissingRangeCount > 0 || q.OverlapConflictCount > 0:
		q.Classification = "partial_but_usable"
	case len(c.Exchanges) > 0:
		q.Classification = "good_for_http_reconstruction"
	default:
		q.Classification = "good_for_metadata_correlation"
	}
	if q.ReportedDrops != nil && *q.ReportedDrops == 0 && (q.MissingRangeCount > 0 || q.OverlapConflictCount > 0) {
		q.Warnings = append(q.Warnings, "zero tool-reported drops does not override reassembly gaps or conflicts")
	}
	return q
}
func containsUnsupported(xs []Interface) bool {
	for _, x := range xs {
		if !x.Supported {
			return true
		}
	}
	return false
}
func correlationFindings(logs []SemanticLogEvent, r CorrelationResult) []ResearchFinding {
	var f []ResearchFinding
	seen := map[string]bool{}
	add := func(id, desc string) {
		if !seen[id] {
			seen[id] = true
			f = append(f, ResearchFinding{ID: id, State: "observed", Description: desc})
		}
	}
	for _, x := range logs {
		if x.SemanticState == "machine_policy_assignment_request" {
			add("SCCM-POLICY-TRIGGER-OBSERVED", "fixture-supported machine-policy assignment request marker observed")
		}
		if x.SemanticState != "unknown_policy_event" {
			add("SCCM-POLICY-LOG-EVIDENCE-OBSERVED", "redacted semantic log evidence observed")
		}
	}
	if len(r.Candidates) > 0 {
		add("SCCM-TLS-FLOW-CANDIDATE", "opaque TLS flow candidate ranked offline")
	}
	if strings.Contains(r.Classification, "ambiguous") || strings.Contains(r.Classification, "multiple") {
		add("SCCM-TLS-FLOW-ATTRIBUTION-AMBIGUOUS", "available metadata does not uniquely attribute an SCCM flow")
	}
	if r.Quality.Classification == "partial_but_usable" {
		add("SCCM-CAPTURE-QUALITY-PARTIAL", "capture contains visible reconstruction limitations")
	}
	add("SCCM-POLICY-PAYLOAD-NOT-VISIBLE", "opaque TLS prevents policy payload inspection")
	return f
}

func LoadTrigger(path string) (Trigger, error) {
	var t Trigger
	b, e := os.ReadFile(path)
	if e != nil {
		return t, e
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&t); e != nil {
		return t, e
	}
	if t.SchemaVersion != 1 {
		return t, fmt.Errorf("unsupported trigger schema %d", t.SchemaVersion)
	}
	if t.Timestamp.IsZero() {
		return t, errors.New("trigger timestamp is required")
	}
	if !safeAction.MatchString(t.Action) {
		return t, errors.New("trigger action must be a bounded safe label")
	}
	t.SourceID = safeMetadata(t.SourceID, safeAction, "source")
	return t, nil
}
