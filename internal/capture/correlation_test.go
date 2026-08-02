package capture

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func TestSemanticCMTraceLogAndRedaction(t *testing.T) {
	line := `<![LOG[Requesting machine policy assignments from https://mp.synthetic.invalid/path id=11111111-2222-3333-4444-555555555555]LOG]!><time="10:20:30.123+060" date="07-01-2026" component="PolicyAgent" context="" type="1" thread="42" file="x">`
	e, ok := ParseSemanticLogLine("PolicyAgent.log", 7, line)
	if !ok || e.SemanticState != "machine_policy_assignment_request" || e.Confidence != "high" {
		t.Fatalf("unexpected event: %#v", e)
	}
	if e.Timestamp.Location() != time.UTC || e.OriginalTimezone != "-01:00" || e.TimestampPrecision != "millisecond" || e.Timestamp.Hour() != 11 {
		t.Fatalf("timestamp metadata lost: %#v", e)
	}
	b, _ := json.Marshal(e)
	for _, secret := range []string{"mp.synthetic.invalid", "11111111-2222-3333-4444-555555555555"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("identifier leaked: %s", secret)
		}
	}
}

func TestCMTraceBiasConvertsLocalTimeToUTC(t *testing.T) {
	line := `<![LOG[synthetic timestamp record]LOG]!><time="19:16:29.623+240" date="08-02-2026" component="Synthetic" context="" type="1" thread="7" file="x">`
	e, ok := ParseSemanticLogLine("synthetic.log", 1, line)
	if !ok || e.OriginalTimezone != "-04:00" || e.Timestamp.Format(time.RFC3339Nano) != "2026-08-02T23:16:29.623Z" {
		t.Fatalf("CMTrace bias conversion: %#v", e)
	}
}

func TestReadSemanticLogsUTF16(t *testing.T) {
	d := t.TempDir()
	line := `<![LOG[No new assignments]LOG]!><time="10:20:30.123+000" date="07-01-2026" component="PolicyAgent" context="" type="1" thread="42" file="x">`
	u := utf16.Encode([]rune(line))
	b := []byte{0xff, 0xfe}
	for _, x := range u {
		var p [2]byte
		binary.LittleEndian.PutUint16(p[:], x)
		b = append(b, p[:]...)
	}
	if e := os.WriteFile(filepath.Join(d, "synthetic.log"), b, 0600); e != nil {
		t.Fatal(e)
	}
	events, w, e := ReadSemanticLogs(d)
	if e != nil || len(w) != 0 || len(events) != 1 || events[0].SemanticState != "machine_policy_no_new_assignments" {
		t.Fatalf("events=%#v warnings=%v err=%v", events, w, e)
	}
}

func TestSemanticLogDoesNotUseFilenameAlone(t *testing.T) {
	e, ok := ParseSemanticLogLine("PolicyAgent.log", 1, `<![LOG[ordinary unrelated message]LOG]!><time="10:20:30.000+000" date="07-01-2026" component="Other" context="" type="1" thread="2" file="x">`)
	if !ok || e.SemanticState != "unknown_policy_event" || e.Confidence != "low" {
		t.Fatalf("filename assigned semantics: %#v", e)
	}
}

func TestMalformedSemanticLogLineRejected(t *testing.T) {
	if _, ok := ParseSemanticLogLine("synthetic.log", 1, "not a timestamped record"); ok {
		t.Fatal("malformed line accepted")
	}
}

func TestTimelineDeterministicMissingAndEqualTimestamps(t *testing.T) {
	at := time.Date(2026, 7, 1, 10, 0, 0, 0, time.FixedZone("lab", 3600))
	xs := []TimelineEvent{{EventID: "z"}, {EventID: "b", Timestamp: at.UTC()}, {EventID: "a", Timestamp: at.UTC()}}
	SortTimeline(xs)
	if got := []string{xs[0].EventID, xs[1].EventID, xs[2].EventID}; strings.Join(got, ",") != "a,b,z" {
		t.Fatalf("order=%v", got)
	}
}

func TestCorrelationTimingAloneStaysLowConfidence(t *testing.T) {
	trigger := Trigger{SchemaVersion: 1, Timestamp: time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC), Action: "machine_policy_cycle"}
	c := NormalizedCapture{Interfaces: []Interface{{ID: 0, LinkType: 1, Supported: true, TimestampResolution: 1_000_000, SnapLength: 65535}}, Packets: []Packet{{ID: "p", Timestamp: trigger.Timestamp.Add(time.Second)}}, Flows: []Flow{{ID: "f", TLS: true, StartedAt: trigger.Timestamp.Add(time.Second), EndedAt: trigger.Timestamp.Add(2 * time.Second), DirectionConfidence: "medium", PacketIDs: []string{"p"}}}}
	r, err := Correlate(c, nil, trigger, DefaultCorrelationWindow())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Candidates) != 1 || r.Candidates[0].Confidence != "low" || r.Classification != "low_confidence_sccm_tls_candidate" {
		t.Fatalf("timing elevated trust: %#v", r.Candidates)
	}
}

func TestCorrelationEndpointEvidenceAndContradiction(t *testing.T) {
	trigger := Trigger{SchemaVersion: 1, Timestamp: time.Now().UTC(), Action: "machine_policy_cycle"}
	ep := shortHash("mp.synthetic.invalid")
	logs := []SemanticLogEvent{{EventID: "l", Timestamp: trigger.Timestamp, EndpointFingerprint: ep, SemanticState: "message_send_started", Confidence: "medium"}}
	flows := []Flow{{ID: "match", TLS: true, SNI: ep, StartedAt: trigger.Timestamp.Add(time.Second), DirectionConfidence: "high"}, {ID: "late", TLS: true, StartedAt: trigger.Timestamp.Add(10 * time.Minute), DirectionConfidence: "high"}}
	r, err := Correlate(NormalizedCapture{Interfaces: []Interface{{ID: 0, LinkType: 1, Supported: true}}, Packets: []Packet{{ID: "p", Timestamp: trigger.Timestamp}}, Flows: flows}, logs, trigger, DefaultCorrelationWindow())
	if err != nil {
		t.Fatal(err)
	}
	if r.Candidates[0].FlowID != "match" || r.Candidates[0].Confidence != "high" {
		t.Fatalf("ranking=%#v", r.Candidates)
	}
	if len(r.Candidates[1].ContradictingEvidence) == 0 {
		t.Fatal("missing contradiction")
	}
}

func TestCorrelationMultipleAndNoCandidates(t *testing.T) {
	at := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	trigger := Trigger{Timestamp: at, Action: "machine_policy_cycle"}
	base := NormalizedCapture{Interfaces: []Interface{{ID: 0, LinkType: 1, Supported: true}}, Packets: []Packet{{ID: "p", Timestamp: at}}}
	r, e := Correlate(base, nil, trigger, DefaultCorrelationWindow())
	if e != nil || r.Classification != "no_correlatable_tls_flow" {
		t.Fatalf("no candidate: %#v %v", r, e)
	}
	base.Flows = []Flow{{ID: "a", TLS: true, StartedAt: at.Add(5 * time.Second), DirectionConfidence: "medium"}, {ID: "b", TLS: true, StartedAt: at.Add(5 * time.Second), DirectionConfidence: "medium"}}
	r, e = Correlate(base, nil, trigger, DefaultCorrelationWindow())
	if e != nil || r.Classification != "multiple_indistinguishable_candidates" {
		t.Fatalf("multiple: %#v %v", r.Candidates, e)
	}
}

func TestRemoteManagementTimingIsContradictory(t *testing.T) {
	at := time.Date(2026, 8, 2, 23, 16, 29, 0, time.UTC)
	c := NormalizedCapture{Interfaces: []Interface{{ID: 0, LinkType: 1, Supported: true}}, Packets: []Packet{{ID: "p", Timestamp: at}}, Flows: []Flow{{ID: "remote_control", TLS: true, StartedAt: at.Add(time.Second), DirectionConfidence: "medium", Client: Endpoint{Port: 5986}}}}
	r, err := Correlate(c, nil, Trigger{Timestamp: at, Action: "machine_policy_cycle"}, DefaultCorrelationWindow())
	if err != nil {
		t.Fatal(err)
	}
	if r.Classification != "no_correlatable_tls_flow" || len(r.Candidates) != 1 || r.Candidates[0].Score != 0 || len(r.Candidates[0].ContradictingEvidence) == 0 {
		t.Fatalf("remote-management flow trusted: %#v", r)
	}
}

func TestCaptureQualityZeroDropsDoesNotHideGaps(t *testing.T) {
	z := 0
	c := NormalizedCapture{Interfaces: []Interface{{ID: 0, LinkType: 1, Supported: true, SnapLength: 128}}, Packets: []Packet{{ID: "p"}}, Flows: []Flow{{ID: "f", Gaps: 1, DirectionConfidence: "low"}}}
	q := AssessCaptureQualityWithDrops(c, &z)
	if q.Classification != "partial_but_usable" || len(q.Warnings) == 0 {
		t.Fatalf("quality=%#v", q)
	}
}

func TestCaptureQualityCompleteHTTPAndInvalid(t *testing.T) {
	q := AssessCaptureQuality(NormalizedCapture{})
	if q.Classification != "invalid_capture" {
		t.Fatal(q)
	}
	q = AssessCaptureQuality(NormalizedCapture{Interfaces: []Interface{{ID: 0, LinkType: 1, Supported: true}}, Packets: []Packet{{ID: "p"}}, Flows: []Flow{{ID: "f", DirectionConfidence: "high"}}, Exchanges: []Exchange{{ID: "e", State: "complete"}}})
	if q.Classification != "good_for_http_reconstruction" {
		t.Fatal(q)
	}
}

func TestCorrelationDossierIsRedactedAndPrivate(t *testing.T) {
	d := filepath.Join(t.TempDir(), "dossier")
	r := CorrelationResult{SchemaVersion: 1, AlgorithmVersion: CorrelationAlgorithmVersion, Classification: "no_correlatable_tls_flow", Quality: CaptureQuality{Classification: "partial_but_usable"}}
	if err := GenerateCorrelationDossier(d, r, false); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(d)
	if st.Mode().Perm() != 0700 {
		t.Fatalf("mode=%o", st.Mode().Perm())
	}
	for _, name := range []string{"timeline.json", "log-events.json", "tls-flow-candidates.json", "capture-quality.json", "correlation-summary.json", "correlation-summary.md", "gaps-and-next-actions.md"} {
		st, e := os.Stat(filepath.Join(d, name))
		if e != nil {
			t.Fatal(e)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%o", name, st.Mode().Perm())
		}
	}
}

func TestCorrelationWindowValidationAndBound(t *testing.T) {
	_, err := Correlate(NormalizedCapture{}, nil, Trigger{Timestamp: time.Now()}, CorrelationWindow{PostTrigger: 16 * time.Minute, Maximum: 15 * time.Minute})
	if err == nil {
		t.Fatal("accepted excessive window")
	}
}

func TestCorrelationBoundsTimelineEvents(t *testing.T) {
	at := time.Now().UTC()
	logs := make([]SemanticLogEvent, MaxTimelineEvents)
	for i := range logs {
		logs[i] = SemanticLogEvent{EventID: fmt.Sprintf("l%d", i), Timestamp: at, SemanticState: "unknown_policy_event"}
	}
	r, e := Correlate(NormalizedCapture{}, logs, Trigger{Timestamp: at, Action: "machine_policy_cycle"}, DefaultCorrelationWindow())
	if e != nil {
		t.Fatal(e)
	}
	if len(r.LogEvents) > MaxTimelineEvents/2 || len(r.Timeline) > MaxTimelineEvents {
		t.Fatalf("unbounded logs=%d timeline=%d", len(r.LogEvents), len(r.Timeline))
	}
}

func TestTCPOverlapResolutionPreservesFirstSeenBytes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		stream     []byte
		next, seq  uint32
		payload    []byte
		want, kind string
	}{
		{"identical", []byte("abcdef"), 16, 13, []byte("defXYZ"), "XYZ", "identical"},
		{"conflict", []byte("abcdef"), 16, 13, []byte("zzzXYZ"), "XYZ", "conflict"},
		{"duplicate", []byte("abcdef"), 16, 10, []byte("abcdef"), "", "identical"},
		{"new", []byte("abcdef"), 16, 16, []byte("XYZ"), "XYZ", "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, kind := resolveTCPOverlap(tc.stream, tc.next, tc.seq, tc.payload)
			if string(got) != tc.want || kind != tc.kind {
				t.Fatalf("got %q %s", got, kind)
			}
		})
	}
}

func TestPCAPBridgePreservesFlowTimestampAndFingerprintsEndpoint(t *testing.T) {
	p := make([]byte, 14+20+20+6)
	p[12], p[13] = 0x08, 0x00
	p[14] = 0x45
	p[23] = 6
	copy(p[26:30], []byte{192, 0, 2, 10})
	copy(p[30:34], []byte{192, 0, 2, 20})
	tcp := p[34:]
	binary.BigEndian.PutUint16(tcp, 50000)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	binary.BigEndian.PutUint32(tcp[4:], 100)
	tcp[12] = 0x50
	copy(tcp[20:], []byte{0x16, 0x03, 0x03, 0, 1, 0})
	at := time.Date(2026, 7, 1, 10, 0, 1, 123000000, time.UTC)
	raw := encodeClassicPCAP([]classicPacket{{data: p, timestamp: at, originalLength: uint32(len(p))}})
	c, e := Import(bytes.NewReader(raw), "synthetic.pcap", "pcap", DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Flows) != 1 || !c.Flows[0].StartedAt.Equal(at.Truncate(time.Microsecond)) || !c.Flows[0].TLS {
		t.Fatalf("flow=%#v", c.Flows)
	}
	b, _ := json.Marshal(c.Flows[0])
	if bytes.Contains(b, []byte("c000020a")) || c.Flows[0].Client.AddressFingerprint == "" {
		t.Fatalf("endpoint not safely fingerprinted: %s", b)
	}
}

func TestTLSClientHelloSNIIsFingerprintOnly(t *testing.T) {
	name := []byte("mp.synthetic.invalid")
	ext := make([]byte, 4+2+1+2+len(name))
	binary.BigEndian.PutUint16(ext[0:2], 0)
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(ext)-4))
	binary.BigEndian.PutUint16(ext[4:6], uint16(3+len(name)))
	ext[6] = 0
	binary.BigEndian.PutUint16(ext[7:9], uint16(len(name)))
	copy(ext[9:], name)
	body := make([]byte, 34+1+2+2+1+1+2+len(ext))
	p := 0
	p += 34
	body[p] = 0
	p++
	binary.BigEndian.PutUint16(body[p:p+2], 2)
	p += 2
	p += 2
	body[p] = 1
	p++
	body[p] = 0
	p++
	binary.BigEndian.PutUint16(body[p:p+2], uint16(len(ext)))
	p += 2
	copy(body[p:], ext)
	record := make([]byte, 9+len(body))
	record[0], record[1], record[2] = 0x16, 0x03, 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(4+len(body)))
	record[5] = 1
	copy(record[9:], body)
	got := tlsSNIFingerprint(record)
	if got == "" || strings.Contains(got, "synthetic") {
		t.Fatalf("unsafe SNI result %q", got)
	}
}
