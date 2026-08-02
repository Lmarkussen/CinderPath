package capture

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dnsName(s string) []byte {
	var b []byte
	for _, p := range strings.Split(s, ".") {
		b = append(b, byte(len(p)))
		b = append(b, p...)
	}
	return append(b, 0)
}
func dnsResponse(name string, typ uint16, answer []byte, rcode uint16) []byte {
	q := dnsName(name)
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[2:4], 0x8000|rcode)
	binary.BigEndian.PutUint16(b[4:6], 1)
	if len(answer) > 0 {
		binary.BigEndian.PutUint16(b[6:8], 1)
	}
	b = append(b, q...)
	b = append(b, byte(typ>>8), byte(typ), 0, 1)
	if len(answer) > 0 {
		b = append(b, 0xc0, 0x0c, byte(typ>>8), byte(typ), 0, 1, 0, 0, 0, 60, byte(len(answer)>>8), byte(len(answer)))
		b = append(b, answer...)
	}
	return b
}

func dnsEthernet(msg []byte, tcp bool) []byte {
	transport := make([]byte, 8)
	proto := byte(17)
	if tcp {
		proto = 6
		transport = make([]byte, 22)
		binary.BigEndian.PutUint16(transport[2:4], 53)
		transport[12] = 5 << 4
		binary.BigEndian.PutUint16(transport[20:22], uint16(len(msg)))
	} else {
		binary.BigEndian.PutUint16(transport[2:4], 53)
		binary.BigEndian.PutUint16(transport[4:6], uint16(8+len(msg)))
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = proto
	copy(ip[12:16], []byte{192, 0, 2, 20})
	copy(ip[16:20], []byte{192, 0, 2, 53})
	e := make([]byte, 14)
	e[12], e[13] = 0x08, 0x00
	return append(append(append(e, ip...), transport...), msg...)
}

func TestDNSMessageAAndNXDOMAIN(t *testing.T) {
	at := time.Date(2026, 8, 2, 1, 2, 3, 0, time.UTC)
	xs, e := parseDNSMessage(dnsResponse("mp.synthetic.test", 1, []byte{192, 0, 2, 10}, 0), "packet_1", "flow_1", at)
	if e != nil || len(xs) != 1 {
		t.Fatalf("parse: %v %#v", e, xs)
	}
	if xs[0].QueryNameFingerprint == "" || len(xs[0].AnswerFingerprints) != 1 || xs[0].TTL != 60 || !xs[0].Response {
		t.Fatalf("unexpected event: %#v", xs[0])
	}
	nx, e := parseDNSMessage(dnsResponse("absent.synthetic.test", 1, nil, 3), "packet_2", "flow_2", at)
	if e != nil || nx[0].ResponseCode != 3 {
		t.Fatalf("nxdomain: %v %#v", e, nx)
	}
}

func TestDNSMessageAAAAAndCNAME(t *testing.T) {
	addr := make([]byte, 16)
	addr[15] = 1
	xs, e := parseDNSMessage(dnsResponse("v6.synthetic.test", 28, addr, 0), "p", "f", time.Time{})
	if e != nil || len(xs[0].AnswerFingerprints) != 1 {
		t.Fatalf("AAAA: %v %#v", e, xs)
	}
	cname := dnsName("alias.synthetic.test")
	xs, e = parseDNSMessage(dnsResponse("mp.synthetic.test", 5, cname, 0), "p2", "f", time.Time{})
	if e != nil || len(xs[0].CNAMEChainFingerprints) != 1 {
		t.Fatalf("CNAME: %v %#v", e, xs)
	}
}

func TestDNSMalformedCompressionAndBounds(t *testing.T) {
	b := make([]byte, 18)
	binary.BigEndian.PutUint16(b[4:6], 1)
	b[12], b[13] = 0xc0, 0x0c
	if _, e := parseDNSMessage(b, "p", "f", time.Time{}); e == nil {
		t.Fatal("expected compression loop")
	}
	b = make([]byte, 12)
	binary.BigEndian.PutUint16(b[4:6], maxDNSQuestions+1)
	if _, e := parseDNSMessage(b, "p", "f", time.Time{}); e == nil {
		t.Fatal("expected bound")
	}
}

func TestDNSUDPAndTCPTransport(t *testing.T) {
	msg := dnsResponse("mp.synthetic.test", 1, []byte{192, 0, 2, 10}, 0)
	for _, tcp := range []bool{false, true} {
		xs := parseDNSPacket(dnsEthernet(msg, tcp), "packet", time.Now())
		if len(xs) != 1 || xs[0].FlowID == "" {
			t.Fatalf("tcp=%v %#v", tcp, xs)
		}
	}
}

func TestDNSTruncatedResponse(t *testing.T) {
	msg := dnsResponse("mp.synthetic.test", 1, nil, 0)
	binary.BigEndian.PutUint16(msg[2:4], 0x8200)
	xs, e := parseDNSMessage(msg, "p", "f", time.Now())
	if e != nil || !xs[0].Truncated || xs[0].Confidence != "medium" {
		t.Fatalf("%v %#v", e, xs)
	}
}

func TestLoadInventoryEvidenceRedacts(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "client.json")
	raw := `{"schema_version":1,"sccm_authority":{"CurrentManagementPoint":"mp.synthetic.test","Name":"P01"},"sccm_client":{"ClientVersion":"1.2.3"}}`
	if e := os.WriteFile(p, []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	xs, e := LoadInventoryEvidence(p)
	if e != nil || len(xs) != 1 || !xs[0].Observed || xs[0].HostnameFingerprint == "" {
		t.Fatalf("%v %#v", e, xs)
	}
	b, _ := json.Marshal(xs)
	if strings.Contains(string(b), "mp.synthetic") || strings.Contains(string(b), "1.2.3") {
		t.Fatal("plaintext inventory leaked")
	}
}

func TestEndpointCorrelationIndependentEvidence(t *testing.T) {
	trigger := Trigger{Timestamp: time.Date(2026, 8, 2, 1, 0, 0, 0, time.UTC), Action: "machine_policy_cycle"}
	host := endpointFingerprint("mp.synthetic.test")
	addr := endpointFingerprint("192.0.2.10")
	c := NormalizedCapture{DNSEvents: []DNSEvent{{ID: "dns_1", Timestamp: trigger.Timestamp.Add(-time.Second), QueryNameFingerprint: host, AnswerFingerprints: []string{addr}, Confidence: "high"}}, Flows: []Flow{{ID: "flow_1", TLS: true, SNI: host, StartedAt: trigger.Timestamp.Add(time.Second), Client: Endpoint{AddressFingerprint: endpointFingerprint("192.0.2.20"), Port: 50000}, Server: Endpoint{AddressFingerprint: addr, Port: 443}}}}
	logs := []SemanticLogEvent{{EventID: "log_1", Timestamp: trigger.Timestamp, EndpointFingerprint: host, SemanticState: "message_send_started", Confidence: "medium"}}
	r, e := CorrelateEndpoints(c, logs, []InventoryEndpointEvidence{{HostnameFingerprint: host, Source: "windows_client_inventory", Observed: true}}, trigger, DefaultCorrelationWindow())
	if e != nil {
		t.Fatal(e)
	}
	if r.EndpointClassification != "high_confidence_management_point_endpoint" || r.FlowClassification != "high_confidence_sccm_tls_flow" {
		t.Fatalf("unexpected: %s %s %#v", r.EndpointClassification, r.FlowClassification, r.Endpoints)
	}
}

func TestEndpointTimingAndPortStayWeak(t *testing.T) {
	trigger := Trigger{Timestamp: time.Now().UTC(), Action: "machine_policy_cycle"}
	c := NormalizedCapture{Flows: []Flow{{ID: "flow", TLS: true, StartedAt: trigger.Timestamp, Server: Endpoint{Port: 443}}}}
	r, e := CorrelateEndpoints(c, nil, nil, trigger, DefaultCorrelationWindow())
	if e != nil {
		t.Fatal(e)
	}
	if r.EndpointClassification != "insufficient_endpoint_metadata" || r.FlowClassification != "no_correlatable_sccm_flow" {
		t.Fatalf("timing/port over-attributed: %#v", r)
	}
}

func TestEndpointWinRMContradiction(t *testing.T) {
	trigger := Trigger{Timestamp: time.Now().UTC(), Action: "machine_policy_cycle"}
	host := endpointFingerprint("mp.synthetic.test")
	c := NormalizedCapture{Flows: []Flow{{ID: "flow", TLS: true, SNI: host, StartedAt: trigger.Timestamp, Server: Endpoint{Port: 5986}}}}
	r, e := CorrelateEndpoints(c, nil, []InventoryEndpointEvidence{{HostnameFingerprint: host, Source: "windows_client_inventory", Observed: true}}, trigger, DefaultCorrelationWindow())
	if e != nil {
		t.Fatal(e)
	}
	if len(r.TLSLinks) != 1 || len(r.TLSLinks[0].ContradictingEvidence) == 0 {
		t.Fatalf("missing contradiction: %#v", r.TLSLinks)
	}
}

func TestEndpointTrustListContradiction(t *testing.T) {
	trigger := Trigger{Timestamp: time.Now().UTC(), Action: "machine_policy_cycle"}
	host := "trust.synthetic.test"
	full := fingerprint([]byte(host))
	c := NormalizedCapture{Exchanges: []Exchange{{ID: "exchange", StartedAt: trigger.Timestamp, Request: &Message{Route: "/update/authrootstl.cab", Headers: []Header{{Name: "host", Value: Field{Fingerprint: full}}}}}}}
	r, e := CorrelateEndpoints(c, nil, nil, trigger, DefaultCorrelationWindow())
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Endpoints) != 1 || !containsString(r.Endpoints[0].Roles, "trust_list_endpoint") || len(r.Endpoints[0].ContradictingEvidence) == 0 {
		t.Fatalf("missing trust-list contradiction: %#v", r.Endpoints)
	}
}

func TestEndpointDossierModesAndRedaction(t *testing.T) {
	d := filepath.Join(t.TempDir(), "dossier")
	r := EndpointCorrelationResult{EndpointClassification: "no_management_point_endpoint_identified", FlowClassification: "no_correlatable_sccm_flow"}
	if e := GenerateEndpointDossier(d, r); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(d)
	if st.Mode().Perm() != 0700 {
		t.Fatalf("dir mode %o", st.Mode().Perm())
	}
	ents, _ := os.ReadDir(d)
	if len(ents) != 7 {
		t.Fatalf("files=%d", len(ents))
	}
	for _, x := range ents {
		st, _ = os.Stat(filepath.Join(d, x.Name()))
		if st.Mode().Perm() != 0600 {
			t.Fatalf("%s mode %o", x.Name(), st.Mode().Perm())
		}
	}
}

func FuzzDNSNameDecompression(f *testing.F) {
	f.Add([]byte{1, 'a', 0}, 0)
	f.Fuzz(func(t *testing.T, b []byte, o int) {
		if len(b) > 4096 {
			return
		}
		if o < 0 || o >= len(b) {
			o = 0
		}
		_, _, _ = decodeDNSName(b, o)
	})
}
func FuzzDNSMessageParser(f *testing.F) {
	f.Add(dnsResponse("x.test", 1, []byte{192, 0, 2, 1}, 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		_, _ = parseDNSMessage(b, "packet", "flow", time.Time{})
	})
}

func FuzzEndpointGraphConstruction(f *testing.F) {
	f.Add("host", "addr", int64(0))
	f.Fuzz(func(t *testing.T, h, a string, n int64) {
		if len(h) > 256 || len(a) > 256 {
			return
		}
		at := time.Unix(n%2_000_000_000, 0).UTC()
		fp := endpointFingerprint(h)
		c := NormalizedCapture{DNSEvents: []DNSEvent{{ID: "dns", Timestamp: at, QueryNameFingerprint: fp, AnswerFingerprints: []string{endpointFingerprint(a)}}}}
		r, e := CorrelateEndpoints(c, nil, []InventoryEndpointEvidence{{HostnameFingerprint: fp, Source: "fuzz", Observed: true}}, Trigger{Timestamp: at, Action: "machine_policy_cycle"}, DefaultCorrelationWindow())
		if e != nil {
			t.Fatal(e)
		}
		_, _ = json.Marshal(r)
	})
}
func FuzzEndpointCandidateScoring(f *testing.F) {
	f.Add(int64(0), true)
	f.Fuzz(func(t *testing.T, delta int64, sni bool) {
		if delta > 1_000_000 || delta < -1_000_000 {
			return
		}
		at := time.Unix(1_700_000_000, 0).UTC()
		fp := ""
		if sni {
			fp = endpointFingerprint("synthetic.test")
		}
		_, _ = CorrelateEndpoints(NormalizedCapture{Flows: []Flow{{ID: "flow", TLS: true, SNI: fp, StartedAt: at.Add(time.Duration(delta) * time.Millisecond), Server: Endpoint{Port: 443}}}}, nil, nil, Trigger{Timestamp: at, Action: "machine_policy_cycle"}, DefaultCorrelationWindow())
	})
}
func FuzzTLSMetadataCorrelation(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x03})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= 65535 {
			_, _, _ = tlsClientMetadata(b)
		}
	})
}
func FuzzEndpointDossierSerialization(f *testing.F) {
	f.Add("no_management_point_endpoint_identified")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 128 {
			return
		}
		d := filepath.Join(t.TempDir(), "dossier")
		_ = GenerateEndpointDossier(d, EndpointCorrelationResult{EndpointClassification: safeMetadata(s, safeAction, "classification"), FlowClassification: "no_correlatable_sccm_flow"})
	})
}
