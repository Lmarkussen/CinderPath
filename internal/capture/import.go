package capture

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func fingerprint(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func stableID(prefix string, parts ...string) string {
	return prefix + "_" + fingerprint([]byte(strings.Join(parts, "\x00")))[:20]
}
func Import(r io.Reader, name, format string, limits Limits) (NormalizedCapture, error) {
	if limits.MaxCaptureBytes <= 0 {
		limits = DefaultLimits()
	}
	b, err := io.ReadAll(io.LimitReader(r, limits.MaxCaptureBytes+1))
	if err != nil {
		return NormalizedCapture{}, err
	}
	if int64(len(b)) > limits.MaxCaptureBytes {
		return NormalizedCapture{}, errors.New("capture exceeds configured maximum")
	}
	if format == "" {
		format = strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
	}
	var c NormalizedCapture
	switch format {
	case "har":
		c, err = importHAR(b, limits)
	case "json", "normalized_json":
		c, err = importNormalized(b)
	case "pcap":
		c, err = importPCAP(b, limits, false)
	case "pcapng":
		c, err = importPCAP(b, limits, true)
	default:
		return c, fmt.Errorf("unsupported capture format %q", format)
	}
	if err != nil {
		return c, err
	}
	c.SchemaVersion = SchemaVersion
	c.AlgorithmVersion = AlgorithmVersion
	c.Source.Format = format
	c.Source.Fingerprint = fingerprint(b)
	c.Source.ID = stableID("capture", format, c.Source.Fingerprint)
	finalize(&c)
	return c, nil
}
func importNormalized(b []byte) (NormalizedCapture, error) {
	var c NormalizedCapture
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("decode normalized capture: %w", err)
	}
	if c.SchemaVersion != SchemaVersion {
		return c, fmt.Errorf("unsupported normalized schema %d", c.SchemaVersion)
	}
	return c, nil
}

type harHeader struct{ Name, Value string }
type harFile struct {
	Log struct {
		Version string `json:"version"`
		Entries []struct {
			Started string  `json:"startedDateTime"`
			Time    float64 `json:"time"`
			Request struct {
				Method, URL, HTTPVersion string
				Headers                  []harHeader
				Query                    []struct{ Name, Value string }            `json:"queryString"`
				Post                     struct{ MimeType, Text, Encoding string } `json:"postData"`
			}
			Response struct {
				Status      int
				HTTPVersion string
				Headers     []harHeader
				Content     struct {
					Size                     int64
					MimeType, Text, Encoding string
				}
			}
		} `json:"entries"`
	} `json:"log"`
}

func importHAR(b []byte, l Limits) (NormalizedCapture, error) {
	var h harFile
	d := json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&h); err != nil {
		return NormalizedCapture{}, fmt.Errorf("parse HAR: %w", err)
	}
	if len(h.Log.Entries) > l.MaxPackets {
		return NormalizedCapture{}, errors.New("HAR entry limit exceeded")
	}
	c := NormalizedCapture{RedactionSummary: map[string]int{}}
	for i, e := range h.Log.Entries {
		u, _ := url.Parse(e.Request.URL)
		route := ""
		var q []string
		if u != nil {
			route = u.EscapedPath()
			if route == "" {
				route = "/"
			}
			for k := range u.Query() {
				q = append(q, k)
			}
			sort.Strings(q)
		}
		reqBody := []byte(e.Request.Post.Text)
		respBody := []byte(e.Response.Content.Text)
		req := &Message{Direction: "request", Method: e.Request.Method, Route: route, HTTPVersion: e.Request.HTTPVersion, QueryKeys: q, MediaType: media(e.Request.Post.MimeType), Body: bodyField(reqBody, l), Headers: redactHeaders(e.Request.Headers, c.RedactionSummary), RawMemberFingerprint: fingerprint(reqBody)}
		resp := &Message{Direction: "response", StatusCode: e.Response.Status, HTTPVersion: e.Response.HTTPVersion, MediaType: media(e.Response.Content.MimeType), Body: bodyField(respBody, l), Headers: redactHeaders(e.Response.Headers, c.RedactionSummary), RawMemberFingerprint: fingerprint(respBody)}
		t, _ := time.Parse(time.RFC3339Nano, e.Started)
		ex := Exchange{Index: i, Request: req, Response: resp, ResponseComplete: int64(len(respBody)) <= l.MaxBodyBytes, StartedAt: t, AssociationEvidence: []string{"HAR entry pairing"}, AssociationConfidence: "high"}
		c.Exchanges = append(c.Exchanges, ex)
	}
	return c, nil
}
func media(v string) string {
	m, _, e := mime.ParseMediaType(v)
	if e != nil {
		return ""
	}
	return strings.ToLower(m)
}
func bodyField(b []byte, l Limits) Field {
	if len(b) == 0 {
		return Field{State: Empty}
	}
	n := int64(len(b))
	if n > l.MaxBodyBytes {
		return Field{State: Truncated, Fingerprint: fingerprint(b[:l.MaxBodyBytes]), Length: n}
	}
	return Field{State: Redacted, Fingerprint: fingerprint(b), Length: n}
}
func redactHeaders(in []harHeader, summary map[string]int) []Header {
	out := make([]Header, 0, len(in))
	for _, h := range in {
		name := strings.ToLower(strings.TrimSpace(h.Name))
		if name == "" {
			continue
		}
		v := Field{State: Redacted, Fingerprint: fingerprint([]byte(h.Value)), Length: int64(len(h.Value))}
		if h.Value == "" {
			v = Field{State: Empty}
		}
		out = append(out, Header{Name: name, Value: v})
		summary["header_values_redacted"]++
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func finalize(c *NormalizedCapture) {
	for i := range c.Exchanges {
		e := &c.Exchanges[i]
		e.ID = stableID("exchange", c.Source.Fingerprint, fmt.Sprint(i), messageKey(e.Request), messageKey(e.Response))
		if e.Request != nil {
			e.Request.ID = stableID("message", e.ID, "request")
		}
		if e.Response != nil {
			e.Response.ID = stableID("message", e.ID, "response")
		}
		c.Sequence.ExchangeIDs = append(c.Sequence.ExchangeIDs, e.ID)
		if i > 0 {
			prev := c.Exchanges[i-1]
			edge := SequenceEdge{From: prev.ID, To: e.ID, Kind: "source_order", Evidence: "capture record order", Confidence: "high"}
			if !prev.StartedAt.IsZero() && !e.StartedAt.IsZero() {
				edge.DeltaNanos = e.StartedAt.Sub(prev.StartedAt).Nanoseconds()
			}
			c.Sequence.Edges = append(c.Sequence.Edges, edge)
		}
	}
	if len(c.Exchanges) == 0 {
		c.Sequence.Classification = "incomplete"
	} else if len(c.Exchanges) == 1 {
		c.Sequence.Classification = "single_exchange"
	} else {
		c.Sequence.Classification = "fully_ordered"
	}
	c.Sequence.ID = stableID("sequence", strings.Join(c.Sequence.ExchangeIDs, ","))
	c.Observations = Observe(c)
	sort.Slice(c.Observations, func(i, j int) bool { return c.Observations[i].ID < c.Observations[j].ID })
}
func messageKey(m *Message) string {
	if m == nil {
		return "absent"
	}
	return fmt.Sprintf("%s|%s|%d|%s", m.Method, m.Route, m.StatusCode, m.Body.Fingerprint)
}

// minimal offline classic-PCAP/PCAPNG validation and opaque visibility classification.
func importPCAP(b []byte, l Limits, ng bool) (NormalizedCapture, error) {
	c := NormalizedCapture{RedactionSummary: map[string]int{}}
	if ng {
		if len(b) < 12 || binary.LittleEndian.Uint32(b[:4]) != 0x0a0d0d0a {
			return c, errors.New("invalid pcapng header")
		}
		c.Source.Warnings = []string{"pcapng blocks preserved; multiplexed and encrypted payloads remain opaque"}
		return c, nil
	}
	if len(b) < 24 {
		return c, errors.New("truncated pcap header")
	}
	magic := binary.LittleEndian.Uint32(b[:4])
	le := true
	if magic == 0xd4c3b2a1 {
		le = false
	} else if magic != 0xa1b2c3d4 && magic != 0xa1b23c4d {
		return c, errors.New("invalid pcap magic")
	}
	type segment struct {
		seq     uint32
		index   int
		payload []byte
	}
	flows := map[string][]segment{}
	o := 24
	packets := 0
	for o+16 <= len(b) {
		var n uint32
		if le {
			n = binary.LittleEndian.Uint32(b[o+8 : o+12])
		} else {
			n = binary.BigEndian.Uint32(b[o+8 : o+12])
		}
		o += 16
		if n > uint32(l.MaxStreamBytes) || o+int(n) > len(b) {
			c.Source.Warnings = append(c.Source.Warnings, "truncated or oversized packet")
			break
		}
		packets++
		if packets > l.MaxPackets {
			return c, errors.New("packet limit exceeded")
		}
		packet := b[o : o+int(n)]
		o += int(n)
		payload, flow, seq, ok := tcpPayload(packet)
		if ok && len(payload) > 0 {
			if len(flows) >= l.MaxStreams {
				return c, errors.New("stream limit exceeded")
			}
			cp := append([]byte(nil), payload...)
			flows[flow] = append(flows[flow], segment{seq: seq, index: packets, payload: cp})
		} else if bytes.Contains(packet, []byte{0x16, 0x03}) {
			c.Source.Warnings = append(c.Source.Warnings, "opaque TLS stream; HTTP content not visible")
		}
	}
	keys := make([]string, 0, len(flows))
	for k := range flows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		segs := flows[k]
		original := append([]segment(nil), segs...)
		sort.SliceStable(segs, func(i, j int) bool { return segs[i].seq < segs[j].seq })
		var stream []byte
		var next uint32
		complete := true
		for i, x := range segs {
			if i > 0 && x.seq > next {
				complete = false
				c.Source.Warnings = append(c.Source.Warnings, "missing TCP segment bytes")
			}
			if i > 0 && x.seq < next {
				c.Source.Warnings = append(c.Source.Warnings, "duplicate or overlapping TCP segment")
				skip := int(next - x.seq)
				if skip >= len(x.payload) {
					continue
				}
				x.payload = x.payload[skip:]
			}
			if x.index != original[i].index {
				c.Source.Warnings = append(c.Source.Warnings, "out-of-order TCP segment observed")
			}
			if int64(len(stream)+len(x.payload)) > l.MaxStreamBytes {
				return c, errors.New("reassembled stream limit exceeded")
			}
			stream = append(stream, x.payload...)
			next = x.seq + uint32(len(x.payload))
		}
		if bytes.HasPrefix(stream, []byte("HTTP/")) {
			resp, e := http.ReadResponse(bufio.NewReader(bytes.NewReader(stream)), nil)
			if e != nil {
				c.Source.Warnings = append(c.Source.Warnings, "malformed visible HTTP response")
				continue
			}
			m := &Message{Direction: "response", StatusCode: resp.StatusCode, HTTPVersion: resp.Proto, Headers: redactHTTPHeaders(resp.Header, c.RedactionSummary)}
			c.Exchanges = append(c.Exchanges, Exchange{Index: len(c.Exchanges), StreamID: stableID("stream", k), Response: m, ResponseComplete: complete, AssociationEvidence: []string{"bounded TCP stream framing"}, AssociationConfidence: "low", Ambiguities: []string{"opposite-direction pairing not established"}})
		} else if looksRequest(stream) {
			req, e := http.ReadRequest(bufio.NewReader(bytes.NewReader(stream)))
			if e != nil {
				c.Source.Warnings = append(c.Source.Warnings, "malformed visible HTTP request")
				continue
			}
			route := req.URL.EscapedPath()
			if route == "" {
				route = "/"
			}
			m := &Message{Direction: "request", Method: req.Method, Route: route, HTTPVersion: req.Proto, Headers: redactHTTPHeaders(req.Header, c.RedactionSummary)}
			c.Exchanges = append(c.Exchanges, Exchange{Index: len(c.Exchanges), StreamID: stableID("stream", k), Request: m, ResponseComplete: false, AssociationEvidence: []string{"bounded TCP stream framing"}, AssociationConfidence: "low", Ambiguities: []string{"response pairing not established"}})
		} else if len(stream) > 2 && stream[0] == 0x16 && stream[1] == 0x03 {
			c.Source.Warnings = append(c.Source.Warnings, "opaque TLS stream; HTTP content not visible")
		}
	}
	return c, nil
}

func tcpPayload(p []byte) ([]byte, string, uint32, bool) {
	if len(p) < 14 || binary.BigEndian.Uint16(p[12:14]) != 0x0800 {
		return nil, "", 0, false
	}
	ip := p[14:]
	if len(ip) < 20 || ip[9] != 6 {
		return nil, "", 0, false
	}
	ihl := int(ip[0]&15) * 4
	if ihl < 20 || len(ip) < ihl+20 {
		return nil, "", 0, false
	}
	tcp := ip[ihl:]
	off := int(tcp[12]>>4) * 4
	if off < 20 || len(tcp) < off {
		return nil, "", 0, false
	}
	key := fmt.Sprintf("%x:%d>%x:%d", ip[12:16], binary.BigEndian.Uint16(tcp[:2]), ip[16:20], binary.BigEndian.Uint16(tcp[2:4]))
	return tcp[off:], key, binary.BigEndian.Uint32(tcp[4:8]), true
}
func looksRequest(b []byte) bool {
	for _, m := range []string{"GET ", "POST ", "HEAD ", "PUT ", "OPTIONS "} {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}
func redactHTTPHeaders(in http.Header, summary map[string]int) []Header {
	var hs []harHeader
	for k, vs := range in {
		for _, v := range vs {
			hs = append(hs, harHeader{Name: k, Value: v})
		}
	}
	return redactHeaders(hs, summary)
}

func DecodeBody(m *Message, raw []byte, l Limits) ([]byte, error) {
	if int64(len(raw)) > l.MaxBodyBytes {
		return nil, errors.New("body limit exceeded")
	}
	if strings.EqualFold(m.ContentEncoding, "gzip") {
		z, e := gzip.NewReader(bytes.NewReader(raw))
		if e != nil {
			return nil, e
		}
		defer z.Close()
		out, e := io.ReadAll(io.LimitReader(z, l.MaxDecompressedBytes+1))
		if int64(len(out)) > l.MaxDecompressedBytes {
			return nil, errors.New("decompressed body limit exceeded")
		}
		if len(raw) > 0 && float64(len(out))/float64(len(raw)) > l.MaxCompressionRatio {
			return nil, errors.New("compression ratio limit exceeded")
		}
		return out, e
	}
	return raw, nil
}
