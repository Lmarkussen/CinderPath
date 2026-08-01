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
		req := &Message{Direction: "request", Method: e.Request.Method, Route: route, HTTPVersion: e.Request.HTTPVersion, QueryKeys: q, MediaType: media(e.Request.Post.MimeType), Body: bodyField(reqBody, l), Headers: redactHeaders(e.Request.Headers, c.RedactionSummary), RawMemberFingerprint: fingerprint(reqBody), rawBody: reqBody}
		resp := &Message{Direction: "response", StatusCode: e.Response.Status, HTTPVersion: e.Response.HTTPVersion, MediaType: media(e.Response.Content.MimeType), Body: bodyField(respBody, l), Headers: redactHeaders(e.Response.Headers, c.RedactionSummary), RawMemberFingerprint: fingerprint(respBody), rawBody: respBody}
		req.Structured, req.Warnings = ParseStructured(e.Request.Post.MimeType, reqBody, l)
		resp.Structured, resp.Warnings = ParseStructured(e.Response.Content.MimeType, respBody, l)
		t, _ := time.Parse(time.RFC3339Nano, e.Started)
		ex := Exchange{Index: i, Request: req, Response: resp, ResponseComplete: int64(len(respBody)) <= l.MaxBodyBytes, StartedAt: t, AssociationEvidence: []string{"HAR entry pairing"}, AssociationConfidence: "high", State: "complete"}
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
		if i > 0 && (c.Source.Format == "har" || (e.StreamID != "" && e.StreamID == c.Exchanges[i-1].StreamID)) {
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
	} else if c.Source.Format == "har" || len(c.Flows) <= 1 {
		c.Sequence.Classification = "fully_ordered"
	} else {
		c.Sequence.Classification = "partially_ordered"
		c.Sequence.Warnings = append(c.Sequence.Warnings, "independent TCP flows remain unordered")
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
		return decodePCAPNG(b, l)
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
		var n, orig, sec, usec uint32
		if le {
			sec = binary.LittleEndian.Uint32(b[o : o+4])
			usec = binary.LittleEndian.Uint32(b[o+4 : o+8])
			n = binary.LittleEndian.Uint32(b[o+8 : o+12])
			orig = binary.LittleEndian.Uint32(b[o+12 : o+16])
		} else {
			sec = binary.BigEndian.Uint32(b[o : o+4])
			usec = binary.BigEndian.Uint32(b[o+4 : o+8])
			n = binary.BigEndian.Uint32(b[o+8 : o+12])
			orig = binary.BigEndian.Uint32(b[o+12 : o+16])
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
		idx := len(c.Packets)
		c.Packets = append(c.Packets, Packet{ID: stableID("packet", fmt.Sprint(idx), fingerprint(packet)), Index: idx, Timestamp: time.Unix(int64(sec), int64(usec)*1000).UTC(), CapturedLength: n, OriginalLength: orig, Truncated: n < orig, LinkType: 1, Fingerprint: fingerprint(packet)})
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
				skip := int(next - x.seq)
				cmp := skip
				if cmp > len(x.payload) {
					cmp = len(x.payload)
				}
				start := len(stream) - skip
				if start < 0 {
					start = 0
				}
				conflict := start+cmp <= len(stream) && !bytes.Equal(stream[start:start+cmp], x.payload[:cmp])
				if conflict {
					c.Source.Warnings = append(c.Source.Warnings, "conflicting overlapping TCP segment")
				} else {
					c.Source.Warnings = append(c.Source.Warnings, "duplicate retransmitted TCP segment")
				}
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
			br := bufio.NewReader(bytes.NewReader(stream))
			for {
				if _, e := br.Peek(1); e != nil {
					break
				}
				resp, e := http.ReadResponse(br, nil)
				if e != nil {
					c.Source.Warnings = append(c.Source.Warnings, "malformed or incomplete visible HTTP response")
					break
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, l.MaxBodyBytes+1))
				_ = resp.Body.Close()
				m := &Message{Direction: "response", StatusCode: resp.StatusCode, HTTPVersion: resp.Proto, Headers: redactHTTPHeaders(resp.Header, c.RedactionSummary), MediaType: media(resp.Header.Get("Content-Type")), ContentEncoding: resp.Header.Get("Content-Encoding"), TransferEncoding: strings.Join(resp.TransferEncoding, ","), DeclaredLength: resp.ContentLength, Body: bodyField(body, l), rawBody: body}
				m.Structured, m.Warnings = ParseStructured(resp.Header.Get("Content-Type"), body, l)
				state := "response_only"
				if !complete || int64(len(body)) > l.MaxBodyBytes {
					state = "partial_response"
				}
				c.Exchanges = append(c.Exchanges, Exchange{Index: len(c.Exchanges), StreamID: stableID("stream", canonicalFlowKey(k)), Response: m, ResponseComplete: state == "response_only", AssociationEvidence: []string{"bounded TCP stream framing"}, AssociationConfidence: "medium", State: state})
			}
		} else if looksRequest(stream) {
			br := bufio.NewReader(bytes.NewReader(stream))
			for {
				if _, e := br.Peek(1); e != nil {
					break
				}
				req, e := http.ReadRequest(br)
				if e != nil {
					c.Source.Warnings = append(c.Source.Warnings, "malformed or incomplete visible HTTP request")
					break
				}
				route := req.URL.EscapedPath()
				if route == "" {
					route = "/"
				}
				body, _ := io.ReadAll(io.LimitReader(req.Body, l.MaxBodyBytes+1))
				_ = req.Body.Close()
				m := &Message{Direction: "request", Method: req.Method, Route: route, HTTPVersion: req.Proto, Headers: redactHTTPHeaders(req.Header, c.RedactionSummary), MediaType: media(req.Header.Get("Content-Type")), ContentEncoding: req.Header.Get("Content-Encoding"), TransferEncoding: strings.Join(req.TransferEncoding, ","), DeclaredLength: req.ContentLength, Body: bodyField(body, l), rawBody: body}
				m.Structured, m.Warnings = ParseStructured(req.Header.Get("Content-Type"), body, l)
				state := "request_only"
				if !complete || int64(len(body)) > l.MaxBodyBytes {
					state = "partial_request"
				}
				c.Exchanges = append(c.Exchanges, Exchange{Index: len(c.Exchanges), StreamID: stableID("stream", canonicalFlowKey(k)), Request: m, AssociationEvidence: []string{"bounded TCP stream framing"}, AssociationConfidence: "medium", State: state})
			}
		} else if len(stream) > 2 && stream[0] == 0x16 && stream[1] == 0x03 {
			c.Source.Warnings = append(c.Source.Warnings, "opaque TLS stream; HTTP content not visible")
		}
	}
	pairDirectional(&c)
	return c, nil
}

func canonicalFlowKey(k string) string {
	p := strings.Split(k, ">")
	if len(p) != 2 {
		return k
	}
	if p[0] > p[1] {
		p[0], p[1] = p[1], p[0]
	}
	return p[0] + "<>" + p[1]
}
func pairDirectional(c *NormalizedCapture) {
	groups := map[string][]Exchange{}
	for _, e := range c.Exchanges {
		groups[e.StreamID] = append(groups[e.StreamID], e)
	}
	var out []Exchange
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		xs := groups[k]
		var reqs, resps []*Message
		for _, e := range xs {
			if e.Request != nil {
				reqs = append(reqs, e.Request)
			}
			if e.Response != nil {
				resps = append(resps, e.Response)
			}
		}
		n := len(reqs)
		if len(resps) > n {
			n = len(resps)
		}
		f := Flow{ID: k, Transport: "tcp", DirectionConfidence: "medium", RequestCount: len(reqs), ResponseCount: len(resps)}
		for _, w := range c.Source.Warnings {
			switch {
			case strings.Contains(w, "missing TCP"):
				f.Gaps++
			case strings.Contains(w, "duplicate"):
				f.Duplicates++
				f.Retransmissions++
			case strings.Contains(w, "overlapping"):
				f.Conflicts++
			}
		}
		if f.Gaps > 0 || f.Conflicts > 0 {
			f.State = "partial"
		} else {
			f.State = "reassembled"
		}
		for i := 0; i < n; i++ {
			e := Exchange{Index: len(out), StreamID: k, AssociationEvidence: []string{"same bidirectional TCP flow", "HTTP/1 response order"}, AssociationConfidence: "medium"}
			if i < len(reqs) {
				e.Request = reqs[i]
			}
			if i < len(resps) {
				e.Response = resps[i]
				e.ResponseComplete = true
			}
			switch {
			case e.Request != nil && e.Response != nil:
				e.State = "complete"
			case e.Request != nil:
				e.State = "request_only"
			case e.Response != nil:
				e.State = "response_only"
			}
			out = append(out, e)
		}
		c.Flows = append(c.Flows, f)
	}
	c.Exchanges = out
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
