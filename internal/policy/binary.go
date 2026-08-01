package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	MaxBinaryObservations = 512
	MaxBinaryBytes        = 8 << 20
)

type BinaryObservation struct {
	Classification string  `json:"classification"`
	Offset         int     `json:"offset"`
	Length         int     `json:"length"`
	Encoding       string  `json:"encoding,omitempty"`
	Description    string  `json:"description"`
	Confidence     float64 `json:"confidence"`
}
type BinaryAnalysis struct {
	Size           int                 `json:"size"`
	SHA256         string              `json:"sha256"`
	Entropy        float64             `json:"entropy"`
	PrintableRatio float64             `json:"printable_ratio"`
	Observations   []BinaryObservation `json:"observations"`
	Unknown        []string            `json:"unknown"`
}

var (
	urlBytes   = regexp.MustCompile(`(?i)https?://[a-z0-9._~-]+(?::[0-9]{1,5})?(?:/[a-z0-9._~!$&'()*+,;=:@%/?#-]*)?`)
	routeBytes = regexp.MustCompile(`/(?:[A-Za-z0-9._$~-]+/)*[A-Za-z0-9._$?=&%~-]+`)
	uncBytes   = regexp.MustCompile(`\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9.$_-]+(?:\\[A-Za-z0-9 ._$-]+)*`)
	hostBytes  = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b`)
	guidBytes  = regexp.MustCompile(`(?i)\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?`)
	sidBytes   = regexp.MustCompile(`\bS-1-[0-9]+(?:-[0-9]+){2,15}\b`)
)

func InspectBinary(b []byte) (BinaryAnalysis, error) {
	if len(b) > MaxBinaryBytes {
		return BinaryAnalysis{}, errors.New("binary input exceeds limit")
	}
	sum := sha256.Sum256(b)
	a := BinaryAnalysis{Size: len(b), SHA256: "sha256:" + hex.EncodeToString(sum[:]), Unknown: []string{"protocol field semantics remain unknown", "heuristic values require fixture comparison"}}
	freq := [256]int{}
	printable := 0
	for _, x := range b {
		freq[x]++
		if x >= 32 && x < 127 {
			printable++
		}
	}
	if len(b) > 0 {
		a.PrintableRatio = float64(printable) / float64(len(b))
		for _, n := range freq {
			if n > 0 {
				p := float64(n) / float64(len(b))
				a.Entropy -= p * math.Log2(p)
			}
		}
	}
	add := func(c string, o, l int, e, d string, conf float64) {
		if l > 0 && len(a.Observations) < MaxBinaryObservations {
			a.Observations = append(a.Observations, BinaryObservation{c, o, l, e, d, conf})
		}
	}
	for _, bom := range []struct {
		v   []byte
		enc string
	}{{[]byte{0xef, 0xbb, 0xbf}, "utf-8"}, {[]byte{0xff, 0xfe}, "utf-16le"}, {[]byte{0xfe, 0xff}, "utf-16be"}} {
		if bytes.HasPrefix(b, bom.v) {
			add("observed", 0, len(bom.v), bom.enc, "byte-order mark", 1)
		}
	}
	for _, r := range detectTextRegions(b) {
		add("observed", r.Offset, r.Length, r.Encoding, "bounded text region (content preview redacted)", .95)
	}
	for _, p := range []struct {
		re   *regexp.Regexp
		desc string
		conf float64
	}{{urlBytes, "embedded URL", .98}, {routeBytes, "relative HTTP path candidate", .7}, {uncBytes, "UNC path", .95}, {hostBytes, "hostname-like string (role unknown)", .65}, {guidBytes, "text GUID", .98}, {sidBytes, "SID-like text", .9}} {
		for _, m := range p.re.FindAllIndex(b, 64) {
			add(mapClass(p.conf), m[0], m[1]-m[0], "ascii", p.desc, p.conf)
		}
	}
	lower := bytes.ToLower(b)
	for _, p := range []struct{ s, desc string }{{"<?xml", "embedded XML start"}, {"content-type:", "MIME content-type header"}, {"content-disposition:", "multipart header"}, {"multipart/", "multipart content type"}, {"boundary=", "MIME boundary declaration"}} {
		for off := 0; ; {
			i := bytes.Index(lower[off:], []byte(p.s))
			if i < 0 {
				break
			}
			i += off
			end := bytes.IndexByte(b[i:], '\n')
			if end < 0 || end > 1024 {
				end = len(p.s)
			}
			add("observed", i, end, "ascii", p.desc, .95)
			off = i + len(p.s)
		}
	}
	for _, m := range []struct {
		v    []byte
		desc string
	}{{[]byte{0x1f, 0x8b}, "gzip header"}, {[]byte{'P', 'K', 3, 4}, "ZIP local header"}, {[]byte{'P', 'K', 1, 2}, "ZIP central-directory hint"}, {[]byte{'M', 'S', 'C', 'F'}, "CAB header"}} {
		for off := 0; ; {
			i := bytes.Index(b[off:], m.v)
			if i < 0 {
				break
			}
			i += off
			add("observed", i, len(m.v), "binary", m.desc, 1)
			off = i + len(m.v)
		}
	}
	if i := bytes.Index(b, []byte{'M', 'S', 'C', 'F'}); i >= 0 && i+36 <= len(b) {
		size := binary.LittleEndian.Uint32(b[i+8 : i+12])
		folders := binary.LittleEndian.Uint16(b[i+26 : i+28])
		files := binary.LittleEndian.Uint16(b[i+28 : i+30])
		add("observed", i, 36, "little-endian", fmt.Sprintf("CAB header metadata: cabinet_size=%d folders=%d files=%d", size, folders, files), .98)
	}
	if i := bytes.Index(b, []byte{0x1f, 0x8b}); i >= 0 && i+10 <= len(b) {
		add("observed", i, 10, "binary", fmt.Sprintf("gzip header metadata: method=%d flags=0x%02x", b[i+2], b[i+3]), .98)
	}
	if off, n := nullDelimitedTable(b); n > 0 {
		add("heuristic", off, n, "binary", "long null-delimited string table candidate", .65)
	}
	for i := 0; i+16 <= len(b); i++ {
		x := b[i : i+16]
		if x[6]&0xf0 >= 0x10 && x[6]&0xf0 <= 0x50 && x[8]&0xc0 == 0x80 {
			add("heuristic", i, 16, "binary", "binary GUID candidate", .45)
			i += 15
		}
	}
	for i := 0; i+4 <= len(b) && i < 4096; i += 4 {
		le := binary.LittleEndian.Uint32(b[i : i+4])
		be := binary.BigEndian.Uint32(b[i : i+4])
		if le > 0 && int(le) <= len(b)-i {
			add("heuristic", i, 4, "little-endian", "candidate bounded length value", .35)
		}
		if be != le && be > 0 && int(be) <= len(b)-i {
			add("heuristic", i, 4, "big-endian", "candidate bounded length value", .35)
		}
	}
	if n := trailingSame(b); n >= 8 {
		add("observed", len(b)-n, n, "binary", "trailing repeated-byte padding", .9)
	}
	if off, size := repeatedBlock(b); size > 0 {
		add("heuristic", off, size, "binary", "repeated fixed-size block pattern", .55)
	}
	for off := 0; off+256 <= len(b); off += 256 {
		if entropy(b[off:off+256]) >= 7.4 {
			add("heuristic", off, 256, "binary", "high-entropy region", .6)
		}
	}
	for _, n := range []int{16, 20, 32, 64} {
		for off := 0; off+n <= len(b) && off < 4096; off += n {
			chunk := b[off : off+n]
			if entropy(chunk) > float64(n)/4 && bytes.IndexByte(chunk, 0) < 0 {
				add("heuristic", off, n, "binary", "candidate checksum or hash-sized region", .3)
			}
		}
	}
	sort.SliceStable(a.Observations, func(i, j int) bool {
		x, y := a.Observations[i], a.Observations[j]
		if x.Offset != y.Offset {
			return x.Offset < y.Offset
		}
		if x.Length != y.Length {
			return x.Length < y.Length
		}
		return x.Description < y.Description
	})
	return a, nil
}
func mapClass(c float64) string {
	if c >= .9 {
		return "observed"
	}
	return "heuristic"
}
func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var f [256]int
	for _, x := range b {
		f[x]++
	}
	e := 0.
	for _, n := range f {
		if n > 0 {
			p := float64(n) / float64(len(b))
			e -= p * math.Log2(p)
		}
	}
	return e
}
func trailingSame(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	i := len(b) - 1
	for i > 0 && b[i-1] == b[len(b)-1] {
		i--
	}
	return len(b) - i
}
func repeatedBlock(b []byte) (int, int) {
	for _, n := range []int{8, 16, 32, 64} {
		for i := 0; i+3*n <= len(b); i++ {
			if bytes.Equal(b[i:i+n], b[i+n:i+2*n]) && bytes.Equal(b[i:i+n], b[i+2*n:i+3*n]) {
				return i, 3 * n
			}
		}
	}
	return 0, 0
}
func nullDelimitedTable(b []byte) (int, int) {
	for i := 0; i < len(b); i++ {
		start := i
		count := 0
		for i < len(b) {
			j := bytes.IndexByte(b[i:], 0)
			if j < 2 {
				break
			}
			j += i
			ok := true
			for _, x := range b[i:j] {
				if x < 0x20 || x >= 0x7f {
					ok = false
					break
				}
			}
			if !ok {
				break
			}
			count++
			i = j + 1
		}
		if count >= 4 {
			return start, i - start
		}
		i = start
	}
	return 0, 0
}

type TextRegion struct {
	Offset, Length int
	Encoding, Text string
}

func detectTextRegions(b []byte) []TextRegion {
	var out []TextRegion
	// UTF-16 is detected first; ASCII runs with alternating NULs are excluded below.
	for _, be := range []bool{false, true} {
		for i := 0; i+8 <= len(b); i++ {
			start := i
			var u []uint16
			for i+1 < len(b) {
				var v uint16
				if be {
					v = binary.BigEndian.Uint16(b[i : i+2])
				} else {
					v = binary.LittleEndian.Uint16(b[i : i+2])
				}
				if v == 0 || v < 0x20 || v == 0xffff {
					break
				}
				r := utf16.Decode([]uint16{v})[0]
				if r == '\ufffd' || (!utf8.ValidRune(r)) {
					break
				}
				u = append(u, v)
				i += 2
			}
			if len(u) >= 4 {
				enc := "utf-16le"
				if be {
					enc = "utf-16be"
				}
				out = append(out, TextRegion{start, len(u) * 2, enc, string(utf16.Decode(u))})
				i = start + len(u)*2 - 1
			} else {
				i = start
			}
		}
	}
	for i := 0; i < len(b); {
		if b[i] < 0x20 || b[i] == 0x7f || b[i] == 0 {
			i++
			continue
		}
		start := i
		for i < len(b) && b[i] != 0 && b[i] >= 0x20 && b[i] != 0x7f {
			i++
		}
		if i-start >= 4 && utf8.Valid(b[start:i]) {
			enc := "utf-8"
			ascii := true
			for _, x := range b[start:i] {
				if x >= 0x80 {
					ascii = false
				}
			}
			if ascii {
				enc = "ascii"
			}
			out = append(out, TextRegion{start, i - start, enc, string(b[start:i])})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Offset != out[j].Offset {
			return out[i].Offset < out[j].Offset
		}
		return out[i].Encoding < out[j].Encoding
	})
	return out
}

type ServerOptions struct {
	Listen                      string
	Strict, Once                bool
	RequestTimeout, IdleTimeout time.Duration
}

func ServeFixture(ctx context.Context, f Fixture, o ServerOptions) (string, <-chan error, error) {
	host, _, e := net.SplitHostPort(o.Listen)
	if e != nil {
		return "", nil, e
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return "", nil, errors.New("wildcard fixture bind is forbidden")
	}
	ips, e := net.LookupIP(host)
	if e != nil {
		return "", nil, e
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return "", nil, errors.New("fixture server hostname must resolve only to loopback")
		}
	}
	ln, e := net.Listen("tcp", o.Listen)
	if e != nil {
		return "", nil, e
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = 10 * time.Second
	}
	srv := &http.Server{ReadHeaderTimeout: o.RequestTimeout, ReadTimeout: o.RequestTimeout, WriteTimeout: o.RequestTimeout, IdleTimeout: o.IdleTimeout, MaxHeaderBytes: 64 << 10}
	done := make(chan error, 1)
	var once sync.Once
	var idle *time.Timer
	if o.IdleTimeout > 0 {
		idle = time.AfterFunc(o.IdleTimeout, func() {
			c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			select {
			case done <- srv.Shutdown(c):
			default:
			}
		})
	}
	allowed := map[string]bool{"Content-Type": true, "Content-Length": true, "Cache-Control": true, "ETag": true, "Last-Modified": true}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if idle != nil {
			idle.Reset(o.IdleTimeout)
		}
		if r.URL.Path != f.Metadata.Request.Route || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		if r.Method != f.Metadata.Request.Method {
			http.Error(w, "fixture method mismatch", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxFixtureBytes)
		body, er := io.ReadAll(r.Body)
		if er != nil {
			http.Error(w, "bounded fixture request rejected", http.StatusRequestEntityTooLarge)
			return
		}
		if o.Strict && !bytes.Equal(body, f.RequestBody) {
			http.Error(w, "fixture body fingerprint mismatch", http.StatusBadRequest)
			return
		}
		if o.Strict {
			for k, v := range f.RequestHeaders {
				if !equalHeaderValues(r.Header.Values(k), v) {
					http.Error(w, "fixture header mismatch", http.StatusBadRequest)
					return
				}
			}
		}
		for k, v := range f.ResponseHeaders {
			if allowed[http.CanonicalHeaderKey(k)] {
				for _, x := range v {
					w.Header().Add(k, x)
				}
			}
		}
		status := f.Metadata.Response.Status
		if status < 100 {
			status = 200
		}
		w.WriteHeader(status)
		_, _ = w.Write(f.ResponseBody)
		if o.Once {
			once.Do(func() {
				go func() {
					c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					done <- srv.Shutdown(c)
				}()
			})
		}
	})
	go func() {
		e := srv.Serve(ln)
		if e != nil && !errors.Is(e, http.ErrServerClosed) {
			select {
			case done <- e:
			default:
			}
		}
	}()
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		select {
		case done <- srv.Shutdown(c):
		default:
		}
	}()
	return "http://" + ln.Addr().String(), done, nil
}
func equalHeaderValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	return strings.Join(aa, "\x00") == strings.Join(bb, "\x00")
}
