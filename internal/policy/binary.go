package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"time"
	"unicode/utf8"
)

type BinaryObservation struct {
	Kind, Description string
	Offset            int
}
type BinaryAnalysis struct {
	Size                    int
	SHA256                  string
	Entropy, PrintableRatio float64
	Observed, Heuristic     []BinaryObservation
	Unknown                 []string
}

func InspectBinary(b []byte) (BinaryAnalysis, error) {
	if len(b) > MaxFixtureBytes {
		return BinaryAnalysis{}, errors.New("binary input exceeds limit")
	}
	sum := sha256.Sum256(b)
	a := BinaryAnalysis{Size: len(b), SHA256: "sha256:" + hex.EncodeToString(sum[:]), Unknown: []string{"message envelope type", "compression semantics", "integrity fields"}}
	freq := [256]int{}
	print := 0
	for _, x := range b {
		freq[x]++
		if x >= 32 && x < 127 {
			print++
		}
	}
	if len(b) > 0 {
		a.PrintableRatio = float64(print) / float64(len(b))
		for _, n := range freq {
			if n > 0 {
				p := float64(n) / float64(len(b))
				a.Entropy -= p * math.Log2(p)
			}
		}
	}
	add := func(k, d string, o int) { a.Observed = append(a.Observed, BinaryObservation{k, d, o}) }
	if utf8.Valid(b) && a.PrintableRatio > .5 {
		add("utf8", "UTF-8 text present", 0)
	}
	if i := bytes.Index(b, []byte("<?xml")); i >= 0 {
		add("xml", "XML signature", i)
	}
	for _, m := range []struct {
		v []byte
		n string
	}{{[]byte{0x1f, 0x8b}, "gzip"}, {[]byte{'P', 'K', 3, 4}, "zip"}, {[]byte{'M', 'S', 'C', 'F'}, "cab"}} {
		if i := bytes.Index(b, m.v); i >= 0 {
			add("magic", m.n+" magic", i)
		}
	}
	if bytes.Contains(bytes.ToLower(b), []byte("multipart/")) {
		add("mime", "multipart marker", bytes.Index(bytes.ToLower(b), []byte("multipart/")))
	}
	nulls := bytes.Count(b, []byte{0})
	if nulls > len(b)/4 {
		add("null_pattern", "frequent null bytes; possible UTF-16 or padding", 0)
	}
	for i := 0; i+4 <= len(b) && i < 256; i += 4 {
		v := binary.LittleEndian.Uint32(b[i : i+4])
		if v > 0 && int(v) <= len(b) {
			a.Heuristic = append(a.Heuristic, BinaryObservation{"candidate_length", "possible little-endian length matching bounded input", i})
		}
	}
	return a, nil
}
func ServeFixture(ctx context.Context, f Fixture, listen string, strict, once bool) (string, error) {
	host, _, e := net.SplitHostPort(listen)
	if e != nil {
		return "", e
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("fixture server must bind to an explicit loopback address")
	}
	ln, e := net.Listen("tcp", listen)
	if e != nil {
		return "", e
	}
	mux := http.NewServeMux()
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	mux.HandleFunc(f.Metadata.Request.Route, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != f.Metadata.Request.Method {
			http.Error(w, "fixture method mismatch", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxFixtureBytes)
		body, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, "bounded fixture request rejected", http.StatusRequestEntityTooLarge)
			return
		}
		if strict && !bytes.Equal(body, f.RequestBody) {
			http.Error(w, "fixture body fingerprint mismatch", http.StatusBadRequest)
			return
		}
		for k, v := range f.ResponseHeaders {
			if !forbiddenHeader(k) {
				for _, x := range v {
					w.Header().Add(k, x)
				}
			}
		}
		w.WriteHeader(f.Metadata.Response.Status)
		_, _ = w.Write(f.ResponseBody)
		if once {
			go srv.Shutdown(context.Background())
		}
	})
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	go srv.Serve(ln)
	return "http://" + ln.Addr().String(), nil
}
