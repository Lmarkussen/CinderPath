package live

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>Lab</title>"+strings.Repeat("x", 100))
	}))
	defer srv.Close()
	d := profileEndpoint(context.Background(), srv.URL, HTTPOptions{UserAgent: "test", MaxBodyBytes: 32, MaxRedirects: 1, Timeout: time.Second})
	if d["body_truncated"] != true {
		t.Fatalf("data=%v", d)
	}
	if len(d["body_preview"].(string)) > 32 {
		t.Fatal("preview exceeded limit")
	}
}
func TestHTTPRedirectLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/again", http.StatusFound) }))
	defer srv.Close()
	d := profileEndpoint(context.Background(), srv.URL, HTTPOptions{UserAgent: "test", MaxBodyBytes: 32, MaxRedirects: 1, Timeout: time.Second})
	if d["error"] == nil || !strings.Contains(fmt.Sprint(d["error"]), "redirect limit") {
		t.Fatalf("data=%v", d)
	}
}
func TestTLSMetadata(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer srv.Close()
	d := profileEndpoint(context.Background(), srv.URL, HTTPOptions{UserAgent: "test", MaxBodyBytes: 32, MaxRedirects: 1, Timeout: time.Second})
	tlsData, ok := d["tls"].(map[string]any)
	if !ok || tlsData["sha256_fingerprint"] == "" {
		t.Fatalf("data=%v", d)
	}
	if tlsData["verification_successful"] != false {
		t.Fatalf("expected fixture certificate to be untrusted: %v", tlsData)
	}
}
