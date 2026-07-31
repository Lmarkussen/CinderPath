package live

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/progress"
)

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type httpModule struct{ opts Options }

func (m *httpModule) Metadata() modules.Metadata {
	return modules.Metadata{Name: "live.http.profile", Description: "Collects bounded HTTP and TLS metadata from open web endpoints", Category: modules.CategoryDiscovery, Safety: modules.SafetySafe, Requirements: []modules.Requirement{{Capability: "network_probe_completed"}}}
}
func (m *httpModule) Applicable(context.Context, modules.RunContext, *models.Asset) (bool, string) {
	return true, ""
}
func (m *httpModule) Run(ctx context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	run.Emit(progress.Event{Type: progress.StageStarted, Module: m.Metadata().Name, Message: "bounded HTTP profiling"})
	assets, err := run.Store.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	targets := filterLiveTargets(assets)
	out := &modules.Result{}
	var mu sync.Mutex
	parallel(ctx, m.opts.Concurrency, len(targets), func(i int) {
		a := targets[i]
		open := parseOpenPorts(a.Properties["open_ports"])
		var endpoints []string
		var evidence []models.Evidence
		for _, port := range []int{80, 443, 8530, 8531} {
			if !open[port] {
				continue
			}
			scheme := "http"
			if port == 443 || port == 8531 {
				scheme = "https"
			}
			endpoint := fmt.Sprintf("%s://%s/", scheme, netHostPort(targetAddress(a), port, scheme))
			data := profileEndpoint(ctx, endpoint, m.opts.HTTP)
			e := models.Evidence{Type: "http_profile", Title: "HTTP endpoint " + endpoint, Summary: httpSummary(data), Data: data, SourceModule: m.Metadata().Name, AssetID: a.ID, Sensitivity: models.SensitivityInternal}
			e.Prepare(time.Now())
			evidence = append(evidence, e)
			endpoints = append(endpoints, endpoint)
		}
		if len(endpoints) > 0 {
			a.Properties = cloneMap(a.Properties)
			a.Properties["http_endpoints"] = strings.Join(endpoints, ",")
			mu.Lock()
			out.Assets = append(out.Assets, a)
			out.Evidence = append(out.Evidence, evidence...)
			mu.Unlock()
		}
	})
	cap := models.Capability{Name: "http_profiling", Available: true, Reason: "Bounded HTTP profiling stage completed", Source: m.Metadata().Name}
	cap.Prepare()
	out.Capabilities = []models.Capability{cap}
	return out, ctx.Err()
}
func netHostPort(host string, port int, scheme string) string {
	_ = scheme
	return net.JoinHostPort(host, strconv.Itoa(port))
}
func profileEndpoint(ctx context.Context, endpoint string, opts HTTPOptions) map[string]any {
	start := time.Now()
	data := map[string]any{"endpoint": endpoint, "transport_tls_verification": "independent_after_collection", "max_body_bytes": opts.MaxBodyBytes}
	transport := &http.Transport{TLSClientConfig: tlsConfigInsecure(), TLSHandshakeTimeout: opts.Timeout, ResponseHeaderTimeout: opts.Timeout, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: opts.Timeout, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) > opts.MaxRedirects {
			return fmt.Errorf("redirect limit %d exceeded", opts.MaxRedirects)
		}
		if len(via) > 0 && !strings.EqualFold(request.URL.Hostname(), via[0].URL.Hostname()) {
			return fmt.Errorf("redirect outside scoped host is not allowed")
		}
		return nil
	}}
	defer transport.CloseIdleConnections()
	headReq, _ := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	headReq.Header.Set("User-Agent", opts.UserAgent)
	if resp, err := client.Do(headReq); err == nil {
		data["head_status_code"] = resp.StatusCode
		_ = resp.Body.Close()
	} else {
		data["head_error"] = err.Error()
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("User-Agent", opts.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		data["error"] = err.Error()
		data["duration_ms"] = time.Since(start).Milliseconds()
		return data
	}
	defer resp.Body.Close()
	data["status_code"] = resp.StatusCode
	copyHeader(data, resp.Header, "Server", "server")
	copyHeader(data, resp.Header, "Location", "location")
	copyHeader(data, resp.Header, "Content-Type", "content_type")
	data["authentication_headers"] = resp.Header.Values("WWW-Authenticate")
	limited, readErr := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes+1))
	if readErr != nil {
		data["body_error"] = readErr.Error()
	}
	truncated := int64(len(limited)) > opts.MaxBodyBytes
	if truncated {
		limited = limited[:opts.MaxBodyBytes]
	}
	data["body_truncated"] = truncated
	if utf8.Valid(limited) {
		preview := strings.TrimSpace(string(limited))
		data["body_preview"] = preview
		if match := titlePattern.FindStringSubmatch(preview); len(match) > 1 {
			data["page_title"] = strings.TrimSpace(htmlSpace(match[1]))
		}
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		data["tls"] = certificateMetadata(resp.TLS.PeerCertificates[0], req.URL.Hostname())
	}
	data["final_url"] = resp.Request.URL.String()
	data["duration_ms"] = time.Since(start).Milliseconds()
	return data
}
func tlsConfigInsecure() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
} // #nosec G402 -- scoped collection verifies independently and records result.
func certificateMetadata(cert *x509.Certificate, hostname string) map[string]any {
	sum := sha256.Sum256(cert.Raw)
	verified := false
	verifyError := ""
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: hostname}); err == nil {
		verified = true
	} else {
		verifyError = err.Error()
	}
	ips := make([]string, len(cert.IPAddresses))
	for i := range cert.IPAddresses {
		ips[i] = cert.IPAddresses[i].String()
	}
	dns := append([]string(nil), cert.DNSNames...)
	sort.Strings(dns)
	return map[string]any{"subject": cert.Subject.String(), "issuer": cert.Issuer.String(), "dns_names": dns, "ip_addresses": ips, "serial_number": cert.SerialNumber.String(), "not_before": cert.NotBefore.UTC(), "not_after": cert.NotAfter.UTC(), "signature_algorithm": cert.SignatureAlgorithm.String(), "sha256_fingerprint": hex.EncodeToString(sum[:]), "verification_successful": verified, "verification_error": verifyError}
}
func copyHeader(data map[string]any, h http.Header, name, key string) {
	if v := h.Get(name); v != "" {
		data[key] = v
	}
}
func httpSummary(data map[string]any) string {
	if err, ok := data["error"]; ok {
		return "HTTP profiling failed safely: " + fmt.Sprint(err)
	}
	return fmt.Sprintf("HTTP endpoint returned status %v.", data["status_code"])
}
func htmlSpace(s string) string {
	return strings.Join(strings.Fields(regexp.MustCompile(`<[^>]+>`).ReplaceAllString(s, " ")), " ")
}
