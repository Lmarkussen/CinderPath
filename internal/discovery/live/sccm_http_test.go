package live

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
)

func sccmTestOptions() HTTPOptions {
	return HTTPOptions{UserAgent: "CinderPath-test", MaxBodyBytes: 4096, MaxRedirects: 2, Timeout: time.Second}
}

func observationByID(t *testing.T, observations []routeObservation, routeID string) routeObservation {
	t.Helper()
	for _, observation := range observations {
		if observation.RouteID == routeID {
			return observation
		}
	}
	t.Fatalf("route %s not observed: %+v", routeID, observations)
	return routeObservation{}
}

func TestParseManagementPointList(t *testing.T) {
	parsed := parseMPList([]byte(`<MPList><MP><FQDN>MP01.LAB.LOCAL</FQDN><SiteCode>lab</SiteCode></MP></MPList>`))
	if parsed.Outcome != "valid_sccm_mp_list" || len(parsed.Hosts) != 1 || parsed.Hosts[0] != "mp01.lab.local" || len(parsed.SiteCodes) != 1 || parsed.SiteCodes[0] != "LAB" {
		t.Fatalf("parsed=%+v", parsed)
	}
	for name, input := range map[string]string{
		"generic HTML":  `<html><title>Welcome</title></html>`,
		"generic XML":   `<root><server>mp01.lab.local</server></root>`,
		"malformed XML": `<MPList><MP FQDN="mp01.lab.local">`,
	} {
		t.Run(name, func(t *testing.T) {
			if result := parseMPList([]byte(input)); result.Outcome == "valid_sccm_mp_list" {
				t.Fatalf("accepted %q: %+v", input, result)
			}
		})
	}
}

func TestManagementPointRouteValidationStates(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		body          string
		auth          string
		wantParser    string
		wantValidated bool
		wantAuth      bool
	}{
		{name: "valid", status: http.StatusOK, body: `<MPList><MP FQDN="mp01.lab.local" SiteCode="LAB"/></MPList>`, wantParser: "valid_sccm_mp_list", wantValidated: true},
		{name: "generic 200", status: http.StatusOK, body: `<html><title>IIS</title></html>`, wantParser: "generic_html"},
		{name: "authentication required", status: http.StatusUnauthorized, auth: "Negotiate, NTLM", wantParser: "empty_response", wantAuth: true},
		{name: "authentication response body is not usable", status: http.StatusUnauthorized, auth: "Negotiate", body: `<MPList><MP FQDN="mp01.lab.local" SiteCode="LAB"/></MPList>`, wantParser: "valid_sccm_mp_list", wantAuth: true},
		{name: "malformed", status: http.StatusOK, body: `<MPList><MP>`, wantParser: "malformed_xml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/SMS_MP/.sms_aut" {
					if tt.auth != "" {
						w.Header().Set("WWW-Authenticate", tt.auth)
					}
					w.WriteHeader(tt.status)
					_, _ = io.WriteString(w, tt.body)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()
			parsed, _ := url.Parse(server.URL)
			observations := probeSCCMOrigin(context.Background(), "asset", server.URL, map[string]any{"head_status_code": 404}, map[string]bool{normalizeHost(parsed.Hostname()): true}, sccmTestOptions())
			mp := observationByID(t, observations, sccmRouteMPList)
			if mp.ParserOutcome != tt.wantParser || mp.AccessState.ProtocolValidated != tt.wantValidated || mp.AccessState.UsableReadAccess != tt.wantValidated || mp.AccessState.AuthenticationRequested != tt.wantAuth {
				t.Fatalf("observation=%+v", mp)
			}
			if !mp.AccessState.AnonymousRequest || mp.AccessState.AuthenticationAttempted || mp.AccessState.Authenticated {
				t.Fatalf("unsafe access state=%+v", mp.AccessState)
			}
		})
	}
}

func TestManagementPointResponseIsBoundedAndReferencesArePassive(t *testing.T) {
	var referencedContacts atomic.Int64
	referenced := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { referencedContacts.Add(1) }))
	defer referenced.Close()
	referencedURL, _ := url.Parse(referenced.URL)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/SMS_MP/.sms_aut" {
			fmt.Fprintf(w, `<MPList><MP FQDN=%q SiteCode="LAB"/></MPList>%s`, "http://localhost:"+referencedURL.Port()+"/", strings.Repeat("x", 256))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	originURL, _ := url.Parse(server.URL)
	scope := map[string]bool{normalizeHost(originURL.Hostname()): true}
	opts := sccmTestOptions()
	opts.MaxBodyBytes = 64
	observations := probeSCCMOrigin(context.Background(), "asset", server.URL, nil, scope, opts)
	mp := observationByID(t, observations, sccmRouteMPList)
	if !mp.Truncated || mp.ParserOutcome != "oversized_response" || len(mp.Preview) > 64 {
		t.Fatalf("observation=%+v", mp)
	}
	if referencedContacts.Load() != 0 {
		t.Fatal("a host referenced by MP-list data was contacted")
	}
	if len(scope) != 1 || scope["localhost"] {
		t.Fatalf("referenced MP host was added to active scope: %v", scope)
	}
}

func TestDistributionPointRoutesAreHEADOnlyAndAllowlisted(t *testing.T) {
	var mu sync.Mutex
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || len(body) != 0 || request.ContentLength > 0 {
			t.Errorf("unsafe request headers/body: %s %s", request.Method, request.URL.String())
		}
		mu.Lock()
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		mu.Unlock()
		if strings.HasPrefix(request.URL.Path, "/SMS_DP_") || strings.HasPrefix(request.URL.Path, "/NOCERT_SMS_DP_") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	observations := probeSCCMOrigin(context.Background(), "asset", server.URL, map[string]any{"head_status_code": 404}, map[string]bool{normalizeHost(u.Hostname()): true}, sccmTestOptions())
	if len(observations) != 5 || len(requests) != 5 {
		t.Fatalf("observations=%d requests=%v", len(observations), requests)
	}
	want := map[string]bool{
		"GET /SMS_MP/.sms_aut?MPLIST": true,
		"HEAD /SMS_DP_SMSPKG$/":       true, "HEAD /SMS_DP_SMSSIG$/": true,
		"HEAD /NOCERT_SMS_DP_SMSPKG$/": true, "HEAD /NOCERT_SMS_DP_SMSSIG$/": true,
	}
	for _, request := range requests {
		if !want[request] {
			t.Fatalf("unexpected method or route: %q", request)
		}
		delete(want, request)
	}
	if len(want) != 0 {
		t.Fatalf("missing routes: %v", want)
	}
	for _, observation := range observations[1:] {
		if observation.Method != http.MethodHead || observation.StatusCode != http.StatusNoContent || observation.MatchesRootProfile {
			t.Fatalf("DP observation=%+v", observation)
		}
	}
}

func TestDistributionPointCatchAllProtection(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		auth   string
		root   map[string]any
	}{
		{name: "catch-all 401", status: 401, auth: "Negotiate", root: map[string]any{"head_status_code": 401, "head_authentication_headers": []string{"Negotiate"}}},
		{name: "generic catch-all 200", status: 200, root: map[string]any{"head_status_code": 200}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if tt.auth != "" {
					w.Header().Set("WWW-Authenticate", tt.auth)
				}
				w.WriteHeader(tt.status)
			}))
			defer server.Close()
			u, _ := url.Parse(server.URL)
			observations := probeSCCMOrigin(context.Background(), "asset", server.URL, tt.root, map[string]bool{normalizeHost(u.Hostname()): true}, sccmTestOptions())
			for _, observation := range observations[1:] {
				if !observation.MatchesRootProfile {
					t.Fatalf("catch-all was not detected: %+v", observation)
				}
			}
			items := dpTestItems(observations[1:])
			classification, _, _, _ := classifyDistributionPoint(items, nil, models.Asset{})
			if classification == "likely_distribution_point" {
				t.Fatal("catch-all response validated a DP")
			}
		})
	}
}

func TestDistributionPointPositiveAndMissingClassification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/SMS_DP_SMSPKG$/" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	observations := probeSCCMOrigin(context.Background(), "asset", server.URL, map[string]any{"head_status_code": 404}, map[string]bool{normalizeHost(u.Hostname()): true}, sccmTestOptions())
	classification, confidence, _, _ := classifyDistributionPoint(dpTestItems(observations[1:]), nil, models.Asset{})
	if classification != "likely_distribution_point" || confidence != string(models.ConfidenceHigh) {
		t.Fatalf("classification=%s confidence=%s", classification, confidence)
	}
	missing := observationByID(t, observations, "dp_sms_sig")
	if missing.StatusCode != http.StatusNotFound || missing.UnverifiedReason != "route_not_found_inconclusive" {
		t.Fatalf("missing=%+v", missing)
	}
}

func dpTestItems(observations []routeObservation) []struct {
	evidence    models.Evidence
	observation routeObservation
} {
	out := make([]struct {
		evidence    models.Evidence
		observation routeObservation
	}, 0, len(observations))
	for _, observation := range observations {
		evidence := routeEvidenceFromObservation(observation, "test")
		out = append(out, struct {
			evidence    models.Evidence
			observation routeObservation
		}{evidence, observation})
	}
	return out
}

func TestSCCMRedirectPolicy(t *testing.T) {
	t.Run("same origin accepted", func(t *testing.T) {
		var count atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			count.Add(1)
			if request.URL.Path == "/SMS_MP/.sms_aut" {
				http.Redirect(w, request, "/mp-list-result", http.StatusFound)
				return
			}
			if request.URL.Path == "/mp-list-result" {
				_, _ = io.WriteString(w, `<MPList><MP FQDN="mp01.lab.local" SiteCode="LAB"/></MPList>`)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()
		u, _ := url.Parse(server.URL)
		observations := probeSCCMOrigin(context.Background(), "asset", server.URL, nil, map[string]bool{normalizeHost(u.Hostname()): true}, sccmTestOptions())
		mp := observationByID(t, observations, sccmRouteMPList)
		if mp.RedirectDecision != "accepted_same_origin" || !mp.AccessState.ProtocolValidated {
			t.Fatalf("observation=%+v", mp)
		}
		if count.Load() > maxSCCMRoutesPerOrigin {
			t.Fatalf("request budget exceeded: %d", count.Load())
		}
	})
	t.Run("configured redirect limit is lower", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			http.Redirect(w, request, "/again", http.StatusFound)
		}))
		defer server.Close()
		u, _ := url.Parse(server.URL)
		opts := sccmTestOptions()
		opts.MaxRedirects = 0
		observations := probeSCCMOrigin(context.Background(), "asset", server.URL, nil, map[string]bool{normalizeHost(u.Hostname()): true}, opts)
		if decision := observationByID(t, observations, sccmRouteMPList).RedirectDecision; decision != "rejected_limit" {
			t.Fatalf("decision=%s", decision)
		}
	})

	tests := []struct {
		name         string
		makeLocation func(origin *url.URL, other string) string
		scope        func(origin *url.URL) map[string]bool
		want         string
		tlsOrigin    bool
	}{
		{name: "cross host", makeLocation: func(origin *url.URL, _ string) string {
			return origin.Scheme + "://localhost:" + origin.Port() + "/elsewhere"
		}, scope: func(origin *url.URL) map[string]bool {
			return map[string]bool{normalizeHost(origin.Hostname()): true, "localhost": true}
		}, want: "rejected_cross_host"},
		{name: "out of scope", makeLocation: func(origin *url.URL, _ string) string {
			return origin.Scheme + "://localhost:" + origin.Port() + "/elsewhere"
		}, scope: func(origin *url.URL) map[string]bool { return map[string]bool{normalizeHost(origin.Hostname()): true} }, want: "rejected_out_of_scope"},
		{name: "cross port", makeLocation: func(origin *url.URL, other string) string { return other + "/elsewhere" }, scope: func(origin *url.URL) map[string]bool { return map[string]bool{normalizeHost(origin.Hostname()): true} }, want: "rejected_cross_port"},
		{name: "http to https", makeLocation: func(_ *url.URL, other string) string {
			return strings.Replace(other, "http://", "https://", 1) + "/elsewhere"
		}, scope: func(origin *url.URL) map[string]bool { return map[string]bool{normalizeHost(origin.Hostname()): true} }, want: "rejected_cross_scheme"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			other := httptest.NewServer(http.NotFoundHandler())
			defer other.Close()
			var location string
			originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				http.Redirect(w, request, location, http.StatusFound)
			}))
			defer originServer.Close()
			origin, _ := url.Parse(originServer.URL)
			location = tt.makeLocation(origin, other.URL)
			observations := probeSCCMOrigin(context.Background(), "asset", originServer.URL, nil, tt.scope(origin), sccmTestOptions())
			if decision := observationByID(t, observations, sccmRouteMPList).RedirectDecision; decision != tt.want {
				t.Fatalf("decision=%s want=%s location=%s", decision, tt.want, location)
			}
		})
	}

	t.Run("https to http", func(t *testing.T) {
		var location string
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			http.Redirect(w, request, location, http.StatusFound)
		}))
		defer server.Close()
		u, _ := url.Parse(server.URL)
		location = "http://" + u.Host + "/elsewhere"
		observations := probeSCCMOrigin(context.Background(), "asset", server.URL, nil, map[string]bool{normalizeHost(u.Hostname()): true}, sccmTestOptions())
		if decision := observationByID(t, observations, sccmRouteMPList).RedirectDecision; decision != "rejected_cross_scheme" {
			t.Fatalf("decision=%s", decision)
		}
	})
}

func TestSCCMRequestSafetyAndNoClientCertificate(t *testing.T) {
	var proxyContacts atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyContacts.Add(1) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.TLS != nil && len(request.TLS.PeerCertificates) != 0 {
			t.Error("client certificate was sent")
		}
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("forbidden headers: %v", request.Header)
		}
		body, _ := io.ReadAll(request.Body)
		if len(body) != 0 || request.ContentLength > 0 {
			t.Errorf("request body length=%d content-length=%d", len(body), request.ContentLength)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	u, _ := url.Parse(server.URL)
	tracker := &requestTracker{}
	client, transport, _ := dedicatedSCCMClient(sccmTestOptions(), u, map[string]bool{normalizeHost(u.Hostname()): true}, tracker)
	budget := client.Transport.(*requestBudgetTransport)
	if client.Jar != nil || budget.base.(*http.Transport).Proxy != nil || len(budget.base.(*http.Transport).TLSClientConfig.Certificates) != 0 {
		t.Fatal("dedicated transport permits proxy or client certificates")
	}
	transport.CloseIdleConnections()
	observations := probeSCCMOrigin(context.Background(), "asset", server.URL, nil, map[string]bool{normalizeHost(u.Hostname()): true}, sccmTestOptions())
	if len(observations) != 5 || proxyContacts.Load() != 0 {
		t.Fatalf("observations=%d proxy contacts=%d", len(observations), proxyContacts.Load())
	}
	if !observationByID(t, observations, sccmRouteMPList).AccessState.AuthenticationRequested {
		t.Fatal("TLS client-certificate request was not represented as authentication required")
	}
}

func TestSCCMContextCancellationAndTimeoutReturnPromptly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	scope := map[string]bool{normalizeHost(u.Hostname()): true}
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if observations := probeSCCMOrigin(ctx, "asset", server.URL, nil, scope, sccmTestOptions()); len(observations) != 0 {
		t.Fatalf("cancelled request generated observations: %+v", observations)
	}
	opts := sccmTestOptions()
	opts.Timeout = 20 * time.Millisecond
	started := time.Now()
	observations := probeSCCMOrigin(context.Background(), "asset", server.URL, nil, scope, opts)
	if time.Since(started) > 500*time.Millisecond || len(observations) == 0 || observationByID(t, observations, sccmRouteMPList).UnverifiedReason != "timeout" {
		t.Fatalf("elapsed=%s observations=%+v", time.Since(started), observations)
	}
	time.Sleep(30 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+8 {
		t.Fatalf("possible goroutine leak: before=%d after=%d", before, after)
	}
}

func TestSCCMRouteEvidenceFingerprintIsStableAndMaterialStateChanges(t *testing.T) {
	base := routeObservation{AssetID: "asset", Origin: "http://127.0.0.1:80", Scheme: "http", Host: "127.0.0.1", Port: 80, RouteID: sccmRouteMPList, Path: "/SMS_MP/.sms_aut?MPLIST", Method: http.MethodGet, StatusCode: 200, ParserOutcome: "valid_sccm_mp_list", AccessState: SCCMAccessState{AnonymousRequest: true, TransportReachable: true, HTTPResponseReceived: true, UsableReadAccess: true, ProtocolValidated: true}}
	first := routeEvidenceFromObservation(base, "live.sccm.http_routes")
	second := routeEvidenceFromObservation(base, "live.sccm.http_routes")
	if first.ID != second.ID || first.Fingerprint != second.Fingerprint {
		t.Fatal("identical route evidence did not deduplicate")
	}
	base.StatusCode = http.StatusUnauthorized
	base.AccessState.ProtocolValidated = false
	changed := routeEvidenceFromObservation(base, "live.sccm.http_routes")
	if changed.ID == first.ID {
		t.Fatal("material response-state change was hidden by the fingerprint")
	}
}
