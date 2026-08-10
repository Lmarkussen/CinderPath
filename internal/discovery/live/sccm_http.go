package live

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"
)

const (
	sccmRouteMPList        = "mp_list"
	maxSCCMRoutesPerOrigin = 5
	maxSCCMOriginsPerHost  = 2
	maxSCCMRoutesPerHost   = 10
	maxSCCMPreviewBytes    = 512
	maxSCCMHeaderBytes     = 64 * 1024
	maxSCCMHeaderValue     = 512
)

type sccmRouteDefinition struct {
	ID, Method, Path, Kind string
}

var sccmRouteAllowlist = []sccmRouteDefinition{
	{ID: sccmRouteMPList, Method: http.MethodGet, Path: "/SMS_MP/.sms_aut?MPLIST", Kind: "management_point"},
	{ID: "dp_sms_pkg", Method: http.MethodHead, Path: "/SMS_DP_SMSPKG$/", Kind: "distribution_point"},
	{ID: "dp_sms_sig", Method: http.MethodHead, Path: "/SMS_DP_SMSSIG$/", Kind: "distribution_point"},
	{ID: "dp_nocert_sms_pkg", Method: http.MethodHead, Path: "/NOCERT_SMS_DP_SMSPKG$/", Kind: "distribution_point"},
	{ID: "dp_nocert_sms_sig", Method: http.MethodHead, Path: "/NOCERT_SMS_DP_SMSSIG$/", Kind: "distribution_point"},
}

type SCCMAccessState struct {
	TransportReachable      bool `json:"transport_reachable"`
	HTTPResponseReceived    bool `json:"http_response_received"`
	AnonymousRequest        bool `json:"anonymous_request"`
	AuthenticationRequested bool `json:"authentication_requested"`
	AuthenticationAttempted bool `json:"authentication_attempted"`
	Authenticated           bool `json:"authenticated"`
	UsableReadAccess        bool `json:"usable_read_access"`
	ProtocolValidated       bool `json:"protocol_validated"`
}

type mpListResult struct {
	Outcome   string
	SiteCodes []string
	Hosts     []string
	Markers   []string
}

type routeObservation struct {
	AssetID                       string
	Origin                        string
	Scheme                        string
	Host                          string
	Port                          int
	RouteID                       string
	Path                          string
	Method                        string
	StatusCode                    int
	SelectedHeaders               map[string]string
	AuthenticationSchemes         []string
	RedirectDecision              string
	ResponseLength                int64
	Truncated                     bool
	ParserOutcome                 string
	SCCMMarkers                   []string
	SiteCodes                     []string
	ReferencedHosts               []string
	AccessState                   SCCMAccessState
	UnverifiedReason              string
	Preview                       string
	MatchesRootProfile            bool
	TLSClientCertificateRequested bool
	Error                         string
}

type requestTracker struct {
	transportReachable  atomic.Bool
	httpResponse        atomic.Bool
	clientCertRequested atomic.Bool
}

type requestBudgetTransport struct {
	base      http.RoundTripper
	remaining atomic.Int64
}

func newRequestBudgetTransport(base http.RoundTripper, maximum int64) *requestBudgetTransport {
	t := &requestBudgetTransport{base: base}
	t.remaining.Store(maximum)
	return t
}

func (t *requestBudgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return nil, fmt.Errorf("unsafe SCCM HTTP method %q rejected", req.Method)
	}
	if req.Body != nil || req.GetBody != nil || req.ContentLength > 0 {
		return nil, errors.New("SCCM HTTP request bodies are forbidden")
	}
	if req.Header.Get("Authorization") != "" || req.Header.Get("Proxy-Authorization") != "" {
		return nil, errors.New("authorization headers are forbidden")
	}
	if req.Header.Get("Cookie") != "" {
		return nil, errors.New("cookies are forbidden")
	}
	if t.remaining.Add(-1) < 0 {
		return nil, errors.New("SCCM per-origin request budget exhausted")
	}
	return t.base.RoundTrip(req)
}

func dedicatedSCCMClient(opts HTTPOptions, origin *url.URL, scopedHosts map[string]bool, tracker *requestTracker) (*http.Client, *http.Transport, *string) {
	redirectDecision := "not_applicable"
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		// Some supported SCCM/IIS HTTPS endpoints request one client-side
		// renegotiation while probing the anonymous route. Permit only the
		// single bounded renegotiation; no client certificate or credentials
		// are supplied by this discovery transport.
		Renegotiation: tls.RenegotiateOnceAsClient,
		Certificates:  nil,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			tracker.clientCertRequested.Store(true)
			return &tls.Certificate{}, nil
		},
	} // #nosec G402 -- collection is scoped; certificate verification is profiled independently.
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if opts.TransportIP == "" {
				return (&net.Dialer{Timeout: opts.Timeout}).DialContext(ctx, network, address)
			}
			return (&net.Dialer{Timeout: opts.Timeout}).DialContext(ctx, network, net.JoinHostPort(opts.TransportIP, strconv.Itoa(effectivePort(origin))))
		},
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    opts.Timeout,
		ResponseHeaderTimeout:  opts.Timeout,
		MaxResponseHeaderBytes: maxSCCMHeaderBytes,
		MaxConnsPerHost:        1,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
	}
	budget := newRequestBudgetTransport(transport, maxSCCMRoutesPerOrigin)
	redirectLimit := opts.MaxRedirects
	if redirectLimit > 2 {
		redirectLimit = 2
	}
	if redirectLimit < 0 {
		redirectLimit = 0
	}
	client := &http.Client{Transport: budget, Timeout: opts.Timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		destination := req.URL
		if !strings.EqualFold(destination.Scheme, origin.Scheme) {
			redirectDecision = "rejected_cross_scheme"
			return errors.New("redirect changed scheme")
		}
		if effectivePort(destination) != effectivePort(origin) {
			redirectDecision = "rejected_cross_port"
			return errors.New("redirect changed port")
		}
		host := normalizeHost(destination.Hostname())
		if !scopedHosts[host] {
			redirectDecision = "rejected_out_of_scope"
			return errors.New("redirect destination is outside explicit scope")
		}
		if !strings.EqualFold(host, normalizeHost(origin.Hostname())) {
			redirectDecision = "rejected_cross_host"
			return errors.New("redirect changed hostname")
		}
		if len(via) > redirectLimit {
			redirectDecision = "rejected_limit"
			return fmt.Errorf("redirect limit %d exceeded", redirectLimit)
		}
		if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
			redirectDecision = "rejected_unsafe_headers"
			return errors.New("redirect attempted to propagate forbidden headers")
		}
		redirectDecision = "accepted_same_origin"
		return nil
	}}
	return client, transport, &redirectDecision
}

func probeSCCMOrigin(ctx context.Context, assetID, origin string, rootProfile map[string]any, scopedHosts map[string]bool, opts HTTPOptions) []routeObservation {
	base, err := url.Parse(origin)
	if err != nil {
		return nil
	}
	tracker := &requestTracker{}
	client, transport, redirectDecision := dedicatedSCCMClient(opts, base, scopedHosts, tracker)
	defer transport.CloseIdleConnections()
	out := make([]routeObservation, 0, len(sccmRouteAllowlist))
	for _, route := range sccmRouteAllowlist {
		if ctx.Err() != nil {
			break
		}
		tracker.transportReachable.Store(false)
		tracker.httpResponse.Store(false)
		tracker.clientCertRequested.Store(false)
		*redirectDecision = "not_applicable"
		u := *base
		u.Path = route.Path
		u.RawQuery = ""
		if route.ID == sccmRouteMPList {
			u.Path = "/SMS_MP/.sms_aut"
			u.RawQuery = "MPLIST"
		}
		obs := routeObservation{AssetID: assetID, Origin: canonicalOrigin(base), Scheme: strings.ToLower(base.Scheme), Host: normalizeHost(base.Hostname()), Port: effectivePort(base), RouteID: route.ID, Path: route.Path, Method: route.Method, SelectedHeaders: map[string]string{}, ParserOutcome: "not_applicable", AccessState: SCCMAccessState{AnonymousRequest: true}, RedirectDecision: "not_applicable"}
		trace := &httptrace.ClientTrace{
			GotConn:              func(httptrace.GotConnInfo) { tracker.transportReachable.Store(true) },
			GotFirstResponseByte: func() { tracker.httpResponse.Store(true) },
		}
		req, reqErr := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), route.Method, u.String(), nil)
		if reqErr != nil {
			obs.Error = reqErr.Error()
			obs.UnverifiedReason = "request_creation_failed"
			out = append(out, obs)
			continue
		}
		req.Header.Set("User-Agent", opts.UserAgent)
		req.Header.Set("Accept", "application/xml, text/xml;q=0.9, */*;q=0.1")
		resp, doErr := client.Do(req)
		obs.AccessState.TransportReachable = tracker.transportReachable.Load()
		obs.AccessState.HTTPResponseReceived = tracker.httpResponse.Load() || resp != nil
		obs.RedirectDecision = *redirectDecision
		if tracker.clientCertRequested.Load() {
			obs.AccessState.AuthenticationRequested = true
			obs.TLSClientCertificateRequested = true
		}
		if doErr != nil {
			obs.Error = doErr.Error()
			obs.UnverifiedReason = redirectOrRequestReason(obs.RedirectDecision, doErr)
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			out = append(out, obs)
			continue
		}
		obs.StatusCode = resp.StatusCode
		obs.SelectedHeaders = selectedSCCMHeaders(resp.Header)
		obs.AuthenticationSchemes = authenticationSchemes(resp.Header.Values("WWW-Authenticate"))
		obs.AccessState.AuthenticationRequested = obs.AccessState.AuthenticationRequested || resp.StatusCode == http.StatusUnauthorized || len(obs.AuthenticationSchemes) > 0
		if route.Method == http.MethodHead {
			obs.ResponseLength = responseLength(resp)
			obs.MatchesRootProfile = matchesRootHTTPProfile(obs, rootProfile)
			obs.UnverifiedReason = dpRouteUnverifiedReason(obs)
			_ = resp.Body.Close()
			out = append(out, obs)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes+1))
		_ = resp.Body.Close()
		obs.ResponseLength = int64(len(body))
		if readErr != nil {
			obs.Error = readErr.Error()
			obs.UnverifiedReason = "response_read_failed"
			out = append(out, obs)
			continue
		}
		if int64(len(body)) > opts.MaxBodyBytes {
			obs.Truncated = true
			body = body[:opts.MaxBodyBytes]
			obs.ParserOutcome = "oversized_response"
			obs.UnverifiedReason = "response_exceeded_body_limit"
		} else {
			parsed := parseMPList(body)
			obs.ParserOutcome = parsed.Outcome
			obs.SiteCodes = parsed.SiteCodes
			obs.ReferencedHosts = parsed.Hosts
			obs.SCCMMarkers = parsed.Markers
			if parsed.Outcome == "valid_sccm_mp_list" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
				obs.AccessState.UsableReadAccess = true
				obs.AccessState.ProtocolValidated = true
			} else {
				obs.UnverifiedReason = mpUnverifiedReason(resp.StatusCode, parsed.Outcome)
			}
		}
		obs.Preview = boundedUTF8Preview(body, maxSCCMPreviewBytes)
		out = append(out, obs)
	}
	return out
}

func parseMPList(data []byte) mpListResult {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return mpListResult{Outcome: "empty_response"}
	}
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype html") {
		return mpListResult{Outcome: "generic_html"}
	}
	decoder := xml.NewDecoder(strings.NewReader(trimmed))
	var root string
	var hosts, sites, markers []string
	var elementStack []string
	mpDepth := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return mpListResult{Outcome: "malformed_xml"}
		}
		switch typed := token.(type) {
		case xml.StartElement:
			name := strings.ToLower(typed.Name.Local)
			if root == "" {
				root = name
			}
			elementStack = append(elementStack, name)
			if name == "mp" || name == "managementpoint" || name == "management_point" {
				markers = append(markers, typed.Name.Local)
				mpDepth = len(elementStack)
			}
			if mpDepth == 0 {
				continue
			}
			for _, attr := range typed.Attr {
				hosts, sites = collectMPField(strings.ToLower(attr.Name.Local), attr.Value, hosts, sites)
			}
		case xml.CharData:
			if mpDepth > 0 && len(elementStack) > mpDepth {
				hosts, sites = collectMPField(elementStack[len(elementStack)-1], string(typed), hosts, sites)
			}
		case xml.EndElement:
			if mpDepth == len(elementStack) {
				mpDepth = 0
			}
			if len(elementStack) > 0 {
				elementStack = elementStack[:len(elementStack)-1]
			}
		}
	}
	validRoot := root == "mplist" || root == "managementpointlist" || root == "managementpoints"
	hosts = mergeUnique(hosts)
	sites = normalizedStrings(sites)
	markers = normalizedStrings(markers)
	if !validRoot || len(markers) == 0 || len(hosts)+len(sites) == 0 {
		return mpListResult{Outcome: "unexpected_xml_structure", Hosts: hosts, SiteCodes: sites, Markers: markers}
	}
	return mpListResult{Outcome: "valid_sccm_mp_list", Hosts: hosts, SiteCodes: sites, Markers: markers}
}

func collectMPField(key, value string, hosts, sites []string) ([]string, []string) {
	value = strings.TrimSpace(value)
	switch key {
	case "sitecode", "site", "site_code":
		if normalized := normalizeSiteCode(value); normalized != "" {
			sites = append(sites, normalized)
		}
	case "fqdn", "hostname", "host", "name", "networkospath", "server":
		if normalized := normalizeMPHostReference(value); normalized != "" {
			hosts = append(hosts, normalized)
		}
	}
	return hosts, sites
}

func normalizeMPHostReference(value string) string {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	if u, err := url.Parse(value); err == nil && u.Hostname() != "" {
		value = u.Hostname()
	}
	value = strings.TrimPrefix(value, `\\`)
	if i := strings.IndexAny(value, `\/`); i >= 0 {
		value = value[:i]
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = normalizeHost(value)
	if value == "" || strings.ContainsAny(value, " ,=<>") {
		return ""
	}
	if net.ParseIP(value) == nil {
		for _, label := range strings.Split(value, ".") {
			if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return ""
			}
			for _, char := range label {
				if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && char != '-' {
					return ""
				}
			}
		}
	}
	return value
}

func normalizeSiteCode(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) != 3 {
		return ""
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') {
			return ""
		}
	}
	return value
}

func selectedSCCMHeaders(header http.Header) map[string]string {
	out := map[string]string{}
	for name, key := range map[string]string{
		"Content-Type": "content_type", "Content-Length": "content_length", "Content-Location": "content_location",
		"Server": "server", "Allow": "allow",
	} {
		if value := strings.TrimSpace(header.Get(name)); value != "" {
			out[key] = boundedUTF8Preview([]byte(value), maxSCCMHeaderValue)
		}
	}
	return out
}

func authenticationSchemes(values []string) []string {
	var out []string
	for _, value := range values {
		for _, challenge := range strings.Split(value, ",") {
			fields := strings.Fields(strings.TrimSpace(challenge))
			if len(fields) == 0 || strings.Contains(fields[0], "=") {
				continue
			}
			out = append(out, strings.ToLower(fields[0]))
		}
	}
	return normalizedStrings(out)
}

func normalizedStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func matchesRootHTTPProfile(obs routeObservation, root map[string]any) bool {
	rootStatus := intFromAny(root["head_status_code"])
	if rootStatus == 0 {
		rootStatus = intFromAny(root["status_code"])
	}
	if rootStatus == 0 || rootStatus != obs.StatusCode {
		return false
	}
	rootAuth := authenticationSchemes(anyStringsLocal(root["head_authentication_headers"]))
	if len(rootAuth) == 0 {
		rootAuth = authenticationSchemes(anyStringsLocal(root["authentication_headers"]))
	}
	if !sameStrings(rootAuth, obs.AuthenticationSchemes) {
		return false
	}
	if obs.StatusCode == http.StatusUnauthorized || obs.StatusCode == http.StatusForbidden {
		return true
	}
	if obs.StatusCode >= 200 && obs.StatusCode < 300 {
		rootType := mapString(root, "head_content_type")
		if rootType == "" {
			rootType = mapString(root, "content_type")
		}
		rootServer := mapString(root, "head_server")
		if rootServer == "" {
			rootServer = mapString(root, "server")
		}
		return strings.EqualFold(rootType, obs.SelectedHeaders["content_type"]) && strings.EqualFold(rootServer, obs.SelectedHeaders["server"])
	}
	return false
}

func mapString(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func sameStrings(a, b []string) bool {
	a, b = normalizedStrings(a), normalizedStrings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

func canonicalOrigin(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + net.JoinHostPort(normalizeHost(u.Hostname()), strconv.Itoa(effectivePort(u)))
}

func effectivePort(u *url.URL) int {
	if port, err := strconv.Atoi(u.Port()); err == nil && port > 0 {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

func responseLength(resp *http.Response) int64 {
	if resp.ContentLength >= 0 {
		return resp.ContentLength
	}
	if value, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); err == nil {
		return value
	}
	return 0
}

func boundedUTF8Preview(data []byte, maximum int) string {
	if len(data) > maximum {
		data = data[:maximum]
	}
	for len(data) > 0 && !utf8.Valid(data) {
		data = data[:len(data)-1]
	}
	return strings.TrimSpace(string(data))
}

func redirectOrRequestReason(decision string, err error) string {
	if strings.HasPrefix(decision, "rejected_") {
		return decision
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "timeout"
	}
	return "request_failed"
}

func mpUnverifiedReason(status int, parser string) string {
	if parser == "valid_sccm_mp_list" {
		if status >= 200 && status < 300 {
			return ""
		}
		return "sccm_structure_on_unsuccessful_status"
	}
	switch status {
	case http.StatusNotFound:
		return "route_not_found"
	case http.StatusMethodNotAllowed:
		return "method_not_allowed"
	}
	if status >= 500 {
		return "server_error"
	}
	return parser
}

func dpRouteUnverifiedReason(obs routeObservation) string {
	if obs.MatchesRootProfile {
		return "matches_generic_root_profile"
	}
	switch {
	case obs.StatusCode >= 200 && obs.StatusCode < 300:
		return "route_response_requires_correlation"
	case obs.StatusCode == http.StatusUnauthorized || obs.StatusCode == http.StatusForbidden:
		return "access_controlled_route_requires_correlation"
	case obs.StatusCode == http.StatusNotFound:
		return "route_not_found_inconclusive"
	case obs.StatusCode == http.StatusMethodNotAllowed:
		return "method_not_allowed_inconclusive"
	case obs.StatusCode >= 500:
		return "server_error_inconclusive"
	default:
		return "status_inconclusive"
	}
}

func intFromAny(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		value, _ := strconv.Atoi(fmt.Sprint(value))
		return value
	}
}

func anyStringsLocal(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case string:
		if typed != "" {
			return []string{typed}
		}
	}
	return nil
}
