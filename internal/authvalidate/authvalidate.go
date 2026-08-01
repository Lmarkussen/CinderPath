package authvalidate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/identity"
	"github.com/Lmarkussen/CinderPath/internal/models"
)

type Budget struct {
	MaxTotal, MaxPerIdentity, MaxPerEndpoint, MaxPerIdentityEndpoint int
	MinimumDelay                                                     time.Duration
	StopAfterSuccess                                                 bool
}
type Options struct {
	Enabled, DryRun, AcknowledgeLockout, AcknowledgeMultiple, AllowBasicHTTP, AllowRepeat, ValidatedManagementPoints bool
	IdentityID                                                                                                       string
	Endpoints                                                                                                        []string
	Method                                                                                                           string
	Budget                                                                                                           Budget
	Timeout                                                                                                          time.Duration
	Now                                                                                                              func() time.Time
	Sleep                                                                                                            func(context.Context, time.Duration) error
	ClientFactory                                                                                                    func(Plan, *tls.Certificate) (*http.Client, error)
	PlanSink                                                                                                         func([]Plan)
}
type Plan struct {
	Identity                                                 models.Credential
	AssetID, Origin, Route, HTTPMethod, AuthenticationMethod string
	ChallengeBefore                                          []string
	ProtocolValidatedBefore                                  bool
	EvidenceIDs                                              []string
	EvidenceFreshness                                        models.TemporalState
	PreviousAttempts                                         int
}

func (p Plan) IdentityID() string { return p.Identity.ID }

type Store interface {
	ListCredentials(context.Context) ([]models.Credential, error)
	ListEvidence(context.Context) ([]models.Evidence, error)
	ListAuthenticationAttempts(context.Context) ([]models.AuthenticationAttempt, error)
	SaveAuthenticationAttempt(context.Context, *models.AuthenticationAttempt) error
	AcquireAuthenticationLock(context.Context, string) (bool, error)
	ReleaseAuthenticationLock(context.Context, string) error
}

func BuildPlans(ids []models.Credential, evidence []models.Evidence, history []models.AuthenticationAttempt, o Options, latestDiscoveryRun string) ([]Plan, error) {
	if o.IdentityID == "" {
		return nil, errors.New("an explicit --identity-id is required")
	}
	var id *models.Credential
	for i := range ids {
		if ids[i].ID == o.IdentityID {
			id = &ids[i]
			break
		}
	}
	if id == nil {
		return nil, fmt.Errorf("identity %q was not found", o.IdentityID)
	}
	selected := map[string]bool{}
	for _, raw := range o.Endpoints {
		u, err := canonicalOrigin(raw)
		if err != nil {
			return nil, err
		}
		selected[u] = true
	}
	if len(selected) == 0 && !o.ValidatedManagementPoints {
		return nil, errors.New("an explicit --endpoint or --validated-management-points is required")
	}
	method := strings.ToLower(o.Method)
	if method == "" {
		method = "basic"
	}
	if method != "basic" && method != "tls_client_certificate" {
		return nil, fmt.Errorf("unsupported authentication method %q", method)
	}
	plans := []Plan{}
	for _, e := range evidence {
		if e.Type != "sccm_http_route" {
			continue
		}
		origin := fmt.Sprint(e.Data["origin"])
		if !selected[origin] && !o.ValidatedManagementPoints {
			continue
		}
		state, _ := e.Data["access_state"].(map[string]any)
		if o.ValidatedManagementPoints && !boolv(state["protocol_validated"]) {
			continue
		}
		path := fmt.Sprint(e.Data["path"])
		verb := strings.ToUpper(fmt.Sprint(e.Data["method"]))
		if !allowedRoute(path, verb) {
			continue
		}
		schemes := schemes(e.Data["authentication_schemes"])
		if method == "basic" && !contains(schemes, "basic") {
			continue
		}
		if method == "tls_client_certificate" && !boolv(e.Data["tls_client_certificate_requested"]) {
			continue
		}
		fresh := models.TemporalUnknown
		if e.RunID != "" && e.RunID == latestDiscoveryRun {
			fresh = models.TemporalCurrent
		} else if e.RunID != "" {
			fresh = models.TemporalStale
		}
		p := Plan{Identity: *id, AssetID: e.AssetID, Origin: origin, Route: path, HTTPMethod: verb, AuthenticationMethod: method, ChallengeBefore: schemes, ProtocolValidatedBefore: boolv(state["protocol_validated"]), EvidenceIDs: []string{e.ID}, EvidenceFreshness: fresh}
		for _, a := range history {
			if a.Attempted && a.IdentityID == id.ID && a.Origin == origin && a.Route == path && a.AuthenticationMethod == method {
				p.PreviousAttempts++
			}
		}
		plans = append(plans, p)
	}
	sort.Slice(plans, func(i, j int) bool { return plans[i].Origin+plans[i].Route < plans[j].Origin+plans[j].Route })
	if len(plans) == 0 {
		return nil, errors.New("no exact previously observed SCCM route advertises the selected authentication method")
	}
	return plans, nil
}

func Validate(ctx context.Context, store Store, runID, latestDiscoveryRun string, o Options) ([]models.AuthenticationAttempt, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleepContext
	}
	ids, err := store.ListCredentials(ctx)
	if err != nil {
		return nil, err
	}
	ev, err := store.ListEvidence(ctx)
	if err != nil {
		return nil, err
	}
	history, err := store.ListAuthenticationAttempts(ctx)
	if err != nil {
		return nil, err
	}
	plans, err := BuildPlans(ids, ev, history, o, latestDiscoveryRun)
	if err != nil {
		return nil, err
	}
	if o.PlanSink != nil {
		o.PlanSink(plans)
	}
	if !o.DryRun && !o.Enabled {
		return nil, errors.New("remote authentication validation is disabled; add --enable-auth-validation")
	}
	if !o.DryRun && !o.AcknowledgeLockout {
		return nil, errors.New("--acknowledge-lockout-risk is required for an actual attempt")
	}
	if len(plans) > 1 && !o.AcknowledgeMultiple {
		return nil, fmt.Errorf("%d attempts are planned; add --acknowledge-multiple-attempts", len(plans))
	}
	if err := checkBudget(plans, history, o); err != nil {
		return nil, err
	}
	out := []models.AuthenticationAttempt{}
	if !o.DryRun && o.Budget.MinimumDelay > 0 {
		if wait := remainingDelay(history, o.Now(), o.Budget.MinimumDelay); wait > 0 {
			if err := o.Sleep(ctx, wait); err != nil {
				return out, err
			}
		}
	}
	for i, p := range plans {
		if i > 0 && o.Budget.MinimumDelay > 0 {
			if err := o.Sleep(ctx, o.Budget.MinimumDelay); err != nil {
				return out, err
			}
		}
		a := newAttempt(runID, p, o, i)
		if o.DryRun {
			a.Status = models.AuthDryRun
			a.Reason = "dry-run plan; no secret was read and no network request was sent"
			a.ID = models.StableID("authplan", models.StableFingerprint(p.Identity.ID, p.Origin, p.Route, p.AuthenticationMethod))
			_ = store.SaveAuthenticationAttempt(ctx, &a)
			out = append(out, a)
			continue
		}
		if p.EvidenceFreshness != models.TemporalCurrent {
			a.Status = models.AuthBlocked
			a.FailureCategory = "stale_evidence"
			a.Reason = "endpoint evidence is not attributed to the latest completed discovery run"
			_ = store.SaveAuthenticationAttempt(ctx, &a)
			out = append(out, a)
			continue
		}
		if p.PreviousAttempts > 0 && !o.AllowRepeat {
			a.Status = models.AuthBlocked
			a.FailureCategory = "budget_exceeded"
			a.Reason = "an attempt for this identity, endpoint, route, and method already exists"
			_ = store.SaveAuthenticationAttempt(ctx, &a)
			out = append(out, a)
			continue
		}
		locked, lockErr := store.AcquireAuthenticationLock(ctx, p.Identity.ID)
		if lockErr != nil {
			return out, lockErr
		}
		if !locked {
			a.Status = models.AuthBlocked
			a.FailureCategory = "safety_blocked"
			a.Reason = "another authentication attempt is active for this identity"
			_ = store.SaveAuthenticationAttempt(ctx, &a)
			out = append(out, a)
			continue
		}
		execute(ctx, &a, p, o)
		_ = store.ReleaseAuthenticationLock(context.WithoutCancel(ctx), p.Identity.ID)
		_ = store.SaveAuthenticationAttempt(context.WithoutCancel(ctx), &a)
		out = append(out, a)
		if a.Succeeded && o.Budget.StopAfterSuccess {
			break
		}
	}
	return out, nil
}
func remainingDelay(history []models.AuthenticationAttempt, now time.Time, minimum time.Duration) time.Duration {
	var last time.Time
	for _, a := range history {
		if !a.Attempted {
			continue
		}
		t := a.StartedAt
		if a.FinishedAt != nil {
			t = *a.FinishedAt
		}
		if t.After(last) {
			last = t
		}
	}
	if last.IsZero() {
		return 0
	}
	remaining := minimum - now.Sub(last)
	if remaining > 0 {
		return remaining
	}
	return 0
}

func checkBudget(plans []Plan, h []models.AuthenticationAttempt, o Options) error {
	actual := 0
	byID := map[string]int{}
	byEP := map[string]int{}
	byPair := map[string]int{}
	for _, a := range h {
		if !a.Attempted {
			continue
		}
		actual++
		byID[a.IdentityID]++
		byEP[a.Origin]++
		byPair[a.IdentityID+"\x00"+a.Origin]++
	}
	if actual+len(plans) > o.Budget.MaxTotal {
		return errors.New("authentication global attempt budget exceeded")
	}
	for _, p := range plans {
		if byID[p.Identity.ID]+1 > o.Budget.MaxPerIdentity {
			return errors.New("authentication identity attempt budget exceeded")
		}
		if byEP[p.Origin]+1 > o.Budget.MaxPerEndpoint {
			return errors.New("authentication endpoint attempt budget exceeded")
		}
		if byPair[p.Identity.ID+"\x00"+p.Origin]+1 > o.Budget.MaxPerIdentityEndpoint {
			return errors.New("authentication identity/endpoint attempt budget exceeded")
		}
	}
	return nil
}
func newAttempt(run string, p Plan, o Options, n int) models.AuthenticationAttempt {
	now := o.Now().UTC()
	id := models.StableID("auth", models.StableFingerprint(run, p.Identity.ID, p.Origin, p.Route, p.AuthenticationMethod, fmt.Sprint(n), now.Format(time.RFC3339Nano)))
	return models.AuthenticationAttempt{ID: id, RunID: run, IdentityID: p.Identity.ID, AssetID: p.AssetID, Origin: p.Origin, Route: p.Route, Method: p.HTTPMethod, AuthenticationMethod: p.AuthenticationMethod, StartedAt: now, Status: models.AuthPlanned, ChallengeBefore: p.ChallengeBefore, ProtocolValidatedBefore: p.ProtocolValidatedBefore, EvidenceIDs: p.EvidenceIDs, SafetyAcknowledged: o.AcknowledgeLockout, PreviousAttempts: p.PreviousAttempts, EvidenceFreshness: p.EvidenceFreshness, RepeatOverride: o.AllowRepeat, Reason: "planned"}
}
func execute(ctx context.Context, a *models.AuthenticationAttempt, p Plan, o Options) {
	if p.AuthenticationMethod == "basic" {
		u, _ := url.Parse(p.Origin)
		if u.Scheme != "https" && !o.AllowBasicHTTP {
			finish(a, o, models.AuthBlocked, "safety_blocked", "Basic authentication requires HTTPS unless --allow-basic-over-http is explicit")
			return
		}
	}
	cert, secret, err := material(p, o.Now())
	if secret != nil {
		defer clear(secret)
	}
	if err != nil {
		finish(a, o, models.AuthError, "unsupported_authentication", err.Error())
		return
	}
	client, err := clientFor(p, cert, o)
	if err != nil {
		finish(a, o, models.AuthError, "tls_error", err.Error())
		return
	}
	u := p.Origin + p.Route
	req, err := http.NewRequestWithContext(ctx, p.HTTPMethod, u, nil)
	if err != nil {
		finish(a, o, models.AuthError, "unknown", "request construction failed")
		return
	}
	req.Header.Set("User-Agent", "CinderPath-auth-validation/1")
	req.Header.Set("Accept", "application/xml, text/xml;q=0.9, */*;q=0.1")
	if p.AuthenticationMethod == "basic" {
		req.SetBasicAuth(identityName(p.Identity), string(secret))
	}
	a.Attempted = true
	a.BudgetCost = 1
	resp, err := client.Do(req)
	if err != nil {
		cat := "transport_error"
		if strings.Contains(err.Error(), "redirect_blocked") {
			cat = "redirect_blocked"
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			cat = "timeout"
		}
		finish(a, o, models.AuthError, cat, "single authentication request failed")
		return
	}
	defer resp.Body.Close()
	a.TransportSucceeded = true
	a.HTTPResponseReceived = true
	a.StatusCode = resp.StatusCode
	a.ChallengeAfter = normalizedChallenges(resp.Header.Values("WWW-Authenticate"))
	body := []byte{}
	if p.HTTPMethod == http.MethodGet {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 4097))
		if len(body) > 4096 {
			body = nil
		}
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		if p.AuthenticationMethod == "basic" && len(a.ChallengeAfter) > 0 && !contains(a.ChallengeAfter, "basic") {
			finish(a, o, models.AuthInconclusive, "endpoint_changed", "endpoint authentication challenge changed before validation")
		} else {
			finish(a, o, models.AuthRejected, "invalid_credentials", "endpoint returned 401 after the single authentication attempt")
		}
	case resp.StatusCode == http.StatusForbidden:
		finish(a, o, models.AuthInconclusive, "access_denied", "403 does not prove whether authentication succeeded")
	case resp.StatusCode >= 200 && resp.StatusCode < 300 && strongSuccess(p, body):
		a.Succeeded = true
		a.UsableAccessAfter = true
		finish(a, o, models.AuthSucceeded, "", "exact route returned strongly validated usable access")
	default:
		finish(a, o, models.AuthInconclusive, "unknown", "response did not provide a strong authentication success signal")
	}
}
func finish(a *models.AuthenticationAttempt, o Options, status models.AuthenticationAttemptStatus, cat, reason string) {
	now := o.Now().UTC()
	a.FinishedAt = &now
	a.Status = status
	a.FailureCategory = cat
	a.Reason = reason
	a.Rejected = status == models.AuthRejected
	a.Inconclusive = status == models.AuthInconclusive
	a.RemainingUncertainty = "authentication is scoped to this exact identity, origin, route, and method; no broader authorization is inferred"
}
func material(p Plan, now time.Time) (*tls.Certificate, []byte, error) {
	if p.AuthenticationMethod == "basic" {
		if p.Identity.Username == "" {
			return nil, nil, errors.New("Basic requires a username")
		}
		b, err := identity.LoadSecret(p.Identity.SecretReference)
		return nil, b, err
	}
	certPath, keyPath := certRefs(p.Identity.SecretReference)
	if certPath == "" || keyPath == "" {
		return nil, nil, errors.New("certificate and private-key references are required")
	}
	certPEM, err := boundedPEM(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := boundedPEM(keyPath)
	if err != nil {
		return nil, nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	clear(keyPEM)
	if err != nil {
		return nil, nil, errors.New("certificate and private key do not match or are unsupported")
	}
	x, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	if now.Before(x.NotBefore) || now.After(x.NotAfter) {
		return nil, nil, errors.New("certificate is not currently valid")
	}
	if !hasClientAuth(x) {
		return nil, nil, errors.New("certificate lacks client-auth EKU")
	}
	return &pair, nil, nil
}
func clientFor(p Plan, cert *tls.Certificate, o Options) (*http.Client, error) {
	u, _ := url.Parse(p.Origin)
	if p.AuthenticationMethod == "basic" && u.Scheme != "https" && !o.AllowBasicHTTP {
		return nil, errors.New("Basic authentication requires HTTPS unless --allow-basic-over-http is explicit")
	}
	if o.ClientFactory != nil {
		return o.ClientFactory(p, cert)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cert}
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: o.Timeout}).DialContext, TLSClientConfig: tlsCfg, TLSHandshakeTimeout: o.Timeout, ResponseHeaderTimeout: o.Timeout, MaxResponseHeaderBytes: 64 << 10, DisableKeepAlives: true, MaxConnsPerHost: 1, ForceAttemptHTTP2: false}
	return &http.Client{Transport: tr, Timeout: o.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect_blocked") }}, nil
}
func allowedRoute(p, m string) bool {
	if m == http.MethodGet && p == "/SMS_MP/.sms_aut?MPLIST" {
		return true
	}
	if m != http.MethodHead {
		return false
	}
	switch p {
	case "/SMS_DP_SMSPKG$/", "/SMS_DP_SMSSIG$/", "/NOCERT_SMS_DP_SMSPKG$/", "/NOCERT_SMS_DP_SMSSIG$/":
		return true
	}
	return false
}
func canonicalOrigin(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" {
		return "", errors.New("endpoint must be an exact origin without a path or query")
	}
	u.Path = ""
	u.RawPath = ""
	u.Fragment = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}
func schemes(v any) []string {
	switch x := v.(type) {
	case []string:
		return normalizedChallenges(x)
	case []any:
		o := []string{}
		for _, v := range x {
			o = append(o, fmt.Sprint(v))
		}
		return normalizedChallenges(o)
	}
	return nil
}
func normalizedChallenges(v []string) []string {
	set := map[string]bool{}
	for _, h := range v {
		if f := strings.Fields(strings.TrimSpace(h)); len(f) > 0 {
			set[strings.ToLower(f[0])] = true
		}
	}
	o := []string{}
	for k := range set {
		o = append(o, k)
	}
	sort.Strings(o)
	return o
}
func boolv(v any) bool { return strings.EqualFold(fmt.Sprint(v), "true") }
func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}
func identityName(c models.Credential) string {
	if c.Domain != "" && !strings.Contains(c.Username, "@") {
		return c.Domain + "\\" + c.Username
	}
	return c.Username
}
func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
func certRefs(ref string) (string, string) {
	var cert, key string
	for _, line := range strings.Split(ref, "\n") {
		if strings.HasPrefix(line, "certificate:") {
			cert = strings.TrimPrefix(line, "certificate:")
		}
		if strings.HasPrefix(line, "private-key:") {
			key = strings.TrimPrefix(line, "private-key:")
		}
	}
	return cert, key
}
func boundedPEM(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, errors.New("referenced PEM file is unavailable")
	}
	if !st.Mode().IsRegular() || st.Size() > identity.MaxCertificateBytes {
		return nil, errors.New("certificate/key must be a bounded regular file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("referenced PEM file could not be read")
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("certificate/key is not PEM")
	}
	if strings.Contains(block.Type, "ENCRYPTED") {
		clear(b)
		return nil, errors.New("encrypted private keys are unsupported")
	}
	return b, nil
}
func hasClientAuth(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}
func strongSuccess(p Plan, b []byte) bool {
	if p.HTTPMethod == http.MethodHead {
		return true
	}
	s := strings.ToLower(string(bytes.TrimSpace(b)))
	return strings.Contains(s, "<mplist") && strings.Contains(s, "<mp")
}
