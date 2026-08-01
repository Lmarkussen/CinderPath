package authvalidate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
)

type memoryStore struct {
	mu       sync.Mutex
	ids      []models.Credential
	ev       []models.Evidence
	attempts []models.AuthenticationAttempt
	locks    map[string]bool
}

func (s *memoryStore) AcquireAuthenticationLock(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locks == nil {
		s.locks = map[string]bool{}
	}
	if s.locks[id] {
		return false, nil
	}
	s.locks[id] = true
	return true, nil
}
func (s *memoryStore) ReleaseAuthenticationLock(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.locks, id)
	return nil
}

func (s *memoryStore) ListCredentials(context.Context) ([]models.Credential, error) {
	return s.ids, nil
}
func (s *memoryStore) ListEvidence(context.Context) ([]models.Evidence, error) { return s.ev, nil }
func (s *memoryStore) ListAuthenticationAttempts(context.Context) ([]models.AuthenticationAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]models.AuthenticationAttempt(nil), s.attempts...), nil
}
func (s *memoryStore) SaveAuthenticationAttempt(_ context.Context, a *models.AuthenticationAttempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.attempts {
		if s.attempts[i].ID == a.ID {
			s.attempts[i] = *a
			return nil
		}
	}
	s.attempts = append(s.attempts, *a)
	return nil
}
func routeEvidence(origin, run string, schemes []string) models.Evidence {
	return models.Evidence{ID: "ev_route", RunID: run, Type: "sccm_http_route", AssetID: "ast_mp", CollectedAt: time.Now(), Data: map[string]any{"origin": origin, "path": "/SMS_MP/.sms_aut?MPLIST", "method": "GET", "route_id": "mp_list", "authentication_schemes": schemes, "access_state": map[string]any{"authentication_requested": true, "protocol_validated": true}}}
}
func options(id, endpoint string) Options {
	return Options{Enabled: true, AcknowledgeLockout: true, IdentityID: id, Endpoints: []string{endpoint}, Method: "basic", Timeout: time.Second, Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }, Budget: Budget{MaxTotal: 3, MaxPerIdentity: 1, MaxPerEndpoint: 1, MaxPerIdentityEndpoint: 1, MinimumDelay: 0, StopAfterSuccess: true}}
}

func TestBasicValidationExactSingleSafeRequestAndSuccess(t *testing.T) {
	const sentinel = "AUTH_SENTINEL_7e41"
	t.Setenv("AUTH_TEST_PASSWORD", sentinel)
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "GET" || r.URL.RequestURI() != "/SMS_MP/.sms_aut?MPLIST" || r.Body == nil {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.RequestURI())
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Error("request body present")
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("unsafe header")
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(`LAB\alice:`+sentinel))
		if r.Header.Get("Authorization") != want || len(r.Header.Values("Authorization")) != 1 {
			t.Error("missing single Basic authorization")
		}
		w.Header().Set("Set-Cookie", "must-not-persist=1")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`<MPList><MP Name="mp.lab" SiteCode="LAB"/></MPList>`))
	}))
	defer server.Close()
	id := models.Credential{ID: "cred_1", Kind: models.CredentialPasswordRef, Username: "alice", Domain: "LAB", SecretReference: "env:AUTH_TEST_PASSWORD"}
	store := &memoryStore{ids: []models.Credential{id}, ev: []models.Evidence{routeEvidence(server.URL, "run_discover", []string{"Basic realm=lab"})}}
	o := options(id.ID, server.URL)
	o.ClientFactory = func(Plan, *tls.Certificate) (*http.Client, error) {
		c := server.Client()
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return c, nil
	}
	got, err := Validate(context.Background(), store, "run_auth", "run_discover", o)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || len(got) != 1 || got[0].Status != models.AuthSucceeded {
		t.Fatalf("requests=%d result=%#v", requests, got)
	}
	raw := fmt.Sprint(store.attempts)
	if strings.Contains(raw, sentinel) || strings.Contains(raw, "Authorization") || strings.Contains(raw, "must-not-persist") {
		t.Fatal("secret/header leaked into persisted result")
	}
}

func TestMinimumDelayCancellationAndSameIdentityLock(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)
	finished := now.Add(-time.Second)
	if got := remainingDelay([]models.AuthenticationAttempt{{Attempted: true, FinishedAt: &finished}}, now, 2*time.Second); got != time.Second {
		t.Fatalf("delay=%s", got)
	}
	t.Setenv("PW", "x")
	id := models.Credential{ID: "cred", Username: "a", SecretReference: "env:PW"}
	st := &memoryStore{ids: []models.Credential{id}, ev: []models.Evidence{routeEvidence("https://127.0.0.1:1", "d", []string{"Basic"})}, locks: map[string]bool{"cred": true}}
	o := options(id.ID, "https://127.0.0.1:1")
	o.ClientFactory = func(Plan, *tls.Certificate) (*http.Client, error) {
		t.Fatal("client created while identity lock held")
		return nil, nil
	}
	got, err := Validate(context.Background(), st, "a", "d", o)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Attempted || got[0].Status != models.AuthBlocked {
		t.Fatalf("lock result %#v", got[0])
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o.Budget.MinimumDelay = 2 * time.Second
	st.attempts = []models.AuthenticationAttempt{{Attempted: true, FinishedAt: &now, IdentityID: "other", Origin: "https://other"}}
	o.Now = func() time.Time { return now }
	o.Sleep = sleepContext
	if _, err := Validate(ctx, st, "b", "d", o); err == nil {
		t.Fatal("cancelled delay was not interrupted")
	}
}

func TestProductionClientDisablesProxyCookiesAndRedirects(t *testing.T) {
	p := Plan{Origin: "https://mp.lab", AuthenticationMethod: "basic"}
	c, err := clientFor(p, nil, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil || c.Jar != nil || !tr.DisableKeepAlives {
		t.Fatalf("unsafe client %#v", c)
	}
	req, _ := http.NewRequest("GET", "https://mp.lab/next", nil)
	if err := c.CheckRedirect(req, nil); err == nil || !strings.Contains(err.Error(), "redirect_blocked") {
		t.Fatalf("redirect not blocked: %v", err)
	}
}

func TestDryRunNoSecretReadNoNetworkAndNoBudgetCost(t *testing.T) {
	id := models.Credential{ID: "cred_1", Kind: models.CredentialPasswordRef, Username: "alice", SecretReference: "env:DOES_NOT_EXIST"}
	store := &memoryStore{ids: []models.Credential{id}, ev: []models.Evidence{routeEvidence("https://127.0.0.1:1", "run_d", []string{"Basic"})}}
	o := options(id.ID, "https://127.0.0.1:1")
	o.DryRun = true
	o.Enabled = false
	o.AcknowledgeLockout = false
	o.ClientFactory = func(Plan, *tls.Certificate) (*http.Client, error) {
		t.Fatal("network client created in dry-run")
		return nil, nil
	}
	got, err := Validate(context.Background(), store, "run_auth", "run_d", o)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Attempted || got[0].BudgetCost != 0 || got[0].Status != models.AuthDryRun {
		t.Fatalf("dry run %#v", got[0])
	}
}

func TestDisabledAcknowledgementStaleHTTPAndBudgetsBlock(t *testing.T) {
	t.Setenv("PW", "x")
	id := models.Credential{ID: "cred", Kind: models.CredentialPasswordRef, Username: "alice", SecretReference: "env:PW"}
	base := &memoryStore{ids: []models.Credential{id}, ev: []models.Evidence{routeEvidence("http://127.0.0.1:1", "old", []string{"Basic"})}}
	o := options(id.ID, "http://127.0.0.1:1")
	o.Enabled = false
	if _, err := Validate(context.Background(), base, "a", "old", o); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled error %v", err)
	}
	o.Enabled = true
	o.AcknowledgeLockout = false
	if _, err := Validate(context.Background(), base, "a", "old", o); err == nil || !strings.Contains(err.Error(), "lockout") {
		t.Fatalf("ack error %v", err)
	}
	o.AcknowledgeLockout = true
	got, err := Validate(context.Background(), base, "a", "old", o)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Attempted || got[0].FailureCategory != "safety_blocked" {
		t.Fatalf("HTTP not blocked %#v", got[0])
	}
	base.attempts = []models.AuthenticationAttempt{{IdentityID: id.ID, Origin: "http://127.0.0.1:1", Route: "/SMS_MP/.sms_aut?MPLIST", AuthenticationMethod: "basic", Attempted: true}}
	if _, err := Validate(context.Background(), base, "b", "old", o); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("budget error %v", err)
	}
}

func TestRejectionAndForbiddenClassification(t *testing.T) {
	for _, tc := range []struct {
		code   int
		status models.AuthenticationAttemptStatus
	}{{401, models.AuthRejected}, {403, models.AuthInconclusive}} {
		t.Run(http.StatusText(tc.code), func(t *testing.T) {
			t.Setenv("PW", "bad")
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.code) }))
			defer srv.Close()
			id := models.Credential{ID: "cred", Username: "a", SecretReference: "env:PW"}
			st := &memoryStore{ids: []models.Credential{id}, ev: []models.Evidence{routeEvidence(srv.URL, "d", []string{"Basic"})}}
			o := options(id.ID, srv.URL)
			o.ClientFactory = func(Plan, *tls.Certificate) (*http.Client, error) { return srv.Client(), nil }
			got, err := Validate(context.Background(), st, "a", "d", o)
			if err != nil {
				t.Fatal(err)
			}
			if got[0].Status != tc.status {
				t.Fatalf("got %s", got[0].Status)
			}
		})
	}
}

func TestCertificateKeyMatchMismatchExpiryAndEKU(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert, key := writePair(t, now.Add(-time.Hour), now.Add(time.Hour), true)
	p := Plan{AuthenticationMethod: "tls_client_certificate", Identity: models.Credential{SecretReference: "certificate:" + cert + "\nprivate-key:" + key}}
	if _, _, err := material(p, now); err != nil {
		t.Fatal(err)
	}
	_, other := writePair(t, now.Add(-time.Hour), now.Add(time.Hour), true)
	p.Identity.SecretReference = "certificate:" + cert + "\nprivate-key:" + other
	if _, _, err := material(p, now); err == nil {
		t.Fatal("mismatch accepted")
	}
	expired, key2 := writePair(t, now.Add(-2*time.Hour), now.Add(-time.Hour), true)
	p.Identity.SecretReference = "certificate:" + expired + "\nprivate-key:" + key2
	if _, _, err := material(p, now); err == nil {
		t.Fatal("expired accepted")
	}
	noeku, key3 := writePair(t, now.Add(-time.Hour), now.Add(time.Hour), false)
	p.Identity.SecretReference = "certificate:" + noeku + "\nprivate-key:" + key3
	if _, _, err := material(p, now); err == nil {
		t.Fatal("missing EKU accepted")
	}
}
func writePair(t *testing.T, notBefore, notAfter time.Time, eku bool) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "client"}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	if eku {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	cp, kp := filepath.Join(d, "cert.pem"), filepath.Join(d, "key.pem")
	_ = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	return cp, kp
}
