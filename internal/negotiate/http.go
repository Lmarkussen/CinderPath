// Package negotiate provides a deliberately explicit Kerberos/SPNEGO HTTP
// client for SCCM AdminService calls. It never consults ambient credentials.
package negotiate

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/identity"
	krbclient "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

const (
	maxAuthRounds    = 3
	maxHeaderBytes   = 64 << 10
	maxResponseBytes = 1 << 20
)

type Options struct {
	Authority   string
	TransportIP string
	Realm       string
	KDC         string
	Username    string
	PasswordRef string
	CCachePath  string
	TLSConfig   *tls.Config
	Timeout     time.Duration
}

// Client is an explicitly authenticated, bounded HTTP client. Authority is
// retained in the URL and SPN; TransportIP only controls the socket address.
type Client struct {
	HTTP        *spnego.Client
	Authority   string
	ServiceSPN  string
	IdentityRef string
	budget      *authBudgetTransport
}

func ServicePrincipal(authority string) (string, error) {
	h, _, err := net.SplitHostPort(strings.TrimSpace(authority))
	if err == nil {
		authority = h
	}
	authority = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(authority)), ".")
	if authority == "" || net.ParseIP(authority) != nil || strings.ContainsAny(authority, "/\\ ") {
		return "", errors.New("Kerberos HTTP authority must be a logical DNS hostname, not an IP address")
	}
	return "HTTP/" + authority, nil
}

func New(ctx context.Context, o Options) (*Client, error) {
	if err := validateOptions(o); err != nil {
		return nil, err
	}
	spn, err := ServicePrincipal(o.Authority)
	if err != nil {
		return nil, err
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	krbconf, err := krbConfig(o.Realm, o.KDC)
	if err != nil {
		return nil, err
	}
	var kc *krbclient.Client
	identityRef := "ccache:" + o.CCachePath
	if o.CCachePath != "" {
		cc, err := credentials.LoadCCache(o.CCachePath)
		if err != nil {
			return nil, fmt.Errorf("explicit Kerberos ccache unavailable: %w", err)
		}
		kc, err = krbclient.NewFromCCache(cc, krbconf, krbclient.DisablePAFXFAST(true))
		if err != nil {
			return nil, fmt.Errorf("explicit Kerberos ccache could not initialize: %w", err)
		}
	} else {
		secret, err := identity.LoadSecret(o.PasswordRef)
		if err != nil {
			return nil, fmt.Errorf("explicit Kerberos password reference unavailable: %w", err)
		}
		defer clear(secret)
		principal := strings.TrimSpace(o.Username)
		if at := strings.IndexByte(principal, '@'); at >= 0 {
			principal = principal[:at]
		}
		kc = krbclient.NewWithPassword(principal, strings.ToUpper(o.Realm), string(secret), krbconf, krbclient.DisablePAFXFAST(true))
		identityRef = o.PasswordRef
		if err := kc.Login(); err != nil {
			return nil, fmt.Errorf("Kerberos ticket acquisition failed for explicit identity: %w", err)
		}
	}
	base := &http.Transport{Proxy: nil, TLSClientConfig: cloneTLS(o.TLSConfig, o.Authority), DialContext: dialContext(o.TransportIP, o.Authority), TLSHandshakeTimeout: o.Timeout, ResponseHeaderTimeout: o.Timeout, MaxResponseHeaderBytes: maxHeaderBytes, DisableKeepAlives: true}
	budget := &authBudgetTransport{base: base}
	hc := &http.Client{Transport: budget, Timeout: o.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Negotiate redirect blocked") }}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return &Client{HTTP: spnego.NewClient(kc, hc, spn), Authority: strings.TrimSpace(o.Authority), ServiceSPN: spn, IdentityRef: identity.RedactReference(identityRef), budget: budget}, nil
}

type authBudgetTransport struct {
	base  http.RoundTripper
	count int
}

func (t *authBudgetTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.count++
	if t.count > maxAuthRounds {
		return nil, errors.New("Negotiate authentication round limit exceeded")
	}
	return t.base.RoundTrip(r)
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if c == nil || c.HTTP == nil {
		return nil, errors.New("explicit Kerberos/Negotiate client is not initialized")
	}
	if req == nil || req.URL == nil {
		return nil, errors.New("request is required")
	}
	if !strings.EqualFold(req.URL.Hostname(), c.Authority) {
		return nil, errors.New("request authority does not match configured Kerberos authority")
	}
	if c.budget != nil {
		c.budget.count = 0
	}
	r, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Kerberos/Negotiate request failed: %w", err)
	}
	if r.StatusCode == http.StatusUnauthorized {
		return r, errors.New("Kerberos authentication rejected by ConfigMgr (Negotiate)")
	}
	if r.StatusCode == http.StatusForbidden {
		return r, errors.New("Kerberos authentication succeeded but ConfigMgr authorization was denied")
	}
	return r, nil
}

func ReadBounded(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxResponseBytes {
		return nil, errors.New("authenticated response exceeds bounded size")
	}
	return b, nil
}

func validateOptions(o Options) error {
	if strings.TrimSpace(o.Authority) == "" {
		return errors.New("explicit ConfigMgr logical authority is required")
	}
	if o.TransportIP == "" || net.ParseIP(o.TransportIP) == nil {
		return errors.New("explicit ConfigMgr transport IP is required")
	}
	if strings.TrimSpace(o.Realm) == "" || strings.TrimSpace(o.KDC) == "" {
		return errors.New("explicit Kerberos realm and KDC are required")
	}
	if (o.CCachePath == "") == (o.PasswordRef == "") {
		return errors.New("select exactly one explicit Kerberos ccache or password reference")
	}
	if o.PasswordRef != "" && strings.TrimSpace(o.Username) == "" {
		return errors.New("explicit Kerberos username is required with a password reference")
	}
	return nil
}

func krbConfig(realm, kdc string) (*config.Config, error) {
	s := fmt.Sprintf("[libdefaults]\n default_realm = %s\n rdns = false\n[realms]\n %s = {\n  kdc = %s\n }\n", strings.ToUpper(realm), strings.ToUpper(realm), kdc)
	return config.NewFromString(s)
}

func dialContext(ip, authority string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid transport address: %w", err)
		}
		return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip, port))
	}
}

func cloneTLS(in *tls.Config, authority string) *tls.Config {
	if in == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: strings.TrimSuffix(authority, ".")}
	}
	c := in.Clone()
	if c.ServerName == "" {
		c.ServerName = strings.TrimSuffix(authority, ".")
	}
	return c
}

func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
