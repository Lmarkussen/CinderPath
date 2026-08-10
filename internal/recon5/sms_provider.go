// Package recon5 implements the bounded SMS Provider user/device inventory
// query used by RECON-5. It deliberately exposes no arbitrary WQL surface.
package recon5

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/negotiate"
)

const (
	ProviderPath = "/AdminService/wmi/SMS_UserMachineRelationship"
	FixedQuery   = "SMS_UserMachineRelationship?$top=129"
	maxRecords   = 128
)

type Options struct {
	Authority, TransportIP, Realm, KDC, Username, PasswordRef, CCachePath string
	TLSConfig                                                             *tls.Config
	Timeout                                                               time.Duration
}

type Client struct {
	http     *negotiate.Client
	base     string
	maxBytes int64
}

type Record struct {
	Username     string `json:"username"`
	Device       string `json:"device"`
	ResourceID   int    `json:"resource_id,omitempty"`
	Sources      string `json:"sources,omitempty"`
	Types        string `json:"types,omitempty"`
	CreationTime string `json:"creation_time,omitempty"`
}

type Result struct {
	Records   []Record `json:"records"`
	Truncated bool     `json:"truncated"`
	Query     string   `json:"query"`
}

func New(ctx context.Context, o Options) (*Client, error) {
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	h, err := negotiate.New(ctx, negotiate.Options{
		Authority: o.Authority, TransportIP: o.TransportIP, Realm: o.Realm,
		KDC: o.KDC, Username: o.Username, PasswordRef: o.PasswordRef,
		CCachePath: o.CCachePath, TLSConfig: o.TLSConfig, Timeout: o.Timeout,
	})
	if err != nil {
		return nil, err
	}
	return &Client{http: h, base: "https://" + o.Authority, maxBytes: 1 << 20}, nil
}

func QueryPath() string { return QueryPathForUser("") }

func QueryPathForUser(username string) string {
	query := "%24top=129"
	if strings.TrimSpace(username) != "" {
		query += "&%24filter=" + url.QueryEscape("UniqueUserName eq '"+strings.ReplaceAll(strings.TrimSpace(username), "'", "''")+"'")
	}
	return ProviderPath + "?" + query
}

func (c *Client) LocateUsers(ctx context.Context) (Result, error) {
	return c.LocateUsersFor(ctx, "")
}

func (c *Client) LocateUsersFor(ctx context.Context, username string) (Result, error) {
	if c == nil || c.http == nil {
		return Result{}, errors.New("explicit ConfigMgr SMS Provider client is not initialized")
	}
	u, err := url.Parse(c.base + QueryPathForUser(username))
	if err != nil {
		return Result{}, fmt.Errorf("SMS Provider request URL invalid: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return Result{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return Result{}, classifyHTTPError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			return Result{}, fmt.Errorf("SMS Provider endpoint unsupported by ConfigMgr (HTTP %d)", resp.StatusCode)
		}
		return Result{}, fmt.Errorf("SMS Provider request returned HTTP %d", resp.StatusCode)
	}
	b, err := readBounded(resp.Body, c.maxBytes)
	if err != nil {
		return Result{}, err
	}
	result, err := ParseResponse(b)
	if err != nil {
		return Result{}, err
	}
	result.Query = FixedQuery
	if strings.TrimSpace(username) != "" {
		result.Query += " filter=" + boundedString(username)
	}
	return result, nil
}

func ParseResponse(b []byte) (Result, error) {
	var envelope struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.Unmarshal(b, &envelope); err != nil {
		return Result{}, fmt.Errorf("malformed SMS Provider response: %w", err)
	}
	if envelope.Value == nil {
		return Result{}, errors.New("malformed SMS Provider response: value array is missing")
	}
	result := Result{Records: make([]Record, 0, min(len(envelope.Value), maxRecords)), Truncated: len(envelope.Value) > maxRecords}
	for i, raw := range envelope.Value {
		if i >= maxRecords {
			break
		}
		r := Record{
			Username:     firstString(raw, "UniqueUserName", "UniqueUsername", "UserName", "Username"),
			Device:       firstString(raw, "ResourceName", "DeviceName", "Name"),
			Sources:      firstString(raw, "Sources", "SourceName"),
			Types:        firstString(raw, "Types", "Type"),
			CreationTime: firstString(raw, "CreationTime", "LastLogonTime"),
		}
		r.ResourceID = firstInt(raw, "ResourceID", "ResourceId")
		if strings.TrimSpace(r.Username) == "" && strings.TrimSpace(r.Device) == "" {
			return Result{}, fmt.Errorf("malformed SMS Provider response: record %d has no bounded user or device identity", i)
		}
		result.Records = append(result.Records, r)
	}
	return result, nil
}

func firstString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			switch x := v.(type) {
			case string:
				return boundedString(x)
			case json.Number:
				return boundedString(x.String())
			}
		}
	}
	return ""
}

func firstInt(m map[string]any, keys ...string) int {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			switch x := v.(type) {
			case float64:
				return int(x)
			case json.Number:
				n, _ := strconv.Atoi(x.String())
				return n
			case string:
				n, _ := strconv.Atoi(x)
				return n
			}
		}
	}
	return 0
}

func boundedString(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 512 {
		return s[:512]
	}
	return s
}

func readBounded(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("SMS Provider response exceeds bounded size")
	}
	return b, nil
}

func classifyHTTPError(err error) error {
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "authorization was denied") || strings.Contains(text, "forbidden") {
		return errors.New("SMS Provider authorization denied for the configured identity")
	}
	if strings.Contains(text, "authentication rejected") || strings.Contains(text, "unauthorized") {
		return errors.New("SMS Provider authentication failed for the configured identity")
	}
	return errors.New("SMS Provider transport failed")
}
