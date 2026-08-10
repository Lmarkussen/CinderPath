// Package recon4 implements the bounded CMPivot client-device reconnaissance
// contract. It deliberately exposes one fixed query and one target per run.
package recon4

import (
	"bytes"
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

const FixedQuery = "OperatingSystem"

const (
	maxBody    = 1 << 20
	maxRows    = 8
	maxColumns = 64
	maxField   = 512
)

type Options struct {
	Authority, TransportIP, Realm, KDC, Username, PasswordRef, CCachePath string
	TLSConfig                                                             *tls.Config
	PollAttempts                                                          int
	PollInterval                                                          time.Duration
}

type Client struct {
	http         *negotiate.Client
	base         string
	pollAttempts int
	pollInterval time.Duration
}

// ListClients returns a small, deterministic candidate set for family
// orchestration. It is intentionally bounded and only exposes ConfigMgr
// client metadata; CMPivot execution remains target-specific.
func (c *Client) ListClients(ctx context.Context) ([]Device, error) {
	b, code, err := c.request(ctx, http.MethodGet, "/Device?$filter=IsClient%20eq%201&$top=32", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("ConfigMgr client discovery returned HTTP %d", code)
	}
	var d deviceEnvelope
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("malformed ConfigMgr client response: %w", err)
	}
	if len(d.Value) > 32 {
		return nil, errors.New("ConfigMgr client discovery exceeded bounded result limit")
	}
	out := make([]Device, 0, len(d.Value))
	for _, v := range d.Value {
		if v.MachineID <= 0 || v.IsClient == 0 || strings.TrimSpace(v.Name) == "" {
			continue
		}
		out = append(out, Device{Name: v.Name, MachineID: v.MachineID, SiteCode: v.SiteCode, ClientVersion: v.ClientVersion, IsClient: true, Online: v.Online})
	}
	return out, nil
}

type Device struct {
	Name          string
	MachineID     int
	SiteCode      string
	ClientVersion string
	IsClient      bool
	Online        bool
}

type Result struct {
	Device      Device
	OperationID int
	Status      string
	Rows        []map[string]string
}

type deviceEnvelope struct {
	Value []struct {
		Name          string `json:"Name"`
		MachineID     int    `json:"MachineId"`
		SiteCode      string `json:"SiteCode"`
		ClientVersion string `json:"ClientVersion"`
		IsClient      int    `json:"IsClient"`
		Online        bool   `json:"CNIsOnline"`
	} `json:"value"`
}
type submitEnvelope struct {
	Value struct {
		OperationID int `json:"OperationId"`
	} `json:"value"`
}
type resultEnvelope struct {
	Value struct {
		Status     string           `json:"Status"`
		MoreResult bool             `json:"MoreResult"`
		Result     []map[string]any `json:"Result"`
	} `json:"value"`
}
type statusEnvelope struct {
	Value []struct {
		ClientOperationID    int    `json:"ClientOperationId"`
		State                int    `json:"State"`
		ErrorMessage         string `json:"ErrorMessage"`
		ScriptExecutionState int    `json:"ScriptExecutionState"`
	} `json:"value"`
}

func New(ctx context.Context, o Options) (*Client, error) {
	if o.PollAttempts <= 0 {
		o.PollAttempts = 8
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 2 * time.Second
	}
	h, err := negotiate.New(ctx, negotiate.Options{Authority: o.Authority, TransportIP: o.TransportIP, Realm: o.Realm, KDC: o.KDC, Username: o.Username, PasswordRef: o.PasswordRef, CCachePath: o.CCachePath, TLSConfig: o.TLSConfig, Timeout: 15 * time.Second})
	if err != nil {
		return nil, err
	}
	return &Client{http: h, base: "https://" + o.Authority + "/AdminService/v1.0", pollAttempts: o.PollAttempts, pollInterval: o.PollInterval}, nil
}

func (c *Client) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	u, err := url.Parse(c.base + path)
	if err != nil {
		return nil, 0, err
	}
	var r io.ReadCloser = http.NoBody
	if body != nil {
		r = io.NopCloser(bytes.NewReader(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), r)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := negotiate.ReadBounded(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return b, resp.StatusCode, nil
}

func (c *Client) Assess(ctx context.Context, target string) (Result, error) {
	if strings.TrimSpace(target) == "" {
		return Result{}, errors.New("RECON-4 target client is required")
	}
	filter := url.QueryEscape("Name eq '" + strings.ReplaceAll(target, "'", "''") + "'")
	b, code, err := c.request(ctx, http.MethodGet, "/Device?$filter="+filter, nil)
	if err != nil {
		return Result{}, err
	}
	if code != http.StatusOK {
		return Result{}, fmt.Errorf("ConfigMgr device resolution returned HTTP %d", code)
	}
	var d deviceEnvelope
	if err := json.Unmarshal(b, &d); err != nil {
		return Result{}, fmt.Errorf("malformed ConfigMgr device response: %w", err)
	}
	if len(d.Value) == 0 {
		return Result{}, fmt.Errorf("ConfigMgr device %q was not found", target)
	}
	if len(d.Value) > 1 {
		return Result{}, fmt.Errorf("ConfigMgr device %q is ambiguous", target)
	}
	dev := d.Value[0]
	if dev.MachineID <= 0 {
		return Result{}, errors.New("ConfigMgr device response has no valid MachineId")
	}
	devout := Device{Name: dev.Name, MachineID: dev.MachineID, SiteCode: dev.SiteCode, ClientVersion: dev.ClientVersion, IsClient: dev.IsClient != 0, Online: dev.Online}
	body, _ := json.Marshal(map[string]string{"InputQuery": FixedQuery})
	b, code, err = c.request(ctx, http.MethodPost, "/Device("+strconv.Itoa(dev.MachineID)+")/AdminService.RunCMPivot", body)
	if err != nil {
		return Result{}, err
	}
	if code != http.StatusOK {
		return Result{}, fmt.Errorf("CMPivot submission returned HTTP %d", code)
	}
	var sub submitEnvelope
	if err := json.Unmarshal(b, &sub); err != nil {
		return Result{}, fmt.Errorf("malformed CMPivot submission response: %w", err)
	}
	if sub.Value.OperationID <= 0 {
		return Result{}, errors.New("CMPivot submission returned no OperationId")
	}
	for attempt := 0; attempt < c.pollAttempts; attempt++ {
		b, code, err = c.request(ctx, http.MethodGet, "/Device("+strconv.Itoa(dev.MachineID)+")/AdminService.CMPivotResult(OperationId="+strconv.Itoa(sub.Value.OperationID)+")", nil)
		if err == nil && code == http.StatusOK {
			var out resultEnvelope
			if err := json.Unmarshal(b, &out); err != nil {
				return Result{}, fmt.Errorf("malformed CMPivot result: %w", err)
			}
			rows, err := normalizeRows(out.Value.Result)
			if err != nil {
				return Result{}, err
			}
			return Result{Device: devout, OperationID: sub.Value.OperationID, Status: "completed", Rows: rows}, nil
		}
		if code != http.StatusNotFound && err != nil {
			return Result{}, err
		}
		// A 404 is the documented pre-materialization state on this server;
		// consult the bounded status entity to distinguish pending from failure.
		statusBody, statusCode, statusErr := c.request(ctx, http.MethodGet, "/SMS_CMPivotStatus?$filter=ClientOperationId%20eq%20"+strconv.Itoa(sub.Value.OperationID), nil)
		if statusErr != nil {
			return Result{}, statusErr
		}
		if statusCode == http.StatusOK {
			var st statusEnvelope
			if json.Unmarshal(statusBody, &st) == nil && len(st.Value) > 0 {
				if st.Value[0].ErrorMessage != "" || st.Value[0].State < 0 {
					return Result{}, errors.New("CMPivot operation failed")
				}
			}
		}
		if attempt+1 < c.pollAttempts {
			select {
			case <-ctx.Done():
				return Result{}, ctx.Err()
			case <-time.After(c.pollInterval):
			}
		}
	}
	return Result{}, errors.New("CMPivot operation did not complete within bounded polling")
}

func normalizeRows(in []map[string]any) ([]map[string]string, error) {
	if len(in) > maxRows {
		return nil, errors.New("CMPivot result exceeds row bound")
	}
	out := make([]map[string]string, 0, len(in))
	for _, row := range in {
		if len(row) > maxColumns {
			return nil, errors.New("CMPivot result exceeds column bound")
		}
		m := map[string]string{}
		for k, v := range row {
			if len(k) > maxField {
				return nil, errors.New("CMPivot field name exceeds bound")
			}
			s := fmt.Sprint(v)
			if len(s) > maxField {
				return nil, errors.New("CMPivot field value exceeds bound")
			}
			m[k] = s
		}
		out = append(out, m)
	}
	return out, nil
}
