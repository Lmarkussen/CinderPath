// Package recon6 implements the bounded, read-only RECON-6 winreg adapter.
package recon6

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	smbdcerpc "github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/msrrp"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
)

const (
	SMSRoot       = `SOFTWARE\Microsoft\SMS`
	SiteDB        = `SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers`
	MaxSubkeys    = 64
	MaxValues     = 16
	MaxValueBytes = 16 * 1024
)

type Options struct {
	LogicalHost string
	Transport   string
	Username    string
	Password    string
	Domain      string
	Timeout     time.Duration
}

type Value struct {
	Key, Name, Type string
	Value           any
}
type Result struct {
	LogicalHost, Transport         string
	Roles                          []string
	SiteCode, SiteServer           string
	ManagementPoints               []string
	SiteDatabase                   string
	AnonymousAccess, PXE           *bool
	Values                         []Value
	Subkeys                        []string
	Reads, Successful, Unavailable int
	Partial                        bool
}

func (r Result) role(role string) bool {
	for _, x := range r.Roles {
		if x == role {
			return true
		}
	}
	return false
}

// Enumerate performs only the fixed MS-RRP reads required by canonical RECON-6.
// It never calls any mutating MS-RRP operation.
func Enumerate(parent context.Context, o Options) (Result, error) {
	var out Result
	out.LogicalHost, out.Transport = o.LogicalHost, o.Transport
	if o.LogicalHost == "" || o.Transport == "" {
		return out, fmt.Errorf("remote registry target authority and transport are required")
	}
	if o.Username == "" || o.Password == "" {
		return out, fmt.Errorf("explicit SMB identity is required")
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	if net.ParseIP(o.Transport) == nil && strings.Contains(o.Transport, ":") {
		return out, fmt.Errorf("invalid SMB transport")
	}
	conn, err := smb.NewConnection(smb.Options{Host: o.LogicalHost, Port: 445, SMB2Only: true, RequireMessageSigning: true, DialTimeout: o.Timeout, ProxyDialer: fixedDialer{transport: o.Transport, timeout: o.Timeout}, Initiator: &spnego.NTLMInitiator{User: principalUser(o.Username), Password: o.Password, Domain: principalDomain(o.Username, o.Domain)}})
	if err != nil {
		return out, classify(err, "SMB authentication/connection")
	}
	defer conn.Close()
	if err = conn.TreeConnect("IPC$"); err != nil {
		return out, classify(err, "IPC$ tree connect")
	}
	pipe, err := conn.OpenFile("IPC$", "winreg")
	if err != nil {
		return out, classify(err, "winreg named pipe")
	}
	// Connection.Close owns the tree/file lifecycle. Calling File.CloseFile
	// first races the library's session shutdown and can panic on double-close.
	transport, err := smbtransport.NewSMBTransport(pipe)
	if err != nil {
		return out, classify(err, "winreg transport")
	}
	bind, err := smbdcerpc.Bind(transport, msrrp.MSRRPUuid, msrrp.MSRRPMajorVersion, msrrp.MSRRPMinorVersion, msrrp.NDRUuid)
	if err != nil {
		return out, classify(err, "Remote Registry RPC bind")
	}
	reg := msrrp.NewRPCCon(bind)
	// Windows Remote Registry applies the remotely-accessible-path policy at
	// the predefined HKLM open. GOAD denies a narrower desired mask here, so
	// use the protocol's standard OpenLocalMachine request. The adapter remains
	// structurally read-only: no mutating MS-RRP operation is exposed or called,
	// and every child key is opened with query/enumerate access only.
	hklm, err := openReadOnlyHKLM(reg)
	if err != nil {
		return out, classify(err, "HKLM open")
	}
	defer reg.CloseKeyHandle(hklm)
	out.Reads++
	keys, truncated, err := boundedSubkeys(reg, hklm, SMSRoot)
	if err != nil {
		return out, classify(err, "SCCM registry key enumeration")
	}
	if truncated {
		out.Partial = true
	}
	sort.Strings(keys)
	out.Subkeys = append([]string(nil), keys...)
	out.Successful++
	for _, k := range keys {
		switch strings.ToUpper(k) {
		case "DP":
			out.Roles = append(out.Roles, "distribution_point")
		case "MP":
			out.Roles = append(out.Roles, "management_point")
		}
	}
	if contains(keys, "DP") {
		if err := readDP(reg, hklm, &out); err != nil {
			out.Partial = true
			out.Unavailable++
		}
	}
	siteDB, truncated, err := boundedSubkeys(reg, hklm, SiteDB)
	out.Reads++
	if err == nil {
		out.Successful++
		sort.Strings(siteDB)
		if truncated {
			out.Partial = true
		}
		switch len(siteDB) {
		case 0:
			out.SiteDatabase = "local"
		case 1:
			out.SiteDatabase = siteDB[0]
		default:
			out.SiteDatabase = strings.Join(siteDB, ", ")
		}
		out.Subkeys = append(out.Subkeys, siteDB...)
	} else {
		out.Unavailable++
		out.Partial = true
	}
	select {
	case <-ctx.Done():
		return out, ctx.Err()
	default:
	}
	return out, nil
}

func boundedSubkeys(reg *msrrp.RPCCon, root []byte, path string) ([]string, bool, error) {
	h, err := reg.OpenSubKeyExt(root, path, 0, msrrp.PermKeyEnumerateSubKeys|msrrp.PermKeyQueryValue)
	if err != nil {
		return nil, false, err
	}
	defer reg.CloseKeyHandle(h)
	info, err := reg.QueryKeyInfo(h)
	if err != nil {
		return nil, false, err
	}
	count := int(info.SubKeys)
	truncated := count > MaxSubkeys
	if count > MaxSubkeys {
		count = MaxSubkeys
	}
	if count < 0 {
		return nil, false, fmt.Errorf("invalid subkey count")
	}
	keys := make([]string, 0, count)
	for i := 0; i < count; i++ {
		item, err := reg.EnumKey(h, uint32(i))
		if err != nil {
			return keys, truncated, err
		}
		if len(item.KeyName) > MaxValueBytes {
			return keys, true, fmt.Errorf("registry subkey name exceeds bound")
		}
		keys = append(keys, item.KeyName)
	}
	return keys, truncated, nil
}

func openReadOnlyHKLM(reg *msrrp.RPCCon) ([]byte, error) {
	return reg.OpenBaseKey(msrrp.HKEYLocalMachine)
}

// fixedDialer preserves the logical SMB authority while forcing transport to
// the current, evidenced address. It deliberately ignores any caller-supplied
// destination and cannot be used to expand scope.
type fixedDialer struct {
	transport string
	timeout   time.Duration
}

func (d fixedDialer) Dial(_ string, _ string) (net.Conn, error) {
	return (&net.Dialer{Timeout: d.timeout}).Dial("tcp", net.JoinHostPort(d.transport, "445"))
}

func (d fixedDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return (&net.Dialer{Timeout: d.timeout}).DialContext(ctx, "tcp", net.JoinHostPort(d.transport, "445"))
}

var _ interface {
	Dial(string, string) (net.Conn, error)
} = fixedDialer{}

func readDP(reg *msrrp.RPCCon, root []byte, out *Result) error {
	h, err := reg.OpenSubKeyExt(root, SMSRoot+`\DP`, 0, msrrp.PermKeyQueryValue|msrrp.PermKeyEnumerateSubKeys)
	if err != nil {
		return err
	}
	defer reg.CloseKeyHandle(h)
	readString := func(name string, dst func(string)) error {
		out.Reads++
		v, typ, err := reg.QueryValueExt(h, name)
		if err != nil {
			out.Unavailable++
			return err
		}
		s, ok := v.(string)
		if !ok || len(s) > MaxValueBytes {
			out.Partial = true
			return fmt.Errorf("registry value %s exceeds bound", name)
		}
		out.Successful++
		dst(strings.TrimSpace(s))
		out.Values = append(out.Values, Value{Key: SMSRoot + `\DP`, Name: name, Type: fmt.Sprint(typ), Value: s})
		return nil
	}
	_ = readString("SiteCode", func(v string) { out.SiteCode = v })
	_ = readString("SiteServer", func(v string) { out.SiteServer = v })
	_ = readString("ManagementPoints", func(v string) {
		for _, p := range strings.Split(v, "*") {
			if p = strings.TrimSpace(p); p != "" {
				out.ManagementPoints = append(out.ManagementPoints, p)
			}
		}
	})
	for _, spec := range []struct {
		name string
		dst  func(bool)
	}{{"IsAnonymousAccessEnabled", func(v bool) { out.AnonymousAccess = &v }}, {"IsPXE", func(v bool) { out.PXE = &v }}} {
		out.Reads++
		raw, typ, found, err := reg.QueryValue2(h, spec.name)
		if err != nil {
			out.Unavailable++
			continue
		}
		if !found {
			out.Unavailable++
			continue
		}
		if typ != msrrp.RegDword || len(raw) != 4 {
			out.Partial = true
			out.Unavailable++
			continue
		}
		out.Successful++
		spec.dst(raw[0] != 0)
		out.Values = append(out.Values, Value{Key: SMSRoot + `\DP`, Name: spec.name, Type: fmt.Sprint(typ), Value: raw[0] != 0})
	}
	return nil
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, want) {
			return true
		}
	}
	return false
}
func principalUser(s string) string {
	if i := strings.LastIndexByte(s, '@'); i > 0 {
		return s[:i]
	}
	if i := strings.IndexByte(s, '\\'); i >= 0 {
		return s[i+1:]
	}
	return s
}
func principalDomain(s, fallback string) string {
	if i := strings.LastIndexByte(s, '@'); i > 0 {
		return s[i+1:]
	}
	if i := strings.IndexByte(s, '\\'); i > 0 {
		return s[:i]
	}
	return fallback
}
func classify(err error, stage string) error {
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "logon failed") || strings.Contains(lower, "bad password") {
		return fmt.Errorf("authentication_failed: %s: %w", stage, err)
	}
	if strings.Contains(lower, "access denied") || strings.Contains(lower, "access_denied") || strings.Contains(lower, "permission") {
		return fmt.Errorf("authorization_denied: %s: %w", stage, err)
	}
	if strings.Contains(lower, "pipe not available") || strings.Contains(lower, "remote registry") {
		return fmt.Errorf("winreg_unavailable: %s: %w", stage, err)
	}
	if strings.Contains(lower, "not found") || strings.Contains(lower, "file_not_found") {
		return fmt.Errorf("target_unavailable: %s: %w", stage, err)
	}
	return fmt.Errorf("%s failed: %w", stage, err)
}
