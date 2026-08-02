package live

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/scope"
)

type Options struct {
	Scope                       scope.Input
	DNSServer, Domain, DC       string
	Ports                       []int
	ConnectTimeout, HostTimeout time.Duration
	Concurrency                 int
	HTTP                        HTTPOptions
	LDAP                        LDAPOptions
	SMB                         SMBOptions
	Hints                       RoleHints
}
type SMBOptions struct {
	Enabled                                                              bool
	Server, User, Password, PasswordReference, PasswordEnv, PasswordFile string
	Domain                                                               string
	Port                                                                 int
	ConnectTimeout, OperationTimeout                                     time.Duration
	MaxShares                                                            int
}
type HTTPOptions struct {
	UserAgent    string
	MaxBodyBytes int64
	MaxRedirects int
	Timeout      time.Duration
}
type LDAPOptions struct {
	Enabled                                         bool
	Server                                          string
	Port                                            int
	BaseDN, User                                    string
	Password                                        string `json:"-" yaml:"-"`
	PasswordReference, PasswordEnv, PasswordFile    string
	UseTLS, StartTLS, InsecureSkipVerify, Anonymous bool
	PageSize, MaxEntries                            int
	SearchTimeout                                   time.Duration
	TLSConfig                                       *tls.Config
}
type RoleHints struct {
	ManagementPoints, DistributionPoints, SiteServers, SQLServers []string
	SiteCode                                                      string
}

func ParsePorts(raw string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := 0, 0
		if strings.Contains(part, "-") {
			pieces := strings.Split(part, "-")
			if len(pieces) != 2 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			var err error
			lo, err = strconv.Atoi(pieces[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", pieces[0])
			}
			hi, err = strconv.Atoi(pieces[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", pieces[1])
			}
		} else {
			var err error
			lo, err = strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			hi = lo
		}
		if lo < 1 || hi > 65535 || lo > hi {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		if hi-lo > 4096 {
			return nil, fmt.Errorf("port range %q is too large", part)
		}
		for p := lo; p <= hi; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one port is required")
	}
	return out, nil
}

func resolver(server string) *net.Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	address := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		address = net.JoinHostPort(server, "53")
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, network, address)
	}}
}

func ResolveLDAPPassword(opts *LDAPOptions) error {
	return ResolveLDAPPasswordContext(context.Background(), opts)
}

func ResolveSMBPassword(opts *SMBOptions) error {
	ldap := LDAPOptions{Enabled: true, User: opts.User, Password: opts.Password, PasswordReference: opts.PasswordReference, PasswordEnv: opts.PasswordEnv, PasswordFile: opts.PasswordFile}
	if err := ResolveLDAPPasswordContext(context.Background(), &ldap); err != nil {
		return err
	}
	opts.Password, opts.PasswordReference = ldap.Password, ldap.PasswordReference
	return nil
}

const maxLDAPPasswordFileBytes int64 = 64 * 1024

func ResolveLDAPPasswordContext(ctx context.Context, opts *LDAPOptions) error {
	if !opts.Enabled || opts.Anonymous {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.PasswordEnv != "" {
		value, ok := os.LookupEnv(opts.PasswordEnv)
		if !ok {
			return fmt.Errorf("LDAP password environment variable %s is not set", opts.PasswordEnv)
		}
		opts.Password = value
		opts.PasswordReference = "env:" + opts.PasswordEnv
		return nil
	}
	if opts.PasswordFile != "" {
		file, err := os.Open(opts.PasswordFile)
		if err != nil {
			return fmt.Errorf("read LDAP password file: %w", err)
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, maxLDAPPasswordFileBytes+1))
		if err != nil {
			return fmt.Errorf("read LDAP password file: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if int64(len(data)) > maxLDAPPasswordFileBytes {
			return fmt.Errorf("LDAP password file exceeds 65536 bytes")
		}
		opts.Password = strings.TrimRight(string(data), "\r\n")
		opts.PasswordReference = "file:" + opts.PasswordFile
		return nil
	}
	return fmt.Errorf("LDAP requires --ldap-password-env, --ldap-password-file, or explicit --ldap-anonymous")
}

func ValidateOptions(opts Options) error {
	if opts.Concurrency <= 0 {
		return fmt.Errorf("concurrency must be greater than zero")
	}
	if opts.ConnectTimeout <= 0 || opts.HostTimeout <= 0 {
		return fmt.Errorf("connect and host timeouts must be greater than zero")
	}
	if opts.HTTP.Timeout <= 0 || opts.HTTP.MaxBodyBytes <= 0 || opts.HTTP.MaxRedirects < 0 {
		return fmt.Errorf("HTTP timeout and body limit must be positive and redirect limit cannot be negative")
	}
	if len(opts.Ports) == 0 {
		return fmt.Errorf("at least one probe port is required")
	}
	if opts.LDAP.UseTLS && opts.LDAP.StartTLS {
		return fmt.Errorf("LDAPS and STARTTLS are mutually exclusive")
	}
	in := opts.Scope
	in.Domain = opts.Domain
	in.Targets = append(in.Targets, opts.DC, opts.LDAP.Server)
	in.Targets = append(in.Targets, opts.Hints.ManagementPoints...)
	in.Targets = append(in.Targets, opts.Hints.DistributionPoints...)
	in.Targets = append(in.Targets, opts.Hints.SiteServers...)
	in.Targets = append(in.Targets, opts.Hints.SQLServers...)
	decision, err := scope.Normalize(in)
	if err != nil {
		return err
	}
	if len(decision.Targets) == 0 {
		return fmt.Errorf("live scope contains no targets after exclusions")
	}
	return nil
}
