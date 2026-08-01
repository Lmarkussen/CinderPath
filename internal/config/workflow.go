package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

type ProjectConfig struct {
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
}
type WorkflowScopeConfig struct {
	Domain           string   `yaml:"domain,omitempty" json:"domain,omitempty"`
	DomainController string   `yaml:"domain_controller,omitempty" json:"domain_controller,omitempty"`
	DNSServer        string   `yaml:"dns_server,omitempty" json:"dns_server,omitempty"`
	Targets          []string `yaml:"targets,omitempty" json:"targets,omitempty"`
	TargetsFile      string   `yaml:"targets_file,omitempty" json:"targets_file,omitempty"`
	IncludeCIDRs     []string `yaml:"include_cidrs,omitempty" json:"include_cidrs,omitempty"`
	ExcludeHosts     []string `yaml:"exclude_hosts,omitempty" json:"exclude_hosts,omitempty"`
	ExcludeCIDRs     []string `yaml:"exclude_cidrs,omitempty" json:"exclude_cidrs,omitempty"`
	MaxTargets       int      `yaml:"max_targets,omitempty" json:"max_targets,omitempty"`
}
type IdentityConfig struct {
	Kind          string `yaml:"kind,omitempty" json:"kind,omitempty"`
	Username      string `yaml:"username,omitempty" json:"username,omitempty"`
	Domain        string `yaml:"domain,omitempty" json:"domain,omitempty"`
	PasswordEnv   string `yaml:"password_env,omitempty" json:"password_env,omitempty"`
	PasswordFile  string `yaml:"password_file,omitempty" json:"password_file,omitempty"`
	Certificate   string `yaml:"certificate,omitempty" json:"certificate,omitempty"`
	PrivateKey    string `yaml:"private_key,omitempty" json:"private_key,omitempty"`
	KerberosCache string `yaml:"kerberos_cache,omitempty" json:"kerberos_cache,omitempty"`
}
type WorkflowConfig struct {
	Provider               string `yaml:"provider,omitempty" json:"provider,omitempty"`
	Discovery              bool   `yaml:"discovery" json:"discovery"`
	LDAP                   bool   `yaml:"ldap" json:"ldap"`
	Authentication         bool   `yaml:"authentication" json:"authentication"`
	AcknowledgeLockoutRisk bool   `yaml:"acknowledge_lockout_risk" json:"acknowledge_lockout_risk"`
	Assessment             bool   `yaml:"assessment" json:"assessment"`
	Reporting              bool   `yaml:"reporting" json:"reporting"`
}
type SafetyConfig struct {
	AllowAuthentication     bool `yaml:"allow_authentication" json:"allow_authentication"`
	AllowContentDownload    bool `yaml:"allow_content_download" json:"allow_content_download"`
	AllowClientRegistration bool `yaml:"allow_client_registration" json:"allow_client_registration"`
	AllowStateChanges       bool `yaml:"allow_state_changes" json:"allow_state_changes"`
	AllowRemoteExecution    bool `yaml:"allow_remote_execution" json:"allow_remote_execution"`
}
type OutputConfig struct {
	Directory   string `yaml:"directory,omitempty" json:"directory,omitempty"`
	HTML        bool   `yaml:"html" json:"html"`
	JSON        bool   `yaml:"json" json:"json"`
	SecretsFile bool   `yaml:"secrets_file" json:"secrets_file"`
}
type PolicyConfig struct {
	LiveCollection bool `yaml:"live_collection" json:"live_collection"`
	Fixtures       struct {
		Enabled     bool     `yaml:"enabled" json:"enabled"`
		Directories []string `yaml:"directories" json:"directories"`
	} `yaml:"fixtures" json:"fixtures"`
	Protocol struct {
		RequireApprovedLiveContract bool `yaml:"require_approved_live_contract" json:"require_approved_live_contract"`
	} `yaml:"protocol" json:"protocol"`
	Parsing struct {
		Enabled bool `yaml:"enabled" json:"enabled"`
	} `yaml:"parsing" json:"parsing"`
}
type SecretsConfig struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	ShowInTerminal bool   `yaml:"show_in_terminal" json:"show_in_terminal"`
	OutputFile     string `yaml:"output_file,omitempty" json:"output_file,omitempty"`
	Format         string `yaml:"format,omitempty" json:"format,omitempty"`
}
type Diagnostic struct{ Level, Message string }

func NewWorkflow(domain string, profile Profile) Config {
	c := Defaults()
	c.Profile = profile
	c.Project.Name = domain
	c.WorkflowScope.Domain = domain
	c.WorkflowScope.MaxTargets = c.Scope.MaxExpandedTargets
	c.Workflow = WorkflowConfig{Provider: "mock", Discovery: true, LDAP: true, Authentication: profile != ProfileSafe, Assessment: true, Reporting: true}
	c.Safety = SafetyConfig{AllowAuthentication: profile != ProfileSafe}
	c.Output = OutputConfig{Directory: derivedReportDir(domain), HTML: true, JSON: true, SecretsFile: profile == ProfileAggressive || profile == ProfileYolo}
	c.OutputDir = c.Output.Directory
	c.Policy.Protocol.RequireApprovedLiveContract = true
	c.Policy.Parsing.Enabled = true
	c.Secrets.Format = "text"
	return c
}
func derivedReportDir(domain string) string {
	n, _ := NormalizeFilename(domain)
	n = strings.TrimSuffix(n, ".yaml")
	if n == "" {
		n = "cinderpath"
	}
	return filepath.Join("reports", n)
}

func NormalizeFilename(domain string) (string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return "cinderpath.yaml", nil
	}
	var b strings.Builder
	sep := false
	for _, r := range domain {
		if r > unicode.MaxASCII {
			return "", fmt.Errorf("domain contains unsupported non-ASCII character %q", r)
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			sep = false
		} else if !sep {
			b.WriteByte('_')
			sep = true
		}
	}
	n := strings.Trim(b.String(), "_")
	if n == "" {
		return "", errors.New("domain does not contain filename-safe characters")
	}
	return n + ".yaml", nil
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func Validate(c Config) []Diagnostic {
	var d []Diagnostic
	add := func(l, m string) { d = append(d, Diagnostic{l, m}) }
	if c.Profile != ProfileSafe && c.Profile != ProfileStandard && c.Profile != ProfileAggressive && c.Profile != ProfileYolo {
		add("ERROR", fmt.Sprintf("unknown profile %q", c.Profile))
	}
	for label, host := range map[string]string{"domain": c.WorkflowScope.Domain, "domain controller": c.WorkflowScope.DomainController} {
		if host != "" && (strings.ContainsAny(host, "/\\") || strings.Contains(host, "..")) {
			add("ERROR", label+" has an invalid hostname")
		}
	}
	for _, cidr := range append(append([]string{}, c.WorkflowScope.IncludeCIDRs...), c.WorkflowScope.ExcludeCIDRs...) {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			add("ERROR", fmt.Sprintf("invalid CIDR %q", cidr))
		}
	}
	max := c.WorkflowScope.MaxTargets
	if max == 0 {
		max = c.Scope.MaxExpandedTargets
	}
	if max <= 0 || max > 65536 {
		add("ERROR", "scope maximum must be between 1 and 65536")
	}
	if c.Identity.PasswordEnv != "" && !envName.MatchString(c.Identity.PasswordEnv) {
		add("ERROR", "password environment reference has invalid syntax")
	}
	validKinds := map[string]bool{"": true, "domain_user": true, "username_password_reference": true, "certificate_reference": true, "kerberos_cache_reference": true, "anonymous": true}
	if !validKinds[c.Identity.Kind] {
		add("ERROR", fmt.Sprintf("invalid identity kind %q", c.Identity.Kind))
	}
	for _, p := range []string{c.Identity.PasswordFile, c.Identity.Certificate, c.Identity.PrivateKey, c.Identity.KerberosCache, c.WorkflowScope.TargetsFile} {
		if p != "" {
			if _, err := os.Stat(p); err != nil {
				add("WARNING", fmt.Sprintf("referenced file is unavailable: %s", filepath.Base(p)))
			}
		}
	}
	if c.Workflow.Authentication && !c.Workflow.AcknowledgeLockoutRisk {
		add("WARNING", "authentication validation is enabled without lockout acknowledgement")
	}
	if c.Profile == ProfileSafe && c.Safety.AllowAuthentication {
		add("ERROR", "safe profile cannot allow authentication")
	}
	if c.Safety.AllowContentDownload || c.Safety.AllowClientRegistration || c.Safety.AllowStateChanges || c.Safety.AllowRemoteExecution {
		add("ERROR", "unsupported unsafe safety permission is enabled")
	}
	if c.Profile == ProfileAggressive || c.Profile == ProfileYolo {
		for _, m := range []string{"policy retrieval", "DP content inspection", "PXE material inspection", "secret extraction"} {
			add("WARNING", m+" is enabled by profile intent but not implemented")
		}
	}
	if c.Output.SecretsFile {
		add("INFO", "live secret-recovery modules available: 0; offline fixture classification is available")
	}
	if c.Workflow.Provider != "" && c.Workflow.Provider != "mock" && c.Workflow.Provider != "live" {
		add("ERROR", "workflow.provider must be mock or live")
	}
	if c.Workflow.Provider == "live" && len(c.WorkflowScope.Targets) == 0 && c.WorkflowScope.TargetsFile == "" && len(c.WorkflowScope.IncludeCIDRs) == 0 && c.WorkflowScope.DomainController == "" {
		add("ERROR", "live provider requires explicit target scope")
	}
	if c.WorkflowScope.DNSServer != "" {
		h := c.WorkflowScope.DNSServer
		if x, _, e := net.SplitHostPort(h); e == nil {
			h = x
		}
		if net.ParseIP(h) == nil && strings.ContainsAny(h, "/\\") {
			add("ERROR", "invalid DNS server")
		}
	}
	if c.Policy.LiveCollection {
		add("ERROR", "live policy collection is unavailable: no approved live protocol contract")
	}
	if c.Secrets.Format != "" && c.Secrets.Format != "text" && c.Secrets.Format != "json" {
		add("ERROR", "secrets.format must be text or json")
	}
	return d
}
func HasErrors(d []Diagnostic) bool {
	for _, x := range d {
		if x.Level == "ERROR" {
			return true
		}
	}
	return false
}

func Marshal(c Config) ([]byte, error)     { return yaml.Marshal(c) }
func MarshalJSON(c Config) ([]byte, error) { return json.MarshalIndent(Redacted(c), "", "  ") }
func Redacted(c Config) Config {
	for _, p := range []*string{&c.Identity.PasswordFile, &c.Identity.Certificate, &c.Identity.PrivateKey, &c.Identity.KerberosCache, &c.WorkflowScope.TargetsFile} {
		if *p != "" {
			*p = filepath.Base(*p)
		}
	}
	return c
}
func WriteAtomic(path string, c Config, force bool) error {
	if HasErrors(Validate(c)) {
		return errors.New("configuration validation failed")
	}
	if !force {
		if _, e := os.Lstat(path); e == nil {
			return fmt.Errorf("refusing to overwrite existing file %q (use --force)", path)
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	data, e := Marshal(c)
	if e != nil {
		return e
	}
	dir := filepath.Dir(path)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".cinderpath-*.tmp")
	if e != nil {
		return e
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if force {
		_ = os.Remove(path)
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	ok = true
	return nil
}
func ParseDuration(s string) error {
	d, e := time.ParseDuration(s)
	if e != nil || d < 0 {
		return errors.New("invalid duration")
	}
	return nil
}
func DecodeStrict(data []byte, out *Config) error {
	return yaml.NewDecoder(bytes.NewReader(data)).Decode(out)
}
