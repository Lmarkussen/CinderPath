package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Profile string

const (
	ProfileSafe       Profile = "safe"
	ProfileStandard   Profile = "standard"
	ProfileAggressive Profile = "aggressive"
	ProfileYolo       Profile = "yolo"
)

type Config struct {
	DBPath         string               `yaml:"db"`
	OutputDir      string               `yaml:"output_dir"`
	LogLevel       string               `yaml:"log_level"`
	NoColor        bool                 `yaml:"no_color"`
	Timeout        time.Duration        `yaml:"-"`
	TimeoutText    string               `yaml:"timeout"`
	Profile        Profile              `yaml:"profile"`
	ConfigPath     string               `yaml:"-"`
	Scope          ScopeConfig          `yaml:"scope"`
	Discovery      DiscoveryConfig      `yaml:"discovery"`
	LDAP           LDAPConfig           `yaml:"ldap"`
	Staleness      StalenessConfig      `yaml:"staleness"`
	AuthValidation AuthValidationConfig `yaml:"auth_validation"`
	Project        ProjectConfig        `yaml:"project,omitempty" json:"project,omitempty"`
	WorkflowScope  WorkflowScopeConfig  `yaml:"workflow_scope,omitempty" json:"scope,omitempty"`
	Identity       IdentityConfig       `yaml:"identity,omitempty" json:"identity,omitempty"`
	Workflow       WorkflowConfig       `yaml:"workflow,omitempty" json:"workflow,omitempty"`
	Safety         SafetyConfig         `yaml:"safety,omitempty" json:"safety,omitempty"`
	Output         OutputConfig         `yaml:"output,omitempty" json:"output,omitempty"`
	Policy         PolicyConfig         `yaml:"policy,omitempty" json:"policy,omitempty"`
	Secrets        SecretsConfig        `yaml:"secrets,omitempty" json:"secrets,omitempty"`
}
type StalenessConfig struct {
	AssetDays              int `yaml:"asset_days"`
	EvidenceDays           int `yaml:"evidence_days"`
	CertificateWarningDays int `yaml:"certificate_warning_days"`
}
type AuthValidationConfig struct {
	Enabled                          bool   `yaml:"enabled"`
	MaxTotalAttempts                 int    `yaml:"max_total_attempts"`
	MaxAttemptsPerIdentity           int    `yaml:"max_attempts_per_identity"`
	MaxAttemptsPerEndpoint           int    `yaml:"max_attempts_per_endpoint"`
	MaxAttemptsPerIdentityEndpoint   int    `yaml:"max_attempts_per_identity_endpoint"`
	MinimumDelay                     string `yaml:"minimum_delay"`
	StopAfterSuccess                 bool   `yaml:"stop_after_success"`
	RefuseMultiplePasswordIdentities bool   `yaml:"refuse_multiple_password_identities"`
	Concurrency                      int    `yaml:"concurrency"`
}

type ScopeConfig struct {
	MaxExpandedTargets int `yaml:"max_expanded_targets"`
}

type DiscoveryConfig struct {
	Ports            string `yaml:"ports"`
	ConnectTimeout   string `yaml:"connect_timeout"`
	HostTimeout      string `yaml:"host_timeout"`
	Concurrency      int    `yaml:"concurrency"`
	HTTPMaxBodyBytes int64  `yaml:"http_max_body_bytes"`
	HTTPMaxRedirects int    `yaml:"http_max_redirects"`
	UserAgent        string `yaml:"user_agent"`
}

type LDAPConfig struct {
	PageSize      int    `yaml:"page_size"`
	MaxEntries    int    `yaml:"max_entries"`
	SearchTimeout string `yaml:"search_timeout"`
}

type Overrides struct {
	DBPath, OutputDir, LogLevel, Timeout, Profile string
	NoColor                                       bool
	Set                                           map[string]bool
}

func Defaults() Config {
	return Config{
		DBPath: "cinderpath.db", OutputDir: "reports", LogLevel: "info", Timeout: 2 * time.Minute, TimeoutText: "2m", Profile: ProfileSafe,
		Scope:          ScopeConfig{MaxExpandedTargets: 4096},
		Discovery:      DiscoveryConfig{Ports: "53,80,88,135,389,443,445,636,1433,3268,3269,8530,8531,10123", ConnectTimeout: "2s", HostTimeout: "30s", Concurrency: 32, HTTPMaxBodyBytes: 32768, HTTPMaxRedirects: 3, UserAgent: "CinderPath-safe-discovery/dev"},
		LDAP:           LDAPConfig{PageSize: 500, MaxEntries: 10000, SearchTimeout: "30s"},
		Staleness:      StalenessConfig{AssetDays: 30, EvidenceDays: 30, CertificateWarningDays: 30},
		AuthValidation: AuthValidationConfig{Enabled: false, MaxTotalAttempts: 3, MaxAttemptsPerIdentity: 1, MaxAttemptsPerEndpoint: 1, MaxAttemptsPerIdentityEndpoint: 1, MinimumDelay: "2s", StopAfterSuccess: true, RefuseMultiplePasswordIdentities: true, Concurrency: 1},
	}
}

func Load(path string, cli Overrides) (Config, error) {
	cfg := Defaults()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config %q: %w", path, err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config %q: %w", path, err)
		}
		cfg.ConfigPath = path
	}
	applyEnvironment(&cfg)
	applyCLI(&cfg, cli)
	if cfg.TimeoutText != "" {
		d, err := time.ParseDuration(cfg.TimeoutText)
		if err != nil {
			return cfg, fmt.Errorf("invalid timeout %q: %w", cfg.TimeoutText, err)
		}
		cfg.Timeout = d
	}
	if cfg.Timeout <= 0 {
		return cfg, errors.New("timeout must be greater than zero")
	}
	if cfg.Scope.MaxExpandedTargets <= 0 {
		return cfg, errors.New("scope.max_expanded_targets must be greater than zero")
	}
	if cfg.Discovery.Concurrency <= 0 {
		return cfg, errors.New("discovery.concurrency must be greater than zero")
	}
	if cfg.Discovery.HTTPMaxBodyBytes <= 0 || cfg.Discovery.HTTPMaxRedirects < 0 {
		return cfg, errors.New("HTTP body limit must be positive and redirect limit cannot be negative")
	}
	if cfg.LDAP.PageSize <= 0 || cfg.LDAP.MaxEntries <= 0 {
		return cfg, errors.New("LDAP page size and maximum entries must be greater than zero")
	}
	if cfg.Staleness.AssetDays <= 0 || cfg.Staleness.EvidenceDays <= 0 || cfg.Staleness.CertificateWarningDays <= 0 {
		return cfg, errors.New("staleness thresholds must be greater than zero")
	}
	if cfg.AuthValidation.MaxTotalAttempts <= 0 || cfg.AuthValidation.MaxAttemptsPerIdentity <= 0 || cfg.AuthValidation.MaxAttemptsPerEndpoint <= 0 || cfg.AuthValidation.MaxAttemptsPerIdentityEndpoint <= 0 || cfg.AuthValidation.Concurrency != 1 {
		return cfg, errors.New("authentication validation budgets must be positive and concurrency must be one")
	}
	if d, err := time.ParseDuration(cfg.AuthValidation.MinimumDelay); err != nil || d < 0 {
		return cfg, errors.New("auth_validation.minimum_delay must be a non-negative duration")
	}
	switch cfg.Profile {
	case ProfileSafe, ProfileStandard, ProfileAggressive, ProfileYolo:
	default:
		return cfg, fmt.Errorf("invalid profile %q (use safe, standard, aggressive, or yolo)", cfg.Profile)
	}
	switch strings.ToLower(cfg.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		return cfg, fmt.Errorf("invalid log level %q", cfg.LogLevel)
	}
	return cfg, nil
}

func applyEnvironment(cfg *Config) {
	if v := os.Getenv("CINDERPATH_DB"); v != "" {
		cfg.DBPath = v
	}
	if v := os.Getenv("CINDERPATH_OUTPUT_DIR"); v != "" {
		cfg.OutputDir = v
	}
	if v := os.Getenv("CINDERPATH_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("CINDERPATH_TIMEOUT"); v != "" {
		cfg.TimeoutText = v
	}
	if v := os.Getenv("CINDERPATH_PROFILE"); v != "" {
		cfg.Profile = Profile(v)
	}
	if v := os.Getenv("CINDERPATH_NO_COLOR"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.NoColor = b
		}
	}
}

func applyCLI(cfg *Config, cli Overrides) {
	if cli.Set["db"] {
		cfg.DBPath = cli.DBPath
	}
	if cli.Set["output-dir"] {
		cfg.OutputDir = cli.OutputDir
	}
	if cli.Set["log-level"] {
		cfg.LogLevel = cli.LogLevel
	}
	if cli.Set["timeout"] {
		cfg.TimeoutText = cli.Timeout
	}
	if cli.Set["profile"] {
		cfg.Profile = Profile(cli.Profile)
	}
	if cli.Set["no-color"] {
		cfg.NoColor = cli.NoColor
	}
}
