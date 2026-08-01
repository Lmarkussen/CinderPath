package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/app"
	"github.com/Lmarkussen/CinderPath/internal/authvalidate"
	"github.com/Lmarkussen/CinderPath/internal/config"
	"github.com/Lmarkussen/CinderPath/internal/discovery/live"
	"github.com/Lmarkussen/CinderPath/internal/identity"
	"github.com/Lmarkussen/CinderPath/internal/scope"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type workflowFlags struct {
	domain, dc, dns, username, kind, passwordEnv, passwordFile, certificate, privateKey, kerberosCache, profile, output, targetsFile, provider string
	targets, includeCIDRs, excludeHosts, excludeCIDRs                                                                                          []string
	force, nonInteractive, dryRun, saveConfig, forceConfig, ackLockout                                                                         bool
	configOutput                                                                                                                               string
}

func (s *state) bindWorkflowFlags(f interface {
	StringVar(*string, string, string, string)
	StringArrayVar(*[]string, string, []string, string)
	BoolVar(*bool, string, bool, string)
}, init bool) {
	w := &s.workflow
	f.StringVar(&w.domain, "domain", "", "assessment domain")
	f.StringVar(&w.dc, "domain-controller", "", "domain controller and explicit target")
	f.StringVar(&w.dns, "dns-server", "", "DNS resolver")
	f.StringVar(&w.username, "username", "", "primary identity username")
	f.StringVar(&w.kind, "identity-kind", "", "primary identity kind")
	f.StringVar(&w.passwordEnv, "password-env", "", "password environment-variable reference")
	f.StringVar(&w.passwordFile, "password-file", "", "password file reference")
	f.StringVar(&w.certificate, "certificate", "", "public certificate path")
	f.StringVar(&w.privateKey, "private-key", "", "private-key reference")
	f.StringVar(&w.kerberosCache, "kerberos-cache", "", "Kerberos cache reference")
	f.StringArrayVar(&w.targets, "target", nil, "explicit target (repeatable)")
	f.StringVar(&w.targetsFile, "targets-file", "", "targets file")
	f.StringArrayVar(&w.includeCIDRs, "include-cidr", nil, "included CIDR")
	f.StringArrayVar(&w.excludeHosts, "exclude-host", nil, "excluded host")
	f.StringArrayVar(&w.excludeCIDRs, "exclude-cidr", nil, "excluded CIDR")
	if init {
		f.StringVar(&w.output, "output", "", "configuration output path")
		f.BoolVar(&w.force, "force", false, "overwrite an existing configuration")
		f.BoolVar(&w.nonInteractive, "non-interactive", false, "disable prompts")
	}
}

func (s *state) configCommand() *cobra.Command {
	root := &cobra.Command{Use: "config", Short: "Create, validate, and inspect workflow configuration"}
	init := &cobra.Command{Use: "init", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return s.configInit(cmd) }}
	s.bindWorkflowFlags(init.Flags(), true)
	validate := &cobra.Command{Use: "validate FILE", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		c, e := config.Load(args[0], config.Overrides{Set: map[string]bool{}})
		if e != nil {
			return e
		}
		ds := config.Validate(c)
		printDiagnostics(s.stdout, ds)
		if config.HasErrors(ds) {
			return errors.New("configuration invalid")
		}
		fmt.Fprintf(s.stdout, "Configuration valid with %d warnings\n\nEffective profile: %s\n", countLevel(ds, "WARNING"), c.Profile)
		return nil
	}}
	format := "yaml"
	show := &cobra.Command{Use: "show FILE", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		c, e := config.Load(args[0], config.Overrides{Set: map[string]bool{}})
		if e != nil {
			return e
		}
		r := config.Redacted(c)
		var b []byte
		if format == "json" {
			y, ye := yaml.Marshal(r)
			var generic any
			if ye == nil {
				ye = yaml.Unmarshal(y, &generic)
			}
			if ye != nil {
				return ye
			}
			b, e = json.MarshalIndent(generic, "", "  ")
		} else if format == "yaml" {
			b, e = yaml.Marshal(r)
		} else {
			return errors.New("format must be yaml or json")
		}
		if e == nil {
			fmt.Fprintln(s.stdout, string(b))
			printDiagnostics(s.stdout, config.Validate(c))
		}
		return e
	}}
	show.Flags().StringVar(&format, "format", "yaml", "yaml or json")
	root.AddCommand(init, validate, show)
	return root
}
func countLevel(ds []config.Diagnostic, l string) int {
	n := 0
	for _, d := range ds {
		if d.Level == l {
			n++
		}
	}
	return n
}
func printDiagnostics(w io.Writer, ds []config.Diagnostic) {
	for _, d := range ds {
		fmt.Fprintf(w, "%s %s\n", d.Level, d.Message)
	}
}

func (s *state) configInit(cmd *cobra.Command) error {
	w := &s.workflow
	if !w.nonInteractive && w.domain == "" {
		if fi, e := os.Stdin.Stat(); e != nil || fi.Mode()&os.ModeCharDevice == 0 {
			return errors.New("interactive input unavailable; use --non-interactive with --domain or explicit --output")
		}
		r := bufio.NewReader(os.Stdin)
		w.domain = prompt(r, s.stdout, "Domain", "")
		w.dc = prompt(r, s.stdout, "Domain controller", "optional")
		w.username = prompt(r, s.stdout, "Username", "optional")
		w.profile = prompt(r, s.stdout, "Assessment profile (safe, standard, aggressive, yolo)", "safe")
	}
	if w.nonInteractive && w.domain == "" && w.output == "" {
		return errors.New("non-interactive configuration requires --domain or --output")
	}
	profile := config.Profile(valueOr(w.profile, string(s.cfg.Profile)))
	c := config.NewWorkflow(w.domain, profile)
	applyWorkflow(&c, *w)
	path := w.output
	if path == "" {
		var e error
		path, e = config.NormalizeFilename(w.domain)
		if e != nil {
			return e
		}
	}
	if ds := config.Validate(c); config.HasErrors(ds) {
		printDiagnostics(s.stderr, ds)
		return errors.New("configuration validation failed")
	}
	if err := config.WriteAtomic(path, c, w.force); err != nil {
		return err
	}
	fmt.Fprintf(s.stdout, "Created configuration: %s\nPermissions: 0600\nProfile: %s\nPassword source: %s\n\nRun:\n\n  cinderpath run --config %s\n", path, c.Profile, passwordSource(c), path)
	return nil
}
func prompt(r *bufio.Reader, w io.Writer, label, def string) string {
	if def != "" {
		fmt.Fprintf(w, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(w, "%s: ", label)
	}
	v, _ := r.ReadString('\n')
	v = strings.TrimSpace(v)
	if v == "" && def != "optional" {
		v = def
	}
	return v
}
func passwordSource(c config.Config) string {
	if c.Identity.PasswordEnv != "" {
		return "env:" + c.Identity.PasswordEnv
	}
	if c.Identity.PasswordFile != "" {
		return "file:" + filepath.Base(c.Identity.PasswordFile)
	}
	if c.Identity.Certificate != "" {
		return "certificate:" + filepath.Base(c.Identity.Certificate)
	}
	if c.Identity.KerberosCache != "" {
		return "kerberos-cache:" + filepath.Base(c.Identity.KerberosCache)
	}
	return "none"
}
func applyWorkflow(c *config.Config, w workflowFlags) {
	c.Project.Name = w.domain
	c.WorkflowScope = config.WorkflowScopeConfig{Domain: w.domain, DomainController: w.dc, DNSServer: w.dns, Targets: w.targets, TargetsFile: w.targetsFile, IncludeCIDRs: w.includeCIDRs, ExcludeHosts: w.excludeHosts, ExcludeCIDRs: w.excludeCIDRs, MaxTargets: c.Scope.MaxExpandedTargets}
	c.Identity = config.IdentityConfig{Kind: w.kind, Username: w.username, PasswordEnv: w.passwordEnv, PasswordFile: w.passwordFile, Certificate: w.certificate, PrivateKey: w.privateKey, KerberosCache: w.kerberosCache}
	if c.Identity.Kind == "" && w.username != "" {
		c.Identity.Kind = "username_password_reference"
	}
	if w.profile != "" {
		c.Profile = config.Profile(w.profile)
	}
	if w.provider != "" {
		c.Workflow.Provider = w.provider
	}
	if w.ackLockout {
		c.Workflow.AcknowledgeLockoutRisk = true
	}
}

func (s *state) runCommand() *cobra.Command {
	c := &cobra.Command{Use: "run", Short: "Run the unified CinderPath workflow", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return s.executeWorkflow(cmd) }}
	s.bindWorkflowFlags(c.Flags(), false)
	f := c.Flags()
	f.StringVar(&s.workflow.provider, "provider", "", "mock or explicitly enabled live discovery")
	f.BoolVar(&s.workflow.dryRun, "dry-run", false, "plan without network activity or persistent observations")
	f.BoolVar(&s.workflow.saveConfig, "save-config", false, "save flag-derived configuration before running")
	f.StringVar(&s.workflow.configOutput, "config-output", "", "saved configuration path")
	f.BoolVar(&s.workflow.forceConfig, "force-config", false, "overwrite saved configuration")
	f.BoolVar(&s.workflow.ackLockout, "acknowledge-lockout-risk", false, "acknowledge authentication lockout risk")
	return c
}
func (s *state) executeWorkflow(cmd *cobra.Command) error {
	c := s.cfg
	if s.configPath == "" {
		base := c
		c = config.NewWorkflow(s.workflow.domain, config.Profile(valueOr(s.workflow.profile, string(c.Profile))))
		c.DBPath, c.LogLevel, c.NoColor, c.Timeout, c.TimeoutText = base.DBPath, base.LogLevel, base.NoColor, base.Timeout, base.TimeoutText
		if cmd.Flags().Changed("output-dir") {
			c.OutputDir, c.Output.Directory = base.OutputDir, base.OutputDir
		}
		applyWorkflow(&c, s.workflow)
	}
	if ds := config.Validate(c); config.HasErrors(ds) {
		printDiagnostics(s.stderr, ds)
		return errors.New("configuration validation failed")
	}
	if s.workflow.saveConfig {
		p := s.workflow.configOutput
		if p == "" {
			p, _ = config.NormalizeFilename(c.WorkflowScope.Domain)
		}
		if e := config.WriteAtomic(p, c, s.workflow.forceConfig); e != nil {
			return e
		}
		fmt.Fprintf(s.stdout, "Created configuration: %s\n", p)
	}
	plan := app.BuildWorkflowPlan(c, s.workflow.dryRun)
	app.PrintWorkflowPlan(s.stdout, plan)
	if s.workflow.dryRun {
		return nil
	}
	s.cfg = c
	s.application.Config = c
	ctx, cancel := context.WithTimeout(cmd.Context(), c.Timeout)
	defer cancel()
	primaryID := ""
	if c.Identity.Username != "" {
		idOut, e := s.application.InspectIdentity(ctx, identity.Input{User: c.Identity.Username, Domain: c.Identity.Domain, Kind: c.Identity.Kind, PasswordEnv: c.Identity.PasswordEnv, PasswordFile: c.Identity.PasswordFile, Certificate: c.Identity.Certificate, PrivateKey: c.Identity.PrivateKey, KerberosCache: c.Identity.KerberosCache})
		if e != nil {
			fmt.Fprintf(s.stderr, "identity inspection: %v; continuing\n", e)
		} else {
			primaryID = idOut.Identity.ID
		}
	}
	provider := c.Workflow.Provider
	if provider == "" {
		provider = "mock"
	}
	o := app.DiscoverOptions{Provider: provider}
	if provider == "live" {
		ports, _ := live.ParsePorts(c.Discovery.Ports)
		host := mustDuration(c.Discovery.HostTimeout)
		o.Live = live.Options{Domain: c.WorkflowScope.Domain, DC: c.WorkflowScope.DomainController, DNSServer: c.WorkflowScope.DNSServer, Ports: ports, Concurrency: c.Discovery.Concurrency, ConnectTimeout: mustDuration(c.Discovery.ConnectTimeout), HostTimeout: host, Scope: scopeInput(c), HTTP: live.HTTPOptions{UserAgent: c.Discovery.UserAgent, MaxBodyBytes: c.Discovery.HTTPMaxBodyBytes, MaxRedirects: c.Discovery.HTTPMaxRedirects, Timeout: host}, LDAP: live.LDAPOptions{Enabled: c.Workflow.LDAP, Server: c.WorkflowScope.DomainController, User: c.Identity.Username, PasswordEnv: c.Identity.PasswordEnv, PasswordFile: c.Identity.PasswordFile, PageSize: c.LDAP.PageSize, MaxEntries: c.LDAP.MaxEntries, SearchTimeout: mustDuration(c.LDAP.SearchTimeout)}}
	}
	disc, e := s.application.DiscoverWithOptions(ctx, []string{"run"}, o)
	if e != nil {
		return e
	}
	if c.Profile != config.ProfileSafe && c.Workflow.Authentication && c.Safety.AllowAuthentication && c.Workflow.AcknowledgeLockoutRisk && primaryID != "" {
		delay := mustDuration(c.AuthValidation.MinimumDelay)
		authOpts := authvalidate.Options{Enabled: true, AcknowledgeLockout: true, ValidatedManagementPoints: true, IdentityID: primaryID, Method: "basic", Timeout: c.Timeout, Budget: authvalidate.Budget{MaxTotal: c.AuthValidation.MaxTotalAttempts, MaxPerIdentity: c.AuthValidation.MaxAttemptsPerIdentity, MaxPerEndpoint: c.AuthValidation.MaxAttemptsPerEndpoint, MaxPerIdentityEndpoint: c.AuthValidation.MaxAttemptsPerIdentityEndpoint, MinimumDelay: delay, StopAfterSuccess: c.AuthValidation.StopAfterSuccess}}
		authOpts.PlanSink = func(plans []authvalidate.Plan) {
			fmt.Fprintf(s.stdout, "\nAuthentication plan: %d exact known route attempt(s)\n", len(plans))
		}
		if _, authErr := s.application.ValidateAuthentication(ctx, []string{"run"}, authOpts); authErr != nil {
			fmt.Fprintf(s.stderr, "authentication validation blocked or failed: %v; continuing safe stages\n", authErr)
		}
	}
	assess, ae := s.application.Assess(ctx, []string{"run"})
	rep, re := s.application.Report(ctx, []string{"run"})
	fmt.Fprintf(s.stdout, "\nCinderPath run complete\n\nProject: %s\nProfile: %s\nRun ID: %s\nAssets: %d\nCompleted modules: %d\nBlocked modules: %d\nNot implemented: %d\nSecret-recovery modules available: 0\nSecrets recovered: 0\nAttack paths: %d\nHTML: %s\nJSON: %s\n", c.Project.Name, c.Profile, disc.Run.ID, disc.Assets, disc.ModuleSummary.Executed, disc.ModuleSummary.Skipped, plan.NotImplemented, assess.AttackPaths, rep.ReportPaths.HTML, rep.ReportPaths.JSON)
	if ae != nil {
		return ae
	}
	return re
}
func mustDuration(v string) time.Duration { d, _ := time.ParseDuration(v); return d }
func scopeInput(c config.Config) scope.Input {
	files := []string{}
	if c.WorkflowScope.TargetsFile != "" {
		files = append(files, c.WorkflowScope.TargetsFile)
	}
	return scope.Input{Targets: c.WorkflowScope.Targets, TargetFiles: files, IncludeCIDRs: c.WorkflowScope.IncludeCIDRs, ExcludeHosts: c.WorkflowScope.ExcludeHosts, ExcludeCIDRs: c.WorkflowScope.ExcludeCIDRs, Domain: c.WorkflowScope.Domain, MaxTargets: c.WorkflowScope.MaxTargets}
}
