package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/app"
	"github.com/Lmarkussen/CinderPath/internal/authvalidate"
	"github.com/Lmarkussen/CinderPath/internal/config"
	"github.com/Lmarkussen/CinderPath/internal/discovery/live"
	"github.com/Lmarkussen/CinderPath/internal/framework"
	"github.com/Lmarkussen/CinderPath/internal/identity"
	"github.com/Lmarkussen/CinderPath/internal/logging"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/outputpolicy"
	"github.com/Lmarkussen/CinderPath/internal/scope"
	"github.com/Lmarkussen/CinderPath/internal/terminal"
	"github.com/Lmarkussen/CinderPath/internal/version"
	"github.com/spf13/cobra"
)

type state struct {
	configPath                                string
	db, outputDir, logLevel, timeout, profile string
	noColor, verbose                          bool
	color                                     string
	renderer                                  terminal.Renderer
	redactSecrets                             bool
	cfg                                       config.Config
	application                               *app.Application
	stdout, stderr                            io.Writer
	familyPreflight                           bool
	discover                                  discoverFlags
	identity                                  identity.Input
	auth                                      authFlags
	workflow                                  workflowFlags
}

type discoverFlags struct {
	provider                                                       string
	targets, targetFiles, includeCIDRs, excludeHosts, excludeCIDRs []string
	domain, dnsServer, dc, ports, connectTimeout, hostTimeout      string
	maxTargets, concurrency                                        int
	ldap                                                           bool
	ldapServer                                                     string
	ldapPort                                                       int
	ldapBaseDN, ldapUser, ldapPasswordEnv, ldapPasswordFile        string
	ldapUseTLS, ldapStartTLS, ldapInsecure, ldapAnonymous          bool
	managementPoints, distributionPoints, siteServers, sqlServers  []string
	siteCode                                                       string
}
type authFlags struct {
	enabled, dryRun, ackLockout, ackMultiple, allowBasicHTTP, allowRepeat, validatedMPs bool
	identityID, method, minimumDelay                                                    string
	endpoints                                                                           []string
	maxTotal, maxIdentity, maxEndpoint, maxPair                                         int
}

func New(stdout, stderr io.Writer) *cobra.Command {
	s := &state{stdout: stdout, stderr: stderr}
	d := config.Defaults()
	root := &cobra.Command{Use: "cinderpath", Short: "Safe SCCM discovery and Misconfiguration Manager assessment", Long: "CinderPath discovers SCCM, assesses supported Misconfiguration Manager techniques, validates findings through explicit safety gates, records cleanup obligations, and generates evidence-backed reports. Advanced offline tooling lives under research; diagnostic tooling lives under debug.", Example: "  cinderpath discover --provider mock\n  cinderpath assess --framework misconfiguration-manager --target lab.example\n  cinderpath assess pxe --target srv01\n  cinderpath report\n  cinderpath research --help", SilenceUsage: true, SilenceErrors: true, PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return s.configure(cmd) }}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetHelpCommand(s.helpCommand(root))
	f := root.PersistentFlags()
	f.StringVar(&s.configPath, "config", "", "optional YAML configuration file")
	f.StringVar(&s.db, "db", d.DBPath, "SQLite database path")
	f.StringVar(&s.outputDir, "output-dir", d.OutputDir, "report output directory")
	f.StringVar(&s.logLevel, "log-level", d.LogLevel, "log level: debug, info, warn, error")
	f.BoolVar(&s.noColor, "no-color", d.NoColor, "disable ANSI color output")
	f.StringVar(&s.color, "color", "auto", "color output: auto, always, or never")
	_ = f.MarkHidden("color")
	f.BoolVar(&s.verbose, "verbose", false, "show resolved context sources and advanced details")
	f.BoolVar(&s.redactSecrets, "redact-secrets", false, "redact secret values in operator output and reports")
	f.StringVar(&s.timeout, "timeout", d.TimeoutText, "command timeout")
	f.StringVar(&s.profile, "profile", string(d.Profile), "policy profile: safe, standard, aggressive, yolo, or research")
	root.AddCommand(s.versionCommand(), s.discoverCommand(), s.assessCommand(), s.validationCommand(), s.exploitCommand(), s.cleanupCommand(), s.reportCommand(), s.runCommand(), s.frameworkCommand(), s.researchCommand(), s.debugCommand(root), s.techniquesCommand())
	return root
}
func (s *state) authCommand() *cobra.Command {
	root := &cobra.Command{Use: "auth", Short: "Explicitly validate selected authentication against exact known SCCM routes"}
	validate := &cobra.Command{Use: "validate", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		delay, err := time.ParseDuration(valueOr(s.auth.minimumDelay, s.cfg.AuthValidation.MinimumDelay))
		if err != nil {
			return err
		}
		o := authvalidate.Options{Enabled: s.auth.enabled, DryRun: s.auth.dryRun, AcknowledgeLockout: s.auth.ackLockout, AcknowledgeMultiple: s.auth.ackMultiple, AllowBasicHTTP: s.auth.allowBasicHTTP, AllowRepeat: s.auth.allowRepeat, ValidatedManagementPoints: s.auth.validatedMPs, IdentityID: s.auth.identityID, Endpoints: s.auth.endpoints, Method: s.auth.method, Timeout: s.cfg.Timeout, Budget: authvalidate.Budget{MaxTotal: intOr(s.auth.maxTotal, s.cfg.AuthValidation.MaxTotalAttempts), MaxPerIdentity: intOr(s.auth.maxIdentity, s.cfg.AuthValidation.MaxAttemptsPerIdentity), MaxPerEndpoint: intOr(s.auth.maxEndpoint, s.cfg.AuthValidation.MaxAttemptsPerEndpoint), MaxPerIdentityEndpoint: intOr(s.auth.maxPair, s.cfg.AuthValidation.MaxAttemptsPerIdentityEndpoint), MinimumDelay: delay, StopAfterSuccess: s.cfg.AuthValidation.StopAfterSuccess}}
		o.PlanSink = func(plans []authvalidate.Plan) {
			fmt.Fprintln(s.stdout, "Authentication validation plan")
			fmt.Fprintf(s.stdout, "Attempts planned: %d\nRemote authentication has not yet been attempted.\n", len(plans))
			for _, p := range plans {
				fmt.Fprintf(s.stdout, "\nIdentity: %s\nEndpoint: %s\nRoute: %s\nMethod: %s\nAuthentication: %s\nPrevious attempts: %d\n", p.IdentityID(), p.Origin, p.Route, p.HTTPMethod, p.AuthenticationMethod, p.PreviousAttempts)
			}
			fmt.Fprintln(s.stdout, "\nWarning: A failed authentication attempt may contribute to account lockout.")
		}
		out, err := s.application.ValidateAuthentication(cmd.Context(), os.Args[1:], o)
		for _, a := range out.Attempts {
			fmt.Fprintf(s.stdout, "\nEndpoint: %s\nRoute: %s\nMethod: %s\nAuthentication: %s\nAttempts planned: 1\nPrevious attempts: %d\nAttempted: %t\nResult: %s\nHTTP response: %d\nCredentials stored: no\nAuthorization data persisted: no\n", a.Origin, a.Route, a.Method, a.AuthenticationMethod, a.PreviousAttempts, a.Attempted, a.Status, a.StatusCode)
		}
		return err
	}}
	f := validate.Flags()
	f.BoolVar(&s.auth.enabled, "enable-auth-validation", false, "explicitly enable remote authentication validation")
	f.BoolVar(&s.auth.dryRun, "dry-run", false, "plan without reading secrets or sending traffic")
	f.BoolVar(&s.auth.ackLockout, "acknowledge-lockout-risk", false, "acknowledge that one failed attempt may contribute to lockout")
	f.BoolVar(&s.auth.ackMultiple, "acknowledge-multiple-attempts", false, "acknowledge a plan containing more than one attempt")
	f.BoolVar(&s.auth.allowBasicHTTP, "allow-basic-over-http", false, "allow Basic over cleartext HTTP (strongly discouraged)")
	f.BoolVar(&s.auth.allowRepeat, "allow-repeat-attempt", false, "permit a repeated tuple within remaining budgets")
	f.BoolVar(&s.auth.validatedMPs, "validated-management-points", false, "select matching routes on validated management points")
	f.StringVar(&s.auth.identityID, "identity-id", "", "exact stored identity ID")
	f.StringArrayVar(&s.auth.endpoints, "endpoint", nil, "exact previously observed origin (repeatable)")
	f.StringVar(&s.auth.method, "authentication-method", "basic", "basic or tls_client_certificate")
	f.StringVar(&s.auth.minimumDelay, "minimum-delay", "", "minimum delay between attempts")
	f.IntVar(&s.auth.maxTotal, "max-total-attempts", 0, "maximum total attempt budget")
	f.IntVar(&s.auth.maxIdentity, "max-attempts-per-identity", 0, "maximum attempts per identity")
	f.IntVar(&s.auth.maxEndpoint, "max-attempts-per-endpoint", 0, "maximum attempts per endpoint")
	f.IntVar(&s.auth.maxPair, "max-attempts-per-identity-endpoint", 0, "maximum attempts per identity/endpoint")
	results := &cobra.Command{Use: "results", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		out, err := s.application.AuthenticationResults(cmd.Context())
		if err != nil {
			return err
		}
		for _, a := range out.Attempts {
			fmt.Fprintf(s.stdout, "%s %s %s %s attempted=%t status=%s code=%d\n", a.StartedAt, a.IdentityID, a.Origin, a.AuthenticationMethod, a.Attempted, a.Status, a.StatusCode)
		}
		return nil
	}}
	root.AddCommand(validate, results)
	return root
}
func valueOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
func intOr(a, b int) int {
	if a > 0 {
		return a
	}
	return b
}
func (s *state) identityCommand() *cobra.Command {
	c := &cobra.Command{Use: "identity", Short: "Inspect local identity references without authenticating"}
	inspect := &cobra.Command{Use: "inspect", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), s.cfg.Timeout)
		defer cancel()
		out, err := s.application.InspectIdentity(ctx, s.identity)
		if err != nil {
			return err
		}
		printIdentity(s.stdout, out.Identity, s.outputPolicy())
		fmt.Fprintf(s.stdout, "\nRemote authentication attempted: no\nRemote authentication validated: no\nDatabase: %s\n", out.DatabasePath)
		if len(out.Capabilities) > 0 {
			fmt.Fprintln(s.stdout, "\nPotential capabilities:")
			printCapabilities(s.stdout, out.Capabilities)
		}
		return nil
	}}
	f := inspect.Flags()
	f.StringVar(&s.identity.User, "identity-user", "", "username, DOMAIN\\user, or UPN")
	f.StringVar(&s.identity.Domain, "identity-domain", "", "identity domain")
	f.StringVar(&s.identity.Kind, "identity-kind", "", "normalized identity kind")
	f.StringVar(&s.identity.PasswordEnv, "password-env", "", "environment variable containing a password")
	f.StringVar(&s.identity.PasswordFile, "password-file", "", "bounded password file reference")
	f.StringVar(&s.identity.NTLMHashEnv, "ntlm-hash-env", "", "environment variable containing an NTLM hash")
	f.StringVar(&s.identity.NTLMHashFile, "ntlm-hash-file", "", "bounded NTLM hash file reference")
	f.StringVar(&s.identity.KerberosCache, "kerberos-cache", "", "Kerberos cache path (existence only)")
	f.StringVar(&s.identity.Certificate, "certificate", "", "public PEM or DER certificate")
	f.StringVar(&s.identity.PrivateKey, "private-key", "", "private-key path reference (not read)")
	f.StringVar(&s.identity.SCCMClientCert, "sccm-client-cert", "", "SCCM client public certificate")
	f.StringVar(&s.identity.SCCMClientKey, "sccm-client-key", "", "SCCM client private-key reference (not read)")
	f.StringVar(&s.identity.MachineAccount, "machine-account", "", "machine-account name ending in $")
	f.BoolVar(&s.identity.CurrentProcess, "current-process-identity", false, "describe the current process identity")
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		out, err := s.application.ListIdentities(cmd.Context())
		if err != nil {
			return err
		}
		for _, id := range out.Identities {
			printIdentity(s.stdout, id, s.outputPolicy())
			fmt.Fprintln(s.stdout)
		}
		return nil
	}}
	c.AddCommand(inspect, list)
	return c
}
func (s *state) capabilitiesCommand() *cobra.Command {
	return &cobra.Command{Use: "capabilities", Short: "Plan future authentication capabilities from stored passive evidence", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		out, err := s.application.PlanCapabilities(cmd.Context())
		if err != nil {
			return err
		}
		fmt.Fprintln(s.stdout, "No remote authentication was attempted during this phase.")
		printCapabilities(s.stdout, out.Capabilities)
		return nil
	}}
}
func printIdentity(w io.Writer, id models.Credential, p outputpolicy.Policy) {
	name := id.Principal
	if name == "" {
		name = id.Username
		if id.Domain != "" {
			name = id.Domain + "\\" + name
		}
	}
	if name == "" {
		name = id.MachineName
	}
	if name == "" {
		name = string(id.Kind)
	}
	fmt.Fprintf(w, "Identity: %s\nIdentity ID: %s\nKind: %s\nReference: %s\nReference available: %t\nMetadata validated locally: %t\nValidation: %s\nRedaction: secrets_redacted=%t\n", name, id.ID, id.Kind, id.RedactedReference, id.Validated, id.Validated, id.ValidationReason, p.RedactSecrets)
}
func printCapabilities(w io.Writer, caps []models.Capability) {
	for _, c := range caps {
		fmt.Fprintf(w, "  %s\n    State: %s\n    Endpoint: %s\n    Reason: %s\n    Blocked by current safety profile: %t\n", c.Name, c.State, c.RelatedEndpoint, c.Reason, c.SafetyBlocked)
	}
}

func (s *state) configure(cmd *cobra.Command) error {
	path := s.configPath
	if path == "" {
		path = os.Getenv("CINDERPATH_CONFIG")
	}
	set := map[string]bool{}
	for _, name := range []string{"db", "output-dir", "log-level", "no-color", "timeout", "profile", "redact-secrets"} {
		set[name] = cmd.Flags().Changed(name)
	}
	cfg, err := config.Load(path, config.Overrides{DBPath: s.db, OutputDir: s.outputDir, LogLevel: s.logLevel, NoColor: s.noColor, RedactSecrets: s.redactSecrets, Timeout: s.timeout, Profile: s.profile, Set: set})
	if err != nil {
		return err
	}
	s.cfg = cfg
	mode := terminal.Mode(s.color)
	if mode != terminal.Auto && mode != terminal.Always && mode != terminal.Never {
		return fmt.Errorf("invalid --color %q (use auto, always, or never)", s.color)
	}
	colorChanged := cmd.Flags().Changed("color")
	if cfg.NoColor && colorChanged && mode == terminal.Always {
		return errors.New("--no-color cannot be combined with --color always")
	}
	if formatFlag := cmd.Flags().Lookup("format"); formatFlag != nil && formatFlag.Value.String() == "json" {
		mode = terminal.Never
	}
	if cfg.NoColor || os.Getenv("NO_COLOR") != "" {
		mode = terminal.Never
	}
	s.renderer = terminal.New(mode, s.stdout)
	s.application = &app.Application{Config: cfg, Logger: logging.New(s.stderr, cfg.LogLevel, cfg.NoColor)}
	return nil
}

func (s *state) outputPolicy() outputpolicy.Policy {
	return outputpolicy.Policy{RedactSecrets: s.cfg.Output.RedactSecrets}
}
func (s *state) versionCommand() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print version and build information", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { fmt.Fprintln(s.stdout, version.Current().String()); return nil }}
}
func (s *state) discoverCommand() *cobra.Command {
	c := &cobra.Command{Use: "discover", Short: "Discover SCCM with bounded live defaults", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), s.cfg.Timeout)
		defer cancel()
		options, err := s.discoverOptions()
		if err != nil {
			return err
		}
		out, err := s.application.DiscoverWithOptions(ctx, os.Args[1:], options)
		s.printOutcome(out)
		return err
	}}
	c.Flags().StringVar(&s.discover.provider, "provider", "live", "live by default; use mock for development/testing")
	c.Flags().StringArrayVar(&s.discover.targets, "target", nil, "target hostname, address, or CIDR (repeatable)")
	return c
}

func (s *state) advancedDiscoverCommand() *cobra.Command {
	c := &cobra.Command{Use: "discover", Short: "Run explicit mock or safe live discovery modules", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), s.cfg.Timeout)
		defer cancel()
		options, err := s.discoverOptions()
		if err != nil {
			return err
		}
		out, err := s.application.DiscoverWithOptions(ctx, os.Args[1:], options)
		s.printOutcome(out)
		return err
	}}
	f := c.Flags()
	f.StringVar(&s.discover.provider, "provider", "live", "live by default; use mock for development/testing")
	f.StringArrayVar(&s.discover.targets, "target", nil, "target hostname, address, or CIDR (repeatable)")
	f.StringArrayVar(&s.discover.targetFiles, "targets-file", nil, "file containing targets")
	f.StringVar(&s.discover.domain, "domain", "", "domain name hint")
	f.StringVar(&s.discover.dnsServer, "dns-server", "", "DNS resolver IP or host:port")
	f.StringVar(&s.discover.dc, "dc", "", "domain controller target")
	f.StringArrayVar(&s.discover.includeCIDRs, "include-cidr", nil, "CIDR to include (repeatable)")
	f.StringArrayVar(&s.discover.excludeHosts, "exclude-host", nil, "host or address to exclude (repeatable)")
	f.StringArrayVar(&s.discover.excludeCIDRs, "exclude-cidr", nil, "CIDR to exclude (repeatable)")
	f.IntVar(&s.discover.maxTargets, "max-targets", 0, "maximum normalized targets (default from config)")
	f.StringVar(&s.discover.ports, "ports", "", "comma-separated ports and ranges")
	f.StringVar(&s.discover.connectTimeout, "connect-timeout", "", "per-connection timeout")
	f.StringVar(&s.discover.hostTimeout, "host-timeout", "", "per-host timeout")
	f.IntVar(&s.discover.concurrency, "concurrency", 0, "global host worker limit")
	f.BoolVar(&s.discover.ldap, "ldap", false, "explicitly enable read-only LDAP discovery")
	f.StringVar(&s.discover.ldapServer, "ldap-server", "", "LDAP server hostname or address")
	f.IntVar(&s.discover.ldapPort, "ldap-port", 0, "LDAP port (default 389 or 636)")
	f.StringVar(&s.discover.ldapBaseDN, "ldap-base-dn", "", "override LDAP search base DN")
	f.StringVar(&s.discover.ldapUser, "ldap-user", "", "LDAP bind user")
	f.StringVar(&s.discover.ldapPasswordEnv, "ldap-password-env", "", "environment variable containing LDAP password")
	f.StringVar(&s.discover.ldapPasswordFile, "ldap-password-file", "", "file containing LDAP password")
	f.BoolVar(&s.discover.ldapUseTLS, "ldap-use-tls", false, "use LDAPS")
	f.BoolVar(&s.discover.ldapStartTLS, "ldap-starttls", false, "upgrade LDAP with STARTTLS")
	f.BoolVar(&s.discover.ldapInsecure, "ldap-insecure-skip-verify", false, "skip LDAP TLS verification and record this choice")
	f.BoolVar(&s.discover.ldapAnonymous, "ldap-anonymous", false, "explicitly request anonymous LDAP bind")
	f.StringArrayVar(&s.discover.managementPoints, "management-point", nil, "unconfirmed management point hint")
	f.StringArrayVar(&s.discover.distributionPoints, "distribution-point", nil, "unconfirmed distribution point hint")
	f.StringArrayVar(&s.discover.siteServers, "site-server", nil, "unconfirmed site server hint")
	f.StringArrayVar(&s.discover.sqlServers, "sql-server", nil, "unconfirmed SQL server hint")
	f.StringVar(&s.discover.siteCode, "site-code", "", "SCCM site-code hint")
	return c
}

func (s *state) discoverOptions() (app.DiscoverOptions, error) {
	d := s.discover
	if d.provider == "mock" {
		return app.DiscoverOptions{Provider: d.provider}, nil
	}
	if d.provider != "live" {
		return app.DiscoverOptions{}, fmt.Errorf("invalid provider %q (use live or mock; mock is for development/testing)", d.provider)
	}
	portsRaw := d.ports
	if portsRaw == "" {
		portsRaw = s.cfg.Discovery.Ports
	}
	ports, err := live.ParsePorts(portsRaw)
	if err != nil {
		return app.DiscoverOptions{}, err
	}
	connectRaw := d.connectTimeout
	if connectRaw == "" {
		connectRaw = s.cfg.Discovery.ConnectTimeout
	}
	connect, err := time.ParseDuration(connectRaw)
	if err != nil {
		return app.DiscoverOptions{}, fmt.Errorf("invalid connect timeout: %w", err)
	}
	hostRaw := d.hostTimeout
	if hostRaw == "" {
		hostRaw = s.cfg.Discovery.HostTimeout
	}
	host, err := time.ParseDuration(hostRaw)
	if err != nil {
		return app.DiscoverOptions{}, fmt.Errorf("invalid host timeout: %w", err)
	}
	search, err := time.ParseDuration(s.cfg.LDAP.SearchTimeout)
	if err != nil {
		return app.DiscoverOptions{}, fmt.Errorf("invalid LDAP search timeout: %w", err)
	}
	max := d.maxTargets
	if max == 0 {
		max = s.cfg.Scope.MaxExpandedTargets
	}
	concurrency := d.concurrency
	if concurrency == 0 {
		concurrency = s.cfg.Discovery.Concurrency
	}
	server := d.ldapServer
	if server == "" {
		server = d.dc
	}
	o := live.Options{Domain: d.domain, DNSServer: d.dnsServer, DC: d.dc, Ports: ports, ConnectTimeout: connect, HostTimeout: host, Concurrency: concurrency, Scope: scope.Input{Targets: d.targets, TargetFiles: d.targetFiles, IncludeCIDRs: d.includeCIDRs, ExcludeHosts: d.excludeHosts, ExcludeCIDRs: d.excludeCIDRs, Domain: d.domain, MaxTargets: max}, HTTP: live.HTTPOptions{UserAgent: s.cfg.Discovery.UserAgent, MaxBodyBytes: s.cfg.Discovery.HTTPMaxBodyBytes, MaxRedirects: s.cfg.Discovery.HTTPMaxRedirects, Timeout: host}, LDAP: live.LDAPOptions{Enabled: d.ldap, Server: server, Port: d.ldapPort, BaseDN: d.ldapBaseDN, User: d.ldapUser, PasswordEnv: d.ldapPasswordEnv, PasswordFile: d.ldapPasswordFile, UseTLS: d.ldapUseTLS, StartTLS: d.ldapStartTLS, InsecureSkipVerify: d.ldapInsecure, Anonymous: d.ldapAnonymous, PageSize: s.cfg.LDAP.PageSize, MaxEntries: s.cfg.LDAP.MaxEntries, SearchTimeout: search}, Hints: live.RoleHints{ManagementPoints: d.managementPoints, DistributionPoints: d.distributionPoints, SiteServers: d.siteServers, SQLServers: d.sqlServers, SiteCode: d.siteCode}}
	if o.LDAP.UseTLS && o.LDAP.StartTLS {
		return app.DiscoverOptions{}, fmt.Errorf("--ldap-use-tls and --ldap-starttls are mutually exclusive")
	}
	if err := live.ResolveLDAPPassword(&o.LDAP); err != nil {
		return app.DiscoverOptions{}, err
	}
	return app.DiscoverOptions{Provider: "live", Live: o}, nil
}
func (s *state) assessCommand() *cobra.Command {
	var frameworkName string
	technique := &techniqueOptions{}
	c := &cobra.Command{Use: "assess [TARGET_OR_TECHNIQUE]", Short: "Assess a target or supported technique", Long: "Assess a target or run a bounded technique. Live is the normal provider; use --provider mock only for deterministic development/testing. A technique ID selects its bounded adapter and acquires safe prerequisites directly.", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 1 {
			if strings.HasSuffix(strings.ToUpper(strings.TrimSpace(args[0])), "-ALL") && !isFrameworkTechnique(args[0]) {
				return fmt.Errorf("%q is not a framework technique or supported family selector", args[0])
			}
			if isFrameworkTechnique(args[0]) {
				return s.assessTechniqueCommand(technique).RunE(cmd, args)
			}
			return s.assessTargetPlan(args[0], technique.format)
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), s.cfg.Timeout)
		defer cancel()
		out, err := s.application.Assess(ctx, os.Args[1:])
		s.printOutcome(out)
		if frameworkName != "" {
			fmt.Fprintf(s.stdout, "Framework: %s\nTargets associated with run: %d\nActive technique validation: blocked by default\n", frameworkName, targetCount(technique.target))
			if frameworkName == "misconfiguration-manager" {
				if snapshot, snapshotErr := framework.EmbeddedSnapshot(); snapshotErr == nil {
					assessable, partial := 0, 0
					for _, coverage := range snapshot.Coverage {
						if coverage.Assessment == framework.Supported {
							assessable++
						} else if coverage.Assessment == framework.Partial {
							partial++
						}
					}
					p := framework.SnapshotProvenance(snapshot)
					fmt.Fprintf(s.stdout, "Framework: %s\nUpstream project: %s\nFramework revision: %s\nImplementation: %s\nAssessable techniques: %d\nPartially supported techniques: %d\nUnsupported validation/execution: preserved\n", p.Name, p.UpstreamRepository, p.UpstreamRevision, p.Implementation, assessable, partial)
				}
			}
		}
		return err
	}}
	c.Flags().StringVar(&frameworkName, "framework", "", "framework snapshot, for example misconfiguration-manager")
	bindTechniqueOptions(c.PersistentFlags(), technique)
	c.AddCommand(s.assessWorkflowCommand("client-policy"), s.assessWorkflowCommand("pxe"), s.assessTechniqueCommand(technique))
	return c
}

func targetCount(target string) int {
	if target == "" {
		return 0
	}
	return 1
}

func isFrameworkTechnique(value string) bool {
	value = strings.ToUpper(strings.TrimSpace(value))
	if strings.HasSuffix(value, "-ALL") {
		family := strings.TrimSuffix(value, "-ALL")
		for _, name := range framework.ProductFamilyNames() {
			if name == family {
				return true
			}
		}
		return false
	}
	snapshot, err := framework.EmbeddedSnapshot()
	if err != nil {
		return false
	}
	for _, technique := range snapshot.Techniques {
		if strings.EqualFold(technique.ID, value) {
			return true
		}
	}
	return false
}

func (s *state) assessTargetPlan(target, format string) error {
	r := canonicalResult{SchemaVersion: 1, Workflow: "assess_target", Target: redactedTarget(target), TargetID: targetID(target), Framework: "misconfiguration-manager", Status: "plan_ready_execution_requires_authorized_connector", Findings: []string{}, Blockers: []string{"no live connector was selected", "active validation remains separately gated"}, NextAction: "select a supported technique or configure an authorized connector", Network: "none", Redaction: s.outputPolicy().Metadata()}
	if format == "json" {
		return json.NewEncoder(s.stdout).Encode(r)
	}
	fmt.Fprintf(s.stdout, "Target: %s\nStatus: %s\nAssessment: safe plan only; no network activity\n", s.renderer.Target(target), s.renderer.Status(r.Status))
	return nil
}
func (s *state) reportCommand() *cobra.Command {
	return &cobra.Command{Use: "report", Short: "Generate portable JSON and HTML reports", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), s.cfg.Timeout)
		defer cancel()
		out, err := s.application.Report(ctx, os.Args[1:])
		s.printOutcome(out)
		return err
	}}
}

func (s *state) printOutcome(out app.Outcome) {
	if out.Run.ID == "" {
		return
	}
	fmt.Fprintf(s.stdout, "Run ID: %s\nProfile: %s (%s)\n", out.Run.ID, out.Run.Profile, app.ProfileNotice(config.Profile(out.Run.Profile)))
	if out.Provider != "" {
		fmt.Fprintf(s.stdout, "Provider: %s\n", out.Provider)
	}
	if out.Provider == "live" {
		d := out.Discovery
		fmt.Fprintf(s.stdout, "Scope: %d targets after %d exclusions\n\nDNS resolution\n  Resolved: %d\n  Unresolved: %d\n\nReachability\n  Reachable hosts: %d\n  Open relevant ports: %d\n  HTTP endpoints: %d\n", d.ScopeTargets, d.Excluded, d.DNSResolved, d.DNSUnresolved, d.ReachableHosts, d.OpenPorts, d.HTTPEndpoints)
		if d.LDAPBind != "" {
			fmt.Fprintf(s.stdout, "\nLDAP\n  Bind: %s\n  Default naming context: %s\n  SCCM directory objects: %d\n", d.LDAPBind, d.DefaultNamingContext, d.SCCMDirectoryObjects)
		}
		fmt.Fprintln(s.stdout, "\nLikely SCCM roles")
		for _, role := range []string{"site_server", "management_point", "distribution_point", "pxe_service_point", "sql_server", "software_update_point", "client"} {
			if d.Roles[role] > 0 {
				fmt.Fprintf(s.stdout, "  %s: %d\n", role, d.Roles[role])
			}
		}
	}
	if len(out.ModuleSummary.Executions) > 0 {
		for _, e := range out.ModuleSummary.Executions {
			switch e.Status {
			case models.ModuleExecutionSkipped:
				fmt.Fprintf(s.stdout, "SKIP %s: %s\n", e.ModuleName, e.SkipReason)
			default:
				fmt.Fprintf(s.stdout, "%s %s", e.Status, e.ModuleName)
				if e.AssetID != "" {
					fmt.Fprintf(s.stdout, " [%s]", e.AssetID)
				}
				fmt.Fprintln(s.stdout)
			}
		}
	}
	fmt.Fprintf(s.stdout, "Assets: %d\nFindings: critical=%d high=%d medium=%d low=%d informational=%d\nAttack paths: %d\nDatabase: %s\n", out.Assets, out.Findings[models.SeverityCritical], out.Findings[models.SeverityHigh], out.Findings[models.SeverityMedium], out.Findings[models.SeverityLow], out.Findings[models.SeverityInformational], out.AttackPaths, out.DatabasePath)
	if out.ReportPaths.JSON != "" {
		fmt.Fprintf(s.stdout, "JSON report: %s\nHTML report: %s\n", out.ReportPaths.JSON, out.ReportPaths.HTML)
	}
}

func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd := New(os.Stdout, os.Stderr)
	cmd.SetContext(ctx)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}
