package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lmarkussen/CinderPath/internal/policy"
	"github.com/spf13/cobra"
)

func (s *state) contractRoot() string {
	return filepath.Join(filepath.Dir(s.cfg.DBPath), ".cinderpath", "protocol-contracts")
}

func (s *state) protocolCommand() *cobra.Command {
	root := &cobra.Command{Use: "protocol", Short: "Import and analyze sanitized SCCM protocol fixtures (offline only)"}
	var dir, request, response, metadata string
	imp := &cobra.Command{Use: "import", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if dir == "" {
			if metadata == "" || request == "" || response == "" {
				return errors.New("use --directory or request, response, and metadata files")
			}
			dir = filepath.Dir(metadata)
		}
		f, c, e := policy.ImportDirectory(dir)
		if e != nil {
			return e
		}
		if e = policy.SaveContract(s.contractRoot(), c); e != nil {
			return e
		}
		fmt.Fprintf(s.stdout, "Imported fixture: %s\nContract: %s\nState: %s\nLive execution: blocked\n", f.ID, c.ID, c.VerificationState)
		return nil
	}}
	imp.Flags().StringVar(&dir, "directory", "", "fixture directory")
	imp.Flags().StringVar(&request, "request", "", "request body fixture")
	imp.Flags().StringVar(&response, "response", "", "response body fixture")
	imp.Flags().StringVar(&metadata, "metadata", "", "capture metadata")
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		cs, e := policy.ListContracts(s.contractRoot())
		for _, c := range cs {
			fmt.Fprintf(s.stdout, "%s %s %s %s %s\n", c.ID, c.VerificationState, c.Method.Value, c.Path.Value, c.Name)
		}
		return e
	}}
	show := &cobra.Command{Use: "show CONTRACT-ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, a []string) error {
		c, e := policy.LoadContract(s.contractRoot(), a[0])
		if e != nil {
			return e
		}
		b, _ := json.MarshalIndent(c, "", "  ")
		fmt.Fprintln(s.stdout, string(b))
		return nil
	}}
	validate := &cobra.Command{Use: "validate CONTRACT-ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, a []string) error {
		c, e := policy.LoadContract(s.contractRoot(), a[0])
		if e != nil {
			return e
		}
		if c.Method.Value == "" || c.Path.Value == "" {
			return errors.New("contract lacks observed exact method or path")
		}
		fmt.Fprintf(s.stdout, "Contract valid for fixtures\nState: %s\nLive execution: blocked\n", c.VerificationState)
		return nil
	}}
	var analysisDirs []string
	analyze := &cobra.Command{Use: "analyze", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		var fixtures []policy.Fixture
		for _, d := range analysisDirs {
			f, _, e := policy.ImportDirectory(d)
			if e != nil {
				return e
			}
			fixtures = append(fixtures, f)
		}
		a := policy.Analyze(fixtures)
		fmt.Fprintf(s.stdout, "Policy protocol analysis\n\nRoute: %s %s\nState: %s\n", a.Method, a.Route, a.State)
		for _, o := range a.Observations {
			fmt.Fprintf(s.stdout, "%s: %s (%s)\n", o.Presence, o.Label, strings.Join(o.Values, ", "))
		}
		fmt.Fprintln(s.stdout, "\nUnknown:")
		for _, u := range a.Unknown {
			fmt.Fprintf(s.stdout, "  %s\n", u)
		}
		fmt.Fprintln(s.stdout, "\nLive execution: blocked")
		return nil
	}}
	analyze.Flags().StringArrayVar(&analysisDirs, "directory", nil, "fixture directory (repeatable)")
	_ = analyze.MarkFlagRequired("directory")
	var endpoint, fixtureDir string
	replay := &cobra.Command{Use: "replay CONTRACT-ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, a []string) error {
		c, e := policy.LoadContract(s.contractRoot(), a[0])
		if e != nil {
			return e
		}
		f, _, e := policy.ImportDirectory(fixtureDir)
		if e != nil {
			return e
		}
		b, e := policy.Replay(cmd.Context(), c, f, endpoint)
		if e != nil {
			return e
		}
		fmt.Fprintf(s.stdout, "Local replay completed: %d response bytes\nLive execution: blocked\n", len(b))
		return nil
	}}
	replay.Flags().StringVar(&endpoint, "endpoint", "", "loopback fixture server endpoint")
	replay.Flags().StringVar(&fixtureDir, "directory", "", "fixture directory")
	_ = replay.MarkFlagRequired("endpoint")
	_ = replay.MarkFlagRequired("directory")
	var in, out string
	sanitize := &cobra.Command{Use: "sanitize", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return policy.Sanitize(in, out) }}
	sanitize.Flags().StringVar(&in, "input", "", "source capture directory")
	sanitize.Flags().StringVar(&out, "output", "", "new sanitized fixture directory")
	_ = sanitize.MarkFlagRequired("input")
	_ = sanitize.MarkFlagRequired("output")
	root.AddCommand(imp, list, show, validate, analyze, replay, sanitize)
	return root
}

func (s *state) clientIdentityCommand() *cobra.Command {
	root := &cobra.Command{Use: "client-identity", Short: "Import existing SCCM client identity metadata without registration"}
	var metadata string
	imp := &cobra.Command{Use: "import", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		b, e := os.ReadFile(metadata)
		if e != nil {
			return e
		}
		id, e := policy.ParseClientIdentity(b)
		if e != nil {
			return e
		}
		safe := struct {
			Kind, ClientID, SiteCode, ManagementPoint, CertificateReference, SourceType string
			Verified                                                                    bool
		}{id.Kind, id.ClientID, id.SiteCode, id.ManagementPoint, filepath.Base(id.Certificate.Reference), id.Source.Type, id.Source.Verified}
		data, _ := json.MarshalIndent(safe, "", "  ")
		path := filepath.Join(filepath.Dir(s.cfg.DBPath), ".cinderpath", "client-identities", strings.ReplaceAll(id.ClientID, ":", "_")+".json")
		if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			return e
		}
		if e = os.WriteFile(path, data, 0600); e != nil {
			return e
		}
		fmt.Fprintf(s.stdout, "Imported existing client identity metadata: %s\nNetwork validation: not performed\nRegistration status: unknown\n", id.ClientID)
		return nil
	}}
	imp.Flags().StringVar(&metadata, "metadata", "", "existing client identity metadata YAML")
	_ = imp.MarkFlagRequired("metadata")
	root.AddCommand(imp)
	return root
}

func (s *state) policyCommand() *cobra.Command {
	root := &cobra.Command{Use: "policy", Short: "Parse and classify SCCM policy fixtures offline"}
	var dir, out, format string
	var show, hide bool
	analyze := func(ctx context.Context) ([]policy.Candidate, error) {
		f, _, e := policy.ImportDirectory(dir)
		if e != nil {
			return nil, e
		}
		as, ae := policy.ParseAssignments(ctx, f.ResponseBody, f.ID)
		if ae == nil {
			fmt.Fprintf(s.stdout, "Assignments parsed: %d\n", len(as))
		}
		p, c, e := policy.ParsePolicy(ctx, f.ResponseBody)
		if e != nil {
			return nil, e
		}
		for i := range c {
			c[i].SourceFixture = f.ID
		}
		fmt.Fprintf(s.stdout, "Policy parsed: %s\nCandidates: %d\nLive target validation: not performed\n", p.PolicyID, len(c))
		return c, nil
	}
	parse := &cobra.Command{Use: "parse", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { _, e := analyze(cmd.Context()); return e }}
	secrets := &cobra.Command{Use: "secrets", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		c, e := analyze(cmd.Context())
		if e != nil {
			return e
		}
		_, e = policy.OutputSecrets(s.stdout, c, policy.SecretOptions{Show: show, Hide: hide, Interactive: isTerminalWriter(s.stdout), Profile: string(s.cfg.Profile), Path: out, Format: format})
		return e
	}}
	for _, c := range []*cobra.Command{parse, secrets} {
		c.Flags().StringVar(&dir, "directory", "", "synthetic or sanitized fixture directory")
		_ = c.MarkFlagRequired("directory")
	}
	secrets.Flags().BoolVar(&show, "show-secrets", false, "deliberately show confirmed plaintext")
	secrets.Flags().BoolVar(&hide, "hide-secrets", false, "suppress plaintext terminal output")
	secrets.Flags().StringVar(&out, "secrets-output", "", "dedicated secure output file")
	secrets.Flags().StringVar(&format, "secrets-format", "text", "text or json")
	root.AddCommand(parse, secrets)
	return root
}
func isTerminalWriter(w any) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, e := f.Stat()
	return e == nil && st.Mode()&os.ModeCharDevice != 0
}
