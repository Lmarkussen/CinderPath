package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/policy"
	"github.com/Lmarkussen/CinderPath/internal/version"
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
	var in, out, binaryMode, replacementMap string
	var replacementLiterals []string
	sanitize := &cobra.Command{Use: "sanitize", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		repls := []policy.Replacement{}
		if replacementMap != "" {
			x, e := policy.LoadReplacementMap(replacementMap)
			if e != nil {
				return e
			}
			repls = append(repls, x...)
		}
		for _, v := range replacementLiterals {
			i := strings.IndexByte(v, '=')
			if i < 1 {
				return errors.New("replacement literal must be ORIGINAL=REPLACEMENT")
			}
			repls = append(repls, policy.Replacement{Original: v[:i], Replacement: v[i+1:], Category: "operator_literal"})
		}
		m, e := policy.SanitizeDirectory(policy.SanitizeOptions{Input: in, Output: out, BinaryMode: policy.BinaryMode(binaryMode), Replacements: repls})
		if e == nil {
			if db, openErr := database.Open(context.Background(), s.cfg.DBPath); openErr == nil {
				raw, _ := json.Marshal(m)
				var data map[string]any
				_ = json.Unmarshal(raw, &data)
				_ = db.UpsertPolicyRecord(context.Background(), "sanitization_manifests", database.PolicyRecord{ID: m.ManifestID, Fingerprint: m.OutputFingerprint, Data: data})
				_ = db.Close()
			}
			fmt.Fprintf(s.stdout, "Sanitization manifest: %s\nBinary mode: %s\nBodies sanitized: %d\nBodies untouched: %d\nManual review required: %t\n", m.ManifestID, m.BinaryMode, m.BodiesSanitized, m.BodiesUntouched, m.ManualReviewRequired)
		}
		return e
	}}
	sanitize.Flags().StringVar(&in, "input", "", "source capture directory")
	sanitize.Flags().StringVar(&out, "output", "", "new sanitized fixture directory")
	sanitize.Flags().StringVar(&binaryMode, "binary-mode", string(policy.BinaryMetadataOnly), "metadata_only, text_regions, or structured_known")
	sanitize.Flags().StringArrayVar(&replacementLiterals, "replace-literal", nil, "length-preserving ORIGINAL=REPLACEMENT")
	sanitize.Flags().StringVar(&replacementMap, "replacement-map", "", "mode-0600 YAML replacement map")
	_ = sanitize.MarkFlagRequired("input")
	_ = sanitize.MarkFlagRequired("output")
	var inspectFormat string
	var maxBytes int64
	inspect := &cobra.Command{Use: "inspect-binary FILE", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, a []string) error {
		if maxBytes < 1 || maxBytes > 64<<20 {
			return errors.New("max-bytes must be between 1 and 67108864")
		}
		f, e := os.Open(a[0])
		if e != nil {
			return e
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, maxBytes+1))
		if int64(len(b)) > maxBytes {
			return errors.New("binary input exceeds --max-bytes")
		}
		if e != nil {
			return e
		}
		x, e := policy.InspectBinary(b)
		if e != nil {
			return e
		}
		if inspectFormat == "json" {
			enc := json.NewEncoder(s.stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(x)
		}
		if inspectFormat != "table" && inspectFormat != "text" {
			return errors.New("format must be table, text, or json")
		}
		fmt.Fprintf(s.stdout, "Binary framing analysis\n\nSize: %d bytes\nSHA-256: %s\nEntropy: %.2f\nPrintable ratio: %.2f\nObservations:\n", x.Size, x.SHA256, x.Entropy, x.PrintableRatio)
		for _, o := range x.Observations {
			fmt.Fprintf(s.stdout, "  %-9s offset=%d length=%d encoding=%s confidence=%.2f %s\n", o.Classification, o.Offset, o.Length, o.Encoding, o.Confidence, o.Description)
		}
		fmt.Fprintln(s.stdout, "Unknown:")
		for _, u := range x.Unknown {
			fmt.Fprintf(s.stdout, "  %s\n", u)
		}
		return nil
	}}
	inspect.Flags().StringVar(&inspectFormat, "format", "table", "table or json")
	inspect.Flags().Int64Var(&maxBytes, "max-bytes", policy.MaxBinaryBytes, "maximum bytes to inspect")
	var listen, serveFormat string
	var requestTimeout, idleTimeout time.Duration
	var strict, once bool
	serve := &cobra.Command{Use: "serve-fixtures", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		f, _, e := policy.ImportDirectory(dir)
		if e != nil {
			return e
		}
		endpoint, done, e := policy.ServeFixture(cmd.Context(), f, policy.ServerOptions{Listen: listen, Strict: strict, Once: once, RequestTimeout: requestTimeout, IdleTimeout: idleTimeout})
		if e != nil {
			return e
		}
		if serveFormat == "json" {
			_ = json.NewEncoder(s.stdout).Encode(map[string]any{"endpoint": endpoint, "loopback_only": true, "fixture_id": f.ID})
		} else {
			fmt.Fprintf(s.stdout, "Loopback fixture server only.\nNo live SCCM target will be contacted.\nEndpoint: %s\n", endpoint)
		}
		if once {
			return <-done
		}
		<-cmd.Context().Done()
		return nil
	}}
	serve.Flags().StringVar(&dir, "directory", "", "exact fixture directory")
	serve.Flags().StringVar(&listen, "listen", "127.0.0.1:0", "loopback listen address")
	serve.Flags().BoolVar(&strict, "strict", false, "require exact fixture request body")
	serve.Flags().BoolVar(&once, "once", false, "stop after one matching response")
	serve.Flags().DurationVar(&requestTimeout, "request-timeout", 10*time.Second, "bounded request timeout")
	serve.Flags().DurationVar(&idleTimeout, "idle-timeout", 30*time.Second, "idle connection timeout")
	serve.Flags().StringVar(&serveFormat, "format", "table", "table or json startup output")
	_ = serve.MarkFlagRequired("directory")
	var reviewDir, reviewRef string
	var approveBodies []string
	review := &cobra.Command{Use: "review-sanitization", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		m, e := policy.ReviewSanitization(reviewDir, approveBodies, reviewRef)
		if e == nil {
			if db, openErr := database.Open(context.Background(), s.cfg.DBPath); openErr == nil {
				raw, _ := json.Marshal(m)
				var data map[string]any
				_ = json.Unmarshal(raw, &data)
				_ = db.UpsertPolicyRecord(context.Background(), "sanitization_manifests", database.PolicyRecord{ID: m.ManifestID, Fingerprint: m.OutputFingerprint, Data: data})
				_ = db.Close()
			}
			fmt.Fprintf(s.stdout, "Review recorded: %s\nManual review complete: %t\nLive contract promotion: no\n", m.ManifestID, m.ManualReviewCompleted)
		}
		return e
	}}
	review.Flags().StringVar(&reviewDir, "directory", "", "sanitized fixture directory")
	review.Flags().StringArrayVar(&approveBodies, "approve-body", nil, "body filename to record as reviewed")
	review.Flags().StringVar(&reviewRef, "reviewer-reference", "", "bounded operator-selected review reference")
	_ = review.MarkFlagRequired("directory")
	_ = review.MarkFlagRequired("reviewer-reference")
	bundle := s.bundleCommand()
	root.AddCommand(imp, list, show, validate, analyze, replay, sanitize, review, inspect, serve, bundle)
	return root
}

func (s *state) bundleCommand() *cobra.Command {
	root := &cobra.Command{Use: "bundle", Short: "Export, inspect, and import sanitized offline research bundles"}
	var contractID, input, output string
	var dirs []string
	ex := &cobra.Command{Use: "export", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		c, e := policy.LoadContract(s.contractRoot(), contractID)
		if e != nil {
			return e
		}
		m, e := policy.ExportBundle(policy.BundleExportOptions{Contract: c, FixtureDirectories: dirs, Output: output, ToolVersion: version.Current().Version})
		if e == nil {
			fmt.Fprintf(s.stdout, "Exported offline bundle: %s\nFixtures: %d\nLive execution: blocked\n", m.BundleID, len(m.FixtureIDs))
		}
		return e
	}}
	ex.Flags().StringVar(&contractID, "contract", "", "fixture-only contract ID")
	ex.Flags().StringArrayVar(&dirs, "directory", nil, "reviewed fixture directory (repeatable)")
	ex.Flags().StringVar(&output, "output", "", "new .tar.gz output")
	_ = ex.MarkFlagRequired("contract")
	_ = ex.MarkFlagRequired("directory")
	_ = ex.MarkFlagRequired("output")
	inspect := &cobra.Command{Use: "inspect", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		i, e := policy.InspectBundle(input)
		if e != nil {
			return e
		}
		b, _ := json.MarshalIndent(i, "", "  ")
		fmt.Fprintln(s.stdout, string(b))
		fmt.Fprintln(s.stdout, "Live execution: blocked")
		return nil
	}}
	inspect.Flags().StringVar(&input, "input", "", "bundle archive")
	_ = inspect.MarkFlagRequired("input")
	imp := &cobra.Command{Use: "import", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		i, e := policy.ImportBundle(input, filepath.Join(filepath.Dir(s.cfg.DBPath), ".cinderpath", "bundles"))
		if e == nil {
			fmt.Fprintf(s.stdout, "Imported offline bundle: %s\nTrust: fixture_only or captured_unverified\nLive execution: blocked\n", i.Manifest.BundleID)
		}
		return e
	}}
	imp.Flags().StringVar(&input, "input", "", "bundle archive")
	_ = imp.MarkFlagRequired("input")
	root.AddCommand(ex, inspect, imp)
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
	for _, spec := range []struct{ name, table string }{{"fixtures", "protocol_fixtures"}, {"assignments", "policy_assignments"}, {"documents", "policy_documents"}, {"candidates", "policy_candidates"}} {
		root.AddCommand(s.policyInventoryCommand(spec.name, spec.table))
	}
	root.AddCommand(parse, secrets)
	return root
}
func (s *state) policyInventoryCommand(name, table string) *cobra.Command {
	var runID, fixtureID, policyID, contractID, state, format string
	var limit int
	c := &cobra.Command{Use: name, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		db, e := database.Open(cmd.Context(), s.cfg.DBPath)
		if e != nil {
			return e
		}
		defer db.Close()
		rows, e := db.ListPolicyRecords(cmd.Context(), table)
		if e != nil {
			return e
		}
		filtered := make([]database.PolicyRecord, 0)
		match := func(v any, want string) bool { return want == "" || fmt.Sprint(v) == want }
		for _, r := range rows {
			if runID != "" && r.RunID != runID {
				continue
			}
			if !match(r.Data["fixture_id"], fixtureID) && r.ID != fixtureID {
				continue
			}
			if !match(r.Data["policy_id"], policyID) {
				continue
			}
			if !match(r.Data["contract_id"], contractID) {
				continue
			}
			if !match(r.Data["state"], state) {
				continue
			}
			filtered = append(filtered, r)
			if len(filtered) >= limit {
				break
			}
		}
		if format == "json" {
			enc := json.NewEncoder(s.stdout)
			enc.SetIndent("", "  ")
			if e = enc.Encode(filtered); e != nil {
				return e
			}
		} else if format == "table" {
			for _, r := range filtered {
				fmt.Fprintf(s.stdout, "%s run=%s fixture=%v policy=%v state=%v source=offline_fixture\n", r.ID, r.RunID, r.Data["fixture_id"], r.Data["policy_id"], r.Data["state"])
			}
			fmt.Fprintln(s.stdout, "Live target validation: not performed")
		} else {
			return errors.New("format must be table or json")
		}
		return nil
	}}
	f := c.Flags()
	f.StringVar(&runID, "run-id", "", "filter by run ID")
	f.StringVar(&fixtureID, "fixture-id", "", "filter by fixture ID")
	f.StringVar(&policyID, "policy-id", "", "filter by policy ID")
	f.StringVar(&contractID, "contract-id", "", "filter by contract ID")
	f.StringVar(&state, "state", "", "filter by state")
	f.StringVar(&format, "format", "table", "table or json")
	f.IntVar(&limit, "limit", 500, "maximum records (1-5000)")
	c.PreRunE = func(*cobra.Command, []string) error {
		if limit < 1 || limit > 5000 {
			return errors.New("limit must be between 1 and 5000")
		}
		return nil
	}
	return c
}
func isTerminalWriter(w any) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, e := f.Stat()
	return e == nil && st.Mode()&os.ModeCharDevice != 0
}
