package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Lmarkussen/CinderPath/internal/policy"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
)

func (s *state) signingKeyCommand() *cobra.Command {
	root := &cobra.Command{Use: "signing-key", Short: "Manage offline research signing keys; keys never approve live execution"}
	var out string
	var force bool
	gen := &cobra.Command{Use: "generate", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		id, e := policy.GenerateSigningKey(out, force)
		if e == nil {
			fmt.Fprintf(s.stdout, "Private key: %s\nPublic key: %s.pub\nKey ID: %s\nPrivate key contents: not displayed\n", out, out, id)
		}
		return e
	}}
	gen.Flags().StringVar(&out, "output", "", "private-key output path")
	gen.Flags().BoolVar(&force, "force", false, "replace existing keypair atomically")
	root.AddCommand(gen)
	return root
}
func (s *state) researchSetCommand() *cobra.Command {
	root := &cobra.Command{Use: "research-set", Short: "Compare reviewed captures offline; analysis never enables live SCCM execution"}
	var name, desc, out, set, bundle, label, format, trusted string
	var controlled, fixed, expected []string
	create := &cobra.Command{Use: "create", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if e := policy.CreateResearchSet(name, desc, out); e != nil {
			return e
		}
		return policy.SetResearchVariables(out, controlled, fixed)
	}}
	create.Flags().StringVar(&name, "name", "", "research-set name")
	create.Flags().StringVar(&desc, "description", "", "operator-supplied description")
	create.Flags().StringVar(&out, "output", "", "new research-set YAML")
	create.Flags().StringSliceVar(&controlled, "controlled", nil, "explicit controlled variable categories")
	create.Flags().StringSliceVar(&fixed, "fixed", nil, "explicit fixed variable categories")
	add := &cobra.Command{Use: "add", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		m := map[string]string{}
		for _, v := range expected {
			i := strings.IndexByte(v, '=')
			if i < 1 {
				return errors.New("expected variable must be NAME=VALUE")
			}
			m[v[:i]] = v[i+1:]
		}
		r, e := policy.AddResearchBundle(set, bundle, label, m, trusted)
		if e == nil {
			fmt.Fprintf(s.stdout, "Added bundle to research set: %s\nSignature state recorded; trust effect: none\nLive execution: blocked\n", r.Fingerprint)
			for _, member := range r.Members {
				if member.Label == label && member.SignatureState == "unsigned" {
					fmt.Fprintln(s.stdout, "Warning: bundle is unsigned")
				}
			}
		}
		return e
	}}
	add.Flags().StringVar(&set, "set", "", "research-set YAML")
	add.Flags().StringVar(&bundle, "bundle", "", "validated bundle reference")
	add.Flags().StringVar(&label, "label", "", "bounded member label")
	add.Flags().StringArrayVar(&expected, "expected", nil, "operator variable NAME=VALUE (stored redacted during analysis)")
	add.Flags().StringVar(&trusted, "trusted-keys", "", "optional trusted public-key directory")
	_ = add.MarkFlagRequired("set")
	_ = add.MarkFlagRequired("bundle")
	_ = add.MarkFlagRequired("label")
	analyze := &cobra.Command{Use: "analyze", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		a, e := policy.AnalyzeResearchSet(set, trusted)
		if e != nil {
			return e
		}
		if format == "json" {
			_ = s.application.PersistResearchAnalysis(cmd.Context(), "", a.ResearchSet, a, nil)
			enc := json.NewEncoder(s.stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(a)
		}
		_ = s.application.PersistResearchAnalysis(cmd.Context(), "", a.ResearchSet, a, nil)
		fmt.Fprintf(s.stdout, "Research set: %s\nComparable properties: %d\nCorrelation candidates: %d\nExcluded captures: %d\nLive SCCM policy requests: 0\nCandidate contract approval: none\n", a.ResearchSet, len(a.Comparisons), len(a.Correlations), len(a.Excluded))
		for _, p := range a.Comparisons {
			fmt.Fprintf(s.stdout, "%s: %s observed=%d/%d confidence=%s\n", p.Property, p.Classification, p.ObservedFixtures, p.TotalFixtures, p.Confidence)
		}
		return nil
	}}
	analyze.Flags().StringVar(&set, "set", "", "research-set YAML")
	analyze.Flags().StringVar(&trusted, "trusted-keys", "", "optional trusted public-key directory")
	analyze.Flags().StringVar(&format, "format", "table", "table or json")
	_ = analyze.MarkFlagRequired("set")
	root.AddCommand(create, add, analyze)
	return root
}
func (s *state) contractResearchCommand() *cobra.Command {
	root := &cobra.Command{Use: "contract", Short: "Derive and review offline candidate contracts; no live approval command exists"}
	var set, out, contract, format, reviewer, decision, notes string
	var single, force bool
	derive := &cobra.Command{Use: "derive", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		c, e := policy.DeriveCandidateContract(set, out, single)
		if e == nil {
			if a, ae := policy.AnalyzeResearchSet(set, ""); ae == nil {
				_ = s.application.PersistResearchAnalysis(cmd.Context(), "", a.ResearchSet, a, &c)
			}
			fmt.Fprintf(s.stdout, "Candidate contract derived: %s\nState: candidate_contract\nLive execution allowed: false\n", c.ID)
		}
		return e
	}}
	derive.Flags().StringVar(&set, "research-set", "", "research-set YAML")
	derive.Flags().StringVar(&out, "output", "", "new candidate-contract YAML")
	derive.Flags().BoolVar(&single, "single-fixture-research", false, "allow explicitly low-confidence single-fixture derivation")
	_ = derive.MarkFlagRequired("research-set")
	dossier := &cobra.Command{Use: "dossier", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		b, e := os.ReadFile(contract)
		if e != nil {
			return e
		}
		var c policy.CandidateContract
		if e = yaml.Unmarshal(b, &c); e != nil {
			return e
		}
		a, e := policy.AnalyzeResearchSet(set, "")
		if e != nil {
			return e
		}
		if e = policy.CreateDossier(c, a, out, force); e == nil {
			fmt.Fprintf(s.stdout, "Created contract dossier: %s\nLive SCCM execution is not approved.\nThis dossier is research evidence, not authorization.\n", filepath.Base(out))
		}
		return e
	}}
	dossier.Flags().StringVar(&contract, "contract", "", "candidate-contract YAML")
	dossier.Flags().StringVar(&set, "research-set", "", "source research-set YAML")
	dossier.Flags().StringVar(&out, "output", "", "new dossier directory")
	dossier.Flags().BoolVar(&force, "force", false, "replace existing dossier")
	_ = dossier.MarkFlagRequired("contract")
	_ = dossier.MarkFlagRequired("research-set")
	review := &cobra.Command{Use: "review", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		r := policy.SafetyReview{ContractID: contract, ReviewerReference: reviewer, Decision: decision, NotesRedacted: notes}
		if e := policy.SaveSafetyReview(out, r); e != nil {
			return e
		}
		if b, e := os.ReadFile(out); e == nil && yaml.Unmarshal(b, &r) == nil {
			_ = s.application.PersistSafetyReview(cmd.Context(), "", r)
		}
		fmt.Fprintln(s.stdout, "Safety review recorded. Execution permissions unchanged; live approval: none.")
		return nil
	}}
	review.Flags().StringVar(&contract, "contract", "", "candidate contract ID/reference")
	review.Flags().StringVar(&reviewer, "reviewer-reference", "", "bounded operator label")
	review.Flags().StringVar(&decision, "decision", "needs_more_evidence", "not_reviewed, needs_more_evidence, rejected, candidate_read_only, or approved_for_local_replay")
	review.Flags().StringVar(&notes, "notes-redacted", "", "bounded redacted notes")
	review.Flags().StringVar(&out, "output", "", "new safety-review YAML")
	_ = review.MarkFlagRequired("contract")
	_ = format
	root.AddCommand(derive, dossier, review)
	return root
}
func (s *state) researchViewCommand(kind string) *cobra.Command {
	var set, format string
	c := &cobra.Command{Use: kind, Short: "Show redacted offline " + kind, Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		a, e := policy.AnalyzeResearchSet(set, "")
		if e != nil {
			return e
		}
		var v any = a.Correlations
		if kind == "sequences" {
			v = a.Sequences
		}
		if format == "json" {
			enc := json.NewEncoder(s.stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(v)
		}
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Fprintln(s.stdout, string(b))
		fmt.Fprintln(s.stdout, "Live SCCM policy requests: 0")
		return nil
	}}
	c.Flags().StringVar(&set, "research-set", "", "research-set YAML")
	c.Flags().StringVar(&format, "format", "table", "table or json")
	_ = c.MarkFlagRequired("research-set")
	return c
}
