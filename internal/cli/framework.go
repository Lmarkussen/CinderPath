package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Lmarkussen/CinderPath/internal/framework"
	"github.com/spf13/cobra"
)

func (s *state) frameworkCommand() *cobra.Command {
	root := &cobra.Command{Use: "framework", Short: "Show offline framework coverage and planning"}
	root.AddCommand(s.frameworkCoverageCommand(), s.frameworkTechniqueCommand(), s.frameworkFamilyCommand(), s.frameworkGapsCommand())
	return root
}

func (s *state) loadFramework() (framework.FrameworkSnapshot, error) {
	return framework.EmbeddedSnapshot()
}
func (s *state) frameworkCoverageCommand() *cobra.Command {
	var name, format string
	c := &cobra.Command{Use: "coverage", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if name != "misconfiguration-manager" {
			return fmt.Errorf("unsupported framework %q", name)
		}
		r, err := s.loadFramework()
		if err != nil {
			return err
		}
		visible := framework.ProductSnapshot(r)
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(map[string]any{"framework": framework.SnapshotProvenance(r), "snapshot": visible, "product_scope": framework.ProductFamilyNames()})
		}
		printFrameworkCoverage(s.stdout, visible, s.verbose)
		return nil
	}}
	c.Flags().StringVar(&name, "framework", "misconfiguration-manager", "framework identifier")
	c.Flags().StringVar(&format, "format", "text", "text or json")
	return c
}

func printFrameworkCoverage(out io.Writer, r framework.FrameworkSnapshot, verbose bool) {
	att := 0
	families := map[string]int{}
	support := map[string]int{}
	for _, t := range r.Techniques {
		families[t.Family]++
		att++
	}
	for _, c := range r.Coverage {
		if c.Prerequisites == framework.Supported || c.Prerequisites == framework.Partial {
			support["prerequisites"]++
		}
		if c.Discovery == framework.Supported || c.Discovery == framework.Partial {
			support["discovery"]++
		}
		if c.Assessment == framework.Supported || c.Assessment == framework.Partial {
			support["assessment"]++
		}
		if c.Validation == framework.Supported || c.Validation == framework.Partial {
			support["validation"]++
		}
		if c.Execution == framework.Supported || c.Execution == framework.Partial {
			support["execution"]++
		}
		if c.LabValidation == framework.Supported || c.LabValidation == framework.Partial {
			support["lab"]++
		}
	}
	p := framework.SnapshotProvenance(r)
	fmt.Fprintf(out, "Framework coverage: %s\n\n", r.FrameworkID)
	fmt.Fprintf(out, "Framework: %s\nUpstream project: %s\nUpstream revision: %s\nSnapshot date: %s\nImplementation: %s\n\n", p.Name, p.UpstreamRepository, p.UpstreamRevision, r.SnapshotDate, p.Implementation)
	fmt.Fprintf(out, "Product techniques\n  %d total attack techniques\n  Families: %s\n\n", att, formatFamilies(families))
	fmt.Fprintf(out, "Support (supported or partial)\n  Prerequisites: %d\n  Discovery:     %d\n  Assessment:   %d\n  Validation:   %d\n  Execution:    %d\n  Lab-validated: %d\n\n", support["prerequisites"], support["discovery"], support["assessment"], support["validation"], support["execution"], support["lab"])
	fmt.Fprintln(out, "Notes")
	fmt.Fprintln(out, "  CinderPath product scope: CRED, ELEVATE, EXEC, RECON, TAKEOVER, COERCE.")
	fmt.Fprintln(out, "  Planning metadata only; unsupported validation and execution remain blocked.")
	fmt.Fprintln(out, "  Safety: offline snapshot and planning metadata only; no technique execution.")
	fmt.Fprintln(out, "  Legacy mappings: policy_secrets_naa -> CRED-1; pxe_dp_assessment -> RECON-1")
	if len(r.Warnings) > 0 {
		fmt.Fprintf(out, "  Import warnings: %d (use --verbose to list)\n", len(r.Warnings))
		if verbose {
			fmt.Fprintln(out, "\nImport warnings")
			for _, warning := range r.Warnings {
				fmt.Fprintf(out, "  - %s\n", warning)
			}
		}
	}
}
func formatFamilies(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var p []string
	for _, k := range keys {
		p = append(p, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(p, ", ")
}

func (s *state) frameworkTechniqueCommand() *cobra.Command {
	var format string
	c := &cobra.Command{Use: "technique TECHNIQUE-ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		r, e := s.loadFramework()
		if e != nil {
			return e
		}
		if !framework.IsProductTechnique(args[0]) {
			return fmt.Errorf("technique %q is out of scope: CinderPath supports attack families %s", args[0], strings.Join(framework.ProductFamilyNames(), ", "))
		}
		for _, t := range r.Techniques {
			if t.ID == strings.ToUpper(args[0]) {
				if format == "json" {
					return json.NewEncoder(s.stdout).Encode(map[string]any{"framework": framework.SnapshotProvenance(r), "technique": t})
				}
				p := framework.SnapshotProvenance(r)
				fmt.Fprintf(s.stdout, "%s: %s\nFramework: %s\nUpstream project: %s\nUpstream revision: %s\nImplementation: %s\nFamily: %s\nKind: %s\nSummary: %s\nSource: %s\n", t.ID, t.Title, p.Name, p.UpstreamRepository, p.UpstreamRevision, p.Implementation, t.Family, t.Kind, t.Summary, strings.Join(t.SourceFiles, ", "))
				for _, c := range r.Coverage {
					if c.TechniqueID == t.ID {
						fmt.Fprintf(s.stdout, "Support: prerequisites=%s discovery=%s assessment=%s validation=%s execution=%s lab=%s\nReason: %s\n", c.Prerequisites, c.Discovery, c.Assessment, c.Validation, c.Execution, c.LabValidation, c.Reason)
						if len(c.Limitations) > 0 {
							fmt.Fprintf(s.stdout, "Limitations: %s\n", strings.Join(c.Limitations, "; "))
						}
					}
				}
				return nil
			}
		}
		return fmt.Errorf("unknown technique %q", args[0])
	}}
	c.Flags().StringVar(&format, "format", "text", "text or json")
	return c
}
func (s *state) frameworkFamilyCommand() *cobra.Command {
	var format string
	c := &cobra.Command{Use: "family FAMILY", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		r, e := s.loadFramework()
		if e != nil {
			return e
		}
		fam := strings.ToUpper(args[0])
		if !framework.IsProductAttackFamily(fam) {
			return fmt.Errorf("family %q is out of scope: CinderPath supports attack families %s", args[0], strings.Join(framework.ProductFamilyNames(), ", "))
		}
		var xs []framework.Technique
		for _, t := range r.Techniques {
			if t.Family == fam {
				xs = append(xs, t)
			}
		}
		if len(xs) == 0 {
			return fmt.Errorf("unknown or empty family %q", args[0])
		}
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(map[string]any{"framework": framework.SnapshotProvenance(r), "family": fam, "techniques": xs})
		}
		p := framework.SnapshotProvenance(r)
		fmt.Fprintf(s.stdout, "Framework: %s\nUpstream project: %s\nUpstream revision: %s\nImplementation: %s\nFamily %s (%d techniques)\n", p.Name, p.UpstreamRepository, p.UpstreamRevision, p.Implementation, fam, len(xs))
		for _, t := range xs {
			fmt.Fprintf(s.stdout, "%s %s (%s)\n", t.ID, t.Title, t.Kind)
		}
		return nil
	}}
	c.Flags().StringVar(&format, "format", "text", "text or json")
	return c
}
func (s *state) frameworkGapsCommand() *cobra.Command {
	return &cobra.Command{Use: "gaps", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		r, e := s.loadFramework()
		if e != nil {
			return e
		}
		fmt.Fprintln(s.stdout, "Largest framework gaps")
		for _, c := range framework.ProductSnapshot(r).Coverage {
			if c.Assessment == framework.Unsupported || c.Assessment == framework.Planned || c.Execution == framework.Unsupported {
				fmt.Fprintf(s.stdout, "%s assessment=%s execution=%s\n", c.TechniqueID, c.Assessment, c.Execution)
			}
		}
		return nil
	}}
}

func (s *state) researchFrameworkCommand() *cobra.Command {
	root := &cobra.Command{Use: "framework", Short: "Import or validate an offline framework snapshot"}
	var importSource, importRevision, importDate, importOutput string
	imp := &cobra.Command{Use: "import", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		r, e := framework.Import(framework.ImportOptions{Source: importSource, Revision: importRevision, SnapshotDate: importDate})
		if e != nil {
			return e
		}
		if err := framework.SaveSnapshot(importOutput, r); err != nil {
			return err
		}
		fmt.Fprintf(s.stdout, "Imported %d techniques and %d matrix mappings\nSnapshot: %s\nFingerprint: %s\nWarnings: %s\n", len(r.Techniques), len(r.MatrixMappings), importOutput, framework.SnapshotFingerprint(r), strings.Join(r.Warnings, "; "))
		return nil
	}}
	imp.Flags().StringVar(&importSource, "source", "", "local Misconfiguration-Manager export")
	imp.Flags().StringVar(&importRevision, "revision", "", "upstream revision")
	imp.Flags().StringVar(&importDate, "snapshot-date", "", "snapshot date")
	imp.Flags().StringVar(&importOutput, "output", "internal/framework/data/misconfiguration-manager.json", "snapshot output")
	_ = imp.MarkFlagRequired("source")
	var validatePath string
	val := &cobra.Command{Use: "validate", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		r, e := framework.LoadSnapshot(validatePath)
		if e != nil {
			return e
		}
		fmt.Fprintf(s.stdout, "Valid snapshot: %s\nTechniques: %d\nMatrix mappings: %d\nFingerprint: %s\n", validatePath, len(r.Techniques), len(r.MatrixMappings), framework.SnapshotFingerprint(r))
		return nil
	}}
	val.Flags().StringVar(&validatePath, "snapshot", "internal/framework/data/misconfiguration-manager.json", "snapshot path")
	_ = val.MarkFlagRequired("snapshot")
	root.AddCommand(imp, val)
	return root
}
