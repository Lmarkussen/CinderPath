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
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(r)
		}
		printFrameworkCoverage(s.stdout, r)
		return nil
	}}
	c.Flags().StringVar(&name, "framework", "misconfiguration-manager", "framework identifier")
	c.Flags().StringVar(&format, "format", "text", "text or json")
	return c
}

func printFrameworkCoverage(out io.Writer, r framework.FrameworkSnapshot) {
	att, def := 0, 0
	families := map[string]int{}
	support := map[string]int{}
	for _, t := range r.Techniques {
		families[t.Family]++
		if t.Kind == "attack" {
			att++
		} else {
			def++
		}
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
	fmt.Fprintf(out, "Framework coverage: %s\nUpstream revision: %s\nSnapshot date: %s\nAttack techniques: %d\nDefense techniques: %d\nMatrix mappings: %d\nFamilies: %s\nPrerequisites supported/partial: %d\nDiscovery supported/partial: %d\nAssessment supported/partial: %d\nValidation supported/partial: %d\nExecution supported/partial: %d\nLab-validated: %d\n", r.FrameworkID, r.UpstreamRevision, r.SnapshotDate, att, def, len(r.MatrixMappings), formatFamilies(families), support["prerequisites"], support["discovery"], support["assessment"], support["validation"], support["execution"], support["lab"])
	if len(r.Warnings) > 0 {
		fmt.Fprintf(out, "Warnings: %s\n", strings.Join(r.Warnings, "; "))
	}
	fmt.Fprintln(out, "Legacy objective mapping: policy_secrets_naa -> CRED-1; pxe_dp_assessment -> RECON-1")
	fmt.Fprintln(out, "Planning metadata only: unsupported validation and execution remain blocked.")
	fmt.Fprintln(out, "Safety: offline snapshot and planning metadata only; no technique execution.")
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
		for _, t := range r.Techniques {
			if t.ID == strings.ToUpper(args[0]) {
				if format == "json" {
					return json.NewEncoder(s.stdout).Encode(t)
				}
				fmt.Fprintf(s.stdout, "%s: %s\nFamily: %s\nKind: %s\nSummary: %s\nSource: %s\n", t.ID, t.Title, t.Family, t.Kind, t.Summary, strings.Join(t.SourceFiles, ", "))
				for _, m := range r.MatrixMappings {
					if m.AttackID == t.ID {
						fmt.Fprintf(s.stdout, "Defense mapping: %s\n", m.DefenseID)
					}
				}
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
			return json.NewEncoder(s.stdout).Encode(xs)
		}
		fmt.Fprintf(s.stdout, "Family %s (%d techniques)\n", fam, len(xs))
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
		for _, c := range r.Coverage {
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
