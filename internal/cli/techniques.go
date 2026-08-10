package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Lmarkussen/CinderPath/internal/framework"
	"github.com/Lmarkussen/CinderPath/internal/planner"
	"github.com/spf13/cobra"
)

// techniquesCommand is deliberately backed by the embedded framework
// snapshot and planner metadata. There is no second help-only registry.
func (s *state) techniquesCommand() *cobra.Command {
	var family, format string
	c := &cobra.Command{
		Use:   "techniques",
		Short: "List supported and registered CinderPath techniques",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			snapshot, err := s.loadFramework()
			if err != nil {
				return err
			}
			items := techniqueEntries(snapshot, family)
			if len(items) == 0 {
				if family == "" {
					return fmt.Errorf("no product techniques registered")
				}
				return fmt.Errorf("unknown or empty family %q", family)
			}
			if strings.EqualFold(format, "json") {
				return json.NewEncoder(s.stdout).Encode(map[string]any{"techniques": items})
			}
			printTechniqueList(s.stdout, items)
			return nil
		},
	}
	c.Flags().StringVar(&family, "family", "", "filter by family, for example CRED or RECON")
	c.Flags().StringVar(&format, "format", "text", "text or json")
	return c
}

type techniqueEntry struct {
	ID           string                    `json:"technique_id"`
	Name         string                    `json:"name"`
	Family       string                    `json:"family"`
	Status       string                    `json:"status"`
	Execution    planner.OrchestrationSpec `json:"execution"`
	Requirements []planner.Requirement     `json:"requirements"`
}

func techniqueEntries(snapshot framework.FrameworkSnapshot, family string) []techniqueEntry {
	var out []techniqueEntry
	for _, t := range framework.ProductSnapshot(snapshot).Techniques {
		if family != "" && !strings.EqualFold(t.Family, family) {
			continue
		}
		spec := planner.OrchestrationFor(t.ID)
		status := "unsupported"
		if spec.Implemented {
			status = "supported"
		} else if t.ID == "RECON-7" {
			status = "partial"
		}
		out = append(out, techniqueEntry{ID: t.ID, Name: t.Title, Family: t.Family, Status: status, Execution: spec, Requirements: planner.RequirementsFor(t.ID)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return techniqueNumber(out[i].ID) < techniqueNumber(out[j].ID)
	})
	return out
}

func techniqueNumber(id string) int {
	parts := strings.SplitN(id, "-", 2)
	if len(parts) != 2 {
		return 0
	}
	var n int
	_, _ = fmt.Sscanf(parts[1], "%d", &n)
	return n
}

func printTechniqueList(out io.Writer, entries []techniqueEntry) {
	family := ""
	for _, e := range entries {
		if e.Family != family {
			family = e.Family
			fmt.Fprintf(out, "%s\n\n", family)
		}
		fmt.Fprintf(out, "%s  %s\n", e.ID, e.Name)
		if e.Status == "unsupported" {
			fmt.Fprintf(out, "        Status: unsupported (no CinderPath adapter)\n\n")
			continue
		}
		fmt.Fprintf(out, "        %s; target role: %s\n", executionLabel(e.Execution), e.Execution.TargetRole)
		fmt.Fprintf(out, "        Authentication: %s\n        Privilege: %s\n        Status: %s\n\n", e.Execution.Identity, e.Execution.Privilege, e.Status)
	}
}

func executionLabel(spec planner.OrchestrationSpec) string {
	if spec.Remote {
		return "Remote from Kali"
	}
	return strings.ReplaceAll(spec.Execution, "_", " ")
}

func (s *state) techniqueHelpCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "technique TECHNIQUE-ID",
		Short: "Explain one technique and its prerequisites",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return s.printTechniqueHelp(args[0], "text")
		},
	}
}

func (s *state) helpCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "help [COMMAND|TECHNIQUE-ID]",
		Short: "Help for a command or technique",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return root.Help()
			}
			if isFrameworkTechnique(args[0]) && !strings.HasSuffix(strings.ToUpper(args[0]), "-ALL") {
				return s.printTechniqueHelp(args[0], "text")
			}
			if strings.Contains(args[0], "-") {
				return s.printTechniqueHelp(args[0], "text")
			}
			command, _, err := root.Find(args)
			if err != nil || command == root {
				return fmt.Errorf("unknown command or technique %q", args[0])
			}
			return command.Help()
		},
	}
}

func (s *state) printTechniqueHelp(id, format string) error {
	snapshot, err := s.loadFramework()
	if err != nil {
		return err
	}
	var t framework.Technique
	for _, candidate := range framework.ProductSnapshot(snapshot).Techniques {
		if strings.EqualFold(candidate.ID, id) {
			t = candidate
			break
		}
	}
	if t.ID == "" {
		return fmt.Errorf("unknown technique %q; run cinderpath techniques", id)
	}
	spec := planner.OrchestrationFor(t.ID)
	status := "unsupported"
	if spec.Implemented {
		status = "supported"
	} else if t.ID == "RECON-7" {
		status = "partial"
	}
	if format == "json" {
		return json.NewEncoder(s.stdout).Encode(map[string]any{"technique_id": t.ID, "technique_name": t.Title, "family": t.Family, "description": spec.Description, "status": status, "execution": spec, "requirements": planner.RequirementsFor(t.ID), "canonical_requirements": t.Requirements, "limitations": spec.Limitations})
	}
	fmt.Fprintf(s.stdout, "%s — %s\n\nWhat it does\n  %s\n\nExecution\n  Runs from:          %s\n  Target role:        %s\n  Remote from Kali:   %s\n", t.ID, t.Title, valueOr(spec.Description, t.Summary), spec.Platform, spec.TargetRole, yesNo(spec.Remote))
	fmt.Fprintf(s.stdout, "\nAuthentication\n  Identity:            %s\n  Anonymous path:      %s\n\nAuthorization / privilege\n  %s\n\nServices / capabilities\n  %s\n\nMay produce\n  %s\n\nStatus\n  %s\n", spec.Identity, yesNo(spec.Anonymous), spec.Privilege, strings.Join(spec.Services, ", "), spec.Evidence, status)
	if len(spec.Limitations) > 0 {
		fmt.Fprintln(s.stdout, "\nCurrent limitations")
		for _, limitation := range spec.Limitations {
			fmt.Fprintf(s.stdout, "  - %s\n", limitation)
		}
	}
	if spec.Remediation != "" {
		fmt.Fprintf(s.stdout, "\nHow to resolve blockers\n  %s\n", spec.Remediation)
	}
	if t.ID == "CRED-2" || t.ID == "CRED-3" {
		fmt.Fprintln(s.stdout, "\nImportant")
		fmt.Fprintln(s.stdout, "  A domain credential alone does not provide the required local execution context.")
	}
	return nil
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
