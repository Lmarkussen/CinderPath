package cli

import (
	"encoding/json"
	"fmt"
	"github.com/Lmarkussen/CinderPath/internal/framework"
	"github.com/spf13/cobra"
)

func (s *state) frameworkCommand() *cobra.Command {
	root := &cobra.Command{Use: "framework", Short: "Show truthful framework planning and support coverage"}
	var name, format string
	c := &cobra.Command{Use: "coverage", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if name != "misconfiguration-manager" {
			return fmt.Errorf("unsupported framework %q", name)
		}
		r := framework.MisconfigurationManager()
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(r)
		}
		fmt.Fprintf(s.stdout, "Framework coverage: Misconfiguration Manager\nRegistry schema: %d\nObjectives: %d\n", r.SchemaVersion, len(r.Objectives))
		for _, x := range r.Objectives {
			fmt.Fprintf(s.stdout, "  %s track=%s support=%s\n", x.ID, x.Track, x.Support)
		}
		fmt.Fprintln(s.stdout, "Safety: planning metadata only; planned objectives are not implemented execution capabilities.")
		return nil
	}}
	c.Flags().StringVar(&name, "framework", "", "framework identifier")
	c.Flags().StringVar(&format, "format", "text", "text or json")
	_ = c.MarkFlagRequired("framework")
	root.AddCommand(c)
	return root
}
