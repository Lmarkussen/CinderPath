package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/policy"
	"github.com/spf13/cobra"
	"path/filepath"
)

func (s *state) runsCommand() *cobra.Command {
	root := &cobra.Command{Use: "runs", Short: "Inspect durable run history"}
	var dry bool
	var format string
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		db, e := database.Open(cmd.Context(), s.cfg.DBPath)
		if e != nil {
			return e
		}
		defer db.Close()
		rs, e := db.ListRuns(cmd.Context())
		if e != nil {
			return e
		}
		for _, r := range rs {
			if dry && r.Summary["dry_run"] != true {
				continue
			}
			if format == "json" {
				b, _ := json.Marshal(r)
				fmt.Fprintln(s.stdout, string(b))
			} else {
				fmt.Fprintf(s.stdout, "%s %-16s %-22s profile=%s dry_run=%v\n", r.ID, r.Command, r.Status, r.Profile, r.Summary["dry_run"])
			}
		}
		return nil
	}}
	list.Flags().BoolVar(&dry, "dry-run", false, "show only dry-run records")
	list.Flags().StringVar(&format, "format", "table", "table or json")
	show := &cobra.Command{Use: "show RUN_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, a []string) error {
		db, e := database.Open(cmd.Context(), s.cfg.DBPath)
		if e != nil {
			return e
		}
		defer db.Close()
		r, e := db.GetRun(cmd.Context(), a[0])
		if e != nil {
			return e
		}
		st, _ := db.ListWorkflowStages(cmd.Context())
		md, _ := db.ListWorkflowModuleDecisions(cmd.Context())
		filter := func(in []database.WorkflowRecord) []database.WorkflowRecord {
			var out []database.WorkflowRecord
			for _, x := range in {
				if x.RunID == r.ID {
					out = append(out, x)
				}
			}
			return out
		}
		b, _ := json.MarshalIndent(map[string]any{"run": r, "stages": filter(st), "module_decisions": filter(md), "live_policy_requests": 0}, "", "  ")
		fmt.Fprintln(s.stdout, string(b))
		return nil
	}}
	root.AddCommand(list, show)
	return root
}
func (s *state) labCommand() *cobra.Command {
	root := &cobra.Command{Use: "lab", Short: "Offline authorized-lab preparation helpers"}
	var o policy.CapturePlanOptions
	c := &cobra.Command{Use: "capture-plan", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if e := policy.CreateCapturePlan(o); e != nil {
			return e
		}
		fmt.Fprintf(s.stdout, "Created passive offline capture plan: %s\nNetwork activity: none\nPolicy retrieval: not performed\n", filepath.Base(o.Output))
		return nil
	}}
	f := c.Flags()
	f.StringVar(&o.Output, "output", "", "new capture-plan directory")
	f.BoolVar(&o.Force, "force", false, "replace an existing capture-plan directory atomically")
	f.StringVar(&o.SiteCode, "site-code", "", "optional placeholder site-code metadata")
	f.StringVar(&o.ManagementPoint, "management-point", "", "optional management-point reference")
	f.StringVar(&o.ClientIDReference, "client-id-reference", "", "optional existing-client reference")
	_ = c.MarkFlagRequired("output")
	root.AddCommand(c)
	root.AddCommand(s.captureKitCommand())
	root.AddCommand(s.clientArtifactsCommand())
	root.AddCommand(s.pxeCommand())
	return root
}

var _ = errors.New
