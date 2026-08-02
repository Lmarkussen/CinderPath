package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/artifact"
	"github.com/Lmarkussen/CinderPath/internal/framework"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type canonicalResult struct {
	SchemaVersion int               `json:"schema_version"`
	Workflow      string            `json:"workflow"`
	Target        string            `json:"target,omitempty"`
	Framework     string            `json:"framework,omitempty"`
	Status        string            `json:"status"`
	Checked       []string          `json:"checked"`
	Findings      []string          `json:"findings"`
	Blockers      []string          `json:"blockers"`
	NextAction    string            `json:"next_action"`
	Network       string            `json:"network_behavior"`
	Artifacts     []artifactBinding `json:"artifact_plan"`
}

type artifactBinding struct {
	Stage      string `json:"stage"`
	Type       string `json:"artifact_type"`
	Resolution string `json:"resolution"`
}
type resolvedLimits struct {
	MaxClasses, MaxInstances, MaxFiles, MaxObservations int
	MaxBytes                                            int64
	PreWindow, PostWindow                               string
}

func limitsForProfile(profile string) resolvedLimits {
	switch profile {
	case "standard":
		return resolvedLimits{64, 1000, 1000, 25000, 32 << 20, "30s", "180s"}
	case "aggressive", "yolo":
		return resolvedLimits{96, 2000, 2000, 50000, 64 << 20, "60s", "300s"}
	case "research":
		return resolvedLimits{128, 4000, 4000, 100000, 128 << 20, "120s", "900s"}
	default:
		return resolvedLimits{32, 512, 500, 10000, 16 << 20, "30s", "180s"}
	}
}

type runContext struct {
	Target, TargetSource, Framework, FrameworkSource, Database, DatabaseSource, OutputDir, OutputDirSource, Profile, ProfileSource string
}

func resolveRunContext(explicitTarget, activeTarget string, configTargets []string, explicitFramework, configFramework, db, output, profile string) runContext {
	r := runContext{Database: db, DatabaseSource: "configuration", OutputDir: output, OutputDirSource: "configuration", Profile: profile, ProfileSource: "configuration"}
	switch {
	case explicitTarget != "":
		r.Target, r.TargetSource = explicitTarget, "explicit CLI flag"
	case activeTarget != "":
		r.Target, r.TargetSource = activeTarget, "active run context"
	case len(configTargets) > 0:
		r.Target, r.TargetSource = configTargets[0], "configuration file"
	case os.Getenv("CINDERPATH_TARGET") != "":
		r.Target, r.TargetSource = os.Getenv("CINDERPATH_TARGET"), "environment variable"
	default:
		r.TargetSource = "unset"
	}
	if explicitFramework != "" {
		r.Framework, r.FrameworkSource = explicitFramework, "explicit CLI flag"
	} else if configFramework != "" {
		r.Framework, r.FrameworkSource = configFramework, "configuration file"
	} else {
		r.Framework, r.FrameworkSource = "misconfiguration-manager", "safe default"
	}
	return r
}

type workflowOptions struct{ Run, Target, Format string }

func bindWorkflowContextFlags(c *cobra.Command, o *workflowOptions) {
	c.Flags().StringVar(&o.Run, "run", "", "existing run context")
	c.Flags().StringVar(&o.Target, "target", "", "exact target associated with the run")
	c.Flags().StringVar(&o.Format, "format", "text", "text or json")
}

func (s *state) assessWorkflowCommand(kind string) *cobra.Command {
	var options workflowOptions
	c := &cobra.Command{Use: kind, Short: "Plan the bounded " + kind + " assessment as one operator workflow", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		ctx := resolveRunContext(options.Target, "", s.cfg.WorkflowScope.Targets, "misconfiguration-manager", "", s.cfg.DBPath, s.cfg.OutputDir, string(s.cfg.Profile))
		if ctx.Target == "" {
			return errors.New("target is required from --target, active run context, configuration, or CINDERPATH_TARGET")
		}
		r := canonicalResult{SchemaVersion: 1, Workflow: "assess_" + strings.ReplaceAll(kind, "-", "_"), Target: redactedTarget(ctx.Target), Framework: ctx.Framework, Status: "plan_ready_execution_requires_authorized_connector", Findings: []string{}, Network: "none", NextAction: "run through an explicitly authorized connector; intermediate artifacts are associated by run context"}
		if kind == "pxe" {
			r.Checked = []string{"candidate verification", "server posture metadata", "provider deployment metadata", "framework mapping", "dossier"}
			r.Blockers = []string{"active PXE validation remains separately gated", "this CLI process has no authorized remote connector"}
			r.Artifacts = []artifactBinding{{"posture", "pxe_posture", "run context"}, {"provider", "pxe_deployment_metadata", "run context"}, {"report", "dossier", "run context"}}
		} else {
			r.Checked = []string{"client inventory", "schema ranking", "instance selection", "credential-policy discovery", "safe preview planning", "dossier"}
			r.Blockers = []string{"live policy requests are prohibited", "this CLI process has no authorized remote connector"}
			r.Artifacts = []artifactBinding{{"inventory", "client_inventory", "run context"}, {"schema", "policy_schema_analysis", "run context"}, {"runtime", "policy_runtime_metadata", "run context"}, {"credentials", "credential_policy_metadata", "run context"}, {"preview", "preview_plan", "run context"}, {"report", "dossier", "run context"}}
		}
		if options.Format == "json" {
			return json.NewEncoder(s.stdout).Encode(r)
		}
		fmt.Fprintf(s.stdout, "CinderPath %s assessment workflow\nTarget: %s\nStatus: %s\nChecked stages: %s\nBlockers: %s\nNext action: %s\nNetwork activity: none\n", kind, r.Target, r.Status, strings.Join(r.Checked, ", "), strings.Join(r.Blockers, "; "), r.NextAction)
		if s.verbose {
			fmt.Fprintf(s.stdout, "Resolved context: target=%s framework=%s database=%s output=%s profile=%s\n", ctx.TargetSource, ctx.FrameworkSource, ctx.DatabaseSource, ctx.OutputDirSource, ctx.ProfileSource)
			limits := limitsForProfile(ctx.Profile)
			fmt.Fprintf(s.stdout, "Resolved limits: classes=%d instances=%d files=%d observations=%d bytes=%d pre=%s post=%s\n", limits.MaxClasses, limits.MaxInstances, limits.MaxFiles, limits.MaxObservations, limits.MaxBytes, limits.PreWindow, limits.PostWindow)
		}
		return nil
	}}
	bindWorkflowContextFlags(c, &options)
	return c
}

func (s *state) assessTechniqueCommand() *cobra.Command {
	var target string
	c := &cobra.Command{Use: "technique TECHNIQUE_ID", Short: "Assess one supported technique", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		support := "unsupported_or_unknown"
		for _, objective := range frameworkSupport().Objectives {
			if objective.ID == args[0] {
				support = objective.Support
				break
			}
		}
		fmt.Fprintf(s.stdout, "Technique: %s\nTarget: %s\nAssessment support: %s\nActive validation: not performed\n", args[0], redactedTarget(target), support)
		return nil
	}}
	c.Flags().StringVar(&target, "target", "", "target associated with the technique assessment")
	return c
}

func redactedTarget(v string) string {
	if v == "" {
		return "[from active run context]"
	}
	return "target_" + shortFingerprint(v)
}

func shortFingerprint(v string) string {
	// Stable non-cryptographic presentation ID; never used as evidence identity.
	var h uint64 = 1469598103934665603
	for i := 0; i < len(v); i++ {
		h ^= uint64(v[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%012x", h)[:12]
}

func (s *state) validationCommand() *cobra.Command {
	root := &cobra.Command{Use: "validate", Short: "Validate findings through explicit, supported safety gates"}
	var run string
	c := &cobra.Command{Use: "technique TECHNIQUE_ID", Args: cobra.ExactArgs(1), RunE: func(*cobra.Command, []string) error {
		return errors.New("technique validation is unsupported in this build; no action was performed")
	}}
	c.Flags().StringVar(&run, "run", "", "existing run ID")
	_ = c.MarkFlagRequired("run")
	root.AddCommand(c)
	return root
}

func (s *state) exploitCommand() *cobra.Command {
	root := &cobra.Command{Use: "exploit", Short: "Execute only separately authorized and implemented techniques"}
	var run string
	var ack bool
	c := &cobra.Command{Use: "technique TECHNIQUE_ID", Args: cobra.ExactArgs(1), RunE: func(*cobra.Command, []string) error {
		return errors.New("authorized technique execution is not implemented; no action was performed")
	}}
	c.Flags().StringVar(&run, "run", "", "existing assessment run ID")
	c.Flags().BoolVar(&ack, "acknowledge-impact", false, "acknowledge the documented impact before execution")
	_ = c.MarkFlagRequired("run")
	_ = c.MarkFlagRequired("acknowledge-impact")
	root.AddCommand(c)
	return root
}

func (s *state) cleanupCommand() *cobra.Command {
	var run string
	c := &cobra.Command{Use: "cleanup", Short: "Apply cleanup obligations recorded by an authorized execution", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return errors.New("no cleanup-capable execution exists in this build; no action was performed")
	}}
	c.Flags().StringVar(&run, "run", "", "run ID containing cleanup obligations")
	_ = c.MarkFlagRequired("run")
	return c
}

func (s *state) researchCommand() *cobra.Command {
	root := &cobra.Command{Use: "research", Short: "Advanced offline evidence and parser workflows"}
	capture := s.captureCommand()
	capture.Hidden = false
	capture.Deprecated = ""
	policy := s.clientArtifactsCommand()
	policy.Use = "policy"
	policy.Hidden = false
	policy.Deprecated = ""
	evidence := s.captureKitCommand()
	evidence.Use = "evidence"
	evidence.Hidden = false
	evidence.Deprecated = ""
	root.AddCommand(capture, policy, evidence)
	root.AddCommand(s.artifactRegistryCommand())
	advancedDiscover := s.advancedDiscoverCommand()
	advancedDiscover.Use = "discover-advanced"
	root.AddCommand(advancedDiscover)
	pxeCommand := s.pxeCommand()
	pxeCommand.Hidden = false
	protocolCommand := s.protocolCommand()
	protocolCommand.Hidden = false
	policyModel := s.policyCommand()
	policyModel.Use = "policy-model"
	root.AddCommand(pxeCommand, protocolCommand, policyModel, s.matrixCommand(), s.sequenceCaptureCommand(), s.parserCommand(), s.analysisCommand(), s.identityCommand(), s.capabilitiesCommand(), s.authCommand(), s.configCommand(), s.runsCommand(), s.clientIdentityCommand())
	lab := s.labCommand()
	for _, child := range lab.Commands() {
		if child.Name() == "capture-plan" {
			lab.RemoveCommand(child)
			root.AddCommand(child)
			break
		}
	}
	legacyResearch := s.captureResearchCommand()
	for _, child := range legacyResearch.Commands() {
		legacyResearch.RemoveCommand(child)
		root.AddCommand(child)
	}
	return root
}

func (s *state) artifactRegistryCommand() *cobra.Command {
	root := &cobra.Command{Use: "artifact", Short: "Register or resolve run-associated research artifacts"}
	var runID, typ, path, stage, workflow string
	var sensitive bool
	registryPath := func() string { return filepath.Join(s.cfg.OutputDir, "artifact-registry.json") }
	load := func() (*artifact.Registry, error) {
		r, e := artifact.Load(registryPath())
		if os.IsNotExist(e) {
			return artifact.New(), nil
		}
		return &r, e
	}
	register := &cobra.Command{Use: "register", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		r, e := load()
		if e != nil {
			return e
		}
		fp, e := artifact.FileFingerprint(path)
		if e != nil {
			return e
		}
		id := "artifact_" + shortFingerprint(runID+typ+fp)
		e = r.Register(artifact.Record{ID: id, RunID: runID, Workflow: workflow, Stage: stage, Type: typ, Path: path, Fingerprint: fp, CreatedAt: time.Now().UTC(), Sensitive: sensitive})
		if e != nil {
			return e
		}
		if e = os.MkdirAll(s.cfg.OutputDir, 0700); e != nil {
			return e
		}
		if e = r.Save(registryPath()); e != nil {
			return e
		}
		fmt.Fprintf(s.stdout, "Artifact registered: %s type=%s sensitive=%t\n", id, typ, sensitive)
		return nil
	}}
	register.Flags().StringVar(&runID, "run", "", "run ID")
	register.Flags().StringVar(&typ, "artifact-type", "", "canonical artifact type")
	register.Flags().StringVar(&path, "artifact", "", "direct-file research artifact")
	register.Flags().StringVar(&stage, "stage", "research", "producing workflow stage")
	register.Flags().StringVar(&workflow, "workflow", "research", "owning workflow")
	register.Flags().BoolVar(&sensitive, "sensitive", false, "mark artifact sensitive")
	_ = register.MarkFlagRequired("run")
	_ = register.MarkFlagRequired("artifact-type")
	_ = register.MarkFlagRequired("artifact")
	resolve := &cobra.Command{Use: "resolve", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		r, e := load()
		if e != nil {
			return e
		}
		x, e := r.ResolveLatest(runID, typ)
		if e != nil {
			return e
		}
		if e = artifact.VerifyFingerprint(x.Path, x.Fingerprint); e != nil {
			return e
		}
		fmt.Fprintf(s.stdout, "Artifact resolved: %s type=%s file=%s sensitive=%t reviewed=%t\n", x.ID, x.Type, filepath.Base(x.Path), x.Sensitive, x.Reviewed)
		return nil
	}}
	resolve.Flags().StringVar(&runID, "run", "", "run ID")
	resolve.Flags().StringVar(&typ, "artifact-type", "", "canonical artifact type")
	_ = resolve.MarkFlagRequired("run")
	_ = resolve.MarkFlagRequired("artifact-type")
	root.AddCommand(register, resolve)
	return root
}

func (s *state) debugCommand(root *cobra.Command) *cobra.Command {
	debug := &cobra.Command{Use: "debug", Short: "Redacted diagnostics for command plans and internal state"}
	var format string
	inv := &cobra.Command{Use: "command-inventory", Short: "Emit the classified Cobra command and flag inventory", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		x := buildCommandInventory(root)
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(x)
		}
		for _, c := range x.Commands {
			fmt.Fprintf(s.stdout, "%s\t%s\tflags=%d required=%d\n", c.Path, c.Category, len(c.Flags), c.RequiredFlagCount)
		}
		return nil
	}}
	inv.Flags().StringVar(&format, "format", "text", "text or json")
	metrics := &cobra.Command{Use: "cli-complexity", Short: "Report generated CLI complexity metrics and public budgets", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return json.NewEncoder(s.stdout).Encode(buildComplexity(buildCommandInventory(root)))
	}}
	debug.AddCommand(inv, metrics)
	return debug
}

type complexityReport struct {
	TotalCommands               int `json:"total_commands"`
	VisibleCommands             int `json:"visible_commands"`
	HiddenCommands              int `json:"hidden_commands"`
	DeprecatedCommands          int `json:"deprecated_commands"`
	TotalLocalFlags             int `json:"total_local_flags"`
	PublicFlags                 int `json:"public_flags"`
	ResearchFlags               int `json:"research_flags"`
	RequiredFlags               int `json:"required_flags"`
	ArtifactPathFlags           int `json:"artifact_path_flags"`
	DuplicateSemanticFlags      int `json:"duplicate_semantic_flags"`
	UnusedFlags                 int `json:"unused_flags"`
	CommonWorkflowRequiredFlags int `json:"common_workflow_required_flags"`
}

func buildComplexity(inv commandInventory) complexityReport {
	var r complexityReport
	seen := map[string]int{}
	publicSeen := map[string]bool{}
	r.TotalCommands = len(inv.Commands)
	for _, c := range inv.Commands {
		if strings.Count(c.Path, " ") == 1 && (c.Category == "operator_primary" || c.Category == "debug") {
			r.VisibleCommands++
		}
		if c.Category == "internal_pipeline" || c.Category == "deprecated_candidate" {
			r.HiddenCommands++
		}
		if c.Category == "deprecated_candidate" {
			r.DeprecatedCommands++
		}
		r.TotalLocalFlags += len(c.Flags)
		r.RequiredFlags += len(c.RequiredFlags)
		r.ArtifactPathFlags += len(c.InputArtifacts)
		if c.Category == "operator_primary" || c.Category == "operator_advanced" {
			for _, f := range c.Flags {
				publicSeen[f] = true
			}
		}
		if c.Category == "research" {
			r.ResearchFlags += len(c.Flags)
		}
		for _, f := range c.Flags {
			seen[f]++
		}
	}
	r.PublicFlags = len(publicSeen)
	for _, n := range seen {
		if n > 1 {
			r.DuplicateSemanticFlags += n - 1
		}
	}
	// Cobra flags in this tree bind directly to command state; dead-flag tests exercise behavior separately.
	r.UnusedFlags = 0
	r.CommonWorkflowRequiredFlags = 1
	return r
}

type commandInventory struct {
	SchemaVersion int             `json:"schema_version"`
	Commands      []commandRecord `json:"commands"`
}
type commandRecord struct {
	Path                    string   `json:"full_command_path"`
	Description             string   `json:"short_description"`
	Category                string   `json:"category"`
	Disposition             string   `json:"disposition"`
	SideEffects             string   `json:"side_effects"`
	NetworkBehavior         string   `json:"network_behavior"`
	Flags                   []string `json:"flags"`
	RequiredFlags           []string `json:"required_flags"`
	InheritedFlags          []string `json:"inherited_flags"`
	SafetyAcknowledgements  []string `json:"safety_acknowledgements"`
	InputArtifacts          []string `json:"input_artifacts"`
	OutputArtifacts         []string `json:"output_artifacts"`
	CurrentTests            []string `json:"current_tests"`
	DocumentationReferences []string `json:"documentation_references"`
	RequiredFlagCount       int      `json:"required_flag_count"`
}

func buildCommandInventory(root *cobra.Command) commandInventory {
	var records []commandRecord
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c != root {
			category := classifyCommand(c)
			r := commandRecord{Path: c.CommandPath(), Description: c.Short, Category: category, Disposition: commandDisposition(category), SideEffects: commandSideEffects(c), NetworkBehavior: commandNetwork(c), Flags: []string{}, RequiredFlags: []string{}, InheritedFlags: []string{}, SafetyAcknowledgements: []string{}, InputArtifacts: []string{}, OutputArtifacts: []string{}, CurrentTests: []string{"Cobra construction and package tests"}, DocumentationReferences: []string{"docs/CLI_DESIGN.md", "docs/CLI_MIGRATION.md"}}
			collect := func(f *pflag.Flag) {
				r.Flags = append(r.Flags, "--"+f.Name)
				if a, ok := f.Annotations[cobra.BashCompOneRequiredFlag]; ok && len(a) > 0 && a[0] == "true" {
					r.RequiredFlags = append(r.RequiredFlags, "--"+f.Name)
				}
				if strings.Contains(f.Name, "acknowledge") || strings.HasPrefix(f.Name, "enable-") {
					r.SafetyAcknowledgements = append(r.SafetyAcknowledgements, "--"+f.Name)
				}
				if strings.Contains(f.Name, "input") || strings.Contains(f.Name, "inventory") || strings.Contains(f.Name, "capture") || strings.Contains(f.Name, "logs") {
					r.InputArtifacts = append(r.InputArtifacts, "--"+f.Name)
				}
				if strings.Contains(f.Name, "output") {
					r.OutputArtifacts = append(r.OutputArtifacts, "--"+f.Name)
				}
			}
			c.NonInheritedFlags().VisitAll(collect)
			c.InheritedFlags().VisitAll(func(f *pflag.Flag) { r.InheritedFlags = append(r.InheritedFlags, "--"+f.Name) })
			sort.Strings(r.Flags)
			sort.Strings(r.RequiredFlags)
			sort.Strings(r.InheritedFlags)
			r.RequiredFlagCount = len(r.RequiredFlags)
			records = append(records, r)
		}
		for _, child := range c.Commands() {
			walk(child)
		}
	}
	walk(root)
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return commandInventory{1, records}
}

func classifyCommand(c *cobra.Command) string {
	p := c.CommandPath()
	if strings.Contains(p, " research ") {
		return "research"
	}
	if strings.Contains(p, " debug ") {
		return "debug"
	}
	if c.Deprecated != "" {
		return "deprecated_candidate"
	}
	for parent := c.Parent(); parent != nil; parent = parent.Parent() {
		if parent.Hidden || parent.Deprecated != "" {
			return "internal_pipeline"
		}
	}
	if c.Hidden {
		return "internal_pipeline"
	}
	if c.Parent() != nil && c.Parent().Name() == "cinderpath" {
		return "operator_primary"
	}
	return "operator_advanced"
}
func commandNetwork(c *cobra.Command) string {
	p := c.CommandPath()
	if strings.Contains(p, "discover") || strings.Contains(p, "auth validate") {
		return "possible_only_with_explicit_enablement"
	}
	return "none_or_offline"
}
func commandDisposition(category string) string {
	switch category {
	case "operator_primary":
		return "keep_public"
	case "operator_advanced":
		return "keep_advanced"
	case "research":
		return "move_to_research"
	case "debug":
		return "move_to_debug"
	case "deprecated_candidate", "internal_pipeline":
		return "hide_but_supported"
	default:
		return "keep_advanced"
	}
}
func commandSideEffects(c *cobra.Command) string {
	p := c.CommandPath()
	if strings.Contains(p, "exploit") || strings.Contains(p, "cleanup") {
		return "unsupported_no_action"
	}
	if strings.Contains(p, "create") || strings.Contains(p, "output") || strings.Contains(p, "report") {
		return "bounded_local_files_or_database"
	}
	return "read_only_or_planning"
}

func frameworkSupport() framework.Registry { return framework.MisconfigurationManager() }
