package app

import (
	"context"
	"fmt"

	"github.com/Lmarkussen/CinderPath/internal/discovery/live"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/planner"
)

// PrerequisiteExecutionRequest carries only planner-selected, safe modules.
// It deliberately has no policy-request or arbitrary module fields.
type PrerequisiteExecutionRequest struct {
	TechniqueID string
	Modules     []string
	Live        live.Options
	Args        []string
}

type PrerequisiteExecutionResult struct {
	Outcome         Outcome
	ExecutedModules []string
}

type PrerequisiteResolutionRequest struct {
	PrerequisiteExecutionRequest
	Plan   planner.Plan
	Replan func(currentRun string) planner.Plan
}

type PrerequisiteResolutionResult struct {
	Plan            planner.Plan
	Runs            []Outcome
	ExecutedModules []string
}

const maxPrerequisiteResolutionPasses = 2

// ResolveSafePrerequisites executes each planner-selected safe module at most
// once, then re-plans from the run that persisted the resulting evidence.
func (a *Application) ResolveSafePrerequisites(ctx context.Context, req PrerequisiteResolutionRequest) (PrerequisiteResolutionResult, error) {
	result := PrerequisiteResolutionResult{Plan: req.Plan}
	attempted := map[string]bool{}
	for pass := 0; pass < maxPrerequisiteResolutionPasses; pass++ {
		selected := plannerPrerequisiteModules(result.Plan, attempted)
		if len(selected) == 0 {
			if hasCollectablePrerequisite(result.Plan) {
				return result, fmt.Errorf("safe prerequisite resolution made no progress: planner retained an already attempted module")
			}
			return result, nil
		}
		execution, err := a.ExecuteSafePrerequisites(ctx, PrerequisiteExecutionRequest{TechniqueID: req.TechniqueID, Modules: selected, Live: req.Live, Args: req.Args})
		if err != nil {
			return result, err
		}
		result.Runs = append(result.Runs, execution.Outcome)
		result.ExecutedModules = append(result.ExecutedModules, execution.ExecutedModules...)
		for _, name := range execution.ExecutedModules {
			attempted[name] = true
		}
		if execution.Outcome.ModuleSummary.Failed > 0 {
			return result, fmt.Errorf("safe prerequisite collection failed")
		}
		if req.Replan == nil {
			return result, nil
		}
		result.Plan = req.Replan(execution.Outcome.Run.ID)
		if hasAttemptedPrerequisite(result.Plan, attempted) {
			return result, fmt.Errorf("safe prerequisite resolution made no progress: planner retained an executed module")
		}
	}
	if len(plannerPrerequisiteModules(result.Plan, map[string]bool{})) > 0 {
		return result, fmt.Errorf("safe prerequisite resolution made no progress after %d passes", maxPrerequisiteResolutionPasses)
	}
	return result, nil
}

// ExecuteSafePrerequisites persists a dedicated prerequisite run. It accepts
// only reviewed safe modules registered for prerequisite use and never expands
// the planner's module list.
func (a *Application) ExecuteSafePrerequisites(ctx context.Context, req PrerequisiteExecutionRequest) (PrerequisiteExecutionResult, error) {
	if len(req.Modules) == 0 {
		return PrerequisiteExecutionResult{}, nil
	}
	if err := live.ValidateOptions(req.Live); err != nil {
		return PrerequisiteExecutionResult{}, err
	}
	selected, err := a.safePrerequisiteModules(req.Live, req.Modules)
	if err != nil {
		return PrerequisiteExecutionResult{}, err
	}
	out, err := a.executeModules(ctx, "assess "+req.TechniqueID+" prerequisites", req.Args, "live-prerequisites", selected)
	return PrerequisiteExecutionResult{Outcome: out, ExecutedModules: moduleNames(selected)}, err
}

func (a *Application) safePrerequisiteModules(opts live.Options, names []string) ([]modules.Module, error) {
	available := map[string]modules.Module{}
	moduleSet := live.LDAPOnly
	if a.prerequisiteModuleSet != nil {
		moduleSet = a.prerequisiteModuleSet
	}
	for _, mod := range moduleSet(opts) {
		available[mod.Metadata().Name] = mod
	}
	seen := map[string]bool{}
	selected := make([]modules.Module, 0, len(names))
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		mod, ok := available[name]
		if !ok {
			return nil, fmt.Errorf("planner selected unsupported safe prerequisite module %q", name)
		}
		if mod.Metadata().Safety != modules.SafetySafe {
			return nil, fmt.Errorf("planner selected non-safe prerequisite module %q", name)
		}
		selected = append(selected, mod)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("planner selected no executable safe prerequisite modules")
	}
	return selected, nil
}

func moduleNames(list []modules.Module) []string {
	out := make([]string, 0, len(list))
	for _, mod := range list {
		out = append(out, mod.Metadata().Name)
	}
	return out
}

func plannerPrerequisiteModules(plan planner.Plan, attempted map[string]bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, decision := range plan.Prerequisites {
		if decision.State != planner.Collect || decision.Module == "" || attempted[decision.Module] || seen[decision.Module] {
			continue
		}
		seen[decision.Module] = true
		out = append(out, decision.Module)
	}
	return out
}

func hasCollectablePrerequisite(plan planner.Plan) bool {
	for _, decision := range plan.Prerequisites {
		if decision.State == planner.Collect && decision.Module != "" {
			return true
		}
	}
	return false
}

func hasAttemptedPrerequisite(plan planner.Plan, attempted map[string]bool) bool {
	for _, decision := range plan.Prerequisites {
		if decision.State == planner.Collect && decision.Module != "" && attempted[decision.Module] {
			return true
		}
	}
	return false
}
