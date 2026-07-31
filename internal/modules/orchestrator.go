package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/progress"
)

type Store interface {
	QueryStore
	UpsertAsset(context.Context, *models.Asset) (bool, error)
	UpsertCredential(context.Context, *models.Credential) (bool, error)
	UpsertCapability(context.Context, *models.Capability) (bool, error)
	UpsertEvidence(context.Context, *models.Evidence) (bool, error)
	UpsertFinding(context.Context, *models.Finding) (bool, error)
	UpsertRelationship(context.Context, *models.Relationship) (bool, error)
	UpsertAttackPath(context.Context, *models.AttackPath) (bool, error)
	SaveModuleExecution(context.Context, *models.ModuleExecution) error
}

type Summary struct {
	Executed, Skipped, Failed, AssetsCreated, EvidenceCreated, FindingsCreated, AttackPathsCreated int
	Executions                                                                                     []models.ModuleExecution
	Warnings                                                                                       []string
}
type Orchestrator struct{ store Store }

func NewOrchestrator(store Store) *Orchestrator { return &Orchestrator{store: store} }

func (o *Orchestrator) Execute(ctx context.Context, run RunContext, list []Module, assets []models.Asset) (Summary, error) {
	var summary Summary
	for _, mod := range list {
		meta := mod.Metadata()
		targets := []*models.Asset{nil}
		if meta.Category != CategoryDiscovery && meta.Category != CategoryCorrelation {
			targets = nil
			for i := range assets {
				if Supports(meta, assets[i].Kind) {
					targets = append(targets, &assets[i])
				}
			}
		}
		if len(targets) == 0 {
			targets = []*models.Asset{nil}
		}
		for _, asset := range targets {
			if err := ctx.Err(); err != nil {
				return summary, err
			}
			ex := models.ModuleExecution{RunID: run.RunID, ModuleName: meta.Name, StartedAt: time.Now().UTC(), Status: models.ModuleExecutionRunning}
			run.Emit(progress.Event{Type: progress.ModuleStarted, Module: meta.Name})
			if asset != nil {
				ex.AssetID = asset.ID
			}
			if err := o.store.SaveModuleExecution(ctx, &ex); err != nil {
				return summary, fmt.Errorf("record module start: %w", err)
			}
			if meta.Safety != SafetySafe {
				o.skip(ctx, &ex, "only safe modules are enabled in this release")
				summary.Skipped++
				summary.Executions = append(summary.Executions, ex)
				run.Emit(progress.Event{Type: progress.ModuleSkipped, Module: meta.Name, Message: ex.SkipReason})
				continue
			}
			if reason := o.missingRequirement(ctx, meta); reason != "" {
				o.skip(ctx, &ex, reason)
				summary.Skipped++
				summary.Executions = append(summary.Executions, ex)
				run.Emit(progress.Event{Type: progress.ModuleSkipped, Module: meta.Name, Message: reason})
				continue
			}
			ok, reason := mod.Applicable(ctx, run, asset)
			if !ok {
				o.skip(ctx, &ex, reason)
				summary.Skipped++
				summary.Executions = append(summary.Executions, ex)
				run.Emit(progress.Event{Type: progress.ModuleSkipped, Module: meta.Name, Message: reason})
				continue
			}
			result, err := mod.Run(ctx, run, asset)
			now := time.Now().UTC()
			ex.FinishedAt = &now
			if err != nil {
				ex.Status = models.ModuleExecutionFailed
				ex.Error = err.Error()
				_ = o.store.SaveModuleExecution(context.WithoutCancel(ctx), &ex)
				summary.Failed++
				summary.Executions = append(summary.Executions, ex)
				run.Emit(progress.Event{Type: progress.Error, Module: meta.Name, Message: err.Error()})
				if IsFatal(err) {
					return summary, fmt.Errorf("fatal module %s failure: %w", meta.Name, err)
				}
				continue
			}
			if result == nil {
				result = &Result{}
			}
			counts, persistErr := o.persist(ctx, result)
			ex.AssetsCreated = counts[0]
			ex.EvidenceCreated = counts[1]
			ex.FindingsCreated = counts[2]
			summary.AssetsCreated += counts[0]
			summary.EvidenceCreated += counts[1]
			summary.FindingsCreated += counts[2]
			summary.AttackPathsCreated += counts[3]
			summary.Warnings = append(summary.Warnings, result.Warnings...)
			var resultError error
			fatalResult := false
			if len(result.Errors) > 0 {
				messages := make([]string, 0, len(result.Errors))
				for _, item := range result.Errors {
					messages = append(messages, item.Message)
					fatalResult = fatalResult || item.Fatal
				}
				resultError = fmt.Errorf("module result errors: %s", strings.Join(messages, "; "))
			}
			if persistErr != nil {
				ex.Status = models.ModuleExecutionFailed
				ex.Error = persistErr.Error()
				summary.Failed++
			} else if resultError != nil {
				ex.Status = models.ModuleExecutionFailed
				ex.Error = resultError.Error()
				summary.Failed++
			} else {
				ex.Status = models.ModuleExecutionSuccess
				summary.Executed++
			}
			_ = o.store.SaveModuleExecution(context.WithoutCancel(ctx), &ex)
			summary.Executions = append(summary.Executions, ex)
			run.Emit(progress.Event{Type: progress.ModuleCompleted, Module: meta.Name, Data: map[string]any{"status": ex.Status}})
			if fatalResult {
				return summary, fmt.Errorf("fatal module %s result: %w", meta.Name, resultError)
			}
		}
	}
	return summary, nil
}

func (o *Orchestrator) missingRequirement(ctx context.Context, m Metadata) string {
	if len(m.Requirements) == 0 {
		return ""
	}
	caps, err := o.store.ListCapabilities(ctx)
	if err != nil {
		return "capabilities could not be evaluated"
	}
	for _, req := range m.Requirements {
		found := false
		for _, cap := range caps {
			if cap.Name == req.Capability && cap.Available {
				found = true
				break
			}
		}
		if !found {
			return "missing capability: " + req.Capability
		}
	}
	return ""
}
func (o *Orchestrator) skip(ctx context.Context, e *models.ModuleExecution, reason string) {
	now := time.Now().UTC()
	e.FinishedAt = &now
	e.Status = models.ModuleExecutionSkipped
	e.SkipReason = reason
	_ = o.store.SaveModuleExecution(context.WithoutCancel(ctx), e)
}
func (o *Orchestrator) persist(ctx context.Context, r *Result) ([4]int, error) {
	var c [4]int
	for i := range r.Assets {
		n, e := o.store.UpsertAsset(ctx, &r.Assets[i])
		if e != nil {
			return c, e
		}
		if n {
			c[0]++
		}
	}
	for i := range r.Credentials {
		if _, e := o.store.UpsertCredential(ctx, &r.Credentials[i]); e != nil {
			return c, e
		}
	}
	for i := range r.Capabilities {
		if _, e := o.store.UpsertCapability(ctx, &r.Capabilities[i]); e != nil {
			return c, e
		}
	}
	for i := range r.Evidence {
		n, e := o.store.UpsertEvidence(ctx, &r.Evidence[i])
		if e != nil {
			return c, e
		}
		if n {
			c[1]++
		}
	}
	for i := range r.Findings {
		n, e := o.store.UpsertFinding(ctx, &r.Findings[i])
		if e != nil {
			return c, e
		}
		if n {
			c[2]++
		}
	}
	for i := range r.Relationships {
		if _, e := o.store.UpsertRelationship(ctx, &r.Relationships[i]); e != nil {
			return c, e
		}
	}
	for i := range r.AttackPaths {
		n, e := o.store.UpsertAttackPath(ctx, &r.AttackPaths[i])
		if e != nil {
			return c, e
		}
		if n {
			c[3]++
		}
	}
	return c, nil
}
