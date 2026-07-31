package live

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/progress"
	"github.com/Lmarkussen/CinderPath/internal/scope"
)

type scopeModule struct{ opts Options }

func (m *scopeModule) Metadata() modules.Metadata {
	return modules.Metadata{Name: "live.scope.normalize", Description: "Normalizes explicit targets and applies exclusions", Category: modules.CategoryDiscovery, Safety: modules.SafetySafe}
}
func (m *scopeModule) Applicable(_ context.Context, _ modules.RunContext, _ *models.Asset) (bool, string) {
	if len(m.opts.Scope.Targets)+len(m.opts.Scope.TargetFiles)+len(m.opts.Scope.IncludeCIDRs)+len(m.opts.Hints.ManagementPoints)+len(m.opts.Hints.DistributionPoints)+len(m.opts.Hints.SiteServers)+len(m.opts.Hints.SQLServers) == 0 && m.opts.DC == "" && m.opts.LDAP.Server == "" {
		return false, "live discovery requires at least one explicit target, CIDR, DC, or LDAP server"
	}
	return true, ""
}
func (m *scopeModule) Run(ctx context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	run.Emit(progress.Event{Type: progress.StageStarted, Module: m.Metadata().Name, Message: "input normalization"})
	in := m.opts.Scope
	in.Domain = m.opts.Domain
	in.Targets = append(in.Targets, m.opts.DC, m.opts.LDAP.Server)
	in.Targets = append(in.Targets, m.opts.Hints.ManagementPoints...)
	in.Targets = append(in.Targets, m.opts.Hints.DistributionPoints...)
	in.Targets = append(in.Targets, m.opts.Hints.SiteServers...)
	in.Targets = append(in.Targets, m.opts.Hints.SQLServers...)
	d, err := scope.Normalize(in)
	if err != nil {
		return nil, err
	}
	if len(d.Targets) == 0 {
		return nil, fmt.Errorf("live scope contains no targets after exclusions")
	}
	now := time.Now().UTC()
	result := &modules.Result{}
	for _, target := range d.Targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		a := models.Asset{Kind: models.AssetUnknown, Domain: strings.ToUpper(m.opts.Domain), SiteCode: strings.ToUpper(m.opts.Hints.SiteCode), Properties: map[string]string{"observation_origin": "live", "original_input": target.Original, "normalized_target": target.Value, "input_kind": target.Kind}, Source: m.Metadata().Name, Confidence: models.ConfidenceLow}
		if target.Kind == "ip" {
			a.IPAddresses = []string{target.Value}
		} else {
			a.FQDN = target.Value
			if !strings.Contains(target.Value, ".") {
				a.Hostname = target.Value
			} else {
				a.Hostname = strings.Split(target.Value, ".")[0]
			}
		}
		a.Prepare(now)
		result.Assets = append(result.Assets, a)
		run.Emit(progress.Event{Type: progress.TargetCompleted, Module: m.Metadata().Name, Target: target.Value})
	}
	data := map[string]any{"input_count": d.InputCount, "targets": values(d.Targets), "excluded": d.Excluded, "expanded_count": d.ExpandedCount, "max_targets": in.MaxTargets, "domain": strings.ToLower(m.opts.Domain), "origin": "user_input"}
	e := models.Evidence{Type: "scope_decision", Title: "Live discovery scope normalized", Summary: "Explicit target inputs were normalized, deduplicated, bounded, and filtered before network activity.", Data: data, SourceModule: m.Metadata().Name, Sensitivity: models.SensitivityInternal}
	e.Prepare(now)
	result.Evidence = []models.Evidence{e}
	cap := models.Capability{Name: "scope_normalized", Available: true, Reason: "Explicit live scope contains normalized targets", Source: m.Metadata().Name, EvidenceIDs: []string{e.ID}}
	cap.Prepare()
	result.Capabilities = []models.Capability{cap}
	if m.opts.Domain != "" {
		domain := models.Asset{Kind: models.AssetDomain, FQDN: strings.ToLower(m.opts.Domain), Domain: strings.ToUpper(m.opts.Domain), Properties: map[string]string{"observation_origin": "user_input", "original_input": m.opts.Domain}, Source: "user_input", Confidence: models.ConfidenceMedium}
		domain.Prepare(now)
		result.Assets = append(result.Assets, domain)
	}
	return result, nil
}
func values(in []scope.Target) []string {
	out := make([]string, len(in))
	for i := range in {
		out[i] = in[i].Value
	}
	return out
}
