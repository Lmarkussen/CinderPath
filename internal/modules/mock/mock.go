package mock

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
)

const source = "mock"

func All() []modules.Module {
	return []modules.Module{discoveryModule{}, managementPointModule{}, distributionPointModule{}, pxeModule{}, policyExposureModule{}, correlationModule{}}
}

func mockAsset(kind models.AssetKind, hostname, fqdn, domain, site string, roles ...string) models.Asset {
	a := models.Asset{Kind: kind, Hostname: hostname, FQDN: fqdn, Domain: domain, SiteCode: site, Roles: roles, Properties: map[string]string{"mock": "true", "data_origin": "synthetic"}, Source: source, Confidence: models.ConfidenceConfirmed}
	a.Prepare(time.Now())
	return a
}

func mockEvidence(module, typ, title, summary, assetID string, hypothetical bool, data map[string]any) models.Evidence {
	if data == nil {
		data = map[string]any{}
	}
	data["mock"] = true
	data["hypothetical"] = hypothetical
	e := models.Evidence{Type: typ, Title: title, Summary: summary, Data: data, SourceModule: module, AssetID: assetID, Sensitivity: models.SensitivityInternal}
	e.Prepare(time.Now())
	return e
}

type discoveryModule struct{}

func (discoveryModule) Metadata() modules.Metadata {
	return modules.Metadata{Name: "mock.sccm.discovery", Description: "Seeds a synthetic SCCM topology without network access", Category: modules.CategoryDiscovery, Safety: modules.SafetySafe}
}
func (discoveryModule) Applicable(context.Context, modules.RunContext, *models.Asset) (bool, string) {
	return true, ""
}
func (discoveryModule) Run(ctx context.Context, _ modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	assets := []models.Asset{
		mockAsset(models.AssetDomain, "LAB", "LAB.LOCAL", "LAB.LOCAL", ""),
		mockAsset(models.AssetSite, "LAB", "", "LAB.LOCAL", "LAB"),
		mockAsset(models.AssetSiteServer, "SCCM01", "SCCM01.LAB.LOCAL", "LAB.LOCAL", "LAB", "site_server"),
		mockAsset(models.AssetManagementPoint, "SCCM01", "SCCM01.LAB.LOCAL", "LAB.LOCAL", "LAB", "management_point"),
		mockAsset(models.AssetDistributionPoint, "DP01", "DP01.LAB.LOCAL", "LAB.LOCAL", "LAB", "distribution_point"),
		mockAsset(models.AssetPXEServicePoint, "DP01", "DP01.LAB.LOCAL", "LAB.LOCAL", "LAB", "pxe_service_point"),
		mockAsset(models.AssetSQLServer, "SQL01", "SQL01.LAB.LOCAL", "LAB.LOCAL", "LAB", "site_database"),
		mockAsset(models.AssetClient, "WS01", "WS01.LAB.LOCAL", "LAB.LOCAL", "LAB", "client"),
	}
	byKind := map[models.AssetKind]models.Asset{}
	for _, a := range assets {
		byKind[a.Kind] = a
	}
	ev := mockEvidence("mock.sccm.discovery", "synthetic_topology", "Synthetic SCCM topology", "Imaginary LAB.LOCAL SCCM environment generated locally; no network activity occurred.", byKind[models.AssetSite].ID, false, map[string]any{"site_code": "LAB", "asset_count": len(assets)})
	rels := []models.Relationship{
		{FromID: byKind[models.AssetDomain].ID, ToID: byKind[models.AssetSite].ID, Type: models.RelationshipContains, Confidence: models.ConfidenceConfirmed},
		{FromID: byKind[models.AssetSiteServer].ID, ToID: byKind[models.AssetManagementPoint].ID, Type: models.RelationshipHostsRole, Confidence: models.ConfidenceConfirmed},
		{FromID: byKind[models.AssetManagementPoint].ID, ToID: byKind[models.AssetSiteServer].ID, Type: models.RelationshipDependsOn, Confidence: models.ConfidenceHigh},
		{FromID: byKind[models.AssetDistributionPoint].ID, ToID: byKind[models.AssetPXEServicePoint].ID, Type: models.RelationshipHostsRole, Confidence: models.ConfidenceConfirmed},
		{FromID: byKind[models.AssetSiteServer].ID, ToID: byKind[models.AssetSQLServer].ID, Type: models.RelationshipDependsOn, Confidence: models.ConfidenceConfirmed},
		{FromID: byKind[models.AssetClient].ID, ToID: byKind[models.AssetManagementPoint].ID, Type: models.RelationshipCommunicatesWith, Confidence: models.ConfidenceHigh},
	}
	for i := range rels {
		rels[i].Properties = map[string]string{"mock": "true"}
		rels[i].EvidenceIDs = []string{ev.ID}
		rels[i].Prepare()
	}
	caps := []models.Capability{
		{Name: "dns_resolution", Available: true, Reason: "Synthetic names are considered resolvable for the mock workflow", Source: source, EvidenceIDs: []string{ev.ID}},
		{Name: "http_authenticated", Available: true, Reason: "Synthetic mock execution context only; no credential was used", Source: source, EvidenceIDs: []string{ev.ID}},
	}
	for i := range caps {
		caps[i].Prepare()
	}
	return &modules.Result{Assets: assets, Capabilities: caps, Evidence: []models.Evidence{ev}, Relationships: rels, Warnings: []string{"mock discovery data only; no SCCM systems were contacted"}}, nil
}

type assessmentDefinition struct {
	name, description, rule, title, summary string
	kind                                    models.AssetKind
	severity                                models.Severity
	confidence                              models.Confidence
	requirement                             string
	hypothetical                            bool
}

func (d assessmentDefinition) Metadata() modules.Metadata {
	m := modules.Metadata{Name: d.name, Description: d.description, Category: modules.CategoryAssessment, Safety: modules.SafetySafe, SupportedAssetTypes: []models.AssetKind{d.kind}}
	if d.requirement != "" {
		m.Requirements = []modules.Requirement{{Capability: d.requirement}}
	}
	return m
}
func (d assessmentDefinition) Applicable(_ context.Context, _ modules.RunContext, a *models.Asset) (bool, string) {
	if a == nil {
		return false, "requires a discovered asset"
	}
	if a.Kind != d.kind {
		return false, "unsupported asset type"
	}
	return true, ""
}
func (d assessmentDefinition) Run(ctx context.Context, run modules.RunContext, a *models.Asset) (*modules.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ev := mockEvidence(d.name, "mock_observation", d.title, d.summary, a.ID, d.hypothetical, map[string]any{"asset_fqdn": a.FQDN, "profile": run.Profile})
	f := models.Finding{RuleID: d.rule, Title: d.title, Summary: d.summary, Description: "Synthetic assessment result produced to exercise CinderPath's normalized finding pipeline. It is not evidence of a real vulnerability.", Severity: d.severity, Confidence: d.confidence, AssetIDs: []string{a.ID}, EvidenceIDs: []string{ev.ID}, Tags: []string{"mock", "sccm"}, Remediation: "Validate the condition against the authorized environment and apply least privilege and SCCM hardening guidance."}
	f.Prepare(time.Now())
	return &modules.Result{Evidence: []models.Evidence{ev}, Findings: []models.Finding{f}}, nil
}

type managementPointModule struct{ assessmentDefinition }

func (managementPointModule) Metadata() modules.Metadata {
	return assessmentDefinition{name: "mock.assess.management_point", description: "Records synthetic management point reachability", rule: "MOCK-MP-REACHABLE", kind: models.AssetManagementPoint, requirement: "dns_resolution"}.Metadata()
}
func (managementPointModule) Applicable(c context.Context, r modules.RunContext, a *models.Asset) (bool, string) {
	return assessmentDefinition{kind: models.AssetManagementPoint}.Applicable(c, r, a)
}
func (managementPointModule) Run(c context.Context, r modules.RunContext, a *models.Asset) (*modules.Result, error) {
	return assessmentDefinition{name: "mock.assess.management_point", rule: "MOCK-MP-REACHABLE", title: "Management point identified and reachable", summary: "Mock observation: SCCM01.LAB.LOCAL is modeled as a reachable management point.", kind: models.AssetManagementPoint, severity: models.SeverityInformational, confidence: models.ConfidenceConfirmed}.Run(c, r, a)
}

type distributionPointModule struct{ assessmentDefinition }

func (distributionPointModule) Metadata() modules.Metadata {
	return assessmentDefinition{name: "mock.assess.distribution_point", description: "Models read-only distribution point content enumeration", rule: "MOCK-DP-ENUM", kind: models.AssetDistributionPoint, requirement: "http_authenticated"}.Metadata()
}
func (distributionPointModule) Applicable(c context.Context, r modules.RunContext, a *models.Asset) (bool, string) {
	return assessmentDefinition{kind: models.AssetDistributionPoint}.Applicable(c, r, a)
}
func (distributionPointModule) Run(c context.Context, r modules.RunContext, a *models.Asset) (*modules.Result, error) {
	return assessmentDefinition{name: "mock.assess.distribution_point", rule: "MOCK-DP-ENUM", title: "Distribution point permits content enumeration", summary: "Mock observation: DP01 exposes a synthetic, read-only content listing.", kind: models.AssetDistributionPoint, severity: models.SeverityLow, confidence: models.ConfidenceHigh}.Run(c, r, a)
}

type pxeModule struct{ assessmentDefinition }

func (pxeModule) Metadata() modules.Metadata {
	return assessmentDefinition{name: "mock.assess.pxe", description: "Records synthetic PXE capability", rule: "MOCK-PXE-DETECTED", kind: models.AssetPXEServicePoint}.Metadata()
}
func (pxeModule) Applicable(c context.Context, r modules.RunContext, a *models.Asset) (bool, string) {
	return assessmentDefinition{kind: models.AssetPXEServicePoint}.Applicable(c, r, a)
}
func (pxeModule) Run(c context.Context, r modules.RunContext, a *models.Asset) (*modules.Result, error) {
	return assessmentDefinition{name: "mock.assess.pxe", rule: "MOCK-PXE-DETECTED", title: "PXE functionality detected", summary: "Mock observation: DP01 is modeled with an SCCM PXE service point.", kind: models.AssetPXEServicePoint, severity: models.SeverityInformational, confidence: models.ConfidenceConfirmed}.Run(c, r, a)
}

type policyExposureModule struct{ assessmentDefinition }

func (policyExposureModule) Metadata() modules.Metadata {
	return assessmentDefinition{name: "mock.assess.policy_exposure", description: "Models a hypothetical policy exposure without collecting secrets", rule: "MOCK-POLICY-EXPOSURE", kind: models.AssetClient, requirement: "http_authenticated", hypothetical: true}.Metadata()
}
func (policyExposureModule) Applicable(c context.Context, r modules.RunContext, a *models.Asset) (bool, string) {
	return assessmentDefinition{kind: models.AssetClient}.Applicable(c, r, a)
}
func (policyExposureModule) Run(ctx context.Context, run modules.RunContext, a *models.Asset) (*modules.Result, error) {
	base := assessmentDefinition{name: "mock.assess.policy_exposure", rule: "MOCK-POLICY-EXPOSURE", title: "Hypothetical policy credential exposure", summary: "Hypothetical mock condition: a policy reference could expose reusable administrative material; no secret exists or was recovered.", kind: models.AssetClient, severity: models.SeverityHigh, confidence: models.ConfidenceMedium, hypothetical: true}
	r, err := base.Run(ctx, run, a)
	if err != nil {
		return nil, err
	}
	assets, err := run.Store.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	var mp *models.Asset
	for i := range assets {
		if assets[i].Kind == models.AssetManagementPoint {
			mp = &assets[i]
			break
		}
	}
	if mp == nil {
		return nil, fmt.Errorf("mock management point not found")
	}
	cap := models.Capability{Name: "mock_policy_credential_available", Available: true, Reason: "Hypothetical marker only; no credential or secret was produced", Source: base.name, AssetID: a.ID, EvidenceIDs: []string{r.Evidence[0].ID}}
	cap.Prepare()
	rel := models.Relationship{FromID: a.ID, ToID: mp.ID, Type: models.RelationshipCanAccess, Properties: map[string]string{"mock": "true", "hypothetical": "true"}, EvidenceIDs: []string{r.Evidence[0].ID}, Confidence: models.ConfidenceMedium}
	rel.Prepare()
	r.Capabilities = []models.Capability{cap}
	r.Relationships = []models.Relationship{rel}
	return r, nil
}

type correlationModule struct{}

func (correlationModule) Metadata() modules.Metadata {
	return modules.Metadata{Name: "mock.correlate.attack_paths", Description: "Correlates stored mock facts into attack paths", Category: modules.CategoryCorrelation, Safety: modules.SafetySafe, Requirements: []modules.Requirement{{Capability: "mock_policy_credential_available"}}}
}
func (correlationModule) Applicable(context.Context, modules.RunContext, *models.Asset) (bool, string) {
	return true, ""
}
func (correlationModule) Run(ctx context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	assets, err := run.Store.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	findings, err := run.Store.ListFindings(ctx)
	if err != nil {
		return nil, err
	}
	rels, err := run.Store.ListRelationships(ctx)
	if err != nil {
		return nil, err
	}
	caps, err := run.Store.ListCapabilities(ctx)
	if err != nil {
		return nil, err
	}
	var exposure *models.Finding
	for i := range findings {
		if findings[i].RuleID == "MOCK-POLICY-EXPOSURE" {
			exposure = &findings[i]
			break
		}
	}
	if exposure == nil {
		return &modules.Result{Warnings: []string{"no policy exposure finding available for correlation"}}, nil
	}
	capOK := false
	var capEvidence []string
	for _, c := range caps {
		if c.Name == "mock_policy_credential_available" && c.Available {
			capOK = true
			capEvidence = append(capEvidence, c.EvidenceIDs...)
		}
	}
	if !capOK {
		return &modules.Result{}, nil
	}
	var end string
	for _, a := range assets {
		if a.Kind == models.AssetSiteServer {
			end = a.ID
			break
		}
	}
	if end == "" || len(exposure.AssetIDs) == 0 {
		return &modules.Result{}, nil
	}
	steps, evidence, ok := findPath(exposure.AssetIDs[0], end, rels)
	if !ok {
		return &modules.Result{Warnings: []string{"mock exposure could not be connected to a site server"}}, nil
	}
	evidence = unique(append(append(evidence, exposure.EvidenceIDs...), capEvidence...))
	p := models.AttackPath{Title: "Hypothetical policy exposure to SCCM administrative access", Summary: "Correlated mock facts connect a modeled client policy exposure to the SCCM site server. This path is synthetic and requires real-world validation.", Severity: models.SeverityHigh, Confidence: models.ConfidenceMedium, StartNodeID: exposure.AssetIDs[0], EndNodeID: end, Steps: steps, EvidenceIDs: evidence}
	p.Prepare()
	return &modules.Result{AttackPaths: []models.AttackPath{p}}, nil
}

func findPath(start, end string, rels []models.Relationship) ([]models.AttackPathStep, []string, bool) {
	type state struct {
		id       string
		steps    []models.AttackPathStep
		evidence []string
	}
	q := []state{{id: start}}
	seen := map[string]bool{start: true}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if cur.id == end {
			return cur.steps, cur.evidence, true
		}
		for _, r := range rels {
			if r.FromID != cur.id || seen[r.ToID] {
				continue
			}
			seen[r.ToID] = true
			step := models.AttackPathStep{Order: len(cur.steps) + 1, FromID: r.FromID, ToID: r.ToID, RelationshipType: r.Type, Description: fmt.Sprintf("%s %s %s", r.FromID, r.Type, r.ToID), EvidenceIDs: r.EvidenceIDs}
			q = append(q, state{id: r.ToID, steps: append(append([]models.AttackPathStep{}, cur.steps...), step), evidence: append(append([]string{}, cur.evidence...), r.EvidenceIDs...)})
		}
	}
	return nil, nil, false
}
func unique(in []string) []string {
	m := map[string]bool{}
	var out []string
	for _, v := range in {
		if v != "" && !m[v] {
			m[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
