package live

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
)

type sccmTestStore struct {
	assets       []models.Asset
	capabilities []models.Capability
	evidence     []models.Evidence
	findings     []models.Finding
}

func (s *sccmTestStore) ListAssets(context.Context) ([]models.Asset, error) { return s.assets, nil }
func (s *sccmTestStore) ListCapabilities(context.Context) ([]models.Capability, error) {
	return s.capabilities, nil
}
func (s *sccmTestStore) ListEvidence(context.Context) ([]models.Evidence, error) {
	return s.evidence, nil
}
func (s *sccmTestStore) ListFindings(context.Context) ([]models.Finding, error) {
	return s.findings, nil
}
func (s *sccmTestStore) ListRelationships(context.Context) ([]models.Relationship, error) {
	return nil, nil
}
func (s *sccmTestStore) ListAttackPaths(context.Context) ([]models.AttackPath, error) {
	return nil, nil
}

func TestLiveSCCMModuleOrderMetadataAndNoProfileSkip(t *testing.T) {
	modulesList := All(Options{})
	var names []string
	for _, module := range modulesList {
		metadata := module.Metadata()
		names = append(names, metadata.Name)
		if strings.HasPrefix(metadata.Name, "live.sccm.") && (metadata.Category != modules.CategoryDiscovery || metadata.Safety != modules.SafetySafe || len(metadata.SupportedAssetTypes) != 0) {
			t.Fatalf("metadata=%+v", metadata)
		}
	}
	want := []string{"live.scope.normalize", "live.dns.resolve", "live.network.probe", "live.http.profile", "live.ldap.rootdse", "live.ldap.sccm_directory", "live.sccm.http_routes", "live.sccm.management_point", "live.sccm.distribution_point", "live.roles.infer", "live.sccm.correlate"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("module order=%v", names)
	}
	store := &sccmTestStore{}
	run := modules.RunContext{Store: store}
	for _, module := range []modules.Module{&sccmHTTPRoutesModule{}, &sccmManagementPointModule{}, &sccmDistributionPointModule{}} {
		applicable, reason := module.Applicable(context.Background(), run, nil)
		if applicable || reason == "" {
			t.Fatalf("module=%s applicable=%t reason=%q", module.Metadata().Name, applicable, reason)
		}
	}
	asset := models.Asset{Kind: models.AssetUnknown, FQDN: "mp01.lab.local", Properties: map[string]string{"observation_origin": "live", "normalized_target": "mp01.lab.local", "open_ports": "80"}}
	asset.Prepare(time.Now())
	profile := models.Evidence{Type: "http_profile", Title: "root", SourceModule: "live.http.profile", AssetID: asset.ID, Data: map[string]any{"endpoint": "http://mp01.lab.local:80/", "status_code": 200}}
	profile.Prepare(time.Now())
	store.assets = []models.Asset{asset}
	store.evidence = []models.Evidence{profile}
	if applicable, reason := (&sccmHTTPRoutesModule{}).Applicable(context.Background(), run, nil); !applicable || reason != "" {
		t.Fatalf("successfully profiled standard origin was skipped: applicable=%t reason=%q", applicable, reason)
	}
	profile.Data["endpoint"] = "http://mp01.lab.local:8080/"
	profile.Prepare(time.Now())
	store.evidence = []models.Evidence{profile}
	if applicable, _ := (&sccmHTTPRoutesModule{}).Applicable(context.Background(), run, nil); applicable {
		t.Fatal("custom SCCM port was accepted for route probing")
	}
}

func TestManagementPointClassifierFindingsAndDeduplication(t *testing.T) {
	asset := models.Asset{Kind: models.AssetUnknown, FQDN: "mp01.lab.local", Hostname: "mp01", Properties: map[string]string{"observation_origin": "live", "normalized_target": "mp01.lab.local"}, Source: "test", Confidence: models.ConfidenceLow}
	asset.Prepare(time.Now())
	validatedObservation := routeObservation{AssetID: asset.ID, Origin: "https://mp01.lab.local:443", Scheme: "https", Host: "mp01.lab.local", Port: 443, RouteID: sccmRouteMPList, Path: "/SMS_MP/.sms_aut?MPLIST", Method: "GET", StatusCode: 200, ParserOutcome: "valid_sccm_mp_list", ReferencedHosts: []string{"mp02.lab.local"}, SiteCodes: []string{"LAB"}, AccessState: SCCMAccessState{TransportReachable: true, HTTPResponseReceived: true, AnonymousRequest: true, UsableReadAccess: true, ProtocolValidated: true}}
	routeEvidence := routeEvidenceFromObservation(validatedObservation, "live.sccm.http_routes")
	store := &sccmTestStore{assets: []models.Asset{asset}, evidence: []models.Evidence{routeEvidence}}
	run := modules.RunContext{Store: store}
	module := &sccmManagementPointModule{}
	first, err := module.Run(context.Background(), run, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := module.Run(context.Background(), run, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Findings) != 1 || first.Findings[0].RuleID != "DISCOVERY-SCCM-MP-ENDPOINT" || first.Findings[0].Confidence != models.ConfidenceHigh {
		t.Fatalf("findings=%+v", first.Findings)
	}
	if first.Findings[0].ID != second.Findings[0].ID || first.Evidence[0].ID != second.Evidence[0].ID {
		t.Fatal("repeated classification IDs are not deterministic")
	}
	db, err := database.Open(context.Background(), filepath.Join(t.TempDir(), "dedup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for iteration := 0; iteration < 2; iteration++ {
		if created, err := db.UpsertEvidence(context.Background(), &routeEvidence); err != nil || (iteration == 1 && created) {
			t.Fatalf("route evidence iteration=%d created=%t err=%v", iteration, created, err)
		}
	}
	for iteration, result := range []*modules.Result{first, second} {
		for index := range result.Evidence {
			if created, err := db.UpsertEvidence(context.Background(), &result.Evidence[index]); err != nil || (iteration == 1 && created) {
				t.Fatalf("evidence iteration=%d created=%t err=%v", iteration, created, err)
			}
		}
		for index := range result.Findings {
			if created, err := db.UpsertFinding(context.Background(), &result.Findings[index]); err != nil || (iteration == 1 && created) {
				t.Fatalf("finding iteration=%d created=%t err=%v", iteration, created, err)
			}
		}
		for index := range result.Capabilities {
			if created, err := db.UpsertCapability(context.Background(), &result.Capabilities[index]); err != nil || (iteration == 1 && created) {
				t.Fatalf("capability iteration=%d created=%t err=%v", iteration, created, err)
			}
		}
	}
	storedEvidence, _ := db.ListEvidence(context.Background())
	storedFindings, _ := db.ListFindings(context.Background())
	storedCapabilities, _ := db.ListCapabilities(context.Background())
	if len(storedEvidence) != 2 || len(storedFindings) != 1 || len(storedCapabilities) != len(first.Capabilities) {
		t.Fatalf("evidence=%d findings=%d capabilities=%d", len(storedEvidence), len(storedFindings), len(storedCapabilities))
	}
}

func TestManagementPointClassifierConservativeOutcomes(t *testing.T) {
	asset := models.Asset{Kind: models.AssetUnknown, FQDN: "mp01.lab.local", Properties: map[string]string{"observation_origin": "live", "normalized_target": "mp01.lab.local"}}
	asset.Prepare(time.Now())
	t.Run("generic response creates no finding", func(t *testing.T) {
		observation := routeObservation{AssetID: asset.ID, Origin: "http://mp01.lab.local:80", RouteID: sccmRouteMPList, Method: "GET", StatusCode: 200, ParserOutcome: "generic_html", UnverifiedReason: "generic_html", AccessState: SCCMAccessState{TransportReachable: true, HTTPResponseReceived: true, AnonymousRequest: true}}
		store := &sccmTestStore{assets: []models.Asset{asset}, evidence: []models.Evidence{routeEvidenceFromObservation(observation, "live.sccm.http_routes")}}
		result, err := (&sccmManagementPointModule{}).Run(context.Background(), modules.RunContext{Store: store}, nil)
		if err != nil || len(result.Findings) != 0 || result.Evidence[0].Data["classification"] != "low_confidence_route_behavior" {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("authentication plus LDAP is medium confidence", func(t *testing.T) {
		observation := routeObservation{AssetID: asset.ID, Origin: "http://mp01.lab.local:80", RouteID: sccmRouteMPList, Method: "GET", StatusCode: 401, ParserOutcome: "empty_response", AccessState: SCCMAccessState{TransportReachable: true, HTTPResponseReceived: true, AnonymousRequest: true, AuthenticationRequested: true}}
		route := routeEvidenceFromObservation(observation, "live.sccm.http_routes")
		ldap := models.Evidence{Type: "ldap_sccm_object", Title: "LDAP MP", SourceModule: "live.ldap.sccm_directory", Data: map[string]any{"inferred_roles": []string{"management_point"}, "referenced_hosts": []string{"mp01.lab.local"}}}
		ldap.Prepare(time.Now())
		store := &sccmTestStore{assets: []models.Asset{asset}, evidence: []models.Evidence{route, ldap}}
		result, err := (&sccmManagementPointModule{}).Run(context.Background(), modules.RunContext{Store: store}, nil)
		if err != nil || len(result.Findings) != 1 || result.Findings[0].Confidence != models.ConfidenceMedium {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		for _, capability := range result.Capabilities {
			if capability.Name == "sccm_mp_authentication_required" && !capability.Available {
				t.Fatal("authentication requirement was not represented")
			}
			if strings.Contains(capability.Name, "authenticated") {
				t.Fatalf("unexpected authenticated capability: %s", capability.Name)
			}
		}
	})
}
