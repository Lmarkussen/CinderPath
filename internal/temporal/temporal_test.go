package temporal

import (
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
)

func TestLatestRunCurrentOutsideScopeSkippedAndStale(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	old := models.Run{ID: "old", Command: "discover", StartedAt: now.Add(-48 * time.Hour), Status: models.RunCompleted}
	latest := models.Run{ID: "latest", Command: "discover", StartedAt: now.Add(-time.Hour), Status: models.RunCompleted}
	cancelled := models.Run{ID: "cancelled", Command: "discover", StartedAt: now, Status: models.RunCancelled}
	assets := []models.Asset{{ID: "current", LastObservedRunID: "latest", LastSeen: now.Add(-time.Hour), Properties: map[string]string{"normalized_target": "mp.lab"}}, {ID: "outside", LastObservedRunID: "old", LastSeen: now.Add(-40 * 24 * time.Hour), Properties: map[string]string{"normalized_target": "old.lab"}}}
	ev := []models.Evidence{{ID: "dns", Type: "dns_resolution", AssetID: "current", RunID: "latest", CollectedAt: now.Add(-time.Hour)}, {ID: "ldap", Type: "ldap_sccm_object", AssetID: "outside", RunID: "old", CollectedAt: now.Add(-40 * 24 * time.Hour)}}
	exec := []models.ModuleExecution{{RunID: "latest", ModuleName: "live.sccm.http_routes", Status: models.ModuleExecutionSkipped}}
	got := Analyze(Input{Runs: []models.Run{old, latest, cancelled}, Assets: assets, Evidence: ev, Executions: exec, Now: now, AssetDays: 30, EvidenceDays: 30})
	if got.LatestDiscoveryRun == nil || got.LatestDiscoveryRun.ID != "latest" {
		t.Fatalf("latest %#v", got.LatestDiscoveryRun)
	}
	assertState(t, got, "asset_seen_in_latest_run", "current", models.TemporalCurrent)
	assertState(t, got, "asset_missing_from_latest_run", "outside", models.TemporalNotInLatestScope)
	assertState(t, got, "ldap_reference_current", "outside", models.TemporalStale)
	for _, o := range got.Observations {
		if o.Type == "endpoint_missing_from_latest_run" {
			t.Fatal("skipped stage produced missing endpoint")
		}
	}
}

func TestEndpointMissingOnlySuccessfulStageAndConflicts(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	runs := []models.Run{{ID: "latest", Command: "discover", StartedAt: now, Status: models.RunCompleted}}
	assets := []models.Asset{{ID: "a", LastObservedRunID: "latest", LastSeen: now, Properties: map[string]string{"normalized_target": "mp.lab"}}}
	ev := []models.Evidence{{ID: "route", Type: "sccm_http_route", AssetID: "a", RunID: "old", CollectedAt: now.Add(-time.Hour), Data: map[string]any{"origin": "https://mp.lab"}}, {ID: "r1", Type: "role", AssetID: "a", Data: map[string]any{"role": "management_point", "site_codes": []string{"AAA"}}}, {ID: "r2", Type: "role", AssetID: "a", Data: map[string]any{"role": "distribution_point", "site_codes": []string{"BBB"}}}}
	exec := []models.ModuleExecution{{RunID: "latest", ModuleName: "live.sccm.http_routes", Status: models.ModuleExecutionSuccess}}
	got := Analyze(Input{Runs: runs, Assets: assets, Evidence: ev, Executions: exec, Now: now, AssetDays: 30, EvidenceDays: 30})
	assertState(t, got, "endpoint_missing_from_latest_run", "a", models.TemporalMissingLatest)
	assertState(t, got, "historical_role_conflict", "a", models.TemporalConflicting)
	assertState(t, got, "historical_site_code_conflict", "a", models.TemporalConflicting)
}
func assertState(t *testing.T, r Result, typ, id string, want models.TemporalState) {
	t.Helper()
	for _, o := range r.Observations {
		if o.Type == typ && o.AssetID == id {
			if o.State != want {
				t.Fatalf("%s/%s=%s want %s", typ, id, o.State, want)
			}
			return
		}
	}
	t.Fatalf("missing %s/%s in %#v", typ, id, r.Observations)
}
