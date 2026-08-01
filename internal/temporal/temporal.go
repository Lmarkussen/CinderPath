package temporal

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
)

type Input struct {
	Runs                    []models.Run
	Assets                  []models.Asset
	Evidence                []models.Evidence
	Executions              []models.ModuleExecution
	Now                     time.Time
	AssetDays, EvidenceDays int
}
type Result struct {
	LatestDiscoveryRun *models.Run                  `json:"latest_discovery_run,omitempty"`
	Observations       []models.TemporalObservation `json:"observations"`
}

func Analyze(in Input) Result {
	result := Result{Observations: []models.TemporalObservation{}}
	var fallback *models.Run
	for i := range in.Runs {
		r := &in.Runs[i]
		if r.Command == "discover" && (r.Status == models.RunCompleted || r.Status == models.RunCompletedWithErrors) {
			if fallback == nil || r.StartedAt.After(fallback.StartedAt) {
				copy := *r
				fallback = &copy
			}
			if fmt.Sprint(r.Summary["provider"]) == "live" && (result.LatestDiscoveryRun == nil || r.StartedAt.After(result.LatestDiscoveryRun.StartedAt)) {
				copy := *r
				result.LatestDiscoveryRun = &copy
			}
		}
	}
	if result.LatestDiscoveryRun == nil {
		result.LatestDiscoveryRun = fallback
	}
	latest := ""
	if result.LatestDiscoveryRun != nil {
		latest = result.LatestDiscoveryRun.ID
	}
	stage := map[string]models.ModuleExecutionStatus{}
	for _, e := range in.Executions {
		if e.RunID == latest {
			stage[e.ModuleName] = e.Status
		}
	}
	scoped := map[string]bool{}
	for _, a := range in.Assets {
		if a.LastObservedRunID == latest && a.Properties["normalized_target"] != "" {
			scoped[a.ID] = true
		}
	}
	for _, a := range in.Assets {
		state := models.TemporalUnknown
		typ := "asset_seen_in_latest_run"
		reason := "record predates run attribution"
		switch {
		case latest == "":
			reason = "no completed discovery run is available"
		case a.LastObservedRunID == latest:
			state = models.TemporalCurrent
			reason = "asset was emitted by the latest completed discovery run"
		case !scoped[a.ID]:
			state = models.TemporalNotInLatestScope
			typ = "asset_missing_from_latest_run"
			reason = "asset was not proven to be in the latest explicit scope"
		case stage["live.scope.normalize"] == models.ModuleExecutionSuccess:
			state = models.TemporalMissingLatest
			typ = "asset_missing_from_latest_run"
			reason = "asset was in scope and the relevant stage completed, but no observation was emitted"
		}
		if state == models.TemporalCurrent && in.Now.Sub(a.LastSeen) > days(in.AssetDays) {
			state = models.TemporalStale
			reason = "latest asset timestamp exceeds configured age"
		}
		result.Observations = append(result.Observations, models.TemporalObservation{Type: typ, State: state, AssetID: a.ID, LatestRunID: latest, Reason: reason})
	}
	for _, e := range in.Evidence {
		typ := temporalType(e.Type)
		if typ == "" {
			continue
		}
		state := models.TemporalUnknown
		reason := "evidence predates run attribution"
		if e.RunID == latest {
			state = models.TemporalCurrent
			reason = "evidence was collected in latest completed discovery run"
		} else if e.RunID != "" {
			state = models.TemporalStale
			reason = "evidence belongs to an earlier discovery run"
		}
		if in.Now.Sub(e.CollectedAt) > days(in.EvidenceDays) {
			state = models.TemporalStale
			reason = "evidence exceeds configured age"
		}
		result.Observations = append(result.Observations, models.TemporalObservation{Type: typ, State: state, AssetID: e.AssetID, Endpoint: fmt.Sprint(e.Data["origin"]), EvidenceIDs: []string{e.ID}, LatestRunID: latest, Reason: reason})
	}
	// Missing endpoints are asserted only when the asset was in current scope and the route stage succeeded.
	if stage["live.sccm.http_routes"] == models.ModuleExecutionSuccess {
		for _, e := range in.Evidence {
			if e.Type != "sccm_http_route" || e.RunID == latest || !scoped[e.AssetID] {
				continue
			}
			result.Observations = append(result.Observations, models.TemporalObservation{Type: "endpoint_missing_from_latest_run", State: models.TemporalMissingLatest, AssetID: e.AssetID, Endpoint: fmt.Sprint(e.Data["origin"]), EvidenceIDs: []string{e.ID}, LatestRunID: latest, Reason: "endpoint was historically observed on an in-scope asset but the successful latest route stage did not reproduce it"})
		}
	}
	conflicts(in.Evidence, &result)
	sort.Slice(result.Observations, func(i, j int) bool {
		a, b := result.Observations[i], result.Observations[j]
		return strings.Join([]string{a.Type, a.AssetID, a.Endpoint}, "|") < strings.Join([]string{b.Type, b.AssetID, b.Endpoint}, "|")
	})
	return result
}
func temporalType(t string) string {
	switch t {
	case "dns_resolution":
		return "dns_observation_current"
	case "ldap_sccm_object", "ldap_rootdse":
		return "ldap_reference_current"
	case "sccm_mp_protocol", "sccm_http_route":
		return "protocol_validation_current"
	}
	return ""
}
func days(n int) time.Duration {
	if n <= 0 {
		n = 30
	}
	return time.Duration(n) * 24 * time.Hour
}
func conflicts(ev []models.Evidence, r *Result) {
	roles := map[string]map[string][]string{}
	sites := map[string]map[string][]string{}
	for _, e := range ev {
		if e.AssetID == "" {
			continue
		}
		role := fmt.Sprint(e.Data["role"])
		if role != "" {
			if roles[e.AssetID] == nil {
				roles[e.AssetID] = map[string][]string{}
			}
			roles[e.AssetID][role] = append(roles[e.AssetID][role], e.ID)
		}
		for _, site := range anyStrings(e.Data["site_codes"]) {
			if sites[e.AssetID] == nil {
				sites[e.AssetID] = map[string][]string{}
			}
			sites[e.AssetID][site] = append(sites[e.AssetID][site], e.ID)
		}
	}
	for id, v := range roles {
		if len(v) > 1 {
			r.Observations = append(r.Observations, models.TemporalObservation{Type: "historical_role_conflict", State: models.TemporalConflicting, AssetID: id, EvidenceIDs: flatten(v), Reason: "retained evidence contains conflicting historical role observations"})
		}
	}
	for id, v := range sites {
		if len(v) > 1 {
			r.Observations = append(r.Observations, models.TemporalObservation{Type: "historical_site_code_conflict", State: models.TemporalConflicting, AssetID: id, EvidenceIDs: flatten(v), Reason: "retained evidence contains conflicting historical site-code observations"})
		}
	}
}
func anyStrings(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		o := []string{}
		for _, v := range x {
			o = append(o, fmt.Sprint(v))
		}
		return o
	}
	return nil
}
func flatten(m map[string][]string) []string {
	o := []string{}
	for _, v := range m {
		o = append(o, v...)
	}
	sort.Strings(o)
	return o
}
