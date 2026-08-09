package planner

import (
	"github.com/Lmarkussen/CinderPath/internal/models"
	"testing"
	"time"
)

func TestCredentialPlanSchedulesLDAPWhenFactsMissing(t *testing.T) {
	p := Resolve(Input{Technique: "CRED-2", Provider: "live", DomainController: "DC.SCCM.LAB", Username: "user", Now: time.Now()})
	if len(p.Modules) == 0 || p.Modules[0] != "live.ldap.rootdse" {
		t.Fatalf("%+v", p)
	}
}
func TestCurrentEvidenceSkipsLDAP(t *testing.T) {
	now := time.Now()
	p := Resolve(Input{Technique: "CRED-2", Provider: "live", DomainController: "DC", Username: "user", Now: now, Evidence: []models.Evidence{{Type: "ldap_rootdse", RunID: "run-current", CollectedAt: now, Data: map[string]any{"server": "DC"}}, {Type: "ldap_sccm_object", RunID: "run-current", CollectedAt: now}}})
	for _, d := range p.Prerequisites {
		if d.State == Collect {
			t.Fatalf("unexpected collection: %+v", p)
		}
	}
}

func TestCredentialPlanRequiresExistingClientIdentityAndPolicyEndpoint(t *testing.T) {
	p := Resolve(Input{Technique: "CRED-2", Provider: "live", DomainController: "DC", Username: "user", Now: time.Now()})
	want := map[Fact]State{ClientIdentity: OperatorInput, PolicyEndpoint: OperatorInput}
	for _, d := range p.Prerequisites {
		if state, ok := want[d.Fact]; ok && d.State != state {
			t.Fatalf("%s: got %s, want %s: %+v", d.Fact, d.State, state, p)
		}
	}
}

func TestCurrentRunEvidenceIsDistinguished(t *testing.T) {
	now := time.Now()
	p := Resolve(Input{Technique: "CRED-2", Provider: "live", DomainController: "DC", Username: "user", CurrentRun: "run-current", Now: now, Evidence: []models.Evidence{{Type: "ldap_rootdse", RunID: "run-current", CollectedAt: now, Data: map[string]any{"server": "DC"}}, {Type: "ldap_sccm_object", RunID: "run-current", CollectedAt: now}}})
	if p.Prerequisites[1].State != Current {
		t.Fatalf("%+v", p.Prerequisites)
	}
}

func TestReplannedEvidenceIncludesProvenanceAndPolicyEndpoint(t *testing.T) {
	now := time.Now()
	p := Resolve(Input{Technique: "CRED-2", Provider: "live", Target: "SCCM.LAB", DomainController: "DC.SCCM.LAB", Username: "user", CurrentRun: "run-prerequisite", Now: now, Evidence: []models.Evidence{
		{Type: "ldap_rootdse", RunID: "run-prerequisite", CollectedAt: now, Data: map[string]any{"server": "DC.SCCM.LAB"}},
		{Type: "ldap_sccm_object", RunID: "run-prerequisite", CollectedAt: now, Data: map[string]any{"referenced_hosts": []string{"MECM.SCCM.LAB"}}},
	}})
	states := map[Fact]Decision{}
	for _, decision := range p.Prerequisites {
		states[decision.Fact] = decision
	}
	for _, fact := range []Fact{RootDSE, SiteCode, ManagementPt, PolicyEndpoint} {
		if states[fact].State != Current || states[fact].SourceRun != "run-prerequisite" {
			t.Fatalf("%s: %+v", fact, states[fact])
		}
	}
}
func TestStaleEvidenceIsTruthful(t *testing.T) {
	p := Resolve(Input{Technique: "CRED-2", Provider: "mock", Now: time.Now(), Evidence: []models.Evidence{{Type: "ldap_rootdse", CollectedAt: time.Now().Add(-48 * time.Hour)}}, EvidenceMaxAge: time.Hour})
	if p.Prerequisites[1].State != Stale {
		t.Fatalf("%+v", p.Prerequisites)
	}
}
func TestExplicitReconTargetsDoNotNeedLDAP(t *testing.T) {
	for _, id := range []string{"RECON-2", "RECON-3"} {
		p := Resolve(Input{Technique: id, Target: "MECM.SCCM.LAB", Now: time.Now()})
		for _, d := range p.Prerequisites {
			if d.Module != "" {
				t.Fatalf("%s: %+v", id, p)
			}
		}
	}
}

func TestExplicitlyDisabledLDAPBlocksSafeCollection(t *testing.T) {
	disabled := false
	p := Resolve(Input{Technique: "CRED-2", Provider: "live", DomainController: "DC.SCCM.LAB", Username: "user", AllowSafeLDAP: &disabled, Now: time.Now()})
	for _, decision := range p.Prerequisites {
		if decision.Fact == RootDSE && decision.State != Blocked {
			t.Fatalf("RootDSE=%+v", decision)
		}
		if decision.State == Collect {
			t.Fatalf("unexpected collection with LDAP disabled: %+v", p)
		}
	}
}

func TestDirectoryEvidenceFromAnotherControllerIsNotReused(t *testing.T) {
	now := time.Now()
	p := Resolve(Input{Technique: "CRED-2", Provider: "live", DomainController: "DC.SCCM.LAB", Username: "user", Now: now, Evidence: []models.Evidence{
		{Type: "ldap_rootdse", RunID: "run-other", CollectedAt: now, Data: map[string]any{"server": "OTHER.SCCM.LAB"}},
		{Type: "ldap_sccm_object", RunID: "run-other", CollectedAt: now},
	}})
	for _, decision := range p.Prerequisites {
		if decision.Fact == SiteCode || decision.Fact == ManagementPt {
			if decision.State != Collect {
				t.Fatalf("%s reused mismatched evidence: %+v", decision.Fact, decision)
			}
		}
	}
}
