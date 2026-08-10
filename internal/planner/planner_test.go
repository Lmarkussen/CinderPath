package planner

import (
	"strings"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
)

func TestCredentialPlanSchedulesLDAPWhenFactsMissing(t *testing.T) {
	p := Resolve(Input{Technique: "CRED-2", Provider: "live", DomainController: "DC.SCCM.LAB", Username: "user", Now: time.Now()})
	if len(p.Modules) == 0 || p.Modules[0] != "live.ldap.rootdse" {
		t.Fatalf("%+v", p)
	}
}

func TestCRED2LocalPlanUsesClientRuntimePrerequisites(t *testing.T) {
	p := Resolve(Input{Technique: "CRED-2", Provider: "live", Target: "CLIENT", LocalExecution: true, Now: time.Now()})
	if len(p.Modules) != 0 || len(p.Prerequisites) != 4 {
		t.Fatalf("unexpected local CRED-2 plan: %+v", p)
	}
	want := map[Fact]bool{LocalExecution: true, SCCMClient: true, SystemContext: true, CurrentNAA: true}
	for _, d := range p.Prerequisites {
		if !want[d.Fact] || d.State != Current {
			t.Fatalf("unexpected local prerequisite: %+v", d)
		}
	}
}

func TestCRED3LocalPlanUsesCurrentClientPrerequisites(t *testing.T) {
	p := Resolve(Input{Technique: "CRED-3", Provider: "live", Target: "CLIENT", LocalExecution: true, Now: time.Now()})
	if len(p.Modules) != 0 || len(p.Prerequisites) != 4 {
		t.Fatalf("unexpected local CRED-3 plan: %+v", p)
	}
	for _, d := range p.Prerequisites {
		if d.State != Current {
			t.Fatalf("unexpected local CRED-3 prerequisite: %+v", d)
		}
	}
}

func TestOrchestrationMetadataKeepsFamilyRootAndChildRolesDistinct(t *testing.T) {
	if got := OrchestrationFor("RECON-4"); got.TargetRole != "sccm_client_via_management_point" || got.Execution != "management_point_authority" || !got.Implemented {
		t.Fatalf("RECON-4 orchestration=%+v", got)
	}
	if got := OrchestrationFor("CRED-2"); got.TargetRole != "sccm_client" || got.Execution != "local_sccm_client" || !got.Implemented {
		t.Fatalf("CRED-2 orchestration=%+v", got)
	}
	if got := OrchestrationFor("RECON-5"); got.TargetRole != "management_point_sms_provider" || got.Execution != "management_point_authority" || !got.Implemented {
		t.Fatalf("RECON-5 orchestration=%+v", got)
	}
}

func TestRECON5RequiresProviderIdentityAndUsesManagementPointRole(t *testing.T) {
	p := Resolve(Input{Technique: "RECON-5", Provider: "live", Target: "MECM.SCCM.LAB", Now: time.Now()})
	if len(p.Prerequisites) != 2 || p.Prerequisites[0].Fact != SMSProvider || p.Prerequisites[1].Fact != Identity {
		t.Fatalf("RECON-5 prerequisites=%+v", p.Prerequisites)
	}
	spec := OrchestrationFor("RECON-5")
	if !spec.Implemented || spec.TargetRole != "management_point_sms_provider" || spec.Capability != "sms_provider" {
		t.Fatalf("RECON-5 spec=%+v", spec)
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

func TestImportedClientIdentitySatisfiesCRED2Prerequisite(t *testing.T) {
	p := Resolve(Input{Technique: "CRED-2", Provider: "live", DomainController: "DC.SCCM.LAB", Username: "user", ClientID: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", ClientIdentitySource: "local_sccm_client_artifact", Now: time.Now()})
	for _, decision := range p.Prerequisites {
		if decision.Fact == ClientIdentity && (decision.State != Current || !strings.Contains(decision.Reason, "local_sccm_client_artifact")) {
			t.Fatalf("client identity=%+v", decision)
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

func TestDefensiveTechniqueCannotEnterPlanner(t *testing.T) {
	p := Resolve(Input{Technique: "PREVENT-1", Provider: "live", Now: time.Now()})
	if len(p.Prerequisites) != 1 || p.Prerequisites[0].State != Unsupported || len(p.Modules) != 0 {
		t.Fatalf("defensive technique received a plan: %+v", p)
	}
}
