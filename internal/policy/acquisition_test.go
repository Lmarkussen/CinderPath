package policy

import (
	"context"
	"strings"
	"testing"
)

func TestCRED2ContractStaysBlockedWithCompleteReferences(t *testing.T) {
	c := ClientIdentity{Kind: "existing_sccm_client", ClientID: "{11111111-1111-1111-1111-111111111111}"}
	p := PlanCRED2Acquisition("MECM.SCCM.LAB", "P01", c)
	if p.State != BlockedMissingPrerequisite || !strings.Contains(p.Reason, "unverified") || p.Method != "CCM_POST" || p.Route != "/ccm_system/request" {
		t.Fatalf("%+v", p)
	}
}

func TestCRED2ResponseStates(t *testing.T) {
	ctx := context.Background()
	if r, _ := AnalyzeCRED2Response(ctx, 204, "application/xml", nil); r.State != NoPolicyReturned {
		t.Fatalf("%+v", r)
	}
	if r, _ := AnalyzeCRED2Response(ctx, 401, "", nil); r.State != AuthenticationFailed {
		t.Fatalf("%+v", r)
	}
	non := []byte(`<Policy PolicyID="P" PolicyType="Configuration"><Setting Name="Mode" Value="safe"/></Policy>`)
	if r, e := AnalyzeCRED2Response(ctx, 200, "application/xml", non); e != nil || r.State != NonCredentialPolicy {
		t.Fatalf("%+v %v", r, e)
	}
	protected := []byte(`<Policy PolicyID="P" PolicyType="Credential" PolicyCategory="Credential"><Setting Name="ProtectedValue" Value="&lt;PolicySecret&gt;x&lt;/PolicySecret&gt;"/></Policy>`)
	if r, e := AnalyzeCRED2Response(ctx, 200, "application/xml", protected); e != nil || r.State != ProtectedCredential || len(r.Candidates) != 1 {
		t.Fatalf("%+v %v", r, e)
	}
	plain := []byte(`<Policy PolicyID="P" PolicyType="Credential" PolicyCategory="Credential"><Setting Name="AccountName" Value="SCCMLAB\\svc-naa"/><Setting Name="Password" Value="ExampleRecoveredPassword!123"/></Policy>`)
	if r, e := AnalyzeCRED2Response(ctx, 200, "application/xml", plain); e != nil || r.State != RecoveredCredential {
		t.Fatalf("%+v %v", r, e)
	}
	if r, e := AnalyzeCRED2Response(ctx, 200, "application/xml", []byte("<Policy")); e == nil || r.State != ParserFailed {
		t.Fatalf("%+v %v", r, e)
	}
}
