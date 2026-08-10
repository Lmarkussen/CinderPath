package recon5

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseResponsePositiveAndZeroResult(t *testing.T) {
	got, err := ParseResponse([]byte(`{"value":[{"UniqueUserName":"SCCMLAB\\alice","ResourceName":"CLIENT","ResourceID":42,"Sources":"UDA","CreationTime":"2026-01-01T00:00:00Z"}]}`))
	if err != nil || len(got.Records) != 1 || got.Records[0].Username != `SCCMLAB\alice` || got.Records[0].Device != "CLIENT" || got.Records[0].ResourceID != 42 {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	zero, err := ParseResponse([]byte(`{"value":[]}`))
	if err != nil || len(zero.Records) != 0 || zero.Truncated {
		t.Fatalf("zero result=%+v err=%v", zero, err)
	}
}

func TestParseResponseBoundedAndTruncated(t *testing.T) {
	rows := make([]map[string]any, maxRecords+1)
	for i := range rows {
		rows[i] = map[string]any{"UniqueUserName": "SCCMLAB\\user", "ResourceName": "CLIENT"}
	}
	b, _ := json.Marshal(map[string]any{"value": rows})
	got, err := ParseResponse(b)
	if err != nil || len(got.Records) != maxRecords || !got.Truncated {
		t.Fatalf("bounded result=%+v err=%v", got, err)
	}
}

func TestParseResponseRejectsMalformedAndOversizedFields(t *testing.T) {
	if _, err := ParseResponse([]byte(`{"value":`)); err == nil {
		t.Fatal("malformed response accepted")
	}
	long := strings.Repeat("x", 1024)
	got, err := ParseResponse([]byte(`{"value":[{"UniqueUserName":"` + long + `"}]}`))
	if err != nil || len(got.Records) != 1 || len(got.Records[0].Username) != 512 {
		t.Fatalf("bounded field=%+v err=%v", got, err)
	}
	if _, err := ParseResponse([]byte(`{"value":[{"Other":"value"}]}`)); err == nil {
		t.Fatal("unexpected schema accepted")
	}
}

func TestFixedProviderPathAndQuery(t *testing.T) {
	if ProviderPath != "/AdminService/wmi/SMS_UserMachineRelationship" || QueryPath() != ProviderPath+"?%24top=129" {
		t.Fatalf("path=%q query=%q", ProviderPath, QueryPath())
	}
	if got := QueryPathForUser(`SCCMLAB\\does-not-exist`); !strings.Contains(got, "%24filter=") || !strings.Contains(got, "does-not-exist") {
		t.Fatalf("filtered query=%q", got)
	}
}

func TestClassifyHTTPErrorDoesNotExposeSecrets(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{"auth", "Kerberos authentication rejected by ConfigMgr (Negotiate)", "authentication failed"},
		{"authz", "Kerberos authentication succeeded but ConfigMgr authorization was denied", "authorization denied"},
		{"transport", "dial tcp: timeout", "transport failed"},
	} {
		got := classifyHTTPError(errors.New(tc.input + " password=should-not-appear"))
		if !strings.Contains(got.Error(), tc.want) || strings.Contains(got.Error(), "should-not-appear") {
			t.Fatalf("%s: %v", tc.name, got)
		}
	}
}
