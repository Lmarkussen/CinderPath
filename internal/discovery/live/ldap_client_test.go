package live

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestParseRootDSE(t *testing.T) {
	r := parseRootDSE(map[string][]string{"defaultNamingContext": {"DC=LAB,DC=LOCAL"}, "dnsHostName": {"dc01.lab.local"}, "supportedLDAPVersion": {"3"}})
	if r.DefaultNamingContext != "DC=LAB,DC=LOCAL" || r.DNSHostName != "dc01.lab.local" {
		t.Fatalf("root=%+v", r)
	}
	if domainFromDN(r.DefaultNamingContext) != "LAB.LOCAL" {
		t.Fatal(domainFromDN(r.DefaultNamingContext))
	}
}
func TestParseSCCMObject(t *testing.T) {
	o := parseDirectoryObject("CN=MP,CN=System Management,DC=lab,DC=local", map[string][]string{"objectClass": {"mSSMSManagementPoint"}, "serviceBindingInformation": {"http://sccm01.lab.local/"}, "keywords": {"Management Point"}})
	if len(o.Roles) != 1 || o.Roles[0] != "management_point" || len(o.Hosts) != 1 || o.Hosts[0] != "sccm01.lab.local" {
		t.Fatalf("object=%+v", o)
	}
}

func TestRECON1EvidenceAndSiteDeduplication(t *testing.T) {
	objects := []directoryObject{
		{DN: "CN=Site,CN=System Management,DC=lab,DC=local", Attributes: map[string][]string{"objectClass": {"mSSMSSite"}, "mSMSSiteCode": {"P01"}}, Roles: []string{"site_server"}},
		{DN: "CN=MP,CN=System Management,DC=lab,DC=local", Attributes: map[string][]string{"objectClass": {"mSMSManagementPoint"}}, Roles: []string{"management_point"}, Hosts: []string{"mp01.lab.local"}},
	}
	r := recon1Evidence(objects, rootDSE{DefaultNamingContext: "DC=lab,DC=local"}, "test")
	if len(r.Evidence) != 1 || len(r.Findings) != 1 || r.Evidence[0].Data["publishing_state"] != "sccm_ad_publishing_confirmed" {
		t.Fatalf("result=%+v", r)
	}
	if got := r.Evidence[0].Data["sites_observed"].([]string); len(got) != 1 || got[0] != "P01" {
		t.Fatalf("sites=%v", got)
	}
}

func TestRECON1SiteCodeFallbackFromCommonCN(t *testing.T) {
	obj := directoryObject{Attributes: map[string][]string{"cn": {"SMS-Site-P01"}}}
	if got := siteCodeForObject(obj); got != "P01" {
		t.Fatalf("site code=%q", got)
	}
}

func TestLDAPFailureIsModuleError(t *testing.T) {
	r := ldapFailure(LDAPOptions{Server: "dc.example.test"}, context.DeadlineExceeded)
	if len(r.Errors) != 1 || r.Errors[0].Message != context.DeadlineExceeded.Error() {
		t.Fatalf("errors=%+v", r.Errors)
	}
}
func TestDNSResultNormalization(t *testing.T) {
	got := mergeUnique([]string{"192.0.2.1", "2001:0db8::1"}, []string{"192.0.2.1"})
	if len(got) != 2 || got[1] != "2001:db8::1" {
		t.Fatalf("got=%v", got)
	}
}
func TestResolverConfigParsing(t *testing.T) {
	servers, search := parseResolverConfig(strings.NewReader("nameserver 192.0.2.53\nsearch lab.local example.test\n"))
	if len(servers) != 1 || servers[0] != "192.0.2.53" || len(search) != 2 {
		t.Fatalf("servers=%v search=%v", servers, search)
	}
}
func TestLDAPConnectCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := connectLDAP(ctx, LDAPOptions{Server: "127.0.0.1", SearchTimeout: time.Second}); err == nil {
		t.Fatal("expected cancellation")
	}
}
