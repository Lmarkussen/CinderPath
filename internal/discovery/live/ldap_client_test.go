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
