package live

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParsePorts(t *testing.T) {
	p, err := ParsePorts("80,443,8000-8002,80")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{80, 443, 8000, 8001, 8002}
	if len(p) != len(want) {
		t.Fatalf("ports=%v", p)
	}
	for i := range p {
		if p[i] != want[i] {
			t.Fatalf("ports=%v", p)
		}
	}
}
func TestLDAPPasswordEnvironmentIsRedacted(t *testing.T) {
	t.Setenv("CP_TEST_PASSWORD", "super-secret-fixture")
	o := LDAPOptions{Enabled: true, User: "lab\\user", PasswordEnv: "CP_TEST_PASSWORD"}
	if err := ResolveLDAPPassword(&o); err != nil {
		t.Fatal(err)
	}
	if o.Password != "super-secret-fixture" || o.PasswordReference != "env:CP_TEST_PASSWORD" {
		t.Fatal("resolved metadata incorrect")
	}
	b, _ := json.Marshal(o)
	if strings.Contains(string(b), "super-secret-fixture") {
		t.Fatal("password serialized")
	}
}
func TestParsePortsRejectsInvalid(t *testing.T) {
	for _, v := range []string{"0", "65536", "90-80", "x", "1-9000"} {
		if _, err := ParsePorts(v); err == nil {
			t.Fatalf("accepted %q", v)
		}
	}
}
