package live

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestLDAPPasswordFileBoundedRead(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{name: "small", data: []byte("fixture-password\r\n"), want: "fixture-password"},
		{name: "exactly 64 KiB", data: []byte(strings.Repeat("x", int(maxLDAPPasswordFileBytes))), want: strings.Repeat("x", int(maxLDAPPasswordFileBytes))},
		{name: "exceeds 64 KiB", data: []byte(strings.Repeat("x", int(maxLDAPPasswordFileBytes)+1)), wantErr: true},
		{name: "empty", data: []byte{}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ldap-password")
			if err := os.WriteFile(path, tt.data, 0o600); err != nil {
				t.Fatal(err)
			}
			opts := LDAPOptions{Enabled: true, PasswordFile: path}
			err := ResolveLDAPPasswordContext(context.Background(), &opts)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "exceeds 65536 bytes") {
					t.Fatalf("error=%v", err)
				}
				if opts.Password != "" || opts.PasswordReference != "" {
					t.Fatal("oversized password material was retained")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if opts.Password != tt.want || opts.PasswordReference != "file:"+path {
				t.Fatalf("password length=%d reference=%q", len(opts.Password), opts.PasswordReference)
			}
		})
	}
}

func TestLDAPPasswordFileCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ldap-password")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts := LDAPOptions{Enabled: true, PasswordFile: path}
	if err := ResolveLDAPPasswordContext(ctx, &opts); err != context.Canceled {
		t.Fatalf("error=%v", err)
	}
	if opts.Password != "" || opts.PasswordReference != "" {
		t.Fatal("cancelled read retained password material")
	}
}
func TestParsePortsRejectsInvalid(t *testing.T) {
	for _, v := range []string{"0", "65536", "90-80", "x", "1-9000"} {
		if _, err := ParsePorts(v); err == nil {
			t.Fatalf("accepted %q", v)
		}
	}
}
