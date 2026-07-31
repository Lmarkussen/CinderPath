package scope

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTargetFileAndNormalization(t *testing.T) {
	p := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(p, []byte("# lab\nSCCM01\n192.0.2.1 # host\n\n"), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := Normalize(Input{TargetFiles: []string{p}, Domain: "LAB.LOCAL", MaxTargets: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Targets) != 2 || d.Targets[0].Value != "192.0.2.1" || d.Targets[1].Value != "sccm01.lab.local" {
		t.Fatalf("targets=%+v", d.Targets)
	}
}
func TestCIDRLimit(t *testing.T) {
	_, err := Normalize(Input{Targets: []string{"10.0.0.0/8"}, MaxTargets: 4096})
	if err == nil {
		t.Fatal("expected limit error")
	}
}
func TestExclusionsWin(t *testing.T) {
	d, err := Normalize(Input{Targets: []string{"192.0.2.0/30", "skip.lab"}, ExcludeHosts: []string{"192.0.2.1", "skip.lab"}, ExcludeCIDRs: []string{"192.0.2.2/32"}, MaxTargets: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Targets) != 2 || d.Targets[0].Value != "192.0.2.0" || d.Targets[1].Value != "192.0.2.3" {
		t.Fatalf("targets=%+v excluded=%v", d.Targets, d.Excluded)
	}
}
func TestNormalizeIPv6AndHost(t *testing.T) {
	v, k, err := NormalizeValue("2001:0db8::1", "")
	if err != nil || v != "2001:db8::1" || k != "ip" {
		t.Fatalf("%q %q %v", v, k, err)
	}
	v, _, err = NormalizeValue("HOST", "Example.COM")
	if err != nil || v != "host.example.com" {
		t.Fatalf("%q %v", v, err)
	}
}
