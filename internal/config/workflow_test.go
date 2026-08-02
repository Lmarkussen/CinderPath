package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeFilename(t *testing.T) {
	for in, want := range map[string]string{"lab.local": "lab_local.yaml", "sevenkingdoms.local": "sevenkingdoms_local.yaml", "corp.example.com": "corp_example_com.yaml", "": "cinderpath.yaml", "../LAB///local": "lab_local.yaml"} {
		got, err := NormalizeFilename(in)
		if err != nil || got != want {
			t.Fatalf("NormalizeFilename(%q)=%q,%v want %q", in, got, err, want)
		}
	}
	if _, err := NormalizeFilename("例.local"); err == nil {
		t.Fatal("expected Unicode rejection")
	}
}
func TestWriteAtomicSafeAndNoSecrets(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "lab.yaml")
	c := NewWorkflow("lab.local", ProfileSafe)
	c.Identity.PasswordEnv = "CINDERPATH_TEST_PASSWORD"
	if err := WriteAtomic(p, c, false); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", st.Mode().Perm())
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "secret-value") {
		t.Fatal("secret serialized")
	}
	if err := WriteAtomic(p, c, false); err == nil {
		t.Fatal("expected overwrite refusal")
	}
	if err := WriteAtomic(p, c, true); err != nil {
		t.Fatal(err)
	}
}
func TestProfilesAndValidation(t *testing.T) {
	for _, p := range []Profile{ProfileSafe, ProfileStandard, ProfileAggressive, ProfileYolo, ProfileResearch} {
		c := NewWorkflow("lab.local", p)
		ds := Validate(c)
		if HasErrors(ds) {
			t.Fatalf("%s errors: %#v", p, ds)
		}
		if p == ProfileSafe && c.Workflow.Authentication {
			t.Fatal("safe authentication enabled")
		}
	}
	c := NewWorkflow("lab.local", ProfileSafe)
	c.WorkflowScope.IncludeCIDRs = []string{"bad"}
	if !HasErrors(Validate(c)) {
		t.Fatal("invalid CIDR accepted")
	}
}
