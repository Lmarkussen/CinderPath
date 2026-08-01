package buildtool

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestMakeBuildCreatesProjectLocalBinary(t *testing.T) {
	root := repositoryRoot(t)
	cmd := exec.Command("make", "build")
	cmd.Dir = root
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make build: %v\n%s", err, output)
	}
	info, err := os.Stat(filepath.Join(root, "bin", "cinderpath"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatal("bin/cinderpath is not executable")
	}
}

func TestMakeCheckIncludesRequiredValidation(t *testing.T) {
	root := repositoryRoot(t)
	cmd := exec.Command("make", "-n", "check")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n check: %v\n%s", err, output)
	}
	text := string(output)
	for _, required := range []string{"gofmt -l", "go vet ./...", "go test ./...", "go build"} {
		if !strings.Contains(text, required) {
			t.Fatalf("make check does not include %q:\n%s", required, text)
		}
	}
}
func TestAuthDryRunTargetCannotEnableAuthentication(t *testing.T) {
	root := repositoryRoot(t)
	cmd := exec.Command("make", "-n", "auth-dry-run", "ARGS=--identity-id cred --endpoint https://example.invalid")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "auth validate --dry-run") || strings.Contains(text, "--enable-auth-validation") {
		t.Fatalf("unsafe auth dry-run target:\n%s", text)
	}
}
