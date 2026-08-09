package terminal

import (
	"bytes"
	"strings"
	"testing"
)

func TestModesAndSemanticStyles(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	r := New(Always, &bytes.Buffer{})
	if !r.Enabled() || !strings.Contains(r.Success("ok"), "\x1b[32m") || !strings.Contains(r.Warning("warn"), "\x1b[33m") || !strings.Contains(r.Failure("bad"), "\x1b[31m") || !strings.Contains(r.Target("host"), "\x1b[36m") || !strings.Contains(r.Secret("secret"), "\x1b[95m") {
		t.Fatal("semantic color missing")
	}
	if New(Auto, &bytes.Buffer{}).Enabled() {
		t.Fatal("non-TTY auto must be plain")
	}
	if !NewWithTTY(Auto, true).Enabled() {
		t.Fatal("TTY auto must be colored")
	}
	if New(Never, &bytes.Buffer{}).Enabled() {
		t.Fatal("never must be plain")
	}
}
func TestNoColorOverridesAuto(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if New(Auto, &bytes.Buffer{}).Enabled() {
		t.Fatal("NO_COLOR must disable auto")
	}
	if New(Always, &bytes.Buffer{}).Enabled() {
		t.Fatal("NO_COLOR must disable explicit color")
	}
}
