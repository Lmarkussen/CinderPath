package logging

import "testing"

func TestMaskSecret(t *testing.T) {
	if got := MaskSecret("hunter2"); got != "<redacted:7>" {
		t.Fatalf("got %q", got)
	}
}
