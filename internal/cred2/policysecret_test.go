package cred2

import (
	"fmt"
	"strings"
	"testing"
)

func envelope(n int) string {
	return fmt.Sprintf(`<PolicySecret Version="1"><![CDATA[%s]]></PolicySecret>`, strings.Repeat("ab", n))
}

func TestParsePolicySecret(t *testing.T) {
	for _, n := range []int{sccmWrapperLength + minDPAPIBlobLength, sccmWrapperLength + minDPAPIBlobLength + 19} {
		got, err := ParsePolicySecret(envelope(n))
		if err != nil || len(got.DPAPIBlob) != n-sccmWrapperLength {
			t.Fatalf("length %d: blob=%d err=%v", n, len(got.DPAPIBlob), err)
		}
	}
}

func TestParsePolicySecretRejectsInvalidInput(t *testing.T) {
	valid := envelope(sccmWrapperLength + minDPAPIBlobLength)
	for name, value := range map[string]string{
		"malformed XML":        `<PolicySecret Version="1">`,
		"wrong root":           `<Other Version="1"><![CDATA[abab]]></Other>`,
		"wrong version":        strings.Replace(valid, `Version="1"`, `Version="2"`, 1),
		"missing value":        `<PolicySecret Version="1"></PolicySecret>`,
		"invalid hex":          strings.Replace(valid, "ab", "xz", 1),
		"odd hex":              `<PolicySecret Version="1"><![CDATA[abc]]></PolicySecret>`,
		"whitespace":           `<PolicySecret Version="1"><![CDATA[ ab]]></PolicySecret>`,
		"truncated DPAPI blob": envelope(sccmWrapperLength + minDPAPIBlobLength - 1),
		"oversized":            `<PolicySecret Version="1"><![CDATA[` + strings.Repeat("ab", maxPolicySecretXML) + `]]></PolicySecret>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePolicySecret(value); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}
