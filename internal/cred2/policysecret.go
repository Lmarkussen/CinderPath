// Package cred2 implements the deliberately narrow local recovery path for
// Configuration Manager Network Access Account PolicySecret values.
package cred2

import (
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

const (
	maxPolicySecretXML = 16 << 10
	sccmWrapperLength  = 4
	minDPAPIBlobLength = 44
)

// PolicySecret is a validated PolicySecret envelope. DPAPIBlob is sensitive
// and must remain in memory only.
type PolicySecret struct {
	DPAPIBlob []byte
}

type policySecretXML struct {
	XMLName xml.Name `xml:"PolicySecret"`
	Version string   `xml:"Version,attr"`
	Value   string   `xml:",chardata"`
}

// ParsePolicySecret accepts only the SCCM PolicySecret v1 envelope used by
// CCM_NetworkAccessAccount. It removes the four-byte SCCM wrapper and returns
// the remaining DPAPI blob.
func ParsePolicySecret(value string) (PolicySecret, error) {
	if len(value) == 0 {
		return PolicySecret{}, errors.New("PolicySecret is empty")
	}
	if len(value) > maxPolicySecretXML {
		return PolicySecret{}, fmt.Errorf("PolicySecret exceeds %d bytes", maxPolicySecretXML)
	}
	var envelope policySecretXML
	if err := xml.Unmarshal([]byte(value), &envelope); err != nil {
		return PolicySecret{}, fmt.Errorf("invalid PolicySecret XML: %w", err)
	}
	if envelope.XMLName.Space != "" || envelope.XMLName.Local != "PolicySecret" || envelope.Version != "1" {
		return PolicySecret{}, errors.New("unexpected PolicySecret envelope")
	}
	if envelope.Value == "" || strings.TrimSpace(envelope.Value) != envelope.Value {
		return PolicySecret{}, errors.New("PolicySecret protected value is missing or contains whitespace")
	}
	if len(envelope.Value)%2 != 0 {
		return PolicySecret{}, errors.New("PolicySecret protected value has odd-length hexadecimal data")
	}
	decoded := make([]byte, hex.DecodedLen(len(envelope.Value)))
	if _, err := hex.Decode(decoded, []byte(envelope.Value)); err != nil {
		return PolicySecret{}, errors.New("PolicySecret protected value is not hexadecimal")
	}
	if len(decoded) < sccmWrapperLength+minDPAPIBlobLength {
		return PolicySecret{}, errors.New("PolicySecret is too short for an SCCM wrapper and DPAPI blob")
	}
	return PolicySecret{DPAPIBlob: decoded[sccmWrapperLength:]}, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
