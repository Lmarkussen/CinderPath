package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ClientNAAArtifactKind      = "sccm_client_naa_artifact"
	ClientNAANamespace         = `root\ccm\policy\machine\actualconfig`
	ClientNAAClass             = "CCM_NetworkAccessAccount"
	MaxProtectedMaterialLength = 1 << 20
)

// ProtectedMaterial is deliberately metadata-only. Value material is never an
// accepted field in this import format.
type ProtectedMaterial struct {
	Present bool   `yaml:"present" json:"present"`
	State   string `yaml:"material_state" json:"material_state"`
	Length  int    `yaml:"length" json:"length"`
}

type ClientArtifactSource struct {
	Type     string `yaml:"type" json:"type"`
	Verified bool   `yaml:"verified" json:"verified"`
}

// ClientNAAArtifact represents one reviewed, current local WMI observation.
// It cannot represent plaintext recovery and intentionally carries no blobs.
type ClientNAAArtifact struct {
	Kind       string               `yaml:"kind" json:"kind"`
	SourceHost string               `yaml:"source_host" json:"source_host"`
	Domain     string               `yaml:"domain" json:"domain"`
	SiteCode   string               `yaml:"site_code" json:"site_code"`
	Namespace  string               `yaml:"namespace" json:"namespace"`
	Class      string               `yaml:"class" json:"class"`
	CapturedAt string               `yaml:"captured_at" json:"captured_at"`
	Source     ClientArtifactSource `yaml:"source" json:"source"`
	Username   ProtectedMaterial    `yaml:"network_access_username" json:"network_access_username"`
	Password   ProtectedMaterial    `yaml:"network_access_password" json:"network_access_password"`
}

func ParseClientNAAArtifact(b []byte) (ClientNAAArtifact, error) {
	var a ClientNAAArtifact
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	if err := decoder.Decode(&a); err != nil {
		return a, err
	}
	a.Kind = strings.TrimSpace(a.Kind)
	a.SourceHost = strings.TrimSpace(a.SourceHost)
	a.Domain = strings.ToUpper(strings.TrimSpace(a.Domain))
	a.SiteCode = strings.ToUpper(strings.TrimSpace(a.SiteCode))
	a.Namespace = strings.ToLower(strings.TrimSpace(a.Namespace))
	a.Class = strings.TrimSpace(a.Class)
	a.Source.Type = strings.TrimSpace(a.Source.Type)
	if a.Kind != ClientNAAArtifactKind {
		return a, fmt.Errorf("kind must be %q", ClientNAAArtifactKind)
	}
	if a.SourceHost == "" || a.Domain == "" || a.SiteCode == "" || a.CapturedAt == "" || a.Source.Type == "" {
		return a, errors.New("source_host, domain, site_code, captured_at, and source.type are required")
	}
	if !a.Source.Verified {
		return a, errors.New("source.verified must be true for reusable client artifact evidence")
	}
	if _, err := time.Parse(time.RFC3339, a.CapturedAt); err != nil {
		return a, fmt.Errorf("captured_at must be RFC3339: %w", err)
	}
	if a.Namespace != ClientNAANamespace || a.Class != ClientNAAClass {
		return a, errors.New("artifact must be root\\ccm\\policy\\machine\\actualconfig CCM_NetworkAccessAccount")
	}
	if err := validateProtectedMaterial("network_access_username", a.Username); err != nil {
		return a, err
	}
	if err := validateProtectedMaterial("network_access_password", a.Password); err != nil {
		return a, err
	}
	if !a.Username.Present && !a.Password.Present {
		return a, errors.New("artifact has neither protected NAA material property")
	}
	return a, nil
}

func validateProtectedMaterial(name string, m ProtectedMaterial) error {
	if !m.Present {
		if m.Length != 0 || m.State != "" {
			return fmt.Errorf("%s absent material must not have state or length", name)
		}
		return nil
	}
	if m.State != "protected" {
		return fmt.Errorf("%s material_state must be protected", name)
	}
	if m.Length < 1 || m.Length > MaxProtectedMaterialLength {
		return fmt.Errorf("%s length must be between 1 and %d", name, MaxProtectedMaterialLength)
	}
	return nil
}

func (a ClientNAAArtifact) ObservedAt() time.Time {
	t, _ := time.Parse(time.RFC3339, a.CapturedAt)
	return t.UTC()
}
func (a ClientNAAArtifact) Fingerprint() string {
	s := fmt.Sprintf("%s|%s|%s|%s|%t|%s|%d|%t|%s|%d", a.SourceHost, a.Domain, a.SiteCode, a.Namespace, a.Username.Present, a.Username.State, a.Username.Length, a.Password.Present, a.Password.State, a.Password.Length)
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}
