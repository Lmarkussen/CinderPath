// Package outputpolicy centralizes operator-facing output decisions.
package outputpolicy

import "strings"

const RedactedMarker = "<redacted>"

// Policy controls rendering only. It never changes the underlying observation
// or result held by an assessment.
type Policy struct {
	RedactSecrets bool
}

type Metadata struct {
	SecretsRedacted bool `json:"secrets_redacted"`
}

func (p Policy) Metadata() Metadata { return Metadata{SecretsRedacted: p.RedactSecrets} }

func (p Policy) Secret(value string) string {
	if p.RedactSecrets && value != "" {
		return RedactedMarker
	}
	return value
}

// RedactValue returns a recursively copied JSON-compatible value. It is used
// at report/render boundaries; persistent observations are not rewritten.
func (p Policy) RedactValue(value any) any {
	if !p.RedactSecrets {
		return value
	}
	return redactValue(value)
}

func redactValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			secret := isSecretKey(key)
			if secret {
				out[key] = RedactedMarker
				continue
			}
			out[key] = redactValue(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactValue(item)
		}
		return out
	case string:
		return v
	default:
		return value
	}
}

func isSecretKey(key string) bool {
	k := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
	if k == "secrets_redacted" || strings.Contains(k, "reference") || strings.Contains(k, "fingerprint") || strings.HasSuffix(k, "_source") {
		return false
	}
	for _, part := range []string{"password", "passwd", "token", "private_key", "privatekey", "session_key", "sessionkey", "api_key", "apikey", "secret", "credential_blob", "protected_variable", "plaintext_value", "secret_value"} {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}
