package cred2

import "context"

const (
	NAANamespace = `root\ccm\policy\machine\actualconfig`
	NAAClass     = "CCM_NetworkAccessAccount"
)

// Credential is transient local recovery output. Callers must not persist it.
type Credential struct {
	Username string
	Password string
}

// RecoverLocal reads the one current NAA policy object and decrypts its two
// PolicySecret values. Platform implementations enforce their prerequisites.
func RecoverLocal(ctx context.Context) (Credential, error) { return recoverLocal(ctx) }
