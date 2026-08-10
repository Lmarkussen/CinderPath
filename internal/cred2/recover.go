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
func RecoverLocal(ctx context.Context) (Credential, error) {
	return RecoverLocalForTechnique(ctx, "CRED-2")
}

// RecoverLocalForTechnique is the shared current-client NAA recovery primitive.
// The technique label is used only for truthful operator-facing prerequisite
// and recovery errors; the acquisition and decryption path is identical.
func RecoverLocalForTechnique(ctx context.Context, technique string) (Credential, error) {
	if technique == "" {
		technique = "CRED-2"
	}
	return recoverLocal(ctx, technique)
}
