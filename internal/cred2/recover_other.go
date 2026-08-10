//go:build !windows

package cred2

import (
	"context"
	"errors"
)

func recoverLocal(context.Context) (Credential, error) {
	return Credential{}, errors.New("CRED-2 local recovery requires Windows on an SCCM client")
}
