//go:build !windows

package cred2

import (
	"context"
	"errors"
)

func recoverLocal(_ context.Context, technique string) (Credential, error) {
	return Credential{}, errors.New(technique + " local recovery requires Windows on an SCCM client")
}
