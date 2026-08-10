//go:build !linux || !cgo

package cred1

// CheckCapturePrerequisites reports the real platform limitation without
// attempting a packet capture.
func CheckCapturePrerequisites(string) CapturePrerequisites {
	return CapturePrerequisites{Reason: "CRED-1 requires a Linux cgo build with libpcap because the observed WDS reply has an invalid UDP checksum", Remediation: "run the native Linux cgo binary with libpcap installed", Supported: false}
}
