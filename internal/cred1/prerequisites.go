package cred1

// CapturePrerequisites describes only the local requirements of the bounded
// CRED-1 PXE receive path. It is intentionally metadata-only: checking it does
// not open a capture device or send network traffic.
type CapturePrerequisites struct {
	Supported        bool
	Libpcap          bool
	CaptureAllowed   bool
	Interface        string
	Reason           string
	Remediation      string
	AutoFixSupported bool
}
