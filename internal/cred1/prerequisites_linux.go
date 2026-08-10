//go:build linux && cgo

package cred1

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket/pcap"
)

// CheckCapturePrerequisites performs a bounded local check for the actual
// CRED-1 receive dependency. It never installs packages or changes privileges.
func CheckCapturePrerequisites(target string) CapturePrerequisites {
	out := CapturePrerequisites{Supported: true}
	if _, err := pcap.FindAllDevs(); err != nil {
		out.Reason = "libpcap is unavailable"
		out.Remediation = "install the distribution libpcap runtime and rebuild/run the Linux cgo binary"
		return out
	}
	out.Libpcap = true
	for _, iface := range interfaceCandidates() {
		if iface != "lo" {
			out.Interface = iface
			break
		}
	}
	if out.Interface == "" {
		out.Reason = "no usable network interface is available for the target"
		out.Remediation = "connect the assessment host to the target network and retry"
		return out
	}
	if hasCaptureCapability() {
		out.CaptureAllowed = true
		return out
	}
	out.Reason = "packet-capture capability is missing"
	out.Remediation = "sudo setcap cap_net_raw,cap_net_admin+eip ./cinderpath"
	out.AutoFixSupported = true
	_ = target // route validation remains owned by the application transport.
	return out
}

func interfaceCandidates() []string {
	ifs, _ := net.Interfaces()
	out := make([]string, 0, len(ifs))
	for _, iface := range ifs {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			out = append(out, iface.Name)
		}
	}
	return out
}

func hasCaptureCapability() bool {
	if os.Geteuid() == 0 {
		return true
	}
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		var value uint64
		if _, err := fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), "%x", &value); err != nil {
			return false
		}
		return value&(1<<12) != 0 && value&(1<<13) != 0
	}
	return false
}
