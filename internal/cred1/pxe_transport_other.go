//go:build !linux || !cgo

package cred1

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// AcquirePXEReply is unavailable outside Linux with cgo/libpcap. This exact
// receive path is required only because the observed WDS reply has a bad UDP
// checksum that the normal Linux UDP stack rejects.
func AcquirePXEReply(context.Context, string, netip.Addr, time.Duration) (PXEReply, error) {
	return PXEReply{}, errors.New("CRED-1 PXE receive requires a Linux binary built with cgo and libpcap because WDS replies with invalid UDP checksums bypass the normal UDP stack; run CinderPath on Linux, install the libpcap development package, and rebuild")
}
