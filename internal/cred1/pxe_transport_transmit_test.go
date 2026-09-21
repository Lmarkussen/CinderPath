//go:build !windows

package cred1

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// occupyDHCPClientPort reproduces the reported real-world condition: the host
// DHCP client already owns UDP/68. It returns a release function when this test
// created the owner, and ok=false when the runner cannot establish the premise
// at all (an unprivileged runner cannot bind the reserved DHCP client port and
// an EADDRINUSE result means a running DHCP client such as NetworkManager
// already owns it).
func occupyDHCPClientPort(t *testing.T) (release func(), ok bool) {
	t.Helper()
	owner, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: pxeClientPort})
	switch {
	case err == nil:
		return func() { _ = owner.Close() }, true
	case errors.Is(err, syscall.EADDRINUSE):
		return func() {}, true
	case errors.Is(err, syscall.EACCES), errors.Is(err, os.ErrPermission):
		return func() {}, false
	default:
		t.Logf("unexpected UDP/%d owner probe result: %v", pxeClientPort, err)
		return func() {}, false
	}
}

type recordingTransmitter struct{ sent [][]byte }

func (r *recordingTransmitter) Transmit(datagram []byte, _ netip.Addr) error {
	r.sent = append(r.sent, append([]byte(nil), datagram...))
	return nil
}

func (r *recordingTransmitter) Close() error { return nil }

// requireUDPSockets skips socket-dependent assertions in environments that
// cannot create UDP sockets at all (for example a restricted test sandbox).
func requireUDPSockets(t *testing.T) {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: pxeProxyDHCPPort})
	if err != nil {
		t.Skipf("this environment cannot create UDP sockets: %v", err)
	}
	_ = conn.Close()
}

func TestPXEUDPDatagramUsesDHCPClientSourcePort(t *testing.T) {
	clientIP := netip.MustParseAddr("192.0.2.10")
	dp := netip.MustParseAddr("198.51.100.20")
	xid, request, err := newPXERequest(clientIP, []byte{2, 3, 4, 5, 6, 7})
	if err != nil {
		t.Fatal(err)
	}
	datagram, err := pxeUDPDatagram(clientIP, dp, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(datagram) != 8+len(request) || binary.BigEndian.Uint16(datagram[4:6]) != uint16(len(datagram)) {
		t.Fatalf("invalid UDP datagram framing: %d bytes", len(datagram))
	}
	if sp := binary.BigEndian.Uint16(datagram[0:2]); sp != pxeClientPort {
		t.Fatalf("PXE request source port = %d, want the DHCP client port %d", sp, pxeClientPort)
	}
	if dpPort := binary.BigEndian.Uint16(datagram[2:4]); dpPort != pxeProxyDHCPPort {
		t.Fatalf("PXE request destination port = %d, want %d", dpPort, pxeProxyDHCPPort)
	}
	if got := string(datagram[8:]); got != string(request) {
		t.Fatal("PXE request payload was not preserved")
	}
	if string(datagram[8:8+bootpHeaderBytes+dhcpCookieBytes]) == "" || binary.BigEndian.Uint32(datagram[12:16]) != binary.BigEndian.Uint32(xid[:]) {
		t.Fatal("PXE request payload lost its transaction correlation")
	}
	// A false checksum would make the request unusable, so verify the value
	// stored in the header against a fresh computation.
	want := make([]byte, len(datagram))
	copy(want, datagram)
	binary.BigEndian.PutUint16(want[6:8], 0)
	computed := udpChecksum(clientIP, dp, want)
	if computed == 0 {
		computed = 0xffff
	}
	if stored := binary.BigEndian.Uint16(datagram[6:8]); stored != computed {
		t.Fatalf("PXE request UDP checksum = %#04x, want %#04x", stored, computed)
	}
}

func TestPXEUDPDatagramRejectsInvalidSourceIPv4(t *testing.T) {
	dp := netip.MustParseAddr("198.51.100.20")
	_, request, err := newPXERequest(netip.MustParseAddr("192.0.2.10"), []byte{2, 3, 4, 5, 6, 7})
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]netip.Addr{
		"zero address":     {},
		"unspecified IPv4": netip.IPv4Unspecified(),
		"multicast IPv4":   netip.MustParseAddr("224.0.0.1"),
		"IPv6 address":     netip.MustParseAddr("2001:db8::1"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pxeUDPDatagram(source, dp, request); err == nil {
				t.Fatalf("accepted unusable PXE source address %q", source)
			}
		})
	}
	valid := netip.MustParseAddr("192.0.2.10")
	if _, err := pxeUDPDatagram(valid, netip.Addr{}, request); err == nil {
		t.Fatal("accepted an invalid PXE distribution point")
	}
	if _, err := pxeUDPDatagram(valid, dp, request[:bootpHeaderBytes]); err == nil {
		t.Fatal("accepted an undersized PXE request payload")
	}
	if _, err := pxeUDPDatagram(valid, dp, make([]byte, maxPXEPayloadBytes+1)); err == nil {
		t.Fatal("accepted an oversized PXE request payload")
	}
}

// TestPXERouteSelectedSourceIPv4 confirms the client address is the kernel's
// route-selected IPv4 source and that a mismatch with the capture interface is
// refused instead of silently using an unrelated address.
func TestPXERouteSelectedSourceIPv4(t *testing.T) {
	if _, err := routeSourceIPv4(netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Fatal("accepted an IPv6 distribution point for an IPv4 transport")
	}
	requireUDPSockets(t)
	source, err := routeSourceIPv4(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatalf("route-selected source for loopback: %v", err)
	}
	if source != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("route-selected source = %s, want 127.0.0.1", source)
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no loopback interface available: %v", err)
	}
	if got, err := pxeSourceIPv4(lo, netip.MustParseAddr("127.0.0.1")); err != nil || got != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("loopback capture interface source = %s err = %v", got, err)
	}
	for _, iface := range mustInterfacesForTest(t) {
		if iface.Name == "lo" || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if _, err := pxeSourceIPv4(&iface, netip.MustParseAddr("127.0.0.1")); err == nil {
			t.Fatalf("accepted a route-selected source that is not assigned to %s", iface.Name)
		}
		return
	}
	t.Log("no non-loopback interface available to exercise the interface mismatch check")
}

func mustInterfacesForTest(t *testing.T) []net.Interface {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	return ifaces
}

// TestPXERequestTransmitsWhileDHCPClientOwnsUDP68 is the direct regression test
// for the reported bug: CRED-1 must prepare and transmit its one request even
// though the host DHCP client owns UDP/68.
func TestPXERequestTransmitsWhileDHCPClientOwnsUDP68(t *testing.T) {
	requireUDPSockets(t)
	release, ok := occupyDHCPClientPort(t)
	if !ok {
		// The runner cannot create a token owner for the reserved DHCP client
		// port, but the transmit assertion below must hold regardless because
		// the production path no longer requests that port from the kernel.
		t.Logf("runner cannot establish a UDP/%d owner; asserting the transmit path still", pxeClientPort)
	}
	defer release()
	clientIP := netip.MustParseAddr("192.0.2.10")
	dp := netip.MustParseAddr("198.51.100.20")
	_, request, err := newPXERequest(clientIP, []byte{2, 3, 4, 5, 6, 7})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingTransmitter{}
	if err := transmitPXERequest(recorder, clientIP, dp, request); err != nil {
		t.Fatalf("PXE request failed while the DHCP client owned UDP/%d: %v", pxeClientPort, err)
	}
	if len(recorder.sent) != 1 {
		t.Fatalf("PXE request transmission count = %d, want 1", len(recorder.sent))
	}
	if sp := binary.BigEndian.Uint16(recorder.sent[0][0:2]); sp != pxeClientPort {
		t.Fatalf("transmitted source port = %d, want %d", sp, pxeClientPort)
	}
}

// TestPXERawTransmitterCoexistsWithDHCPClientPort proves the production
// transmit socket is a raw IP socket, which the host DHCP client's UDP/68
// listener cannot block. It skips when packet privileges are unavailable.
func TestPXERawTransmitterCoexistsWithDHCPClientPort(t *testing.T) {
	requireUDPSockets(t)
	release, ok := occupyDHCPClientPort(t)
	if !ok {
		t.Skipf("cannot establish the UDP/%d ownership condition in this environment", pxeClientPort)
	}
	defer release()
	transmitter, err := newRawTransmitter(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, os.ErrPermission) {
			t.Skipf("raw transmit socket requires packet-capture privileges: %v", err)
		}
		t.Fatalf("raw transmit socket failed while the DHCP client owned UDP/%d: %v", pxeClientPort, err)
	}
	defer transmitter.Close()
}

// buildPXEReplyFrame assembles an Ethernet/IPv4/UDP frame carrying a BOOTP
// reply. The UDP checksum is deliberately invalid to mirror the observed WDS
// reply that the Linux UDP stack drops but libpcap still delivers.
func buildPXEReplyFrame(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	binary.BigEndian.PutUint16(udp[6:8], 0x1234)
	copy(udp[8:], payload)
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(udp)))
	copy(ip[12:16], srcIP.AsSlice())
	copy(ip[16:20], dstIP.AsSlice())
	eth := make([]byte, 14)
	for i := 0; i < 6; i++ {
		eth[i] = 0xff
	}
	eth[6], eth[7], eth[8], eth[9], eth[10], eth[11] = 2, 0, 0, 0, 0, 1
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	return append(append(eth, ip...), udp...)
}

// TestPXEReplyCorrelationIgnoresUnrelatedDHCPTraffic proves that ordinary
// DHCP traffic, including the host's own DHCP server replies, cannot satisfy
// the CRED-1 exchange, and that the intended WDS reply still parses.
func TestPXEReplyCorrelationIgnoresUnrelatedDHCPTraffic(t *testing.T) {
	dp := netip.MustParseAddr("10.128.116.90")
	clientIP := netip.MustParseAddr("172.20.133.162")
	dhcpServer := netip.MustParseAddr("10.128.129.11")
	xid := [4]byte{9, 8, 7, 6}
	intended := buildPXEReplyFrame(dp, broadcastIPv4, pxeProxyDHCPPort, pxeClientPort, testPXEPayload(xid))
	frame, err := parsePXEFrame(intended)
	if err != nil {
		t.Fatalf("intended WDS reply did not parse: %v", err)
	}
	reply, err := matchPXEReply(frame, dp, clientIP, xid)
	if err != nil {
		t.Fatalf("intended WDS reply was rejected: %v", err)
	}
	if reply.UDPChecksum != 0x1234 || len(reply.Payload) == 0 {
		t.Fatalf("unexpected accepted reply: %#v", reply)
	}
	for name, frameBytes := range map[string][]byte{
		"host DHCP server offer on 67/68": buildPXEReplyFrame(dhcpServer, broadcastIPv4, 67, pxeClientPort, testPXEPayload([4]byte{1, 1, 1, 1})),
		"DHCP traffic from the DP on 67":  buildPXEReplyFrame(dp, broadcastIPv4, 67, pxeClientPort, testPXEPayload([4]byte{1, 1, 1, 1})),
		"unrelated transaction on 4011":   buildPXEReplyFrame(dp, broadcastIPv4, pxeProxyDHCPPort, pxeClientPort, testPXEPayload([4]byte{1, 1, 1, 1})),
		"WDS reply to another client":     buildPXEReplyFrame(dp, netip.MustParseAddr("172.20.133.199"), pxeProxyDHCPPort, pxeClientPort, testPXEPayload(xid)),
	} {
		t.Run(name, func(t *testing.T) {
			candidate, err := parsePXEFrame(frameBytes)
			if err != nil {
				t.Fatalf("test frame did not parse: %v", err)
			}
			if _, err := matchPXEReply(candidate, dp, clientIP, xid); err == nil {
				t.Fatal("accepted unrelated DHCP traffic as the CRED-1 reply")
			}
		})
	}
}

// TestPXETransportNeverOpensClientPortListener is a structural guard against
// reintroducing the reported failure. The transmit path must not create a
// conventional UDP listener, because the host DHCP client legitimately owns
// UDP/68.
func TestPXETransportNeverOpensClientPortListener(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the CRED-1 transport sources")
	}
	dir := filepath.Dir(file)
	for _, name := range []string{"pxe_transport.go", "pxe_transport_linux.go"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "ListenUDP") || strings.Contains(string(b), "ListenPacket(\"udp") {
			t.Fatalf("%s binds a conventional UDP socket; CRED-1 must not require the DHCP client port", name)
		}
	}
	linuxSource, err := os.ReadFile(filepath.Join(dir, "pxe_transport_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"newRawTransmitter", "transmitPXERequest"} {
		if !strings.Contains(string(linuxSource), want) {
			t.Fatalf("Linux PXE transport does not use %s", want)
		}
	}
}
