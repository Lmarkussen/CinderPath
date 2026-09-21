package cred1

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

const (
	pxeClientPort      = 68
	pxeProxyDHCPPort   = 4011
	bootpHeaderBytes   = 236
	dhcpCookieBytes    = 4
	maxPXEPayloadBytes = 2048
	// maxPXEObservedFrames bounds the total frames the capture loop inspects.
	// The capture filter is observational (it also shows what the selected DP
	// sent and ICMP addressed to this client), so the bound is work, not
	// correctness: acceptance still requires the exact reply correlation.
	maxPXEObservedFrames          = 64
	maxPXEObservationSignatures   = 4
	maxPXEObservationSummaryBytes = 400
)

var (
	dhcpMagicCookie = [4]byte{99, 130, 83, 99}
	broadcastIPv4   = netip.MustParseAddr("255.255.255.255")
)

// PXEReply is the bounded result of the CRED-1 PXE request/reply exchange.
// Payload is the BOOTP/DHCP payload only; it contains no parsed options yet.
type PXEReply struct {
	TransactionID   [4]byte
	Payload         []byte
	SourceIP        netip.Addr
	DestinationIP   netip.Addr
	SourcePort      uint16
	DestinationPort uint16
	UDPChecksum     uint16
}

// pxeFrame is intentionally smaller than a generic packet representation. It
// contains only fields needed to reject unrelated broadcast replies.
type pxeFrame struct {
	sourceIP, destinationIP     netip.Addr
	sourcePort, destinationPort uint16
	udpChecksum                 uint16
	payload                     []byte
}

func newPXERequest(clientIP netip.Addr, hardwareAddr []byte) ([4]byte, []byte, error) {
	var xid [4]byte
	if !clientIP.Is4() || len(hardwareAddr) != 6 {
		return xid, nil, errors.New("invalid PXE client address")
	}
	if _, err := rand.Read(xid[:]); err != nil {
		return xid, nil, fmt.Errorf("PXE transaction ID: %w", err)
	}
	var machineID [16]byte
	if _, err := rand.Read(machineID[:]); err != nil {
		return xid, nil, fmt.Errorf("PXE client identifier: %w", err)
	}
	p := make([]byte, bootpHeaderBytes, maxPXEPayloadBytes)
	p[0] = 1 // BOOTREQUEST
	p[1] = 1 // Ethernet
	p[2] = byte(len(hardwareAddr))
	copy(p[4:8], xid[:])
	copy(p[12:16], clientIP.AsSlice()) // ciaddr, as observed in the GOAD request
	// The validated ConfigMgr proxy-DHCP request leaves BOOTP chaddr zeroed.
	// The physical source remains the selected interface; PXE identity is
	// carried in option 97. Supplying the interface MAC here changed GOAD WDS
	// reply delivery from the observed broadcast form to unicast.
	p = append(p, dhcpMagicCookie[:]...)
	// The following are the exact PXE request options established from the
	// retained GOAD oracle. This transport does not interpret the reply options.
	p = append(p,
		53, 1, 3, // DHCPREQUEST
		55, 11, 3, 1, 60, 128, 129, 130, 131, 132, 133, 134, 135,
		93, 2, 0, 0, // x86 architecture, as in the observed request
		250, 21, 0x0c, 0x01, 0x01, 0x0d, 0x02, 0x08, 0x00, 0x01, 0x02, 0x00, 0x07, 0x0e, 0x01, 0x01, 0x05, 0x04, 0x00, 0x00, 0x00, 0x11, 0xff,
		60, 9, 'P', 'X', 'E', 'C', 'l', 'i', 'e', 'n', 't',
		97, 17, 0,
	)
	p = append(p, machineID[:]...)
	p = append(p, 255)
	if len(p) > maxPXEPayloadBytes {
		return xid, nil, errors.New("PXE request exceeds payload bound")
	}
	return xid, p, nil
}

func matchPXEReply(frame pxeFrame, dp, clientIP netip.Addr, xid [4]byte) (PXEReply, error) {
	var out PXEReply
	if !dp.Is4() || frame.sourceIP != dp {
		return out, errors.New("PXE reply source does not match DP")
	}
	// Retained GOAD traffic used the IPv4 broadcast address. Current WDS
	// responses to the same exact request use the selected client IPv4 address
	// with a broadcast Ethernet destination. Both are bounded reply forms for
	// this one request; no other destination is accepted.
	if frame.destinationIP != broadcastIPv4 && frame.destinationIP != clientIP {
		return out, errors.New("PXE reply destination does not match request")
	}
	if frame.sourcePort != pxeProxyDHCPPort || frame.destinationPort != pxeClientPort {
		return out, errors.New("PXE reply ports do not match")
	}
	if len(frame.payload) < bootpHeaderBytes+dhcpCookieBytes || len(frame.payload) > maxPXEPayloadBytes {
		return out, errors.New("invalid PXE BOOTP payload size")
	}
	if frame.payload[0] != 2 || frame.payload[1] != 1 || frame.payload[2] != 6 ||
		binary.BigEndian.Uint32(frame.payload[4:8]) != binary.BigEndian.Uint32(xid[:]) ||
		string(frame.payload[bootpHeaderBytes:bootpHeaderBytes+dhcpCookieBytes]) != string(dhcpMagicCookie[:]) {
		return out, errors.New("PXE reply does not match request")
	}
	out = PXEReply{
		TransactionID: xid, Payload: append([]byte(nil), frame.payload...), SourceIP: frame.sourceIP,
		DestinationIP: frame.destinationIP, SourcePort: frame.sourcePort, DestinationPort: frame.destinationPort,
		UDPChecksum: frame.udpChecksum,
	}
	return out, nil
}

// validateSourceIPv4 rejects a source address that cannot carry the one CRED-1
// request. The route-selected client address is used verbatim; the operator
// never supplies it.
func validateSourceIPv4(clientIP netip.Addr) error {
	if !clientIP.IsValid() || !clientIP.Is4() || clientIP.IsUnspecified() || clientIP.IsMulticast() {
		return fmt.Errorf("PXE transport requires a usable route-selected IPv4 source address, got %q", clientIP)
	}
	return nil
}

// routeSourceIPv4 returns the kernel's route-selected IPv4 source address for
// the PXE distribution point. Dialing a UDP socket only performs route
// selection and source-address selection; it transmits nothing.
func routeSourceIPv4(dp netip.Addr) (netip.Addr, error) {
	if !dp.Is4() {
		return netip.Addr{}, fmt.Errorf("PXE transport requires an IPv4 distribution point, got %q", dp)
	}
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dp.AsSlice(), Port: pxeProxyDHCPPort})
	if err != nil {
		return netip.Addr{}, fmt.Errorf("CRED-1 cannot find a route to PXE DP %s; add an IPv4 route to the authorized DP before assessment: %w", dp, err)
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("CRED-1 could not determine the route-selected source address")
	}
	source, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		return netip.Addr{}, errors.New("CRED-1 route-selected source address is unusable")
	}
	source = source.Unmap()
	if err := validateSourceIPv4(source); err != nil {
		return netip.Addr{}, err
	}
	return source, nil
}

// pxeSourceIPv4 resolves the route-selected client address and confirms it is
// assigned to the capture interface. The capture filter, the request ciaddr,
// and the reply correlation therefore all use the same address the kernel
// stamps on the request.
func pxeSourceIPv4(iface *net.Interface, dp netip.Addr) (netip.Addr, error) {
	source, err := routeSourceIPv4(dp)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("PXE interface %s addresses: %w", iface.Name, err)
	}
	for _, addr := range addrs {
		ip, _, splitErr := net.ParseCIDR(addr.String())
		if splitErr != nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil && netip.AddrFrom4([4]byte(ip4)) == source {
			return source, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("CRED-1 route to PXE DP %s selects source %s, which is not assigned to capture interface %s; use a host with an IPv4 interface on the authorized DP route", dp, source, iface.Name)
}

// pxeUDPDatagram builds the complete IPv4 UDP datagram (UDP header plus BOOTP
// payload) for the one CRED-1 request. Constructing the header locally is what
// lets the request carry the conventional DHCP client source port 68 without
// binding it, because on a normal DHCP-managed workstation that port already
// belongs to the host DHCP client (for example NetworkManager).
func pxeUDPDatagram(clientIP, dp netip.Addr, payload []byte) ([]byte, error) {
	if err := validateSourceIPv4(clientIP); err != nil {
		return nil, err
	}
	if !dp.Is4() || dp.IsUnspecified() || dp.IsMulticast() {
		return nil, fmt.Errorf("PXE transport requires a usable IPv4 distribution point, got %q", dp)
	}
	if len(payload) < bootpHeaderBytes+dhcpCookieBytes || len(payload) > maxPXEPayloadBytes {
		return nil, errors.New("invalid PXE request payload size")
	}
	datagram := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(datagram[0:2], pxeClientPort)
	binary.BigEndian.PutUint16(datagram[2:4], pxeProxyDHCPPort)
	binary.BigEndian.PutUint16(datagram[4:6], uint16(len(datagram)))
	copy(datagram[8:], payload)
	// For IPv4 a zero UDP checksum means "not computed", so a computed zero is
	// transmitted as 0xffff as required by RFC 768.
	if sum := udpChecksum(clientIP, dp, datagram); sum == 0 {
		binary.BigEndian.PutUint16(datagram[6:8], 0xffff)
	} else {
		binary.BigEndian.PutUint16(datagram[6:8], sum)
	}
	return datagram, nil
}

// udpChecksum computes the RFC 768 checksum over the IPv4 pseudo-header and the
// UDP datagram. The caller passes the datagram with its checksum field zeroed.
func udpChecksum(clientIP, dp netip.Addr, datagram []byte) uint16 {
	full := make([]byte, 0, 12+len(datagram)+1)
	full = append(full, clientIP.AsSlice()...)
	full = append(full, dp.AsSlice()...)
	full = append(full, 0, 17, byte(len(datagram)>>8), byte(len(datagram)))
	full = append(full, datagram...)
	if len(full)%2 != 0 {
		full = append(full, 0)
	}
	var sum uint32
	for i := 0; i < len(full); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(full[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// pxeTransmitter transmits one prepared IPv4 UDP datagram to the distribution
// point. Implementations must not bind the DHCP client port: the request
// carries source port 68 in its own header so the host DHCP client keeps sole
// ownership of UDP/68.
type pxeTransmitter interface {
	Transmit(datagram []byte, dp netip.Addr) error
	Close() error
}

// rawTransmitter sends IPv4 datagrams through an IPPROTO_UDP raw socket. The
// kernel performs route, interface, and source-address selection (preserving
// automatic route-selected source IPv4) and adds the IPv4 header, while the
// application supplies the UDP header. No local UDP port is bound, so a
// conventional listener cannot collide with the host DHCP client's UDP/68
// socket.
type rawTransmitter struct{ conn net.PacketConn }

func newRawTransmitter(clientIP netip.Addr) (pxeTransmitter, error) {
	if err := validateSourceIPv4(clientIP); err != nil {
		return nil, err
	}
	conn, err := net.ListenPacket("ip4:udp", clientIP.String())
	if err != nil {
		return nil, fmt.Errorf("CRED-1 PXE raw transmit socket on %s: %w", clientIP, err)
	}
	return rawTransmitter{conn: conn}, nil
}

func (t rawTransmitter) Transmit(datagram []byte, dp netip.Addr) error {
	if !dp.Is4() || dp.IsUnspecified() || dp.IsMulticast() {
		return fmt.Errorf("invalid PXE distribution point address %q", dp)
	}
	if _, err := t.conn.WriteTo(datagram, &net.IPAddr{IP: dp.AsSlice()}); err != nil {
		return fmt.Errorf("CRED-1 PXE request: %w", err)
	}
	return nil
}

func (t rawTransmitter) Close() error {
	if t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

// transmitPXERequest builds the UDP datagram and hands it to the transmitter.
// It never opens a conventional client socket, so UDP/68 being owned by the
// host DHCP client cannot fail the exchange.
func transmitPXERequest(transmitter pxeTransmitter, clientIP, dp netip.Addr, payload []byte) error {
	datagram, err := pxeUDPDatagram(clientIP, dp, payload)
	if err != nil {
		return err
	}
	return transmitter.Transmit(datagram, dp)
}

// pxeObservationSignature returns a bounded, payload-free description of one
// captured frame. It is used only to explain a failed exchange: the selected
// DP sending ICMP port-unreachable, answering on an unexpected port, or staying
// silent are all different outcomes that must not look identical to the
// operator. It never influences acceptance, which stays with matchPXEReply.
func pxeObservationSignature(data []byte, clientIP, dp netip.Addr) string {
	const ethernetBytes = 14
	if len(data) < ethernetBytes+20 || binary.BigEndian.Uint16(data[12:14]) != 0x0800 {
		return "non-IPv4 frame"
	}
	ip := data[ethernetBytes:]
	if ip[0]>>4 != 4 {
		return "non-IPv4 frame"
	}
	headerBytes := int(ip[0]&0x0f) * 4
	if headerBytes < 20 || len(ip) < headerBytes {
		return "truncated IPv4 header"
	}
	src := netip.AddrFrom4([4]byte(ip[12:16]))
	dst := netip.AddrFrom4([4]byte(ip[16:20]))
	switch ip[9] {
	case 17:
		if len(ip) < headerBytes+8 {
			return "truncated UDP"
		}
		return fmt.Sprintf("udp %s:%d -> %s:%d", src, binary.BigEndian.Uint16(ip[headerBytes:]), dst, binary.BigEndian.Uint16(ip[headerBytes+2:]))
	case 1:
		if len(ip) < headerBytes+8 {
			return "truncated ICMP"
		}
		icmpType, icmpCode := ip[headerBytes], ip[headerBytes+1]
		// ICMP error messages quote the datagram that triggered them, so only a
		// quote of this exact request is reported as related to the exchange.
		if quoted, ok := quotedPXERequest(ip[headerBytes+8:], clientIP, dp); ok {
			return fmt.Sprintf("icmp type %d code %d for the PXE request (%s)", icmpType, icmpCode, quoted)
		}
		return fmt.Sprintf("icmp type %d code %d %s -> %s", icmpType, icmpCode, src, dst)
	default:
		return fmt.Sprintf("ip protocol %d %s -> %s", ip[9], src, dst)
	}
}

// quotedPXERequest reports whether an ICMP error quote describes this exact
// PXE request (client:68 to DP:4011).
func quotedPXERequest(quoted []byte, clientIP, dp netip.Addr) (string, bool) {
	if len(quoted) < 28 || quoted[0]>>4 != 4 || quoted[9] != 17 {
		return "", false
	}
	qsrc, qdst := netip.AddrFrom4([4]byte(quoted[12:16])), netip.AddrFrom4([4]byte(quoted[16:20]))
	qsport, qdport := binary.BigEndian.Uint16(quoted[20:22]), binary.BigEndian.Uint16(quoted[22:24])
	if qsrc != clientIP || qdst != dp || qsport != pxeClientPort || qdport != pxeProxyDHCPPort {
		return "", false
	}
	return fmt.Sprintf("udp %s:%d -> %s:%d", qsrc, qsport, qdst, qdport), true
}

// summarizePXEObservations renders observed frame signatures in first-seen
// order with counts, bounded by signature count and total length. It never
// includes payload content.
func summarizePXEObservations(observed []string, maxSignatures, maxBytes int) string {
	if len(observed) == 0 || maxSignatures <= 0 {
		return ""
	}
	order := make([]string, 0, maxSignatures)
	counts := make(map[string]int, maxSignatures)
	other := 0
	for _, signature := range observed {
		if seen, ok := counts[signature]; ok {
			counts[signature] = seen + 1
			continue
		}
		if len(order) >= maxSignatures {
			other++
			continue
		}
		order = append(order, signature)
		counts[signature] = 1
	}
	parts := make([]string, 0, len(order)+1)
	for _, signature := range order {
		if counts[signature] == 1 {
			parts = append(parts, signature)
			continue
		}
		parts = append(parts, fmt.Sprintf("%s x%d", signature, counts[signature]))
	}
	if other > 0 {
		parts = append(parts, fmt.Sprintf("%d other frames", other))
	}
	summary := strings.Join(parts, "; ")
	if maxBytes > 0 && len(summary) > maxBytes {
		summary = summary[:maxBytes] + "..."
	}
	return summary
}

// pxeReplyTimeoutError explains a failed exchange using the frames the capture
// actually observed, so silence, a closed port, and an unexpected reply shape
// are distinguishable.
func pxeReplyTimeoutError(frames int, lastRejection string, observed []string) error {
	detail := summarizePXEObservations(observed, maxPXEObservationSignatures, maxPXEObservationSummaryBytes)
	switch {
	case detail != "" && lastRejection != "":
		return fmt.Errorf("PXE reply timeout after %d observed frames: %s; last rejection: %s", frames, detail, lastRejection)
	case detail != "":
		return fmt.Errorf("PXE reply timeout after %d observed frames: %s", frames, detail)
	case lastRejection != "":
		return fmt.Errorf("PXE reply timeout after %d observed frames; last rejection: %s", frames, lastRejection)
	default:
		return fmt.Errorf("PXE reply timeout after %d observed frames; the distribution point sent no UDP or ICMP response to this request", frames)
	}
}
