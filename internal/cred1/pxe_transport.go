package cred1

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	pxeClientPort        = 68
	pxeProxyDHCPPort     = 4011
	bootpHeaderBytes     = 236
	dhcpCookieBytes      = 4
	maxPXEPayloadBytes   = 2048
	maxPXECapturedFrames = 16
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
