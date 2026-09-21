//go:build linux && cgo

package cred1

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket/pcap"
)

// AcquirePXEReply sends one bounded PXE request and receives only its exact
// WDS proxy-DHCP reply. The capture path is deliberately Linux/libpcap-only:
// the GOAD WDS reply has an invalid UDP checksum and is dropped by Linux UDP.
func AcquirePXEReply(ctx context.Context, ifaceName string, dp netip.Addr, timeout time.Duration) (PXEReply, error) {
	var out PXEReply
	if ifaceName == "" || !dp.Is4() || timeout <= 0 || timeout > 30*time.Second {
		return out, errors.New("invalid PXE transport configuration")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return out, fmt.Errorf("PXE interface: %w", err)
	}
	clientIP, err := pxeSourceIPv4(iface, dp)
	if err != nil {
		return out, err
	}
	xid, request, err := newPXERequest(clientIP, iface.HardwareAddr)
	if err != nil {
		return out, err
	}
	// A finite pcap read timeout is required so Close can release the packet
	// source promptly when our bounded context expires. BlockForever leaves a
	// reader stuck inside libpcap and defeats the caller's timeout.
	// WDS emits the reply as an Ethernet broadcast. Promiscuous capture is
	// needed on this GOAD virtual NIC to receive that frame through libpcap;
	// the BPF and post-parse correlation remain restricted to one DP exchange.
	handle, err := pcap.OpenLive(ifaceName, maxPXEPayloadBytes+256, true, 100*time.Millisecond)
	if err != nil {
		return out, fmt.Errorf("CRED-1 PXE capture on %s requires libpcap and packet-capture privileges because WDS replies with invalid UDP checksums bypass the normal UDP stack; install libpcap and grant CAP_NET_RAW/CAP_NET_ADMIN (or run with equivalent authorized capture privileges): %w", ifaceName, err)
	}
	defer handle.Close()
	filter := fmt.Sprintf("udp and src host %s and src port %d and dst port %d", dp, pxeProxyDHCPPort, pxeClientPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		return out, fmt.Errorf("PXE capture filter: %w", err)
	}

	// Opening the capture and installing BPF before transmission eliminates the
	// WDS reply race. Packet decoding begins before the one send below.
	//
	// The request is transmitted through a raw IP socket so it can carry the
	// conventional DHCP client source port 68 without binding it. A normal
	// DHCP-managed workstation already has that port owned by the host DHCP
	// client (for example NetworkManager), and CRED-1 must coexist with it
	// rather than take it over. The reply is still received only through the
	// bounded libpcap capture below.
	transmitter, err := newRawTransmitter(clientIP)
	if err != nil {
		return out, err
	}
	defer transmitter.Close()
	if err := transmitPXERequest(transmitter, clientIP, dp, request); err != nil {
		return out, err
	}
	deadline := time.Now().Add(timeout)
	frames := 0
	lastRejection := ""
	for frames < maxPXECapturedFrames {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if time.Now().After(deadline) {
			if lastRejection != "" {
				return out, fmt.Errorf("PXE reply timeout after %d filtered frames: %s", frames, lastRejection)
			}
			return out, fmt.Errorf("PXE reply timeout after %d filtered frames", frames)
		}
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			return out, fmt.Errorf("PXE capture: %w", err)
		}
		frames++
		frame, err := parsePXEFrame(data)
		if err != nil {
			lastRejection = err.Error()
			continue
		}
		if reply, err := matchPXEReply(frame, dp, clientIP, xid); err == nil {
			return reply, nil
		} else {
			lastRejection = err.Error()
		}
	}
	return out, fmt.Errorf("PXE capture frame limit reached after %d filtered frames", frames)
}

// parsePXEFrame reads only Ethernet/IPv4/UDP framing. It intentionally does
// not call a kernel-style UDP checksum validator: the known WDS reply has a
// malformed checksum, while libpcap has already supplied the exact Ethernet
// frame and matchPXEReply enforces the complete request correlation.
func parsePXEFrame(data []byte) (pxeFrame, error) {
	var out pxeFrame
	const ethernetBytes = 14
	if len(data) < ethernetBytes+20+8 || binary.BigEndian.Uint16(data[12:14]) != 0x0800 {
		return out, errors.New("not IPv4 UDP")
	}
	ipOffset := ethernetBytes
	if data[ipOffset]>>4 != 4 || data[ipOffset+9] != 17 {
		return out, errors.New("not IPv4 UDP")
	}
	ipHeader := int(data[ipOffset]&0x0f) * 4
	if ipHeader < 20 || len(data) < ipOffset+ipHeader+8 {
		return out, errors.New("truncated IPv4 header")
	}
	total := int(binary.BigEndian.Uint16(data[ipOffset+2 : ipOffset+4]))
	if total < ipHeader+8 || len(data) < ipOffset+total {
		return out, errors.New("truncated IPv4 packet")
	}
	udpOffset := ipOffset + ipHeader
	udpLength := int(binary.BigEndian.Uint16(data[udpOffset+4 : udpOffset+6]))
	if udpLength < 8 || udpLength > total-ipHeader {
		return out, errors.New("truncated UDP packet")
	}
	payload := data[udpOffset+8 : udpOffset+udpLength]
	if len(payload) > maxPXEPayloadBytes {
		return out, errors.New("PXE payload exceeds bound")
	}
	src := netip.AddrFrom4([4]byte(data[ipOffset+12 : ipOffset+16]))
	dst := netip.AddrFrom4([4]byte(data[ipOffset+16 : ipOffset+20]))
	return pxeFrame{
		sourceIP: src, destinationIP: dst,
		sourcePort:      binary.BigEndian.Uint16(data[udpOffset : udpOffset+2]),
		destinationPort: binary.BigEndian.Uint16(data[udpOffset+2 : udpOffset+4]),
		udpChecksum:     binary.BigEndian.Uint16(data[udpOffset+6 : udpOffset+8]),
		payload:         payload,
	}, nil
}
