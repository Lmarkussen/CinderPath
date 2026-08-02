package capture

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	maxDNSQuestions = 16
	maxDNSAnswers   = 64
	maxDNSNameBytes = 255
	maxDNSPointers  = 16
)

type dnsTransport struct {
	payload []byte
	flowID  string
}

func dnsPayload(packet []byte) (dnsTransport, bool) {
	if len(packet) < 14 || binary.BigEndian.Uint16(packet[12:14]) != 0x0800 {
		return dnsTransport{}, false
	}
	ip := packet[14:]
	if len(ip) < 20 {
		return dnsTransport{}, false
	}
	ihl := int(ip[0]&15) * 4
	if ihl < 20 || len(ip) < ihl+8 {
		return dnsTransport{}, false
	}
	switch ip[9] {
	case 17:
		u := ip[ihl:]
		src, dst := binary.BigEndian.Uint16(u[:2]), binary.BigEndian.Uint16(u[2:4])
		if src != 53 && dst != 53 {
			return dnsTransport{}, false
		}
		n := int(binary.BigEndian.Uint16(u[4:6]))
		if n < 8 || n > len(u) {
			n = len(u)
		}
		return dnsTransport{payload: u[8:n], flowID: stableID("dnsflow", canonicalFlowKey(fmt.Sprintf("%x:%d>%x:%d", ip[12:16], src, ip[16:20], dst)))}, true
	case 6:
		t := ip[ihl:]
		if len(t) < 20 {
			return dnsTransport{}, false
		}
		src, dst := binary.BigEndian.Uint16(t[:2]), binary.BigEndian.Uint16(t[2:4])
		if src != 53 && dst != 53 {
			return dnsTransport{}, false
		}
		off := int(t[12]>>4) * 4
		if off < 20 || len(t) < off+2 {
			return dnsTransport{}, false
		}
		n := int(binary.BigEndian.Uint16(t[off : off+2]))
		if n == 0 || off+2+n > len(t) {
			return dnsTransport{}, false
		}
		return dnsTransport{payload: t[off+2 : off+2+n], flowID: stableID("dnsflow", canonicalFlowKey(fmt.Sprintf("%x:%d>%x:%d", ip[12:16], src, ip[16:20], dst)))}, true
	default:
		return dnsTransport{}, false
	}
}

func parseDNSPacket(packet []byte, packetID string, at time.Time) []DNSEvent {
	t, ok := dnsPayload(packet)
	if !ok {
		return nil
	}
	e, err := parseDNSMessage(t.payload, packetID, t.flowID, at)
	if err != nil {
		return []DNSEvent{{ID: stableID("dns_event", packetID, "malformed"), Timestamp: at, PacketIDs: []string{packetID}, FlowID: t.flowID, Confidence: "low", Warnings: []string{"malformed DNS evidence: " + safeDNSError(err)}}}
	}
	return e
}

func parseDNSMessage(msg []byte, packetID, flowID string, at time.Time) ([]DNSEvent, error) {
	if len(msg) < 12 {
		return nil, errors.New("short header")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	qd, an := int(binary.BigEndian.Uint16(msg[4:6])), int(binary.BigEndian.Uint16(msg[6:8]))
	if qd > maxDNSQuestions || an > maxDNSAnswers {
		return nil, errors.New("record limit exceeded")
	}
	type question struct {
		name string
		typ  uint16
	}
	questions := make([]question, 0, qd)
	off := 12
	for i := 0; i < qd; i++ {
		name, next, err := decodeDNSName(msg, off)
		if err != nil || next+4 > len(msg) {
			return nil, errors.New("malformed question")
		}
		questions = append(questions, question{name, binary.BigEndian.Uint16(msg[next : next+2])})
		off = next + 4
	}
	type answer struct {
		owner, value string
		typ          uint16
		ttl          uint32
	}
	answers := make([]answer, 0, an)
	for i := 0; i < an; i++ {
		owner, next, err := decodeDNSName(msg, off)
		if err != nil || next+10 > len(msg) {
			return nil, errors.New("malformed answer")
		}
		typ := binary.BigEndian.Uint16(msg[next : next+2])
		ttl := binary.BigEndian.Uint32(msg[next+4 : next+8])
		n := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		data := next + 10
		if data+n > len(msg) {
			return nil, errors.New("truncated answer")
		}
		value := ""
		switch typ {
		case 1:
			if n == 4 {
				value = net.IP(msg[data : data+n]).String()
			}
		case 28:
			if n == 16 {
				value = net.IP(msg[data : data+n]).String()
			}
		case 5:
			value, _, err = decodeDNSName(msg, data)
			if err != nil {
				return nil, errors.New("malformed CNAME")
			}
		}
		answers = append(answers, answer{owner, value, typ, ttl})
		off = data + n
	}
	if len(questions) == 0 {
		return nil, nil
	}
	out := make([]DNSEvent, 0, len(questions))
	for i, q := range questions {
		e := DNSEvent{Timestamp: at.UTC(), QueryNameFingerprint: endpointFingerprint(q.name), QueryType: q.typ, ResponseCode: int(flags & 0xf), Response: flags&0x8000 != 0, Truncated: flags&0x0200 != 0, PacketIDs: []string{packetID}, FlowID: flowID, Confidence: "high"}
		for _, a := range answers {
			if a.value == "" {
				continue
			}
			if a.typ == 5 {
				e.CNAMEChainFingerprints = append(e.CNAMEChainFingerprints, endpointFingerprint(a.value))
			} else {
				e.AnswerFingerprints = append(e.AnswerFingerprints, endpointFingerprint(a.value))
			}
			if e.TTL == 0 || a.ttl < e.TTL {
				e.TTL = a.ttl
			}
		}
		e.AnswerFingerprints = uniqueSorted(e.AnswerFingerprints)
		e.CNAMEChainFingerprints = uniqueSorted(e.CNAMEChainFingerprints)
		if e.Truncated {
			e.Confidence = "medium"
			e.Warnings = append(e.Warnings, "DNS response marked truncated")
		}
		e.ID = stableID("dns_event", packetID, fmt.Sprint(i), e.QueryNameFingerprint, fmt.Sprint(e.QueryType), fmt.Sprint(e.Response))
		out = append(out, e)
	}
	return out, nil
}

func decodeDNSName(msg []byte, start int) (string, int, error) {
	if start < 0 || start >= len(msg) {
		return "", start, errors.New("name offset outside message")
	}
	var labels []string
	pos, next, jumps := start, -1, 0
	seen := map[int]bool{}
	total := 0
	for {
		if pos >= len(msg) {
			return "", start, errors.New("truncated name")
		}
		if seen[pos] {
			return "", start, errors.New("compression loop")
		}
		seen[pos] = true
		n := int(msg[pos])
		if n&0xc0 == 0xc0 {
			if pos+1 >= len(msg) || jumps >= maxDNSPointers {
				return "", start, errors.New("invalid compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(msg[pos:pos+2]) & 0x3fff)
			if ptr >= len(msg) {
				return "", start, errors.New("compression pointer outside message")
			}
			if next < 0 {
				next = pos + 2
			}
			pos, jumps = ptr, jumps+1
			continue
		}
		if n&0xc0 != 0 {
			return "", start, errors.New("unsupported label encoding")
		}
		pos++
		if n == 0 {
			if next < 0 {
				next = pos
			}
			break
		}
		if n > 63 || pos+n > len(msg) || total+n+1 > maxDNSNameBytes {
			return "", start, errors.New("invalid label length")
		}
		labels = append(labels, strings.ToLower(string(msg[pos:pos+n])))
		total += n + 1
		pos += n
	}
	return strings.Join(labels, "."), next, nil
}

func endpointFingerprint(v string) string {
	v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
	if v == "" {
		return ""
	}
	if ip := net.ParseIP(v); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			v = hex.EncodeToString(v4)
		} else {
			v = hex.EncodeToString(ip.To16())
		}
	}
	return fingerprint([]byte(v))[:16]
}

func uniqueSorted(xs []string) []string {
	sort.Strings(xs)
	out := xs[:0]
	for _, x := range xs {
		if x != "" && (len(out) == 0 || out[len(out)-1] != x) {
			out = append(out, x)
		}
	}
	return out
}

func safeDNSError(err error) string {
	if err == nil {
		return ""
	}
	switch err.Error() {
	case "short header", "record limit exceeded", "malformed question", "malformed answer", "truncated answer", "malformed CNAME":
		return err.Error()
	default:
		return "invalid name encoding"
	}
}
