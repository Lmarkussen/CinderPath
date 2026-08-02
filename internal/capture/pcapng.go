package capture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

const (
	pcapngSection   = 0x0a0d0d0a
	pcapngInterface = 1
	pcapngSimple    = 3
	pcapngEnhanced  = 6
)

type ngIface struct {
	link       uint16
	snap       uint32
	resolution uint64
	comment    string
}

func decodePCAPNG(b []byte, l Limits) (NormalizedCapture, error) {
	c := NormalizedCapture{RedactionSummary: map[string]int{}}
	if len(b) < 28 {
		return c, errors.New("truncated pcapng section")
	}
	off := 0
	blocks := 0
	var order binary.ByteOrder = binary.LittleEndian
	var ifaces []ngIface
	var ethernet []classicPacket
	var firstErr error
	for off < len(b) {
		if len(b)-off < 12 {
			if firstErr == nil {
				firstErr = errors.New("truncated pcapng block")
			}
			break
		}
		typLE := binary.LittleEndian.Uint32(b[off:])
		if typLE == pcapngSection {
			if len(b)-off < 12 {
				return c, errors.New("truncated section header")
			}
			bom := b[off+8 : off+12]
			switch {
			case bytes.Equal(bom, []byte{0x4d, 0x3c, 0x2b, 0x1a}):
				order = binary.LittleEndian
			case bytes.Equal(bom, []byte{0x1a, 0x2b, 0x3c, 0x4d}):
				order = binary.BigEndian
			default:
				return c, errors.New("invalid pcapng byte-order magic")
			}
		}
		typ := order.Uint32(b[off:])
		size := order.Uint32(b[off+4:])
		if size < 12 || size%4 != 0 || uint64(size) > uint64(l.MaxStreamBytes) || off+int(size) > len(b) {
			return c, fmt.Errorf("invalid pcapng block length at %d", off)
		}
		if order.Uint32(b[off+int(size)-4:off+int(size)]) != size {
			return c, fmt.Errorf("pcapng trailing block length mismatch at %d", off)
		}
		blocks++
		if blocks > l.MaxPackets*2 {
			return c, errors.New("pcapng block limit exceeded")
		}
		body := b[off+8 : off+int(size)-4]
		switch typ {
		case pcapngSection:
			if len(body) < 16 {
				return c, errors.New("short section header")
			}
			ifaces = nil
		case pcapngInterface:
			if len(body) < 8 {
				return c, errors.New("short interface block")
			}
			if len(ifaces) >= l.MaxStreams {
				return c, errors.New("pcapng interface limit exceeded")
			}
			x := ngIface{link: order.Uint16(body), snap: order.Uint32(body[4:8]), resolution: 1_000_000}
			parseNGOptions(body[8:], order, func(code uint16, v []byte) {
				if code == 9 && len(v) == 1 {
					if v[0]&0x80 != 0 {
						x.resolution = uint64(math.Pow(2, float64(v[0]&0x7f)))
					} else {
						x.resolution = uint64(math.Pow10(int(v[0])))
					}
					if x.resolution == 0 {
						x.resolution = 1_000_000
					}
				}
				if code == 1 {
					x.comment = fingerprint(v)
				}
			})
			ifaces = append(ifaces, x)
			c.Interfaces = append(c.Interfaces, Interface{ID: len(c.Interfaces), LinkType: x.link, SnapLength: x.snap, TimestampResolution: x.resolution, CommentFingerprint: x.comment, Supported: x.link == 1})
		case pcapngEnhanced:
			if len(body) < 20 {
				return c, errors.New("short enhanced packet")
			}
			id := int(order.Uint32(body))
			if id >= len(ifaces) {
				return c, errors.New("packet references unknown interface")
			}
			caplen := order.Uint32(body[12:16])
			orig := order.Uint32(body[16:20])
			padded := (int(caplen) + 3) &^ 3
			if int(caplen) > int(ifaces[id].snap) && ifaces[id].snap > 0 {
				c.Source.Warnings = append(c.Source.Warnings, "packet exceeds interface snap length")
			}
			if 20+padded > len(body) {
				return c, errors.New("enhanced packet captured length exceeds block")
			}
			data := append([]byte(nil), body[20:20+int(caplen)]...)
			tsraw := uint64(order.Uint32(body[4:8]))<<32 | uint64(order.Uint32(body[8:12]))
			ts := ngTime(tsraw, ifaces[id].resolution)
			addNGPacket(&c, data, id, ifaces[id].link, caplen, orig, ts)
			if ifaces[id].link == 1 {
				ethernet = append(ethernet, classicPacket{data: data, timestamp: ts, originalLength: orig})
			} else {
				c.Source.Warnings = append(c.Source.Warnings, fmt.Sprintf("unsupported pcapng link type %d", ifaces[id].link))
			}
		case pcapngSimple:
			if len(body) < 4 || len(ifaces) == 0 {
				return c, errors.New("simple packet without interface")
			}
			orig := order.Uint32(body)
			caplen := uint32(len(body) - 4)
			if ifaces[0].snap > 0 && caplen > ifaces[0].snap {
				caplen = ifaces[0].snap
			}
			data := append([]byte(nil), body[4:4+caplen]...)
			addNGPacket(&c, data, 0, ifaces[0].link, caplen, orig, time.Time{})
			if ifaces[0].link == 1 {
				ethernet = append(ethernet, classicPacket{data: data, originalLength: orig})
			}
		default:
			c.Source.Warnings = append(c.Source.Warnings, fmt.Sprintf("unsupported pcapng block type 0x%08x", typ))
		}
		off += int(size)
	}
	if len(ethernet) > 0 {
		classic := encodeClassicPCAP(ethernet)
		parsed, e := importPCAP(classic, l, false)
		if e != nil && firstErr == nil {
			firstErr = e
		}
		c.Exchanges = parsed.Exchanges
		c.Flows = parsed.Flows
		c.Source.Warnings = append(c.Source.Warnings, parsed.Source.Warnings...)
	}
	if firstErr != nil && len(c.Packets) == 0 {
		return c, firstErr
	}
	if firstErr != nil {
		c.Source.Warnings = append(c.Source.Warnings, firstErr.Error())
	}
	return c, nil
}
func parseNGOptions(b []byte, o binary.ByteOrder, visit func(uint16, []byte)) {
	for len(b) >= 4 {
		code := o.Uint16(b)
		n := int(o.Uint16(b[2:]))
		b = b[4:]
		if code == 0 {
			return
		}
		if n > len(b) {
			return
		}
		visit(code, b[:n])
		p := (n + 3) &^ 3
		if p > len(b) {
			return
		}
		b = b[p:]
	}
}
func ngTime(v, res uint64) time.Time {
	if res == 0 {
		return time.Time{}
	}
	sec := v / res
	nano := (v % res) * 1_000_000_000 / res
	return time.Unix(int64(sec), int64(nano)).UTC()
}
func addNGPacket(c *NormalizedCapture, data []byte, id int, link uint16, caplen, orig uint32, ts time.Time) {
	idx := len(c.Packets)
	c.Packets = append(c.Packets, Packet{ID: stableID("packet", fmt.Sprint(idx), fingerprint(data)), Index: idx, InterfaceID: id, Timestamp: ts, CapturedLength: caplen, OriginalLength: orig, Truncated: caplen < orig, LinkType: link, Fingerprint: fingerprint(data)})
	if link == 1 {
		c.DNSEvents = append(c.DNSEvents, parseDNSPacket(data, c.Packets[len(c.Packets)-1].ID, ts)...)
	}
}

type classicPacket struct {
	data           []byte
	timestamp      time.Time
	originalLength uint32
}

func encodeClassicPCAP(ps []classicPacket) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(0xa1b2c3d4))
	_ = binary.Write(&b, binary.LittleEndian, uint16(2))
	_ = binary.Write(&b, binary.LittleEndian, uint16(4))
	_ = binary.Write(&b, binary.LittleEndian, int32(0))
	_ = binary.Write(&b, binary.LittleEndian, uint32(0))
	_ = binary.Write(&b, binary.LittleEndian, uint32(65535))
	_ = binary.Write(&b, binary.LittleEndian, uint32(1))
	for _, p := range ps {
		sec, usec := uint32(0), uint32(0)
		if !p.timestamp.IsZero() {
			sec = uint32(p.timestamp.Unix())
			usec = uint32(p.timestamp.Nanosecond() / 1000)
		}
		orig := p.originalLength
		if orig == 0 {
			orig = uint32(len(p.data))
		}
		_ = binary.Write(&b, binary.LittleEndian, sec)
		_ = binary.Write(&b, binary.LittleEndian, usec)
		_ = binary.Write(&b, binary.LittleEndian, uint32(len(p.data)))
		_ = binary.Write(&b, binary.LittleEndian, orig)
		_, _ = b.Write(p.data)
	}
	return b.Bytes()
}
