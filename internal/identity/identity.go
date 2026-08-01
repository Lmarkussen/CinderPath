package identity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
)

const MaxSecretBytes int64 = 64 << 10
const MaxCertificateBytes int64 = 1 << 20

type Input struct {
	Kind, User, Domain, PasswordEnv, PasswordFile, NTLMHashEnv, NTLMHashFile, KerberosCache, Certificate, PrivateKey, SCCMClientCert, SCCMClientKey, MachineAccount string
	CurrentProcess                                                                                                                                                  bool
}

func Parse(in Input, now time.Time, warningDays int) (models.Credential, error) {
	kind := models.CredentialType(strings.ToLower(strings.TrimSpace(in.Kind)))
	if kind == "" {
		kind = inferKind(in)
	}
	if !validKind(kind) {
		return models.Credential{}, fmt.Errorf("invalid identity kind %q", in.Kind)
	}
	c := models.Credential{Kind: kind, Type: kind, Domain: strings.ToUpper(strings.TrimSpace(in.Domain)), Username: strings.TrimSpace(in.User), MachineName: strings.ToUpper(strings.TrimSpace(in.MachineAccount)), Source: "identity.inspect", Confidence: models.ConfidenceHigh, Properties: map[string]string{"remote_authentication_attempted": "false", "remote_authentication_validated": "false"}}
	if strings.Contains(c.Username, "\\") {
		p := strings.SplitN(c.Username, "\\", 2)
		if c.Domain == "" {
			c.Domain = strings.ToUpper(p[0])
		}
		c.Username = p[1]
	}
	if strings.Contains(c.Username, "@") {
		c.Principal = c.Username
		p := strings.SplitN(c.Username, "@", 2)
		if c.Domain == "" {
			c.Domain = strings.ToUpper(p[1])
		}
	}
	if c.Kind == models.CredentialMachineAccount && c.MachineName == "" {
		c.MachineName = strings.ToUpper(c.Username)
	}
	if c.Kind == models.CredentialMachineAccount && !strings.HasSuffix(c.MachineName, "$") {
		return c, errors.New("machine-account name must end in $")
	}
	ref, refType := chooseReference(in)
	c.SecretReference, c.ReferenceType, c.HasSecret = ref, refType, ref != ""
	c.RedactedReference = RedactReference(ref)
	if refType == "ccache" {
		c.KerberosCacheReference = c.RedactedReference
	}
	certPath := in.Certificate
	if certPath == "" {
		certPath = in.SCCMClientCert
	}
	if certPath != "" {
		c.CertificateReference = RedactReference("certificate:" + certPath)
		md, err := InspectCertificate(certPath, now, warningDays)
		if err != nil {
			c.ValidationReason = err.Error()
		} else {
			c.Certificate = &md
			c.Validated = true
			c.ValidationReason = "public certificate metadata parsed locally"
		}
	}
	if ref != "" && certPath == "" {
		present, readable, warn, reason := ValidateReference(ref, MaxSecretBytes)
		c.Properties["reference_present"] = fmt.Sprint(present)
		c.Properties["reference_readable"] = fmt.Sprint(readable)
		c.Properties["permissions_warning"] = warn
		c.Validated = present && readable
		c.ValidationReason = reason
		if readable && (refType == "env_ntlm_hash" || refType == "file_ntlm_hash") {
			if err := validateNTLMHashReference(ref); err != nil {
				c.Validated = false
				c.ValidationReason = err.Error()
			}
		}
	}
	key := in.PrivateKey
	if key == "" {
		key = in.SCCMClientKey
	}
	if key != "" {
		if certPath != "" {
			c.SecretReference = "certificate:" + certPath + "\nprivate-key:" + key
			c.HasSecret = true
		}
		p, _, warn, reason := validateFile(key, MaxCertificateBytes, false)
		c.Properties["private_key_reference_present"] = fmt.Sprint(p)
		c.Properties["private_key_pairing_verified"] = "false"
		c.Properties["private_key_validation"] = reason
		if warn != "" {
			c.Properties["private_key_permissions_warning"] = warn
		}
	}
	if kind == models.CredentialAnonymous || kind == models.CredentialCurrentProcess || (ref == "" && certPath == "" && key == "") {
		c.Validated = true
		if c.ValidationReason == "" {
			c.ValidationReason = "identity syntax normalized; no reusable secret validated"
		}
	}
	c.Prepare()
	return c, nil
}

func inferKind(in Input) models.CredentialType {
	switch {
	case in.CurrentProcess:
		return models.CredentialCurrentProcess
	case in.MachineAccount != "":
		return models.CredentialMachineAccount
	case in.NTLMHashEnv != "" || in.NTLMHashFile != "":
		return models.CredentialNTLMHashRef
	case in.KerberosCache != "":
		return models.CredentialKerberosCacheRef
	case in.Certificate != "" || in.SCCMClientCert != "":
		return models.CredentialCertificateRef
	case in.PasswordEnv != "" || in.PasswordFile != "":
		return models.CredentialPasswordRef
	case in.User != "":
		return models.CredentialDomainUser
	default:
		return models.CredentialAnonymous
	}
}
func validKind(k models.CredentialType) bool {
	for _, v := range []models.CredentialType{models.CredentialAnonymous, models.CredentialDomainUser, models.CredentialMachineAccount, models.CredentialCurrentProcess, models.CredentialPasswordRef, models.CredentialNTLMHashRef, models.CredentialKerberosCacheRef, models.CredentialCertificateRef, models.CredentialSCCMClientRef, models.CredentialUnknown} {
		if k == v {
			return true
		}
	}
	return false
}
func chooseReference(in Input) (string, string) {
	switch {
	case in.PasswordEnv != "":
		return "env:" + in.PasswordEnv, "env"
	case in.PasswordFile != "":
		return "file:" + in.PasswordFile, "file"
	case in.NTLMHashEnv != "":
		return "env:" + in.NTLMHashEnv, "env_ntlm_hash"
	case in.NTLMHashFile != "":
		return "file:" + in.NTLMHashFile, "file_ntlm_hash"
	case in.KerberosCache != "":
		return "ccache:" + in.KerberosCache, "ccache"
	}
	return "", ""
}

func RedactReference(ref string) string {
	p := strings.IndexByte(ref, ':')
	if p < 0 {
		return ref
	}
	typ, val := ref[:p], ref[p+1:]
	if typ == "env" {
		return ref
	}
	return typ + ":" + filepath.Base(val)
}
func ValidateReference(ref string, max int64) (bool, bool, string, string) {
	p := strings.IndexByte(ref, ':')
	if p < 0 {
		return false, false, "", "invalid reference"
	}
	typ, val := ref[:p], ref[p+1:]
	if typ == "env" {
		_, ok := os.LookupEnv(val)
		if !ok {
			return false, false, "", "environment variable is not set"
		}
		return true, true, "", "environment reference exists"
	}
	if typ == "ccache" {
		return validateFile(val, max, false)
	}
	return validateFile(val, max, true)
}

var ntlmHashPattern = regexp.MustCompile(`(?i)^(?:[0-9a-f]{32}|[0-9a-f]{32}:[0-9a-f]{32})$`)

func validateNTLMHashReference(ref string) error {
	p := strings.IndexByte(ref, ':')
	typ, val := ref[:p], ref[p+1:]
	var raw []byte
	var err error
	if typ == "env" {
		v, ok := os.LookupEnv(val)
		if !ok {
			return errors.New("environment variable is not set")
		}
		if len(v) > int(MaxSecretBytes) {
			return errors.New("NTLM hash reference exceeds bounded limit")
		}
		raw = []byte(v)
	} else {
		f, e := os.Open(val)
		if e != nil {
			return e
		}
		defer f.Close()
		raw = make([]byte, MaxSecretBytes+1)
		n, e := f.Read(raw)
		if e != nil && n == 0 {
			return e
		}
		if int64(n) > MaxSecretBytes {
			return errors.New("NTLM hash reference exceeds bounded limit")
		}
		raw = raw[:n]
	}
	if !ntlmHashPattern.MatchString(strings.TrimSpace(string(raw))) {
		return errors.New("NTLM hash reference has invalid local format")
	}
	return err
}

// LoadSecret performs one bounded read for an explicitly selected reference.
// Callers must discard the returned bytes immediately after the single use.
func LoadSecret(ref string) ([]byte, error) {
	p := strings.IndexByte(ref, ':')
	if p < 0 {
		return nil, errors.New("invalid secret reference")
	}
	typ, val := ref[:p], ref[p+1:]
	switch typ {
	case "env":
		v, ok := os.LookupEnv(val)
		if !ok {
			return nil, errors.New("secret environment reference is unavailable")
		}
		if len(v) > int(MaxSecretBytes) {
			return nil, errors.New("secret exceeds bounded limit")
		}
		return []byte(v), nil
	case "file":
		f, err := os.Open(val)
		if err != nil {
			return nil, errors.New("secret file reference is unavailable")
		}
		defer f.Close()
		b := make([]byte, MaxSecretBytes+1)
		n, err := f.Read(b)
		if err != nil && n == 0 {
			return nil, errors.New("secret file reference could not be read")
		}
		if int64(n) > MaxSecretBytes {
			return nil, errors.New("secret exceeds bounded limit")
		}
		return []byte(strings.TrimRight(string(b[:n]), "\r\n")), nil
	default:
		return nil, errors.New("reference is not a password source")
	}
}
func validateFile(path string, max int64, bounded bool) (bool, bool, string, string) {
	st, err := os.Stat(path)
	if err != nil {
		return false, false, "", err.Error()
	}
	if !st.Mode().IsRegular() {
		return true, false, "", "reference is not a regular file"
	}
	if st.Size() > max {
		return true, false, "", fmt.Sprintf("reference exceeds %d-byte limit", max)
	}
	warn := ""
	if st.Mode().Perm()&0o077 != 0 {
		warn = "file is accessible by group or others"
	}
	if bounded {
		f, e := os.Open(path)
		if e != nil {
			return true, false, warn, e.Error()
		}
		defer f.Close()
		b := make([]byte, max+1)
		n, e := f.Read(b)
		if e != nil && n == 0 {
			return true, false, warn, e.Error()
		}
		if int64(n) > max {
			return true, false, warn, "reference exceeds bounded-read limit"
		}
	}
	return true, true, warn, "local reference exists and is readable"
}

func InspectCertificate(path string, now time.Time, warningDays int) (models.CertificateMetadata, error) {
	st, err := os.Stat(path)
	if err != nil {
		return models.CertificateMetadata{}, err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxCertificateBytes {
		return models.CertificateMetadata{}, errors.New("certificate must be a bounded regular file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return models.CertificateMetadata{}, err
	}
	der := b
	if block, _ := pem.Decode(b); block != nil {
		if block.Type != "CERTIFICATE" {
			return models.CertificateMetadata{}, errors.New("PEM does not contain a public certificate")
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return models.CertificateMetadata{}, fmt.Errorf("parse public certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	md := models.CertificateMetadata{Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), SerialNumber: cert.SerialNumber.Text(16), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, DNSNames: cert.DNSNames, EmailAddresses: cert.EmailAddresses, PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(), SignatureAlgorithm: cert.SignatureAlgorithm.String(), SHA256Fingerprint: hex.EncodeToString(sum[:]), Expired: now.After(cert.NotAfter), NotYetValid: now.Before(cert.NotBefore), NearExpiry: !now.After(cert.NotAfter) && cert.NotAfter.Sub(now) <= time.Duration(warningDays)*24*time.Hour}
	for _, ip := range cert.IPAddresses {
		md.IPAddresses = append(md.IPAddresses, ip.String())
	}
	for _, e := range cert.ExtKeyUsage {
		s := fmt.Sprint(e)
		if e == x509.ExtKeyUsageClientAuth {
			md.HasClientAuthEKU = true
			s = "client_auth"
		}
		md.ExtendedKeyUsage = append(md.ExtendedKeyUsage, s)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		md.KeyUsage = append(md.KeyUsage, "digital_signature")
	}
	return md, nil
}

type AuthRequirement struct {
	Origin                        string   `json:"origin"`
	AssetID                       string   `json:"asset_id"`
	EndpointRole                  string   `json:"endpoint_role"`
	AnonymousResponseAvailable    bool     `json:"anonymous_response_available"`
	AuthenticationRequested       bool     `json:"authentication_requested"`
	AdvertisedSchemes             []string `json:"advertised_schemes"`
	TLSClientCertificateRequested bool     `json:"tls_client_certificate_requested"`
	AuthenticatedObservation      bool     `json:"authenticated_observation"`
	UsableAnonymousAccess         bool     `json:"usable_anonymous_access"`
	ProtocolValidated             bool     `json:"protocol_validated"`
	EvidenceIDs                   []string `json:"evidence_ids"`
	Stale                         bool     `json:"stale"`
}

func Requirements(evidence []models.Evidence, now time.Time, staleDays int, latestRun ...string) []AuthRequirement {
	by := map[string]*AuthRequirement{}
	for _, e := range evidence {
		if e.Type != "sccm_http_route" {
			continue
		}
		origin := fmt.Sprint(e.Data["origin"])
		k := e.AssetID + "\x00" + origin
		r := by[k]
		if r == nil {
			r = &AuthRequirement{Origin: origin, AssetID: e.AssetID}
			by[k] = r
		}
		state, _ := e.Data["access_state"].(map[string]any)
		r.AuthenticationRequested = r.AuthenticationRequested || boolValue(state["authentication_requested"])
		r.UsableAnonymousAccess = r.UsableAnonymousAccess || boolValue(state["usable_read_access"])
		r.AnonymousResponseAvailable = r.AnonymousResponseAvailable || boolValue(state["http_response_received"])
		r.ProtocolValidated = r.ProtocolValidated || boolValue(state["protocol_validated"])
		r.AdvertisedSchemes = append(r.AdvertisedSchemes, stringsValue(e.Data["authentication_schemes"])...)
		r.TLSClientCertificateRequested = r.TLSClientCertificateRequested || boolValue(e.Data["tls_client_certificate_requested"])
		r.EvidenceIDs = append(r.EvidenceIDs, e.ID)
		r.Stale = r.Stale || now.Sub(e.CollectedAt) > time.Duration(staleDays)*24*time.Hour
		if len(latestRun) > 0 && latestRun[0] != "" && e.RunID != latestRun[0] {
			r.Stale = true
		}
		if strings.Contains(fmt.Sprint(e.Data["route_id"]), "mp_") {
			r.EndpointRole = "management_point"
		} else if strings.Contains(fmt.Sprint(e.Data["route_id"]), "dp_") {
			r.EndpointRole = "distribution_point"
		}
	}
	out := make([]AuthRequirement, 0, len(by))
	for _, r := range by {
		r.AdvertisedSchemes = normalizeSchemes(r.AdvertisedSchemes)
		sort.Strings(r.EvidenceIDs)
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Origin < out[j].Origin })
	return out
}
func normalizeSchemes(v []string) []string {
	seen := map[string]bool{}
	for _, s := range v {
		s = strings.ToLower(strings.Fields(s)[0])
		switch s {
		case "negotiate", "ntlm", "kerberos", "basic", "digest", "anonymous":
		default:
			s = "unknown"
		}
		seen[s] = true
	}
	out := []string{}
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
func boolValue(v any) bool { return strings.EqualFold(fmt.Sprint(v), "true") }
func stringsValue(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		r := []string{}
		for _, v := range x {
			r = append(r, fmt.Sprint(v))
		}
		return r
	}
	return nil
}
func endpointHost(origin string) string { u, _ := url.Parse(origin); return u.Hostname() }

func Plan(ids []models.Credential, reqs []AuthRequirement) []models.Capability {
	out := []models.Capability{}
	add := func(c models.Capability) {
		c.Source = "identity.capability_planner"
		c.Available = c.State == models.CapabilityAvailable
		c.Prepare()
		out = append(out, c)
	}
	for _, id := range ids {
		base := models.Capability{CredentialID: id.ID, AvailableInputs: []string{string(id.Kind)}, State: models.CapabilityRequiresValidation, Reason: "identity is described; remote authentication remains unvalidated"}
		switch id.Kind {
		case models.CredentialDomainUser, models.CredentialPasswordRef:
			base.Name = "domain_identity_available"
		case models.CredentialMachineAccount:
			base.Name = "machine_identity_available"
		case models.CredentialKerberosCacheRef:
			base.Name = "kerberos_cache_reference_available"
		case models.CredentialNTLMHashRef:
			base.Name = "ntlm_hash_reference_available"
		case models.CredentialCertificateRef, models.CredentialSCCMClientRef:
			base.Name = "public_client_certificate_available"
		default:
			continue
		}
		if id.Validated && (id.Kind != models.CredentialMachineAccount || id.HasSecret) {
			base.State = models.CapabilityAvailable
		}
		add(base)
	}
	for _, r := range reqs {
		hasDomain, hasCert, hasKey := false, false, false
		var related string
		for _, id := range ids {
			if id.Validated && (id.Kind == models.CredentialPasswordRef || id.Kind == models.CredentialKerberosCacheRef || id.Kind == models.CredentialNTLMHashRef || id.Kind == models.CredentialCurrentProcess) {
				hasDomain = true
				related = id.ID
			}
			if id.Certificate != nil && id.Certificate.HasClientAuthEKU {
				hasCert = true
				related = id.ID
			}
			if id.Properties["private_key_reference_present"] == "true" {
				hasKey = true
			}
		}
		if contains(r.AdvertisedSchemes, "negotiate") || contains(r.AdvertisedSchemes, "ntlm") {
			c := models.Capability{Name: "integrated_auth_potentially_available", State: models.CapabilityBlockedBySafety, SafetyBlocked: true, Reason: "endpoint advertises integrated authentication; no authentication was attempted", AssetID: r.AssetID, CredentialID: related, RelatedEndpoint: r.Origin, EvidenceIDs: r.EvidenceIDs, RequiredInputs: []string{"validated SCCM endpoint", "domain identity reference"}}
			if !hasDomain {
				c.State = models.CapabilityUnavailable
				c.SafetyBlocked = false
				c.MissingInputs = []string{"locally available domain identity reference"}
			}
			if r.Stale {
				c.State = models.CapabilityRequiresValidation
				c.Stale = true
				c.Reason = "capability depends on stale endpoint evidence"
			}
			add(c)
		}
		if contains(r.AdvertisedSchemes, "basic") {
			c := models.Capability{Name: "basic_auth_potentially_available", State: models.CapabilityRequiresValidation, Reason: "endpoint advertises Basic and validation requires an explicit guarded auth command", AssetID: r.AssetID, CredentialID: related, RelatedEndpoint: r.Origin, EvidenceIDs: r.EvidenceIDs, RequiredInputs: []string{"password identity reference", "explicit authentication enablement", "lockout-risk acknowledgement"}}
			passwordAvailable := false
			for _, id := range ids {
				if id.Validated && id.Kind == models.CredentialPasswordRef {
					passwordAvailable = true
					c.CredentialID = id.ID
					break
				}
			}
			if !passwordAvailable {
				c.State = models.CapabilityUnavailable
				c.MissingInputs = []string{"locally available password identity reference"}
			}
			if r.Stale {
				c.State = models.CapabilityRequiresValidation
				c.Stale = true
				c.Reason = "Basic authentication potential depends on stale or missing endpoint evidence"
			}
			add(c)
		}
		if r.TLSClientCertificateRequested || hasCert {
			c := models.Capability{Name: "client_certificate_auth_potentially_available", State: models.CapabilityBlockedBySafety, SafetyBlocked: true, Reason: "client-auth certificate metadata and endpoint evidence are only local/passive", AssetID: r.AssetID, CredentialID: related, RelatedEndpoint: r.Origin, EvidenceIDs: r.EvidenceIDs, RequiredInputs: []string{"client-auth certificate", "private-key reference"}}
			if !hasCert || !hasKey {
				c.State = models.CapabilityUnavailable
				c.SafetyBlocked = false
				if !hasCert {
					c.MissingInputs = append(c.MissingInputs, "client-auth certificate")
				}
				if !hasKey {
					c.MissingInputs = append(c.MissingInputs, "private-key reference")
				}
			}
			add(c)
		}
		if r.ProtocolValidated {
			add(models.Capability{Name: "management_point_protocol_validated", State: models.CapabilityAvailable, Reason: "existing anonymous SCCM protocol evidence is validated", AssetID: r.AssetID, RelatedEndpoint: r.Origin, EvidenceIDs: r.EvidenceIDs})
		}
		if r.UsableAnonymousAccess {
			add(models.Capability{Name: "anonymous_sccm_http", State: models.CapabilityAvailable, Reason: "stored evidence records usable anonymous read access", AssetID: r.AssetID, RelatedEndpoint: r.Origin, EvidenceIDs: r.EvidenceIDs})
		}
		_ = endpointHost(r.Origin)
	}
	return out
}
func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}
