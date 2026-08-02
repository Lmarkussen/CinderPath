package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const SigningKeyVersion = 1

type SigningKeyFile struct {
	Version    int    `yaml:"version"`
	Algorithm  string `yaml:"algorithm"`
	KeyID      string `yaml:"key_id"`
	PrivateKey string `yaml:"private_key"`
}
type PublicKeyFile struct {
	Version   int    `yaml:"version"`
	Algorithm string `yaml:"algorithm"`
	KeyID     string `yaml:"key_id"`
	PublicKey string `yaml:"public_key"`
}
type SignatureEnvelope struct {
	Version         int    `yaml:"version" json:"version"`
	Algorithm       string `yaml:"algorithm" json:"algorithm"`
	KeyID           string `yaml:"key_id" json:"key_id"`
	PublicKey       string `yaml:"public_key" json:"public_key"`
	Signature       string `yaml:"signature" json:"signature"`
	CanonicalSHA256 string `yaml:"canonical_sha256" json:"canonical_sha256"`
}
type CanonicalMember struct {
	Path   string `json:"path"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}
type CanonicalSigningManifest struct {
	BundleSchemaVersion          int               `json:"bundle_schema_version"`
	BundleID                     string            `json:"bundle_id"`
	CreatedAt                    string            `json:"created_at"`
	ContractIDs                  []string          `json:"contract_ids"`
	FixtureIDs                   []string          `json:"fixture_ids"`
	Members                      []CanonicalMember `json:"members"`
	SanitizerVersions            []string          `json:"sanitizer_versions"`
	ParserVersions               []string          `json:"parser_versions"`
	ExpectedAnalysisFingerprints map[string]string `json:"expected_analysis_fingerprints"`
	SigningKeyID                 string            `json:"signing_key_id"`
}
type SignatureVerification struct {
	State, SignerKeyID, Integrity  string
	SignerKnown                    bool
	TrustEffect, ContractPromotion string
}

func KeyID(pub ed25519.PublicKey) string {
	x := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(x[:12])
}

// SignCanonicalPayload reuses the research Ed25519 key format for other
// canonical offline artifacts. The caller owns canonicalization and binding.
func SignCanonicalPayload(payload []byte, keyPath string) (SignatureEnvelope, error) {
	priv, pub, e := loadPrivateKey(keyPath)
	if e != nil {
		return SignatureEnvelope{}, e
	}
	sum := sha256.Sum256(payload)
	return SignatureEnvelope{SigningKeyVersion, "ed25519", pub.KeyID, pub.PublicKey, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)), "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func VerifyCanonicalPayload(payload []byte, env SignatureEnvelope) (SignatureVerification, error) {
	pubRaw, e := base64.StdEncoding.DecodeString(env.PublicKey)
	if e != nil || len(pubRaw) != ed25519.PublicKeySize || KeyID(pubRaw) != env.KeyID {
		return SignatureVerification{State: "signature_invalid", SignerKeyID: env.KeyID, Integrity: "failed", TrustEffect: "none", ContractPromotion: "none"}, errors.New("invalid signer public key")
	}
	sig, e := base64.StdEncoding.DecodeString(env.Signature)
	if e != nil || !ed25519.Verify(pubRaw, payload, sig) {
		return SignatureVerification{State: "signature_invalid", SignerKeyID: env.KeyID, Integrity: "failed", TrustEffect: "none", ContractPromotion: "none"}, errors.New("signature is invalid")
	}
	return SignatureVerification{State: "signature_valid", SignerKeyID: env.KeyID, Integrity: "all members verified", TrustEffect: "none", ContractPromotion: "none"}, nil
}
func GenerateSigningKey(path string, force bool) (string, error) {
	if path == "" {
		return "", errors.New("signing key output is required")
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return "", e
	}
	id := KeyID(pub)
	kf := SigningKeyFile{SigningKeyVersion, "ed25519", id, base64.StdEncoding.EncodeToString(priv)}
	pf := PublicKeyFile{SigningKeyVersion, "ed25519", id, base64.StdEncoding.EncodeToString(pub)}
	kb, _ := yaml.Marshal(kf)
	pb, _ := yaml.Marshal(pf)
	if !force {
		if _, e = os.Lstat(path); e == nil {
			return "", errors.New("private signing key already exists")
		}
		if _, e = os.Lstat(path + ".pub"); e == nil {
			return "", errors.New("public signing key already exists")
		}
	}
	if e = atomicWrite(path, kb, 0600, force); e != nil {
		return "", e
	}
	if e = atomicWrite(path+".pub", pb, 0644, force); e != nil {
		_ = os.Remove(path)
		return "", e
	}
	return id, nil
}
func loadPrivateKey(path string) (ed25519.PrivateKey, PublicKeyFile, error) {
	var p PublicKeyFile
	st, e := os.Stat(path)
	if e != nil {
		return nil, p, e
	}
	if st.Mode().Perm()&0077 != 0 {
		return nil, p, errors.New("private signing key must have mode 0600")
	}
	b, e := os.ReadFile(path)
	if e != nil || len(b) > 4096 {
		return nil, p, errors.New("invalid signing key file")
	}
	var k SigningKeyFile
	if yaml.Unmarshal(b, &k) != nil || k.Version != SigningKeyVersion || k.Algorithm != "ed25519" {
		return nil, p, errors.New("invalid signing key format")
	}
	raw, e := base64.StdEncoding.DecodeString(k.PrivateKey)
	if e != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, p, errors.New("invalid signing private key")
	}
	priv := ed25519.PrivateKey(raw)
	pub := priv.Public().(ed25519.PublicKey)
	if KeyID(pub) != k.KeyID {
		return nil, p, errors.New("signing key ID mismatch")
	}
	p = PublicKeyFile{SigningKeyVersion, "ed25519", k.KeyID, base64.StdEncoding.EncodeToString(pub)}
	return priv, p, nil
}
func canonicalSigning(m BundleManifest, members map[string][]byte, keyID string) (CanonicalSigningManifest, []byte, error) {
	names := make([]string, 0, len(m.MemberFingerprints))
	for n := range m.MemberFingerprints {
		names = append(names, n)
	}
	sort.Strings(names)
	cm := CanonicalSigningManifest{BundleSchemaVersion: m.SchemaVersion, BundleID: m.BundleID, CreatedAt: m.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z"), ContractIDs: append([]string(nil), m.ContractIDs...), FixtureIDs: append([]string(nil), m.FixtureIDs...), SanitizerVersions: append([]string(nil), m.SanitizerVersions...), ParserVersions: append([]string(nil), m.ParserVersions...), ExpectedAnalysisFingerprints: m.ExpectedAnalysisFingerprints, SigningKeyID: keyID}
	sort.Strings(cm.ContractIDs)
	sort.Strings(cm.FixtureIDs)
	sort.Strings(cm.SanitizerVersions)
	sort.Strings(cm.ParserVersions)
	for _, n := range names {
		b, ok := members[n]
		if !ok {
			return cm, nil, errors.New("signed manifest member missing")
		}
		cm.Members = append(cm.Members, CanonicalMember{n, len(b), m.MemberFingerprints[n]})
	}
	raw, e := json.Marshal(cm)
	return cm, raw, e
}
func SignBundle(input, keyPath, output string) (SignatureEnvelope, error) {
	info, members, e := readBundleMembers(input)
	if e != nil {
		return SignatureEnvelope{}, e
	}
	if !info.Manifest.Sanitized || !info.Manifest.ManualReviewComplete {
		return SignatureEnvelope{}, errors.New("bundle is not eligible for signing")
	}
	if e = bundleSigningEligible(info.Manifest, members); e != nil {
		return SignatureEnvelope{}, e
	}
	if _, ok := members["signatures/signature.yaml"]; ok {
		return SignatureEnvelope{}, errors.New("bundle is already signed")
	}
	priv, pub, e := loadPrivateKey(keyPath)
	if e != nil {
		return SignatureEnvelope{}, e
	}
	_, canonical, e := canonicalSigning(info.Manifest, members, pub.KeyID)
	if e != nil {
		return SignatureEnvelope{}, e
	}
	sum := sha256.Sum256(canonical)
	env := SignatureEnvelope{SigningKeyVersion, "ed25519", pub.KeyID, pub.PublicKey, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical)), "sha256:" + hex.EncodeToString(sum[:])}
	eb, _ := yaml.Marshal(env)
	members["signatures/signature.yaml"] = eb
	return env, writeBundle(output, members)
}
func bundleSigningEligible(m BundleManifest, members map[string][]byte) error {
	for _, fid := range m.FixtureIDs {
		base := "fixtures/" + fid + "/"
		var meta Metadata
		if yaml.Unmarshal(members[base+"metadata.yaml"], &meta) != nil {
			return errors.New("bundle fixture metadata invalid")
		}
		if !meta.Synthetic {
			var man SanitizationManifest
			if json.Unmarshal(members["manifests/"+fid+".json"], &man) != nil || man.ManualReviewRequired && !man.ManualReviewCompleted {
				return errors.New("bundle fixture review incomplete")
			}
			for _, n := range []string{"request.headers", "response.headers", "request.body", "response.body"} {
				l := strings.ToLower(string(members[base+n]))
				for _, bad := range []string{"authorization:", "proxy-authorization:", "cookie:", "set-cookie:", "private key-----", "password=", "bearer ", "syntheticpassword123!", "cinderpath_synthetic_sanitizer_sentinel"} {
					if strings.Contains(l, bad) {
						return errors.New("bundle contains unresolved sensitive indicator")
					}
				}
			}
		}
	}
	return nil
}
func VerifyBundle(path, trustedDir string) (SignatureVerification, error) {
	info, members, e := readBundleMembers(path)
	if e != nil {
		state := "manifest_invalid"
		if strings.Contains(e.Error(), "fingerprint mismatch") {
			state = "member_fingerprint_mismatch"
		}
		return SignatureVerification{State: state, Integrity: "failed", TrustEffect: "none", ContractPromotion: "none"}, e
	}
	eb, ok := members["signatures/signature.yaml"]
	if !ok {
		return SignatureVerification{State: "unsigned", Integrity: "all members verified", TrustEffect: "none", ContractPromotion: "none"}, nil
	}
	var env SignatureEnvelope
	if yaml.Unmarshal(eb, &env) != nil || env.Algorithm != "ed25519" {
		return SignatureVerification{State: "signature_invalid", Integrity: "all members verified", TrustEffect: "none", ContractPromotion: "none"}, errors.New("invalid signature envelope")
	}
	pubRaw, e := base64.StdEncoding.DecodeString(env.PublicKey)
	if e != nil || len(pubRaw) != ed25519.PublicKeySize || KeyID(pubRaw) != env.KeyID {
		return SignatureVerification{State: "signature_invalid", SignerKeyID: env.KeyID, Integrity: "all members verified", TrustEffect: "none", ContractPromotion: "none"}, errors.New("invalid signer public key")
	}
	_, canonical, e := canonicalSigning(info.Manifest, members, env.KeyID)
	if e != nil {
		return SignatureVerification{}, e
	}
	sig, e := base64.StdEncoding.DecodeString(env.Signature)
	valid := e == nil && ed25519.Verify(pubRaw, canonical, sig)
	v := SignatureVerification{State: "signature_valid", SignerKeyID: env.KeyID, Integrity: "all members verified", TrustEffect: "none", ContractPromotion: "none"}
	if !valid {
		v.State = "signature_invalid"
		return v, errors.New("bundle signature is invalid")
	}
	if trustedDir != "" {
		v.SignerKnown = trustedKeyKnown(trustedDir, env.KeyID, pubRaw)
		if !v.SignerKnown {
			v.State = "unknown_signer"
		}
	}
	return v, nil
}
func trustedKeyKnown(dir, id string, pub []byte) bool {
	es, e := os.ReadDir(dir)
	if e != nil {
		return false
	}
	for _, x := range es {
		if x.IsDir() {
			continue
		}
		b, e := os.ReadFile(filepath.Join(dir, x.Name()))
		if e != nil || len(b) > 4096 {
			continue
		}
		var p PublicKeyFile
		if yaml.Unmarshal(b, &p) == nil && p.KeyID == id {
			raw, _ := base64.StdEncoding.DecodeString(p.PublicKey)
			if ed25519.PublicKey(raw).Equal(ed25519.PublicKey(pub)) {
				return true
			}
		}
	}
	return false
}
