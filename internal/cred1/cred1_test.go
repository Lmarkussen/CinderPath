package cred1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rsa"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func u16(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, x := range u {
		b[2*i] = byte(x)
		b[2*i+1] = byte(x >> 8)
	}
	return b
}
func TestBootVarAndSequenceBoundedDecoding(t *testing.T) {
	xml := `<MediaVarList><var name="SMSTSMP">http://mecm.lab</var><var name="_SMSTSSiteCode">P01</var><var name="_SMSMediaGuid">{11111111-2222-3333-4444-555555555555}</var><var name="_SMSTSx64UnknownMachineGUID">AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE</var><var name="_SMSTSMediaPFX">` + strings.Repeat("AB", 64) + `</var></MediaVarList>`
	plain := u16(xml)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, make([]byte, pad)...)
	key := []byte("0123456789abcdef")
	block, _ := aes.NewCipher(key)
	enc := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(enc, plain)
	raw := append(make([]byte, 24), enc...)
	raw = append(raw, make([]byte, 8)...)
	d, e := DecryptBootVar(raw, key)
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseBootVar(d)
	if e != nil {
		t.Fatal(e)
	}
	if got.SiteCode != "P01" {
		t.Fatal(got.SiteCode)
	}
	if p, _ := got.PFXPassword(); p != got.MediaGUID[:31] {
		t.Fatal(p)
	}
	for _, bad := range [][]byte{nil, raw[:25]} {
		if _, e := DecryptBootVar(bad, key); e == nil {
			t.Fatal("accepted bad boot var")
		}
	}
}
func TestDeobfuscateSequence(t *testing.T) {
	keymat := []byte("0123456789012345678901234567890123456789")
	text := `<sequence><action>tsenv.exe "example=secret"</action></sequence>`
	p := u16(text)
	for len(p)%8 != 0 {
		p = append(p, 0)
	}
	b, _ := des.NewTripleDESCipher(MediaKey(keymat)[:24])
	c := make([]byte, len(p))
	cipher.NewCBCEncrypter(b, make([]byte, 8)).CryptBlocks(c, p)
	v := "00000000" + hex.EncodeToString(keymat) + strings.Repeat("0", 40) + hex.EncodeToString(c)
	got, e := DeobfuscateSequence(v)
	if e != nil || !strings.Contains(got, "example=secret") {
		t.Fatalf("%q %v", got, e)
	}
	for _, bad := range []string{"", v[:128], strings.Repeat("Z", 130)} {
		if _, e := DeobfuscateSequence(bad); e == nil {
			t.Fatal("accepted invalid sequence")
		}
	}
}

func TestExtractVariablesDoesNotIncludeTsenvSwitches(t *testing.T) {
	got, err := extractVariables(`<sequence><step><action>tsenv.exe "ExampleVariable=" /hiddenflag:False /another:one</action><defaultVarList><variable name="SetVariableActionHiddenVariableValue" property="HiddenVariableValue">Example-Secret-Value</variable><variable name="VariableName" property="VariableName" hidden="true">ExampleVariable</variable></defaultVarList></step></sequence>`)
	if err != nil || len(got) != 1 || got[0].Name != "ExampleVariable" || got[0].Value != "Example-Secret-Value" {
		t.Fatalf("variables=%+v err=%v", got, err)
	}
}

func TestCMSRejectsMalformedAndMissingKey(t *testing.T) {
	for _, tc := range []struct {
		body []byte
		key  *rsa.PrivateKey
	}{{nil, nil}, {[]byte{0x30, 0x00}, &rsa.PrivateKey{}}, {make([]byte, MaxCMSBytes+1), &rsa.PrivateKey{}}} {
		if _, err := DecryptPolicyCMS(tc.body, tc.key); err == nil {
			t.Fatal("accepted invalid CMS input")
		}
	}
}

func TestSelectTaskSequencePoliciesIsBoundedAndExact(t *testing.T) {
	refs := []PolicyReference{
		{ID: "n", Category: "NetworkAccessAccount", Path: "/SMS_MP/.sms_pol?n"},
		{ID: "one", Category: "TaskSequence", Path: "/SMS_MP/.sms_pol?one"},
		{ID: "one", Category: "TaskSequence", Path: "/SMS_MP/.sms_pol?one"},
		{ID: "two", Category: "tasksequence", Path: "/SMS_MP/.sms_pol?two"},
	}
	got, err := SelectTaskSequencePolicies(refs)
	if err != nil || len(got) != 2 || got[0].ID != "one" || got[1].ID != "two" {
		t.Fatalf("selected=%+v err=%v", got, err)
	}
	tooMany := make([]PolicyReference, MaxPolicyCount+1)
	for i := range tooMany {
		tooMany[i] = PolicyReference{ID: string(rune('a' + i)), Category: "TaskSequence", Path: "/SMS_MP/.sms_pol?x" + string(rune('a'+i))}
	}
	if _, err := SelectTaskSequencePolicies(tooMany); err == nil {
		t.Fatal("accepted too many task-sequence policies")
	}
	if _, err := SelectTaskSequencePolicies([]PolicyReference{{ID: "", Category: "TaskSequence", Path: "/SMS_MP/.sms_pol?x"}}); err == nil {
		t.Fatal("accepted incomplete task-sequence reference")
	}
}

// This optional runtime test never embeds lab PFX material. It is run only
// with an owner-only temporary file supplied by the authorized GOAD harness.
func TestGOADMediaPFX(t *testing.T) {
	p := os.Getenv("CINDERPATH_CRED1_GOAD_PFX")
	media := os.Getenv("CINDERPATH_CRED1_GOAD_MEDIA_GUID")
	if p == "" || media == "" {
		t.Skip("GOAD media PFX fixture is not supplied")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	_, meta, err := LoadMediaPFX(BootstrapIdentity{MediaGUID: media, PFXHex: hex.EncodeToString(b)})
	if err != nil {
		t.Fatal(err)
	}
	if meta.KeyAlgorithm != "RSA" || meta.KeyBits < 1024 || meta.FingerprintSHA256 == "" {
		t.Fatalf("unexpected media certificate metadata: %+v", meta)
	}
}

// TestGOADCMS is an opt-in lab test. Its raw response remains outside Git.
func TestGOADCMS(t *testing.T) {
	pfxPath, cmsPath, media := os.Getenv("CINDERPATH_CRED1_GOAD_PFX"), os.Getenv("CINDERPATH_CRED1_GOAD_CMS"), os.Getenv("CINDERPATH_CRED1_GOAD_MEDIA_GUID")
	if pfxPath == "" || cmsPath == "" || media == "" {
		t.Skip("GOAD CMS fixture is not supplied")
	}
	pfx, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := LoadMediaPFX(BootstrapIdentity{MediaGUID: media, PFXHex: hex.EncodeToString(pfx)})
	if err != nil {
		t.Fatal(err)
	}
	cms, err := os.ReadFile(cmsPath)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := DecryptPolicyCMS(cms, key)
	if err != nil || len(plain) == 0 {
		t.Fatalf("CMS decryption: %v", err)
	}
}

func TestGOADTaskSequence(t *testing.T) {
	pfxPath, cmsPath, media, variable := os.Getenv("CINDERPATH_CRED1_GOAD_PFX"), os.Getenv("CINDERPATH_CRED1_GOAD_CMS"), os.Getenv("CINDERPATH_CRED1_GOAD_MEDIA_GUID"), os.Getenv("CINDERPATH_CRED1_GOAD_VARIABLE")
	if pfxPath == "" || cmsPath == "" || media == "" || variable == "" {
		t.Skip("GOAD task-sequence fixture is not supplied")
	}
	pfx, _ := os.ReadFile(pfxPath)
	key, _, err := LoadMediaPFX(BootstrapIdentity{MediaGUID: media, PFXHex: hex.EncodeToString(pfx)})
	if err != nil {
		t.Fatal(err)
	}
	cms, _ := os.ReadFile(cmsPath)
	plain, err := DecryptPolicyCMS(cms, key)
	if err != nil {
		t.Fatal(err)
	}
	seqs, err := ExtractTaskSequences(plain)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, seq := range seqs {
		for _, v := range seq.Variables {
			if v.Name == variable && v.Value != "" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("recovered variable %q not found", variable)
	}
}

// TestGOADMPAssignment is deliberately opt-in and uses the PXE-derived PFX
// only. It sends the single evidenced assignment request with Ack=False.
func TestGOADMPAssignment(t *testing.T) {
	if os.Getenv("CINDERPATH_CRED1_GOAD_LIVE") != "yes" {
		t.Skip("live GOAD test not enabled")
	}
	pfxPath, media := os.Getenv("CINDERPATH_CRED1_GOAD_PFX"), os.Getenv("CINDERPATH_CRED1_GOAD_MEDIA_GUID")
	variable := os.Getenv("CINDERPATH_CRED1_GOAD_VARIABLE")
	expected := os.Getenv("CINDERPATH_CRED1_GOAD_EXPECTED_VALUE")
	if pfxPath == "" || media == "" {
		t.Fatal("live fixture is incomplete")
	}
	pfx, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatal(err)
	}
	c := MPClient{BaseURL: "http://10.1.10.41", Host: "MECM.sccm.lab"}
	identity := BootstrapIdentity{MediaGUID: media, SiteCode: "P01", PFXHex: hex.EncodeToString(pfx)}
	result, err := c.ExecutePolicyPath(identity, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Policies) == 0 {
		t.Fatal("assignment has no task-sequence policy")
	}
	foundVariable := variable == ""
	matchedExpected := expected == ""
	if variable != "" {
		for _, seq := range result.TaskSequences {
			for _, v := range seq.Variables {
				if v.Name == variable && v.Value != "" {
					foundVariable = true
					if expected != "" && v.Value == expected {
						matchedExpected = true
					}
				}
			}
		}
	}
	if !foundVariable {
		t.Fatalf("recovered variable %q not found", variable)
	}
	if !matchedExpected {
		t.Fatal("recovered variable did not match the lab-only expected value")
	}
}
