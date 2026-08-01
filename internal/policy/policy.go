// Package policy implements offline-only, fixture-driven SCCM policy research.
// It intentionally contains no live execution path.
package policy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const MaxFixtureBytes = 4 << 20

type VerificationState string

const (
	Unknown                VerificationState = "unknown"
	FixtureOnly            VerificationState = "fixture_only"
	CapturedUnverified     VerificationState = "captured_unverified"
	VerifiedLocalReplay    VerificationState = "verified_local_replay"
	CandidateContractState VerificationState = "candidate_contract"
	ApprovedLive           VerificationState = "approved_live"
	Rejected               VerificationState = "rejected"
)

type Provenance string

const (
	Observed   Provenance = "observed"
	Inferred   Provenance = "inferred"
	Documented Provenance = "documented"
	Approved   Provenance = "approved"
)

type Property struct {
	Value      string     `json:"value" yaml:"value"`
	Provenance Provenance `json:"provenance" yaml:"provenance"`
}
type Contract struct {
	ID                   string            `json:"id" yaml:"id"`
	Name                 string            `json:"name" yaml:"name"`
	Protocol             string            `json:"protocol" yaml:"protocol"`
	Method               Property          `json:"method" yaml:"method"`
	Path                 Property          `json:"path" yaml:"path"`
	RequestContentType   Property          `json:"request_content_type" yaml:"request_content_type"`
	ResponseContentType  Property          `json:"response_content_type" yaml:"response_content_type"`
	RequiredHeaders      []Property        `json:"required_headers" yaml:"required_headers"`
	OptionalHeaders      []Property        `json:"optional_headers" yaml:"optional_headers"`
	RequestSchema        string            `json:"request_schema" yaml:"request_schema"`
	ResponseSchema       string            `json:"response_schema" yaml:"response_schema"`
	IdentityRequirements []string          `json:"identity_requirements" yaml:"identity_requirements"`
	ReadOnlyAssumption   Property          `json:"read_only_assumption" yaml:"read_only_assumption"`
	FixtureIDs           []string          `json:"fixture_ids" yaml:"fixture_ids"`
	VerificationState    VerificationState `json:"verification_state" yaml:"verification_state"`
	VerifiedAt           *time.Time        `json:"verified_at,omitempty" yaml:"verified_at,omitempty"`
	SafetyNotes          []string          `json:"safety_notes" yaml:"safety_notes"`
}

func (c Contract) LiveAllowed() error {
	if c.VerificationState != ApprovedLive {
		return errors.New("live policy execution blocked: contract is not approved_live")
	}
	return errors.New("live policy execution is unavailable in this build")
}

type Metadata struct {
	Name      string `yaml:"name" json:"name"`
	Synthetic bool   `yaml:"synthetic" json:"synthetic"`
	Sanitized bool   `yaml:"sanitized" json:"sanitized"`
	Transport struct {
		Scheme, Host string
		Port         int
	} `yaml:"transport" json:"transport"`
	Request struct {
		Method, Route, ContentType string `yaml:",omitempty"`
	} `yaml:"request" json:"request"`
	Response struct {
		Status      int
		ContentType string `yaml:"content_type"`
	} `yaml:"response" json:"response"`
	Identity struct {
		ClientIDPresent, CertificatePresent bool `yaml:",omitempty"`
		Source                              string
	} `yaml:"identity" json:"identity"`
	Contract struct {
		VerificationState  VerificationState `yaml:"verification_state"`
		ReadOnlyAssumption string            `yaml:"read_only_assumption"`
	} `yaml:"contract" json:"contract"`
	Sanitization struct {
		SecretsRemoved, IdentifiersReplaced, CertificatesRemoved   bool `yaml:",omitempty"`
		BodySanitized, ManualReviewRequired, ManualReviewCompleted bool `yaml:",omitempty"`
	} `yaml:"sanitization" json:"sanitization"`
}
type Fixture struct {
	ID, Directory                   string
	Metadata                        Metadata
	RequestHeaders, ResponseHeaders http.Header
	RequestBody, ResponseBody       []byte
}

func safeRead(dir, name string, required bool) ([]byte, error) {
	if filepath.Base(name) != name {
		return nil, errors.New("unsafe fixture filename")
	}
	p := filepath.Join(dir, name)
	b, e := os.ReadFile(p)
	if e != nil {
		if !required && os.IsNotExist(e) {
			return nil, nil
		}
		return nil, e
	}
	if len(b) > MaxFixtureBytes {
		return nil, fmt.Errorf("%s exceeds fixture size limit", name)
	}
	return b, nil
}
func parseHeaders(b []byte) (http.Header, error) {
	h := http.Header{}
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 1 {
			return nil, errors.New("malformed header fixture")
		}
		k := http.CanonicalHeaderKey(strings.TrimSpace(line[:i]))
		if forbiddenHeader(k) {
			return nil, fmt.Errorf("sensitive header %s is forbidden", k)
		}
		h.Add(k, strings.TrimSpace(line[i+1:]))
	}
	return h, s.Err()
}
func forbiddenHeader(k string) bool {
	switch http.CanonicalHeaderKey(k) {
	case "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "Authentication-Info", "Proxy-Authentication-Info":
		return true
	}
	return false
}
func ImportDirectory(dir string) (Fixture, Contract, error) {
	clean := filepath.Clean(dir)
	if clean == "." || strings.Contains(filepath.ToSlash(dir), "../") {
		return Fixture{}, Contract{}, errors.New("unsafe fixture directory")
	}
	mb, e := safeRead(clean, "metadata.yaml", true)
	if e != nil {
		return Fixture{}, Contract{}, e
	}
	var m Metadata
	if e = yaml.Unmarshal(mb, &m); e != nil {
		return Fixture{}, Contract{}, e
	}
	if !m.Synthetic && !m.Sanitized {
		manifest, me := LoadSanitizationManifest(clean)
		if me != nil || !manifest.ManualReviewCompleted {
			return Fixture{}, Contract{}, errors.New("fixture must be synthetic, sanitized, or completely reviewed")
		}
	}
	if m.Request.Method == "" || m.Request.Route == "" || !strings.HasPrefix(m.Request.Route, "/") {
		return Fixture{}, Contract{}, errors.New("fixture requires an exact relative method and route")
	}
	if strings.Contains(m.Request.Route, "..") {
		return Fixture{}, Contract{}, errors.New("unsafe route")
	}
	rb, e := safeRead(clean, "request.body", true)
	if e != nil {
		return Fixture{}, Contract{}, e
	}
	resp, e := safeRead(clean, "response.body", true)
	if e != nil {
		return Fixture{}, Contract{}, e
	}
	rh, _ := safeRead(clean, "request.headers", false)
	sh, _ := safeRead(clean, "response.headers", false)
	reqH, e := parseHeaders(rh)
	if e != nil {
		return Fixture{}, Contract{}, e
	}
	respH, e := parseHeaders(sh)
	if e != nil {
		return Fixture{}, Contract{}, e
	}
	sum := sha256.Sum256(append(append(mb, rb...), resp...))
	id := "fixture_" + hex.EncodeToString(sum[:10])
	f := Fixture{ID: id, Directory: clean, Metadata: m, RequestHeaders: reqH, ResponseHeaders: respH, RequestBody: rb, ResponseBody: resp}
	state := m.Contract.VerificationState
	if state == "" {
		state = FixtureOnly
	}
	if state == ApprovedLive {
		return Fixture{}, Contract{}, errors.New("fixtures cannot import approved_live contracts")
	}
	c := Contract{ID: "contract_" + hex.EncodeToString(sum[:10]), Name: m.Name, Protocol: "SCCM policy fixture", Method: Property{m.Request.Method, Observed}, Path: Property{m.Request.Route, Observed}, RequestContentType: Property{m.Request.ContentType, Observed}, ResponseContentType: Property{m.Response.ContentType, Observed}, VerificationState: state, FixtureIDs: []string{id}, ReadOnlyAssumption: Property{m.Contract.ReadOnlyAssumption, Observed}, SafetyNotes: []string{"fixture-only; live execution prohibited", "client registration and identity generation are not implemented"}}
	for k := range reqH {
		c.OptionalHeaders = append(c.OptionalHeaders, Property{k, Observed})
	}
	return f, c, nil
}

func SaveContract(root string, c Contract) error {
	if c.VerificationState == ApprovedLive {
		return errors.New("normal CLI cannot promote a contract to approved_live")
	}
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(filepath.Join(root, c.ID+".json"), b, 0600, false)
}
func LoadContract(root, id string) (Contract, error) {
	if filepath.Base(id) != id {
		return Contract{}, errors.New("unsafe contract id")
	}
	b, e := os.ReadFile(filepath.Join(root, id+".json"))
	if e != nil {
		return Contract{}, e
	}
	var c Contract
	e = json.Unmarshal(b, &c)
	return c, e
}
func ListContracts(root string) ([]Contract, error) {
	es, e := os.ReadDir(root)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var out []Contract
	for _, x := range es {
		if x.IsDir() || filepath.Ext(x.Name()) != ".json" {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(root, x.Name()))
		var c Contract
		if json.Unmarshal(b, &c) == nil {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

type Observation struct {
	Label, Presence string
	Values          []string
}
type Analysis struct {
	Method, Route string
	State         VerificationState
	Observations  []Observation
	Unknown       []string
}

func Analyze(fixtures []Fixture) Analysis {
	a := Analysis{State: FixtureOnly, Unknown: []string{"registration prerequisites", "whether the route is safe with an existing client", "whether user authentication alone is sufficient"}}
	if len(fixtures) == 0 {
		return a
	}
	a.Method = fixtures[0].Metadata.Request.Method
	a.Route = fixtures[0].Metadata.Request.Route
	all := map[string][]string{}
	for _, f := range fixtures {
		seen := map[string]bool{}
		for k, v := range f.RequestHeaders {
			all[k] = append(all[k], strings.Join(v, ","))
			seen[k] = true
		}
		for k := range all {
			if !seen[k] {
				all[k] = append(all[k], "")
			}
		}
	}
	for k, v := range all {
		presence := "observed in all fixtures"
		for _, x := range v {
			if x == "" {
				presence = "observed in some fixtures"
			}
		}
		uniq := map[string]bool{}
		for _, x := range v {
			if x != "" {
				uniq[x] = true
			}
		}
		vals := make([]string, 0, len(uniq))
		for x := range uniq {
			vals = append(vals, x)
		}
		sort.Strings(vals)
		a.Observations = append(a.Observations, Observation{k, presence, vals})
	}
	sort.Slice(a.Observations, func(i, j int) bool { return a.Observations[i].Label < a.Observations[j].Label })
	return a
}

type Assignment struct{ PolicyID, AssignmentID, PolicyCategory, PolicyVersion, PolicyFlags, PolicyReference, TargetReference, SiteCode, ClientReference, SourceFixtureID, Fingerprint string }
type Setting struct{ Name, Value, Path string }
type ParsedPolicy struct {
	PolicyID, Type, Category, Version string
	Settings                          []Setting
	UnknownFingerprint                string
}
type Candidate struct {
	ID, PolicyID, SourceFixture, Category, Field, SourcePath, Username, Value, RedactedPreview, State, Confidence, Fingerprint string
	Protected, Encrypted                                                                                                       bool
}
type parseNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr  `xml:",any,attr"`
	Text     string      `xml:",chardata"`
	Children []parseNode `xml:",any"`
}

func decodeXML(ctx context.Context, b []byte) (parseNode, error) {
	if len(b) > MaxFixtureBytes {
		return parseNode{}, errors.New("input exceeds policy parser limit")
	}
	if bytes.Contains(bytes.ToUpper(b), []byte("<!DOCTYPE")) || bytes.Contains(bytes.ToUpper(b), []byte("<!ENTITY")) {
		return parseNode{}, errors.New("XML entities and doctypes are forbidden")
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	var root parseNode
	if e := d.Decode(&root); e != nil {
		return root, errors.New("malformed policy XML")
	}
	if e := ctx.Err(); e != nil {
		return root, e
	}
	count := 0
	var walk func(parseNode, int) error
	walk = func(n parseNode, depth int) error {
		count++
		if depth > 32 || count > 10000 || len(n.Attrs) > 64 || len(n.Text) > 65536 {
			return errors.New("policy XML structural limit exceeded")
		}
		for _, c := range n.Children {
			if e := walk(c, depth+1); e != nil {
				return e
			}
		}
		return nil
	}
	return root, walk(root, 0)
}
func attr(n parseNode, names ...string) string {
	for _, a := range n.Attrs {
		for _, x := range names {
			if strings.EqualFold(a.Name.Local, x) {
				return strings.TrimSpace(a.Value)
			}
		}
	}
	return ""
}
func ParseAssignments(ctx context.Context, b []byte, fixtureID string) ([]Assignment, error) {
	root, e := decodeXML(ctx, b)
	if e != nil {
		return nil, e
	}
	if !strings.Contains(strings.ToLower(root.XMLName.Local), "assignment") {
		return nil, errors.New("unsupported assignment document")
	}
	var out []Assignment
	seen := map[string]bool{}
	var walk func(parseNode)
	walk = func(n parseNode) {
		if strings.Contains(strings.ToLower(n.XMLName.Local), "assignment") {
			a := Assignment{PolicyID: attr(n, "PolicyID", "PolicyId"), AssignmentID: attr(n, "AssignmentID", "AssignmentId"), PolicyCategory: attr(n, "PolicyCategory", "Category"), PolicyVersion: attr(n, "PolicyVersion", "Version"), PolicyFlags: attr(n, "PolicyFlags", "Flags"), PolicyReference: attr(n, "PolicyReference", "PolicyLocation"), TargetReference: attr(n, "TargetReference", "Target"), SiteCode: attr(n, "SiteCode"), ClientReference: attr(n, "ClientReference", "ClientID"), SourceFixtureID: fixtureID}
			a.Fingerprint = fingerprint(a.PolicyID, a.AssignmentID, a.PolicyVersion, a.PolicyReference)
			if a.PolicyID != "" && !seen[a.Fingerprint] {
				seen[a.Fingerprint] = true
				out = append(out, a)
			}
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(root)
	return out, nil
}
func ParsePolicy(ctx context.Context, b []byte) (ParsedPolicy, []Candidate, error) {
	root, e := decodeXML(ctx, b)
	if e != nil {
		return ParsedPolicy{}, nil, e
	}
	if !strings.Contains(strings.ToLower(root.XMLName.Local), "policy") {
		return ParsedPolicy{}, nil, errors.New("unsupported policy document")
	}
	p := ParsedPolicy{PolicyID: attr(root, "PolicyID", "PolicyId", "ID"), Type: attr(root, "Type", "PolicyType"), Category: attr(root, "Category", "PolicyCategory"), Version: attr(root, "Version", "PolicyVersion")}
	var walk func(parseNode, string)
	walk = func(n parseNode, path string) {
		path += "/" + n.XMLName.Local
		name := attr(n, "Name", "name")
		value := attr(n, "Value", "value")
		if value == "" {
			value = strings.TrimSpace(n.Text)
		}
		if name != "" && value != "" {
			if len(value) > 65536 {
				value = value[:65536]
			}
			p.Settings = append(p.Settings, Setting{name, value, path})
		}
		for _, c := range n.Children {
			walk(c, path)
		}
	}
	walk(root, "")
	sort.Slice(p.Settings, func(i, j int) bool {
		if p.Settings[i].Path == p.Settings[j].Path {
			return p.Settings[i].Name < p.Settings[j].Name
		}
		return p.Settings[i].Path < p.Settings[j].Path
	})
	c := Classify(p, "")
	sum := sha256.Sum256(b)
	p.UnknownFingerprint = "sha256:" + hex.EncodeToString(sum[:])
	return p, c, nil
}
func Classify(p ParsedPolicy, fixture string) []Candidate {
	var out []Candidate
	user := ""
	for _, s := range p.Settings {
		l := strings.ToLower(s.Name)
		if strings.Contains(l, "user") || strings.Contains(l, "account") {
			user = s.Value
		}
	}
	seen := map[string]bool{}
	for _, s := range p.Settings {
		l := strings.ToLower(s.Name + " " + s.Path)
		cat, state, conf := "", "plaintext_candidate", "medium"
		prot := strings.Contains(l, "protected") || strings.HasPrefix(s.Value, "<PolicySecret")
		enc := strings.Contains(l, "encrypted")
		switch {
		case prot:
			cat, state = "protected_secret_blob", "protected"
		case enc:
			cat, state = "encrypted_value", "encrypted"
		case strings.Contains(l, "password") || strings.Contains(l, "secret"):
			cat = "plaintext_password"
			if user != "" && strings.Contains(strings.ToLower(p.Category+" "+p.Type), "credential") {
				cat, state, conf = "username_password_pair", "confirmed_plaintext", "high"
			}
		case strings.Contains(l, "connectionstring") || strings.Contains(l, "connection_string"):
			cat = "connection_string_candidate"
		case strings.Contains(l, "script"):
			cat = "sensitive_script"
		case strings.Contains(l, "command"):
			cat = "sensitive_command"
		}
		if cat == "" {
			continue
		}
		fp := fingerprint(p.PolicyID, s.Path, s.Name, s.Value)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		c := Candidate{ID: "candidate_" + fp[:20], PolicyID: p.PolicyID, SourceFixture: fixture, Category: cat, Field: s.Name, SourcePath: s.Path, Username: user, Value: s.Value, RedactedPreview: redact(s.Value), State: state, Confidence: conf, Fingerprint: fp, Protected: prot, Encrypted: enc}
		if prot || enc {
			c.Value = ""
		}
		out = append(out, c)
	}
	return out
}
func Redacted(c Candidate) Candidate { c.Value = ""; c.Username = redact(c.Username); return c }
func redact(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return "[redacted]"
	}
	return string(r[:3]) + "..." + string(r[len(r)-2:])
}
func fingerprint(v ...string) string {
	h := sha256.Sum256([]byte(strings.Join(v, "\x00")))
	return hex.EncodeToString(h[:])
}

type SecretOptions struct {
	Show, Hide, Interactive, WriteEmpty, IncludeCandidates bool
	Profile, Path, Format                                  string
}

func OutputSecrets(w io.Writer, cands []Candidate, o SecretOptions) (int, error) {
	show := !o.Hide && (o.Show || (o.Interactive && (o.Profile == "aggressive" || o.Profile == "yolo")))
	uniq := map[string]Candidate{}
	for _, c := range cands {
		if c.State == "confirmed_plaintext" || (o.IncludeCandidates && c.State == "plaintext_candidate") {
			uniq[c.Fingerprint] = c
		}
	}
	items := make([]Candidate, 0, len(uniq))
	for _, c := range uniq {
		items = append(items, c)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Fingerprint < items[j].Fingerprint })
	if show && o.Profile != "safe" {
		for _, c := range items {
			label := "SECRET CANDIDATE"
			if c.State == "confirmed_plaintext" {
				label = "RECOVERED CREDENTIAL"
			}
			fmt.Fprintf(w, "%s\n\nType: %s\nUsername: %s\nPassword: %s\nSource policy: %s\nSource fixture: %s\nConfidence: %s\nUsable: unvalidated\n\n", label, c.Category, c.Username, c.Value, c.PolicyID, c.SourceFixture, c.Confidence)
		}
	}
	if o.Path != "" && (len(items) > 0 || o.WriteEmpty) {
		var b []byte
		var e error
		if o.Format == "json" {
			b, e = json.MarshalIndent(items, "", "  ")
		} else {
			var x strings.Builder
			for _, c := range items {
				fmt.Fprintf(&x, "[%s]\ntype=%s\nusername=%s\npassword=%s\nsource_policy=%s\nsource_fixture=%s\nconfidence=%s\nvalidated=false\n\n", c.State, c.Category, c.Username, c.Value, c.PolicyID, c.SourceFixture, c.Confidence)
			}
			b = []byte(x.String())
		}
		if e != nil {
			return 0, e
		}
		if e = atomicWrite(o.Path, b, 0600, true); e != nil {
			return 0, e
		}
	}
	return len(items), nil
}
func atomicWrite(path string, b []byte, mode os.FileMode, replace bool) error {
	if path == "" || filepath.Base(path) == "." {
		return errors.New("invalid output path")
	}
	if !replace {
		if _, e := os.Lstat(path); e == nil {
			return errors.New("output already exists")
		}
	}
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".cinderpath-output-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	_ = f.Chmod(mode)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	ok = true
	return nil
}

func Replay(ctx context.Context, c Contract, f Fixture, endpoint string) ([]byte, error) {
	u, e := url.Parse(endpoint)
	if e != nil {
		return nil, e
	}
	ips, e := net.LookupIP(u.Hostname())
	if e != nil {
		return nil, e
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return nil, errors.New("fixture replay endpoint must resolve only to loopback")
		}
	}
	u.Path = c.Path.Value
	u.RawQuery = ""
	req, e := http.NewRequestWithContext(ctx, c.Method.Value, u.String(), bytes.NewReader(f.RequestBody))
	if e != nil {
		return nil, e
	}
	for k, v := range f.RequestHeaders {
		if forbiddenHeader(k) {
			return nil, errors.New("authentication and cookie headers are forbidden in replay")
		}
		for _, x := range v {
			req.Header.Add(k, x)
		}
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 10 * time.Second}
	resp, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, MaxFixtureBytes+1))
}

var guidRE = regexp.MustCompile(`(?i)(?:GUID:)?\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?`)
var sidRE = regexp.MustCompile(`S-1-[0-9-]{6,}`)
var ipv4RE = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

func Sanitize(input, output string) error {
	_, err := SanitizeDirectory(SanitizeOptions{Input: input, Output: output, BinaryMode: BinaryMetadataOnly})
	return err
}

type ClientIdentity struct {
	Kind, ClientID, SiteCode, ManagementPoint string
	Certificate                               struct{ Reference, Fingerprint, Subject, NotBefore, NotAfter string }
	Source                                    struct {
		Type, CapturedAt string
		Verified         bool
	}
}

func ParseClientIdentity(b []byte) (ClientIdentity, error) {
	var x ClientIdentity
	if e := yaml.Unmarshal(b, &x); e != nil {
		return x, e
	}
	if x.Kind != "existing_sccm_client" {
		return x, errors.New("kind must be existing_sccm_client")
	}
	if !guidRE.MatchString(x.ClientID) {
		return x, errors.New("client_id must be an existing GUID reference")
	}
	if x.Certificate.Reference != "" && strings.Contains(x.Certificate.Reference, "PRIVATE KEY") {
		return x, errors.New("certificate must be a reference, not private key contents")
	}
	return x, nil
}
