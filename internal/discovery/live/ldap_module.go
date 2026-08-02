package live

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/progress"
)

type ldapRootDSEModule struct {
	opts    Options
	connect func(context.Context, LDAPOptions) (directoryClient, error)
}

func (m *ldapRootDSEModule) Metadata() modules.Metadata {
	return modules.Metadata{Name: "live.ldap.rootdse", Description: "Validates an explicit LDAP bind and reads bounded RootDSE attributes", Category: modules.CategoryDiscovery, Safety: modules.SafetySafe}
}
func (m *ldapRootDSEModule) Applicable(_ context.Context, _ modules.RunContext, _ *models.Asset) (bool, string) {
	if !m.opts.LDAP.Enabled {
		return false, "LDAP discovery was not explicitly enabled"
	}
	if m.opts.LDAP.Server == "" {
		return false, "LDAP server or domain controller was not supplied"
	}
	return true, ""
}
func (m *ldapRootDSEModule) Run(ctx context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	run.Emit(progress.Event{Type: progress.StageStarted, Module: m.Metadata().Name, Message: "explicit LDAP RootDSE discovery"})
	connect := m.connect
	if connect == nil {
		connect = connectLDAP
	}
	client, err := connect(ctx, m.opts.LDAP)
	if err != nil {
		return ldapFailure(m.opts.LDAP, err), nil
	}
	defer client.Close()
	root, err := client.RootDSE(ctx)
	if err != nil {
		return ldapFailure(m.opts.LDAP, fmt.Errorf("read RootDSE: %w", err)), nil
	}
	now := time.Now()
	endpoint := findEndpointAsset(ctx, run, m.opts.LDAP.Server)
	data := rootDSEData(root)
	data["server"] = m.opts.LDAP.Server
	data["bind_type"] = bindType(m.opts.LDAP)
	data["tls_mode"] = tlsMode(m.opts.LDAP)
	data["tls_verification_skipped"] = m.opts.LDAP.InsecureSkipVerify
	e := models.Evidence{Type: "ldap_rootdse", Title: "LDAP RootDSE environment metadata", Summary: "Explicit LDAP bind succeeded and bounded RootDSE attributes were read.", Data: data, SourceModule: m.Metadata().Name, AssetID: endpoint, Sensitivity: models.SensitivityInternal}
	e.Prepare(now)
	out := &modules.Result{Evidence: []models.Evidence{e}}
	cred := models.Credential{Username: m.opts.LDAP.User, Domain: m.opts.Domain, Type: models.CredentialUsernamePassword, Source: m.Metadata().Name, HasSecret: m.opts.LDAP.PasswordReference != "", SecretReference: m.opts.LDAP.PasswordReference, Properties: map[string]string{"storage": "reference_only"}}
	if m.opts.LDAP.Anonymous {
		cred.Type = models.CredentialAnonymous
		cred.Username = "anonymous"
		cred.HasSecret = false
	}
	cred.Prepare()
	out.Credentials = []models.Credential{cred}
	for _, cap := range ldapCapabilities(root, m.opts.LDAP, endpoint, cred.ID, e.ID) {
		cap.Prepare()
		out.Capabilities = append(out.Capabilities, cap)
	}
	if root.DefaultNamingContext != "" {
		domain := models.Asset{Kind: models.AssetDomain, FQDN: domainFromDN(root.DefaultNamingContext), Domain: strings.ToUpper(domainFromDN(root.DefaultNamingContext)), Properties: map[string]string{"observation_origin": "live", "naming_context": root.DefaultNamingContext}, Source: m.Metadata().Name, Confidence: models.ConfidenceHigh}
		domain.Prepare(now)
		out.Assets = append(out.Assets, domain)
	}
	return out, nil
}
func ldapFailure(opts LDAPOptions, err error) *modules.Result {
	cred := models.Credential{Username: opts.User, Type: models.CredentialUsernamePassword, Source: "live.ldap.rootdse", HasSecret: opts.PasswordReference != "", SecretReference: opts.PasswordReference, Properties: map[string]string{"storage": "reference_only", "validation": "failed"}}
	if opts.Anonymous {
		cred.Username = "anonymous"
		cred.Type = models.CredentialAnonymous
		cred.HasSecret = false
	}
	cred.Prepare()
	cap := models.Capability{Name: "ldap_bind_successful", Available: false, Reason: err.Error(), Source: "live.ldap.rootdse", CredentialID: cred.ID}
	cap.Prepare()
	e := models.Evidence{Type: "ldap_connection", Title: "LDAP connection or bind failed", Summary: err.Error(), Data: map[string]any{"server": opts.Server, "bind_type": bindType(opts), "tls_mode": tlsMode(opts), "error": err.Error()}, SourceModule: "live.ldap.rootdse", CredentialID: cred.ID, Sensitivity: models.SensitivityInternal}
	e.Prepare(time.Now())
	cap.EvidenceIDs = []string{e.ID}
	return &modules.Result{Credentials: []models.Credential{cred}, Capabilities: []models.Capability{cap}, Evidence: []models.Evidence{e}, Warnings: []string{err.Error()}}
}
func rootDSEData(r rootDSE) map[string]any {
	return map[string]any{"default_naming_context": r.DefaultNamingContext, "configuration_naming_context": r.ConfigurationNamingContext, "root_domain_naming_context": r.RootDomainNamingContext, "schema_naming_context": r.SchemaNamingContext, "dns_host_name": r.DNSHostName, "supported_ldap_version": r.SupportedLDAPVersion, "supported_sasl_mechanisms": r.SupportedSASLMechanisms, "domain_functionality": r.DomainFunctionality, "forest_functionality": r.ForestFunctionality, "domain_controller_functionality": r.DomainControllerFunctionality, "is_global_catalog_ready": r.IsGlobalCatalogReady}
}
func bindType(o LDAPOptions) string {
	if o.Anonymous {
		return "explicit_anonymous"
	}
	return "simple_reference"
}
func tlsMode(o LDAPOptions) string {
	if o.UseTLS {
		return "ldaps"
	}
	if o.StartTLS {
		return "starttls"
	}
	return "ldap"
}
func findEndpointAsset(ctx context.Context, run modules.RunContext, server string) string {
	a, _ := run.Store.ListAssets(ctx)
	for _, v := range a {
		if strings.EqualFold(targetAddress(v), server) {
			return v.ID
		}
	}
	return ""
}
func ldapCapabilities(r rootDSE, o LDAPOptions, asset, cred, evidence string) []models.Capability {
	base := []models.Capability{{Name: "ldap_endpoint_reachable", Available: true, Reason: "LDAP connection established", Source: "live.ldap.rootdse"}, {Name: "ldap_bind_successful", Available: true, Reason: "Explicit LDAP bind succeeded", Source: "live.ldap.rootdse"}, {Name: "rootdse_readable", Available: true, Reason: "Bounded RootDSE query succeeded", Source: "live.ldap.rootdse"}, {Name: "default_naming_context_known", Available: r.DefaultNamingContext != "", Reason: "RootDSE defaultNamingContext", Source: "live.ldap.rootdse"}, {Name: "configuration_naming_context_known", Available: r.ConfigurationNamingContext != "", Reason: "RootDSE configurationNamingContext", Source: "live.ldap.rootdse"}}
	if o.Anonymous {
		base = append(base, models.Capability{Name: "ldap_anonymous", Available: true, Reason: "Anonymous bind was explicitly requested and succeeded", Source: "live.ldap.rootdse"})
	} else {
		base = append(base, models.Capability{Name: "ldap_authenticated", Available: true, Reason: "Credential-reference bind succeeded", Source: "live.ldap.rootdse"})
	}
	for i := range base {
		base[i].AssetID = asset
		base[i].CredentialID = cred
		base[i].EvidenceIDs = []string{evidence}
	}
	return base
}

type ldapDirectoryModule struct {
	opts    Options
	connect func(context.Context, LDAPOptions) (directoryClient, error)
}

func (m *ldapDirectoryModule) Metadata() modules.Metadata {
	return modules.Metadata{Name: "live.ldap.sccm_directory", Description: "Searches bounded SCCM-related AD objects with paging", Category: modules.CategoryDiscovery, Safety: modules.SafetySafe, Requirements: []modules.Requirement{{Capability: "rootdse_readable"}}}
}
func (m *ldapDirectoryModule) Applicable(_ context.Context, _ modules.RunContext, _ *models.Asset) (bool, string) {
	if !m.opts.LDAP.Enabled {
		return false, "LDAP discovery was not explicitly enabled"
	}
	return true, ""
}
func (m *ldapDirectoryModule) Run(ctx context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	connect := m.connect
	if connect == nil {
		connect = connectLDAP
	}
	client, err := connect(ctx, m.opts.LDAP)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	root, err := client.RootDSE(ctx)
	if err != nil {
		return nil, err
	}
	objects, err := client.SearchSCCM(ctx, root, m.opts.LDAP.BaseDN, m.opts.LDAP.PageSize, m.opts.LDAP.MaxEntries)
	if err != nil {
		return nil, err
	}
	out := &modules.Result{}
	now := time.Now()
	siteIDs := map[string]string{}
	for _, obj := range objects {
		e := models.Evidence{Type: "ldap_sccm_object", Title: "SCCM-related directory object", Summary: "Bounded LDAP search returned an object with SCCM-related class, name, keywords, or service binding metadata.", Data: map[string]any{"distinguished_name": obj.DN, "attributes": obj.Attributes, "inferred_roles": obj.Roles, "referenced_hosts": obj.Hosts}, SourceModule: m.Metadata().Name, Sensitivity: models.SensitivityInternal}
		e.Prepare(now)
		out.Evidence = append(out.Evidence, e)
		if hasRole(obj.Roles, "site_server") {
			if siteCode := strings.ToUpper(first(obj.Attributes, "mSMSSiteCode")); siteCode != "" {
				site := models.Asset{Kind: models.AssetSite, SiteCode: siteCode, Domain: strings.ToUpper(m.opts.Domain), Properties: map[string]string{"observation_origin": "live", "directory_reference": models.StableFingerprint(obj.DN), "role_basis": "ldap_sccm_object"}, Source: m.Metadata().Name, Confidence: models.ConfidenceHigh}
				site.Prepare(now)
				out.Assets = append(out.Assets, site)
				siteIDs[siteCode] = site.ID
			}
		}
		for _, host := range obj.Hosts {
			kind := models.AssetUnknown
			if hasRole(obj.Roles, "management_point") {
				kind = models.AssetManagementPoint
			} else if hasRole(obj.Roles, "site_server") {
				kind = models.AssetSiteServer
			}
			a := models.Asset{Kind: kind, FQDN: host, Hostname: strings.Split(host, ".")[0], Domain: strings.ToUpper(m.opts.Domain), SiteCode: first(obj.Attributes, "mSMSSiteCode"), Roles: obj.Roles, Properties: map[string]string{"observation_origin": "live", "directory_reference": models.StableFingerprint(obj.DN), "role_basis": "ldap_sccm_object"}, Source: m.Metadata().Name, Confidence: models.ConfidenceHigh}
			a.Prepare(now)
			out.Assets = append(out.Assets, a)
			rel := models.Relationship{FromID: models.StableID("ldapobj", models.StableFingerprint(obj.DN)), ToID: a.ID, Type: models.RelationshipDirectoryReferencesHost, Properties: map[string]string{"origin": "live", "distinguished_name": obj.DN}, EvidenceIDs: []string{e.ID}, Confidence: models.ConfidenceHigh}
			rel.Prepare()
			out.Relationships = append(out.Relationships, rel)
			if siteCode := strings.ToUpper(first(obj.Attributes, "mSMSSiteCode")); siteCode != "" {
				if siteID := siteIDs[siteCode]; siteID != "" {
					member := models.Relationship{FromID: a.ID, ToID: siteID, Type: models.RelationshipMemberOfSite, Properties: map[string]string{"origin": "live", "site_code": siteCode}, EvidenceIDs: []string{e.ID}, Confidence: models.ConfidenceHigh}
					member.Prepare()
					out.Relationships = append(out.Relationships, member)
				}
			}
		}
	}
	if recon := recon1Evidence(objects, root, m.Metadata().Name); recon != nil {
		out.Evidence = append(out.Evidence, recon.Evidence...)
		out.Findings = append(out.Findings, recon.Findings...)
		out.Capabilities = append(out.Capabilities, recon.Capabilities...)
		out.Warnings = append(out.Warnings, recon.Warnings...)
	}
	cap := models.Capability{Name: "sccm_directory_objects_discovered", Available: len(objects) > 0, Reason: fmt.Sprintf("bounded LDAP searches returned %d SCCM-related objects", len(objects)), Source: m.Metadata().Name, EvidenceIDs: evidenceIDs(out.Evidence)}
	cap.Prepare()
	out.Capabilities = append(out.Capabilities, cap)
	if len(objects) > 0 {
		f := models.Finding{RuleID: "DISCOVERY-SCCM-DIRECTORY", Title: "SCCM-related LDAP objects discovered", Summary: fmt.Sprintf("Read-only LDAP searches found %d potentially SCCM-related directory objects.", len(objects)), Description: "This informational result identifies directory metadata for topology mapping; it is not a vulnerability.", Severity: models.SeverityInformational, Confidence: models.ConfidenceHigh, EvidenceIDs: evidenceIDs(out.Evidence), Tags: []string{"discovery", "ldap", "sccm"}, Remediation: "Confirm role assignments and restrict directory visibility only where operationally appropriate."}
		f.Prepare(now)
		out.Findings = []models.Finding{f}
	}
	return out, nil
}

func hasRole(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func recon1Evidence(objects []directoryObject, root rootDSE, source string) *modules.Result {
	if len(objects) == 0 {
		return &modules.Result{Warnings: []string{"RECON-1 found no SCCM-related LDAP objects within the bounded search"}}
	}
	sites, mps := map[string]bool{}, map[string]bool{}
	systemManagement, namingHints := false, 0
	for _, obj := range objects {
		text := strings.ToLower(obj.DN + " " + strings.Join(flatten(obj.Attributes), " "))
		if strings.Contains(text, "cn=system management") {
			systemManagement = true
		}
		if hasRole(obj.Roles, "site_server") {
			if v := first(obj.Attributes, "mSMSSiteCode"); v != "" {
				sites[strings.ToUpper(v)] = true
			}
		}
		if hasRole(obj.Roles, "management_point") {
			for _, h := range obj.Hosts {
				mps[h] = true
			}
		}
		if strings.Contains(text, "sccm") || strings.Contains(text, "mecm") || strings.Contains(text, "configmgr") || strings.Contains(text, "sms") {
			namingHints++
		}
	}
	data := map[string]any{"technique_id": "RECON-1", "publishing_state": "sccm_ad_publishing_confirmed", "system_management_state": map[bool]string{true: "system_management_container_present", false: "historical_or_partial_sccm_evidence"}[systemManagement], "sites_observed": sortedStrings(sites), "management_points_observed": sortedStrings(mps), "possible_cas_sites": []string{}, "weak_naming_hints": namingHints, "default_naming_context_fingerprint": models.StableFingerprint(root.DefaultNamingContext), "evidence_source": source, "network_behavior": "ldap_only"}
	e := models.Evidence{Type: "recon1_ldap_assessment", Title: "RECON-1 SCCM site information via LDAP", Summary: "Bounded LDAP evidence assessed SCCM publishing objects, sites, and management points.", Data: data, SourceModule: source, Sensitivity: models.SensitivityInternal}
	e.Prepare(time.Now())
	cap := models.Capability{Name: "recon1_ldap_assessment", Available: true, Reason: "bounded LDAP SCCM publishing evidence was assessed", Source: source, EvidenceIDs: []string{e.ID}}
	cap.Prepare()
	f := models.Finding{RuleID: "SCCM-RECON-1-AD-PUBLISHING-CONFIRMED", Title: "SCCM AD publishing observed", Summary: "LDAP publishing metadata identifies SCCM site or management-point objects.", Description: "This is a discovery observation, not a vulnerability or authorization finding.", Severity: models.SeverityInformational, Confidence: models.ConfidenceHigh, EvidenceIDs: []string{e.ID}, Tags: []string{"discovery", "ldap", "recon-1"}}
	f.Prepare(time.Now())
	return &modules.Result{Evidence: []models.Evidence{e}, Capabilities: []models.Capability{cap}, Findings: []models.Finding{f}}
}
func sortedStrings(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for x := range m {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}
func evidenceIDs(in []models.Evidence) []string {
	out := make([]string, len(in))
	for i := range in {
		out[i] = in[i].ID
	}
	return out
}
