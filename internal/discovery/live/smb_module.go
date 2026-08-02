package live

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/progress"
	"github.com/hirochachacha/go-smb2"
)

const (
	defaultSMBPort      = 445
	defaultSMBMaxShares = 128
	maxSMBShareName     = 256
)

type smbShareMetadataModule struct{ opts Options }

type smbSession interface {
	ListSharenames() ([]string, error)
	Logoff() error
}

var dialSMBSession = func(ctx context.Context, conn net.Conn, user, password, domain string) (smbSession, error) {
	return (&smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: user, Password: password, Domain: domain}}).DialContext(ctx, conn)
}
var dialSMBTCP = func(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
}

func (m *smbShareMetadataModule) Metadata() modules.Metadata {
	return modules.Metadata{Name: "live.smb.share_metadata", Description: "Enumerates bounded authenticated SMB share metadata through IPC$ srvsvc", Category: modules.CategoryDiscovery, Safety: modules.SafetySafe}
}
func (m *smbShareMetadataModule) Applicable(context.Context, modules.RunContext, *models.Asset) (bool, string) {
	o := m.opts.SMB
	if !o.Enabled {
		return false, "SMB share metadata was not explicitly enabled"
	}
	if o.Server == "" {
		return false, "SMB target was not supplied"
	}
	if o.User == "" {
		return false, "SMB identity was not supplied"
	}
	if o.Password == "" {
		return false, "SMB password reference did not resolve"
	}
	return true, ""
}

func (m *smbShareMetadataModule) Run(parent context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	o := m.opts.SMB
	connectTimeout, operationTimeout, maxShares := o.ConnectTimeout, o.OperationTimeout, o.MaxShares
	if connectTimeout <= 0 {
		connectTimeout = 5 * time.Second
	}
	if operationTimeout <= 0 {
		operationTimeout = 10 * time.Second
	}
	if maxShares <= 0 || maxShares > defaultSMBMaxShares {
		maxShares = defaultSMBMaxShares
	}
	ctx, cancel := context.WithTimeout(parent, operationTimeout)
	defer cancel()
	port := o.Port
	if port == 0 {
		port = defaultSMBPort
	}
	address := net.JoinHostPort(o.Server, fmt.Sprint(port))
	run.Emit(progress.Event{Type: progress.StageStarted, Module: m.Metadata().Name, Message: "authenticated SMB srvsvc share metadata"})
	conn, err := dialSMBTCP(ctx, address, connectTimeout)
	if err != nil {
		return smbFailure(o, "connection_failed", fmt.Errorf("SMB connection: %w", err)), nil
	}
	defer conn.Close()
	user, domain := splitSMBPrincipal(o.User, o.Domain)
	session, err := dialSMBSession(ctx, conn, user, o.Password, domain)
	if err != nil {
		classification := "protocol_negotiation_failed"
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "logon") || strings.Contains(lower, "password") || strings.Contains(lower, "access denied") || strings.Contains(lower, "authentication") {
			classification = "authentication_failed"
		}
		return smbFailure(o, classification, fmt.Errorf("SMB session setup: %w", err)), nil
	}
	defer session.Logoff()
	names, err := session.ListSharenames()
	if err != nil {
		classification := "share_enumeration_failed"
		if strings.Contains(strings.ToLower(err.Error()), "bind") {
			classification = "rpc_bind_failed"
		}
		return smbFailure(o, classification, fmt.Errorf("srvsvc share enumeration: %w", err)), nil
	}
	sort.Strings(names)
	observedShareCount := len(names)
	truncated := observedShareCount > maxShares
	if truncated {
		names = names[:maxShares]
	}
	shares := make([]map[string]any, 0, len(names))
	hasSCCM := false
	for _, raw := range names {
		name := sanitizeSMBText(raw, maxSMBShareName)
		classification := classifySMBShare(name)
		if classification != "unclassified_share" && classification != "generic_administrative_share" {
			hasSCCM = true
		}
		shares = append(shares, map[string]any{"name": name, "classification": classification, "type": "share_metadata"})
	}
	asset := models.Asset{Kind: models.AssetUnknown, FQDN: o.Server, Domain: strings.ToUpper(o.Domain), Roles: []string{"smb_endpoint"}, Source: m.Metadata().Name, Confidence: models.ConfidenceConfirmed, Properties: map[string]string{"observation_origin": "live", "network_behavior": "smb_share_metadata_only"}}
	asset.Prepare(time.Now().UTC())
	data := map[string]any{"server": o.Server, "endpoint": address, "protocol": "SMB2/3", "dialect": "unknown_library_does_not_expose_negotiated_dialect", "signing_enabled": "unknown_library_does_not_expose_signing_state", "signing_required": "unknown_library_does_not_expose_signing_state", "named_pipe": "srvsvc", "rpc_operation": "NetShareEnumAll", "shares": shares, "share_count": len(names), "observed_share_count": observedShareCount, "truncated": truncated, "network_behavior": "smb_share_metadata_only"}
	evidence := models.Evidence{Type: "smb_share_metadata", Title: "Authenticated SMB share metadata", Summary: "One authenticated SMB2/3 session enumerated bounded share metadata through IPC$ srvsvc; no files or directories were read.", Data: data, SourceModule: m.Metadata().Name, AssetID: asset.ID, Sensitivity: models.SensitivityInternal}
	evidence.Prepare(time.Now().UTC())
	cred := models.Credential{Username: o.User, Domain: domain, Type: models.CredentialPasswordRef, Source: m.Metadata().Name, HasSecret: o.PasswordReference != "", SecretReference: o.PasswordReference, Properties: map[string]string{"storage": "reference_only"}}
	cred.Prepare()
	cap := models.Capability{Name: "smb_authenticated_share_metadata", Available: true, Reason: "Authenticated srvsvc share enumeration completed", Source: m.Metadata().Name, AssetID: asset.ID, CredentialID: cred.ID, EvidenceIDs: []string{evidence.ID}}
	cap.Prepare()
	out := &modules.Result{Assets: []models.Asset{asset}, Credentials: []models.Credential{cred}, Capabilities: []models.Capability{cap}, Evidence: []models.Evidence{evidence}}
	for _, share := range shares {
		name := fmt.Sprint(share["name"])
		shareAsset := models.Asset{Kind: models.AssetUnknown, FQDN: o.Server + "\\" + name, Source: m.Metadata().Name, Confidence: models.ConfidenceMedium, Properties: map[string]string{"share_classification": fmt.Sprint(share["classification"]), "observation_origin": "live"}}
		shareAsset.Prepare(time.Now().UTC())
		out.Assets = append(out.Assets, shareAsset)
		rel := models.Relationship{FromID: asset.ID, ToID: shareAsset.ID, Type: models.RelationshipContains, Properties: map[string]string{"relation": "host_exposes_share", "share_name": name}, EvidenceIDs: []string{evidence.ID}, Confidence: models.ConfidenceConfirmed}
		rel.Prepare()
		out.Relationships = append(out.Relationships, rel)
	}
	if hasSCCM {
		finding := models.Finding{RuleID: "SCCM-RECON-2-SHARE-METADATA", Title: "Authenticated SMB enumeration exposed SCCM role-identifying share metadata", Summary: "SCCM-relevant share names were observed without reading share contents.", Description: "This is informational reconnaissance evidence only; share names do not establish a definitive role or vulnerability.", Severity: models.SeverityInformational, Confidence: models.ConfidenceMedium, Status: models.FindingOpen, AssetIDs: []string{asset.ID}, EvidenceIDs: []string{evidence.ID}, Tags: []string{"reconnaissance", "smb", "sccm"}, Remediation: "Review SMB exposure and role-specific access controls."}
		finding.Prepare(time.Now().UTC())
		out.Findings = append(out.Findings, finding)
	} else {
		out.Warnings = append(out.Warnings, "completed_no_sccm_shares: absence of SCCM share names does not prove absence of an SCCM role")
	}
	run.Emit(progress.Event{Type: progress.ModuleCompleted, Module: m.Metadata().Name, Message: "SMB share metadata completed", Data: map[string]any{"shares": len(names), "truncated": truncated}})
	return out, nil
}

func smbFailure(o SMBOptions, classification string, err error) *modules.Result {
	cred := models.Credential{Username: o.User, Type: models.CredentialPasswordRef, Source: "live.smb.share_metadata", HasSecret: o.PasswordReference != "", SecretReference: o.PasswordReference, Properties: map[string]string{"storage": "reference_only", "validation": "failed"}}
	cred.Prepare()
	e := models.Evidence{Type: "smb_connection", Title: "SMB assessment failed", Summary: err.Error(), Data: map[string]any{"server": o.Server, "classification": classification, "network_behavior": "smb_share_metadata_only", "error": err.Error()}, SourceModule: "live.smb.share_metadata", CredentialID: cred.ID, Sensitivity: models.SensitivityInternal}
	e.Prepare(time.Now().UTC())
	return &modules.Result{Credentials: []models.Credential{cred}, Evidence: []models.Evidence{e}, Errors: []modules.ResultError{{Message: classification + ": " + err.Error()}}, Warnings: []string{classification}}
}

func splitSMBPrincipal(principal, fallbackDomain string) (string, string) {
	if i := strings.IndexByte(principal, '\\'); i > 0 {
		return principal[i+1:], principal[:i]
	}
	if i := strings.LastIndexByte(principal, '@'); i > 0 {
		return principal[:i], principal[i+1:]
	}
	return principal, fallbackDomain
}
func sanitizeSMBText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		return s[:max]
	}
	return s
}
func classifySMBShare(name string) string {
	u := strings.ToUpper(strings.TrimSpace(name))
	switch {
	case u == "SCCMCONTENTLIB$":
		return "content_library_candidate"
	case strings.HasPrefix(u, "SMS_DP") || strings.HasPrefix(u, "SMSPKG"):
		return "distribution_point_share_candidate"
	case u == "SMSSIG$":
		return "signature_share_candidate"
	case strings.HasPrefix(u, "SMS_") && len(u) > 4:
		return "sccm_site_share_candidate"
	case u == "ADMIN$" || u == "C$" || u == "IPC$" || u == "NETLOGON" || u == "SYSVOL":
		return "generic_administrative_share"
	default:
		return "unclassified_share"
	}
}
