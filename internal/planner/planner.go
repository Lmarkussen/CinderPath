// Package planner resolves declared technique facts into bounded module plans.
package planner

import (
	"os"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/framework"
	"github.com/Lmarkussen/CinderPath/internal/models"
)

type Fact string

const (
	DomainContext      Fact = "domain_context"
	RootDSE            Fact = "rootdse"
	SiteCode           Fact = "site_code"
	ManagementPt       Fact = "management_point"
	SMBTarget          Fact = "smb_target"
	HTTPTarget         Fact = "http_target"
	Identity           Fact = "authenticated_identity"
	ClientIdentity     Fact = "client_identity"
	PolicyEndpoint     Fact = "policy_endpoint"
	LocalExecution     Fact = "local_windows_execution"
	SCCMClient         Fact = "installed_sccm_client"
	SystemContext      Fact = "system_context"
	CurrentNAA         Fact = "current_naa_artifact"
	SMSProvider        Fact = "sms_provider"
	CMPivotAccess      Fact = "cmpivot_permission"
	RemoteRegistry     Fact = "remote_registry"
	LocalSCCMFiles     Fact = "local_sccm_files"
	ConfigMgrNegotiate Fact = "explicit_configmgr_negotiate"
)

type State string

const (
	Current       State = "already_satisfied_current_run"
	Recent        State = "satisfied_by_compatible_prior_evidence"
	Collect       State = "requires_safe_collection"
	OperatorInput State = "requires_operator_input"
	Unsupported   State = "unsupported"
	Blocked       State = "blocked_by_safety_gate"
	Stale         State = "stale"
	Conflicting   State = "conflicting"
	Missing       State = "missing"
)

type Requirement struct {
	Fact  Fact
	Label string
}
type Decision struct {
	Requirement
	State     State  `json:"state"`
	Reason    string `json:"reason"`
	Module    string `json:"module,omitempty"`
	SourceRun string `json:"source_run,omitempty"`
	Age       string `json:"age,omitempty"`
}
type Input struct {
	Technique, Provider, Target, DomainController, Username, CurrentRun   string
	ClientID, ClientIdentitySource, ClientIdentityReason, ManagementPoint string
	AllowSafeLDAP                                                         *bool
	Evidence                                                              []models.Evidence
	Now                                                                   time.Time
	EvidenceMaxAge                                                        time.Duration
	LocalExecution                                                        bool
}
type Plan struct {
	Technique     string     `json:"technique"`
	Prerequisites []Decision `json:"prerequisites"`
	Modules       []string   `json:"modules"`
}

// OrchestrationSpec describes how a family selector should interpret the
// environment target. It is intentionally small: family runners use this
// metadata to route a child without turning the planner into a scheduler.
type OrchestrationSpec struct {
	Technique   string `json:"technique"`
	TargetRole  string `json:"target_role"`
	Execution   string `json:"execution_locality"`
	Capability  string `json:"required_capability,omitempty"`
	Implemented bool   `json:"implemented"`
}

func OrchestrationFor(technique string) OrchestrationSpec {
	id := strings.ToUpper(strings.TrimSpace(technique))
	spec := OrchestrationSpec{Technique: id, TargetRole: "environment_root", Execution: "current_assessment_host"}
	switch id {
	case "RECON-1":
		spec.TargetRole, spec.Capability = "directory_site_context", "ldap_identity"
	case "RECON-2":
		spec.TargetRole, spec.Capability = "site_system", "sccm_smb"
	case "RECON-3":
		spec.TargetRole, spec.Capability = "management_point", "sccm_http"
	case "RECON-4":
		spec.TargetRole, spec.Capability = "sccm_client_via_management_point", "explicit_configmgr_negotiate"
		spec.Execution = "management_point_authority"
	case "CRED-1":
		spec.TargetRole, spec.Capability = "distribution_point_or_management_point", "packet_capture"
	case "CRED-2", "CRED-3":
		spec.TargetRole, spec.Capability = "sccm_client", "local_sccm_client_context"
		spec.Execution = "local_sccm_client"
	default:
		return spec
	}
	spec.Implemented = familyTechniqueImplemented(id)
	return spec
}

func familyTechniqueImplemented(id string) bool {
	switch strings.ToUpper(id) {
	case "RECON-1", "RECON-2", "RECON-3", "RECON-4", "CRED-1", "CRED-2", "CRED-3":
		return true
	default:
		return false
	}
}

func RequirementsFor(technique string) []Requirement {
	switch strings.ToUpper(technique) {
	case "RECON-1":
		return []Requirement{{RootDSE, "RootDSE"}, {SiteCode, "SCCM site"}, {ManagementPt, "Management point"}, {Identity, "Authorized identity"}}
	case "RECON-2":
		return []Requirement{{SMBTarget, "SMB target"}, {Identity, "Authorized identity"}}
	case "RECON-3":
		return []Requirement{{HTTPTarget, "HTTP target"}}
	case "RECON-4":
		return []Requirement{{SMSProvider, "SMS Provider"}, {CMPivotAccess, "CMPivot permission"}, {ConfigMgrNegotiate, "explicit ConfigMgr Negotiate authentication"}}
	case "RECON-5":
		return []Requirement{{SMSProvider, "SMS Provider"}, {Identity, "ConfigMgr authorized identity"}}
	case "RECON-6":
		return []Requirement{{SMBTarget, "SMB target"}, {RemoteRegistry, "Remote Registry winreg"}, {Identity, "Authorized identity"}}
	case "RECON-7":
		return []Requirement{{LocalSCCMFiles, "local SCCM client files"}}
	case "CRED-2":
		return []Requirement{{DomainContext, "Domain context"}, {RootDSE, "RootDSE"}, {SiteCode, "SCCM site"}, {ManagementPt, "Management point"}, {Identity, "Authorized identity"}, {ClientIdentity, "Existing SCCM client identity"}, {PolicyEndpoint, "Policy endpoint"}}
	default:
		return nil
	}
}

func Resolve(in Input) Plan {
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	if in.EvidenceMaxAge <= 0 {
		in.EvidenceMaxAge = 30 * 24 * time.Hour
	}
	p := Plan{Technique: strings.ToUpper(in.Technique)}
	if !framework.IsProductTechnique(p.Technique) {
		p.Prerequisites = []Decision{{Requirement: Requirement{Fact: "product_scope", Label: "CinderPath product scope"}, State: Unsupported, Reason: "technique family is out of scope; CinderPath supports CRED, ELEVATE, EXEC, RECON, TAKEOVER, and COERCE"}}
		return p
	}
	if (p.Technique == "CRED-2" || p.Technique == "CRED-3") && in.LocalExecution {
		adapterReason := p.Technique + " local-client adapter selected; runtime verifies Windows"
		p.Prerequisites = []Decision{
			{Requirement: Requirement{LocalExecution, "Windows local execution"}, State: Current, Reason: adapterReason},
			{Requirement: Requirement{SCCMClient, "installed SCCM client"}, State: Current, Reason: "runtime verifies the fixed SCCM WMI namespace"},
			{Requirement: Requirement{SystemContext, `NT AUTHORITY\\SYSTEM context`}, State: Current, Reason: "runtime verifies the current security token"},
			{Requirement: Requirement{CurrentNAA, "current CCM_NetworkAccessAccount artifact"}, State: Current, Reason: "runtime reads the current artifact and refuses historical evidence"},
		}
		return p
	}
	if p.Technique == "RECON-4" {
		p.Prerequisites = []Decision{
			{Requirement: Requirement{Fact: HTTPTarget, Label: "ConfigMgr AdminService target"}, State: func() State {
				if in.Target != "" {
					return Current
				}
				return OperatorInput
			}(), Reason: "explicit client target is required"},
			{Requirement: Requirement{Fact: ConfigMgrNegotiate, Label: "explicit ConfigMgr Negotiate authentication"}, State: func() State {
				if in.Username != "" && os.Getenv("CINDERPATH_CONFIGMGR_AUTHORITY") != "" && os.Getenv("CINDERPATH_CONFIGMGR_TRANSPORT_IP") != "" {
					return Current
				}
				return OperatorInput
			}(), Reason: "explicit identity and ConfigMgr authority/transport configuration are required"},
		}
		if executable(p.Prerequisites) {
			p.Modules = []string{"recon4.cmpivot"}
		}
		return p
	}
	for _, r := range RequirementsFor(p.Technique) {
		p.Prerequisites = append(p.Prerequisites, resolve(r, in))
	}
	for _, d := range p.Prerequisites {
		if d.State == Collect && d.Module != "" {
			p.Modules = append(p.Modules, d.Module)
		}
	}
	if executable(p.Prerequisites) {
		switch p.Technique {
		case "RECON-1":
			p.Modules = append(p.Modules, "live.ldap.rootdse", "live.ldap.sccm_directory")
		case "RECON-2":
			p.Modules = append(p.Modules, "live.smb.share_metadata")
		case "RECON-3":
			p.Modules = append(p.Modules, "live.sccm.http_recon")
		}
	}
	p.Modules = unique(p.Modules)
	return p
}

func executable(ds []Decision) bool {
	for _, d := range ds {
		if d.State != Current && d.State != Recent && d.State != Collect {
			return false
		}
	}
	return len(ds) > 0
}

func resolve(r Requirement, in Input) Decision {
	d := Decision{Requirement: r, State: Missing}
	if r.Fact == Identity {
		if in.Username != "" {
			d.State, d.Reason = Current, "configured identity"
		} else {
			d.State, d.Reason = OperatorInput, "identity is required"
		}
		return d
	}
	if r.Fact == ClientIdentity {
		if in.ClientID != "" {
			d.State, d.Reason = Current, "imported existing SCCM client identity"
			if in.ClientIdentitySource != "" {
				d.Reason += " from " + in.ClientIdentitySource
			}
		} else {
			d.State, d.Reason = OperatorInput, "existing SCCM client GUID is required"
			if in.ClientIdentityReason != "" {
				d.Reason = in.ClientIdentityReason
			}
		}
		return d
	}
	if r.Fact == PolicyEndpoint {
		if in.ManagementPoint != "" {
			d.State, d.Reason = Current, "explicit management point"
			return d
		}
		match := evidenceFor(ManagementPt, in)
		if match.current != nil {
			return evidenceDecision(d, Current, "management point evidence collected in the current run", match.current, in.Now)
		}
		if match.fresh != nil {
			return evidenceDecision(d, Recent, "compatible management point evidence", match.fresh, in.Now)
		}
		if match.stale != nil {
			return evidenceDecision(d, Stale, "management point evidence exceeds configured age", match.stale, in.Now)
		}
		d.State, d.Reason = OperatorInput, "exact management point is required"
		return d
	}
	if r.Fact == SMBTarget || r.Fact == HTTPTarget {
		if in.Target != "" {
			d.State, d.Reason = Current, "explicit target"
		} else {
			d.State, d.Reason = OperatorInput, "exact target is required"
		}
		return d
	}
	if r.Fact == DomainContext && in.DomainController != "" {
		d.State, d.Reason = Current, "configured domain controller"
		return d
	}
	match := evidenceFor(r.Fact, in)
	if match.current != nil {
		return evidenceDecision(d, Current, "evidence collected in the current run", match.current, in.Now)
	}
	if match.fresh != nil {
		return evidenceDecision(d, Recent, "compatible retained evidence", match.fresh, in.Now)
	}
	if match.stale != nil {
		return evidenceDecision(d, Stale, "matching evidence exceeds configured age", match.stale, in.Now)
	}
	d.Reason = "no compatible evidence"
	if in.Provider == "live" && in.DomainController != "" && in.Username != "" && safeLDAPCollectionAllowed(in) {
		d.State, d.Module = Collect, "live.ldap.rootdse"
		if r.Fact == SiteCode || r.Fact == ManagementPt {
			d.Module = "live.ldap.sccm_directory"
		}
		d.Reason = "bounded LDAP collection is justified by this technique"
	} else if in.Provider != "live" {
		d.State, d.Reason = Blocked, "live connector is not selected"
	} else if !safeLDAPCollectionAllowed(in) {
		d.State, d.Reason = Blocked, "LDAP collection is explicitly disabled by configuration"
	} else {
		d.State, d.Reason = OperatorInput, "domain controller and authorized identity are required"
	}
	return d
}

func safeLDAPCollectionAllowed(in Input) bool {
	return in.AllowSafeLDAP == nil || *in.AllowSafeLDAP
}

type evidenceMatch struct{ current, fresh, stale *models.Evidence }

func evidenceFor(f Fact, in Input) evidenceMatch {
	var out evidenceMatch
	for _, e := range in.Evidence {
		if e.CollectedAt.IsZero() || !matches(f, e) {
			continue
		}
		if !evidenceMatchesScope(f, e, in) {
			continue
		}
		if in.CurrentRun != "" && e.RunID == in.CurrentRun {
			if out.current == nil || e.CollectedAt.After(out.current.CollectedAt) {
				copy := e
				out.current = &copy
			}
		} else if in.Now.Sub(e.CollectedAt) <= in.EvidenceMaxAge {
			if out.fresh == nil || e.CollectedAt.After(out.fresh.CollectedAt) {
				copy := e
				out.fresh = &copy
			}
		} else {
			if out.stale == nil || e.CollectedAt.After(out.stale.CollectedAt) {
				copy := e
				out.stale = &copy
			}
		}
	}
	return out
}

func evidenceMatchesScope(f Fact, evidence models.Evidence, in Input) bool {
	if in.DomainController == "" {
		return true
	}
	if f == RootDSE {
		server := strings.ToLower(strings.TrimSpace(stringValue(evidence.Data["server"])))
		return server == "" || server == strings.ToLower(in.DomainController)
	}
	if f != SiteCode && f != ManagementPt && f != PolicyEndpoint {
		return true
	}
	for _, candidate := range in.Evidence {
		if candidate.RunID != evidence.RunID || candidate.Type != "ldap_rootdse" {
			continue
		}
		server := strings.ToLower(strings.TrimSpace(stringValue(candidate.Data["server"])))
		if server != "" && server == strings.ToLower(in.DomainController) {
			return true
		}
	}
	return false
}

func evidenceDecision(d Decision, state State, reason string, evidence *models.Evidence, now time.Time) Decision {
	d.State, d.Reason, d.SourceRun = state, reason, evidence.RunID
	if !evidence.CollectedAt.IsZero() {
		d.Age = now.Sub(evidence.CollectedAt).Round(time.Minute).String()
	}
	return d
}
func matches(f Fact, e models.Evidence) bool {
	switch f {
	case RootDSE:
		return e.Type == "ldap_rootdse"
	case SiteCode, ManagementPt:
		return e.Type == "ldap_sccm_object" || e.Type == "sccm_directory"
	case DomainContext:
		return e.Type == "ldap_rootdse" || e.Type == "ldap_sccm_object"
	}
	return false
}
func stringValue(v any) string { s, _ := v.(string); return s }
func unique(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
