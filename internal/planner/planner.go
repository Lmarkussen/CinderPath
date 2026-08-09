// Package planner resolves declared technique facts into bounded module plans.
package planner

import (
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
)

type Fact string

const (
	DomainContext  Fact = "domain_context"
	RootDSE        Fact = "rootdse"
	SiteCode       Fact = "site_code"
	ManagementPt   Fact = "management_point"
	SMBTarget      Fact = "smb_target"
	HTTPTarget     Fact = "http_target"
	Identity       Fact = "authenticated_identity"
	ClientIdentity Fact = "client_identity"
	PolicyEndpoint Fact = "policy_endpoint"
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
	State  State  `json:"state"`
	Reason string `json:"reason"`
	Module string `json:"module,omitempty"`
}
type Input struct {
	Technique, Provider, Target, DomainController, Username, CurrentRun string
	ClientID, ManagementPoint                                           string
	Evidence                                                            []models.Evidence
	Now                                                                 time.Time
	EvidenceMaxAge                                                      time.Duration
}
type Plan struct {
	Technique     string     `json:"technique"`
	Prerequisites []Decision `json:"prerequisites"`
	Modules       []string   `json:"modules"`
}

func RequirementsFor(technique string) []Requirement {
	switch strings.ToUpper(technique) {
	case "RECON-1":
		return []Requirement{{RootDSE, "RootDSE"}, {SiteCode, "SCCM site"}, {ManagementPt, "Management point"}, {Identity, "Authorized identity"}}
	case "RECON-2":
		return []Requirement{{SMBTarget, "SMB target"}, {Identity, "Authorized identity"}}
	case "RECON-3":
		return []Requirement{{HTTPTarget, "HTTP target"}}
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
			d.State, d.Reason = Current, "existing client identity reference"
		} else {
			d.State, d.Reason = OperatorInput, "existing SCCM client GUID is required"
		}
		return d
	}
	if r.Fact == PolicyEndpoint {
		if in.ManagementPoint != "" {
			d.State, d.Reason = Current, "explicit management point"
		} else {
			d.State, d.Reason = OperatorInput, "exact management point is required"
		}
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
	current, matched, stale := evidenceFor(r.Fact, in)
	if current {
		d.State, d.Reason = Current, "evidence from the selected run"
		return d
	}
	if matched {
		d.State, d.Reason = Recent, "compatible retained evidence"
		return d
	}
	if stale {
		d.State, d.Reason = Stale, "matching evidence exceeds configured age"
		return d
	}
	d.Reason = "no compatible evidence"
	if in.Provider == "live" && in.DomainController != "" && in.Username != "" {
		d.State, d.Module = Collect, "live.ldap.rootdse"
		if r.Fact == SiteCode || r.Fact == ManagementPt {
			d.Module = "live.ldap.sccm_directory"
		}
		d.Reason = "bounded LDAP collection is justified by this technique"
	} else if in.Provider != "live" {
		d.State, d.Reason = Blocked, "live connector is not selected"
	} else {
		d.State, d.Reason = OperatorInput, "domain controller and authorized identity are required"
	}
	return d
}

func evidenceFor(f Fact, in Input) (bool, bool, bool) {
	var current, fresh, stale bool
	for _, e := range in.Evidence {
		if e.CollectedAt.IsZero() || !matches(f, e) {
			continue
		}
		if in.Target != "" {
			value := strings.ToLower(strings.TrimSpace(stringValue(e.Data["server"])))
			if value != "" && value != strings.ToLower(in.Target) {
				continue
			}
		}
		if in.CurrentRun != "" && e.RunID == in.CurrentRun {
			current = true
		} else if in.Now.Sub(e.CollectedAt) <= in.EvidenceMaxAge {
			fresh = true
		} else {
			stale = true
		}
	}
	return current, fresh, stale
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
