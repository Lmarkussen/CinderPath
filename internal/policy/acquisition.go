package policy

import (
	"context"
	"errors"
	"strings"
)

// AcquisitionState distinguishes a blocked request from a completed response
// analysis. It does not authorize any network operation.
type AcquisitionState string

const (
	NotRun                     AcquisitionState = "not_run"
	BlockedMissingPrerequisite AcquisitionState = "blocked_missing_prerequisite"
	EndpointUnresolved         AcquisitionState = "endpoint_unresolved"
	ConnectionFailed           AcquisitionState = "connection_failed"
	AuthenticationFailed       AcquisitionState = "authentication_failed"
	RequestRejected            AcquisitionState = "request_rejected"
	NoPolicyReturned           AcquisitionState = "no_policy_returned"
	PolicyReturned             AcquisitionState = "policy_returned"
	NonCredentialPolicy        AcquisitionState = "non_credential_policy"
	CredentialPolicyDetected   AcquisitionState = "credential_policy_detected"
	ProtectedCredential        AcquisitionState = "protected_credential_material_detected"
	RecoveredCredential        AcquisitionState = "recovered_credential"
	ParserFailed               AcquisitionState = "parser_failed"
	UnsupportedProtection      AcquisitionState = "unsupported_protection_format"
)

// AcquisitionContract records only the exact fields observed in retained
// fixtures. The synthetic fixture does not evidence a usable client envelope,
// so LiveAllowed is deliberately absent.
type AcquisitionContract struct {
	TechniqueID, Method, Route, ContentType   string
	MaximumRequestBytes, MaximumResponseBytes int
	RequiredIdentity                          []string
	State                                     AcquisitionState
	Reason                                    string
}

func CRED2AcquisitionContract() AcquisitionContract {
	return AcquisitionContract{
		TechniqueID: "CRED-2", Method: "CCM_POST", Route: "/ccm_system/request",
		ContentType: "application/octet-stream", MaximumRequestBytes: MaxFixtureBytes,
		MaximumResponseBytes: MaxFixtureBytes,
		RequiredIdentity:     []string{"existing SCCM client GUID"},
		State:                BlockedMissingPrerequisite,
		Reason:               "retained fixtures prove only a synthetic request; request envelope, certificate use, and required headers are not structurally evidenced",
	}
}

func PlanCRED2Acquisition(managementPoint, siteCode string, client ClientIdentity) AcquisitionContract {
	p := CRED2AcquisitionContract()
	if strings.TrimSpace(managementPoint) == "" {
		p.Reason = "exact management point is required"
		return p
	}
	if strings.TrimSpace(siteCode) == "" {
		p.Reason = "site code is required"
		return p
	}
	if strings.TrimSpace(client.ClientID) == "" {
		p.Reason = "existing SCCM client GUID is required"
		return p
	}
	// Even complete operator references cannot fill in the unevidenced body.
	p.Reason = "policy request body and certificate authentication semantics remain unverified; no live request is authorized"
	return p
}

type ResponseResult struct {
	State      AcquisitionState `json:"state"`
	Reason     string           `json:"reason,omitempty"`
	Policy     ParsedPolicy     `json:"policy,omitempty"`
	Candidates []Candidate      `json:"candidates,omitempty"`
}

// AnalyzeCRED2Response is offline-only. It classifies an already obtained,
// bounded response and never constructs or sends an SCCM request.
func AnalyzeCRED2Response(ctx context.Context, status int, contentType string, body []byte) (ResponseResult, error) {
	if status == 401 || status == 403 {
		return ResponseResult{State: AuthenticationFailed, Reason: "response denied client authentication"}, nil
	}
	if status < 200 || status >= 300 {
		return ResponseResult{State: RequestRejected, Reason: "non-success policy response"}, nil
	}
	if len(body) == 0 || status == 204 {
		return ResponseResult{State: NoPolicyReturned, Reason: "empty policy response"}, nil
	}
	if len(body) > MaxFixtureBytes {
		return ResponseResult{State: ParserFailed, Reason: "response exceeds policy parser limit"}, errors.New("response exceeds policy parser limit")
	}
	if contentType != "" && !strings.Contains(strings.ToLower(contentType), "xml") {
		return ResponseResult{State: ParserFailed, Reason: "unsupported policy response content type"}, errors.New("unsupported policy response content type")
	}
	p, candidates, err := ParsePolicy(ctx, body)
	if err != nil {
		return ResponseResult{State: ParserFailed, Reason: err.Error()}, err
	}
	r := ResponseResult{State: PolicyReturned, Policy: p, Candidates: candidates}
	if len(candidates) == 0 {
		r.State, r.Reason = NonCredentialPolicy, "policy contains no credential-bearing indicators"
		return r, nil
	}
	for _, c := range candidates {
		if c.Protected || c.Encrypted {
			r.State, r.Reason = ProtectedCredential, "protected credential material identified; recovery is unsupported"
			return r, nil
		}
	}
	for _, c := range candidates {
		if c.State == "confirmed_plaintext" {
			r.State, r.Reason = RecoveredCredential, "concrete plaintext value was present in the supplied response"
			return r, nil
		}
	}
	r.State, r.Reason = CredentialPolicyDetected, "credential-bearing policy indicators identified"
	return r, nil
}
