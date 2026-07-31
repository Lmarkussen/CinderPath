package modules

import (
	"context"
	"errors"
	"log/slog"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/progress"
)

type Category string

const (
	CategoryDiscovery   Category = "discovery"
	CategoryProfiling   Category = "profiling"
	CategoryAssessment  Category = "assessment"
	CategoryCollection  Category = "collection"
	CategoryCorrelation Category = "correlation"
)

type SafetyLevel string

const (
	SafetySafe      SafetyLevel = "safe"
	SafetyActive    SafetyLevel = "active"
	SafetyIntrusive SafetyLevel = "intrusive"
)

type Requirement struct {
	Capability  string `json:"capability"`
	Description string `json:"description,omitempty"`
}
type Metadata struct {
	Name                string             `json:"name"`
	Description         string             `json:"description"`
	Category            Category           `json:"category"`
	Safety              SafetyLevel        `json:"safety"`
	Requirements        []Requirement      `json:"requirements,omitempty"`
	SupportedAssetTypes []models.AssetKind `json:"supported_asset_types,omitempty"`
}

type QueryStore interface {
	ListAssets(context.Context) ([]models.Asset, error)
	ListCapabilities(context.Context) ([]models.Capability, error)
	ListEvidence(context.Context) ([]models.Evidence, error)
	ListFindings(context.Context) ([]models.Finding, error)
	ListRelationships(context.Context) ([]models.Relationship, error)
	ListAttackPaths(context.Context) ([]models.AttackPath, error)
}

type RunContext struct {
	RunID    string
	Profile  string
	Mock     bool
	Store    QueryStore
	Logger   *slog.Logger
	Progress progress.Sink
}

func (r RunContext) Emit(e progress.Event) {
	if r.Progress != nil {
		e.RunID = r.RunID
		r.Progress.Publish(e)
	}
}

type ResultError struct {
	Message string `json:"message"`
	Fatal   bool   `json:"fatal"`
}

type FatalError struct{ Err error }

func (e FatalError) Error() string { return e.Err.Error() }
func (e FatalError) Unwrap() error { return e.Err }
func Fatal(err error) error {
	if err == nil {
		return nil
	}
	return FatalError{Err: err}
}
func IsFatal(err error) bool {
	var fatal FatalError
	return errors.As(err, &fatal)
}

type Result struct {
	Assets        []models.Asset        `json:"assets,omitempty"`
	Credentials   []models.Credential   `json:"credentials,omitempty"`
	Capabilities  []models.Capability   `json:"capabilities,omitempty"`
	Evidence      []models.Evidence     `json:"evidence,omitempty"`
	Findings      []models.Finding      `json:"findings,omitempty"`
	Relationships []models.Relationship `json:"relationships,omitempty"`
	AttackPaths   []models.AttackPath   `json:"attack_paths,omitempty"`
	Errors        []ResultError         `json:"errors,omitempty"`
	Warnings      []string              `json:"warnings,omitempty"`
}

type Module interface {
	Metadata() Metadata
	Applicable(context.Context, RunContext, *models.Asset) (bool, string)
	Run(context.Context, RunContext, *models.Asset) (*Result, error)
}

func Supports(m Metadata, kind models.AssetKind) bool {
	if len(m.SupportedAssetTypes) == 0 {
		return true
	}
	for _, k := range m.SupportedAssetTypes {
		if k == kind {
			return true
		}
	}
	return false
}
