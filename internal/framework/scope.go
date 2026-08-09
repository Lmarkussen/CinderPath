package framework

import (
	"sort"
	"strings"
)

// ProductAttackFamilies is the complete set of Misconfiguration Manager
// technique families that CinderPath exposes as product capabilities. The
// embedded snapshot intentionally retains upstream defensive provenance, but
// those records are not runnable or supported by CinderPath.
var ProductAttackFamilies = map[string]struct{}{
	"CRED":     {},
	"ELEVATE":  {},
	"EXEC":     {},
	"RECON":    {},
	"TAKEOVER": {},
	"COERCE":   {},
}

func IsProductAttackFamily(family string) bool {
	_, ok := ProductAttackFamilies[strings.ToUpper(strings.TrimSpace(family))]
	return ok
}

func IsProductTechnique(id string) bool {
	family, _, ok := strings.Cut(strings.ToUpper(strings.TrimSpace(id)), "-")
	return ok && IsProductAttackFamily(family)
}

func ProductFamilyNames() []string {
	names := make([]string, 0, len(ProductAttackFamilies))
	for family := range ProductAttackFamilies {
		names = append(names, family)
	}
	sort.Strings(names)
	return names
}

// ProductSnapshot returns the product-visible portion of an upstream
// snapshot. It deliberately removes defensive technique and matrix records
// while retaining the source snapshot's provenance fields.
func ProductSnapshot(s FrameworkSnapshot) FrameworkSnapshot {
	visible := s
	visible.Techniques = nil
	visible.Coverage = nil
	visible.MatrixMappings = nil
	for _, technique := range s.Techniques {
		if IsProductAttackFamily(technique.Family) && technique.Kind == "attack" {
			visible.Techniques = append(visible.Techniques, technique)
		}
	}
	for _, coverage := range s.Coverage {
		if IsProductTechnique(coverage.TechniqueID) {
			coverage.DefenseAssessment = ""
			visible.Coverage = append(visible.Coverage, coverage)
		}
	}
	visible.Warnings = nil
	for _, warning := range s.Warnings {
		if !strings.Contains(strings.ToLower(warning), "defense-techniques/") {
			visible.Warnings = append(visible.Warnings, warning)
		}
	}
	return visible
}
