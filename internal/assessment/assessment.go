package assessment

import "github.com/Lmarkussen/CinderPath/internal/modules"

func Select(all []modules.Module) []modules.Module {
	var out []modules.Module
	for _, m := range all {
		c := m.Metadata().Category
		if c == modules.CategoryAssessment || c == modules.CategoryCorrelation {
			out = append(out, m)
		}
	}
	return out
}
