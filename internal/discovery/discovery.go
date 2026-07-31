package discovery

import "github.com/Lmarkussen/CinderPath/internal/modules"

func Select(all []modules.Module) []modules.Module {
	var out []modules.Module
	for _, m := range all {
		if m.Metadata().Category == modules.CategoryDiscovery {
			out = append(out, m)
		}
	}
	return out
}
