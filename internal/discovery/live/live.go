package live

import "github.com/Lmarkussen/CinderPath/internal/modules"

func All(opts Options) []modules.Module {
	return []modules.Module{&scopeModule{opts: opts}, &dnsModule{opts: opts}, &networkModule{opts: opts}, &httpModule{opts: opts}, &ldapRootDSEModule{opts: opts}, &ldapDirectoryModule{opts: opts}, &roleModule{opts: opts}}
}
