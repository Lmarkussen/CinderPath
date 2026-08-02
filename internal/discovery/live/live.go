package live

import "github.com/Lmarkussen/CinderPath/internal/modules"

func All(opts Options) []modules.Module {
	return []modules.Module{
		&scopeModule{opts: opts},
		&dnsModule{opts: opts},
		&networkModule{opts: opts},
		&httpModule{opts: opts},
		&ldapRootDSEModule{opts: opts},
		&ldapDirectoryModule{opts: opts},
		&sccmHTTPRoutesModule{opts: opts},
		&sccmManagementPointModule{opts: opts},
		&sccmDistributionPointModule{opts: opts},
		&roleModule{opts: opts},
		&correlationModule{opts: opts},
	}
}

// LDAPOnly returns the existing bounded LDAP modules for technique-specific
// reconnaissance. It deliberately excludes DNS, TCP, HTTP, PXE, and SCCM
// protocol modules.
func LDAPOnly(opts Options) []modules.Module {
	return []modules.Module{&ldapRootDSEModule{opts: opts}, &ldapDirectoryModule{opts: opts}}
}

func SMBOnly(opts Options) []modules.Module {
	return []modules.Module{&smbShareMetadataModule{opts: opts}}
}
