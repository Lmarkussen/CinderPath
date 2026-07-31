package version

import (
	"fmt"
	"runtime/debug"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

type Info struct{ Version, Commit, BuildDate, GoVersion string }

func Current() Info {
	i := Info{Version: Version, Commit: Commit, BuildDate: BuildDate}
	if bi, ok := debug.ReadBuildInfo(); ok {
		i.GoVersion = bi.GoVersion
		if Version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			i.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && Commit == "unknown" {
				i.Commit = s.Value
			}
		}
	}
	return i
}

func (i Info) String() string {
	return fmt.Sprintf("cinderpath %s (commit=%s build_date=%s go=%s)", i.Version, i.Commit, i.BuildDate, i.GoVersion)
}
