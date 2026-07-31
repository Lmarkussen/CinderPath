package live

import (
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/progress"
	"io"
	"log/slog"
)

func modulesRun() modules.RunContext {
	return modules.RunContext{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Progress: progress.Nop{}}
}
