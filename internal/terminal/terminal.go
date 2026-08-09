// Package terminal centralizes presentation-only ANSI styling.
package terminal

import (
	"io"
	"os"
)

type Mode string

const (
	Auto   Mode = "auto"
	Always Mode = "always"
	Never  Mode = "never"
)

type Renderer struct{ enabled bool }

func New(mode Mode, w io.Writer) Renderer {
	f, ok := w.(*os.File)
	if !ok {
		return NewWithTTY(mode, false)
	}
	info, err := f.Stat()
	return NewWithTTY(mode, err == nil && info.Mode()&os.ModeCharDevice != 0)
}

// NewWithTTY makes terminal capability explicit for deterministic rendering tests.
func NewWithTTY(mode Mode, tty bool) Renderer {
	if mode == Never || os.Getenv("NO_COLOR") != "" {
		return Renderer{}
	}
	if mode == Always {
		return Renderer{true}
	}
	return Renderer{enabled: tty}
}
func (r Renderer) Enabled() bool { return r.enabled }
func (r Renderer) style(code, v string) string {
	if !r.enabled || v == "" {
		return v
	}
	return "\x1b[" + code + "m" + v + "\x1b[0m"
}
func (r Renderer) Success(v string) string { return r.style("32", v) }
func (r Renderer) Warning(v string) string { return r.style("33", v) }
func (r Renderer) Failure(v string) string { return r.style("31", v) }
func (r Renderer) Target(v string) string  { return r.style("36", v) }
func (r Renderer) Secret(v string) string  { return r.style("95", v) }
func (r Renderer) Dim(v string) string     { return r.style("2", v) }
func (r Renderer) Status(v string) string {
	switch v {
	case "completed", "completed_with_sccm_evidence":
		return r.Success("✓ " + v)
	case "not_run_no_connector", "completed_with_errors", "stale":
		return r.Warning("! " + v)
	default:
		return r.Failure("✗ " + v)
	}
}
