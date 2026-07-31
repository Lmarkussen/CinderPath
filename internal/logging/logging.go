package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

func New(out io.Writer, level string, noColor bool) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	h := slog.NewTextHandler(out, &slog.HandlerOptions{Level: l, ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}})
	_ = noColor // text output deliberately has no mandatory ANSI sequences
	return slog.New(h)
}

func MaskSecret(value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf("<redacted:%d>", len(value))
}
