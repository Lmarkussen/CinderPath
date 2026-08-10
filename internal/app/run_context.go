package app

import "context"

type parentRunContextKey struct{}

// WithParentRun preserves the operator-facing family command while allowing
// child adapters to retain their technique-specific evidence attribution.
func WithParentRun(ctx context.Context, command string) context.Context {
	return context.WithValue(ctx, parentRunContextKey{}, command)
}

func runCommand(ctx context.Context, fallback string) string {
	if value, ok := ctx.Value(parentRunContextKey{}).(string); ok && value != "" {
		return value
	}
	return fallback
}
