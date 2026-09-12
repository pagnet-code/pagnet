package domain

import "context"

// Correlation and causation are first-class: every operation that results
// from another operation propagates correlation_id / causation_id so the UI
// can display one activity chain (A delegates to B, B asks C, ...).
//
// Convention: when work is delegated, the Task ID becomes the correlation
// root. If a participant asks a third party while executing that task, the
// same correlation ID is propagated; causation points at the direct cause.

type ctxKey int

const (
	correlationCtxKey ctxKey = iota
	causationCtxKey
)

// WithCorrelationID attaches the correlation root to ctx.
func WithCorrelationID(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, correlationCtxKey, id)
}

// CorrelationID returns the correlation root carried by ctx, if any.
func CorrelationID(ctx context.Context) (ID, bool) {
	id, ok := ctx.Value(correlationCtxKey).(ID)
	return id, ok
}

// WithCausationID attaches the direct-cause ID to ctx.
func WithCausationID(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, causationCtxKey, id)
}

// CausationID returns the direct cause carried by ctx, if any.
func CausationID(ctx context.Context) (ID, bool) {
	id, ok := ctx.Value(causationCtxKey).(ID)
	return id, ok
}

// ForTask returns a context rooted at taskID: correlation becomes taskID when
// unset, and causation is set to taskID so that any event emitted from this
// context links back to the task that caused it.
func ForTask(ctx context.Context, taskID ID) context.Context {
	if _, ok := CorrelationID(ctx); !ok {
		ctx = WithCorrelationID(ctx, taskID)
	}
	ctx = WithCausationID(ctx, taskID)
	return ctx
}
