package extension

import (
	"context"
	"slices"
)

// executingExtensionsKey is a private node-minted capability. Wire data,
// envelope assertions and serialized contexts cannot carry it: only trusted
// in-process node composition can install the value.
type executingExtensionsKey struct{}

// WithExecutingExtensions is trusted node composition only. It mints the
// node-verified list of extension IDs currently executing the invocation
// (the executing-extension stack as verified by the node, at most one entry
// per process boundary). The node mints it once per extension invocation in
// its forward-composition path from its own retained node-verified
// association; the caller's transport provenance ExtensionChain is signed
// lineage, not local execution authority, and is never a source for this
// value.
func WithExecutingExtensions(ctx context.Context, ids []string) context.Context {
	return context.WithValue(ctx, executingExtensionsKey{}, slices.Clone(ids))
}

// ExecutingExtensionsFrom returns the node-minted executing extension IDs, or
// nil when the node has no verified local execution chain for the invocation.
// The result is read-only: consumers must not mutate it.
func ExecutingExtensionsFrom(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}
	ids, _ := ctx.Value(executingExtensionsKey{}).([]string)
	return ids
}
