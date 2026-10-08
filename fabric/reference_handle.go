package fabric

import (
	"context"
	"fmt"
)

const (
	// ReferenceHandleSlotMax is the finite hard bound on a friendly handle slot.
	// Per-scope admission quotas (registry storage limits) stay far below it;
	// the bound only keeps the compact text form parseable and finite.
	ReferenceHandleSlotMax = 1_000_000_000
	// ReferenceHandleRevisionMax is the finite hard bound on a handle revision.
	ReferenceHandleRevisionMax = 1_000_000_000
)

// ReferenceHandleView is the bounded public view of a friendly persistent
// reference: the compact handle, the truthful persisted participant label, and
// the exact canonical reference plus bound revision. It grants no authority,
// carries no private root material, and is disclosed only on explicit request.
// The handle stays exactly routable: it resolves to this one canonical
// reference, never a different target.
type ReferenceHandleView struct {
	Handle   string      `json:"handle"`
	Label    string      `json:"label"`
	Ref      EndpointRef `json:"ref"`
	Revision Revision    `json:"revision"`
}

// ReferenceHandleResolver resolves compact friendly handles to exactly one
// canonical reference plus bound revision inside a single private root. It is
// an optional capability a descriptor store may implement: a store without it,
// or without an allocated handle, discloses nothing rather than failing or
// fabricating a reference.
type ReferenceHandleResolver interface {
	// ResolveReferenceHandle maps a compact handle to its canonical target.
	// A live slot whose requested handle revision is not current fails with
	// CodeStaleReference while returning the CURRENT handle alongside the
	// error, so the caller recovers the friendly reference it needs.
	ResolveReferenceHandle(context.Context, string) (ReferenceHandleView, error)
	// ReferenceHandleForRef returns the allocated handle for an exact canonical
	// endpoint reference, or CodeNotFound when none was allocated.
	ReferenceHandleForRef(context.Context, EndpointRef) (ReferenceHandleView, error)
}

// FormatReferenceHandle renders the compact friendly handle form:
// "#<slot>.r<revision>", for example "#7.r3".
func FormatReferenceHandle(slot, revision uint64) string {
	return fmt.Sprintf("#%d.r%d", slot, revision)
}

func handleNumber(text string, start int) (uint64, int, bool) {
	if start >= len(text) || text[start] < '1' || text[start] > '9' {
		return 0, 0, false
	}
	i := start
	var value uint64
	for i < len(text) && text[i] >= '0' && text[i] <= '9' {
		if i-start >= 10 {
			return 0, 0, false
		}
		value = value*10 + uint64(text[i]-'0')
		i++
	}
	return value, i, true
}

// ParseReferenceHandle accepts only the exact compact form
// "#<slot>.r<revision>". It performs no normalization, case folding or alias
// resolution, and rejects leading zeros, zero values and values above the
// finite handle bounds.
func ParseReferenceHandle(text string) (slot, revision uint64, err error) {
	if len(text) < 4 || text[0] != '#' {
		return 0, 0, referenceInputError("invalid reference handle")
	}
	slot, i, ok := handleNumber(text, 1)
	if !ok || slot > ReferenceHandleSlotMax || i+2 > len(text) || text[i] != '.' || text[i+1] != 'r' {
		return 0, 0, referenceInputError("invalid reference handle")
	}
	revision, j, ok := handleNumber(text, i+2)
	if !ok || revision > ReferenceHandleRevisionMax || j != len(text) {
		return 0, 0, referenceInputError("invalid reference handle")
	}
	return slot, revision, nil
}
