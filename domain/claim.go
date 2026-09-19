package domain

import (
	"strings"
	"time"
)

// Claim is a temporary coordination lease. Claims prevent two agents from
// accidentally taking ownership of the same work. They are NOT security
// permissions.
type Claim struct {
	ID         ID
	NetworkID  ID
	ScopeType  ClaimScopeType
	Scope      string // e.g. "src/compiler/**", task id, "github.com/xemahq/dsl"
	ResourceID *ID
	// OwnerPrincipalID is the principal holding the claim (canonical).
	OwnerPrincipalID *ID
	// OwnerInstanceID is the instance that took the claim (execution
	// provenance; nil when the owner is not a managed instance).
	OwnerInstanceID *ID
	TaskID          *ID
	TTLSeconds      int
	ExpiresAt       time.Time
	CreatedAt       time.Time
	ReleasedAt      *time.Time
}

// Active reports whether the claim currently holds.
func (c Claim) Active() bool {
	return c.ReleasedAt == nil && time.Now().Before(c.ExpiresAt)
}

// ClaimsOverlap reports whether two path-scope patterns could match the same
// file. This is v1 "simple prefix/glob overlap" logic, not a complete glob
// intersection engine. When the patterns cannot be proven disjoint, it
// conservatively returns true: a rejected claim is far cheaper than two
// agents editing the same code.
//
// Rules:
//   - patterns are compared segment by segment (split on "/")
//   - "**" matches any remaining depth
//   - a pattern that is a directory prefix of the other overlaps
//   - a segment containing wildcard chars (*) is assumed to possibly match
func ClaimsOverlap(a, b string) bool {
	as := pathSegments(a)
	bs := pathSegments(b)

	for i := 0; i < len(as) || i < len(bs); i++ {
		if i >= len(as) || i >= len(bs) {
			return true // one is a prefix of the other
		}
		ai, bi := as[i], bs[i]
		if ai == bi {
			continue
		}
		if ai == "**" || bi == "**" {
			return true
		}
		if !hasGlobChars(ai) && !hasGlobChars(bi) {
			return false
		}
		// At least one side is a wildcard: it may match the other side's
		// segment, so keep walking.
	}
	return true
}

func pathSegments(scope string) []string {
	s := strings.TrimSpace(scope)
	s = strings.TrimPrefix(s, "./")
	s = strings.Trim(s, "/")
	if s == "" || s == "." {
		return nil // repo root: matches everything
	}
	// Collapse duplicate slashes; keep "**" segments intact.
	var out []string
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || seg == "." {
			continue
		}
		out = append(out, seg)
	}
	return out
}

func hasGlobChars(s string) bool {
	return strings.ContainsAny(s, "*?")
}
