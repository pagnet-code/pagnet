package domain

import "strings"

// RuntimeInteractionOption contains only a native identifier and a known
// presentation kind. Native tool details and arbitrary vendor labels stay private.
type RuntimeInteractionOption struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

func ValidRuntimeInteractionOptions(options []RuntimeInteractionOption) bool {
	if len(options) == 0 || len(options) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, option := range options {
		if option.ID == "" || len(option.ID) > 1024 || strings.ContainsAny(option.ID, "\x00\r\n") || seen[option.ID] {
			return false
		}
		seen[option.ID] = true
		switch option.Kind {
		case "allow_once", "allow_always", "reject_once", "reject_always":
		default:
			return false
		}
	}
	return true
}
