package sdk

import "testing"

func TestMatchEventPattern(t *testing.T) {
	cases := []struct {
		pattern string
		event   string
		want    bool
	}{
		{"task.created", "task.created", true},  // exact
		{"task.created", "task.updated", false}, // different exact
		{"task.*", "task.created", true},        // single-level wildcard
		{"task.*", "task.updated", true},        // single-level wildcard
		{"task.*", "task.sub.created", false},   // wildcard is single-level only
		{"task.*", "task", false},               // wildcard needs a segment
		{"documents.*", "task.created", false},  // different prefix
		{"a.b.c", "a.b.c", true},                // deep exact
		{"a.b.*", "a.b.c", true},                // deep wildcard
		{"a.b.*", "a.b.c.d", false},             // deep wildcard single-level
	}
	for _, tc := range cases {
		if got := matchEventPattern(tc.pattern, tc.event); got != tc.want {
			t.Fatalf("matchEventPattern(%q, %q) = %v, want %v", tc.pattern, tc.event, got, tc.want)
		}
	}
}
