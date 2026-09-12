package domain

import "testing"

func TestClaimsOverlap(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"src/compiler/**", "src/compiler/parser/**", true}, // nested conflict (spec test 6)
		{"src/compiler/parser/**", "src/compiler/**", true},
		{"src/compiler/**", "src/api/**", false},
		{"src/compiler", "src/compiler/parser.ts", true},
		{"src/compiler/**", "src/compiler", true},
		{"a/**", "b/**", false},
		{"src/*", "src/x", true},
		{"", "anything", true}, // repo root overlaps everything
		{".", "src/x", true},
		{"src/compiler/x.go", "src/compiler/y.go", false},
		{"src/compiler/x.go", "src/compiler/x.go", true},
		{"src/compiler", "srcx/compiler", false},
	}
	for _, tt := range tests {
		if got := ClaimsOverlap(tt.a, tt.b); got != tt.want {
			t.Errorf("ClaimsOverlap(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
