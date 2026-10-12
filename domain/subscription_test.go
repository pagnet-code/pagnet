package domain

import (
	"strings"
	"testing"
)

func TestValidEventPattern(t *testing.T) {
	for _, p := range []string{"x", "task.created", "task.*", "a-b.c_d.E1.*", strings.Repeat("a", 128)} {
		if !ValidEventPattern(p) {
			t.Errorf("rejected valid pattern %q", p)
		}
	}
	for _, p := range []string{"", "*", ".*", "a.*.b", "task..created", "task. created", "task.*x", "ta*sk.created", "tásk.created", strings.Repeat("a", 129)} {
		if ValidEventPattern(p) {
			t.Errorf("accepted invalid pattern %q", p)
		}
	}
}
