package fabricagent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/runtimeprofile"
)

func TestExplicitRuntimeSelectionAndAmbiguity(t *testing.T) {
	a := RuntimeChoice{Runtime: domain.RuntimeClaudeCode, Available: true, Executable: "/secret/claude"}
	b := RuntimeChoice{Name: "private", Runtime: domain.RuntimeClaudeCode, Available: true, Executable: "/secret/wrapper", Profile: runtimeprofile.Profile{Args: []string{"private-arg"}, Env: map[string]string{"PRIVATE": "private-value"}}}
	if chosen, e := SelectRuntime([]RuntimeChoice{a, b}, "", ""); e != nil || chosen != nil {
		t.Fatal("ambiguous choices must remain unbound", e)
	}
	if chosen, e := SelectRuntime([]RuntimeChoice{a, b}, domain.RuntimeClaudeCode, ""); e != nil || chosen.Executable != a.Executable {
		t.Fatal("explicit canonical runtime failed", e)
	}
	if chosen, e := SelectRuntime([]RuntimeChoice{a, b}, "", "private"); e != nil || chosen.Executable != b.Executable {
		t.Fatal("explicit wrapper failed", e)
	}
	if _, e := SelectRuntime([]RuntimeChoice{a, b}, domain.RuntimeCodex, "private"); e == nil {
		t.Fatal("mismatched profile allowed")
	}
	if chosen, e := SelectRuntime([]RuntimeChoice{a}, "", ""); e != nil || chosen == nil {
		t.Fatal("sole installed choice not selected", e)
	}
	a.Available = false
	if _, e := SelectRuntime([]RuntimeChoice{a}, domain.RuntimeClaudeCode, ""); e == nil {
		t.Fatal("missing executable allowed")
	}
	raw, _ := json.Marshal(b)
	for _, secret := range []string{"/secret", "private-arg", "private-value"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private selection published")
		}
	}
}
