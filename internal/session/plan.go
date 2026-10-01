package session

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

const MaxPlanEntries = 100
const MaxPlanBytes = 32 * 1024

// PlanSnapshot replaces the previous snapshot of this exact logical turn.
// Entry indexes are snapshot-local; runtimes do not universally supply IDs.
type PlanSnapshot struct {
	Source       string      `json:"source"`
	NativeTurnID string      `json:"nativeTurnId,omitempty"`
	Entries      []PlanEntry `json:"entries"`
}
type PlanEntry struct {
	Text     string `json:"text"`
	Status   string `json:"status"`
	Priority string `json:"priority,omitempty"`
}

func ValidatePlan(p *PlanSnapshot) error {
	if p == nil || (p.Source != "codex" && p.Source != "acp") || p.Entries == nil || len(p.Entries) > MaxPlanEntries || len(p.NativeTurnID) > 256 {
		return errors.New("invalid runtime plan")
	}
	for _, e := range p.Entries {
		if !utf8.ValidString(e.Text) || strings.TrimSpace(e.Text) == "" || len(e.Text) > 4096 {
			return errors.New("invalid runtime plan entry")
		}
		if e.Status != "pending" && e.Status != "in_progress" && e.Status != "completed" {
			return errors.New("invalid runtime plan status")
		}
		if e.Priority != "" && e.Priority != "high" && e.Priority != "medium" && e.Priority != "low" {
			return errors.New("invalid runtime plan priority")
		}
	}
	b, err := json.Marshal(p)
	if err != nil || len(b) > MaxPlanBytes {
		return errors.New("runtime plan too large")
	}
	return nil
}
