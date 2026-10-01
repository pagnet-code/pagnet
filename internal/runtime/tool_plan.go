package runtime

import (
	"encoding/json"

	"github.com/pagnet-code/pagnet/internal/session"
)

// OpenCode's run JSON emits completed tool parts after the native list update.
// Only the structured result metadata is evidence; proposed input is ignored.
func opencodePlan(part opencodePart, ownedSession string) *session.PlanSnapshot {
	if part.Type != "tool" || part.Tool != "todowrite" || part.SessionID != ownedSession || len(part.State) > session.MaxPlanBytes {
		return nil
	}
	var state struct {
		Status   string `json:"status"`
		Metadata struct {
			Todos json.RawMessage `json:"todos"`
		} `json:"metadata"`
	}
	if json.Unmarshal(part.State, &state) != nil || state.Status != "completed" {
		return nil
	}
	return todoPlan("opencode", state.Metadata.Todos)
}

func todoPlan(source string, raw json.RawMessage) *session.PlanSnapshot {
	if len(raw) > session.MaxPlanBytes {
		return nil
	}
	var todos []struct {
		Content  string `json:"content"`
		Status   string `json:"status"`
		Priority string `json:"priority"`
	}
	if json.Unmarshal(raw, &todos) != nil || todos == nil || len(todos) > session.MaxPlanEntries {
		return nil
	}
	plan := &session.PlanSnapshot{Source: source, Entries: make([]session.PlanEntry, 0, len(todos))}
	for _, todo := range todos {
		plan.Entries = append(plan.Entries, session.PlanEntry{Text: todo.Content, Status: todo.Status, Priority: todo.Priority})
	}
	if session.ValidatePlan(plan) != nil {
		return nil
	}
	return plan
}

// Claude's TaskCreate/Update are partial deltas, potentially against a resumed
// list we have never observed. Only paired successful full-list outputs can
// establish a full snapshot; failed tools and assistant inputs cannot.
type claudePlanTracker struct{ pending map[string]string }

func (p *claudePlanTracker) consume(ev claudeEvent) *session.PlanSnapshot {
	if ev.Type == "assistant" {
		if p.pending == nil {
			p.pending = make(map[string]string)
		}
		for _, part := range ev.Message.Content {
			if part.Type == "tool_use" && part.ID != "" && len(part.ID) <= 256 && (part.Name == "TodoWrite" || part.Name == "TaskList") && len(p.pending) < session.MaxPlanEntries {
				p.pending[part.ID] = part.Name
			}
		}
		return nil
	}
	if ev.Type != "user" || len(ev.Message.Content) != 1 || len(ev.ToolUseResult) > session.MaxPlanBytes {
		return nil
	}
	result := ev.Message.Content[0]
	if result.Type != "tool_result" {
		return nil
	}
	tool := p.pending[result.ToolUseID]
	delete(p.pending, result.ToolUseID)
	if result.IsError || tool == "" {
		return nil
	}
	if tool == "TodoWrite" {
		var out struct {
			NewTodos json.RawMessage `json:"newTodos"`
		}
		if json.Unmarshal(ev.ToolUseResult, &out) != nil {
			return nil
		}
		return todoPlan("claude", out.NewTodos)
	}
	var out struct {
		Tasks []struct {
			ID      string `json:"id"`
			Subject string `json:"subject"`
			Status  string `json:"status"`
		} `json:"tasks"`
	}
	if json.Unmarshal(ev.ToolUseResult, &out) != nil || out.Tasks == nil || len(out.Tasks) > session.MaxPlanEntries {
		return nil
	}
	plan := &session.PlanSnapshot{Source: "claude", Entries: make([]session.PlanEntry, 0, len(out.Tasks))}
	ids := make(map[string]bool)
	for _, task := range out.Tasks {
		if task.ID == "" || len(task.ID) > 500 || ids[task.ID] {
			return nil
		}
		ids[task.ID] = true
		plan.Entries = append(plan.Entries, session.PlanEntry{Text: task.Subject, Status: task.Status})
	}
	if session.ValidatePlan(plan) != nil {
		return nil
	}
	return plan
}
