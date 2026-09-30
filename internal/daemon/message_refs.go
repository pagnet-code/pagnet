package daemon

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/pagnet-code/pagnet/transport"
)

// References are durable local presentation identifiers, never authorization
// tokens. Canonical IDs still reach the server and the encryption AAD.
func referenceOwner(row *InstanceRow) string {
	if row.AgentPrincipalID != "" {
		return row.AgentPrincipalID
	}
	return row.InstanceID
}

func (s *State) shortReference(owner, kind, canonical string) (string, error) {
	if canonical == "" {
		return "", nil
	}
	if _, err := s.db.Exec(`INSERT INTO message_references (owner, kind, canonical) VALUES (?,?,?) ON CONFLICT(owner,kind,canonical) DO NOTHING`, owner, kind, canonical); err != nil {
		return "", err
	}
	var index int64
	if err := s.db.QueryRow(`SELECT id FROM message_references WHERE owner=? AND kind=? AND canonical=?`, owner, kind, canonical).Scan(&index); err != nil {
		return "", err
	}
	return kind + "#" + strconv.FormatInt(index, 10), nil
}

func (s *State) resolveReference(owner, kind, reference string) (string, error) {
	if !strings.HasPrefix(reference, kind+"#") {
		return reference, nil
	} // existing UUID transcripts remain valid
	index, err := strconv.ParseInt(strings.TrimPrefix(reference, kind+"#"), 10, 64)
	if err != nil || index < 1 {
		return "", fmt.Errorf("invalid %s reference", kind)
	}
	var canonical string
	err = s.db.QueryRow(`SELECT canonical FROM message_references WHERE id=? AND owner=? AND kind=?`, index, owner, kind).Scan(&canonical)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("unknown %s reference; use the reference from this agent's message", kind)
	}
	return canonical, err
}

func (d *Daemon) compactDeliveryInput(row *InstanceRow, p transport.NetworkEventPayload) (string, error) {
	owner := referenceOwner(row)
	for _, f := range []struct {
		kind  string
		value *string
	}{{"thread", &p.ThreadID}, {"task", &p.TaskID}, {"conversation", &p.ConversationID}, {"peer", &p.FromPrincipalID}} {
		short, err := d.state.shortReference(owner, f.kind, *f.value)
		if err != nil {
			return "", fmt.Errorf("persist message reference: %w", err)
		}
		*f.value = short
	}
	// Message IDs are delivery/dedup metadata; the agent has no action requiring
	// them. They remain unchanged in the durable transport and server records.
	p.MessageID = ""
	return deliveryInput(row, p), nil
}

func (d *Daemon) resolveToolReferences(row *InstanceRow, tool string, raw json.RawMessage) (json.RawMessage, string) {
	if !strings.HasPrefix(tool, "network_") && !strings.HasPrefix(tool, "control_") {
		return raw, ""
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, "invalid tool arguments"
	}
	for field, kind := range map[string]string{"threadId": "thread", "taskId": "task", "conversationId": "conversation"} {
		value, ok := args[field]
		if !ok {
			continue
		}
		var ref string
		if json.Unmarshal(value, &ref) != nil {
			continue
		}
		canonical, err := d.state.resolveReference(referenceOwner(row), kind, ref)
		if err != nil {
			return nil, err.Error()
		}
		args[field], _ = json.Marshal(canonical)
	}
	out, err := json.Marshal(args)
	if err != nil {
		return nil, err.Error()
	}
	return out, ""
}
