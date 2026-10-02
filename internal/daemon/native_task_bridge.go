package daemon

import (
	"context"
	"encoding/json"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func (d *Daemon) nativeTaskReadForBridge(ctx context.Context, p *NativeWorkerProxy, row *InstanceRow, call *sessionworker.BridgeCall, args, raw json.RawMessage) (json.RawMessage, string) {
	if call.Tool != "network_task_get" {
		return raw, ""
	}
	var source *transport.NativeTaskSource
	if turn := call.TurnSource; turn != nil {
		source = turn.SourceTask
		if source != nil && (turn.InputKind != "task" || turn.Sequence <= 0 || turn.NativeGeneration != call.NativeGeneration || turn.NativeSessionID == "" || turn.SourceCommandID == "" || turn.SourceAdmissionID == "") {
			return nil, "original task turn binding unavailable"
		}
	}
	var request struct {
		TaskID string `json:"taskId"`
	}
	if json.Unmarshal(args, &request) != nil {
		return nil, "invalid task request"
	}
	if source != nil && source.TaskID == request.TaskID {
		// First the ordinary read establishes current task authority/status. Its
		// mutable encrypted body is then replaced only with the original snapshot.
		var result map[string]json.RawMessage
		var task domain.Task
		if json.Unmarshal(raw, &result) != nil || json.Unmarshal(result["task"], &task) != nil || task.ID.String() != source.TaskID || task.NetworkID.String() != row.NetworkID {
			return nil, "original task read identity unavailable"
		}
		turn := call.TurnSource
		snapshot, err := p.connection.ReadOriginalTaskInput(ctx, row.InstanceID, turn.SourceCommandID, turn.SourceAdmissionID, source)
		if err != nil {
			return nil, "original encrypted task input unavailable; retry after reconnecting its host"
		}
		if task.Metadata == nil {
			task.Metadata = map[string]any{}
		}
		task.Metadata["e2ee_envelope"] = snapshot.Envelope
		task.Metadata["e2ee_aad"] = snapshot.TaskSource.InputAAD
		result["task"], err = json.Marshal(task)
		if err != nil {
			return nil, "invalid original task metadata"
		}
		raw, err = json.Marshal(result)
		if err != nil {
			return nil, "invalid original task response"
		}
	}
	return d.NativeTaskReadResult(ctx, row, call.Tool, args, raw, source)
}
