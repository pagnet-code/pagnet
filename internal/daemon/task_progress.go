package daemon

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/session"
)

// sendTaskProgress never uploads a plaintext checklist or attributes an ASK
// or interactive native turn to a task. Failure only drops this observation.
func (d *Daemon) sendTaskProgress(conn *websocket.Conn, spec agentruntime.TurnSpec, nativeSession string, revision uint64, plan *session.PlanSnapshot) {
	task, _ := spec.Metadata["taskId"].(string)
	network, _ := spec.Metadata["taskNetworkId"].(string)
	command, _ := spec.Metadata["deliveryCommandId"].(string)
	if spec.InputKind != "task" || task == "" || network == "" || command == "" || nativeSession == "" || spec.TurnID == "" || revision == 0 || session.ValidatePlan(plan) != nil {
		return
	}
	st, err := d.contentCryptoReady(network)
	if err != nil {
		return
	}
	plain, err := json.Marshal(plan)
	if err != nil {
		return
	}
	id := domain.NewID().String()
	recipient := fmt.Sprintf("%s:%s:%d", task, spec.TurnID, revision)
	env, aad, err := d.encryptProtected(st, "runtime_task_progress", id, spec.InstanceID, recipient, string(plain))
	if err != nil {
		return
	}
	_ = d.send(conn, "host.runtime_task_progress", map[string]any{"id": id, "instanceId": spec.InstanceID, "taskId": task, "turnId": spec.TurnID, "commandId": command, "sessionId": nativeSession, "revision": revision, "envelope": env, "aad": aad})
}

// A turn owns one pending replacement, not a growing native-event queue.
// The final snapshot is flushed before the turn-ended frame.
type taskPlanCoalescer struct {
	pending *session.PlanSnapshot
	last    time.Time
}

func (p *taskPlanCoalescer) take(now time.Time, force bool) *session.PlanSnapshot {
	if p.pending == nil || (!force && !p.last.IsZero() && now.Sub(p.last) < 200*time.Millisecond) {
		return nil
	}
	plan := p.pending
	p.pending = nil
	p.last = now
	return plan
}
