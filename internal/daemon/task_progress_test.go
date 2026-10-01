package daemon

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func TestTaskProgressOnlyEncryptsBoundTaskSnapshot(t *testing.T) {
	d := newCryptoDaemon(t)
	network := domain.NewID().String()
	setupActiveNetCrypto(t, d, domain.NewID().String(), network)
	client, peer := newMemWS(t)
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	spec := agentruntime.TurnSpec{InstanceID: domain.NewID().String(), TurnID: domain.NewID().String(), InputKind: "task", Metadata: map[string]any{"taskId": domain.NewID().String(), "taskNetworkId": network, "deliveryCommandId": domain.NewID().String()}}
	plan := &session.PlanSnapshot{Source: "codex", NativeTurnID: "native-turn", Entries: []session.PlanEntry{{Text: "private-checklist-marker", Status: "pending"}}}
	d.sendTaskProgress(client, spec, "native-session", 1, plan)
	var frame transport.Envelope
	if err := peer.ReadJSON(&frame); err != nil {
		t.Fatal(err)
	}
	if frame.Type != "host.runtime_task_progress" || strings.Contains(string(frame.Payload), "private-checklist-marker") {
		t.Fatal("missing encrypted projection or plaintext leaked")
	}
	var p struct {
		TaskID, TurnID, SessionID string
		Revision                  int
		Envelope                  e2ee.EncryptedPayloadV1
		AAD                       e2ee.AAD
	}
	if err := frame.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	plain, err := d.decryptProtected(network, p.Envelope, p.AAD)
	if err != nil || !strings.Contains(plain, "private-checklist-marker") {
		t.Fatalf("snapshot not decryptable: %v", err)
	}
	if p.AAD.ObjectType != "runtime_task_progress" || p.TurnID != spec.TurnID || p.SessionID != "native-session" || p.Revision != 1 {
		t.Fatal("wrong native/task binding")
	}
	var decoded session.PlanSnapshot
	if json.Unmarshal([]byte(plain), &decoded) != nil || session.ValidatePlan(&decoded) != nil {
		t.Fatal("invalid cleartext schema")
	}
	spec.InputKind = "ask"
	d.sendTaskProgress(client, spec, "native-session", 2, plan)
	if err = d.send(client, transport.MsgHeartbeat, map[string]any{"after": "ask"}); err != nil {
		t.Fatal(err)
	}
	if err = peer.ReadJSON(&frame); err != nil || frame.Type != transport.MsgHeartbeat {
		t.Fatal("ASK snapshot attributed to a task")
	}
	spec.InputKind = "task"
	spec.Metadata["taskNetworkId"] = domain.NewID().String()
	d.sendTaskProgress(client, spec, "native-session", 3, plan)
	_ = d.send(client, transport.MsgHeartbeat, map[string]any{"after": "no-key"})
	if err = peer.ReadJSON(&frame); err != nil || frame.Type != transport.MsgHeartbeat {
		t.Fatal("unknown crypto had a plaintext fallback")
	}
}

func TestTaskPlanCoalescerBoundedLatestAndFinal(t *testing.T) {
	now := time.Now()
	first := &session.PlanSnapshot{Source: "codex", Entries: []session.PlanEntry{}}
	latest := &session.PlanSnapshot{Source: "codex", Entries: []session.PlanEntry{{Text: "latest", Status: "pending"}}}
	p := taskPlanCoalescer{pending: first}
	if p.take(now, false) != first {
		t.Fatal("first snapshot delayed")
	}
	for i := 0; i < 1000; i++ {
		p.pending = latest
		if p.take(now.Add(time.Millisecond), false) != nil {
			t.Fatal("unbounded native upload")
		}
	}
	if p.take(now.Add(200*time.Millisecond), false) != latest {
		t.Fatal("latest replacement lost")
	}
	p.pending = first
	if p.take(now.Add(201*time.Millisecond), true) != first || p.take(now, true) != nil {
		t.Fatal("final snapshot lost or duplicated")
	}
}
