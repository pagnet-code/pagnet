package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func TestBridgeTaskSourceRequiresActualBoundTurnAndOriginalProducerPin(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	current := lease(t, j)
	dir := t.TempDir()
	network := uuid.NewString()
	task := uuid.NewString()
	ring := hostcrypto.NewKeyring(network)
	epoch, err := ring.Activate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(dir, ring); err != nil {
		t.Fatal(err)
	}
	owner := &SessionOwner{journal: j, manager: session.NewManager(), generation: "original-gen", spec: NativeSpec{NetworkID: network, NetworkTenantID: j.scope.TenantID, NetworkStateDir: dir}}
	sess := owner.manager.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	sess.NativeID = "actual-original-session"
	source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: owner.generation, NativeSessionID: sess.NativeID, SourceCommandID: "original-command", SourceAdmissionID: "original-admission", InputKind: "task", SourceTask: &transport.NativeTaskSource{TaskID: task, InputAAD: e2ee.AAD{TenantID: j.scope.TenantID, NetworkID: network, ObjectType: e2ee.ObjectTypeTask, ObjectID: task, KeyEpochID: epoch.ID}}}
	owner.candidateTurnSource = source
	owner.pinOriginalTaskContent(source)
	if got, err := owner.activeBridgeTurnSource(ctx, owner.generation); got != nil || err != nil {
		t.Fatal("unbound candidate granted task source")
	}
	if _, _, err = j.Admit(ctx, current, 1, "original-command", "prompt", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err = j.BindNativeTurn(ctx, source); err != nil {
		t.Fatal(err)
	}
	got, err := owner.activeBridgeTurnSource(ctx, owner.generation)
	if err != nil || got == nil || got.SourceCommandID != source.SourceCommandID || !bytes.Equal(got.SourceTask.InputAAD.CanonicalBytes(), source.SourceTask.InputAAD.CanonicalBytes()) {
		t.Fatal("actual original source not forwarded")
	}
	got.SourceTask.InputAAD.KeyEpochID = "mutated callback copy"
	if next, err := owner.activeBridgeTurnSource(ctx, owner.generation); err != nil || next == nil || next.SourceTask.InputAAD.KeyEpochID != epoch.ID {
		t.Fatal("call mutated original producer descriptor")
	}
	if got, err = owner.activeBridgeTurnSource(ctx, "replacement-generation"); got != nil || err == nil {
		t.Fatal("replacement native callback inherited original source")
	}
	owner.releaseNativeTaskTurnPin(&source)
	if got, err = owner.activeBridgeTurnSource(ctx, owner.generation); got != nil || err == nil {
		t.Fatal("settled native callback resurrected original task authority")
	}
}

func TestBridgeNonTaskSourceRetainsActualAcceptedAdmission(t *testing.T) {
	for _, kind := range []string{"ask", "notice", "status", "wake", "user_input"} {
		t.Run(kind, func(t *testing.T) {
			j, _ := testJournal(t)
			defer j.Close()
			current := lease(t, j)
			owner := &SessionOwner{journal: j, manager: session.NewManager(), generation: "original-generation"}
			sess := owner.manager.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
			sess.NativeID = "actual-original-session"
			source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: owner.generation, NativeSessionID: sess.NativeID, SourceCommandID: "original-command", SourceAdmissionID: "original-admission", InputKind: kind}
			owner.candidateTurnSource = source
			if got, err := owner.activeBridgeTurnSource(t.Context(), owner.generation); got != nil || err != nil {
				t.Fatal("unbound candidate granted source")
			}
			if _, _, err := j.Admit(t.Context(), current, 1, "original-command", "prompt", json.RawMessage(`{}`)); err != nil {
				t.Fatal(err)
			}
			if err := j.BindNativeTurn(t.Context(), source); err != nil {
				t.Fatal(err)
			}
			got, err := owner.activeBridgeTurnSource(t.Context(), owner.generation)
			if err != nil || got == nil || got.SourceCommandID != source.SourceCommandID || got.InputKind != kind || got.SourceTask != nil {
				t.Fatal("non-task admission lost its original source")
			}
			if got, err := owner.activeBridgeTurnSource(t.Context(), "replacement-generation"); got != nil || err == nil {
				t.Fatal("foreign native generation inherited source")
			}
			for _, state := range []string{"admitted", "uncertain", "completed"} {
				if _, err = j.db.Exec(`UPDATE worker_intent SET state=? WHERE sequence=1`, state); err != nil {
					t.Fatal(err)
				}
				if _, err = j.db.Exec(`UPDATE worker_turn_sources SET completed=1 WHERE sequence=1`); err != nil {
					t.Fatal(err)
				}
				idle, idleErr := owner.activeBridgeTurnSource(t.Context(), owner.generation)
				if idle != nil || (state == "uncertain" && idleErr == nil) || (state != "uncertain" && idleErr != nil) {
					t.Fatal("completed/uncertain source incorrectly selected endpoint authority", state, idle, idleErr)
				}
			}
			// Failed reads cannot silently authorize an endpoint call.
			if err = j.db.Close(); err != nil {
				t.Fatal(err)
			}
			if idle, idleErr := owner.activeBridgeTurnSource(t.Context(), owner.generation); idle != nil || idleErr == nil {
				t.Fatal("journal failure became endpoint fallback")
			}
		})
	}
}
