package session

import (
	"github.com/pagnet-code/pagnet/domain"
	"testing"
)

func TestSettledMachineTurnDoesNotEraseObservedHumanWork(t *testing.T) {
	manager := NewManager()
	sess := manager.Session("native-owner", domain.RuntimeFakePersistent, "workspace")
	manager.ObserveNativeActivity(sess.InstanceID, SessionEvent{Type: EventTurnStarted, TurnID: "human-turn"})
	manager.settlePrompt(sess, &TurnResult{Completed: true})
	state, _ := manager.State(sess.InstanceID)
	if state != StateBusy || !manager.ActiveWork(sess.InstanceID) {
		t.Fatal("logical completion hid actual native work")
	}
	manager.ObserveNativeActivity(sess.InstanceID, SessionEvent{Type: EventTurnCompleted, TurnID: "human-turn"})
	state, _ = manager.State(sess.InstanceID)
	if state != StateIdle || manager.ActiveWork(sess.InstanceID) {
		t.Fatal("completed native work stayed busy")
	}
}

func TestNewNativeGenerationClearsFormerWorkAndPermissions(t *testing.T) {
	manager := NewManager()
	sess := manager.Session("native-owner", domain.RuntimeFakePersistent, "workspace")
	manager.ObserveNativeActivity(sess.InstanceID, SessionEvent{Type: EventInteractionStarted, Interaction: &InteractionEvent{NativeInteractionID: "old-native-question"}})
	if !manager.HasPendingInteraction(sess.InstanceID) || !sess.NativeBusy {
		t.Fatal("fixture native work not recorded")
	}
	manager.ResetNativeActivity(sess.InstanceID)
	manager.settlePrompt(sess, &TurnResult{Completed: true})
	state, _ := manager.State(sess.InstanceID)
	if state != StateIdle || manager.HasPendingInteraction(sess.InstanceID) || manager.ActiveWork(sess.InstanceID) {
		t.Fatal("replacement endpoint inherited former native work")
	}
}
