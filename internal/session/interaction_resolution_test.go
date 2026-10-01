package session

import (
	"context"
	"testing"
)

func TestResolvePendingInteractionRequiresLiveSessionGeneration(t *testing.T) {
	m := NewManager()
	driver := newInteractionDriver()
	m.RegisterDriver(driver)
	sess := &RuntimeSession{InstanceID: "approval-instance", Runtime: driver.Name(), NativeID: "native-session", State: StateBusy, PendingInteractions: map[string]bool{"permission-generation:4": true}}
	m.mu.Lock()
	m.sessions[sess.InstanceID] = sess
	m.mu.Unlock()
	for _, tc := range []struct{ native, permission string }{{"old-native", "permission-generation:4"}, {"native-session", "old-generation:4"}} {
		if m.ResolvePendingInteraction(context.Background(), sess.InstanceID, tc.native, tc.permission, "allow") == nil {
			t.Fatal("stale session/permission delivered")
		}
	}
	if driver.interactionsCount() != 0 {
		t.Fatal("stale choice reached native driver")
	}
	if err := m.ResolvePendingInteraction(context.Background(), sess.InstanceID, "native-session", "permission-generation:4", "allow"); err != nil {
		t.Fatal(err)
	}
	if driver.interactionsCount() != 1 {
		t.Fatal("current choice wasn't delivered")
	}
	m.mu.Lock()
	sess.State = StateInactive
	m.mu.Unlock()
	if m.ResolvePendingInteraction(context.Background(), sess.InstanceID, "native-session", "permission-generation:4", "allow") == nil {
		t.Fatal("inactive session was woken to approve")
	}
	lock := m.activationLock(sess.InstanceID)
	lock.Lock()
	if m.ResolvePendingInteraction(context.Background(), sess.InstanceID, "native-session", "permission-generation:4", "allow") == nil {
		t.Fatal("changing session approved")
	}
	lock.Unlock()
}
