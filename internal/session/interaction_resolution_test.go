package session

import (
	"context"
	"github.com/pagnet-code/pagnet/domain"
	"testing"
)

func TestResolvePendingInteractionRequiresLiveSessionGeneration(t *testing.T) {
	m := NewManager()
	driver := newInteractionDriver()
	m.RegisterDriver(driver)
	sess := &RuntimeSession{InstanceID: "approval-instance", Runtime: driver.Name(), NativeID: "native-session", State: StateBusy, PendingInteractions: map[string]bool{"permission-generation:4": true}, pendingPermissionChoices: map[string]pendingPermissionChoice{"permission-generation:4": {nativeSessionID: "native-session", options: []domain.RuntimeInteractionOption{{ID: "allow", Kind: "allow_once"}}}}}
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

type permissionDecisionDriver struct {
	*interactionDriver
	requests []SubmitRequest
}

func (d *permissionDecisionDriver) Submit(_ context.Context, _ *RuntimeSession, request SubmitRequest, _ chan<- SessionEvent) error {
	d.requests = append(d.requests, request)
	return nil
}

func TestResolvePendingInteractionUsesOriginalObservedOptionKind(t *testing.T) {
	for _, tc := range []struct{ kind, decision string }{{"allow_once", "resolved"}, {"allow_always", "resolved"}, {"reject_once", "declined"}, {"reject_always", "declined"}} {
		t.Run(tc.kind, func(t *testing.T) {
			m := NewManager()
			d := &permissionDecisionDriver{interactionDriver: newInteractionDriver()}
			m.RegisterDriver(d)
			sess := &RuntimeSession{InstanceID: "original-instance", Runtime: d.Name(), NativeID: "original-session", State: StateBusy}
			m.sessions[sess.InstanceID] = sess
			options := []domain.RuntimeInteractionOption{{ID: "vendor-option-42", Kind: tc.kind}}
			m.applyEvent(sess, nil, SessionEvent{Type: EventInteractionStarted, SessionID: sess.NativeID, Interaction: &InteractionEvent{NativeInteractionID: "original-permission", Kind: "permission", Options: options}})
			// Native event objects can be reused by a driver. The Manager must retain
			// the actual observed value rather than share its mutable slice.
			options[0].Kind = "allow_once"
			if err := m.ResolvePendingInteraction(t.Context(), sess.InstanceID, sess.NativeID, "original-permission", "unobserved"); err == nil {
				t.Fatal("unobserved choice was delivered")
			}
			if len(d.requests) != 0 {
				t.Fatal("unobserved choice reached driver")
			}
			if err := m.ResolvePendingInteraction(t.Context(), sess.InstanceID, sess.NativeID, "original-permission", "vendor-option-42"); err != nil {
				t.Fatal(err)
			}
			if len(d.requests) != 1 || d.requests[0].Decision != tc.decision || d.requests[0].Answer != "vendor-option-42" || d.requests[0].InteractionID != "original-permission" {
				t.Fatal("original native permission semantics were changed", d.requests)
			}
			m.applyEvent(sess, nil, SessionEvent{Type: EventInteractionResolved, SessionID: sess.NativeID, Interaction: &InteractionEvent{NativeInteractionID: "original-permission"}})
			if err := m.ResolvePendingInteraction(t.Context(), sess.InstanceID, sess.NativeID, "original-permission", "vendor-option-42"); err == nil {
				t.Fatal("resolved native choice replayed")
			}
		})
	}
}

func TestResolvePendingInteractionRefusesUnboundPermissionOptions(t *testing.T) {
	for _, tc := range []struct{ name, native, kind, optionKind string }{{"missing", "original-session", "permission", ""}, {"question", "original-session", "question", "reject_once"}, {"old-session", "old-session", "permission", "reject_once"}, {"invalid-kind", "original-session", "permission", "invented"}} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager()
			d := &permissionDecisionDriver{interactionDriver: newInteractionDriver()}
			m.RegisterDriver(d)
			sess := &RuntimeSession{InstanceID: "original-instance", Runtime: d.Name(), NativeID: "original-session", State: StateBusy}
			m.sessions[sess.InstanceID] = sess
			m.applyEvent(sess, nil, SessionEvent{Type: EventInteractionStarted, SessionID: tc.native, Interaction: &InteractionEvent{NativeInteractionID: "permission", Kind: tc.kind, Options: []domain.RuntimeInteractionOption{{ID: "option", Kind: tc.optionKind}}}})
			if err := m.ResolvePendingInteraction(t.Context(), sess.InstanceID, sess.NativeID, "permission", "option"); err == nil {
				t.Fatal("unbound native choice was delivered")
			}
			if len(d.requests) != 0 {
				t.Fatal("unbound choice reached driver")
			}
		})
	}
}

func TestResolvePendingHumanPermissionUsesNativeObservationAndClearsOnReset(t *testing.T) {
	m := NewManager()
	d := &permissionDecisionDriver{interactionDriver: newInteractionDriver()}
	m.RegisterDriver(d)
	sess := &RuntimeSession{InstanceID: "human-instance", Runtime: d.Name(), NativeID: "human-native", State: StateIdle}
	m.sessions[sess.InstanceID] = sess
	event := SessionEvent{Type: EventInteractionStarted, SessionID: sess.NativeID, Interaction: &InteractionEvent{NativeInteractionID: "human-choice", Kind: "permission", Options: []domain.RuntimeInteractionOption{{ID: "native-button", Kind: "reject_once"}}}}
	m.ObserveNativeActivity(sess.InstanceID, event)
	if err := m.ResolvePendingInteraction(t.Context(), sess.InstanceID, sess.NativeID, "human-choice", "native-button"); err != nil {
		t.Fatal(err)
	}
	if len(d.requests) != 1 || d.requests[0].Decision != "declined" {
		t.Fatal("human native rejection semantics lost")
	}
	m.ResetNativeActivity(sess.InstanceID)
	if len(sess.pendingPermissionChoices) != 0 {
		t.Fatal("replacement endpoint retained old native choices")
	}
	if err := m.ResolvePendingInteraction(t.Context(), sess.InstanceID, sess.NativeID, "human-choice", "native-button"); err == nil {
		t.Fatal("retired human choice replayed")
	}
}
