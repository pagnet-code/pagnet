package session

import (
	"context"
	"errors"
	"github.com/pagnet-code/pagnet/domain"
)

type pendingPermissionChoice struct {
	nativeSessionID string
	options         []domain.RuntimeInteractionOption
}

// observePermissionChoicesLocked copies only options from the original native
// session. Both machine streams and native human/background observers use it.
func observePermissionChoicesLocked(sess *RuntimeSession, event SessionEvent) {
	if event.Interaction == nil {
		return
	}
	id := event.Interaction.NativeInteractionID
	delete(sess.pendingPermissionChoices, id)
	if event.Type != EventInteractionStarted || id == "" || event.Interaction.Kind != "permission" || event.SessionID != sess.NativeID || !domain.ValidRuntimeInteractionOptions(event.Interaction.Options) {
		return
	}
	if sess.pendingPermissionChoices == nil {
		sess.pendingPermissionChoices = make(map[string]pendingPermissionChoice)
	}
	sess.pendingPermissionChoices[id] = pendingPermissionChoice{nativeSessionID: event.SessionID, options: append([]domain.RuntimeInteractionOption(nil), event.Interaction.Options...)}
}

// ResolvePendingInteraction never activates or wakes a session. Both the native
// session and interaction must still match the observed, running endpoint.
func (m *Manager) ResolvePendingInteraction(ctx context.Context, instanceID, nativeSessionID, interactionID, optionID string) error {
	lock := m.activationLock(instanceID)
	if !lock.TryLock() {
		return errors.New("native session is changing")
	}
	defer lock.Unlock()
	m.mu.Lock()
	sess := m.sessions[instanceID]
	valid := sess != nil && sess.NativeID == nativeSessionID && sess.State == StateBusy && sess.PendingInteractions[interactionID]
	decision := ""
	if valid {
		observed := sess.pendingPermissionChoices[interactionID]
		if observed.nativeSessionID == nativeSessionID {
			for _, option := range observed.options {
				if option.ID != optionID {
					continue
				}
				switch option.Kind {
				case "allow_once", "allow_always":
					decision = "resolved"
				case "reject_once", "reject_always":
					decision = "declined"
				}
			}
		}
	}
	m.mu.Unlock()
	if !valid {
		return errors.New("native interaction is no longer pending")
	}
	if decision == "" {
		return errors.New("native choice was not observed")
	}
	events := make(chan SessionEvent, 16)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range events {
		}
	}()
	_, err := m.Submit(ctx, sess, SubmitRequest{Kind: SubmitInteraction, InteractionID: interactionID, Decision: decision, Answer: optionID}, events)
	<-drained
	return err
}
