package session

import (
	"context"
	"errors"
)

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
	m.mu.Unlock()
	if !valid {
		return errors.New("native interaction is no longer pending")
	}
	events := make(chan SessionEvent, 16)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range events {
		}
	}()
	_, err := m.Submit(ctx, sess, SubmitRequest{Kind: SubmitInteraction, InteractionID: interactionID, Decision: "resolved", Answer: optionID}, events)
	<-drained
	return err
}
