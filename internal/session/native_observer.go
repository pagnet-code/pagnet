package session

// NativeEventObserver belongs to one actual endpoint generation. It observes
// all native events before machine-turn filtering, including human and idle
// background events. It must retain/backpressure the original event until
// durable admission, rather than acknowledge a failed journal write.
type NativeEventObserver func(SessionEvent) error

// No batch frame is accepted/published until its durable observer returns.
type NativeEventBatchObserver func([]SessionEvent) error

const NativeOutputBatchMaxEvents = 32
const NativeOutputBatchMaxBytes = 64 << 10

type NativeEventObserverFactory func(instanceID string) NativeEventObserver

// NativeEventObserverRegistration owns the append capability for one endpoint.
// Retire closes Observe and waits for all callbacks, including concurrent
// interaction resolution callbacks. The endpoint must call it when its reader
// exits; no old reader or resolution callback can append after it returns.
type NativeEventObserverRegistration struct {
	Observe      NativeEventObserver
	ObserveBatch NativeEventBatchObserver
	Retire       func()
}
type NativeEventObserverRegistrationFactory func(instanceID string) NativeEventObserverRegistration

// ObserveNativeActivity folds positively observed native work into the owned
// session. Activation identity remains the driver's activation-lock authority;
// native activity must not race those identity writes.
func (m *Manager) ObserveNativeActivity(instanceID string, event SessionEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess := m.sessions[instanceID]
	if sess == nil {
		return
	}
	switch event.Type {
	case EventTurnStarted, EventBusy:
		sess.NativeBusy = true
		sess.State = StateBusy
	case EventTurnCompleted, EventTurnFailed, EventIdle:
		sess.NativeBusy = len(sess.PendingInteractions) > 0
		if len(sess.PendingInteractions) == 0 {
			sess.State = StateIdle
		}
		if event.Type == EventTurnCompleted {
			sess.Materialised = true
		}
	case EventInteractionStarted:
		if event.Interaction != nil && event.Interaction.NativeInteractionID != "" {
			if sess.PendingInteractions == nil {
				sess.PendingInteractions = map[string]bool{}
			}
			sess.PendingInteractions[event.Interaction.NativeInteractionID] = true
			observePermissionChoicesLocked(sess, event)
			sess.NativeBusy = true
			sess.State = StateBusy
		}
	case EventInteractionResolved:
		if event.Interaction != nil {
			delete(sess.PendingInteractions, event.Interaction.NativeInteractionID)
			observePermissionChoicesLocked(sess, event)
		}
	}
	sess.LastActivity = m.now()
}

// ResetNativeActivity is called only when a new actual endpoint generation
// replaces the former process. Stale busy/approval state is not inherited.
func (m *Manager) ResetNativeActivity(instanceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sess := m.sessions[instanceID]; sess != nil {
		sess.NativeBusy = false
		sess.PendingInteractions = map[string]bool{}
		sess.pendingPermissionChoices = nil
	}
}
