package proc

// AdmitWork reserves admission until release. The supervisor and its callers
// use the same gate, covering preparation as well as the actual process start.
// Nested reservations are safe: exclusive admission only uses TryLock, never
// queues a writer that would block a nested read lock.
func (s *Supervisor) AdmitWork() func() {
	s.admission.RLock()
	return s.admission.RUnlock
}

// TryQuiesce excludes new work while checking idle state and replacing the
// process image. It never waits for an active turn or slow activation. The
// callback must not admit work; its lock order is admission then state/registry.
func (s *Supervisor) TryQuiesce(fn func() bool) bool {
	if !s.admission.TryLock() {
		return false
	}
	defer s.admission.Unlock()
	return fn()
}
