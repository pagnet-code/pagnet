package daemon

func (d *Daemon) admitWork() func() {
	if d.sup == nil {
		return func() {}
	} // Validation-only test fixtures.
	return d.sup.AdmitWork()
}

// finalizeIdleUpdate retains the common admission barrier from the final
// idle snapshot through binary replacement and exec. State inspection failures
// count as busy. Callers cannot mistake an unknown state for safe quiescence.
func (d *Daemon) finalizeIdleUpdate(finalize func()) bool {
	if d.sup == nil {
		return false
	}
	return d.sup.TryQuiesce(func() bool {
		if d.activeWorkCount() != 0 {
			return false
		}
		finalize()
		return true
	})
}
