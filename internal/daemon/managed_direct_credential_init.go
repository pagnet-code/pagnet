//go:build linux || darwin

package daemon

func (d *Daemon) initManagedDirectCredential() {
	if !d.ManagedDirectCredentialEnabled || d.managedDirectCredential != nil {
		return
	}
	executor, err := newLocalManagedDirectCredential(d)
	// Keep constructed custody even while dependencies are temporarily unready.
	// The exact offer gate checks live readiness separately on each connection.
	if err == nil {
		d.managedDirectCredential = executor
	}
}
