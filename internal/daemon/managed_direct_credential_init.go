//go:build linux || darwin

package daemon

func (d *Daemon) initManagedDirectCredential() {
	if !d.ManagedDirectCredentialEnabled || !d.managedEndpointPoPReady() {
		return
	}
	executor, err := newLocalManagedDirectCredential(d)
	if err == nil && executor.ready() {
		d.managedDirectCredential = executor
	}
}
