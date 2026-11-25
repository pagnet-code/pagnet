//go:build !linux && !darwin

package daemon

func (*Daemon) initManagedDirectCredential() {}

func (*Daemon) managedDirectCredentialReady() bool      { return false }
func managedDirectCredentialServerOrigin(string) string { return "" }
