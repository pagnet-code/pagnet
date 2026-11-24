//go:build !linux && !darwin

package daemon

func (*Daemon) initManagedEndpointPrepare() {}
