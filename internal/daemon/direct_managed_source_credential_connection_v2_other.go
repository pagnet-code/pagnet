//go:build !linux && !darwin

package daemon

type directManagedSourceCredentialExecutorV2 interface{ ready() bool }
