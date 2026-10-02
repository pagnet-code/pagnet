package sessionworker

import "github.com/pagnet-code/pagnet/internal/session"

// Legacy unpublished capture fixtures precede the production registration
// protocol. No production reader gets an unregistered append callback.
func (o *SessionOwner) nativeEventObserver(instanceID string) session.NativeEventObserver {
	return o.nativeSourceObserver(instanceID, nil)
}
