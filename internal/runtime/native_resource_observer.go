package runtime

import (
	"errors"

	"github.com/pagnet-code/pagnet/internal/session"
)

// The termination callback is bound to the exact launched supervisor handle.
// A resource marker cannot stop a replacement generation through an instance ID.
func resourceBoundObserver(observe session.NativeEventObserver, terminate func(string) error) session.NativeEventObserver {
	if observe == nil {
		return nil
	}
	return func(event session.SessionEvent) error {
		err := observe(event)
		if errors.Is(err, session.ErrNativeResourceLimit) {
			return errors.Join(err, terminate("native-source-resource-limit"))
		}
		return err
	}
}
