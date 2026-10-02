package sessionworker

import "errors"

// The only production append writer is the original native event observer.
// A pin spans its entire retry loop and is released only after known success
// or callback cancellation. No controller IPC can create or recreate a pin.
// Worker crash destroys the original callback and its retry capability.
type nativeSourceRetry struct {
	digest  string
	retired bool
}

func (j *Journal) pinSourceRetry(id, digest string) error {
	if id == "" || len(digest) != 64 {
		return errors.New("invalid source producer identity")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.sourceRetries == nil {
		j.sourceRetries = make(map[string]*nativeSourceRetry)
	}
	if j.sourceRetries[id] != nil {
		return ErrConflict
	}
	if len(j.sourceRetries) >= maxPendingObservations {
		return ErrFull
	}
	j.sourceRetries[id] = &nativeSourceRetry{digest: digest}
	return nil
}
func (j *Journal) releaseSourceRetry(id, digest string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if retry := j.sourceRetries[id]; retry != nil && retry.digest == digest {
		delete(j.sourceRetries, id)
	}
}
