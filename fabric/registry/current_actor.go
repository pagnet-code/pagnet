package registry

import "github.com/pagnet-code/pagnet/fabric"

// VerifyCurrentActorBinding inspects a caller's explicitly retained descriptor
// in the SAME transaction as its selected target. It does not infer authority
// from kind, description, offers or instructions, and performs no external IO.
func (a *AuthorityTx) VerifyCurrentActorBinding(ref fabric.EndpointRef, revision fabric.Revision, binding string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e := a.guard(); e != nil {
		return e
	}
	if ref.IsOffer() || ref.Domain() != a.store.identity.Namespace || revision == "" || binding == "" {
		return invalid("Current actor binding is incomplete")
	}
	object, e := loadObject(a.ctx, a.tx, ref.String())
	if e != nil || object.retired || object.revision != revision {
		return conflict("Current actor descriptor is retired or stale")
	}
	var descriptor fabric.EndpointDescriptor
	if e = a.store.decode(object.payload, &descriptor); e != nil {
		return e
	}
	for _, candidate := range descriptor.Bindings {
		if candidate.ID == binding {
			return nil
		}
	}
	return invalid("Current actor binding is absent")
}
