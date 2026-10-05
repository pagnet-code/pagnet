package fabricnode

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
	extregistry "github.com/pagnet-code/pagnet/fabric/extension/registry"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/node/continuations"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

func (r *ExtensionRuntime) administration(ctx context.Context, admin *fabricauth.OwnerAdministration, next func(context.Context) error) error {
	if r == nil || ctx == nil || next == nil || admin == nil || !admin.MatchesAuthority(r.boundary.root) || admin.VerifyCurrent(ctx) != nil {
		return localDenied()
	}
	r.mu.Lock()
	closing := r.closing
	if !closing {
		r.work.Add(1)
	}
	r.mu.Unlock()
	if closing {
		return localDenied()
	}
	defer r.work.Done()
	owned, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	defer func() { stop(); cancel() }()
	ctx = owned
	if e := next(ctx); e != nil {
		return e
	}
	return admin.VerifyCurrent(ctx)
}
func (r *ExtensionRuntime) PutProfile(ctx context.Context, admin *fabricauth.OwnerAdministration, profile ExtensionProfile) (string, error) {
	var digest string
	e := r.administration(ctx, admin, func(c context.Context) error {
		var e error
		digest, e = r.infrastructure.Profiles.Put(c, profile)
		return e
	})
	return digest, e
}
func (r *ExtensionRuntime) Install(ctx context.Context, admin *fabricauth.OwnerAdministration, generation uint64, input extregistry.Installation) (extregistry.Reference, error) {
	var result extregistry.Reference
	e := r.administration(ctx, admin, func(c context.Context) error {
		for _, binding := range input.Bindings {
			if r.config.Credentials == nil && binding.Selector != "credentials.none" {
				return fabric.NewError(fabric.CodeUnsupported, "Selected interceptor credential provider unavailable")
			}
			profile, e := r.infrastructure.Profiles.Get(c, binding.ProfileDigest)
			if e != nil || profile.Protocol != binding.Protocol || binding.Selector != profile.CredentialSelector {
				return localDenied()
			}
		}
		owner, e := r.installation.Operator(c)
		if e != nil {
			return e
		}
		result, e = r.infrastructure.Registry.Install(c, owner, generation, input)
		if e != nil {
			return e
		}
		return r.reload(c)
	})
	return result, e
}
func (r *ExtensionRuntime) Update(ctx context.Context, admin *fabricauth.OwnerAdministration, generation, revision uint64, input extregistry.Installation) (extregistry.Reference, error) {
	var result extregistry.Reference
	err := r.administration(ctx, admin, func(c context.Context) error {
		for _, binding := range input.Bindings {
			if r.config.Credentials == nil && binding.Selector != "credentials.none" {
				return fabric.NewError(fabric.CodeUnsupported, "Selected interceptor credential provider unavailable")
			}
			profile, e := r.infrastructure.Profiles.Get(c, binding.ProfileDigest)
			if e != nil || profile.Protocol != binding.Protocol || binding.Selector != profile.CredentialSelector {
				return localDenied()
			}
		}
		owner, e := r.installation.Operator(c)
		if e != nil {
			return e
		}
		result, e = r.infrastructure.Registry.Update(c, owner, generation, revision, input)
		if e != nil {
			return e
		}
		return r.reload(c)
	})
	return result, err
}
func (r *ExtensionRuntime) Inspect(ctx context.Context, admin *fabricauth.OwnerAdministration, id string) (extregistry.Reference, extregistry.Installation, error) {
	var ref extregistry.Reference
	var installed extregistry.Installation
	err := r.administration(ctx, admin, func(c context.Context) error {
		owner, e := r.installation.Operator(c)
		if e != nil {
			return e
		}
		ref, installed, e = r.infrastructure.Registry.Inspect(c, owner, id)
		return e
	})
	return ref, installed, err
}

func (r *ExtensionRuntime) Remove(ctx context.Context, admin *fabricauth.OwnerAdministration, generation, revision uint64, id string) error {
	return r.administration(ctx, admin, func(c context.Context) error {
		owner, e := r.installation.Operator(c)
		if e != nil {
			return e
		}
		if e = r.infrastructure.Registry.Remove(c, owner, generation, revision, id); e != nil {
			return e
		}
		return r.reload(c)
	})
}
func (r *ExtensionRuntime) List(ctx context.Context, admin *fabricauth.OwnerAdministration, after string, limit int) (extregistry.Page, error) {
	var page extregistry.Page
	e := r.administration(ctx, admin, func(c context.Context) error {
		owner, e := r.installation.Operator(c)
		if e != nil {
			return e
		}
		page, e = r.infrastructure.Registry.List(c, owner, after, limit)
		return e
	})
	return page, e
}

// PrivateDelivery never returns a JSON capability. The caller is the actual
// owner administration session and must consume it within this private port.
func (r *ExtensionRuntime) PrivateDelivery(ctx context.Context, admin *fabricauth.OwnerAdministration, id string, next func(context.Context, continuation.PrivateDelivery) error) error {
	if next == nil {
		return localDenied()
	}
	return r.administration(ctx, admin, func(c context.Context) error {
		return admin.WithResumerContext(c, func(c context.Context, recipient fabric.ExecutionContext) error {
			delivery, e := r.notifications.Delivery(c, recipient, id)
			if e != nil {
				return e
			}
			return next(c, delivery)
		})
	})
}

// RecoverNotification completes only the separate signed publication phase
// from the SAME SQLite outbox. It does not rotate a secret, claim or execute.
func (r *ExtensionRuntime) RecoverNotification(ctx context.Context, admin *fabricauth.OwnerAdministration, id string) error {
	return r.administration(ctx, admin, func(c context.Context) error {
		return admin.WithResumerContext(c, func(c context.Context, recipient fabric.ExecutionContext) error {
			d, e := r.infrastructure.Continuations.PrivateNotification(c, recipient, id)
			if e != nil {
				return e
			}
			return r.notifications.Publish(c, continuations.PrivateNotification{ID: d.ID, Capability: d.Capability(), Revision: d.Revision, ExpiresAt: d.ExpiresAt, Recipients: []fabric.Principal{d.Recipient}})
		})
	})
}

// RotatePendingCapability FULL-commits replacement secret and recipient outbox
// first. A failed Root publication leaves it recoverable; old proof/token can
// neither deliver the new secret nor resume after this irreversible rotation.
func (r *ExtensionRuntime) RotatePendingCapability(ctx context.Context, admin *fabricauth.OwnerAdministration, id string, expected uint64) (continuation.Issued, error) {
	var issued continuation.Issued
	e := r.administration(ctx, admin, func(c context.Context) error {
		return admin.WithResumerContext(c, func(c context.Context, recipient fabric.ExecutionContext) error {
			var e error
			issued, e = r.infrastructure.Continuations.RotatePendingCapability(c, recipient, id, expected)
			if e != nil {
				return e
			}
			d, e := r.infrastructure.Continuations.PrivateNotification(c, recipient, id)
			if e != nil {
				return e
			}
			return r.notifications.Publish(c, continuations.PrivateNotification{ID: d.ID, Capability: d.Capability(), Revision: d.Revision, ExpiresAt: d.ExpiresAt, Recipients: []fabric.Principal{d.Recipient}})
		})
	})
	// Never return the capability from an administration DTO; the only delivery
	// path is recipient-authenticated private retrieval above.
	issued.Capability = continuation.Capability{}
	return issued, e
}

// Resume creates an owned original pipeline lifetime. Only the fresh claim can
// retain its genuine resumer after the synchronous admin response returns.
// Duplicate claim returns the original receipt without restoration or effect.
func (r *ExtensionRuntime) Resume(ctx context.Context, admin *fabricauth.OwnerAdministration, id, claimID string, service *node.Service) (continuations.ResumeResult, error) {
	var result continuations.ResumeResult
	if service == nil {
		return result, localDenied()
	}
	e := r.administration(ctx, admin, func(c context.Context) error {
		return admin.WithResumerContext(c, func(c context.Context, resumer fabric.ExecutionContext) error {
			receipt, found, e := r.infrastructure.Continuations.ClaimReceipt(c, resumer, id, claimID)
			if e != nil {
				return e
			}
			if found {
				result.Claim = receipt
				return nil
			}
			delivery, e := r.notifications.Delivery(c, resumer, id)
			if e != nil {
				return e
			}
			// This owned context is not the short response lifetime. Actual original
			// paid deadline and session/claim revocation are still verified by engine.
			owned, release, bundle, e := r.begin(context.WithoutCancel(c))
			if e != nil {
				return e
			}
			owned = context.WithValue(owned, extensionPhaseActorKey{}, &extensionPhaseActors{runtime: r})
			result, e = bundle.recorder.Resume(owned, resumer, delivery.Capability().Token(), claimID, bundle.engine, func(call context.Context, original fabric.ExecutionContext, envelope fabric.Envelope) (extension.Outcome, error) {
				binding, ok := r.boundary.resumeBinding(original)
				if !ok {
					return extension.Outcome{}, localDenied()
				}
				out, e := service.InvokeResumed(call, original, binding.originalBytes, envelope)
				return extension.Outcome{Stream: out.Stream}, e
			})
			if e != nil || result.Outcome.Stream == nil {
				release()
				return e
			}
			stream := &extensionRuntimeStream{runtime: r, upstream: result.Outcome.Stream, release: release, phase: owned}
			r.mu.Lock()
			r.streams[stream] = struct{}{}
			r.pulseLocked()
			closing := r.closing
			r.mu.Unlock()
			if closing {
				stream.Close()
				return localDenied()
			}
			result.Outcome.Stream = stream
			return nil
		})
	})
	if e != nil && result.Outcome.Stream != nil {
		result.Outcome.Stream.Close()
		result.Outcome.Stream = nil
	}
	return result, e
}
