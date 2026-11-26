//go:build linux || darwin

package daemon

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

var errDirectEndpointReconcileObservation = errors.New("direct endpoint observation unavailable or rejected")

type directEndpointReconcileObservation struct {
	Binding     directEndpointReconcileBinding
	Enrollment  directhttp.Enrollment
	Publication []byte
}
type directEndpointReconcileObserver func(context.Context) (directEndpointReconcileObservation, error)

type directEndpointReconcileReader interface {
	Descriptor(context.Context, string, string) (transport.DirectChannelDescriptorV2, error)
	Enrollment(context.Context, string, string, string) (directhttp.Enrollment, error)
	Publication(context.Context, string, string) (transport.DirectChannelPublicationV2, error)
}

type directEndpointReconcileObservationValidator func(context.Context, transport.DirectChannelDescriptorV2, directhttp.Enrollment, time.Time) (directEndpointReconcileBinding, error)

func newDirectSourceReconcileObserver(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.DirectManagedSourceCredentialIssueV2) (directEndpointReconcileObserver, error) {
	return newDirectSourceReconcileObserverWithReader(d, captured, s, issue, nil, time.Now)
}
func newDirectSourceReconcileObserverWithReader(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.DirectManagedSourceCredentialIssueV2, reader directEndpointReconcileReader, now func() time.Time) (directEndpointReconcileObserver, error) {
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, errDirectEndpointOperationRejected
	}
	owned, err := transport.DecodeDirectManagedSourceCredentialIssueV2(raw)
	if err != nil {
		return nil, errDirectEndpointOperationRejected
	}
	captured, err = ownDirectReconcileOperationScope(d, captured, s, raw, "S", string(owned.PoP.ACK.Reservation.InstallationID))
	if err != nil {
		return nil, err
	}
	origin := s.binding.metadata.ServerOrigin
	if origin != owned.PoP.ACK.Reservation.ServerURL || now == nil {
		return nil, errDirectEndpointOperationRejected
	}
	operate, err := newDirectSourceReconcileOperation(d, captured, s, owned)
	if err != nil {
		return nil, err
	}
	reader, err = directReconcileObservationReader(origin, reader)
	if err != nil {
		return nil, err
	}
	validate := func(ctx context.Context, descriptor transport.DirectChannelDescriptorV2, enrollment directhttp.Enrollment, at time.Time) (directEndpointReconcileBinding, error) {
		snapshot, err := transport.DecodeDirectManagedSourceCredentialIssueV2(raw)
		if err != nil {
			return directEndpointReconcileBinding{}, errDirectEndpointReconcileBinding
		}
		return validateDirectSourceReconcileBindingV2Context(ctx, s, captured, snapshot, descriptor, enrollment, at)
	}
	return newDirectReconcileObserver(s, origin, string(owned.CredentialID), string(owned.PoP.Prepare.Subject.DirectIntentID), "S", reader, now, operate, validate), nil
}
func newDirectTargetReconcileObserver(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.ManagedDirectCredentialIssue) (directEndpointReconcileObserver, error) {
	return newDirectTargetReconcileObserverWithReader(d, captured, s, issue, nil, time.Now)
}
func newDirectTargetReconcileObserverWithReader(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.ManagedDirectCredentialIssue, reader directEndpointReconcileReader, now func() time.Time) (directEndpointReconcileObserver, error) {
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, errDirectEndpointOperationRejected
	}
	owned, err := transport.DecodeManagedDirectCredentialIssue(raw)
	if err != nil {
		return nil, errDirectEndpointOperationRejected
	}
	captured, err = ownDirectReconcileOperationScope(d, captured, s, raw, "P", string(owned.PoP.ACK.Reservation.InstallationID))
	if err != nil {
		return nil, err
	}
	origin := s.binding.metadata.ServerOrigin
	if origin != owned.PoP.ACK.Reservation.ServerURL || now == nil {
		return nil, errDirectEndpointOperationRejected
	}
	operate, err := newDirectTargetReconcileOperation(d, captured, s, owned)
	if err != nil {
		return nil, err
	}
	reader, err = directReconcileObservationReader(origin, reader)
	if err != nil {
		return nil, err
	}
	validate := func(ctx context.Context, descriptor transport.DirectChannelDescriptorV2, enrollment directhttp.Enrollment, at time.Time) (directEndpointReconcileBinding, error) {
		snapshot, err := transport.DecodeManagedDirectCredentialIssue(raw)
		if err != nil {
			return directEndpointReconcileBinding{}, errDirectEndpointReconcileBinding
		}
		return validateDirectTargetReconcileBindingContext(ctx, s, captured, snapshot, descriptor, enrollment, at)
	}
	return newDirectReconcileObserver(s, origin, string(owned.CredentialID), string(owned.PoP.Prepare.Subject.DirectIntentID), "P", reader, now, operate, validate), nil
}

func directReconcileObservationReader(origin string, reader directEndpointReconcileReader) (directEndpointReconcileReader, error) {
	// Validate the pinned origin even when a test supplies the read-only seam.
	client, err := directhttp.New(origin)
	if err != nil {
		return nil, sanitizeDirectReconcileReadError(err)
	}
	if reader != nil {
		return reader, nil
	}
	return client, nil
}

// Reads are staged inside one synchronous custody use. Read failures return nil
// from that callback so exact-lease response acceptance always takes precedence.
// The observer retains no custody and starts no coordinator or retry loop.
func newDirectReconcileObserver(s *DirectEndpointSubscription, origin, credentialID, intent, role string, reader directEndpointReconcileReader, now func() time.Time, operate directEndpointMaterialOperation, validate directEndpointReconcileObservationValidator) directEndpointReconcileObserver {
	var active sync.Mutex
	return func(ctx context.Context) (result directEndpointReconcileObservation, err error) {
		defer func() {
			if recover() != nil {
				err = errDirectEndpointOperationUnknown
			}
			if err != nil {
				result = directEndpointReconcileObservation{}
			}
		}()
		if ctx == nil || s == nil || reader == nil || now == nil || operate == nil || validate == nil || !active.TryLock() {
			return result, errDirectEndpointOperationRejected
		}
		defer active.Unlock()
		if s.binding.metadata.ServerOrigin != origin {
			return result, errDirectEndpointOperationRejected
		}
		var staged directEndpointReconcileObservation
		var readErr error
		var called, repeated atomic.Bool
		operationErr := operate(ctx, func(opctx context.Context, custody endpointMaterial) error {
			if !called.CompareAndSwap(false, true) {
				repeated.Store(true)
				return nil
			}
			read := func() error {
				if err := s.operationCurrentContextError(opctx); err != nil {
					return err
				}
				if len(custody.secret) != 32 {
					return errDirectEndpointReconcileObservation
				}
				credentialBytes := make([]byte, len(credentialID)+1+base64.RawURLEncoding.EncodedLen(32))
				defer clear(credentialBytes)
				copy(credentialBytes, credentialID)
				credentialBytes[len(credentialID)] = ':'
				base64.RawURLEncoding.Encode(credentialBytes[len(credentialID)+1:], custody.secret)
				credential := string(credentialBytes)
				clear(credentialBytes)
				descriptor, err := reader.Descriptor(opctx, credential, intent)
				if err != nil {
					return sanitizeDirectReconcileReadError(err)
				}
				enrollment, err := reader.Enrollment(opctx, credential, intent, role)
				if err != nil {
					return sanitizeDirectReconcileReadError(err)
				}
				binding, err := validate(opctx, descriptor, enrollment, now())
				if err != nil {
					return err
				}
				var publication []byte
				if enrollment.PublicationHash != nil {
					value, err := reader.Publication(opctx, credential, intent)
					if err != nil {
						return sanitizeDirectReconcileReadError(err)
					}
					publication, err = value.CanonicalBytes()
					if err != nil || !binding.publicationMatches(value) || !reconcilePublicationHash(enrollment, publication) {
						return errDirectEndpointReconcileBinding
					}
				}
				binding, err = validate(opctx, descriptor, enrollment, now())
				if err != nil {
					return err
				}
				staged = directEndpointReconcileObservation{Binding: binding, Enrollment: enrollment, Publication: publication}
				return nil
			}
			readErr = read()
			return nil
		})
		if operationErr != nil {
			return result, operationErr
		}
		if err := s.operationCurrentContextError(ctx); err != nil {
			return result, err
		}
		if !called.Load() || repeated.Load() {
			return result, errDirectEndpointOperationRejected
		}
		if readErr != nil {
			return result, readErr
		}
		return staged, nil
	}
}

func sanitizeDirectReconcileReadError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var wire *directhttp.Error
	if errors.As(err, &wire) {
		switch wire.Kind {
		case directhttp.Invalid, directhttp.Unauthorized, directhttp.Unavailable, directhttp.Conflict, directhttp.TooLarge, directhttp.ServiceUnavailable, directhttp.Protocol, directhttp.Transport:
			status := wire.Status
			if status < 100 || status > 599 {
				status = 0
			}
			return &directhttp.Error{Kind: wire.Kind, Status: status}
		}
	}
	return errDirectEndpointReconcileObservation
}
