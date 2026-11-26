//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

type reconcileObservationReader struct {
	t                          *testing.T
	descriptor                 transport.DirectChannelDescriptorV2
	enrollment                 directhttp.Enrollment
	publication                transport.DirectChannelPublicationV2
	credentialID, intent, role string
	calls                      []string
	fail                       string
	failure                    error
	hook                       func(string)
}

func (r *reconcileObservationReader) record(name, credential, intent string) error {
	r.calls = append(r.calls, name)
	id, encoded, ok := strings.Cut(credential, ":")
	secret, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	defer clear(secret)
	if !ok || id != r.credentialID || err != nil || len(secret) != 32 || intent != r.intent {
		r.t.Error("read used invalid credential or intent scope")
	}
	if r.hook != nil {
		r.hook(name)
	}
	if r.fail == name {
		return r.failure
	}
	return nil
}
func (r *reconcileObservationReader) Descriptor(_ context.Context, credential, intent string) (transport.DirectChannelDescriptorV2, error) {
	err := r.record("descriptor", credential, intent)
	return r.descriptor, err
}
func (r *reconcileObservationReader) Enrollment(_ context.Context, credential, intent, role string) (directhttp.Enrollment, error) {
	if role != r.role {
		r.t.Error("read used wrong role")
	}
	err := r.record("enrollment", credential, intent)
	return r.enrollment, err
}
func (r *reconcileObservationReader) Publication(_ context.Context, credential, intent string) (transport.DirectChannelPublicationV2, error) {
	err := r.record("publication", credential, intent)
	return r.publication, err
}
func observationReader(t *testing.T, s *DirectEndpointSubscription, b directEndpointReconcileBinding, e directhttp.Enrollment) *reconcileObservationReader {
	t.Helper()
	return &reconcileObservationReader{t: t, descriptor: b.Descriptor, enrollment: e, credentialID: string(s.binding.metadata.CredentialID), intent: string(s.binding.metadata.IntentID), role: s.binding.metadata.Role}
}
func observationPublication(t *testing.T, b directEndpointReconcileBinding) transport.DirectChannelPublicationV2 {
	t.Helper()
	// Observation validates authenticated public bytes and performs no HPKE open.
	p := transport.DirectChannelPublicationV2{Descriptor: b.Descriptor, Enc: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), Ciphertext: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 48))}
	if _, err := p.CanonicalBytes(); err != nil {
		t.Fatal(err)
	}
	return p
}
func assertZeroObservation(t *testing.T, result directEndpointReconcileObservation) {
	t.Helper()
	if !reflect.DeepEqual(result, directEndpointReconcileObservation{}) {
		t.Fatal("failed observer exposed a result")
	}
}
func TestDirectReconcileObservationRoles(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			var f *reconcileOperationFixture
			var b directEndpointReconcileBinding
			var e directhttp.Enrollment
			if role == "S" {
				f = newReconcileOperationFixture(t, role)
				b, e, _ = reconcileSourceOperationBinding(t, f)
			} else {
				f, b, e = newReconcileObservationTargetFixture(t)
			}
			reader := observationReader(t, f.s, b, e)
			var observer directEndpointReconcileObserver
			var err error
			if role == "S" {
				observer, err = newDirectSourceReconcileObserverWithReader(f.d, f.captured, f.s, f.source, reader, time.Now)
			} else {
				observer, err = newDirectTargetReconcileObserverWithReader(f.d, f.captured, f.s, f.target, reader, time.Now)
			}
			if err != nil {
				t.Fatal(err)
			}
			// The observer and operation both own their issue/session snapshots.
			f.captured.Session.ProtocolFeatures[0] = "caller mutation"
			if role == "P" {
				f.target.PoP.Authorization.Permissions[0] = "caller issue mutation"
			}
			f.source = transport.DirectManagedSourceCredentialIssueV2{}
			f.target = transport.ManagedDirectCredentialIssue{}
			result, err := observer(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(reader.calls, []string{"descriptor", "enrollment"}) || result.Publication != nil || result.Binding.DescriptorHash != b.DescriptorHash {
				t.Fatal("absence observation or read order changed")
			}
			reader.calls = nil
			reader.publication = observationPublication(t, b)
			wire, _ := reader.publication.CanonicalBytes()
			reader.enrollment = publishedEnrollment(e, wire)
			result, err = observer(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(reader.calls, []string{"descriptor", "enrollment", "publication"}) || !bytes.Equal(result.Publication, wire) {
				t.Fatal("publication observation or read order changed")
			}
		})
	}
}

func observationCoreFixture(t *testing.T, role string) (*reconcileMaterialFixture, *reconcileObservationReader, directEndpointReconcileObservationValidator) {
	t.Helper()
	f := newReconcileMaterialFixture(t, role)
	reader := observationReader(t, f.subscription, f.binding, f.enrollment)
	reader.publication = observationPublication(t, f.binding)
	validate := func(ctx context.Context, d transport.DirectChannelDescriptorV2, e directhttp.Enrollment, now time.Time) (directEndpointReconcileBinding, error) {
		raw, err := d.CanonicalBytes()
		if err != nil || !bytes.Equal(raw, f.binding.DescriptorBytes) {
			return directEndpointReconcileBinding{}, errDirectEndpointReconcileBinding
		}
		if err := validateDirectReconcileMaterialEvidenceContext(ctx, f.subscription, f.binding, e, now, role); err != nil {
			return directEndpointReconcileBinding{}, err
		}
		return f.binding, nil
	}
	return f, reader, validate
}
func coreObserver(f *reconcileMaterialFixture, reader directEndpointReconcileReader, validate directEndpointReconcileObservationValidator, operate directEndpointMaterialOperation) directEndpointReconcileObserver {
	return newDirectReconcileObserver(f.subscription, f.subscription.binding.metadata.ServerOrigin, string(f.subscription.binding.metadata.CredentialID), string(f.subscription.binding.metadata.IntentID), f.subscription.binding.metadata.Role, reader, func() time.Time { return f.now }, operate, validate)
}
func observationOperation(ctx context.Context, use func(context.Context, endpointMaterial) error) error {
	secret := bytes.Repeat([]byte{3}, 32)
	defer clear(secret)
	return use(ctx, endpointMaterial{secret: secret})
}
func TestDirectReconcileObservationReadFailures(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, method := range []string{"descriptor", "enrollment", "publication"} {
				t.Run(method, func(t *testing.T) {
					for _, kind := range []string{"opaque", "404", "409"} {
						t.Run(kind, func(t *testing.T) {
							f, reader, validate := observationCoreFixture(t, role)
							wire, _ := reader.publication.CanonicalBytes()
							reader.enrollment = publishedEnrollment(reader.enrollment, wire)
							reader.fail = method
							reader.failure = errors.New("untrusted read details")
							if kind == "404" {
								reader.failure = &directhttp.Error{Kind: directhttp.Unavailable, Status: 404, UnknownCommit: true}
							}
							if kind == "409" {
								reader.failure = &directhttp.Error{Kind: directhttp.Conflict, Status: 409, UnknownCommit: true}
							}
							observer := coreObserver(f, reader, validate, observationOperation)
							result, err := observer(t.Context())
							if err == nil {
								t.Fatal("read failure treated as absence")
							}
							assertZeroObservation(t, result)
							want := []string{"descriptor"}
							if method != "descriptor" {
								want = append(want, "enrollment")
							}
							if method == "publication" {
								want = append(want, "publication")
							}
							if !reflect.DeepEqual(reader.calls, want) {
								t.Fatal("read continued after failure")
							}
							if kind == "opaque" && err != errDirectEndpointReconcileObservation {
								t.Fatal("opaque error was not sanitized")
							}
							if kind != "opaque" {
								var wireErr *directhttp.Error
								status := 404
								if kind == "409" {
									status = 409
								}
								if !errors.As(err, &wireErr) || wireErr.Status != status || wireErr.UnknownCommit {
									t.Fatal("read error disposition changed")
								}
							}
						})
					}
				})
			}
		})
	}
}
func TestDirectReconcileObservationMismatch(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"descriptor", "enrollment", "publication descriptor", "publication hash", "expired final"} {
				t.Run(kind, func(t *testing.T) {
					f, reader, validate := observationCoreFixture(t, role)
					wire, _ := reader.publication.CanonicalBytes()
					reader.enrollment = publishedEnrollment(reader.enrollment, wire)
					switch kind {
					case "descriptor":
						reader.descriptor.Limits.MaxInFlight++
					case "enrollment":
						reader.enrollment.DescriptorHash = "mismatch"
					case "publication descriptor":
						reader.publication.Descriptor.Limits.MaxInFlight++
					case "publication hash":
						reader.publication.Enc = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
					case "expired final":
						reader.hook = func(name string) {
							if name == "publication" {
								f.now = f.now.Add(2 * time.Hour)
							}
						}
					}
					result, err := coreObserver(f, reader, validate, observationOperation)(t.Context())
					if err != errDirectEndpointReconcileBinding {
						t.Fatalf("mismatch disposition: %v", err)
					}
					assertZeroObservation(t, result)
					if (kind == "descriptor" || kind == "enrollment") && len(reader.calls) != 2 {
						t.Fatal("invalid binding fetched publication")
					}
				})
			}
		})
	}
}
func TestDirectReconcileObservationAcceptancePrecedence(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"operation", "cancel", "abort", "revoke", "missing callback", "repeated callback", "invalid secret", "panic"} {
				t.Run(kind, func(t *testing.T) {
					f, reader, validate := observationCoreFixture(t, role)
					reader.fail = "descriptor"
					reader.failure = errors.New("read failed")
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					want := errDirectEndpointOperationRejected
					operate := func(ctx context.Context, use func(context.Context, endpointMaterial) error) error {
						if kind == "missing callback" {
							return nil
						}
						if kind == "invalid secret" {
							return use(ctx, endpointMaterial{secret: make([]byte, 31)})
						}
						if kind == "panic" {
							panic("operation failed")
						}
						if err := observationOperation(ctx, use); err != nil {
							return err
						}
						switch kind {
						case "operation":
							return errDirectEndpointOperationUnknown
						case "cancel":
							cancel()
						case "abort":
							done := make(chan struct{})
							close(done)
							f.subscription.binding.proxy = &NativeWorkerProxy{abortDone: done}
						case "revoke":
							f.subscription.Remove()
						case "repeated callback":
							_ = observationOperation(ctx, use)
						}
						return nil
					}
					switch kind {
					case "operation", "panic":
						want = errDirectEndpointOperationUnknown
					case "cancel":
						want = context.Canceled
					case "invalid secret":
						want = errDirectEndpointReconcileObservation
					}
					result, err := coreObserver(f, reader, validate, operate)(ctx)
					if err != want {
						t.Fatalf("acceptance precedence: %v want %v", err, want)
					}
					assertZeroObservation(t, result)
					if (kind == "invalid secret" || kind == "missing callback" || kind == "panic") && len(reader.calls) != 0 {
						t.Fatal("invalid operation reached reader")
					}
					if kind == "repeated callback" && len(reader.calls) != 1 {
						t.Fatal("repeated callback repeated a read")
					}
				})
			}
		})
	}
}
func TestDirectReconcileObservationNoPrivateAndConcurrency(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f, reader, validate := observationCoreFixture(t, role)
			observer := coreObserver(f, reader, validate, observationOperation)
			var reentered bool
			reader.hook = func(name string) {
				if name == "descriptor" {
					result, err := observer(t.Context())
					if err != errDirectEndpointOperationRejected {
						t.Error("reentrant observer accepted")
					}
					assertZeroObservation(t, result)
					reentered = true
				}
			}
			if _, err := observer(t.Context()); err != nil || !reentered {
				t.Fatal("observer requires private key or reentry bypassed gate")
			}
			entered, release := make(chan struct{}), make(chan struct{})
			reader.hook = func(name string) {
				if name == "descriptor" {
					close(entered)
					<-release
				}
			}
			type observationResult struct {
				value directEndpointReconcileObservation
				err   error
			}
			finished := make(chan observationResult, 1)
			go func() { value, err := observer(t.Context()); finished <- observationResult{value, err} }()
			<-entered
			result, err := observer(t.Context())
			if err != errDirectEndpointOperationRejected {
				t.Error("concurrent observer accepted")
			}
			assertZeroObservation(t, result)
			close(release)
			if got := <-finished; got.err != nil {
				t.Fatal(got.err)
			}
		})
	}
}

func TestDirectReconcileObservationRoleLeasePrecedence(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"cancel", "abort", "revoke"} {
				t.Run(kind, func(t *testing.T) {
					var f *reconcileOperationFixture
					var b directEndpointReconcileBinding
					var e directhttp.Enrollment
					if role == "S" {
						f = newReconcileOperationFixture(t, role)
						b, e, _ = reconcileSourceOperationBinding(t, f)
					} else {
						f, b, e = newReconcileObservationTargetFixture(t)
					}
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					reader := observationReader(t, f.s, b, e)
					reader.fail = "descriptor"
					reader.failure = &directhttp.Error{Kind: directhttp.Unavailable, Status: 404}
					reader.hook = func(string) {
						switch kind {
						case "cancel":
							cancel()
						case "abort":
							f.token.proxy.abort()
						case "revoke":
							f.s.Remove()
						}
					}
					var observer directEndpointReconcileObserver
					var err error
					if role == "S" {
						observer, err = newDirectSourceReconcileObserverWithReader(f.d, f.captured, f.s, f.source, reader, time.Now)
					} else {
						observer, err = newDirectTargetReconcileObserverWithReader(f.d, f.captured, f.s, f.target, reader, time.Now)
					}
					if err != nil {
						t.Fatal(err)
					}
					result, err := observer(ctx)
					if err != errDirectEndpointOperationUnknown {
						t.Fatalf("read error displaced operation outcome: %v", err)
					}
					assertZeroObservation(t, result)
					if !reflect.DeepEqual(reader.calls, []string{"descriptor"}) {
						t.Fatal("revoked read continued")
					}
				})
			}
		})
	}
}
