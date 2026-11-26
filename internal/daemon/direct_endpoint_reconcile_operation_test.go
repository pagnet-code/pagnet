//go:build linux || darwin

package daemon

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/directchannelcrypto"
	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

type reconcileOperationFixture struct {
	d        *Daemon
	s        *DirectEndpointSubscription
	token    *nativeWorkerPublicationToken
	captured ManagedEndpointPrepareScope
	source   transport.DirectManagedSourceCredentialIssueV2
	target   transport.ManagedDirectCredentialIssue
	role     string
}

func newReconcileOperationFixture(t *testing.T, role string) *reconcileOperationFixture {
	t.Helper()
	f := &reconcileOperationFixture{role: role}
	if role == "S" {
		source := newDirectEndpointOperationFixture(t, 0)
		metadata := source.s.binding.metadata
		source.token.endpointEpoch = source.token.proxy.observeDirectEndpointSnapshot(reconcileOperationSnapshot(t, source.token), source.token.proxy.directEndpointObservationEpoch())
		admitted, err := source.d.admitDirectEndpoint(context.Background(), source.captured, metadata, source.raw, source.subject, directManagedSourceCredentialProtocolV2, source.issue.IssuedAt, source.custody, source.verify)
		if err != nil {
			t.Fatal(err)
		}
		f.d, f.s, f.token, f.captured, f.source = source.d, admitted, source.token, source.captured, source.issue
	} else {
		keys, issue, d, token, captured := managedCredentialAuthorityFixture(t)

		if _, err := keys.InstallCredential(issue, d.ServerURL, captured.Session, managedCredentialScopeOK, managedCredentialFenceOK); err != nil {
			t.Fatal(err)
		}
		subject := nativeManagedSubjectFromEndpoint(issue.PoP.Prepare.Subject)
		subject.ExpiresAt = issue.PoP.Authorization.ExpiresAt
		token.subject = subject
		token.endpointEpoch = token.proxy.observeDirectEndpointSnapshot(reconcileOperationSnapshot(t, token), token.proxy.directEndpointObservationEpoch())
		metadata := DirectEndpointSubscriptionMetadata{InstallationID: keys.installation, OriginID: subject.OriginID, IntentID: issue.PoP.Prepare.Subject.DirectIntentID, CredentialID: issue.CredentialID, Role: "P", ServerOrigin: d.ServerURL, OwnershipGeneration: subject.OwnershipGeneration, Deadline: directEndpointDeadline(issue.CredentialExpiresAt, issue.Budget.ExpiresAt, subject.ExpiresAt)}
		raw, err := issue.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		scope := endpointMaterialScope{metadata.InstallationID, metadata.CredentialID, "P", endpointMaterialLiveUse}
		s, err := d.admitDirectEndpoint(context.Background(), captured, metadata, raw, subject, managedDirectCredentialProtocolV1, issue.IssuedAt, func(verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
			return keys.withManagedTargetEndpointMaterial(issue, d.ServerURL, captured.Session, scope, func(transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) error {
				return verify()
			}, fence, use)
		}, func(context.Context, ManagedEndpointPrepareScope, string, nativeManagedSubject) (*nativeWorkerPublicationToken, error) {
			return token, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(d.directSubscriptions.close)
		f.d, f.s, f.token, f.captured, f.target = d, s, token, captured, issue
	}
	p := f.token.proxy
	snapshot := reconcileOperationSnapshot(t, f.token)
	p.controller = endpointRPCController(t, p.scope, p.connection, func(server net.Conn, _ *NativeObservationConnection) {
		for endpointRPCRequest(t, server) {
			if swWriteFrame(server, sessionworker.Response{OwnershipVerify: &sessionworker.NativeOwnershipVerifyResult{Snapshot: snapshot}}) != nil {
				return
			}
		}
	})
	return f
}
func reconcileOperationSnapshot(t *testing.T, token *nativeWorkerPublicationToken) sessionworker.NativeSnapshot {
	t.Helper()
	snapshot := subscriptionNativeSnapshot(token)
	snapshot.PID = os.Getpid()
	var err error
	snapshot.NativeStartIdentity, err = proc.StartIdentity(snapshot.PID)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func (f *reconcileOperationFixture) factory() (directEndpointMaterialOperation, error) {
	if f.role == "S" {
		return newDirectSourceReconcileOperation(f.d, f.captured, f.s, f.source)
	}
	return newDirectTargetReconcileOperation(f.d, f.captured, f.s, f.target)
}

func TestDirectReconcileOperationRejectsSubstitution(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"issue", "subscription", "installation", "socket", "connection", "session", "role", "nil daemon", "nil subscription"} {
				t.Run(kind, func(t *testing.T) {
					f := newReconcileOperationFixture(t, role)
					switch kind {
					case "issue":
						if role == "S" {
							f.source.CredentialID = domain.NewID()
						} else {
							f.target.CredentialID = domain.NewID()
						}
					case "subscription":
						f.s = &DirectEndpointSubscription{}
					case "installation":
						f.s.binding.metadata.InstallationID = domain.NewID()
					case "socket":
						f.captured.Socket = &websocket.Conn{}
					case "connection":
						f.captured.Connection = &NativeObservationConnection{}
					case "session":
						f.captured.Session.BootID = "substituted"
					case "role":
						if role == "S" {
							f.s.binding.metadata.Role = "P"
						} else {
							f.s.binding.metadata.Role = "S"
						}
					case "nil daemon":
						f.d = nil
					case "nil subscription":
						f.s = nil
					}
					operation, err := f.factory()
					if err != errDirectEndpointOperationRejected || operation != nil {
						t.Fatal("substituted authority admitted")
					}
				})
			}
		})
	}
}

func TestDirectReconcileOperationOwnsAuthority(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newReconcileOperationFixture(t, role)
			operation, err := f.factory()
			if err != nil {
				t.Fatal(err)
			}
			f.captured.Session.ProtocolFeatures[0] = "caller mutation"
			if role == "P" {
				f.target.PoP.Authorization.Permissions[0] = "caller issue mutation"
			}
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			if operation(cancelled, func(context.Context, endpointMaterial) error { t.Error("cancelled attempt dispatched"); return nil }) != errDirectEndpointOperationRejected {
				t.Fatal("cancelled invocation accepted")
			}
			f.source = transport.DirectManagedSourceCredentialIssueV2{}
			f.target = transport.ManagedDirectCredentialIssue{}
			for attempt := 0; attempt < 2; attempt++ {
				called := 0
				var private []byte
				err = operation(context.Background(), func(_ context.Context, m endpointMaterial) error {
					called++
					private = m.private
					if len(private) != 32 {
						t.Error("invalid custody")
					}
					return nil
				})
				if err != nil || called != 1 {
					t.Fatalf("owned attempt %d: %v calls=%d", attempt, err, called)
				}
				enrollmentCleanupZero(t, "operation custody", private)
			}
		})
	}
}

func TestDirectReconcileOperationExactSubscription(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newReconcileOperationFixture(t, role)
			operation, err := f.factory()
			if err != nil {
				t.Fatal(err)
			}
			binding := f.s.binding
			f.s.Remove()
			replacement := f.s.owner.add(binding)
			if replacement == nil || replacement == f.s {
				t.Fatal("replacement not installed")
			}
			err = operation(context.Background(), func(context.Context, endpointMaterial) error { t.Error("adapter selected replacement"); return nil })
			if err != errDirectEndpointOperationRejected {
				t.Fatalf("replaced subscription accepted: %v", err)
			}
		})
	}
}

func TestDirectReconcileOperationDispatch(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"cancel", "abort", "panic", "concurrent", "reentrant", "nil callback", "nil context"} {
				t.Run(kind, func(t *testing.T) {
					f := newReconcileOperationFixture(t, role)
					operation, err := f.factory()
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if kind == "nil callback" {
						if operation(ctx, nil) != errDirectEndpointOperationRejected {
							t.Fatal("nil callback accepted")
						}
						return
					}
					if kind == "nil context" {
						if operation(nil, func(context.Context, endpointMaterial) error { return nil }) != errDirectEndpointOperationRejected {
							t.Fatal("nil context accepted")
						}
						return
					}
					called := 0
					var secret, private []byte
					err = operation(ctx, func(_ context.Context, material endpointMaterial) error {
						secret, private = material.secret, material.private
						called++
						switch kind {
						case "cancel":
							cancel()
						case "abort":
							f.token.proxy.abort()
						case "panic":
							panic("callback failed")
						case "reentrant":
							if operation(ctx, func(context.Context, endpointMaterial) error { t.Error("reentrant callback"); return nil }) != errDirectEndpointOperationRejected {
								t.Error("reentrant invocation accepted")
							}
						case "concurrent":
							var wg sync.WaitGroup
							wg.Add(1)
							go func() {
								defer wg.Done()
								if operation(ctx, func(context.Context, endpointMaterial) error { t.Error("concurrent callback"); return nil }) != errDirectEndpointOperationRejected {
									t.Error("concurrent invocation accepted")
								}
							}()
							wg.Wait()
						}
						return nil
					})
					want := error(nil)
					if kind == "cancel" || kind == "abort" || kind == "panic" {
						want = errDirectEndpointOperationUnknown
					}
					if err != want || called != 1 {
						t.Fatalf("dispatch result %v calls=%d", err, called)
					}
					if kind == "panic" {
						enrollmentCleanupZero(t, "panic credential custody", secret)
						enrollmentCleanupZero(t, "panic private custody", private)
						retried := 0
						err = operation(context.Background(), func(context.Context, endpointMaterial) error { retried++; return nil })
						if err != nil || retried != 1 {
							t.Fatalf("panic retained operation gate: %v calls=%d", err, retried)
						}
					}
				})
			}
		})
	}
}

func reconcileSourceOperationBinding(t *testing.T, f *reconcileOperationFixture) (directEndpointReconcileBinding, directhttp.Enrollment, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../directchannelcrypto/testdata/sdk-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct{ Descriptor, PeerPrivate []byte }
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("vector")
	}
	t.Cleanup(func() { clear(vector.PeerPrivate) })
	d, err := transport.DecodeDirectChannelDescriptorV2(vector.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	issue := f.source
	subject := issue.PoP.Prepare.Subject
	d.ParentGrantID, d.GrantGeneration, d.NetworkID = string(subject.GrantID), jsonDecimal(subject.GrantGeneration), string(subject.NetworkID)
	d.S.TenantID, d.S.PrincipalID, d.S.EndpointID, d.S.CredentialID = string(subject.TenantID), string(subject.PrincipalID), string(subject.EndpointID), string(issue.CredentialID)
	d.P.PrincipalID = string(subject.TargetPrincipalID)
	d.DirectIntentID, d.ChannelGeneration = string(subject.DirectIntentID), issue.ChannelGeneration
	d.Budget.AgreementID, d.Budget.AcceptedRevision, d.Budget.TermsDigest = string(subject.BudgetID), jsonDecimal(subject.BudgetAcceptedRevision), subject.BudgetTermsDigest
	d.Budget.ExpiresAt = issue.BudgetExpiresAt.UTC().Format(time.RFC3339Nano)
	d.ExpiresAt = issue.CredentialExpiresAt.UTC().Format(time.RFC3339Nano)
	key, _ := hex.DecodeString(issue.PoP.ACK.Reservation.X25519)
	d.S.PublicKey = base64.RawURLEncoding.EncodeToString(key)
	f.s.binding.metadata.TenantID = subject.TenantID
	f.s.binding.metadata.PrincipalID = subject.PrincipalID
	f.s.binding.metadata.EndpointID = subject.EndpointID
	e := reconcileEnrollment(t, d, time.Now())
	b, err := validateDirectSourceReconcileBindingV2(f.s, f.captured, issue, d, e, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return b, e, vector.PeerPrivate
}

func TestDirectReconcileOperationSourceAcquisitionAndRecovery(t *testing.T) {
	f := newReconcileOperationFixture(t, "S")
	b, e, peerPrivate := reconcileSourceOperationBinding(t, f)
	operation, err := f.factory()
	if err != nil {
		t.Fatal(err)
	}
	material, wire, err := acquireDirectSourceReconcileMaterial(context.Background(), f.s, b, e, f.d.nativeRegistry, time.Now, operation)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	peer, err := directchannelcrypto.Accept(wire, b.Descriptor, peerPrivate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Clear()
	if material.Key != peer.Key {
		t.Fatal("source and target roots differ")
	}
	readiness, err := material.ReadinessKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(readiness)
	peerReadiness, err := peer.ReadinessKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(peerReadiness)
	if string(readiness) != string(peerReadiness) {
		t.Fatal("source and target readiness keys differ")
	}
	restored, replay, err := acquireDirectSourceReconcileMaterial(context.Background(), f.s, b, publishedEnrollment(e, wire), f.d.nativeRegistry, time.Now, operation)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Clear()
	if restored.Key != material.Key || string(replay) != string(wire) {
		t.Fatal("retained source recovery changed material")
	}
}
