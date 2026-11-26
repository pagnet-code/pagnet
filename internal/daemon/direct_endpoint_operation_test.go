//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

type directEndpointOperationFixture struct {
	d         *Daemon
	token     *nativeWorkerPublicationToken
	captured  ManagedEndpointPrepareScope
	s         *DirectEndpointSubscription
	issue     transport.DirectManagedSourceCredentialIssueV2
	raw       []byte
	scope     endpointMaterialScope
	custody   directEndpointCustodyUse
	subject   nativeManagedSubject
	verifyErr error
}

func newDirectEndpointOperationFixture(t *testing.T, deadline time.Duration) *directEndpointOperationFixture {
	t.Helper()
	keys, issue, d, token, captured := sourceCredentialAuthorityFixtureV2(t)
	d.ServerURL = "https://example.test"
	// Keep the setup deadline comfortably ahead under the race detector. Tests
	// that need an expired installation use the injected key-store clock below.
	issue.InstallExpiresAt = time.Now().Add(30 * time.Second).UTC()
	if _, err := keys.InstallCredential(issue, d.ServerURL, captured.Session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err != nil {
		t.Fatal(err)
	}
	subject := nativeManagedSubjectFromSourceV2(issue.PoP.Prepare.Subject)
	subject.ExpiresAt = issue.PoP.Prepare.Subject.AuthorizationExpiresAt
	token.subject = subject
	token.endpointEpoch = token.proxy.observeDirectEndpointSnapshot(subscriptionNativeSnapshot(token), token.proxy.directEndpointObservationEpoch())
	metadata := DirectEndpointSubscriptionMetadata{InstallationID: keys.installation, OriginID: subject.OriginID, IntentID: issue.PoP.Prepare.Subject.DirectIntentID, CredentialID: issue.CredentialID, Role: "S", ServerOrigin: d.ServerURL, OwnershipGeneration: subject.OwnershipGeneration, Deadline: directEndpointDeadline(issue.CredentialExpiresAt, issue.BudgetExpiresAt, subject.ExpiresAt)}
	if deadline > 0 {
		metadata.Deadline = time.Now().Add(deadline)
	}
	raw, err := issue.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	f := &directEndpointOperationFixture{d: d, token: token, captured: captured, issue: issue, raw: raw, scope: endpointMaterialScope{metadata.InstallationID, metadata.CredentialID, metadata.Role, endpointMaterialLiveUse}}
	f.subject = subject
	f.custody = func(verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
		return keys.withDirectManagedSourceEndpointMaterialV2(issue, d.ServerURL, captured.Session, endpointMaterialScope{metadata.InstallationID, metadata.CredentialID, metadata.Role, endpointMaterialLiveUse}, func(transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) error {
			return verify()
		}, fence, use)
	}
	f.s, err = d.admitDirectEndpoint(context.Background(), captured, metadata, raw, subject, directManagedSourceCredentialProtocolV2, issue.IssuedAt, f.custody, f.verify)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.directSubscriptions.close)
	keys.now = func() time.Time { return issue.InstallExpiresAt.Add(time.Nanosecond) }
	return f
}

func (f *directEndpointOperationFixture) verify(context.Context, ManagedEndpointPrepareScope, string, nativeManagedSubject) (*nativeWorkerPublicationToken, error) {
	return f.token, f.verifyErr
}

func (f *directEndpointOperationFixture) operate(ctx context.Context, use func(context.Context, endpointMaterial) error) error {
	return f.d.operateDirectEndpoint(ctx, f.captured, f.s, f.raw, f.subject, directManagedSourceCredentialProtocolV2, f.issue.IssuedAt, f.scope, func(opctx context.Context, verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
		keys, err := newDirectManagedSourceKeyStoreV2Context(opctx, f.d.nativeRegistry)
		if err != nil {
			return err
		}
		return keys.withDirectManagedSourceEndpointMaterialV2Context(opctx, f.issue, f.d.ServerURL, f.captured.Session, f.scope, func(transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) error {
			return verify()
		}, fence, use)
	}, f.verify, use)
}

func TestDirectEndpointOperationLifecycleWhileCallbackHeld(t *testing.T) {
	for _, kind := range []string{"gc", "recovery", "worker-replacement", "snapshot-replacement"} {
		t.Run(kind, func(t *testing.T) {
			f := newDirectEndpointOperationFixture(t, 0)
			record, err := f.d.nativeRegistry.Lookup(f.token.instanceID)
			if err != nil {
				t.Fatal(err)
			}
			var write func() error
			if kind == "worker-replacement" {
				write = func() error { f.d.replaceNativeWorkerLink(f.token.instanceID, &nativeWorkerLink{}); return nil }
			} else if kind == "snapshot-replacement" {
				write = func() error {
					snapshot := subscriptionNativeSnapshot(f.token)
					snapshot.NativeGeneration = "replacement"
					f.token.proxy.observeDirectEndpointSnapshot(snapshot, f.token.proxy.directEndpointObservationEpoch())
					return nil
				}
			} else {
				fence := directEndpointRegistryFence(t, f.d, f.token, kind)
				write = func() error { return fence(false) }
			}
			entered := make(chan context.Context, 1)
			release := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			finished := make(chan error, 1)
			go func() {
				finished <- f.operate(context.Background(), func(ctx context.Context, _ endpointMaterial) error {
					entered <- ctx
					<-release
					return nil
				})
			}()
			var opctx context.Context
			select {
			case opctx = <-entered:
			case err := <-finished:
				t.Fatalf("operation did not dispatch: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("operation did not dispatch")
			}
			written := make(chan error, 1)
			go func() {
				scope := record.Scope
				scope.InstanceID = domain.NewID().String()
				scope.Generation = domain.NewID().String()
				if _, err := f.d.nativeRegistry.Reserve(scope, record.Spec, record.Profile, ""); err != nil {
					written <- err
					return
				}
				written <- write()
			}()
			select {
			case err := <-written:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("lifecycle writer blocked on callback")
			}
			select {
			case <-opctx.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("lifecycle writer did not cancel callback context")
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case err := <-finished:
				if err != errDirectEndpointOperationUnknown {
					t.Fatalf("revoked callback outcome: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("operation did not return after callback")
			}
		})
	}
}

func TestDirectEndpointOperationRejectsStaleAndMismatchedScope(t *testing.T) {
	for _, kind := range []string{"removed", "installation", "credential", "role", "use", "issue", "socket", "native", "session", "subject", "canceled", "verifier"} {
		t.Run(kind, func(t *testing.T) {
			f := newDirectEndpointOperationFixture(t, 0)
			ctx := context.Background()
			switch kind {
			case "socket":
				f.captured.Socket = nil
			case "native":
				f.captured.Connection = nil
			case "session":
				f.captured.Session.BootID = "changed"
			case "subject":
				f.subject.NativeGeneration = "changed"
			case "verifier":
				f.verifyErr = errors.New("verifier detail")
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "removed":
				f.s.Remove()
				if replacement := f.d.directSubscriptions.add(f.s.binding); replacement == nil {
					t.Fatal("replacement missing")
				}
			case "installation":
				f.scope.installation = "other-installation"
			case "credential":
				f.scope.credential = "other-credential"
			case "role":
				f.scope.role = "P"
			case "use":
				f.scope.use = "historical"
			case "issue":
				f.raw = append([]byte(nil), f.raw...)
				f.raw[0] ^= 1
			}
			called := false
			err := f.operate(ctx, func(context.Context, endpointMaterial) error { called = true; return nil })
			if err != errDirectEndpointOperationRejected || called {
				t.Fatalf("invalid operation dispatched or wrong error: called=%v err=%v", called, err)
			}
		})
	}
}

func TestDirectEndpointOperationDeadline(t *testing.T) {
	// Leave time for fenced custody under the race detector before expiry.
	f := newDirectEndpointOperationFixture(t, 5*time.Second)
	called := false
	err := f.operate(context.Background(), func(ctx context.Context, _ endpointMaterial) error {
		called = true
		if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(f.s.Metadata().Deadline) {
			t.Error("callback missing live deadline")
		}
		select {
		case <-ctx.Done():
			if time.Now().Before(f.s.Metadata().Deadline) {
				t.Errorf("callback canceled before live deadline: %v", ctx.Err())
			}
		case <-time.After(10 * time.Second):
			t.Error("operation deadline did not cancel callback")
		}
		return nil
	})
	if !called || err != errDirectEndpointOperationUnknown {
		t.Fatalf("deadline disposition: called=%v err=%v", called, err)
	}
}

func TestDirectEndpointOperationExcludesInstallationDeadline(t *testing.T) {
	f := newDirectEndpointOperationFixture(t, 0)
	time.Sleep(time.Until(f.issue.InstallExpiresAt) + 10*time.Millisecond)
	called := false
	if err := f.operate(context.Background(), func(_ context.Context, material endpointMaterial) error {
		called = true
		if len(material.secret) != 32 || len(material.private) != 32 {
			t.Error("invalid material length")
		}
		return nil
	}); err != nil || !called {
		t.Fatalf("live operation used installation deadline: called=%v err=%v", called, err)
	}
}

func TestDirectEndpointOperationSanitizesFailureAndClearsMaterial(t *testing.T) {
	for _, kind := range []string{"panic", "error", "success"} {
		t.Run(kind, func(t *testing.T) {
			f := newDirectEndpointOperationFixture(t, 0)
			var secret, private []byte
			err := f.operate(context.Background(), func(_ context.Context, material endpointMaterial) error {
				secret, private = material.secret, material.private
				if len(secret) != 32 || len(private) != 32 {
					t.Error("invalid material length")
				}
				if kind == "panic" {
					panic("callback detail")
				}
				if kind == "error" {
					return errors.New("callback detail")
				}
				return nil
			})
			if kind == "success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err != errDirectEndpointOperationUnknown {
				t.Fatalf("callback failure was not sanitized: %v", err)
			}
			if len(secret) == 0 || len(private) == 0 || !bytes.Equal(secret, make([]byte, len(secret))) || !bytes.Equal(private, make([]byte, len(private))) {
				t.Fatal("operation retained material after callback")
			}
		})
	}
}

func TestDirectEndpointOperationTargetCustody(t *testing.T) {
	keys, issue, d, token, captured := managedCredentialAuthorityFixture(t)
	issue.InstallExpiresAt = time.Now().Add(500 * time.Millisecond).UTC()
	if _, err := keys.InstallCredential(issue, d.ServerURL, captured.Session, managedCredentialScopeOK, managedCredentialFenceOK); err != nil {
		t.Fatal(err)
	}
	subject := nativeManagedSubjectFromEndpoint(issue.PoP.Prepare.Subject)
	subject.ExpiresAt = issue.PoP.Authorization.ExpiresAt
	token.subject = subject
	token.endpointEpoch = token.proxy.observeDirectEndpointSnapshot(subscriptionNativeSnapshot(token), token.proxy.directEndpointObservationEpoch())
	metadata := DirectEndpointSubscriptionMetadata{InstallationID: keys.installation, OriginID: subject.OriginID, IntentID: issue.PoP.Prepare.Subject.DirectIntentID, CredentialID: issue.CredentialID, Role: "P", ServerOrigin: d.ServerURL, OwnershipGeneration: subject.OwnershipGeneration, Deadline: directEndpointDeadline(issue.CredentialExpiresAt, issue.Budget.ExpiresAt, subject.ExpiresAt)}
	raw, err := issue.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	scope := endpointMaterialScope{metadata.InstallationID, metadata.CredentialID, metadata.Role, endpointMaterialLiveUse}
	custody := directEndpointCustodyUse(func(verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
		return keys.withManagedTargetEndpointMaterial(issue, d.ServerURL, captured.Session, scope, func(transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) error {
			return verify()
		}, fence, use)
	})
	verify := func(context.Context, ManagedEndpointPrepareScope, string, nativeManagedSubject) (*nativeWorkerPublicationToken, error) {
		return token, nil
	}
	s, err := d.admitDirectEndpoint(context.Background(), captured, metadata, raw, subject, managedDirectCredentialProtocolV1, issue.IssuedAt, custody, verify)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.directSubscriptions.close)
	// The production role wrapper must derive its context before opening custody.
	d.nativeRegistry.mu.Lock()
	started := time.Now()
	rejected := d.operateManagedTargetEndpoint(context.Background(), captured, s, issue, func(context.Context, endpointMaterial) error { t.Error("contended target reached use"); return nil })
	d.nativeRegistry.mu.Unlock()
	if rejected != errDirectEndpointOperationRejected || time.Since(started) > time.Second {
		t.Fatal("target role custody waited for registry")
	}
	keys.now = func() time.Time { return issue.InstallExpiresAt.Add(time.Nanosecond) }
	time.Sleep(time.Until(issue.InstallExpiresAt) + 10*time.Millisecond)
	var secret, private []byte
	err = d.operateDirectEndpoint(context.Background(), captured, s, raw, s.binding.subject, managedDirectCredentialProtocolV1, issue.IssuedAt, scope, func(opctx context.Context, verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
		keys, err := newManagedEndpointKeyStoreContext(opctx, d.nativeRegistry)
		if err != nil {
			return err
		}
		return keys.withManagedTargetEndpointMaterialContext(opctx, issue, d.ServerURL, captured.Session, scope, func(transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) error {
			return verify()
		}, fence, use)
	}, verify, func(ctx context.Context, material endpointMaterial) error {
		secret, private = material.secret, material.private
		if len(secret) != 32 || len(private) != 32 {
			t.Error("invalid target material length")
		}
		if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(metadata.Deadline) {
			t.Error("target callback missing live deadline")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) == 0 || len(private) == 0 || !bytes.Equal(secret, make([]byte, len(secret))) || !bytes.Equal(private, make([]byte, len(private))) {
		t.Fatal("target operation retained material")
	}
}

func TestDirectEndpointOperationContextAcquisition(t *testing.T) {
	for _, held := range []string{"registry", "key namespace", "publication", "connection", "owner"} {
		t.Run(held, func(t *testing.T) {
			f := newDirectEndpointOperationFixture(t, 0)
			release := func() {}
			switch held {
			case "registry":
				f.d.nativeRegistry.mu.Lock()
				release = f.d.nativeRegistry.mu.Unlock
			case "key namespace":
				directEndpointHoldChildFlock(t, filepath.Join(f.d.nativeRegistry.root, nativeDirectManagedSourceKeyNamespaceV2, "holder.lock"))
			case "publication":
				f.token.proxy.publicationMu.Lock()
				release = f.token.proxy.publicationMu.Unlock
			case "connection":
				f.d.connMu.Lock()
				release = f.d.connMu.Unlock
			case "owner":
				f.s.owner.mu.Lock()
				release = f.s.owner.mu.Unlock
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			called := false
			start := time.Now()
			use := func(context.Context, endpointMaterial) error { called = true; return nil }
			var err error
			if held == "registry" {
				err = f.d.operateDirectManagedSourceEndpointV2(ctx, f.captured, f.s, f.issue, use)
			} else {
				err = f.operate(ctx, use)
			}
			release()
			if err != errDirectEndpointOperationRejected || called {
				t.Fatalf("held %s operation reached use: %v", held, err)
			}
			if time.Since(start) > time.Second {
				t.Fatal("operation waited for held lock")
			}
		})
	}
}

func TestDirectEndpointOperationContextResponseAcceptance(t *testing.T) {
	for _, kind := range []string{"cancel", "owner held"} {
		t.Run(kind, func(t *testing.T) {
			f := newDirectEndpointOperationFixture(t, 0)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			release := func() {}
			err := f.operate(ctx, func(context.Context, endpointMaterial) error {
				if kind == "cancel" {
					cancel()
				} else {
					f.s.owner.mu.Lock()
					release = f.s.owner.mu.Unlock
				}
				return nil
			})
			release()
			if err != errDirectEndpointOperationUnknown {
				t.Fatalf("unaccepted callback succeeded: %v", err)
			}
		})
	}
}
