//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func subscriptionFixture(t *testing.T) (*Daemon, *nativeWorkerPublicationToken, ManagedEndpointPrepareScope, func(context.Context, func(directEndpointCustodyUse) directEndpointCustodyUse) (*DirectEndpointSubscription, error)) {
	t.Helper()
	keys, issue, d, token, captured := sourceCredentialAuthorityFixtureV2(t)
	d.ServerURL = "https://example.test"
	// This short installation deadline is deliberately independent of live use.
	issue.InstallExpiresAt = time.Now().Add(500 * time.Millisecond).UTC()
	if _, err := keys.InstallCredential(issue, d.ServerURL, captured.Session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err != nil {
		t.Fatal(err)
	}
	if len(d.directSubscriptions.entries) != 0 {
		t.Fatal("installation admitted a subscription")
	}
	subject := nativeManagedSubjectFromSourceV2(issue.PoP.Prepare.Subject)
	subject.ExpiresAt = issue.PoP.Prepare.Subject.AuthorizationExpiresAt
	token.subject = subject
	metadata := DirectEndpointSubscriptionMetadata{InstallationID: keys.installation, OriginID: subject.OriginID, IntentID: issue.PoP.Prepare.Subject.DirectIntentID, CredentialID: issue.CredentialID, Role: "S", ServerOrigin: d.ServerURL, OwnershipGeneration: subject.OwnershipGeneration, Deadline: directEndpointDeadline(issue.CredentialExpiresAt, issue.BudgetExpiresAt, subject.ExpiresAt)}
	raw, err := issue.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	scope := endpointMaterialScope{metadata.InstallationID, metadata.CredentialID, "S", endpointMaterialLiveUse}
	custody := directEndpointCustodyUse(func(verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
		return keys.withDirectManagedSourceEndpointMaterialV2(issue, d.ServerURL, captured.Session, scope, func(transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) error {
			return verify()
		}, fence, use)
	})
	admit := func(ctx context.Context, wrap func(directEndpointCustodyUse) directEndpointCustodyUse) (*DirectEndpointSubscription, error) {
		use := custody
		if wrap != nil {
			use = wrap(use)
		}
		return d.admitDirectEndpoint(ctx, captured, metadata, raw, subject, directManagedSourceCredentialProtocolV2, issue.IssuedAt, use, func(context.Context, ManagedEndpointPrepareScope, string, nativeManagedSubject) (*nativeWorkerPublicationToken, error) {
			return token, nil
		})
	}
	t.Cleanup(d.directSubscriptions.close)
	// Used by the deadline test to move custody beyond its installation window.
	keys.now = func() time.Time { return issue.InstallExpiresAt.Add(time.Nanosecond) }
	return d, token, captured, admit
}

func TestDirectEndpointSubscriptionLifecycle(t *testing.T) {
	for _, kind := range []string{"remove", "proxy-close", "native-close", "worker-replacement", "shutdown"} {
		t.Run(kind, func(t *testing.T) {
			d, token, captured, admit := subscriptionFixture(t)
			s, err := admit(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if !s.Valid() || s.Metadata().Role != "S" {
				t.Fatal("admission missing")
			}
			switch kind {
			case "remove":
				s.Remove()
				s.Remove()
			case "proxy-close":
				if err := token.proxy.Close(); err != nil {
					t.Fatal(err)
				}
			case "native-close":
				captured.Connection.Close()
			case "worker-replacement":
				d.replaceNativeWorkerLink(token.instanceID, &nativeWorkerLink{})
			case "shutdown":
				d.directSubscriptions.close()
			}
			select {
			case <-s.Done():
			default:
				t.Fatal("lifecycle returned before revocation")
			}
			if s.Valid() {
				t.Fatal("revoked generation valid")
			}
		})
	}
}

func TestDirectEndpointSubscriptionCustodyFailure(t *testing.T) {
	for _, kind := range []string{"before-fence", "after-use", "panic", "native-close-after-transaction", "proxy-close-after-transaction", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			d, token, captured, admit := subscriptionFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wrap := func(base directEndpointCustodyUse) directEndpointCustodyUse {
				return func(verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
					if kind == "before-fence" {
						d.nativeWorkers[token.instanceID] = &nativeWorkerLink{}
					}
					err := base(verify, fence, func(m endpointMaterial) error {
						if err := use(m); err != nil {
							return err
						}
						switch kind {
						case "after-use":
							return ErrManagedEndpointPrepareRejected
						case "panic":
							panic("test interruption")
						case "cancel":
							cancel()
						}
						return nil
					})
					switch kind {
					case "native-close-after-transaction":
						captured.Connection.Close()
					case "proxy-close-after-transaction":
						_ = token.proxy.Close()
					}
					return err
				}
			}
			panicked := false
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				s, err := admit(ctx, wrap)
				if err == nil || s != nil {
					t.Fatal("failed custody published a handle")
				}
			}()
			if panicked != (kind == "panic") {
				t.Fatal("unexpected panic disposition")
			}
			d.directSubscriptions.mu.Lock()
			remaining := len(d.directSubscriptions.entries)
			d.directSubscriptions.mu.Unlock()
			if remaining != 0 {
				t.Fatal("failed candidate survived")
			}
		})
	}
}

func TestDirectEndpointSubscriptionLiveDeadline(t *testing.T) {
	d, _, _, admit := subscriptionFixture(t)
	// Let the actual installation deadline pass, not just custody's test clock.
	time.Sleep(550 * time.Millisecond)
	s, err := admit(context.Background(), nil)
	if err != nil {
		t.Fatal("live admission incorrectly used installation deadline", err)
	}
	defer s.Remove()
	if !s.Valid() {
		t.Fatal("live credential invalid")
	}
	d.directSubscriptions.mu.Lock()
	if s.timer == nil {
		t.Fatal("admitted generation has no expiry timer")
	}
	d.directSubscriptions.mu.Unlock()
}

func TestDirectEndpointSubscriptionGenerationAndDeadline(t *testing.T) {
	var owner directEndpointSubscriptions
	binding := directEndpointBinding{metadata: DirectEndpointSubscriptionMetadata{Deadline: time.Now().Add(time.Hour)}}
	old := owner.add(binding)
	if !owner.activate(old) {
		t.Fatal("activate old")
	}
	old.Remove()
	next := owner.add(binding)
	if !owner.activate(next) {
		t.Fatal("activate next")
	}
	defer next.Remove()
	old.Remove()
	if !next.Valid() {
		t.Fatal("old handle revoked replacement generation")
	}
	expiring := owner.add(directEndpointBinding{metadata: DirectEndpointSubscriptionMetadata{Deadline: time.Now().Add(25 * time.Millisecond)}})
	if !owner.activate(expiring) {
		t.Fatal("activate expiry")
	}
	select {
	case <-expiring.Done():
	case <-time.After(time.Second):
		t.Fatal("expiry did not revoke")
	}
	if expiring.Valid() {
		t.Fatal("expired generation valid")
	}
	// Simulate a delayed timer: Valid still checks the strict deadline itself.
	delayed := owner.add(directEndpointBinding{metadata: DirectEndpointSubscriptionMetadata{Deadline: time.Now().Add(25 * time.Millisecond)}})
	if !owner.activate(delayed) {
		t.Fatal("activate delayed")
	}
	owner.mu.Lock()
	delayed.timer.Stop()
	owner.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	if delayed.Valid() {
		t.Fatal("timer delay bypassed deadline")
	}
	owner.close()
	if owner.add(binding) != nil {
		t.Fatal("shutdown allowed readmission")
	}
}

func TestDirectEndpointSubscriptionConcurrentRevoke(t *testing.T) {
	d, token, captured, admit := subscriptionFixture(t)
	s, err := admit(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				s.Valid()
				s.Remove()
			}
		}()
	}
	wg.Add(2)
	go func() { defer wg.Done(); captured.Connection.Close() }()
	go func() { defer wg.Done(); _ = token.proxy.Close() }()
	wg.Wait()
	if s.Valid() {
		t.Fatal("concurrent revoke lost")
	}
	d.directSubscriptions.close()
}

func TestDirectEndpointSubscriptionMissingCustody(t *testing.T) {
	keys, issue, d, token, captured := sourceCredentialAuthorityFixtureV2(t)
	d.ServerURL = "https://example.test"
	token.subject.ExpiresAt = issue.PoP.Prepare.Subject.AuthorizationExpiresAt
	if _, err := keys.InstallCredential(issue, d.ServerURL, captured.Session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(directSourceCredentialPathV2(keys, issue)); err != nil {
		t.Fatal(err)
	}
	// Installed evidence cannot create a subscription when retained material has
	// disappeared. The failure occurs before invoking an authority fence.
	called := false
	err := keys.withDirectManagedSourceEndpointMaterialV2(issue, d.ServerURL, captured.Session, endpointMaterialScope{keys.installation, issue.CredentialID, "S", endpointMaterialLiveUse}, directSourceCredentialScopeOKV2, func(*sql.Conn) (func(), func() error, error) {
		called = true
		return func() {}, func() error { return nil }, nil
	}, func(endpointMaterial) error { t.Fatal("missing custody reached admission"); return nil })
	if err == nil || called {
		t.Fatal("missing custody acquired admission authority")
	}
	if len(d.directSubscriptions.entries) != 0 {
		t.Fatal("missing custody admitted")
	}
}

func TestDirectEndpointSubscriptionWriteFailure(t *testing.T) {
	socket, _ := nativeBindingSocketPair(t)
	var d Daemon
	d.Log = slog.Default()
	d.writeTimeout = time.Second
	d.curConn = socket
	s := d.directSubscriptions.add(directEndpointBinding{socket: socket, metadata: DirectEndpointSubscriptionMetadata{Deadline: time.Now().Add(time.Hour)}})
	if !d.directSubscriptions.activate(s) {
		t.Fatal("activate")
	}
	defer d.directSubscriptions.close()
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.write(socket, []byte("test")); err == nil {
		t.Fatal("closed socket write succeeded")
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("write failure returned before revocation")
	}
	if s.Valid() {
		t.Fatal("failed socket still authorized")
	}
}

func TestDirectEndpointSubscriptionTargetCustody(t *testing.T) {
	keys, issue, d, token, captured := managedCredentialAuthorityFixture(t)
	if _, err := keys.InstallCredential(issue, d.ServerURL, captured.Session, managedCredentialScopeOK, managedCredentialFenceOK); err != nil {
		t.Fatal(err)
	}
	subject := nativeManagedSubjectFromEndpoint(issue.PoP.Prepare.Subject)
	subject.ExpiresAt = issue.PoP.Authorization.ExpiresAt
	token.subject = subject
	metadata := DirectEndpointSubscriptionMetadata{InstallationID: keys.installation, OriginID: subject.OriginID, IntentID: issue.PoP.Prepare.Subject.DirectIntentID, CredentialID: issue.CredentialID, Role: "P", ServerOrigin: d.ServerURL, OwnershipGeneration: subject.OwnershipGeneration, Deadline: directEndpointDeadline(issue.CredentialExpiresAt, issue.Budget.ExpiresAt, subject.ExpiresAt)}
	raw, err := issue.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	s, err := d.admitDirectEndpoint(context.Background(), captured, metadata, raw, subject, managedDirectCredentialProtocolV1, issue.IssuedAt, func(verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
		return keys.withManagedTargetEndpointMaterial(issue, d.ServerURL, captured.Session, endpointMaterialScope{keys.installation, issue.CredentialID, "P", endpointMaterialLiveUse}, func(transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) error {
			return verify()
		}, fence, use)
	}, func(context.Context, ManagedEndpointPrepareScope, string, nativeManagedSubject) (*nativeWorkerPublicationToken, error) {
		return token, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Remove()
	if !s.Valid() || s.Metadata() != metadata {
		t.Fatal("target admission identity changed")
	}
	captured.Connection.Close()
	if s.Valid() {
		t.Fatal("target survived connection close")
	}
}

func TestDirectEndpointSubscriptionAdmissionCloseRace(t *testing.T) {
	for _, kind := range []string{"native", "proxy"} {
		t.Run(kind, func(t *testing.T) {
			d, token, captured, admit := subscriptionFixture(t)
			registered := make(chan struct{})
			release := make(chan struct{})
			type outcome struct {
				s   *DirectEndpointSubscription
				err error
			}
			result := make(chan outcome, 1)
			go func() {
				s, err := admit(context.Background(), func(base directEndpointCustodyUse) directEndpointCustodyUse {
					return func(verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
						return base(verify, fence, func(m endpointMaterial) error {
							if err := use(m); err != nil {
								return err
							}
							close(registered)
							<-release
							return nil
						})
					}
				})
				result <- outcome{s, err}
			}()
			<-registered
			closing := make(chan struct{})
			closed := make(chan struct{})
			go func() {
				close(closing)
				if kind == "native" {
					captured.Connection.Close()
				} else {
					_ = token.proxy.Close()
				}
				close(closed)
			}()
			<-closing
			select {
			case <-closed:
				t.Fatal("close escaped the active authority fence")
			default:
			}
			close(release)
			<-closed
			got := <-result
			if got.err == nil && got.s == nil {
				t.Fatal("successful admission omitted handle")
			}
			if got.s != nil {
				select {
				case <-got.s.Done():
				default:
					t.Fatal("admission escaped synchronous close")
				}
				if got.s.Valid() {
					t.Fatal("closed binding valid")
				}
			}
			d.directSubscriptions.mu.Lock()
			remaining := len(d.directSubscriptions.entries)
			d.directSubscriptions.mu.Unlock()
			if remaining != 0 {
				t.Fatal("close race retained candidate")
			}
		})
	}
}
