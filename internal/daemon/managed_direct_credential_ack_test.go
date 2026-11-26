//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func TestManagedCredentialACKGuardWriteAndReplayV2(t *testing.T) {
	keys, issue, d, token, captured := managedCredentialAuthorityFixture(t)
	lane := newDirectManagedSourceCredentialPublicationLane()
	ack, err := keys.InstallCredential(issue, "https://example.test", captured.Session, managedCredentialScopeOK, d.managedDirectCredentialPublicationFence(token, captured, lane))
	if err != nil {
		t.Fatal(err)
	}
	e := &localManagedDirectCredential{&localManagedEndpointPrepare{d: d, keys: keys}}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		d.writeMu.Lock()
		defer d.writeMu.Unlock()
		finished <- e.publishCredentialACKWithToken(context.Background(), token, captured.Socket, captured.Connection, captured.Session, "https://example.test", issue, lane, ack, func() error { close(entered); <-release; return nil })
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("write did not start")
	}
	revoked := make(chan error, 1)
	go func() { _, err := d.state.db.Exec(`UPDATE instances SET agent_principal_id='revoked'`); revoked <- err }()
	select {
	case err := <-revoked:
		t.Fatalf("revocation completed during guarded write: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	canceled := make(chan struct{})
	go func() { lane.cancel(); close(canceled) }()
	select {
	case <-canceled:
		t.Fatal("cancel completed during guarded write")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("cancel did not finish")
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	if _, err := d.state.db.Exec(`UPDATE instances SET agent_principal_id=?`, issue.PoP.Prepare.Subject.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	evidence, err := keys.CredentialEvidence(issue, "https://example.test", captured.Session, managedCredentialScopeOK)
	if err != nil || evidence.State != "installed" || !bytes.Equal(evidence.ACK, ack) {
		t.Fatalf("ACK-only guard changed installed evidence: %v", err)
	}
	// A lost ACK never changes the committed installation and exact replay returns
	// the original result on a new connection lane.
	fresh := newDirectManagedSourceCredentialPublicationLane()
	replay, err := keys.InstallCredential(issue, "https://example.test", captured.Session, managedCredentialScopeOK, d.managedDirectCredentialPublicationFence(token, captured, fresh))
	if err != nil || !bytes.Equal(replay, ack) {
		t.Fatalf("replay changed ACK: %v", err)
	}
	if err := e.publishCredentialACKWithToken(context.Background(), token, captured.Socket, captured.Connection, captured.Session, "https://example.test", issue, fresh, replay, func() error { return errors.New("disconnected") }); err == nil {
		t.Fatal("lost socket succeeded")
	}
	restart, err := NewManagedEndpointKeyStore(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	replay, err = restart.InstallCredential(issue, "https://example.test", captured.Session, managedCredentialScopeOK, d.managedDirectCredentialPublicationFence(token, captured, fresh))
	if err != nil || !bytes.Equal(replay, ack) {
		t.Fatalf("restart changed ACK: %v", err)
	}
}

func TestManagedCredentialACKRejectsWrongIssueAndACKV2(t *testing.T) {
	for _, mutation := range []string{"issue", "ack", "revocation", "committed failure", "deadline", "cancel", "registry contention"} {
		t.Run(mutation, func(t *testing.T) {
			keys, issue, d, token, captured := managedCredentialAuthorityFixture(t)
			lane := newDirectManagedSourceCredentialPublicationLane()
			ack, err := keys.InstallCredential(issue, "https://example.test", captured.Session, managedCredentialScopeOK, d.managedDirectCredentialPublicationFence(token, captured, lane))
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "issue":
				issue.Nonce = "abababababababababababababababababababababababababababababababab"
			case "ack":
				p, err := transport.DecodeManagedDirectCredentialACK(ack)
				if err != nil {
					t.Fatal(err)
				}
				p.HostConfirmation = "abababababababababababababababababababababababababababababababab"
				ack, _ = p.CanonicalBytes()
			case "committed failure":
				ack = []byte(`{"error":"retryable"}`)
			case "deadline":
				keys.now = func() time.Time { return issue.InstallExpiresAt }
			case "cancel":
				lane.cancel()
			case "registry contention":
				keys.registry.mu.Lock()
				defer keys.registry.mu.Unlock()
			case "revocation":
				if _, err := d.state.db.Exec(`UPDATE instances SET agent_principal_id='revoked'`); err != nil {
					t.Fatal(err)
				}
			}
			e := &localManagedDirectCredential{&localManagedEndpointPrepare{d: d, keys: keys}}
			wrote := false
			err = e.publishCredentialACKWithToken(context.Background(), token, captured.Socket, captured.Connection, captured.Session, "https://example.test", issue, lane, ack, func() error { wrote = true; return nil })
			if err == nil || wrote {
				t.Fatal("invalid authority reached socket")
			}
		})
	}
}
