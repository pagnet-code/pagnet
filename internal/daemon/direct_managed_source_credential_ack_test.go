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

func TestSourceCredentialACKGuardWriteAndReplay(t *testing.T) {
	keys, issue, d, token, captured := sourceCredentialAuthorityFixture(t)
	lane := newDirectManagedSourceCredentialPublicationLane()
	ack, err := keys.InstallCredential(issue, "https://example.test", captured.Session, directSourceCredentialScopeOK, d.directManagedSourceCredentialPublicationFence(token, captured, lane))
	if err != nil {
		t.Fatal(err)
	}
	e := &localDirectManagedSourcePrepare{d: d, keys: keys}
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
	evidence, err := keys.CredentialEvidence(issue, "https://example.test", captured.Session, directSourceCredentialScopeOK)
	if err != nil || evidence.State != "installed" || !bytes.Equal(evidence.ACK, ack) {
		t.Fatalf("ACK-only guard changed installed evidence: %v", err)
	}
	// A lost ACK never changes the committed installation and exact replay returns
	// the original result on a new connection lane.
	fresh := newDirectManagedSourceCredentialPublicationLane()
	replay, err := keys.InstallCredential(issue, "https://example.test", captured.Session, directSourceCredentialScopeOK, d.directManagedSourceCredentialPublicationFence(token, captured, fresh))
	if err != nil || !bytes.Equal(replay, ack) {
		t.Fatalf("replay changed ACK: %v", err)
	}
	if err := e.publishCredentialACKWithToken(context.Background(), token, captured.Socket, captured.Connection, captured.Session, "https://example.test", issue, fresh, replay, func() error { return errors.New("disconnected") }); err == nil {
		t.Fatal("lost socket succeeded")
	}
	restart, err := NewDirectManagedSourceKeyStore(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	replay, err = restart.InstallCredential(issue, "https://example.test", captured.Session, directSourceCredentialScopeOK, d.directManagedSourceCredentialPublicationFence(token, captured, fresh))
	if err != nil || !bytes.Equal(replay, ack) {
		t.Fatalf("restart changed ACK: %v", err)
	}
}

func TestSourceCredentialACKRejectsWrongIssueAndACK(t *testing.T) {
	for _, mutation := range []string{"issue", "ack", "revocation", "committed failure"} {
		t.Run(mutation, func(t *testing.T) {
			keys, issue, d, token, captured := sourceCredentialAuthorityFixture(t)
			lane := newDirectManagedSourceCredentialPublicationLane()
			ack, err := keys.InstallCredential(issue, "https://example.test", captured.Session, directSourceCredentialScopeOK, d.directManagedSourceCredentialPublicationFence(token, captured, lane))
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "issue":
				issue.Nonce = "abababababababababababababababababababababababababababababababab"
			case "ack":
				p, err := transport.DecodeDirectManagedSourceCredentialACK(ack)
				if err != nil {
					t.Fatal(err)
				}
				p.HostConfirmation = "abababababababababababababababababababababababababababababababab"
				ack, _ = p.CanonicalBytes()
			case "committed failure":
				ack = directManagedSourceCredentialFailure(issue)
			case "revocation":
				if _, err := d.state.db.Exec(`UPDATE instances SET agent_principal_id='revoked'`); err != nil {
					t.Fatal(err)
				}
			}
			e := &localDirectManagedSourcePrepare{d: d, keys: keys}
			wrote := false
			err = e.publishCredentialACKWithToken(context.Background(), token, captured.Socket, captured.Connection, captured.Session, "https://example.test", issue, lane, ack, func() error { wrote = true; return nil })
			if err == nil || wrote {
				t.Fatal("invalid authority reached socket")
			}
		})
	}
}

func directManagedSourceCredentialFailure(request transport.DirectManagedSourceCredentialIssue) []byte {
	raw, _ := (transport.DirectManagedSourceCredentialFailureACK{ProtocolVersion: transport.DirectManagedSourceCredentialProtocol, CredentialID: request.CredentialID, Error: transport.DirectManagedSourceCredentialInstallFailure}).CanonicalBytes()
	return raw
}
