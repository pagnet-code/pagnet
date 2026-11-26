//go:build linux || darwin

package daemon

import (
	"context"
	"os"
	"testing"

	"github.com/pagnet-code/pagnet/transport"
)

func TestManagedCredentialDormantExecutorCancellation(t *testing.T) {
	keys, issue, d, _, captured := managedCredentialAuthorityFixture(t)
	lock, err := os.CreateTemp(t.TempDir(), "serve-lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	d.serveLockFile = lock
	e, err := newLocalManagedDirectCredential(d)
	if err != nil || !e.ready() {
		t.Fatal("readiness", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.installCredential(ctx, captured.Socket, captured.Connection, captured.Session, "https://example.test", issue, newDirectManagedSourceCredentialPublicationLane()); err == nil {
		t.Fatal("canceled installation accepted")
	}
	var count int
	if err := keys.registry.db.QueryRow(`SELECT COUNT(*) FROM native_managed_direct_v1_credentials`).Scan(&count); err != nil || count != 0 {
		t.Fatal("canceled operation persisted custody", err)
	}
	raw, _ := issue.CanonicalBytes()
	got, err := e.executeCredential(ctx, captured.Socket, captured.Connection, captured.Session, "https://example.test", "host.managed_direct_credential", raw, newDirectManagedSourceCredentialPublicationLane())
	if _, decodeErr := transport.DecodeManagedDirectCredentialFailureACK(got); err != nil || decodeErr != nil {
		t.Fatal("canceled public ACK", err, decodeErr)
	}
	e.keys = nil
	if e.ready() {
		t.Fatal("missing custody accepted")
	}
}
