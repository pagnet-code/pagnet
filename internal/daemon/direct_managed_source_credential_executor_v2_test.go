//go:build linux || darwin

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectSourceCredentialV2NativeProjection(t *testing.T) {
	for _, reason := range []string{"valid", "historical-pop", "principal", "origin", "ownership", "server", "credential", "admission", "runner", "boot", "native_session", "native_generation", "future", "expired", "ipc"} {
		t.Run(reason, func(t *testing.T) {
			f, command := sourcePrepareVerifierFixtureV2(t)
			_, issue, _ := directSourceCredentialFixtureV2(t)
			issue.PoP.Prepare = command
			issue.PoP.IssuedAt = command.Subject.CreatedAt
			issue.PoP.ExpiresAt = command.Subject.CreatedAt.Add(time.Minute)
			issue.IssuedAt = command.Subject.CreatedAt.Add(time.Millisecond)
			issue.InstallExpiresAt = command.Subject.EnrollmentExpiresAt
			issue.CredentialExpiresAt = command.Subject.AuthorizationExpiresAt
			issue.BudgetExpiresAt = command.Subject.AuthorizationExpiresAt
			server := "https://example.test"
			s := &issue.PoP.Prepare.Subject
			switch reason {
			case "historical-pop":
				issue.PoP.ExpiresAt = command.Subject.CreatedAt.Add(500 * time.Millisecond)
			case "principal":
				s.PrincipalID = domain.NewID()
				s.SourcePrincipalID = s.PrincipalID
			case "origin":
				s.OriginID = domain.NewID()
			case "ownership":
				s.OwnershipID = domain.NewID()
			case "server":
				server = "https://untrusted.test"
			case "credential":
				s.HostCredentialID = domain.NewID()
			case "admission":
				s.NativeAdmissionID = domain.NewID()
				s.ConnectionIncarnationID = s.NativeAdmissionID
			case "runner":
				s.RunnerConnectedAt = s.RunnerConnectedAt.Add(time.Second)
			case "boot":
				s.BootID += "changed"
			case "native_session":
				s.NativeSessionID += "changed"
			case "native_generation":
				s.NativeGeneration += "changed"
			case "future":
				issue.IssuedAt = time.Now().Add(time.Second)
			case "expired":
				issue.InstallExpiresAt = time.Now().Add(-time.Millisecond)
			}
			refreshSourcePoPEvidenceV2(t, &issue.PoP)
			canonical, _ := issue.PoP.CanonicalBytes()
			digest := sha256.Sum256(append([]byte("pagnet/direct-managed-source-host-custody-pop/transcript/v2/"), canonical...))
			issue.PoPReceipt.TranscriptHash = hex.EncodeToString(digest[:])
			token, err := f.d.verifyDirectManagedSourceCredentialTokenV2(t.Context(), f.captured, server, issue, func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
				if reason == "ipc" {
					return nil, context.Canceled
				}
				return &sessionworker.NativeOwnershipVerifyResult{Snapshot: f.snapshot}, nil
			})
			if reason == "valid" || reason == "historical-pop" {
				if err != nil || token == nil {
					t.Fatal("existing worker rejected", err)
				}
			} else if err == nil {
				t.Fatal("mismatched credential authority accepted")
			}
		})
	}
}

func TestSourceCredentialACKCustodyAndSupersessionV2(t *testing.T) {
	for _, reason := range []string{"missing", "corrupt", "socket", "cancel", "expired"} {
		t.Run(reason, func(t *testing.T) {
			keys, issue, d, token, captured := sourceCredentialAuthorityFixtureV2(t)
			lane := newDirectManagedSourceCredentialPublicationLane()
			ack, err := keys.InstallCredential(issue, "https://example.test", captured.Session, directSourceCredentialScopeOKV2, d.directManagedSourceCredentialPublicationFenceV2(token, captured, lane))
			if err != nil {
				t.Fatal(err)
			}
			switch reason {
			case "missing":
				err = os.Remove(directSourceCredentialPathV2(keys, issue))
			case "corrupt":
				err = os.WriteFile(directSourceCredentialPathV2(keys, issue), []byte("damaged"), 0600)
			case "socket":
				d.curConn = &websocket.Conn{}
			case "cancel":
				lane.cancel()
			case "expired":
				keys.now = func() time.Time { return issue.InstallExpiresAt }
			}
			if err != nil {
				t.Fatal(err)
			}
			e := &localDirectManagedSourceCredentialV2{&localDirectManagedSourcePoPV2{&localDirectManagedSourcePrepareV2{d: d, keys: keys}}}
			wrote := false
			err = e.publishCredentialACKWithToken(t.Context(), token, captured.Socket, captured.Connection, captured.Session, "https://example.test", issue, lane, ack, func() error { wrote = true; return nil })
			if err == nil || wrote {
				t.Fatal("invalid installed custody reached socket")
			}
		})
	}
}

func TestDirectSourceCredentialV2DormantExecutor(t *testing.T) {
	keys, issue, d, _, captured := sourceCredentialAuthorityFixtureV2(t)
	lock, err := os.CreateTemp(t.TempDir(), "serve-lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	d.serveLockFile = lock
	e, err := newLocalDirectManagedSourceCredentialV2(d)
	if err != nil || !e.ready() {
		t.Fatal("readiness", err)
	}
	if d.directManagedSourceCredentialV2 != nil || d.directManagedSourceCredentialReadyV2() {
		t.Fatal("constructor activated live executor")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.installCredential(ctx, captured.Socket, captured.Connection, captured.Session, "https://example.test", issue, newDirectManagedSourceCredentialPublicationLane()); err == nil {
		t.Fatal("canceled installation accepted")
	}
	var count int
	if err := keys.registry.db.QueryRow(`SELECT COUNT(*) FROM native_direct_managed_source_v2_credentials`).Scan(&count); err != nil || count != 0 {
		t.Fatal("canceled installation persisted attempt", err)
	}
	if _, err := e.verifyCredentialPublication(t.Context(), captured.Socket, captured.Connection, captured.Session, "https://untrusted.test", issue); err == nil {
		t.Fatal("issue URL substituted for trusted connection origin")
	}
	e.keys = nil
	if e.ready() {
		t.Fatal("missing custody accepted")
	}
}
