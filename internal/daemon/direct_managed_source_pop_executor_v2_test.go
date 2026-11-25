//go:build linux || darwin

package daemon

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func refreshSourcePoPEvidenceV2(t *testing.T, p *transport.DirectManagedSourcePoPChallengeV2) {
	t.Helper()
	p.ACK.CommandID = p.Prepare.CommandID
	p.ACK.Reservation.Subject = p.Prepare.Subject
	var err error
	p.ACK.Reservation.EnrollmentDigest, err = p.ACK.Reservation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	p.Receipt, err = transport.NewDirectManagedSourcePrepareReceiptReferenceV2(p.ACK)
	if err != nil {
		t.Fatal(err)
	}
	p.SourceBindingDigest, err = p.Prepare.Subject.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.CanonicalBytes(); err != nil {
		t.Fatal(err)
	}
}

func TestDirectSourcePoPV2NativeProjection(t *testing.T) {
	for _, reason := range []string{"valid", "principal", "origin", "ownership", "server", "credential", "admission", "runner", "boot", "native_session", "native_generation", "future", "expired", "ipc"} {
		t.Run(reason, func(t *testing.T) {
			f, c := sourcePrepareVerifierFixtureV2(t)
			_, p, _, private := directSourcePoPFixtureV2(t)
			clear(private)
			p.Prepare = c
			server := "https://example.test"
			switch reason {
			case "principal":
				p.Prepare.Subject.PrincipalID = domain.NewID()
				p.Prepare.Subject.SourcePrincipalID = p.Prepare.Subject.PrincipalID
			case "origin":
				p.Prepare.Subject.OriginID = domain.NewID()
			case "ownership":
				p.Prepare.Subject.OwnershipID = domain.NewID()
			case "server":
				server = "https://untrusted.test"
			case "credential":
				p.Prepare.Subject.HostCredentialID = domain.NewID()
			case "admission":
				p.Prepare.Subject.NativeAdmissionID = domain.NewID()
				p.Prepare.Subject.ConnectionIncarnationID = p.Prepare.Subject.NativeAdmissionID
			case "runner":
				p.Prepare.Subject.RunnerConnectedAt = p.Prepare.Subject.RunnerConnectedAt.Add(time.Second)
			case "boot":
				p.Prepare.Subject.BootID += "changed"
			case "native_session":
				p.Prepare.Subject.NativeSessionID += "changed"
			case "native_generation":
				p.Prepare.Subject.NativeGeneration += "changed"
			case "future":
				p.IssuedAt = time.Now().Add(time.Second)
				p.ExpiresAt = p.IssuedAt.Add(time.Minute)
			case "expired":
				p.IssuedAt = c.Subject.CreatedAt
				p.ExpiresAt = time.Now().Add(-time.Millisecond)
			}
			refreshSourcePoPEvidenceV2(t, &p)
			token, err := f.d.verifyDirectManagedSourcePoPTokenV2(t.Context(), f.captured, server, p, func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
				if reason == "ipc" {
					return nil, context.Canceled
				}
				return &sessionworker.NativeOwnershipVerifyResult{Snapshot: f.snapshot}, nil
			})
			if reason == "valid" {
				if err != nil || token == nil {
					t.Fatal("valid existing native worker rejected", err)
				}
			} else if err == nil {
				t.Fatal("mismatched PoP authority accepted")
			}
		})
	}
}

func TestDirectSourcePoPV2DormantExecutorRejectsLostAuthority(t *testing.T) {
	f, _ := sourcePrepareVerifierFixtureV2(t)
	lock, err := os.CreateTemp(t.TempDir(), "serve-lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	f.d.serveLockFile = lock
	e, err := newLocalDirectManagedSourcePoPV2(f.d)
	if err != nil || !e.ready() {
		t.Fatal("readiness", err)
	}
	if f.d.directManagedSourcePoPReadyV2() || f.d.directManagedSourcePoPV2 != nil {
		t.Fatal("constructor activated live executor")
	}
	_, p, _, private := directSourcePoPFixtureV2(t)
	clear(private)
	// Another installation's perfectly canonical evidence cannot reach native IPC.
	if _, err := e.verifyPoPPublication(t.Context(), f.captured.Socket, f.captured.Connection, f.captured.Session, "https://example.test", p); err == nil {
		t.Fatal("foreign installation accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.confirmPoP(ctx, f.captured.Socket, f.captured.Connection, f.captured.Session, "https://example.test", p); err == nil {
		t.Fatal("canceled proof attempt accepted")
	}
	var count int
	if err := f.d.nativeRegistry.db.QueryRow(`SELECT COUNT(*) FROM native_direct_managed_source_v2_pop_challenges`).Scan(&count); err != nil || count != 0 {
		t.Fatal("canceled attempt persisted evidence", err)
	}
	e.keys = nil
	if e.ready() {
		t.Fatal("missing custody accepted")
	}
}
