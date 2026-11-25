//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func sourcePrepareVerifierFixtureV2(t *testing.T) (*managedPrepareVerifierFixture, transport.DirectManagedSourcePrepareCommandV2) {
	t.Helper()
	f := newManagedPrepareVerifierFixture(t)
	_, _, c, _ := directSourceStoreFixtureV2(t)
	raw, _ := json.Marshal(nativeManagedSubjectFromEndpoint(f.command.Subject))
	if err := json.Unmarshal(raw, &c.Subject); err != nil {
		t.Fatal(err)
	}
	c.Subject.ProtocolVersion = transport.DirectManagedSourceBindingProtocolV2
	c.Subject.SourcePrincipalID = c.Subject.PrincipalID
	c.Subject.CreatedAt = time.Now().UTC().Add(-time.Second)
	c.Subject.EnrollmentExpiresAt = c.Subject.CreatedAt.Add(5 * time.Minute)
	c.Subject.AuthorizationExpiresAt = c.Subject.CreatedAt.Add(time.Hour)
	return f, c
}

func TestDirectSourcePrepareV2NativeProjection(t *testing.T) {
	for _, reason := range []string{"valid", "principal", "origin", "ownership", "server", "credential", "admission", "runner", "future", "expired", "native_session", "native_generation"} {
		t.Run(reason, func(t *testing.T) {
			f, c := sourcePrepareVerifierFixtureV2(t)
			server := "https://example.test"
			switch reason {
			case "principal":
				c.Subject.PrincipalID = domain.NewID()
				c.Subject.SourcePrincipalID = c.Subject.PrincipalID
			case "origin":
				c.Subject.OriginID = domain.NewID()
			case "ownership":
				c.Subject.OwnershipID = domain.NewID()
			case "server":
				server = "https://untrusted.test"
			case "credential":
				c.Subject.HostCredentialID = domain.NewID()
			case "admission":
				c.Subject.NativeAdmissionID = domain.NewID()
				c.Subject.ConnectionIncarnationID = c.Subject.NativeAdmissionID
			case "runner":
				c.Subject.RunnerConnectedAt = c.Subject.RunnerConnectedAt.Add(time.Second)
			case "future":
				c.Subject.CreatedAt = time.Now().Add(time.Second)
				c.Subject.EnrollmentExpiresAt = c.Subject.CreatedAt.Add(time.Minute)
			case "expired":
				c.Subject.CreatedAt = time.Now().Add(-time.Minute)
				c.Subject.EnrollmentExpiresAt = time.Now().Add(-time.Second)
			case "native_session":
				c.Subject.NativeSessionID += "changed"
			case "native_generation":
				c.Subject.NativeGeneration += "changed"
			}
			token, err := f.d.verifyDirectManagedSourcePrepareTokenV2(t.Context(), f.captured, server, c, func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
				return &sessionworker.NativeOwnershipVerifyResult{Snapshot: f.snapshot}, nil
			})
			if reason == "valid" {
				if err != nil || token == nil || !token.subject.ExpiresAt.Equal(c.Subject.EnrollmentExpiresAt) {
					t.Fatal("valid existing worker rejected", err)
				}
			} else if err == nil {
				t.Fatal("mismatch accepted")
			}
		})
	}
}

func TestDirectSourcePrepareV2ExecutorDurableRetry(t *testing.T) {
	for _, crash := range []string{"fresh", "before_start", "after_start", "after_key", "terminal"} {
		t.Run(crash, func(t *testing.T) {
			keys, j, c, session := directSourceStoreFixtureV2(t)
			server := "https://example.test"
			var original []byte
			if crash != "fresh" {
				if _, err := j.Reserve(c, server, session, directSourceScopeOKV2); err != nil {
					t.Fatal(err)
				}
			}
			if crash == "after_start" || crash == "after_key" || crash == "terminal" {
				grant, err := j.BeginKeyReservation(c, server, session, directSourceScopeOKV2)
				if err != nil {
					t.Fatal(err)
				}
				if crash != "after_start" {
					reservation, err := keys.Reserve(c, server, session, directSourceScopeOKV2, grant.keyCreationGrant)
					if err != nil {
						t.Fatal(err)
					}
					original, err = (transport.DirectManagedSourcePrepareACKV2{ProtocolVersion: transport.DirectManagedSourcePrepareProtocolV2, CommandID: c.CommandID, Reservation: reservation}).CanonicalBytes()
					if err != nil {
						t.Fatal(err)
					}
					if crash == "terminal" {
						if _, err := j.Succeed(c, server, session, directSourceScopeOKV2, original); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			e := &localDirectManagedSourcePrepareV2{keys: keys, journal: j}
			ack, err := e.execute(session, server, c, directSourceScopeOKV2)
			if err != nil {
				t.Fatal(err)
			}
			if crash == "after_start" {
				if _, err := transport.DecodeDirectManagedSourcePrepareFailureACKV2(ack, c.CommandID); err != nil {
					t.Fatal(err)
				}
			} else if _, err := transport.DecodeDirectManagedSourcePrepareACKV2(ack, c); err != nil {
				t.Fatal(err)
			}
			if original != nil && !bytes.Equal(original, ack) {
				t.Fatal("retained evidence changed")
			}
			retry, err := e.execute(session, server, c, directSourceScopeOKV2)
			if err != nil || !bytes.Equal(ack, retry) {
				t.Fatal("retry changed evidence", err)
			}
			changed := c
			changed.Subject.NativeSessionID += "changed"
			if _, err := e.execute(session, server, changed, directSourceScopeOKV2); err == nil {
				t.Fatal("changed transcript accepted")
			}
			changed = c
			changed.CommandID = domain.NewID()
			if _, err := e.execute(session, server, changed, directSourceScopeOKV2); err == nil {
				t.Fatal("changed command ID accepted")
			}
			j.now = func() time.Time { return c.Subject.EnrollmentExpiresAt }
			if _, err := e.execute(session, server, c, directSourceScopeOKV2); err == nil {
				t.Fatal("expired replay accepted")
			}
		})
	}
}

func TestDirectSourcePrepareV2MissingCustody(t *testing.T) {
	f, _ := sourcePrepareVerifierFixtureV2(t)
	lock, err := os.CreateTemp(t.TempDir(), "serve-lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	f.d.serveLockFile = lock
	e, err := newLocalDirectManagedSourcePrepareV2(f.d)
	if err != nil || !e.ready() {
		t.Fatal("readiness", err)
	}
	e.keys = nil
	if e.ready() {
		t.Fatal("missing custody considered ready")
	}
	if f.d.directManagedSourcePrepareReadyV2() {
		t.Fatal("constructor installed live executor")
	}
}
