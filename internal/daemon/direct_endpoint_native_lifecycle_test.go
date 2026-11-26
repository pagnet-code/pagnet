//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/pagnet-code/pagnet/internal/proc"
	"os"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func subscriptionNativeSnapshot(token *nativeWorkerPublicationToken) sessionworker.NativeSnapshot {
	s := token.subject
	raw, _ := json.Marshal(transport.NativeObservationOrigin{ID: s.OriginID.String(), InstanceID: s.InstanceID.String(), TenantID: s.TenantID.String(), HostID: s.HostID.String(), Runtime: string(token.proxy.bootstrap.Native.Runtime), NativeGeneration: s.NativeGeneration, NativeSessionID: s.NativeSessionID})
	return sessionworker.NativeSnapshot{Scope: token.proxy.scope, ProfileFingerprint: token.proxy.profile, ActualRuntime: token.proxy.bootstrap.Native.Runtime, PID: 1, NativeStartIdentity: "test-start", NativeGeneration: s.NativeGeneration, NativeSessionID: s.NativeSessionID, Origin: raw}
}

func TestDirectEndpointNativeObservationRevokes(t *testing.T) {
	for _, kind := range []string{"inactive", "pending", "generation", "session", "origin", "process", "malformed-origin", "wrong-origin-host"} {
		t.Run(kind, func(t *testing.T) {
			_, token, _, admit := subscriptionFixture(t)
			s, err := admit(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			snapshot := subscriptionNativeSnapshot(token)
			switch kind {
			case "inactive":
				snapshot.PID = 0
			case "pending":
				snapshot.IdentityPending = true
			case "generation":
				snapshot.NativeGeneration = "replacement"
			case "session":
				snapshot.NativeSessionID = "replacement"
			case "origin":
				var o transport.NativeObservationOrigin
				_ = json.Unmarshal(snapshot.Origin, &o)
				o.ID = domain.NewID().String()
				snapshot.Origin, _ = json.Marshal(o)
			case "process":
				snapshot.NativeStartIdentity = "replacement"
			case "malformed-origin":
				snapshot.Origin = []byte("bad")
			case "wrong-origin-host":
				var o transport.NativeObservationOrigin
				_ = json.Unmarshal(snapshot.Origin, &o)
				o.HostID = domain.NewID().String()
				snapshot.Origin, _ = json.Marshal(o)
			}
			token.proxy.observeDirectEndpointSnapshot(snapshot, token.proxy.directEndpointObservationEpoch())
			select {
			case <-s.Done():
			default:
				t.Fatal("observed endpoint change returned before revoke")
			}
			if s.Valid() {
				t.Fatal("old endpoint locally valid")
			}
		})
	}
}

func TestDirectEndpointExplicitTransitionRevokesBeforeOperation(t *testing.T) {
	for _, kind := range []string{"stop", "restart", "replace"} {
		t.Run(kind, func(t *testing.T) {
			_, token, _, admit := subscriptionFixture(t)
			s, err := admit(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			// A mismatched ownership profile fails before worker IPC. Revocation must
			// already have happened and remain in force even on this failure path.
			ownership := token.ownership
			ownership.ProfileFingerprint = "invalid"
			proof := transport.NativeDispatchProof{OwnershipID: ownership.ID, OwnershipGeneration: token.proxy.scope.Generation, SourceCommandID: domain.NewID().String()}
			if _, err := token.proxy.AcceptDispatch(context.Background(), ownership, proof, kind, sessionworker.Operation{}); err == nil {
				t.Fatal("invalid ownership accepted")
			}
			select {
			case <-s.Done():
			default:
				t.Fatal("destructive operation failed without revocation")
			}
			if _, err := admit(context.Background(), nil); err == nil {
				t.Fatal("readmitted old endpoint during transition")
			}
			token.proxy.observeDirectEndpointSnapshot(subscriptionNativeSnapshot(token), token.proxy.directEndpointObservationEpoch())
			if _, err := admit(context.Background(), nil); err == nil {
				t.Fatal("unchanged snapshot cleared transition")
			}
		})
	}
}

func TestDirectEndpointNativeTransitionAdmissionRace(t *testing.T) {
	_, token, _, admit := subscriptionFixture(t)
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
	started := make(chan struct{})
	finished := make(chan struct{})
	go func() { close(started); token.proxy.beginDirectEndpointTransition(); close(finished) }()
	<-started
	select {
	case <-finished:
		t.Fatal("transition escaped admission publication fence")
	default:
	}
	close(release)
	<-finished
	got := <-result
	if got.s != nil {
		select {
		case <-got.s.Done():
		default:
			t.Fatal("transition missed admitted generation")
		}
	}
	if _, err := admit(context.Background(), nil); err == nil {
		t.Fatal("transition allowed old endpoint admission")
	}
}

func TestDirectEndpointNativeTransitionBeforeAdmissionFence(t *testing.T) {
	_, token, _, admit := subscriptionFixture(t)
	s, err := admit(context.Background(), func(base directEndpointCustodyUse) directEndpointCustodyUse {
		return func(verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
			return base(verify, func(conn *sql.Conn) (func(), func() error, error) {
				// IPC verification has completed, but publication authority is not pinned.
				token.proxy.beginDirectEndpointTransition()
				return fence(conn)
			}, use)
		}
	})
	if err == nil || s != nil {
		t.Fatal("pre-transition verification crossed the admission fence")
	}
}

func TestDirectEndpointNativeOldObservationCannotClearTransition(t *testing.T) {
	_, token, _, admit := subscriptionFixture(t)
	snapshot := subscriptionNativeSnapshot(token)
	snapshot.NativeStartIdentity = "changed-before-stop"
	observationEpoch := token.proxy.directEndpointObservationEpoch()
	token.proxy.beginDirectEndpointTransition()
	// A delayed Snapshot/ownership_verify reply began before stop. Even a
	// different endpoint in that response cannot reopen local admission.
	token.proxy.observeDirectEndpointSnapshot(snapshot, observationEpoch)
	token.proxy.publicationMu.RLock()
	blocked := token.proxy.directEndpointTransition
	token.proxy.publicationMu.RUnlock()
	if !blocked {
		t.Fatal("pre-transition snapshot reopened admission")
	}
	if s, err := admit(context.Background(), nil); err == nil || s != nil {
		t.Fatal("old endpoint admitted after stale observation")
	}
}

func TestDirectEndpointNativeOldObservationCannotBorrowNewEpoch(t *testing.T) {
	_, token, _, admit := subscriptionFixture(t)
	oldSnapshot := subscriptionNativeSnapshot(token)
	oldEpoch := token.endpointEpoch
	token.proxy.beginDirectEndpointTransition()
	replacement := oldSnapshot
	replacement.NativeStartIdentity = "new-process"
	token.proxy.observeDirectEndpointSnapshot(replacement, token.proxy.directEndpointObservationEpoch())
	staleEpoch := token.proxy.observeDirectEndpointSnapshot(oldSnapshot, oldEpoch)
	currentEpoch, _ := token.proxy.directEndpointAuthority(token.subject)
	if staleEpoch == currentEpoch {
		t.Fatal("stale verification borrowed current endpoint epoch")
	}
	if s, err := admit(context.Background(), nil); err == nil || s != nil {
		t.Fatal("stale verified endpoint readmitted")
	}
}

func TestDirectEndpointVerifierCurrentSnapshotRevokesStaleSubject(t *testing.T) {
	for _, kind := range []string{"generation", "session", "origin", "inactive", "pending"} {
		t.Run(kind, func(t *testing.T) {
			d, token, captured, admit := subscriptionFixture(t)
			snapshot := subscriptionNativeSnapshot(token)
			snapshot.PID = os.Getpid()
			start, err := proc.StartIdentity(snapshot.PID)
			if err != nil {
				t.Fatal(err)
			}
			snapshot.NativeStartIdentity = start
			token.endpointEpoch = token.proxy.observeDirectEndpointSnapshot(snapshot, token.proxy.directEndpointObservationEpoch())
			admitted, err := admit(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			var origin transport.NativeObservationOrigin
			if err := json.Unmarshal(snapshot.Origin, &origin); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "generation":
				snapshot.NativeGeneration = "current-generation"
				origin.NativeGeneration = snapshot.NativeGeneration
			case "session":
				snapshot.NativeSessionID = "current-session"
				origin.NativeSessionID = snapshot.NativeSessionID
			case "origin":
				origin.ID = domain.NewID().String()
			case "inactive":
				snapshot.PID = 0
			case "pending":
				snapshot.IdentityPending = true
			}
			snapshot.Origin, err = json.Marshal(origin)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := d.verifyNativeManagedSubjectToken(context.Background(), captured, d.ServerURL, token.subject, func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
				return &sessionworker.NativeOwnershipVerifyResult{Snapshot: snapshot}, nil
			})
			if err == nil || verified != nil {
				t.Fatal("stale requested subject accepted current snapshot")
			}
			select {
			case <-admitted.Done():
			default:
				t.Fatal("mismatched ownership verification left prior admission live")
			}
			if admitted.Valid() {
				t.Fatal("stale subject remains locally valid")
			}
		})
	}
}
