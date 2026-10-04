package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

func nativeFixture(t *testing.T) (*Store, fabric.ExecutionContext, AuthorityScope, string) {
	t.Helper()
	s, c, dir := fixture(t)
	d := endpoint(t, s)
	rev, e := s.Register(context.Background(), c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}
	return s, c, AuthorityScope{Endpoint: d.Ref, ExpectedRevision: rev, BindingID: "local"}, dir
}
func nativeVersion(t *testing.T, s *Store) int {
	t.Helper()
	var version int
	if e := s.db.QueryRow("PRAGMA user_version").Scan(&version); e != nil {
		t.Fatal(e)
	}
	return version
}
func nativeCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if e := s.db.QueryRow("SELECT count(*) FROM native_authority_log").Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func TestNativeAuthorityRejectsScopeBeforeCallbackOrSchema(t *testing.T) {
	s, c, scope, _ := nativeFixture(t)
	foreign := testOwner
	foreign.Issuer = "foreign.issuer"
	forged, _ := fabric.NewAuthenticatedContext(foreign, s.Namespace(), []byte("verified"))
	wrongAudience, _ := fabric.NewAuthenticatedContext(testOwner, "foreign-domain", []byte("verified"))
	cases := []struct {
		ctx   fabric.ExecutionContext
		scope AuthorityScope
	}{{fabric.ExecutionContext{}, scope}, {forged, scope}, {wrongAudience, scope}}
	stale := scope
	stale.ExpectedRevision = "stale"
	cases = append(cases, struct {
		ctx   fabric.ExecutionContext
		scope AuthorityScope
	}{c, stale})
	absent := scope
	absent.BindingID = "absent"
	cases = append(cases, struct {
		ctx   fabric.ExecutionContext
		scope AuthorityScope
	}{c, absent})
	for i, v := range cases {
		called := false
		e := s.WithNativeAuthority(context.Background(), v.ctx, v.scope, func(*AuthorityTx) error { called = true; return nil })
		if e == nil || called || nativeVersion(t, s) != 1 {
			t.Fatalf("scope %d callback/schema admitted: %v", i, e)
		}
	}
}
func TestNativeAuthorityRollbackPanicAndEscapedHandle(t *testing.T) {
	s, c, scope, _ := nativeFixture(t)
	key := AuthorityKey{Kind: AuthorityBinding, Endpoint: scope.Endpoint, ID: "binding"}
	sentinel := errors.New("rollback")
	for _, panicCallback := range []bool{false, true} {
		e := s.WithNativeAuthority(context.Background(), c, scope, func(a *AuthorityTx) error {
			if _, e := a.CAS(key, 0, []byte(`{"generation":"one"}`), false); e != nil {
				return e
			}
			if panicCallback {
				panic("private callback data")
			}
			return sentinel
		})
		if e == nil || nativeVersion(t, s) != 1 {
			t.Fatal("callback failure persisted schema or mutation", e)
		}
	}
	var escaped *AuthorityTx
	if e := s.WithNativeAuthority(context.Background(), c, scope, func(a *AuthorityTx) error { escaped = a; return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e := escaped.Get(key); e == nil {
		t.Fatal("escaped read")
	}
	if _, e := escaped.CAS(key, 0, []byte(`{}`), false); e == nil {
		t.Fatal("escaped write")
	}
	if _, e := escaped.SignCallerProof(c, nil, fabric.CallerProofFrame{}); e == nil {
		t.Fatal("escaped original signer")
	}
	if _, e := escaped.SignDispatchAdmission(c, nil, nil, fabric.DispatchAdmissionFrame{}); e == nil {
		t.Fatal("escaped final signer")
	}
	if nativeCount(t, s) != 0 {
		t.Fatal("escaped handle changed state")
	}
}
func TestNativeAuthorityCASRetirementRestartAndConcurrentFence(t *testing.T) {
	s, c, scope, dir := nativeFixture(t)
	key := AuthorityKey{Kind: AuthorityBinding, Endpoint: scope.Endpoint, ID: "binding"}
	var first AuthorityRecord
	write := func(expected uint64, value string, retire bool) (AuthorityRecord, error) {
		var r AuthorityRecord
		e := s.WithNativeAuthority(context.Background(), c, scope, func(a *AuthorityTx) error { var e error; r, e = a.CAS(key, expected, []byte(value), retire); return e })
		return r, e
	}
	var e error
	first, e = write(0, `{"epoch":1}`, false)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyAuthorityRecord(s.AuthorityIdentity(), first); e != nil {
		t.Fatal(e)
	}
	first.Value[0] = 'x'
	if e = VerifyAuthorityRecord(s.AuthorityIdentity(), first); e == nil {
		t.Fatal("tampered signed payload")
	}
	retry, e := write(0, `{"epoch":1}`, false)
	if e != nil || retry.Revision != 1 || nativeCount(t, s) != 1 {
		t.Fatal("exact retry", e)
	}
	if _, e = write(0, `{"epoch":2}`, false); e == nil {
		t.Fatal("changed stale write")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := write(1, fmt.Sprintf(`{"epoch":%d}`, i+2), false)
			if e == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 || nativeCount(t, s) != 2 {
		t.Fatal("concurrent CAS admitted more than one", success)
	}
	retired, e := write(2, `{"retired":true}`, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = write(3, `{"epoch":99}`, false); e == nil {
		t.Fatal("resurrected authority")
	}
	if _, e = write(2, `{"retired":true}`, true); e != nil {
		t.Fatal("retirement retry", e)
	}
	identity := s.AuthorityIdentity()
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if !bytes.Equal(reopened.AuthorityIdentity().PublicKey, identity.PublicKey) || nativeCount(t, reopened) != 3 {
		t.Fatal("restart replaced authority")
	}
	if e = reopened.WithNativeAuthority(context.Background(), c, scope, func(a *AuthorityTx) error {
		r, e := a.Get(key)
		if e != nil {
			return e
		}
		if !r.Retired || r.Revision != retired.Revision {
			t.Fatal("restart lost tombstone")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestNativeAuthorityBudgetsAndSQLFailureRollback(t *testing.T) {
	s, c, scope, _ := nativeFixture(t)
	key := AuthorityKey{Kind: AuthorityBinding, Endpoint: scope.Endpoint, ID: "binding"}
	limited := scope
	limited.MaxOperations = 1
	e := s.WithNativeAuthority(context.Background(), c, limited, func(a *AuthorityTx) error {
		if _, e := a.CAS(key, 0, []byte(`{}`), false); e != nil {
			return e
		}
		_, e := a.Get(key)
		return e
	})
	if e == nil || nativeVersion(t, s) != 1 {
		t.Fatal("operation limit failed rollback", e)
	}
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if e = s.WithNativeAuthority(expired, c, scope, func(*AuthorityTx) error { t.Fatal("expired callback executed"); return nil }); e == nil {
		t.Fatal("expired admitted")
	}
	if e = s.WithNativeAuthority(context.Background(), c, scope, func(*AuthorityTx) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec(`CREATE TRIGGER fail_native BEFORE INSERT ON native_authority_state BEGIN SELECT RAISE(ABORT,'failure'); END;`); e != nil {
		t.Fatal(e)
	}
	if e = s.WithNativeAuthority(context.Background(), c, scope, func(a *AuthorityTx) error { _, e := a.CAS(key, 0, []byte(`{}`), false); return e }); e == nil {
		t.Fatal("SQL failure ignored")
	}
	if nativeCount(t, s) != 0 {
		t.Fatal("partial signed log survived SQL rollback")
	}
	var sequence, total int
	if e = s.db.QueryRow("SELECT sequence,bytes FROM native_authority_head").Scan(&sequence, &total); e != nil {
		t.Fatal(e)
	}
	if sequence != 0 || total != 0 {
		t.Fatal("quota reservation leaked")
	}
}
func TestNativeAuthorityHistoryOnlyCannotReactivateRetiredEndpoint(t *testing.T) {
	s, c, scope, _ := nativeFixture(t)
	if _, e := s.Retire(context.Background(), c, scope.Endpoint, scope.ExpectedRevision); e != nil {
		t.Fatal(e)
	}
	if e := s.WithNativeAuthority(context.Background(), c, scope, func(*AuthorityTx) error { t.Fatal("retired actuation callback"); return nil }); e == nil {
		t.Fatal("retired admitted")
	}
	scope.HistoryOnly = true
	if e := s.WithNativeAuthority(context.Background(), c, scope, func(a *AuthorityTx) error {
		if _, e := a.CAS(AuthorityKey{Kind: AuthorityOrigin, Endpoint: scope.Endpoint, ID: "new"}, 0, []byte(`{}`), false); e == nil {
			t.Fatal("historical origin recreated")
		}
		_, e := a.CAS(AuthorityKey{Kind: AuthoritySource, Endpoint: scope.Endpoint, ID: "actual-source"}, 0, []byte(`{"effect":"unknown"}`), false)
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
func TestNativeAuthoritySigningBindsOriginalFinalAndActualDeadline(t *testing.T) {
	s, owner, scope, _ := nativeFixture(t)
	deadline := time.Now().UTC().Add(time.Hour)
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "invoke-1", Operation: fabric.OperationInvoke, Principal: testOwner, Source: testOwner.Ref, Target: &scope.Endpoint, ExpectedRevision: scope.ExpectedRevision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"input":"original"}`), Context: fabric.EnvelopeContext{Origin: testOwner.Ref, Deadline: &deadline}}
	original, _ := json.Marshal(env)
	caller, e := fabric.NewAuthenticatedContext(testOwner, s.Namespace(), original)
	if e != nil {
		t.Fatal(e)
	}
	env.Payload = json.RawMessage(`{"input":"final"}`)
	final, _ := json.Marshal(env)
	proof := fabric.CallerProofFrame{SourceDomain: s.Namespace(), AudienceDomain: s.Namespace(), CallerRef: testOwner.Ref, IssuerKeyRevision: 1, Operation: env.Operation, OriginalEnvelopeID: env.ID, ReplayID: "replay-1", OriginalEnvelopeDigest: sha256.Sum256(original), Deadline: deadline.Format(time.RFC3339Nano)}
	admission := fabric.DispatchAdmissionFrame{SourceDomain: s.Namespace(), AudienceDomain: s.Namespace(), CallerRef: testOwner.Ref, InvocationID: env.ID, AttemptID: "attempt-1", ReplayID: "replay-1", FinalizedDispatchDigest: sha256.Sum256(final), Deadline: deadline.Format(time.RFC3339Nano)}
	identity := s.AuthorityIdentity()
	e = s.WithNativeAuthority(context.Background(), owner, scope, func(a *AuthorityTx) error {
		sig, e := a.SignCallerProof(caller, original, proof)
		if e != nil {
			return e
		}
		framed, _ := proof.SigningBytes()
		if !ed25519.Verify(identity.PublicKey, framed, sig) {
			t.Fatal("original signature")
		}
		sig, e = a.SignDispatchAdmission(caller, original, final, admission)
		if e != nil {
			return e
		}
		framed, _ = admission.SigningBytes()
		if !ed25519.Verify(identity.PublicKey, framed, sig) {
			t.Fatal("final signature")
		}
		bad := proof
		bad.Deadline = deadline.Add(time.Hour).Format(time.RFC3339Nano)
		if _, e = a.SignCallerProof(caller, original, bad); e == nil {
			t.Fatal("extended original deadline")
		}
		next := admission
		next.Deadline = ""
		if _, e = a.SignDispatchAdmission(caller, original, final, next); e == nil {
			t.Fatal("removed final deadline")
		}
		env.Context.Origin = "changed-source"
		changed, _ := json.Marshal(env)
		next = admission
		next.FinalizedDispatchDigest = sha256.Sum256(changed)
		if _, e = a.SignDispatchAdmission(caller, original, changed, next); e == nil {
			t.Fatal("changed immutable provenance")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestNativeAuthorityRecoveryFailsClosedOnProjectionOrSignedHistoryCorruption(t *testing.T) {
	for _, sql := range []string{"UPDATE native_authority_state SET revision=99", "UPDATE native_authority_log SET record=x'7b7d'", "DROP TABLE native_authority_state", "UPDATE native_authority_head SET bytes=bytes+1", "PRAGMA user_version=1"} {
		t.Run(sql, func(t *testing.T) {
			s, c, scope, dir := nativeFixture(t)
			if e := s.WithNativeAuthority(context.Background(), c, scope, func(a *AuthorityTx) error {
				_, e := a.CAS(AuthorityKey{Kind: AuthorityOrigin, Endpoint: scope.Endpoint, ID: "source"}, 0, []byte(`{}`), false)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			if _, e := s.db.Exec(sql); e != nil {
				t.Fatal(e)
			}
			s.Close()
			if reopened, e := Open(context.Background(), dir); e == nil {
				reopened.Close()
				t.Fatal("corrupt authority silently recovered")
			}
		})
	}
}

func TestNativeAuthorityQuotaAndDeadlineRollbackLeavesNoReservation(t *testing.T) {
	s, c, scope, _ := nativeFixture(t)
	s.options.Limits.MaxRecords = 1
	e := s.WithNativeAuthority(context.Background(), c, scope, func(a *AuthorityTx) error {
		if _, e := a.CAS(AuthorityKey{Kind: AuthorityBinding, Endpoint: scope.Endpoint, ID: "one"}, 0, []byte(`{}`), false); e != nil {
			return e
		}
		_, e := a.CAS(AuthorityKey{Kind: AuthorityOrigin, Endpoint: scope.Endpoint, ID: "two"}, 0, []byte(`{}`), false)
		return e
	})
	if e == nil || nativeVersion(t, s) != 1 {
		t.Fatal("capacity failure left signed prefix or reservation", e)
	}
	limited := scope
	limited.Timeout = time.Nanosecond
	e = s.WithNativeAuthority(context.Background(), c, limited, func(a *AuthorityTx) error {
		_, e := a.CAS(AuthorityKey{Kind: AuthorityOrigin, Endpoint: scope.Endpoint, ID: "expired"}, 0, []byte(`{}`), false)
		return e
	})
	if e == nil || nativeVersion(t, s) != 1 {
		t.Fatal("deadline failure persisted transaction", e)
	}
}
