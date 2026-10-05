package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestOriginalDispatchGlobalFenceAcrossNativeServiceAndHostedBindings(t *testing.T) {
	s, owner, dir := fixture(t)
	d := endpoint(t, s)
	d.Bindings = []fabric.BindingSummary{{ID: "native", Protocol: "pagnet.agent.native", Version: "1"}, {ID: "service", Protocol: "mcp.tools", Version: "1"}, {ID: "hosted", Protocol: "pagnet.agent.hosted-native.v1", Version: "1"}}
	revision, err := s.Register(t.Context(), owner, fabric.RegistryUpdate{Descriptor: d})
	if err != nil {
		t.Fatal(err)
	}
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "one-original-invocation", Operation: fabric.OperationInvoke, Principal: testOwner, Source: testOwner.Ref, Target: &d.Ref, ExpectedRevision: revision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"input":"private original"}`), Context: fabric.EnvelopeContext{Origin: testOwner.Ref}}
	before, _ := json.Marshal(env)
	caller, err := fabric.NewAuthenticatedContext(testOwner, s.Namespace(), before)
	if err != nil {
		t.Fatal(err)
	}
	env.Payload = json.RawMessage(`{"input":"private final"}`)
	final, _ := json.Marshal(env)
	frame := fabric.DispatchAdmissionFrame{SourceDomain: s.Namespace(), AudienceDomain: s.Namespace(), CallerRef: testOwner.Ref, InvocationID: env.ID, AttemptID: "actual-first-attempt", ReplayID: "actual-first-replay", FinalizedDispatchDigest: sha256.Sum256(final)}
	sign := func(binding string, actual fabric.ExecutionContext, original, finalized []byte, f fabric.DispatchAdmissionFrame) ([]byte, error) {
		var signature []byte
		err := s.WithNativeAuthority(t.Context(), owner, AuthorityScope{Endpoint: d.Ref, ExpectedRevision: revision, BindingID: binding}, func(tx *AuthorityTx) error {
			var err error
			signature, err = tx.SignDispatchAdmission(actual, original, finalized, f)
			return err
		})
		return signature, err
	}
	first, err := sign("native", caller, before, final, frame)
	if err != nil {
		t.Fatal("original native dispatch", err)
	}
	count := nativeCount(t, s)
	retry, err := sign("native", caller, before, final, frame)
	if err != nil || !bytes.Equal(first, retry) || nativeCount(t, s) != count {
		t.Fatal("exact retry regenerated or duplicated original claim", err)
	}
	for _, binding := range []string{"service", "hosted"} {
		if _, err = sign(binding, caller, before, final, frame); err == nil {
			t.Fatal("same invocation acquired another protocol's paid claim", binding)
		}
	}
	changedFrame := frame
	changedFrame.AttemptID = "replacement-attempt"
	if _, err = sign("native", caller, before, final, changedFrame); err == nil {
		t.Fatal("replacement realization/attempt reused original paid identity")
	}
	changed := env
	changed.Payload = json.RawMessage(`{"input":"replacement final"}`)
	changedBytes, _ := json.Marshal(changed)
	changedFrame = frame
	changedFrame.FinalizedDispatchDigest = sha256.Sum256(changedBytes)
	if _, err = sign("native", caller, before, changedBytes, changedFrame); err == nil {
		t.Fatal("replacement final input reused original paid identity")
	}
	// A new authenticated original still cannot reuse its principal+invocation
	// identity after changing content. Different authenticated caller identities
	// remain independent; the key includes full principal, not just its name.
	changedCaller, _ := fabric.NewAuthenticatedContext(testOwner, s.Namespace(), changedBytes)
	if _, err = sign("native", changedCaller, changedBytes, changedBytes, changedFrame); err == nil {
		t.Fatal("reauthentication bypassed original global identity")
	}
	if nativeCount(t, s) != count {
		t.Fatal("rejected claims mutated original ledger")
	}
	// Source inspection is read-only and cannot claim a fresh paid dispatch.
	err = s.WithNativeAuthority(t.Context(), owner, AuthorityScope{}, func(tx *AuthorityTx) error {
		row, err := tx.Get(originalDispatchKey(testOwner, env.ID))
		if err != nil || VerifyAuthorityRecord(s.identityAuthorityForTest(), row) != nil {
			return errors.New("actual committed original claim missing")
		}
		return nil
	})
	if err != nil || nativeCount(t, s) != count {
		t.Fatal("source inspection created new original dispatch", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(t.Context(), dir)
	if err != nil {
		t.Fatal("actual signed root restart", err)
	}
	defer s.Close()
	retry, err = sign("native", caller, before, final, frame)
	if err != nil || !bytes.Equal(first, retry) || nativeCount(t, s) != count {
		t.Fatal("restart recreated original claim", err)
	}
	if _, err = sign("hosted", caller, before, final, frame); err == nil {
		t.Fatal("restart lost cross-adapter original fence")
	}
	err = s.WithNativeAuthority(t.Context(), owner, AuthorityScope{}, func(tx *AuthorityTx) error {
		key := originalDispatchKey(testOwner, env.ID)
		row, err := tx.Get(key)
		if err != nil {
			return err
		}
		_, err = tx.CAS(key, row.Revision, row.Value, true)
		return err
	})
	if err != nil {
		t.Fatal("explicit claim retirement", err)
	}
	retiredCount := nativeCount(t, s)
	if _, err = sign("native", caller, before, final, frame); err == nil || nativeCount(t, s) != retiredCount {
		t.Fatal("retired claim silently regenerated", err)
	}
}

func (s *Store) identityAuthorityForTest() AuthorityIdentity {
	return AuthorityIdentity{s.identity.Namespace, s.identity.StoreID, s.identity.Owner, s.identity.PublicKey, 1}
}

func TestOriginalDispatchClaimRollsBackWithFailedAdmission(t *testing.T) {
	s, owner, scope, _ := nativeFixture(t)
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "rolled-back-original", Operation: fabric.OperationInvoke, Principal: testOwner, Source: testOwner.Ref, Target: &scope.Endpoint, ExpectedRevision: scope.ExpectedRevision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"input":"original"}`), Context: fabric.EnvelopeContext{Origin: testOwner.Ref}}
	raw, _ := json.Marshal(env)
	caller, _ := fabric.NewAuthenticatedContext(testOwner, s.Namespace(), raw)
	frame := fabric.DispatchAdmissionFrame{SourceDomain: s.Namespace(), AudienceDomain: s.Namespace(), CallerRef: testOwner.Ref, InvocationID: env.ID, AttemptID: "first", ReplayID: "first", FinalizedDispatchDigest: sha256.Sum256(raw)}
	rollback := errors.New("receipt persistence failed")
	err := s.WithNativeAuthority(context.Background(), owner, scope, func(tx *AuthorityTx) error {
		if _, err := tx.SignDispatchAdmission(caller, raw, raw, frame); err != nil {
			return err
		}
		return rollback
	})
	var tables int
	if queryErr := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='native_authority_log'`).Scan(&tables); queryErr != nil {
		t.Fatal(queryErr)
	}
	if !errors.Is(err, rollback) || tables != 0 {
		t.Fatal("failed original receipt left a paid claim", err)
	}
	frame.AttemptID = "first-committed"
	err = s.WithNativeAuthority(t.Context(), owner, scope, func(tx *AuthorityTx) error {
		_, err := tx.SignDispatchAdmission(caller, raw, raw, frame)
		return err
	})
	if err != nil || nativeCount(t, s) != 1 {
		t.Fatal("first committed original effect could not claim after rollback", err)
	}
}
