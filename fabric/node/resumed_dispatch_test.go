package node

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type resumePortFunc func(context.Context, fabric.ExecutionContext, []byte, fabric.Envelope) error

func (f resumePortFunc) VerifyResumeDispatch(c context.Context, p fabric.ExecutionContext, b []byte, e fabric.Envelope) error {
	return f(c, p, b, e)
}

// These tests exercise the trusted port contract, not a real claim authority.
// Real kernel/store/claim evidence is covered by installed authority fixtures.
func TestResumedDispatchDefaultsDenyAndPreservesOriginalDeadline(t *testing.T) {
	s, e, _, store, dispatcher := setup(t)
	e.Operation = fabric.OperationInvoke
	e.Target = &store.endpoint.Ref
	e.ExpectedRevision = "r1"
	e.Payload = json.RawMessage(`{"text":"original"}`)
	raw, _ := json.Marshal(e)
	caller, _ := fabric.NewAuthenticatedContext(e.Principal, s.config.Audience, raw)
	if _, err := s.InvokeResumed(t.Context(), caller, raw, e); err == nil || len(dispatcher.requests) != 0 {
		t.Fatal("unconfigured resume entered target")
	}
	calls := 0
	s.config.ResumeDispatchVerifier = resumePortFunc(func(context.Context, fabric.ExecutionContext, []byte, fabric.Envelope) error {
		calls++
		return fabric.NewError(fabric.CodeUnauthenticated, "missing private claim")
	})
	if _, err := s.InvokeResumed(t.Context(), caller, raw, e); err == nil || calls != 1 || len(dispatcher.requests) != 0 {
		t.Fatal("rejected claim entered target")
	}
	expiry := time.Now().Add(-time.Second)
	e.Context.Deadline = &expiry
	raw, _ = json.Marshal(e)
	caller, _ = fabric.NewAuthenticatedContext(e.Principal, s.config.Audience, raw)
	if _, err := s.InvokeResumed(t.Context(), caller, raw, e); err == nil || calls != 1 || len(dispatcher.requests) != 0 {
		t.Fatal("expired original was revived")
	}
	future := time.Now().Add(time.Minute)
	changed := e
	changed.Context.Deadline = &future
	if _, err := s.InvokeResumed(t.Context(), caller, raw, changed); err == nil || calls != 1 || len(dispatcher.requests) != 0 {
		t.Fatal("original deadline mutation authorized")
	}
}

func TestTrustedResumeVerifierCannotAccidentallyMutateSealedDispatch(t *testing.T) {
	s, e, _, store, dispatcher := setup(t)
	e.Operation = fabric.OperationInvoke
	e.Target = &store.endpoint.Ref
	e.ExpectedRevision = "r1"
	e.Payload = json.RawMessage(`{"large":9007199254740993}`)
	raw, _ := json.Marshal(e)
	caller, _ := fabric.NewAuthenticatedContext(e.Principal, s.config.Audience, raw)
	s.config.ResumeDispatchVerifier = resumePortFunc(func(_ context.Context, _ fabric.ExecutionContext, b []byte, owned fabric.Envelope) error {
		clear(b)
		clear(owned.Payload)
		*owned.Target = fabric.EndpointRef{}
		return nil
	})
	result, err := s.InvokeResumed(t.Context(), caller, raw, e)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Stream.Close()
	if len(dispatcher.requests) != 1 || dispatcher.requests[0].Target != store.endpoint.Ref || string(dispatcher.requests[0].Input) != string(e.Payload) {
		t.Fatal("verifier changed sealed selection")
	}
	actual, original, final, ok := FinalizedRequestFromContext(dispatcher.ctx)
	if !ok || actual.PrincipalView() != caller.PrincipalView() || string(original) != string(raw) || len(final) == 0 {
		t.Fatal("genuine node dispatch capability missing original/final")
	}
}
