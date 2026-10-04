package actions

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/node"
)

type signedAuthority struct {
	pub       ed25519.PublicKey
	private   ed25519.PrivateKey
	principal fabric.Principal
	audience  string
	revoked   atomic.Bool
	parent    *fabric.Envelope
}

func (a *signedAuthority) Verify(ctx context.Context, scope durable.Scope, input SourceInput) (VerifiedSource, error) {
	var signature []byte
	if a.revoked.Load() || scope.Audience != a.audience || json.Unmarshal(input.Proof, &signature) != nil || !ed25519.Verify(a.pub, input.ExactEvent, signature) {
		return VerifiedSource{}, denied()
	}
	e, err := events.Decode(input.ExactEvent, 1<<20)
	if err != nil || e.Source() != a.principal.Ref {
		return VerifiedSource{}, denied()
	}
	caller, err := fabric.NewAuthenticatedContext(a.principal, a.audience, input.ExactEvent)
	return VerifiedSource{caller, a.parent}, err
}

type definitionVerifier struct {
	private ed25519.PrivateKey
	pub     ed25519.PublicKey
	revoked atomic.Bool
}

func definitionBytes(d TriggerDefinition) []byte {
	d.SignedAuthorization = nil
	b, _ := json.Marshal(d)
	return b
}
func (a *definitionVerifier) Verify(_ context.Context, _ durable.Scope, d TriggerDefinition) error {
	var signature []byte
	if a.revoked.Load() || json.Unmarshal(d.SignedAuthorization, &signature) != nil || !ed25519.Verify(a.pub, definitionBytes(d), signature) {
		return denied()
	}
	return nil
}

type preparer struct{ changes atomic.Bool }

func (a *preparer) Prepare(_ context.Context, caller fabric.ExecutionContext, p Preparation) ([]byte, error) {
	envelope := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: p.ID, Operation: fabric.OperationInvoke, Principal: caller.PrincipalView(), Source: caller.PrincipalView().Ref, Target: &p.Request.Target, ExpectedRevision: p.Request.Revision, CreatedAt: p.CreatedAt, Payload: bytes.Clone(p.Request.Input), Context: p.Context}
	if a.changes.Load() {
		envelope.Context.ParentID = "forged"
	}
	raw, e := json.Marshal(envelope)
	return append(append([]byte(" \n"), raw...), []byte("\t \n")...), e
}
func (a *preparer) Check(context.Context, fabric.ExecutionContext, Action) error {
	if a.changes.Load() {
		return denied()
	}
	return nil
}

// Test admission is a real FULL SQLite commit/query boundary, separate from
// target execution. Losing its reply does not erase its retained receipt.
type sqlAdmission struct {
	db             *sql.DB
	lose           int
	calls, effects int
}

func (a *sqlAdmission) AdmitOrGet(ctx context.Context, request AdmissionRequest) (AdmissionReceipt, error) {
	action := request.Action
	a.calls++
	hash := digest(action.ExactEnvelope)
	var old string
	var stamp int64
	err := a.db.QueryRowContext(ctx, "SELECT digest,stamp FROM admissions WHERE id=?", action.ID).Scan(&old, &stamp)
	if err == nil {
		if old != hash {
			return AdmissionReceipt{}, denied()
		}
		return AdmissionReceipt{action.ID, hash, "admission-" + action.ID, time.Unix(0, stamp).UTC()}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AdmissionReceipt{}, err
	}
	stamp = time.Now().UnixNano()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return AdmissionReceipt{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT INTO admissions(id,digest,stamp) VALUES(?,?,?)", action.ID, hash, stamp); err != nil {
		return AdmissionReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return AdmissionReceipt{}, err
	}
	a.effects++
	if a.effects == a.lose {
		return AdmissionReceipt{}, errors.New("committed reply lost")
	}
	return AdmissionReceipt{action.ID, hash, "admission-" + action.ID, time.Unix(0, stamp).UTC()}, nil
}
func openAdmission(t *testing.T, path string) *sqlAdmission {
	t.Helper()
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	if _, e = db.Exec("PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS admissions(id TEXT PRIMARY KEY,digest TEXT NOT NULL,stamp INTEGER NOT NULL)"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	return &sqlAdmission{db: db}
}

type setup struct {
	config      Config
	source      SourceInput
	sourceAuth  *signedAuthority
	definitions *definitionVerifier
	prepare     *preparer
	admit       *sqlAdmission
	dir         string
}

func fixture(t *testing.T, n int) setup {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dp, dpriv, _ := ed25519.GenerateKey(rand.Reader)
	principal := fabric.Principal{Ref: "urn:producer:registered", Kind: "source.registered", Issuer: "registered-root"}
	scope := durable.Scope{Audience: "registered-domain", Domain: "retained-domain"}
	config := DefaultConfig(scope)
	endpoint, _ := fabric.NewEndpointRef(pub)
	for i := 0; i < n; i++ {
		d := TriggerDefinition{ID: "trigger." + string(rune('a'+i)), Revision: "1", Source: principal.Ref, Type: "test.action", Target: endpoint, TargetRevision: "1", BindingDigest: digest([]byte("profile"))}
		d.SignedAuthorization, _ = json.Marshal(ed25519.Sign(dpriv, definitionBytes(d)))
		config.Definitions = append(config.Definitions, d)
	}
	auth := &signedAuthority{pub: pub, private: priv, principal: principal, audience: scope.Audience}
	defs := &definitionVerifier{pub: dp, private: dpriv}
	prep := &preparer{}
	root := t.TempDir()
	admit := openAdmission(t, filepath.Join(root, "admissions.sqlite"))
	protector, err := durable.NewAESGCM(durable.KeyReference{ID: "operator-key", Version: "1"}, bytes.Repeat([]byte{27}, 32))
	if err != nil {
		t.Fatal(err)
	}
	config.SourceAuthority = auth
	config.DefinitionAuthority = defs
	config.Authorizer = prep
	config.Admitter = admit
	config.Protector = protector
	config.Queue.RetryDelay = time.Millisecond
	e := event.New("1.0")
	e.SetID("immutable-original-event")
	e.SetSource(principal.Ref)
	e.SetType("test.action")
	e.SetTime(time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC))
	_ = e.SetData("application/json", json.RawMessage(`{"exact":900719925474099312345,"private":"marker-private-input"}`))
	raw, err := events.Encode(e, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := json.Marshal(ed25519.Sign(priv, raw))
	return setup{config, SourceInput{raw, proof}, auth, defs, prep, admit, filepath.Join(root, "actions")}
}
func claim(t *testing.T, s *Store) durable.Delivery {
	t.Helper()
	d, ok, e := s.queue.Claim(t.Context(), "actions.dispatch", "test.worker", time.Now().Add(time.Second))
	if e != nil || !ok {
		t.Fatal("no genuine queue claim", e)
	}
	return d
}
func TestAtomicTriggerFanoutRestartLostAdmissionReceipt(t *testing.T) {
	f := fixture(t, 2)
	s, e := Bootstrap(t.Context(), f.dir, f.config)
	if e != nil {
		t.Fatal(e)
	}
	r, e := s.Trigger(t.Context(), f.source)
	if e != nil || r.Duplicate {
		t.Fatal(e)
	}
	state, e := s.State(t.Context())
	if e != nil || state.Pending != 1 {
		t.Fatal("fanout was not one atomic item", state, e)
	}
	d := claim(t, s)
	f.admit.lose = 2
	if e = s.deliver(t.Context(), d.Event); e == nil {
		t.Fatal("lost durable receipt hidden")
	}
	if f.admit.effects != 2 {
		t.Fatal("missing genuine committed admissions")
	}
	if e = s.queue.Nack(t.Context(), d.Claim, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	f.admit.db.Close()
	f.admit = openAdmission(t, filepath.Join(filepath.Dir(f.dir), "admissions.sqlite"))
	f.config.Admitter = f.admit
	s, e = Open(t.Context(), f.dir, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	duplicate, e := s.Trigger(t.Context(), f.source)
	if e != nil || !duplicate.Duplicate {
		t.Fatal("exact original retry failed", e)
	}
	d = claim(t, s)
	if e = s.deliver(t.Context(), d.Event); e != nil {
		t.Fatal(e)
	}
	if f.admit.effects != 0 || f.admit.calls != 2 {
		t.Fatal("retained prefix replayed effects")
	}
	if e = s.queue.Ack(t.Context(), d.Claim, time.Now()); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{filepath.Join(f.dir, "registrations.sealed"), filepath.Join(f.dir, "queue", "events.sqlite")} {
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(raw, []byte("marker-private-input")) {
			t.Fatal("private plaintext persisted")
		}
	}
}
func TestRegistrationCheckpointWrongKeyRemovedAndChangedAuthority(t *testing.T) {
	f := fixture(t, 1)
	s, e := Bootstrap(t.Context(), f.dir, f.config)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	changed := f.config
	changed.Definitions = append([]TriggerDefinition(nil), f.config.Definitions...)
	changed.Definitions[0].TargetRevision = "2"
	if s, e = Open(t.Context(), f.dir, changed); e == nil {
		s.Close()
		t.Fatal("unsigned registration substitution accepted")
	}
	wrong, _ := durable.NewAESGCM(f.config.Protector.Reference(), bytes.Repeat([]byte{28}, 32))
	changed = f.config
	changed.Protector = wrong
	if s, e = Open(t.Context(), f.dir, changed); e == nil {
		s.Close()
		t.Fatal("wrong operator key accepted")
	}
	if e = os.Remove(filepath.Join(f.dir, "registrations.sealed")); e != nil {
		t.Fatal(e)
	}
	if s, e = Open(t.Context(), f.dir, f.config); e == nil {
		s.Close()
		t.Fatal("missing registration checkpoint regenerated")
	}
}
func TestSourceForgeryCurrentRevocationAndLineageCannotDispatch(t *testing.T) {
	f := fixture(t, 1)
	s, e := Bootstrap(t.Context(), f.dir, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	changed := f.source
	changed.ExactEvent = bytes.Replace(f.source.ExactEvent, []byte("test.action"), []byte("test.forged"), 1)
	if _, e = s.Trigger(t.Context(), changed); e == nil {
		t.Fatal("changed signed source accepted")
	}
	f.prepare.changes.Store(true)
	if _, e = s.Trigger(t.Context(), f.source); e == nil {
		t.Fatal("invented parent accepted")
	}
	f.prepare.changes.Store(false)
	if _, e = s.Trigger(t.Context(), f.source); e != nil {
		t.Fatal(e)
	}
	d := claim(t, s)
	f.definitions.revoked.Store(true)
	if e = s.deliver(t.Context(), d.Event); e == nil {
		t.Fatal("revoked trigger dispatched")
	}
	f.definitions.revoked.Store(false)
	f.sourceAuth.revoked.Store(true)
	if e = s.deliver(t.Context(), d.Event); e == nil {
		t.Fatal("revoked source dispatched")
	}
	if f.admit.calls != 0 {
		t.Fatal("gate failure reached admission")
	}
}
func TestBoundedFanoutAtomicCapacityAndEmitSameIdentityConflict(t *testing.T) {
	f := fixture(t, 2)
	f.config.MaxFanout = 1
	s, e := Bootstrap(t.Context(), f.dir, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Trigger(t.Context(), f.source); e == nil {
		t.Fatal("fanout budget ignored")
	}
	state, _ := s.State(t.Context())
	if state.Rows != 0 {
		t.Fatal("partial trigger fanout committed")
	}
	target := f.config.Definitions[0].Target
	r := EmitRequest{target, "1", json.RawMessage(`{"v":1}`)}
	if _, e = s.Emit(t.Context(), f.source, r); e != nil {
		t.Fatal(e)
	}
	r.Input = json.RawMessage(`{"v":2}`)
	if _, e = s.Emit(t.Context(), f.source, r); e == nil {
		t.Fatal("same event identity relabeled different emitted input")
	}
}
func TestActionReplacementAndLoopRejectedBeforeAdmission(t *testing.T) {
	f := fixture(t, 1)
	s, e := Bootstrap(t.Context(), f.dir, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Trigger(t.Context(), f.source); e != nil {
		t.Fatal(e)
	}
	d := claim(t, s)
	var set actionSet
	if e = fabric.DecodeJSON(d.Event.Data(), &set); e != nil {
		t.Fatal(e)
	}
	set.Actions[0].ID = base64.RawURLEncoding.EncodeToString([]byte("invented-action"))
	_ = d.Event.SetData("application/json", set)
	if e = s.deliver(t.Context(), d.Event); e == nil || f.admit.calls != 0 {
		t.Fatal("invented action identity admitted")
	}
	parent := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "genuine-parent", Operation: fabric.OperationDiscover, Principal: f.sourceAuth.principal, Source: f.sourceAuth.principal.Ref, CreatedAt: time.Now(), Payload: json.RawMessage(`{}`), Context: fabric.EnvelopeContext{Origin: f.sourceAuth.principal.Ref, TriggerLineage: []string{f.config.Definitions[0].ID}}}
	f.sourceAuth.parent = &parent
	if _, e = s.Trigger(t.Context(), f.source); e == nil {
		t.Fatal("trigger self recursion accepted")
	}
}

func TestSignedWhitespaceAndLargeNumberSurviveQueueRestartExactly(t *testing.T) {
	f := fixture(t, 1)
	f.source.ExactEvent = append(append([]byte(" \n"), f.source.ExactEvent...), []byte("\t \n")...)
	f.source.Proof, _ = json.Marshal(ed25519.Sign(f.sourceAuth.private, f.source.ExactEvent))
	s, e := Bootstrap(t.Context(), f.dir, f.config)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Trigger(t.Context(), f.source); e != nil {
		t.Fatal(e)
	}
	d := claim(t, s)
	var before actionSet
	if e = fabric.DecodeJSON(d.Event.Data(), &before); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before.Source.ExactEvent, f.source.ExactEvent) || !bytes.HasPrefix(before.Actions[0].ExactEnvelope, []byte(" \n")) || !bytes.Contains(before.Actions[0].ExactEnvelope, []byte("900719925474099312345")) {
		t.Fatal("exact original bytes or numeric precision lost")
	}
	if e = s.queue.Nack(t.Context(), d.Claim, time.Now()); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(t.Context(), f.dir, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	d = claim(t, s)
	var after actionSet
	if e = fabric.DecodeJSON(d.Event.Data(), &after); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before.Actions[0].ExactEnvelope, after.Actions[0].ExactEnvelope) {
		t.Fatal("retained finalized envelope was rewritten")
	}
	if e = s.deliver(t.Context(), d.Event); e != nil {
		t.Fatal(e)
	}
}

type blockedAdmission struct {
	entered chan struct{}
	release chan struct{}
}

func (a *blockedAdmission) AdmitOrGet(context.Context, AdmissionRequest) (AdmissionReceipt, error) {
	close(a.entered)
	<-a.release
	return AdmissionReceipt{}, errors.New("unconfirmed acceptance")
}
func TestCloseDeadlineRetainsLeaseUntilActualAdmissionCallbackReturns(t *testing.T) {
	f := fixture(t, 1)
	blocked := &blockedAdmission{make(chan struct{}), make(chan struct{})}
	f.config.Admitter = blocked
	s, e := Bootstrap(t.Context(), f.dir, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		select {
		case <-blocked.release:
		default:
			close(blocked.release)
		}
		s.Close()
	}()
	if _, e = s.Trigger(t.Context(), f.source); e != nil {
		t.Fatal(e)
	}
	if _, e = s.StartWorkers(t.Context()); e != nil {
		t.Fatal(e)
	}
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("genuine admission did not start")
	}
	bounded, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if e = s.CloseContext(bounded); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("callback cleanup falsely joined", e)
	}
	if other, e := Open(t.Context(), f.dir, f.config); e == nil {
		other.Close()
		t.Fatal("writer lease released with active callback")
	}
	close(blocked.release)
	bounded2, cancel2 := context.WithTimeout(t.Context(), time.Second)
	defer cancel2()
	if e = s.CloseContext(bounded2); e != nil {
		t.Fatal(e)
	}
	other, e := Open(t.Context(), f.dir, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	state, e := other.State(t.Context())
	if e != nil || state.Rows == 0 {
		t.Fatal("unconfirmed original work was discarded", state, e)
	}
}

// The admission fixture below composes the actual canonical node. Authentication
// is an independently reverified producer signature plus an opaque private grant
// issued only for the already-authorized retained action, not a wire principal.
type actionGrant struct{ request AdmissionRequest }
type actionAuthenticator struct{ store *Store }

func (a actionAuthenticator) Authenticate(ctx context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	grant, ok := r.PeerEvidence.(*actionGrant)
	if !ok || r.Audience != a.store.config.Scope.Audience || !bytes.Equal(r.ExactEnvelope, grant.request.Action.ExactEnvelope) {
		return fabric.ExecutionContext{}, denied()
	}
	original, v, e := a.store.verifySource(ctx, grant.request.Source)
	if e != nil {
		return fabric.ExecutionContext{}, e
	}
	action := grant.request.Action
	var envelope fabric.Envelope
	if fabric.DecodeJSON(r.ExactEnvelope, &envelope) != nil || envelope.Principal != v.Caller.PrincipalView() || envelope.Source != v.Caller.PrincipalView().Ref {
		return fabric.ExecutionContext{}, denied()
	}
	key := "emit"
	var definition *TriggerDefinition
	if action.DefinitionID != "" {
		d, ok := a.store.definitions[action.DefinitionID]
		if !ok || d.Revision != action.DefinitionRevision || a.store.config.DefinitionAuthority.Verify(ctx, a.store.config.Scope, cloneDefinition(d)) != nil {
			return fabric.ExecutionContext{}, denied()
		}
		key = d.ID + "@" + d.Revision
		definition = &d
	}
	id, lineage, e := actionIdentity(a.store.config.Scope, original, v, key, definition)
	expected, _ := json.Marshal(lineage)
	actual, _ := json.Marshal(envelope.Context)
	if e != nil || id != action.ID || envelope.ID != id || !bytes.Equal(expected, actual) || a.store.config.Authorizer.Check(ctx, v.Caller, cloneAction(action)) != nil {
		return fabric.ExecutionContext{}, denied()
	}
	p := fabric.Provenance{Origin: lineage.Origin, ParentID: lineage.ParentID, Hops: lineage.Hops, Ancestry: lineage.Ancestry, ExtensionChain: lineage.ExtensionChain, TriggerLineage: lineage.TriggerLineage}
	return fabric.NewAuthenticatedForwardContext(v.Caller.PrincipalView(), r.Audience, r.ExactEnvelope, p)
}

type inputEndpoint struct{ requests []fabric.InvokeRequest }

func (e *inputEndpoint) Invoke(_ context.Context, _ fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	e.requests = append(e.requests, r)
	return &completeFixtureStream{id: r.InvocationID}, nil
}

type completeFixtureStream struct {
	id   string
	next uint64
}

func (s *completeFixtureStream) Next(context.Context) (fabric.InvocationFrame, error) {
	s.next++
	if s.next > 2 {
		return fabric.InvocationFrame{}, io.EOF
	}
	kind := fabric.FrameStart
	if s.next == 2 {
		kind = fabric.FrameComplete
	}
	return fabric.InvocationFrame{InvocationID: s.id, Sequence: s.next - 1, Kind: kind}, nil
}
func (*completeFixtureStream) Close() error { return nil }

type nodeAdmission struct {
	ledger  *sqlAdmission
	service *node.Service
}

func (a nodeAdmission) AdmitOrGet(ctx context.Context, r AdmissionRequest) (AdmissionReceipt, error) {
	previous := a.ledger.effects
	receipt, e := a.ledger.AdmitOrGet(ctx, r)
	if e != nil {
		return receipt, e
	}
	if previous == a.ledger.effects {
		return receipt, nil
	}
	result, e := a.service.Execute(ctx, r.Action.ExactEnvelope, &actionGrant{r})
	if e != nil {
		return AdmissionReceipt{}, e
	}
	if result.Stream == nil {
		return AdmissionReceipt{}, errors.New("actual node did not invoke endpoint")
	}
	defer result.Stream.Close()
	for {
		_, e = result.Stream.Next(ctx)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return AdmissionReceipt{}, e
		}
	}
	return receipt, nil
}
func TestActualNodeReceivesRawApplicationPayloadWithoutRoutingWrapper(t *testing.T) {
	f := fixture(t, 1)
	s, e := Bootstrap(t.Context(), f.dir, f.config)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	endpoint := &inputEndpoint{}
	service, e := node.New(node.Config{Audience: f.config.Scope.Audience, Authenticator: actionAuthenticator{s}, Dispatcher: endpoint})
	if e != nil {
		t.Fatal(e)
	}
	s.config.Admitter = nodeAdmission{f.admit, service}
	if _, e = s.Trigger(t.Context(), f.source); e != nil {
		t.Fatal(e)
	}
	delivery := claim(t, s)
	if e = s.deliver(t.Context(), delivery.Event); e != nil {
		t.Fatal(e)
	}
	original, e := events.Decode(f.source.ExactEvent, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	if len(endpoint.requests) != 1 {
		t.Fatal("actual node endpoint invocation missing")
	}
	request := endpoint.requests[0]
	if !bytes.Equal(request.Input, original.Data()) || !bytes.Contains(request.Input, []byte("900719925474099312345")) || bytes.Contains(request.Input, []byte("idempotencyKey")) || bytes.Contains(request.Input, []byte("target")) {
		t.Fatal("endpoint received nested routing wrapper or lost application precision")
	}
	if request.Target != f.config.Definitions[0].Target || request.ExpectedRevision != "1" || request.InvocationID == "" || request.IdempotencyKey != request.InvocationID {
		t.Fatal("canonical header routing/context not preserved")
	}
	if e = s.deliver(t.Context(), delivery.Event); e != nil {
		t.Fatal(e)
	}
	if len(endpoint.requests) != 1 {
		t.Fatal("committed admission replayed endpoint")
	}
}

type mutatingDefinitionAuthority struct {
	inner DefinitionAuthority
	calls atomic.Int32
}

func (a *mutatingDefinitionAuthority) Verify(ctx context.Context, scope durable.Scope, d TriggerDefinition) error {
	a.calls.Add(1)
	e := a.inner.Verify(ctx, scope, d)
	clear(d.SignedAuthorization) // a callback must not mutate retained authority state
	return e
}
func TestIndexedMatchingAndVerifierMutationCannotAlterOwnedDefinitions(t *testing.T) {
	f := fixture(t, 1)
	for i := 0; i < 64; i++ {
		d := f.config.Definitions[0]
		d.ID = fmt.Sprintf("trigger.other%d", i)
		d.Type = "other.action"
		d.SignedAuthorization, _ = json.Marshal(ed25519.Sign(f.definitions.private, definitionBytes(d)))
		f.config.Definitions = append(f.config.Definitions, d)
	}
	verifier := &mutatingDefinitionAuthority{inner: f.definitions}
	f.config.DefinitionAuthority = verifier
	s, e := Bootstrap(t.Context(), f.dir, f.config)
	if e != nil {
		t.Fatal(e)
	}
	verifier.calls.Store(0)
	if _, e = s.Trigger(t.Context(), f.source); e != nil {
		t.Fatal(e)
	}
	if verifier.calls.Load() != 1 || len(s.matches[triggerKey{f.config.Definitions[0].Source, "test.action"}]) != 1 {
		t.Fatal("trigger lookup verified/scanned unrelated definitions")
	}
	if e = f.definitions.Verify(t.Context(), f.config.Scope, s.definitions[f.config.Definitions[0].ID]); e != nil {
		t.Fatal("verifier mutated indexed authority")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(t.Context(), f.dir, f.config)
	if e != nil {
		t.Fatal("mutating callback corrupted protected registration checkpoint", e)
	}
	defer s.Close()
	d := claim(t, s)
	verifier.calls.Store(0)
	if e = s.deliver(t.Context(), d.Event); e != nil {
		t.Fatal(e)
	}
	if verifier.calls.Load() != 1 {
		t.Fatal("delivery scanned unrelated definitions")
	}
}
