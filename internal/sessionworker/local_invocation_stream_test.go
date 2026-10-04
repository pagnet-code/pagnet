//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/fabric"
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/session"
)

type localStreamFixture struct {
	authorityFixture localAuthorityFixture
	accepted         nativeauthority.VerifiedIntent
	j                *Journal
	key              []byte
	lease            int64
	turn             NativeTurnSource
	producer         *nativeSourceProducer
	origin           json.RawMessage
}

func newLocalStreamFixture(t *testing.T, config LocalStreamConfig) localStreamFixture {
	return newLocalStreamFixtureWithBegin(t, config, true)
}
func newLocalStreamFixtureWithBegin(t *testing.T, config LocalStreamConfig, begin bool) localStreamFixture {
	t.Helper()
	f := newLocalAuthorityFixture(t)
	ctx := context.Background()
	j, e := OpenAuthorityJournal(filepath.Join(t.TempDir(), "worker"), f.scope)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { j.Close() })
	key := bytes.Repeat([]byte{6}, 32)
	if e = j.InitializeLocalInvocationStreams(ctx, key, config); e != nil {
		t.Fatal(e)
	}
	lease, e := j.AdvanceLease(ctx)
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().UTC().Add(time.Hour)
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "stream-invocation", Operation: fabric.OperationInvoke, Principal: f.owner.PrincipalView(), Source: f.owner.PrincipalView().Ref, Target: &f.binding.Scope.Endpoint, ExpectedRevision: f.binding.Scope.DescriptorRevision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"input":"private input"}`), Context: fabric.EnvelopeContext{Origin: f.owner.PrincipalView().Ref, Deadline: &deadline}}
	raw, _ := json.Marshal(env)
	caller, e := fabric.NewAuthenticatedContext(f.owner.PrincipalView(), f.authority.Identity().Namespace, raw)
	if e != nil {
		t.Fatal(e)
	}
	admission, e := f.authority.Admit(ctx, f.owner, f.controller, f.binding, caller, raw, raw, "stream-source-A", "attempt", "replay")
	if e != nil {
		t.Fatal(e)
	}
	binder := nativeauthority.JSONPromptBinder{ProfileDigest: f.binding.Worker.ProfileDigest}
	controller, e := nativeauthority.NewLocalController(f.authority, f.owner, f.binding, binder)
	if e != nil {
		t.Fatal(e)
	}
	var accepted nativeauthority.VerifiedIntent
	_, e = controller.AdmitIntent(ctx, f.controller, admission, caller, raw, raw, func(ctx context.Context, i nativeauthority.VerifiedIntent) (fabricidentity.NativeIntentReceipt, error) {
		accepted = i
		_, r, fresh, e := j.AdmitLocal(ctx, lease, binder, i)
		if !fresh && e == nil {
			t.Fatal("first admission wasn't fresh")
		}
		return r, e
	})
	if e != nil {
		t.Fatal(e)
	}
	origin, e := f.authority.RegisterOrigin(ctx, f.owner, f.controller, f.binding, admission, caller, raw, raw, "stream-origin", "native-generation")
	if e != nil {
		t.Fatal(e)
	}
	original, e := j.localIntentSource(ctx, j.db, accepted.Commitment.Sequence)
	if e != nil {
		t.Fatal(e)
	}
	if e = j.retainLocalActivation(ctx, key, LocalActivationRequest{Authority: f.scope, OriginalSource: *original, NativeGeneration: origin.NativeGeneration}, origin); e != nil {
		t.Fatal(e)
	}
	originRaw, _ := json.Marshal(origin)
	turn := NativeTurnSource{InputKind: "local-native", Sequence: accepted.Commitment.Sequence, LogicalTurnID: logicalWorkerTurn(accepted.Commitment.Sequence), NativeGeneration: origin.NativeGeneration, NativeSessionID: "native-session", SourceCommandID: accepted.Commitment.CommandID, SourceAdmissionID: admission.ID}
	if begin {
		if e = j.BindNativeTurn(ctx, turn); e != nil {
			t.Fatal(e)
		}
		if e = j.BeginLocalInvocationStream(ctx, key, turn); e != nil {
			t.Fatal(e)
		}
	}
	producer, e := j.registerNativeSource(ctx, turn.NativeGeneration, originRaw)
	if e != nil {
		t.Fatal(e)
	}
	return localStreamFixture{authorityFixture: f, accepted: accepted, j: j, key: key, lease: lease, turn: turn, producer: producer, origin: originRaw}
}
func (f localStreamFixture) output(t *testing.T, id, text string) error {
	t.Helper()
	_, _, e := f.j.appendOutputDeltas(context.Background(), f.producer, f.key, f.turn, []session.SessionEvent{{Type: session.EventTurnOutput, SessionID: f.turn.NativeSessionID, TurnID: f.turn.LogicalTurnID, Output: text, NativeOutput: true}}, id, [32]byte{}, false)
	return e
}
func (f localStreamFixture) lifecycle(t *testing.T, id, kind string) error {
	t.Helper()
	event := session.SessionEvent{Type: kind, SessionID: f.turn.NativeSessionID, TurnID: f.turn.LogicalTurnID}
	if kind == session.EventSessionStopped {
		event.TurnID = ""
	}
	o := NativeObservation{localInvocationEvent: &event, invocationCaptureKey: f.key, ID: id, NativeGeneration: f.turn.NativeGeneration, NativeSessionID: f.turn.NativeSessionID, Origin: f.origin, ObservedAt: time.Now().UTC(), Event: event, TurnSource: &f.turn}
	if kind == session.EventSessionStopped {
		o.TurnSource = nil
	}
	o.SourceDigest, _ = observationDigest(o)
	return f.j.journalCapturedObservation(context.Background(), f.producer, o, nil)
}
func localPageFrames(t *testing.T, f localStreamFixture, after int64) (LocalInvocationPage, []fabric.InvocationFrame) {
	t.Helper()
	page, e := f.j.LocalStreamPage(context.Background(), f.key, f.lease, f.turn.Sequence, after, 4)
	if e != nil {
		t.Fatal(e)
	}
	var frames []fabric.InvocationFrame
	for _, cipher := range page.Frames {
		frame, e := OpenLocalInvocationFrame(f.key, f.j.authority, f.j.dir, page.Source, cipher)
		if e != nil {
			t.Fatal(e)
		}
		frames = append(frames, frame)
	}
	return page, frames
}
func TestLocalInvocationFramesSameDeltaCommitRetryAndTerminal(t *testing.T) {
	f := newLocalStreamFixture(t, DefaultLocalStreamConfig())
	text := strings.Repeat("private output ", 3500)
	if e := f.output(t, "original-delta", text); e != nil {
		t.Fatal(e)
	}
	if e := f.output(t, "original-delta", text); e != nil {
		t.Fatal("exact delta retry", e)
	}
	page, frames := localPageFrames(t, f, -1)
	if len(frames) != 3 || frames[0].Kind != fabric.FrameStart || string(frames[1].Data)+string(frames[2].Data) != text || page.Terminal {
		t.Fatalf("early exact stream %#v", frames)
	}
	for _, c := range page.Frames {
		if len(c.Ciphertext) > 64<<10 || bytes.Contains(c.Ciphertext, []byte("private output")) {
			t.Fatal("frame leaked or exceeded bound")
		}
	}
	if e := f.lifecycle(t, "actual-completed", session.EventTurnCompleted); e != nil {
		t.Fatal(e)
	}
	finalPage, final := localPageFrames(t, f, 2)
	if len(final) != 1 || final[0].Kind != fabric.FrameComplete || !finalPage.Terminal {
		t.Fatal("missing genuine terminal", final)
	}
	if e := f.j.AckLocalStream(context.Background(), f.key, f.lease, f.turn.Sequence, 2, page.Frames[2].Digest); e != nil {
		t.Fatal(e)
	}
	if _, e := f.j.LocalStreamPage(context.Background(), f.key, f.lease, f.turn.Sequence, -1, 4); !errors.Is(e, ErrRetired) {
		t.Fatal("pruned prefix returned", e)
	}
	if e := f.j.AckLocalStream(context.Background(), f.key, f.lease, f.turn.Sequence, 3, finalPage.Frames[0].Digest); e != nil {
		t.Fatal(e)
	}
	if e := f.j.InitializeLocalInvocationStreams(context.Background(), f.key, DefaultLocalStreamConfig()); e != nil {
		t.Fatal("authenticated floor", e)
	}
	if e := f.j.BeginLocalInvocationStream(context.Background(), f.key, f.turn); e != nil {
		t.Fatal("retry recreated or lost source", e)
	}
	page, frames = localPageFrames(t, f, 3)
	if len(frames) != 0 || page.Floor != 3 || !page.Terminal {
		t.Fatal("terminal floor changed")
	}
}
func TestLocalInvocationFramesRollbackSourceAndCryptoFences(t *testing.T) {
	f := newLocalStreamFixture(t, DefaultLocalStreamConfig())
	if _, e := f.j.db.Exec(`CREATE TRIGGER deny_local_frame BEFORE INSERT ON worker_local_stream_frames BEGIN SELECT RAISE(ABORT,'fixture rollback'); END`); e != nil {
		t.Fatal(e)
	}
	if e := f.output(t, "delta", "original"); e == nil {
		t.Fatal("injected tx failure accepted")
	}
	var output, frames int
	f.j.db.QueryRow(`SELECT COUNT(*) FROM worker_output_deltas`).Scan(&output)
	f.j.db.QueryRow(`SELECT COUNT(*) FROM worker_local_stream_frames`).Scan(&frames)
	if output != 0 || frames != 0 {
		t.Fatal("partial output/frame commit", output, frames)
	}
	f.j.db.Exec(`DROP TRIGGER deny_local_frame`)
	if e := f.output(t, "delta", "original"); e != nil {
		t.Fatal(e)
	}
	page, _ := localPageFrames(t, f, -1)
	c := page.Frames[1]
	for _, change := range []func(*LocalStreamSource, *LocalInvocationCipherFrame){func(s *LocalStreamSource, c *LocalInvocationCipherFrame) { c.Cursor++ }, func(s *LocalStreamSource, c *LocalInvocationCipherFrame) { s.Turn.NativeGeneration = "changed" }, func(s *LocalStreamSource, c *LocalInvocationCipherFrame) {
		s.Original.Admission.OriginalCaller.Issuer = "changed"
	}, func(s *LocalStreamSource, c *LocalInvocationCipherFrame) {
		c.Ciphertext = bytes.Clone(c.Ciphertext)
		c.Ciphertext[len(c.Ciphertext)-1] ^= 1
		c.Digest = localCipherDigest(c.Ciphertext)
	}} {
		source := page.Source
		cipher := c
		change(&source, &cipher)
		if _, e := OpenLocalInvocationFrame(f.key, f.j.authority, f.j.dir, source, cipher); e == nil {
			t.Fatal("forged frame accepted")
		}
	}
	if _, e := OpenLocalInvocationFrame(f.key, f.j.authority, f.j.dir+"-changed", page.Source, c); e == nil {
		t.Fatal("directory transplant accepted")
	}
	if e := f.j.AckLocalStream(context.Background(), f.key, f.lease+1, f.turn.Sequence, c.Cursor, c.Digest); !errors.Is(e, ErrFenced) {
		t.Fatal("stale lease ACK", e)
	}
	if e := f.j.InitializeLocalInvocationStreams(context.Background(), bytes.Repeat([]byte{9}, 32), DefaultLocalStreamConfig()); e == nil {
		t.Fatal("wrong key accepted")
	}
	f.j.db.Exec(`DELETE FROM worker_local_stream_frames WHERE cursor=1`)
	if e := f.j.InitializeLocalInvocationStreams(context.Background(), f.key, DefaultLocalStreamConfig()); e == nil {
		t.Fatal("missing frame not detected")
	}
}
func TestLocalInvocationCapacityAndGenuineStopUnknown(t *testing.T) {
	f := newLocalStreamFixture(t, LocalStreamConfig{MaxFrames: 3, MaxBytes: 1 << 20, MaxSources: 4})
	if e := f.output(t, "small", "small"); e != nil {
		t.Fatal(e)
	}
	if e := f.output(t, "too-much", "second"); !errors.Is(e, ErrFull) {
		t.Fatal("capacity not enforced", e)
	}
	page, frames := localPageFrames(t, f, -1)
	if len(frames) != 2 {
		t.Fatal("partial overflow")
	}
	if e := f.j.AckLocalStream(context.Background(), f.key, f.lease, f.turn.Sequence, 1, page.Frames[1].Digest); e != nil {
		t.Fatal(e)
	}
	if e := f.lifecycle(t, "original-EOF", session.EventSessionStopped); e != nil {
		t.Fatal(e)
	}
	_, frames = localPageFrames(t, f, 1)
	if len(frames) != 1 || frames[0].Kind != fabric.FrameError || frames[0].Error == nil || frames[0].Error.Effect != fabric.EffectUnknown {
		t.Fatal("EOF invented completion", frames)
	}
}

func TestLocalInvocationRestartAndStaleFloorNeverRegenerates(t *testing.T) {
	f := newLocalStreamFixture(t, DefaultLocalStreamConfig())
	text := strings.Repeat("ação🙂", 8000)
	if e := f.output(t, "utf8-original", text); e != nil {
		t.Fatal(e)
	}
	page, frames := localPageFrames(t, f, -1)
	var reconstructed []byte
	for _, frame := range frames {
		reconstructed = append(reconstructed, frame.Data...)
	}
	if string(reconstructed) != text {
		t.Fatal("unicode output altered")
	}
	dir, scope := f.j.dir, f.j.authority
	f.j.Close()
	reopened, e := OpenAuthorityJournal(dir, scope)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	f.j = reopened
	if e = f.j.InitializeLocalInvocationStreams(context.Background(), f.key, DefaultLocalStreamConfig()); e != nil {
		t.Fatal("restart", e)
	}
	f.lease, e = f.j.AdvanceLease(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	retained, _ := localPageFrames(t, f, -1)
	if !page.Readiness.valid() || !retained.Readiness.valid() || retained.Readiness.Boot == page.Readiness.Boot {
		t.Fatal("Genuine restart reused invalid or previous notification boot")
	}
	// A new worker notification boot cannot rewrite original signed source
	// identity or any retained ciphertext/frame/floor/terminal evidence.
	page.Readiness = ReadinessToken{}
	retained.Readiness = ReadinessToken{}
	if !sameLocalJSON(retained, page) {
		t.Fatal("restarted stream changed original evidence")
	}
	last := page.Frames[len(page.Frames)-1]
	if e = f.j.AckLocalStream(context.Background(), f.key, f.lease, f.turn.Sequence, last.Cursor, last.Digest); e != nil {
		t.Fatal(e)
	}
	if e = f.j.InitializeLocalInvocationStreams(context.Background(), f.key, DefaultLocalStreamConfig()); e != nil {
		t.Fatal("floor integrity", e)
	}
	if _, e = f.j.LocalStreamPage(context.Background(), f.key, f.lease, f.turn.Sequence, -1, 4); !errors.Is(e, ErrRetired) {
		t.Fatal("old cursor resurrected", e)
	}
}

func TestLocalInvocationLaterTurnRetainsFirstActivationAdmission(t *testing.T) {
	f := newLocalStreamFixture(t, DefaultLocalStreamConfig())
	ctx := context.Background()
	a := f.authorityFixture
	if e := f.lifecycle(t, "first-complete", session.EventTurnCompleted); e != nil {
		t.Fatal(e)
	}
	first, _ := localPageFrames(t, f, -1)
	if e := f.j.Settle(ctx, f.turn.Sequence, "completed", json.RawMessage(`{}`)); e != nil {
		t.Fatal(e)
	}
	if e := f.j.Acknowledge(ctx, f.lease, f.turn.Sequence); e != nil {
		t.Fatal(e)
	}
	if _, e := f.j.localIntentSource(ctx, f.j.db, f.turn.Sequence); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("first source not pruned", e)
	}
	deadline := time.Now().UTC().Add(time.Hour)
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "later-invocation", Operation: fabric.OperationInvoke, Principal: a.owner.PrincipalView(), Source: a.owner.PrincipalView().Ref, Target: &a.binding.Scope.Endpoint, ExpectedRevision: a.binding.Scope.DescriptorRevision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"input":"later task"}`), Context: fabric.EnvelopeContext{Origin: a.owner.PrincipalView().Ref, Deadline: &deadline}}
	raw, _ := json.Marshal(env)
	caller, e := fabric.NewAuthenticatedContext(a.owner.PrincipalView(), a.authority.Identity().Namespace, raw)
	if e != nil {
		t.Fatal(e)
	}
	source, e := a.authority.Admit(ctx, a.owner, a.controller, a.binding, caller, raw, raw, "later-source-B", "later-attempt", "later-replay")
	if e != nil {
		t.Fatal(e)
	}
	binder := nativeauthority.JSONPromptBinder{ProfileDigest: a.binding.Worker.ProfileDigest}
	controller, e := nativeauthority.NewLocalController(a.authority, a.owner, a.binding, binder)
	if e != nil {
		t.Fatal(e)
	}
	var accepted nativeauthority.VerifiedIntent
	_, e = controller.AdmitIntent(ctx, a.controller, source, caller, raw, raw, func(ctx context.Context, i nativeauthority.VerifiedIntent) (fabricidentity.NativeIntentReceipt, error) {
		accepted = i
		_, r, _, e := f.j.AdmitLocal(ctx, f.lease, binder, i)
		return r, e
	})
	if e != nil {
		t.Fatal(e)
	}
	f.turn.Sequence = accepted.Commitment.Sequence
	f.turn.LogicalTurnID = logicalWorkerTurn(f.turn.Sequence)
	f.turn.SourceCommandID = accepted.Commitment.CommandID
	f.turn.SourceAdmissionID = source.ID
	if e = f.j.BindNativeTurn(ctx, f.turn); e != nil {
		t.Fatal(e)
	}
	if e = f.j.BeginLocalInvocationStream(ctx, f.key, f.turn); e != nil {
		t.Fatal("later begin requires pruned first admission", e)
	}
	if e = f.output(t, "later-output", "second turn"); e != nil {
		t.Fatal(e)
	}
	later, frames := localPageFrames(t, f, -1)
	if later.Source.Original.Admission.ID != source.ID || later.Source.ActivationAdmission.ID != first.Source.ActivationAdmission.ID || later.Source.ActivationAdmission.ID == source.ID || !sameLocalJSON(later.Source.ActivationOrigin, first.Source.ActivationOrigin) || frames[0].InvocationID != "later-invocation" {
		t.Fatal("conversation origin substituted for new invocation")
	}
}

func TestLocalInteractionIdentityUsesRealAuthorityCloudBytesPreserved(t *testing.T) {
	origin := json.RawMessage(`{"id":"server-origin"}`)
	old := []byte(`{"Domain":"pagnet-native-interaction-identity-v1","Scope":{"serverUrl":"https://control.invalid","tenantId":"tenant","accountId":"account","hostId":"host","instanceId":"instance","generation":"generation"},"OriginID":"server-origin","NativeGeneration":"native-generation","NativeSessionID":"native-session","NativeInteractionID":"native-permission"}`)
	golden := uuid.NewHash(sha256.New(), uuid.NameSpaceOID, old, 8).String()
	if got := nativeInteractionIdentity(testScope(), origin, "native-generation", "native-session", "native-permission"); got != golden {
		t.Fatal("Cloud identity bytes changed", got, golden)
	}
	a := newLocalAuthorityFixture(t)
	b := newLocalAuthorityFixture(t)
	actual := nativeInteractionIdentityBound(a.scope, origin, "native-generation", "native-session", "native-permission")
	other := nativeInteractionIdentityBound(b.scope, origin, "native-generation", "native-session", "native-permission")
	zeroCloud := nativeInteractionIdentity(Scope{}, origin, "native-generation", "native-session", "native-permission")
	if actual == "" || actual == other || actual == zeroCloud || actual == golden {
		t.Fatal("local interaction inherited another domain or Cloud identity")
	}
	if nativeInteractionIdentityBound(AuthorityScope{}, origin, "native-generation", "native-session", "native-permission") != "" {
		t.Fatal("invalid authority accepted")
	}
}

func TestLocalInvocationPageExactAdmissionBeforeBeginIsPending(t *testing.T) {
	f := newLocalStreamFixtureWithBegin(t, DefaultLocalStreamConfig(), false)
	ctx := context.Background()
	page, e := f.j.LocalStreamPage(ctx, f.key, f.lease, f.turn.Sequence, -1, 4)
	if !page.Readiness.valid() {
		t.Fatal("Authenticated pending admission omitted readiness")
	}
	page.Readiness = ReadinessToken{}
	if !errors.Is(e, ErrLocalInvocationNotReady) || !reflect.DeepEqual(page, LocalInvocationPage{}) {
		t.Fatal("pre-materialization invented stream/source", e)
	}
	if _, e = f.j.LocalStreamPage(ctx, f.key, f.lease, f.turn.Sequence+1, -1, 4); !errors.Is(e, ErrRetired) {
		t.Fatal("never-admitted pending", e)
	}
	denied, deniedErr := f.j.LocalStreamPage(ctx, bytes.Repeat([]byte{9}, 32), f.lease, f.turn.Sequence, -1, 4)
	if deniedErr == nil || errors.Is(deniedErr, ErrLocalInvocationNotReady) || !reflect.DeepEqual(denied, LocalInvocationPage{}) {
		t.Fatal("Wrong key saw pending source/readiness", deniedErr)
	}
	denied, deniedErr = f.j.LocalStreamPage(ctx, f.key, f.lease+1, f.turn.Sequence, -1, 4)
	if deniedErr == nil || !reflect.DeepEqual(denied, LocalInvocationPage{}) {
		t.Fatal("Foreign lease saw pending source/readiness", deniedErr)
	}
	if e = f.j.Settle(ctx, f.turn.Sequence, "uncertain", json.RawMessage(`{}`)); e != nil {
		t.Fatal(e)
	}
	_, e = f.j.LocalStreamPage(ctx, f.key, f.lease, f.turn.Sequence, -1, 4)
	var failure *fabric.Error
	if !errors.As(e, &failure) || failure.Effect != fabric.EffectUnknown || errors.Is(e, ErrLocalInvocationNotReady) {
		t.Fatal("uncertain admission stayed pending", e)
	}
	if e = f.j.Acknowledge(ctx, f.lease, f.turn.Sequence); e != nil {
		t.Fatal(e)
	}
	if _, e = f.j.LocalStreamPage(ctx, f.key, f.lease, f.turn.Sequence, -1, 4); !errors.Is(e, ErrRetired) {
		t.Fatal("retired source pending", e)
	}
}

func TestLocalInvocationCancelledBeforeBeginIsUnknownNotPending(t *testing.T) {
	f := newLocalStreamFixtureWithBegin(t, DefaultLocalStreamConfig(), false)
	binder := nativeauthority.JSONPromptBinder{ProfileDigest: f.authorityFixture.binding.Worker.ProfileDigest}
	if e := f.j.requestLocalCancellation(context.Background(), f.lease, binder, f.accepted); e != nil {
		t.Fatal(e)
	}
	page, e := f.j.LocalStreamPage(context.Background(), f.key, f.lease, f.turn.Sequence, -1, 4)
	var failure *fabric.Error
	if !errors.As(e, &failure) || failure.Code != fabric.CodeCancelled || failure.Effect != fabric.EffectUnknown || !reflect.DeepEqual(page, LocalInvocationPage{}) {
		t.Fatal("cancellation manufactured pending/completion/source", e)
	}
}

// Public pull frames project bytes, while original provider fragments remain
// independently sealed and hash-bound in the same admitted transaction.
func TestLocalInvocationBatchProjectionPreservesOriginalEvidence(t *testing.T) {
	for _, text := range []string{"8-bytes!", strings.Repeat("a", 1023) + "🙂ação"} {
		t.Run(fmt.Sprintf("bytes-%d", len(text)), func(t *testing.T) {
			f := newLocalStreamFixture(t, DefaultLocalStreamConfig())
			events := make([]session.SessionEvent, session.NativeOutputBatchMaxEvents)
			for i := range events {
				events[i] = session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, SessionID: f.turn.NativeSessionID, TurnID: f.turn.LogicalTurnID, Output: text}
			}
			// A rejected public projection must roll back all original rows too.
			if _, e := f.j.db.Exec(`CREATE TRIGGER deny_batch_projection BEFORE INSERT ON worker_local_stream_frames WHEN NEW.cursor=1 BEGIN SELECT RAISE(ABORT,'fixture rollback'); END`); e != nil {
				t.Fatal(e)
			}
			if _, _, e := f.j.appendOutputDeltas(context.Background(), f.producer, f.key, f.turn, events, "exact-native-batch", [32]byte{}, false); e == nil {
				t.Fatal("injected projection failure accepted")
			}
			for _, table := range []string{"worker_output_deltas", "worker_local_stream_frames"} {
				if sourceCount(t, f.j, table) != 0 {
					t.Fatal("partial transaction after projection failure", table)
				}
			}
			if _, e := f.j.db.Exec(`DROP TRIGGER deny_batch_projection`); e != nil {
				t.Fatal(e)
			}
			data, count, e := f.j.appendOutputDeltas(context.Background(), f.producer, f.key, f.turn, events, "exact-native-batch", [32]byte{}, false)
			if e != nil || count != len(events) || data.DeltaCount != int64(len(events)) {
				t.Fatal("original batch admission", count, e)
			}
			aead, e := captureAEADBound(f.key, f.j.privateCaptureAuthority(), f.j.dir)
			if e != nil {
				t.Fatal(e)
			}
			var rolling []byte
			for i, event := range events {
				var sealed []byte
				if e := f.j.db.QueryRow(`SELECT ciphertext FROM worker_output_deltas WHERE sequence=? AND ordinal=?`, f.turn.Sequence, i+1).Scan(&sealed); e != nil {
					t.Fatal(e)
				}
				raw, e := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], outputDeltaAADBound(f.j.privateCaptureAuthority(), f.j.dir, f.turn.NativeGeneration, f.turn.Sequence, int64(i+1)))
				want, _ := canonicalNativeJSON(event)
				if e != nil || !bytes.Equal(raw, want) {
					t.Fatal("original native event changed", i, e)
				}
				h := sha256.New()
				h.Write(rolling)
				h.Write(want)
				rolling = h.Sum(nil)
			}
			if data.RollingDigest != hex.EncodeToString(rolling) {
				t.Fatal("original rolling commitment changed")
			}
			page, frames := localPageFrames(t, f, -1)
			var projected []byte
			for _, frame := range frames {
				if len(frame.Data) > 32<<10 || !utf8.Valid(frame.Data) {
					t.Fatal("unbounded or split UTF8 projection")
				}
				projected = append(projected, frame.Data...)
			}
			if frames[0].Kind != fabric.FrameStart || len(frames) > 3 || string(projected) != strings.Repeat(text, len(events)) {
				t.Fatal("provider fragmentation leaked into byte projection", len(frames))
			}
			if _, count, e = f.j.appendOutputDeltas(context.Background(), f.producer, f.key, f.turn, events, "exact-native-batch", [32]byte{}, false); e != nil || count != len(events) {
				t.Fatal("exact FULL retry", count, e)
			}
			replay, _ := localPageFrames(t, f, -1)
			if !page.Readiness.valid() || replay.Readiness.Boot != page.Readiness.Boot || replay.Readiness.Counter < page.Readiness.Counter {
				t.Fatal("Authentic batch retry changed notification boot or reset counter")
			}
			// Readiness reports a commit reconciliation, not immutable source
			// identity. Every source field and exact sealed frame stays equal.
			page.Readiness = ReadinessToken{}
			replay.Readiness = ReadinessToken{}
			if !reflect.DeepEqual(page, replay) || sourceCount(t, f.j, "worker_output_deltas") != len(events) {
				t.Fatal("retry duplicated original rows or projection")
			}
		})
	}
}

func TestLocalInvocationStoppedTerminalSurvivesFullContentCredit(t *testing.T) {
	f := newLocalStreamFixture(t, LocalStreamConfig{MaxFrames: 3, MaxBytes: 1 << 20, MaxSources: 4})
	if e := f.output(t, "exact-output", "retained before stop"); e != nil {
		t.Fatal(e)
	}
	if e := f.output(t, "exhausted-output", "not admitted"); !errors.Is(e, ErrFull) {
		t.Fatal("content credit did not exhaust", e)
	}
	// No ACK releases content credit. Only genuine observed EOF can consume
	// the reserved terminal slot; it reports unknown, never successful finish.
	if e := f.lifecycle(t, "actual-reader-EOF", session.EventSessionStopped); e != nil {
		t.Fatal("stopped terminal blocked behind full content", e)
	}
	page, frames := localPageFrames(t, f, -1)
	if len(frames) != 3 || !page.Terminal || string(frames[1].Data) != "retained before stop" || frames[2].Kind != fabric.FrameError || frames[2].Error == nil || frames[2].Error.Effect != fabric.EffectUnknown {
		t.Fatal("full content lost source or fabricated completion")
	}
}

func TestLocalInvocationBatchProjectionFlushesBeforeSplitRune(t *testing.T) {
	f := newLocalStreamFixture(t, DefaultLocalStreamConfig())
	texts := []string{strings.Repeat("a", (32<<10)-1), "🙂ação"}
	events := make([]session.SessionEvent, len(texts))
	for i, text := range texts {
		events[i] = session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, SessionID: f.turn.NativeSessionID, TurnID: f.turn.LogicalTurnID, Output: text}
	}
	if _, n, e := f.j.appendOutputDeltas(context.Background(), f.producer, f.key, f.turn, events, "actual-rune-edge", [32]byte{}, false); e != nil || n != len(events) {
		t.Fatal(n, e)
	}
	_, frames := localPageFrames(t, f, -1)
	if len(frames) != 3 || string(frames[1].Data) != texts[0] || string(frames[2].Data) != texts[1] || !utf8.Valid(frames[1].Data) || !utf8.Valid(frames[2].Data) {
		t.Fatal("projection split a rune at batch event boundary")
	}
}
