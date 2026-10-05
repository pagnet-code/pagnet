//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

func TestActualNativeInvocationParserOutputOriginalEncryption(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "b", "bin", "native")
	if err = os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	testBinary(t, root, binary, "./cmd/pagnet-fake-runtime", "")
	scope := testScope()
	scope.InstanceID = uuid.NewString()
	j, err := OpenJournal(filepath.Join(t.TempDir(), "worker"), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	network := uuid.NewString()
	keydir := t.TempDir()
	ring := hostcrypto.NewKeyring(network)
	epoch, err := ring.Activate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(keydir, ring); err != nil {
		t.Fatal(err)
	}
	spec := NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: binary, MCPExecutable: binary, Workspace: t.TempDir(), NetworkID: network, NetworkTenantID: scope.TenantID, NetworkStateDir: keydir, TenantID: scope.TenantID, Kind: "worker"}
	owner, err := NewSessionOwner(context.Background(), j, spec, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	owner.generation = "actual-original-generation"
	owner.origin = json.RawMessage(`{"id":"` + uuid.NewString() + `","nativeGeneration":"actual-original-generation"}`)
	owner.sess.Env, err = owner.launchEnvironment("fixture-only-nonce")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Seed only this isolated fixture's original registration identity; activate
	// through the real manager so its endpoint state is authentic.
	owner.manager.RegisterDriver(owner.driver)
	if _, err = owner.manager.EnsureActive(ctx, owner.sess, make(chan session.SessionEvent, 64)); err != nil {
		t.Fatal(err)
	}
	owner.manager.RegisterDriver(&ownedDriver{Driver: owner.driver, owner: owner})
	sid := owner.sess.NativeID
	invocation := "original-invocation"
	secret := "actual private native invocation text €"
	op := Operation{Input: secret, InputKind: "invocation", SourceCommandID: uuid.NewString(), SourceAdmissionID: uuid.NewString(), SourceInvocation: &transport.NativeInvocationSource{InvocationID: invocation, InputAAD: e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: scope.TenantID, NetworkID: network, ObjectType: e2ee.ObjectTypeInvocationInput, ObjectID: invocation, KeyEpochID: epoch.ID}}}
	raw, _ := json.Marshal(op)
	current := lease(t, j)
	grant := &Admission{NativeAdmissionID: op.SourceAdmissionID, Scope: scope, TenantID: scope.TenantID, NetworkID: network, Kind: "worker", RunnerID: uuid.NewString(), RunnerEpoch: time.Now().UTC(), BootID: uuid.NewString()}
	out, execute, err := j.admit(ctx, current, 1, op.SourceCommandID, "prompt", raw, func() (*Admission, error) { return grant, nil })
	if err != nil || !execute {
		t.Fatal(err)
	}
	if out.SourceAdmission == nil || out.SourceAdmission.NativeAdmissionID != op.SourceAdmissionID {
		t.Fatal("original admission not durably bound")
	}
	owner.Execute(out, raw)
	// The hosted adapter discovers the actual original generation from committed
	// operation provenance, never the current SID or a fabricated adoption spec.
	lookup := CloudInvocationSourceRequest{Sequence: out.Sequence, CommandID: op.SourceCommandID, AdmissionID: op.SourceAdmissionID, Invocation: *op.SourceInvocation}
	var observed *CloudInvocationSourceResult
	for {
		observed, err = j.cloudInvocationSource(ctx, current, lookup)
		if err != nil {
			t.Fatal("actual original source lookup", err)
		}
		if observed.Source != nil {
			break
		}
		if _, err = j.cloudReadiness.wait(ctx, observed.Ready); err != nil {
			t.Fatal("actual original source notification", err)
		}
	}
	if observed.Source.NativeSessionID != sid || observed.Source.NativeGeneration != owner.generation || observed.Source.SourceCommandID != op.SourceCommandID || observed.Source.SourceAdmissionID != op.SourceAdmissionID {
		t.Fatal("lookup replaced genuine original runtime provenance", observed.Source)
	}
	for {
		out, err = j.Outcome(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		if out.State != "admitted" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual native task did not settle", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if out.State != "completed" {
		t.Fatal("actual native task failed", out.State)
	}
	rows, err := j.PendingObservations(ctx, 32)
	if err != nil {
		t.Fatal(err)
	}
	var captured *NativeObservation
	for i := range rows {
		if rows[i].Event.Type == session.EventTurnOutput {
			captured = &rows[i]
		}
	}
	if captured == nil || !captured.Event.NativeOutput || captured.OutputContent == nil || captured.NativeSessionID != sid || captured.TurnSource.SourceCommandID != op.SourceCommandID || captured.TurnSource.SourceAdmissionID != op.SourceAdmissionID || captured.TurnSource.SourceTask != nil || captured.TurnSource.SourceInvocation == nil || captured.TurnSource.SourceInvocation.InvocationID != invocation {
		t.Fatal("genuine parser output lost original task source")
	}
	public, _ := json.Marshal(captured)
	if bytes.Contains(public, []byte(secret)) {
		t.Fatal("native task plaintext leaked to public observation")
	}
	var fragments []transport.NativeContentFragment
	for ordinal := 0; ordinal < captured.OutputContent.FragmentCount; ordinal++ {
		fragment, err := j.ReadContentFragment(ctx, current, captured.ID, captured.SourceDigest, captured.OutputContent.ContentID, ordinal)
		if err != nil {
			t.Fatal(err)
		}
		fragments = append(fragments, *fragment)
	}
	key, _ := epoch.KeyArray()
	plain, _, err := nativecontent.Open(*captured.OutputContent, fragments, key)
	expected := "[fake-persist invocation] handled " + secret + ": " + secret
	if err != nil || string(plain) != expected {
		t.Fatal("actual parser output was not exact original text", err)
	}
	source := *captured.TurnSource
	request := InvocationStreamRequest{Source: invocationIdentity(source)}
	sub, err := j.subscribeInvocationStream(ctx, owner.captureKey, current, request)
	if err != nil {
		t.Fatal(err)
	}
	request.SubscriptionID = sub.ID
	var streamed bytes.Buffer
	terminalSeen := false
	for !terminalSeen {
		if err = owner.projectInvocationStreams(ctx); err != nil {
			t.Fatal(err)
		}
		frame, readErr := j.readInvocationStream(ctx, owner.captureKey, current, request)
		if readErr != nil || frame == nil {
			t.Fatal("genuine invocation stream missing", readErr)
		}
		actual, openErr := OpenInvocationStreamProjection(*frame, source, scope.InstanceID, key)
		if openErr != nil {
			t.Fatal(openErr)
		}
		streamed.Write(actual.Data)
		if actual.Terminal != nil {
			terminalSeen = true
			if actual.Terminal.Event.Type != session.EventTurnCompleted || actual.Terminal.NativeSessionID != sid {
				t.Fatal("nonoriginal terminal")
			}
		}
		request.ProjectionOrdinal = frame.Ordinal
		request.Digest = frame.Digest
		if err = j.ackInvocationStream(ctx, owner.captureKey, current, request); err != nil {
			t.Fatal(err)
		}
	}
	if streamed.String() != expected {
		t.Fatal("private ledger did not preserve actual parser output")
	}
	owner.Close()
	for _, name := range []string{"intents.sqlite", "intents.sqlite-wal"} {
		data, err := os.ReadFile(filepath.Join(j.dir, name))
		if err == nil && bytes.Contains(data, []byte(secret)) {
			t.Fatal("native text leaked into worker SQLite")
		}
	}
}
