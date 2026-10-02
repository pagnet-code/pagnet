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

func TestActualNativeTaskParserOutputOriginalEncryption(t *testing.T) {
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
	owner, err := NewSessionOwner(context.Background(), j, NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: binary, MCPExecutable: binary, Workspace: t.TempDir(), NetworkID: network, NetworkTenantID: scope.TenantID, NetworkStateDir: keydir, TenantID: scope.TenantID, Kind: "worker"}, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	owner.generation = "actual-original-generation"
	owner.origin = json.RawMessage(`{"id":"` + uuid.NewString() + `","nativeGeneration":"actual-original-generation"}`)
	owner.sess.Env = owner.launchEnvironment("fixture-only-nonce")
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
	task := uuid.NewString()
	secret := "actual private native task text €"
	op := Operation{Input: secret, InputKind: "task", SourceCommandID: uuid.NewString(), SourceAdmissionID: uuid.NewString(), SourceTask: &transport.NativeTaskSource{TaskID: task, InputAAD: e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: scope.TenantID, NetworkID: network, ObjectType: e2ee.ObjectTypeTask, ObjectID: task, KeyEpochID: epoch.ID}}}
	raw, _ := json.Marshal(op)
	current := lease(t, j)
	out, execute, err := j.Admit(ctx, current, 1, "actual-original-command", "prompt", raw)
	if err != nil || !execute {
		t.Fatal(err)
	}
	owner.Execute(out, raw)
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
	if captured == nil || !captured.Event.NativeOutput || captured.OutputContent == nil || captured.NativeSessionID != sid || captured.TurnSource.SourceCommandID != op.SourceCommandID || captured.TurnSource.SourceAdmissionID != op.SourceAdmissionID {
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
	expected := "[fake-persist task] handled " + secret + ": " + secret
	if err != nil || string(plain) != expected {
		t.Fatal("actual parser output was not exact original text", err)
	}
	owner.Close()
	for _, name := range []string{"intents.sqlite", "intents.sqlite-wal"} {
		data, err := os.ReadFile(filepath.Join(j.dir, name))
		if err == nil && bytes.Contains(data, []byte(secret)) {
			t.Fatal("native text leaked into worker SQLite")
		}
	}
}
