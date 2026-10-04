package fabricnative

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type checkpointFence struct{}

func (checkpointFence) WithAdmission(_ context.Context, f identity.AdmissionFacts, next func(identity.Witness) error) error {
	return next(identity.Witness{Version: "actual-test-owner.v1", FinalizedDigest: f.FinalizedDigest, Value: json.RawMessage(`{"authenticated":true}`)})
}

func checkpointFixture(t *testing.T, options registry.Options) (*Checkpoints, OriginalCheckpoint, string) {
	t.Helper()
	ctx := t.Context()
	principal := fabric.Principal{Ref: "spiffe://checkpoint/owner", Kind: "local.owner", Issuer: "test.owner"}
	dir := filepath.Join(t.TempDir(), "domain")
	store, err := registry.BootstrapWithOptions(ctx, dir, principal, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	owner, err := fabric.NewAuthenticatedContext(principal, store.Namespace(), []byte("actual-owner-setup"))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "actor.agent", Name: "Maria", Description: "Original private role", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := identity.New(store, checkpointFence{})
	if err != nil {
		t.Fatal(err)
	}
	scope := identity.Scope{Endpoint: ref, DescriptorRevision: revision, BindingID: "native"}
	controller, err := authority.AcquireController(ctx, owner, scope, 0, "A", "request-A")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := authority.BindWorker(ctx, owner, controller, 0, identity.WorkerBinding{WorkerID: "actual-worker", StateDirectoryID: "actual-state", OwnershipGeneration: "actual-generation", ActualRuntime: "fixture-native", ProfileDigest: sha256.Sum256([]byte("original-executable"))})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(time.Hour)
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "original-invocation", Operation: fabric.OperationInvoke, Principal: principal, Source: principal.Ref, Target: &ref, ExpectedRevision: revision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"input":"` + strings.Repeat("private-source-marker-", 4200) + `"}`), Context: fabric.EnvelopeContext{Origin: principal.Ref, Deadline: &deadline}}
	original, _ := json.Marshal(env)
	original = append(original, '\n') // Exact historical whitespace must survive.
	caller, err := fabric.NewAuthenticatedContext(principal, store.Namespace(), original)
	if err != nil {
		t.Fatal(err)
	}
	final := bytes.TrimSuffix(original, []byte{'\n'})
	source, err := authority.Admit(ctx, owner, controller, binding, caller, original, final, "original-source", "attempt", "replay")
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte("operator-key-fixture"))
	protector, err := durable.NewAESGCM(durable.KeyReference{ID: "checkpoint-key", Version: "1"}, key[:])
	if err != nil {
		t.Fatal(err)
	}
	checkpoints, err := NewCheckpoints(store, authority, owner, protector)
	if err != nil {
		t.Fatal(err)
	}
	return checkpoints, OriginalCheckpoint{source, binding, original, final}, dir
}

func TestOriginalCheckpointExactEncryptedRestartAndIdentityIsolation(t *testing.T) {
	c, value, dir := checkpointFixture(t, registry.DefaultOptions())
	ctx := t.Context()
	id, err := c.Save(ctx, value)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, e := c.Save(ctx, value); e != nil || duplicate != id {
		t.Fatal("retry changed original checkpoint", e)
	}
	if err = c.store.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		raw, e := os.ReadFile(filepath.Join(dir, f.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(raw, []byte("private-source-marker-")) {
			t.Fatal("original input persisted plaintext")
		}
	}
	store, err := registry.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authority, err := identity.New(store, checkpointFence{})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := NewCheckpoints(store, authority, c.owner, c.protector)
	if err != nil {
		t.Fatal(err)
	}
	got, caller, err := reopened.Load(ctx, value.Admission.OriginalCaller, value.Admission.InvocationID)
	if err != nil || !bytes.Equal(got.Original, value.Original) || !bytes.Equal(got.Finalized, value.Finalized) {
		t.Fatal("original bytes changed on restart", err)
	}
	if _, err = caller.DecodeVerifiedEnvelope(value.Original, store.Namespace()); err != nil {
		t.Fatal(err)
	}
	if _, err = caller.DecodeVerifiedEnvelope(value.Finalized, store.Namespace()); err == nil {
		t.Fatal("historical context authenticated different final bytes")
	}
	foreign := value.Admission.OriginalCaller
	foreign.Issuer = "another"
	if _, _, err = reopened.Load(ctx, foreign, value.Admission.InvocationID); err == nil {
		t.Fatal("foreign principal loaded original source")
	}
	wrongKey := sha256.Sum256([]byte("wrong-operator-key"))
	wrong, _ := durable.NewAESGCM(c.key, wrongKey[:])
	wrongStore, _ := NewCheckpoints(store, authority, c.owner, wrong)
	if _, _, err = wrongStore.Load(ctx, value.Admission.OriginalCaller, value.Admission.InvocationID); err == nil {
		t.Fatal("wrong key restored source")
	}
	changed := value
	changed.Original = append(bytes.Clone(value.Original), ' ')
	if _, err = reopened.Save(ctx, changed); err == nil {
		t.Fatal("changed original admission saved")
	}
	// Actual signed but substituted ciphertext must also fail authenticated load.
	err = store.WithNativeAuthority(ctx, c.owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
		r, e := tx.Get(checkpointKey(id, 0))
		if e != nil {
			return e
		}
		var chunk struct {
			Ciphertext []byte `json:"ciphertext"`
		}
		if e = json.Unmarshal(r.Value, &chunk); e != nil {
			return e
		}
		chunk.Ciphertext[len(chunk.Ciphertext)-1] ^= 1
		raw, _ := json.Marshal(chunk)
		_, e = tx.CAS(r.Key, r.Revision, raw, false)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = reopened.Load(ctx, value.Admission.OriginalCaller, value.Admission.InvocationID); err == nil {
		t.Fatal("substituted ciphertext restored history")
	}
	if _, err = reopened.Save(ctx, value); err == nil {
		t.Fatal("retry regenerated corrupt original checkpoint")
	}
}

func TestOriginalCheckpointQuotaRollsBackEveryChunk(t *testing.T) {
	options := registry.DefaultOptions()
	options.Limits.MaxLedgerBytes = 100 << 10
	c, value, _ := checkpointFixture(t, options)
	if _, err := c.Save(t.Context(), value); err == nil {
		t.Fatal("checkpoint bypassed retained ledger quota")
	}
	id := checkpointID(value.Admission.OriginalCaller, value.Admission.InvocationID)
	err := c.store.WithNativeAuthority(t.Context(), c.owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
		for _, index := range []int{-1, 0, 1} {
			if _, e := tx.Get(checkpointKey(id, index)); e == nil {
				t.Fatal("partial checkpoint survived failed FULL transaction")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
