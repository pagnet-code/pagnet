//go:build unix

package daemon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/transport"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func preparedOwnerDaemon(t *testing.T) (*Daemon, transport.PrepareProtectedContextPayload, transport.ProtectedContextReadyPayload) {
	t.Helper()
	d := newCryptoDaemon(t)
	host := domain.NewID().String()
	if err := d.state.KVSet("host_id", host); err != nil {
		t.Fatal(err)
	}
	instance := domain.NewID().String()
	if err := d.state.UpsertInstance(InstanceRow{InstanceID: instance, Status: "idle", Kind: "representative"}); err != nil {
		t.Fatal(err)
	}
	identity, err := d.cryptoManager().hostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	c := e2ee.ProtectedContext{Kind: e2ee.OwnerContextKind, ID: domain.NewID().String(), TenantID: domain.NewID().String(), OwnerUserID: domain.NewID().String(), HostID: host}
	p := transport.PrepareProtectedContextPayload{CommandID: domain.NewID().String(), InstanceID: instance, Context: c, HostX25519: base64.StdEncoding.EncodeToString(identity.X25519Pub), HostEd25519: base64.StdEncoding.EncodeToString(identity.Ed25519Pub)}
	result, err := d.doPrepareProtectedContext(p)
	if err != nil {
		t.Fatal(err)
	}
	return d, p, result.(transport.ProtectedContextReadyPayload)
}
func TestOwnerContextRotationIdempotentAndMissingKeysFailClosed(t *testing.T) {
	d, p, first := preparedOwnerDaemon(t)
	p.Rotate = true
	p.ExpectedEpochID = first.EpochID
	p.CommandID = domain.NewID().String()
	a, err := d.doPrepareProtectedContext(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.doPrepareProtectedContext(p)
	if err != nil {
		t.Fatal(err)
	}
	if a.(transport.ProtectedContextReadyPayload).EpochID == first.EpochID || a.(transport.ProtectedContextReadyPayload) != b.(transport.ProtectedContextReadyPayload) {
		t.Fatal("rotation was not one durable signed result")
	}
	ring, err := crypto.LoadContextKeyring(d.StateDir, p.Context)
	if err != nil {
		t.Fatal(err)
	}
	if len(ring.Epochs) != 2 {
		t.Fatal("rotation redelivery minted extra keys")
	}
	path := filepath.Join(d.StateDir, "e2ee", "contexts", p.Context.ID, "keyring.json")
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	p.CommandID = domain.NewID().String()
	p.ExpectedEpochID = ""
	p.Rotate = false
	if _, err = d.doPrepareProtectedContext(p); err == nil {
		t.Fatal("lost key was silently replaced")
	}
}
func TestOwnerContextInspectionProofAndAuthenticatedObjectUnwrap(t *testing.T) {
	d, p, ready := preparedOwnerDaemon(t)
	payload := transport.InteractionEventPayload{InteractionID: domain.NewID().String(), InstanceID: p.InstanceID, SessionID: "native-session", NativeInteractionID: "owned-generation-approval", Kind: "permission", Options: []domain.RuntimeInteractionOption{{ID: "allow", Kind: "allow_once"}, {ID: "deny", Kind: "reject_once"}}}
	observed, ok := d.observeOwnerInteraction(payload, &agentruntime.InteractionEvent{Summary: "private tool invocation", NativePayload: json.RawMessage(`{"path":"private-file"}`)})
	if !ok || observed.Summary != "" || observed.NativePayload != nil || observed.DetailEnvelope == nil {
		t.Fatal("private detail not protected")
	}
	ring, err := crypto.LoadContextKeyring(d.StateDir, p.Context)
	if err != nil {
		t.Fatal(err)
	}
	epoch, _ := ring.ActiveEpoch()
	key, _ := epoch.KeyArray()
	plain, err := e2ee.Decrypt(*observed.DetailEnvelope, key, *observed.DetailAAD)
	if err != nil {
		t.Fatal(err)
	}
	var detail transport.OwnerInteractionDetail
	if err = json.Unmarshal(plain, &detail); err != nil {
		t.Fatal(err)
	}
	secret, err := base64.StdEncoding.DecodeString(detail.Inspection.Secret)
	if err != nil {
		t.Fatal(err)
	}
	resolve := transport.ResolveRuntimeInteractionPayload{InstanceID: p.InstanceID, SessionID: payload.SessionID, NativeInteractionID: payload.NativeInteractionID, InteractionID: payload.InteractionID, OptionID: "allow"}
	if d.verifyOwnerApproval(resolve) == nil {
		t.Fatal("allow without inspection accepted")
	}
	proof, err := e2ee.ApprovalProof(secret, *observed.DetailAAD, resolve.InstanceID, resolve.SessionID, resolve.NativeInteractionID, resolve.OptionID)
	if err != nil {
		t.Fatal(err)
	}
	resolve.InspectionProof = base64.StdEncoding.EncodeToString(proof)
	if err = d.verifyOwnerApproval(resolve); err != nil {
		t.Fatal(err)
	}
	resolve.NativeInteractionID = "new-generation"
	if d.verifyOwnerApproval(resolve) == nil {
		t.Fatal("stale native generation accepted")
	}
	resolve.NativeInteractionID = payload.NativeInteractionID
	resolve.OptionID = "deny"
	resolve.InspectionProof = ""
	if err = d.verifyOwnerApproval(resolve); err != nil {
		t.Fatal("reject requires inspection", err)
	}
	browser, err := crypto.NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	session := domain.NewID().String()
	start := transport.CryptoSessionStartPayload{EpochID: ready.EpochID, ProtectedContext: &p.Context, TenantID: p.Context.TenantID, UserID: p.Context.OwnerUserID, SessionID: session, BrowserPub: base64.StdEncoding.EncodeToString(browser.X25519Pub)}
	if _, err = d.ownerSessionStart(start); err != nil {
		t.Fatal(err)
	}
	changed := start
	changed.BrowserPub = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	if _, err = d.ownerSessionStart(changed); err == nil {
		t.Fatal("session public key rebound")
	}
	request := transport.CryptoUnwrapCekPayload{ProtectedContext: &p.Context, TenantID: p.Context.TenantID, SessionID: session, Objects: []transport.CryptoUnwrapCekObject{{ObjectID: payload.InteractionID, Envelope: *observed.DetailEnvelope, AAD: observed.DetailAAD}}}
	result, err := d.ownerUnwrap(request)
	if err != nil {
		t.Fatal(err)
	}
	items := result.(*transport.CryptoUnwrapCekResult).Results
	if len(items) != 1 || items[0].WrappedCek == nil {
		t.Fatalf("valid unwrap failed: %+v", items)
	}
	cek, err := e2ee.HPKEUnwrap(browser.X25519Priv, items[0].WrappedCek.Enc, []byte(e2ee.HPKEInfoOwnerCEK), e2ee.OwnerBrowserSessionAAD(p.Context, session, payload.InteractionID), items[0].WrappedCek.Ciphertext)
	if err != nil || len(cek) != 32 {
		t.Fatal("browser HPKE unwrap failed", err)
	}
	altered := *observed.DetailAAD
	altered.CreatedAt = time.Now().Add(time.Hour).Format(time.RFC3339)
	request.Objects[0].AAD = &altered
	result, err = d.ownerUnwrap(request)
	if err != nil {
		t.Fatal(err)
	}
	if result.(*transport.CryptoUnwrapCekResult).Results[0].Error == "" {
		t.Fatal("tampered full AAD released CEK")
	}
	// A changed native tool snapshot invalidates the previously inspected proof
	// even if the runtime retains its request identifier.
	resolve.OptionID = "allow"
	resolve.InspectionProof = base64.StdEncoding.EncodeToString(proof)
	if _, ok = d.observeOwnerInteraction(payload, &agentruntime.InteractionEvent{Summary: "private tool invocation", NativePayload: json.RawMessage(`{"path":"replacement-file"}`)}); !ok {
		t.Fatal("updated native observation not encrypted")
	}
	if d.verifyOwnerApproval(resolve) == nil {
		t.Fatal("old inspection approved changed native contents")
	}
	p.Rotate = true
	p.ExpectedEpochID = ready.EpochID
	p.CommandID = domain.NewID().String()
	if _, err = d.doPrepareProtectedContext(p); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ownerUnwrap(request); err == nil {
		t.Fatal("rotation did not invalidate old browser session")
	}
}

func TestOwnerContextPrivateStorageAndScopeRefusal(t *testing.T) {
	d, p, ready := preparedOwnerDaemon(t)
	path := filepath.Join(d.StateDir, "e2ee", "contexts", p.Context.ID, "keyring.json")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.LoadContextKeyring(d.StateDir, p.Context); err == nil {
		t.Fatal("readable key file accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "linked-key")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(target, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err = crypto.LoadContextKeyring(d.StateDir, p.Context); err == nil {
		t.Fatal("symlink key file accepted")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	wrong := p
	wrong.Context.OwnerUserID = domain.NewID().String()
	if _, err = d.doPrepareProtectedContext(wrong); err == nil {
		t.Fatal("instance silently rebound to another owner")
	}
	wrong = p
	wrong.HostX25519 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	if _, err = d.doPrepareProtectedContext(wrong); err == nil {
		t.Fatal("wrong host key accepted")
	}
	browser, err := crypto.NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	start := transport.CryptoSessionStartPayload{EpochID: ready.EpochID, ProtectedContext: &p.Context, TenantID: p.Context.TenantID, UserID: domain.NewID().String(), SessionID: domain.NewID().String(), BrowserPub: base64.StdEncoding.EncodeToString(browser.X25519Pub)}
	if _, err = d.ownerSessionStart(start); err == nil {
		t.Fatal("foreign owner started unwrap session")
	}
	start.UserID = p.Context.OwnerUserID
	start.NetworkID = domain.NewID().String()
	if _, err = d.ownerSessionStart(start); err == nil {
		t.Fatal("mixed network/owner authority accepted")
	}
	start.NetworkID = ""
	for i := 0; i < ownerContextLimit; i++ {
		start.SessionID = domain.NewID().String()
		if _, err = d.ownerSessionStart(start); err != nil {
			t.Fatal(err)
		}
	}
	start.SessionID = domain.NewID().String()
	if _, err = d.ownerSessionStart(start); err == nil {
		t.Fatal("unbounded session admission")
	}
}

func TestOwnerContextRevokedEpochCannotBeReactivatedByPreparation(t *testing.T) {
	d, p, ready := preparedOwnerDaemon(t)
	ring, err := crypto.LoadContextKeyring(d.StateDir, p.Context)
	if err != nil {
		t.Fatal(err)
	}
	if err = ring.Revoke(ready.EpochID); err != nil {
		t.Fatal(err)
	}
	if err = crypto.SaveContextKeyring(d.StateDir, ring); err != nil {
		t.Fatal(err)
	}
	p.CommandID = domain.NewID().String()
	p.ExpectedEpochID = ""
	if _, err = d.doPrepareProtectedContext(p); err == nil {
		t.Fatal("revoked context automatically acquired replacement keys")
	}
}
