package federation_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	actualgate "github.com/pagnet-code/pagnet/internal/fabricfederation"
)

type testProtector struct{ aead cipher.AEAD }

func (p testProtector) Reference() durable.KeyReference {
	return durable.KeyReference{ID: "explicit-fixture-key", Version: "1"}
}
func (p testProtector) Seal(aad, plain []byte) ([]byte, error) {
	nonce := make([]byte, p.aead.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return nil, e
	}
	return p.aead.Seal(nonce, nonce, plain, aad), nil
}
func (p testProtector) Open(aad, sealed []byte) ([]byte, error) {
	if len(sealed) < p.aead.NonceSize() {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "fixture ciphertext invalid")
	}
	return p.aead.Open(nil, sealed[:p.aead.NonceSize()], sealed[p.aead.NonceSize():], aad)
}

type testKey struct {
	pub     [32]byte
	private []byte
}

func (k testKey) ExchangePrivateKey(ctx context.Context, p federation.PeerBinding) ([]byte, error) {
	if ctx.Err() != nil || p.ExchangePublicKey != k.pub {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "fixture key invalid")
	}
	return bytes.Clone(k.private), nil
}

type localPolicy struct{ deny atomic.Bool }

func (p *localPolicy) AuthorizeTx(ctx context.Context, tx *registry.AuthorityTx, action federation.AdmissionAction, c fabric.ExecutionContext, f federation.AdmissionFacts) error {
	if p.deny.Load() || c.PrincipalView() != f.Principal {
		return fabric.NewError(fabric.CodeUnauthenticated, "fixture current caller denied")
	}
	// Proves a genuine live same-root transaction is available. No remote provider
	// or fabricated caller classification is used by this explicitly trusted port.
	_, e := tx.Get(registry.AuthorityKey{Kind: registry.AuthorityFederationInvocation, ID: "configuration-v1"})
	return e
}

type ledgerFixture struct {
	source, destination           *registry.Store
	sourceOwner, destinationOwner fabric.ExecutionContext
	cfg                           federation.Config
	admissionConfig               federation.AdmissionConfig
	bundle                        federation.ForwardBundle
	caller                        fabric.ExecutionContext
	gate                          *actualgate.PeerGate
	sourceGate                    *actualgate.PeerGate
	policy                        *localPolicy
	ledger                        *federation.AdmissionLedger
	destinationPath               string
	sourceCaller                  fabric.ExecutionContext
	sourceKey                     testKey
}

func newLedgerFixture(t *testing.T, limit uint64) ledgerFixture {
	t.Helper()
	ctx := context.Background()
	var f ledgerFixture
	sourceOwner := fabric.Principal{Ref: "source-owner", Kind: "local.owner", Issuer: "actual.fixture"}
	destinationOwner := fabric.Principal{Ref: "destination-owner", Kind: "local.owner", Issuer: "actual.fixture"}
	var e error
	f.source, e = registry.Bootstrap(ctx, filepath.Join(t.TempDir(), "source"), sourceOwner)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.source.Close() })
	f.destinationPath = filepath.Join(t.TempDir(), "destination")
	f.destination, e = registry.Bootstrap(ctx, f.destinationPath, destinationOwner)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.destination.Close() })
	f.sourceOwner, _ = fabric.NewAuthenticatedContext(sourceOwner, f.source.Namespace(), []byte("explicit trusted operator fixture"))
	f.destinationOwner, _ = fabric.NewAuthenticatedContext(destinationOwner, f.destination.Namespace(), []byte("explicit trusted operator fixture"))
	ownerCheck := func(ctx context.Context, c fabric.ExecutionContext, r registry.AuthorityIdentity) error {
		if c.VerifyAuthenticated(r.Namespace) != nil || c.PrincipalView() != r.Owner {
			return fabric.NewError(fabric.CodeUnauthenticated, "fixture owner denied")
		}
		return nil
	}
	sp, e := registry.NewPeerIdentity(ctx, f.source, ownerCheck)
	if e != nil {
		t.Fatal(e)
	}
	dp, e := registry.NewPeerIdentity(ctx, f.destination, ownerCheck)
	if e != nil {
		t.Fatal(e)
	}
	keys := make([]testKey, 2)
	certs := make([]registry.CertifiedPeer, 2)
	for i, p := range []*registry.PeerIdentity{sp, dp} {
		pub, priv, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
		if e != nil {
			t.Fatal(e)
		}
		pb, _ := pub.MarshalBinary()
		kb, _ := priv.MarshalBinary()
		copy(keys[i].pub[:], pb)
		keys[i].private = kb
		owner := f.sourceOwner
		if i == 1 {
			owner = f.destinationOwner
		}
		certs[i], e = p.CertifyLocal(ctx, owner, 0, keys[i].pub, 1, time.Now().UTC().Add(-time.Second), time.Now().UTC().Add(time.Hour))
		if e != nil {
			t.Fatal(e)
		}
	}
	sr, e := sp.PinRemote(ctx, f.sourceOwner, 0, certs[1].Authority, certs[1].Certificate)
	if e != nil {
		t.Fatal(e)
	}
	dr, e := dp.PinRemote(ctx, f.destinationOwner, 0, certs[0].Authority, certs[0].Certificate)
	if e != nil {
		t.Fatal(e)
	}
	f.sourceGate, e = actualgate.New(ctx, actualgate.Config{Peers: sp, Owner: func(context.Context) (fabric.ExecutionContext, error) { return f.sourceOwner, nil }, Local: certs[0], Remote: sr})
	if e != nil {
		t.Fatal(e)
	}
	f.gate, e = actualgate.New(ctx, actualgate.Config{Peers: dp, Owner: func(context.Context) (fabric.ExecutionContext, error) { return f.destinationOwner, nil }, Local: certs[1], Remote: dr})
	if e != nil {
		t.Fatal(e)
	}
	local, _ := actualgate.Binding(certs[1])
	remote, _ := actualgate.Binding(dr)
	var channel federation.ChannelBinding
	rand.Read(channel.ID[:])
	rand.Read(channel.SourceRoute[:])
	rand.Read(channel.DestinationRoute[:])
	f.sourceKey = keys[0]
	f.cfg = federation.Config{Local: local, Remote: remote, Keys: keys[1], Trust: f.gate, Channel: channel, MaxRecords: 128}
	target, e := fabric.NewEndpointRef(f.destination.AuthorityIdentity().PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	revision, e := f.destination.Register(ctx, f.destinationOwner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: target, Kind: "agent.native", Name: "actual retained target", Description: "private target"}})
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	deadline := now.Add(time.Minute)
	principal := fabric.Principal{Ref: "original-actor", Kind: "actor.test", Issuer: f.source.Namespace()}
	original := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "global-original-invocation", Operation: fabric.OperationInvoke, Principal: principal, Source: principal.Ref, Target: &target, ExpectedRevision: revision, CreatedAt: now, Payload: json.RawMessage(`{"n":9007199254740993123456789,"private":"exact original input"}`), Context: fabric.EnvelopeContext{Origin: principal.Ref, Deadline: &deadline, IdempotencyKey: "immutable-replay"}}
	forwarded := original
	forwarded.Context.Hops = 1
	forwarded.Context.ExtensionChain = []string{"extension.actual"}
	raw, _ := json.Marshal(original)
	final, _ := json.Marshal(forwarded)
	f.sourceCaller, _ = fabric.NewAuthenticatedContext(principal, f.source.Namespace(), raw)
	frame := fabric.ForwardFrame{SourceDomain: f.source.Namespace(), SourceStoreID: f.source.AuthorityIdentity().StoreID, SourceKeyRevision: 1, DestinationDomain: f.destination.Namespace(), DestinationStoreID: f.destination.AuthorityIdentity().StoreID, SourcePeerBindingDigest: remote.BindingDigest, DestinationPeerBindingDigest: local.BindingDigest, Principal: principal, Target: &target, ExpectedRevision: revision, Operation: original.Operation, InvocationID: original.ID, ReplayID: original.Context.IdempotencyKey, OriginalEnvelopeDigest: sha256.Sum256(raw), ForwardedEnvelopeDigest: sha256.Sum256(final), OriginalProvenance: f.sourceCaller.ProvenanceView(), ForwardedProvenance: fabric.Provenance{Origin: principal.Ref, Hops: 1, ExtensionChain: []string{"extension.actual"}}, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano), Deadline: deadline.Format(time.RFC3339Nano), BindingProfile: federation.Profile}
	proof, e := f.source.SignForwardExact(ctx, f.sourceOwner, f.sourceCaller, raw, final, frame, f.sourceGate)
	if e != nil {
		t.Fatal(e)
	}
	f.bundle = federation.ForwardBundle{Proof: proof, Original: raw, Forwarded: final}
	e = federation.VerifyForwardBundle(ctx, f.cfg, f.bundle, federation.VerifyLimits{MaxLifetime: time.Minute}, func(ctx context.Context, c fabric.ExecutionContext) error { f.caller = c; return nil })
	if e != nil {
		t.Fatal(e)
	}
	block, _ := aes.NewCipher(bytes.Repeat([]byte{77}, 32))
	aead, _ := cipher.NewGCM(block)
	f.policy = &localPolicy{}
	f.admissionConfig = federation.AdmissionConfig{Store: f.destination, Owner: func(context.Context) (fabric.ExecutionContext, error) { return f.destinationOwner, nil }, Protector: testProtector{aead}, Peers: f.gate, Policy: f.policy, Limits: federation.AdmissionLimits{MaxInvocations: limit, MaxBytes: 8 << 20}, Verification: federation.VerifyLimits{MaxLifetime: time.Minute}}
	f.ledger, e = federation.BootstrapAdmissionLedger(ctx, f.admissionConfig)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func TestActualFederationAdmissionConcurrentAttemptAndExactAssociation(t *testing.T) {
	f := newLedgerFixture(t, 8)
	ctx := context.Background()
	var wg sync.WaitGroup
	var fresh atomic.Int64
	results := make(chan federation.Admission, 8)
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, new, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
			if e != nil {
				errs <- e
				return
			}
			if new {
				fresh.Add(1)
			}
			results <- a
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if fresh.Load() != 1 {
		t.Fatal("more than one global admission", fresh.Load())
	}
	a := <-results
	p, new, e := f.ledger.MarkAttempt(ctx, f.cfg, a, f.caller)
	if e != nil || !new {
		t.Fatal("first durable attempt", e)
	}
	again, new, e := f.ledger.MarkAttempt(ctx, f.cfg, a, f.caller)
	if e != nil || new || again.ID() != p.ID() {
		t.Fatal("uncertain attempt permitted reexecution", e)
	}
	association := federation.Association{Protocol: "native.local", BindingDigest: sha256.Sum256([]byte("exact-adapter-binding")), PrivateReference: json.RawMessage(`{"originalCommand":"opaque-existing-association","sequence":1}`)}
	if e = f.ledger.Associate(ctx, f.cfg, a, f.caller, p, association); e != nil {
		t.Fatal(e)
	}
	if e = f.ledger.Associate(ctx, f.cfg, a, f.caller, p, association); e != nil {
		t.Fatal("exact association replay", e)
	}
	changed := association
	changed.PrivateReference = json.RawMessage(`{"originalCommand":"different"}`)
	if e = f.ledger.Associate(ctx, f.cfg, a, f.caller, p, changed); e == nil {
		t.Fatal("changed original association accepted")
	}
	if e = f.ledger.RequestCancellation(ctx, f.cfg, a, f.caller); e != nil {
		t.Fatal(e)
	}
	status, e := f.ledger.Status(ctx, f.cfg, a, f.caller)
	if e != nil || !status.Attempted || !status.CancelRequested || status.Association == nil || !bytes.Equal(status.Association.PrivateReference, association.PrivateReference) || status.Cursor.Ordinal != -1 {
		t.Fatal("durable original status", e)
	}
}
func TestActualFederationAdmissionRejectsChangedRetryAndCurrentPolicy(t *testing.T) {
	f := newLedgerFixture(t, 1)
	ctx := context.Background()
	a, _, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
	if e != nil {
		t.Fatal(e)
	}
	changed := f.bundle
	changed.Proof.Frame.ReplayID = "new-replay"
	if _, _, e = f.ledger.Admit(ctx, f.cfg, changed, f.caller); e == nil {
		t.Fatal("changed proof mapped fresh attempt")
	}
	f.policy.deny.Store(true)
	if _, _, e = f.ledger.MarkAttempt(ctx, f.cfg, a, f.caller); e == nil {
		t.Fatal("revoked current caller paid start")
	}
	f.policy.deny.Store(false)
	if e = f.ledger.RequestCancellation(ctx, f.cfg, a, f.caller); e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.ledger.MarkAttempt(ctx, f.cfg, a, f.caller); e == nil {
		t.Fatal("cancelled unattempted work executed")
	}
}

func resignLedgerBundle(t *testing.T, f ledgerFixture, b federation.ForwardBundle) federation.ForwardBundle {
	t.Helper()
	b.Proof.Frame.OriginalEnvelopeDigest = sha256.Sum256(b.Original)
	b.Proof.Frame.ForwardedEnvelopeDigest = sha256.Sum256(b.Forwarded)
	var original fabric.Envelope
	if e := fabric.DecodeJSON(b.Original, &original); e != nil {
		t.Fatal(e)
	}
	caller, e := fabric.NewAuthenticatedContext(original.Principal, f.source.Namespace(), b.Original)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := f.source.SignForwardExact(context.Background(), f.sourceOwner, caller, b.Original, b.Forwarded, b.Proof.Frame, f.sourceGate)
	if e != nil {
		t.Fatal(e)
	}
	b.Proof = proof
	return b
}
func TestActualFederationHistoricalProofNeverRefreshesPaidValidity(t *testing.T) {
	f := newLedgerFixture(t, 8)
	ctx := context.Background()
	b := f.bundle
	cutoff := time.Now().UTC().Add(2 * time.Second)
	b.Proof.Frame.ExpiresAt = cutoff.Format(time.RFC3339Nano)
	b = resignLedgerBundle(t, f, b)
	var current fabric.ExecutionContext
	if e := federation.VerifyForwardBundle(ctx, f.cfg, b, f.admissionConfig.Verification, func(ctx context.Context, c fabric.ExecutionContext) error { current = c; return nil }); e != nil {
		t.Fatal(e)
	}
	a, new, e := f.ledger.Admit(ctx, f.cfg, b, current)
	if e != nil || !new {
		t.Fatal(e)
	}
	time.Sleep(time.Until(cutoff) + 20*time.Millisecond)
	// This is a fresh independently authenticated control fixture, not the old
	// signed proof being interpreted as current caller authority.
	fresh, _ := fabric.NewAuthenticatedContext(b.Proof.Frame.Principal, f.destination.Namespace(), []byte("fresh trusted historical-control fixture"))
	replay, new, e := f.ledger.Admit(ctx, f.cfg, b, fresh)
	if e != nil || new {
		t.Fatal("exact retained history after expiry", e)
	}
	if _, new, e = f.ledger.MarkAttempt(ctx, f.cfg, replay, fresh); e == nil || new {
		t.Fatal("first paid start after original proof expiry")
	}
	if e = f.ledger.RequestCancellation(ctx, f.cfg, a, fresh); e != nil {
		t.Fatal("current historical stop denied", e)
	}
	// Refreshing a proof cannot turn the same invocation into a new permit.
	b.Proof.Frame.ExpiresAt = time.Now().UTC().Add(10 * time.Second).Format(time.RFC3339Nano)
	b = resignLedgerBundle(t, f, b)
	if _, _, e = f.ledger.Admit(ctx, f.cfg, b, fresh); e == nil {
		t.Fatal("refreshed uncertain original proof accepted")
	}
}
func TestActualFederationQuotaRollbackAndAlteredEngineView(t *testing.T) {
	f := newLedgerFixture(t, 1)
	ctx := context.Background()
	a, _, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
	if e != nil {
		t.Fatal(e)
	}
	altered := f.bundle
	var final fabric.Envelope
	fabric.DecodeJSON(altered.Forwarded, &final)
	final.Payload = json.RawMessage(`{"different":true}`)
	altered.Forwarded, _ = json.Marshal(final)
	altered = resignLedgerBundle(t, f, altered)
	var changedCaller fabric.ExecutionContext
	if e = federation.VerifyForwardBundle(ctx, f.cfg, altered, f.admissionConfig.Verification, func(ctx context.Context, c fabric.ExecutionContext) error { changedCaller = c; return nil }); e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.ledger.Admit(ctx, f.cfg, altered, changedCaller); e == nil {
		t.Fatal("same original remapped changed final input")
	}
	second := f.bundle
	var original fabric.Envelope
	fabric.DecodeJSON(second.Original, &original)
	original.ID = "second-global-invocation"
	second.Original, _ = json.Marshal(original)
	fabric.DecodeJSON(second.Forwarded, &final)
	final.ID = original.ID
	second.Forwarded, _ = json.Marshal(final)
	second.Proof.Frame.InvocationID = original.ID
	second = resignLedgerBundle(t, f, second)
	var secondCaller fabric.ExecutionContext
	if e = federation.VerifyForwardBundle(ctx, f.cfg, second, f.admissionConfig.Verification, func(ctx context.Context, c fabric.ExecutionContext) error { secondCaller = c; return nil }); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if _, _, e = f.ledger.Admit(ctx, f.cfg, second, secondCaller); e == nil {
			t.Fatal("finite quota exceeded or rejected tx became an admission")
		}
	}
	if _, new, e := f.ledger.MarkAttempt(ctx, f.cfg, a, f.caller); e != nil || !new {
		t.Fatal("quota rollback damaged original admission", e)
	}
}

type knownFrameVerifier struct{ cursor federation.ConsumerCursor }

func (v knownFrameVerifier) VerifyCursorTx(ctx context.Context, tx *registry.AuthorityTx, f federation.AdmissionFacts, a federation.Association, c federation.ConsumerCursor) error {
	if c != v.cursor || a.Protocol != "native.local" {
		return fabric.NewError(fabric.CodeUnauthenticated, "fixture original frame denied")
	}
	_, e := tx.Get(registry.AuthorityKey{Kind: registry.AuthorityFederationInvocation, ID: "configuration-v1"})
	return e
}
func TestActualFederationConsumerCheckpointRejectsSkipAndUnverifiedDigest(t *testing.T) {
	f := newLedgerFixture(t, 8)
	ctx := context.Background()
	a, _, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
	if e != nil {
		t.Fatal(e)
	}
	permit, _, e := f.ledger.MarkAttempt(ctx, f.cfg, a, f.caller)
	if e != nil {
		t.Fatal(e)
	}
	association := federation.Association{Protocol: "native.local", BindingDigest: sha256.Sum256([]byte("actual-binding-fixture")), PrivateReference: json.RawMessage(`{"originalSource":"fixture-association"}`)}
	if e = f.ledger.Associate(ctx, f.cfg, a, f.caller, permit, association); e != nil {
		t.Fatal(e)
	}
	floor := federation.ConsumerCursor{Ordinal: -1}
	next := federation.ConsumerCursor{Ordinal: 0, FrameDigest: sha256.Sum256([]byte("exact-original-frame"))}
	gate := knownFrameVerifier{next}
	if e = f.ledger.CheckpointCursor(ctx, f.cfg, a, f.caller, floor, next, nil); e == nil {
		t.Fatal("wire-only cursor accepted")
	}
	forged := next
	forged.FrameDigest[0] ^= 1
	if e = f.ledger.CheckpointCursor(ctx, f.cfg, a, f.caller, floor, forged, gate); e == nil {
		t.Fatal("unverified frame digest accepted")
	}
	skip := next
	skip.Ordinal = 2
	if e = f.ledger.CheckpointCursor(ctx, f.cfg, a, f.caller, floor, skip, knownFrameVerifier{skip}); e == nil {
		t.Fatal("skipped original frames")
	}
	if e = f.ledger.CheckpointCursor(ctx, f.cfg, a, f.caller, floor, next, gate); e != nil {
		t.Fatal(e)
	}
	if e = f.ledger.CheckpointCursor(ctx, f.cfg, a, f.caller, floor, next, gate); e != nil {
		t.Fatal("exact ACK checkpoint replay", e)
	}
	status, e := f.ledger.Status(ctx, f.cfg, a, f.caller)
	if e != nil || status.Cursor != next {
		t.Fatal("consumer cursor disappeared", e)
	}
}

func reopenLedgerFixture(t *testing.T, f *ledgerFixture) {
	t.Helper()
	ctx := context.Background()
	if e := f.destination.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	f.destination, e = registry.Open(ctx, f.destinationPath)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.destination.Close() })
	peers, e := registry.NewPeerIdentity(ctx, f.destination, func(ctx context.Context, c fabric.ExecutionContext, r registry.AuthorityIdentity) error {
		if c.VerifyAuthenticated(r.Namespace) != nil || c.PrincipalView() != r.Owner {
			return fabric.NewError(fabric.CodeUnauthenticated, "fixture retained owner denied")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	local, e := peers.Local(ctx, f.destinationOwner)
	if e != nil {
		t.Fatal(e)
	}
	remote, e := peers.Remote(ctx, f.destinationOwner, f.cfg.Remote.Authority.Namespace, f.cfg.Remote.Authority.StoreID)
	if e != nil {
		t.Fatal(e)
	}
	f.gate, e = actualgate.New(ctx, actualgate.Config{Peers: peers, Owner: func(context.Context) (fabric.ExecutionContext, error) { return f.destinationOwner, nil }, Local: local, Remote: remote})
	if e != nil {
		t.Fatal(e)
	}
	f.cfg.Trust = f.gate
	f.admissionConfig.Store = f.destination
	f.admissionConfig.Peers = f.gate
	f.ledger, e = federation.OpenAdmissionLedger(ctx, f.admissionConfig)
	if e != nil {
		t.Fatal(e)
	}
}

func TestActualFederationRestartRetainsAttemptAndOriginalAssociation(t *testing.T) {
	f := newLedgerFixture(t, 8)
	ctx := context.Background()
	a, fresh, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
	if e != nil || !fresh {
		t.Fatal(e)
	}
	permit, fresh, e := f.ledger.MarkAttempt(ctx, f.cfg, a, f.caller)
	if e != nil || !fresh {
		t.Fatal(e)
	}
	association := federation.Association{Protocol: "native.local", BindingDigest: sha256.Sum256([]byte("real-adapter-selection-fixture")), PrivateReference: json.RawMessage(`{"retainedCommand":"original-only"}`)}
	if e = f.ledger.Associate(ctx, f.cfg, a, f.caller, permit, association); e != nil {
		t.Fatal(e)
	}
	if e = f.ledger.RequestCancellation(ctx, f.cfg, a, f.caller); e != nil {
		t.Fatal(e)
	}
	oldID := permit.ID()
	reopenLedgerFixture(t, &f)
	if _, e = f.ledger.Status(ctx, f.cfg, a, f.caller); e == nil {
		t.Fatal("cross-ledger opaque admission accepted")
	}
	a, fresh, e = f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
	if e != nil || fresh {
		t.Fatal("restart recreated effect", e)
	}
	permit, fresh, e = f.ledger.MarkAttempt(ctx, f.cfg, a, f.caller)
	if e != nil || fresh || permit.ID() != oldID {
		t.Fatal("restart allowed new paid attempt", e)
	}
	status, e := f.ledger.Status(ctx, f.cfg, a, f.caller)
	if e != nil || !status.CancelRequested || status.Association == nil || !bytes.Equal(status.Association.PrivateReference, association.PrivateReference) {
		t.Fatal("retained exact association lost", e)
	}
	if _, e = federation.BootstrapAdmissionLedger(ctx, f.admissionConfig); e == nil {
		t.Fatal("existing replay fence reinitialized")
	}
	wrong := f.admissionConfig
	wrong.Limits.MaxInvocations++
	if _, e = federation.OpenAdmissionLedger(ctx, wrong); e == nil {
		t.Fatal("changed capacity silently accepted")
	}
	block, _ := aes.NewCipher(bytes.Repeat([]byte{99}, 32))
	aead, _ := cipher.NewGCM(block)
	wrong = f.admissionConfig
	wrong.Protector = testProtector{aead}
	if _, e = federation.OpenAdmissionLedger(ctx, wrong); e == nil {
		t.Fatal("wrong same-labelled key accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, e = f.ledger.Admit(cancelled, f.cfg, f.bundle, f.caller); e == nil {
		t.Fatal("cancelled call admitted")
	}
	f.policy.deny.Store(true)
	if _, e = f.ledger.Status(ctx, f.cfg, a, f.caller); e == nil {
		t.Fatal("restart history bypassed current policy")
	}
}

func TestActualFederationCurrentPeerRevocationDeniesAllHistory(t *testing.T) {
	f := newLedgerFixture(t, 8)
	ctx := context.Background()
	a, _, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
	if e != nil {
		t.Fatal(e)
	}
	peers, e := registry.NewPeerIdentity(ctx, f.destination, func(ctx context.Context, c fabric.ExecutionContext, r registry.AuthorityIdentity) error {
		if c.VerifyAuthenticated(r.Namespace) != nil || c.PrincipalView() != r.Owner {
			return fabric.NewError(fabric.CodeUnauthenticated, "fixture owner denied")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	remote, e := peers.Remote(ctx, f.destinationOwner, f.cfg.Remote.Authority.Namespace, f.cfg.Remote.Authority.StoreID)
	if e != nil {
		t.Fatal(e)
	}
	if e = peers.RevokeRemote(ctx, f.destinationOwner, remote.Authority.Namespace, remote.Authority.StoreID, remote.Revision); e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller); e == nil {
		t.Fatal("revoked pair authenticated historical proof")
	}
	if _, e = f.ledger.Status(ctx, f.cfg, a, f.caller); e == nil {
		t.Fatal("revoked pair read history")
	}
	if e = f.ledger.RequestCancellation(ctx, f.cfg, a, f.caller); e == nil {
		t.Fatal("revoked pair mutated cancellation")
	}
}

type failingProtector struct {
	testProtector
	calls  atomic.Int64
	failAt atomic.Int64
}

func (p *failingProtector) Seal(aad, plain []byte) ([]byte, error) {
	n := p.calls.Add(1)
	if n == p.failAt.Load() {
		return nil, fabric.NewError(fabric.ErrorCode("fixture.seal_failure"), "fixture explicit seal failure")
	}
	return p.testProtector.Seal(aad, plain)
}

func TestActualFederationPartialChunkFailureRollsBackEntireAdmission(t *testing.T) {
	f := newLedgerFixture(t, 8)
	ctx := context.Background()
	p := &failingProtector{testProtector: f.admissionConfig.Protector.(testProtector)}
	f.admissionConfig.Protector = p
	var e error
	f.ledger, e = federation.OpenAdmissionLedger(ctx, f.admissionConfig)
	if e != nil {
		t.Fatal(e)
	}
	var original, forwarded fabric.Envelope
	if e = fabric.DecodeJSON(f.bundle.Original, &original); e != nil {
		t.Fatal(e)
	}
	if e = fabric.DecodeJSON(f.bundle.Forwarded, &forwarded); e != nil {
		t.Fatal(e)
	}
	payload, _ := json.Marshal(map[string]string{"largePrivate": string(bytes.Repeat([]byte("x"), 90<<10))})
	original.Payload = payload
	forwarded.Payload = payload
	f.bundle.Original, _ = json.Marshal(original)
	f.bundle.Forwarded, _ = json.Marshal(forwarded)
	f.bundle = resignLedgerBundle(t, f, f.bundle)
	if e = federation.VerifyForwardBundle(ctx, f.cfg, f.bundle, f.admissionConfig.Verification, func(ctx context.Context, c fabric.ExecutionContext) error { f.caller = c; return nil }); e != nil {
		t.Fatal(e)
	}

	p.failAt.Store(2)
	if _, _, e = f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller); e == nil {
		t.Fatal("partial sealed chunk failure admitted")
	}
	p.failAt.Store(0)
	a, fresh, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
	if e != nil || !fresh {
		t.Fatal("partial chunk transaction was not entirely rolled back", e)
	}
	if _, fresh, e = f.ledger.MarkAttempt(ctx, f.cfg, a, f.caller); e != nil || !fresh {
		t.Fatal(e)
	}
}

func TestActualFederationConcurrentAttemptHasExactlyOneFreshPermit(t *testing.T) {
	f := newLedgerFixture(t, 8)
	ctx := context.Background()
	a, _, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var freshCount atomic.Int64
	ids := make(chan string, 8)
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, fresh, e := f.ledger.MarkAttempt(ctx, f.cfg, a, f.caller)
			if e != nil {
				errs <- e
				return
			}
			if fresh {
				freshCount.Add(1)
			}
			ids <- p.ID()
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	var exact string
	for id := range ids {
		if exact == "" {
			exact = id
		}
		if id != exact {
			t.Fatal("changed attempted identity")
		}
	}
	if freshCount.Load() != 1 {
		t.Fatal("more than one durable paid-start permit", freshCount.Load())
	}
}

func TestActualFederationReplayIdentityIncludesKindAndIssuer(t *testing.T) {
	f := newLedgerFixture(t, 8)
	ctx := context.Background()
	originalAdmission, _, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"kind", "issuer"} {
		t.Run(field, func(t *testing.T) {
			b := f.bundle
			var original, final fabric.Envelope
			fabric.DecodeJSON(b.Original, &original)
			fabric.DecodeJSON(b.Forwarded, &final)
			if field == "kind" {
				original.Principal.Kind = "actor.different"
			} else {
				original.Principal.Issuer = "different-actual-issuer"
			}
			final.Principal = original.Principal
			b.Proof.Frame.Principal = original.Principal
			b.Original, _ = json.Marshal(original)
			b.Forwarded, _ = json.Marshal(final)
			b = resignLedgerBundle(t, f, b)
			var caller fabric.ExecutionContext
			if e = federation.VerifyForwardBundle(ctx, f.cfg, b, f.admissionConfig.Verification, func(ctx context.Context, c fabric.ExecutionContext) error { caller = c; return nil }); e != nil {
				t.Fatal(e)
			}
			if _, e = f.ledger.Status(ctx, f.cfg, originalAdmission, caller); e == nil {
				t.Fatal("same ref borrowed cross-kind/issuer admission")
			}
			a, fresh, e := f.ledger.Admit(ctx, f.cfg, b, caller)
			if e != nil || !fresh {
				t.Fatal("full principal replay key collapsed", e)
			}
			if _, e = f.ledger.Status(ctx, f.cfg, a, f.caller); e == nil {
				t.Fatal("original principal borrowed other admission")
			}
		})
	}
}

func TestActualFederationSignedRowSubstitutionCannotEraseReplayFence(t *testing.T) {
	f := newLedgerFixture(t, 8)
	ctx := context.Background()
	a, _, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(struct {
		Purpose    string
		Principal  fabric.Principal
		Invocation string
	}{"pagnet.fabric.federation-admission.v1", f.bundle.Proof.Frame.Principal, f.bundle.Proof.Frame.InvocationID})
	sum := sha256.Sum256(raw)
	key := registry.AuthorityKey{Kind: registry.AuthorityFederationInvocation, ID: "invocation:" + fmt.Sprintf("%x", sum)}
	e = f.destination.WithNativeAuthority(ctx, f.destinationOwner, registry.AuthorityScope{MaxOperations: 8}, func(tx *registry.AuthorityTx) error {
		row, e := tx.Get(key)
		if e != nil {
			return e
		}
		var wrapped struct {
			Ciphertext []byte `json:"ciphertext"`
		}
		if e = json.Unmarshal(row.Value, &wrapped); e != nil {
			return e
		}
		wrapped.Ciphertext[len(wrapped.Ciphertext)-1] ^= 1
		corrupted, _ := json.Marshal(wrapped)
		_, e = tx.CAS(key, row.Revision, corrupted, false)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.ledger.Status(ctx, f.cfg, a, f.caller); e == nil {
		t.Fatal("root-signed but unauthenticated sealed manifest accepted")
	}
	if _, _, e = f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller); e == nil {
		t.Fatal("corrupt manifest reset replay admission")
	}
	if _, _, e = f.ledger.MarkAttempt(ctx, f.cfg, a, f.caller); e == nil {
		t.Fatal("corrupt manifest allowed new paid start")
	}
	if _, e = federation.BootstrapAdmissionLedger(ctx, f.admissionConfig); e == nil {
		t.Fatal("corrupt replay state replaced by bootstrap")
	}
}

func TestActualFederationAlteredTargetAndRevisionCannotCreateSecondEffect(t *testing.T) {
	for _, field := range []string{"target", "revision"} {
		t.Run(field, func(t *testing.T) {
			f := newLedgerFixture(t, 8)
			ctx := context.Background()
			if _, _, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller); e != nil {
				t.Fatal(e)
			}
			b := f.bundle
			var final fabric.Envelope
			fabric.DecodeJSON(b.Forwarded, &final)
			target := *final.Target
			if field == "target" {
				var e error
				target, e = fabric.NewEndpointRef(f.destination.AuthorityIdentity().PublicKey)
				if e != nil {
					t.Fatal(e)
				}
			}
			update := fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: target, Kind: "agent.native", Name: "changed retained target", Description: "changed revision"}}
			if field == "revision" {
				update.ExpectedRevision = final.ExpectedRevision
			}
			var revision fabric.Revision
			var e error
			if field == "revision" {
				revision, e = f.destination.Update(ctx, f.destinationOwner, update)
			} else {
				revision, e = f.destination.Register(ctx, f.destinationOwner, update)
			}
			if e != nil {
				t.Fatal(e)
			}
			final.Target = &target
			final.ExpectedRevision = revision
			b.Proof.Frame.Target = &target
			b.Proof.Frame.ExpectedRevision = revision
			b.Forwarded, _ = json.Marshal(final)
			b = resignLedgerBundle(t, f, b)
			var caller fabric.ExecutionContext
			if e = federation.VerifyForwardBundle(ctx, f.cfg, b, f.admissionConfig.Verification, func(ctx context.Context, c fabric.ExecutionContext) error { caller = c; return nil }); e != nil {
				t.Fatal(e)
			}
			for range 2 {
				if _, _, e = f.ledger.Admit(ctx, f.cfg, b, caller); e == nil {
					t.Fatal("changed selected target/revision created second effect")
				}
			}
		})
	}
}
