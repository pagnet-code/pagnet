//go:build linux || darwin

// The step-6b local admission chain over the real guard fixture: the
// deterministic seal (AAD shape + byte-identical re-prepare + round-trip
// through e2ee.Decrypt and the daemon's decryptProtected), the deterministic
// command ID, the journal reserve co-committing the original-dispatch claim,
// the admit over the exact authenticated connection (a fake host answering
// MsgFabricHostedInvoke like the control plane would), and the failure
// semantics: an admit failure retains the sealed record (an exact retry
// returns the retained receipt and retries the admission), and connection /
// session / reply mismatches are honest conflicts or deferrals.

package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/transport"
)

// fixedHostedEnvelopeCreatedAt is the deterministic envelope timestamp the
// reserve helpers use: an exact retry must re-present byte-identical original
// and finalized bytes, so the fixture never consults the wall clock.
var fixedHostedEnvelopeCreatedAt = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

// hostedInvokeTestServer is the fake host server half of the admit exchange:
// it records every MsgFabricHostedInvoke and answers on the daemon's real
// authenticated connection with a valid dispatch proof. Server-side
// idempotency: the same CommandID always earns the same proof and dispatch
// sequence (a re-admit of the same command is a re-ack, never a new effect).
type hostedInvokeTestServer struct {
	t         *testing.T
	conn      *NativeObservationConnection
	bootID    string
	admission transport.HostSessionPayload
	mu        sync.Mutex
	seen      []transport.FabricHostedInvocation
	proofs    map[string]*transport.NativeDispatchProof
	seq       int64
	refuse    *fabric.Error
	corrupt   func(p transport.FabricHostedInvocation, result *transport.FabricHostedResult)
}

func newHostedInvokeTestServer(t *testing.T, conn *NativeObservationConnection, bootID string, admission transport.HostSessionPayload) *hostedInvokeTestServer {
	return &hostedInvokeTestServer{t: t, conn: conn, bootID: bootID, admission: admission, proofs: map[string]*transport.NativeDispatchProof{}}
}

// serveRequest runs on the observation responder (the daemon's send path), so
// every shared field is read under the mutex.
func (s *hostedInvokeTestServer) serveRequest(p transport.FabricHostedInvocation) {
	s.t.Helper()
	s.mu.Lock()
	s.seen = append(s.seen, p)
	refuse := s.refuse
	corrupt := s.corrupt
	proof, ok := s.proofs[p.CommandID]
	if !ok {
		s.seq++
		proof = &transport.NativeDispatchProof{
			InvocationSource:    &transport.NativeInvocationSource{InvocationID: p.InvocationID, InputAAD: p.AAD},
			SourceBootID:        s.bootID,
			OwnershipID:         p.OwnershipID,
			OwnershipGeneration: p.OwnershipGeneration,
			DispatchSequence:    s.seq,
			SourceCommandID:     p.CommandID,
			SourceAdmissionID:   s.admission.NativeAdmissionID,
			SourceRunnerID:      s.admission.RunnerID,
			SourceRunnerEpoch:   s.admission.RunnerEpoch,
		}
		s.proofs[p.CommandID] = proof
	}
	s.mu.Unlock()

	result := transport.FabricHostedResult{RequestID: p.RequestID, Ref: p.Ref, Revision: p.Revision, CommandID: p.CommandID, Proof: proof}
	if refuse != nil {
		result = transport.FabricHostedResult{RequestID: p.RequestID, Error: refuse}
	}
	if corrupt != nil {
		corrupt(p, &result)
	}
	s.conn.hostedFabricDisposition(result)
}

func (s *hostedInvokeTestServer) requests() []transport.FabricHostedInvocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]transport.FabricHostedInvocation(nil), s.seen...)
}

func (s *hostedInvokeTestServer) setRefuse(e *fabric.Error) {
	s.mu.Lock()
	s.refuse = e
	s.mu.Unlock()
}
func (s *hostedInvokeTestServer) setCorrupt(c func(p transport.FabricHostedInvocation, result *transport.FabricHostedResult)) {
	s.mu.Lock()
	s.corrupt = c
	s.mu.Unlock()
}

// promptBinding builds the exact retained prompt binding for the prompt text
// (a JSON object with a single "input" string field).
func promptBinding(prompt string) []byte {
	raw, _ := json.Marshal(map[string]string{"input": prompt})
	return raw
}

// sealAndReserve seals the prompt through the daemon's REAL prepare path and
// journals it exactly like the router adapter: the caller is composed from the
// retained original bytes (the journal decodes them against the caller's
// evidence), the command ID is deterministic in (principal, invocation), and
// AttemptID/ReplayID = command ID. When originalOverride is non-nil the retry
// re-presents the retained original and finalized bytes verbatim. It returns
// the admit packet (fresh RequestID, retained CommandID/ciphertext/AAD), the
// retained receipt, its freshness, and the retained original/finalized bytes.
func (f *hostedGuardFixture) sealAndReserve(t *testing.T, principal fabric.Principal, invocation, prompt string, originalOverride, finalizedOverride []byte, plan [32]byte) (transport.FabricHostedInvocation, fabricagent.HostedInvocationReceipt, bool, []byte, []byte, error) {
	t.Helper()
	ctx := t.Context()
	promptBytes := promptBinding(prompt)
	cipher, aad, err := f.d.PrepareHostedInvocation(ctx, f.profile, invocation, promptBytes)
	if err != nil {
		return transport.FabricHostedInvocation{}, fabricagent.HostedInvocationReceipt{}, false, nil, nil, err
	}
	commandID := HostedInvocationCommandID(principal, invocation)
	var original, finalized []byte
	if originalOverride != nil {
		original, finalized = originalOverride, finalizedOverride
	} else {
		env := fabric.Envelope{
			ProtocolVersion:  fabric.CurrentProtocolVersion,
			ID:               invocation,
			Operation:        fabric.OperationInvoke,
			Principal:        principal,
			Source:           principal.Ref,
			Target:           &f.ref,
			ExpectedRevision: f.revision,
			CreatedAt:        fixedHostedEnvelopeCreatedAt,
			Payload:          json.RawMessage(promptBytes),
			Context:          fabric.EnvelopeContext{Origin: principal.Ref},
		}
		original, err = json.Marshal(env)
		if err != nil {
			t.Fatalf("marshal envelope: %v", err)
		}
		finalized = original
	}
	caller, err := fabric.NewAuthenticatedContext(principal, f.root.Namespace, original)
	if err != nil {
		t.Fatalf("compose caller: %v", err)
	}
	frame := fabric.DispatchAdmissionFrame{
		SourceDomain:            f.root.Namespace,
		CallerRef:               principal.Ref,
		AudienceDomain:          f.root.Namespace,
		InvocationID:            invocation,
		AttemptID:               commandID,
		ReplayID:                commandID,
		FinalizedDispatchDigest: sha256.Sum256(finalized),
	}
	receipt, fresh, err := f.journal.Reserve(ctx, f.scope, caller, original, finalized, frame, fabricagent.InvokedInput{Ciphertext: cipher, AAD: aad, CommandID: commandID}, plan)
	if err != nil {
		return transport.FabricHostedInvocation{}, receipt, fresh, original, finalized, err
	}
	p := transport.FabricHostedInvocation{
		RequestID:           domain.NewID().String(),
		CommandID:           receipt.CommandID,
		Ref:                 f.scope.Endpoint,
		Revision:            f.scope.ExpectedEndpointRevision,
		InvocationID:        receipt.InvocationID,
		NetworkID:           f.profile.NetworkID,
		InstanceID:          f.profile.Scope.InstanceID,
		OwnershipID:         f.profile.OwnershipID,
		OwnershipGeneration: f.profile.Scope.Generation,
		Envelope:            cipher,
		AAD:                 aad,
	}
	return p, receipt, fresh, original, finalized, nil
}

// journalRecordCounts returns the number of retained hosted-invocation
// journal markers and original-dispatch claims in the installation.
func (f *hostedGuardFixture) journalRecordCounts(t *testing.T) (int, int) {
	t.Helper()
	ctx := t.Context()
	owner, err := f.installation.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	list := func(prefix string, skipNested bool) int {
		t.Helper()
		n := 0
		cursor := ""
		for {
			page, err := f.installation.Store.ListGlobalAuthorityRecords(ctx, owner, registry.AuthorityNativeCheckpoint, prefix, cursor, 32)
			if err != nil {
				t.Fatalf("list %s records: %v", prefix, err)
			}
			for _, r := range page.Records {
				if skipNested && (strings.Contains(r.Key.ID, "/chunk/") || r.Key.ID == "hosted/invocation/capacity") {
					continue
				}
				n++
			}
			if page.NextCursor == "" {
				return n
			}
			cursor = page.NextCursor
		}
	}
	return list("hosted/invocation/", true), list("original-dispatch/", false)
}

// TestDaemonHostedInvocationPrepareSealPinned pins the PrepareHostedInvocation
// contract: the exact 9-field AAD shape (nil ProtectedContext/NativeContent,
// deterministic CreatedAt), the valid envelope, the byte-identical re-prepare,
// and the round-trip through e2ee.Decrypt and the daemon's decryptProtected.
func TestDaemonHostedInvocationPrepareSealPinned(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	prompt := "pinned deterministic hosted prompt"
	promptBytes := promptBinding(prompt)

	// A non-v7 invocation ID carries no embedded timestamp: CreatedAt is "".
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	// Force the version nibble to 4 (variant to 10): a raw random ID is
	// v7-shaped with probability 1/16, in which case it would carry an
	// embedded timestamp.
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	nonV7 := hex.EncodeToString(raw)

	cipher, aad, err := f.d.PrepareHostedInvocation(ctx, f.profile, nonV7, promptBytes)
	if err != nil {
		t.Fatalf("prepare (non-v7 id): %v", err)
	}
	if aad.ProtocolVersion != transport.ProtocolVersion || aad.TenantID != f.admission.TenantID || aad.NetworkID != f.profile.NetworkID || aad.ObjectType != e2ee.ObjectTypeInvocationInput || aad.ObjectID != nonV7 || aad.Sender != f.profile.Scope.HostID || aad.Recipient != f.profile.Scope.InstanceID || aad.CreatedAt != "" || aad.KeyEpochID != f.keyEpochID {
		t.Fatalf("pinned AAD shape mismatch: %+v", aad)
	}
	if aad.ProtectedContext != nil || aad.NativeContent != nil {
		t.Fatalf("invocation AAD must carry no protected context or native content: %+v", aad)
	}
	if err := cipher.Validate(); err != nil {
		t.Fatalf("sealed envelope is not a valid v1 envelope: %v", err)
	}
	if cipher.KeyEpochID != f.keyEpochID {
		t.Fatalf("envelope epoch = %q, want the active epoch %q", cipher.KeyEpochID, f.keyEpochID)
	}
	plaintext, err := e2ee.Decrypt(cipher, f.key, aad)
	if err != nil || !bytes.Equal(plaintext, promptBytes) {
		t.Fatalf("e2ee.Decrypt round-trip = %q / %v, want the prompt bytes", plaintext, err)
	}
	got, err := f.d.decryptProtected(f.networkID, cipher, aad)
	if err != nil || got != string(promptBytes) {
		t.Fatalf("daemon decryptProtected round-trip = %q / %v, want the prompt text", got, err)
	}

	// Determinism: an exact re-prepare re-derives byte-identical ciphertext
	// and AAD (the retry contract the journal's compareRetained relies on).
	cipher2, aad2, err := f.d.PrepareHostedInvocation(ctx, f.profile, nonV7, promptBytes)
	if err != nil {
		t.Fatalf("re-prepare: %v", err)
	}
	if cipher2 != cipher || aad2 != aad {
		t.Fatal("re-prepare is not byte-identical: the exact retry would not re-present the retained bytes")
	}

	// A UUIDv7 invocation ID carries its embedded timestamp as CreatedAt
	// (RFC3339, never the wall clock).
	v7id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	v7 := v7id.String()
	cipherV7, aadV7, err := f.d.PrepareHostedInvocation(ctx, f.profile, v7, promptBytes)
	if err != nil {
		t.Fatalf("prepare (v7 id): %v", err)
	}
	wantTS, ok := uuidV7Time(v7id)
	if !ok {
		t.Fatalf("fixture v7 id lost its timestamp: %s", v7)
	}
	if aadV7.CreatedAt != wantTS.Format(time.RFC3339) {
		t.Fatalf("v7 AAD CreatedAt = %q, want the embedded timestamp %q", aadV7.CreatedAt, wantTS.Format(time.RFC3339))
	}
	if _, err := e2ee.Decrypt(cipherV7, f.key, aadV7); err != nil {
		t.Fatalf("v7 seal does not decrypt: %v", err)
	}
}

// TestDaemonHostedInvocationPrepareProbeRefusal propagates the genuine
// original-worker probe refusal: a mutated profile (a fingerprint the live
// record does not carry) is refused before any seal, on both prepare and
// admit.
func TestDaemonHostedInvocationPrepareProbeRefusal(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	invocation := domain.NewID().String()

	mutated := f.profile
	mutated.NativeProfile = [32]byte{}
	if _, _, err := f.d.PrepareHostedInvocation(ctx, mutated, invocation, promptBinding("probe refusal")); !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatalf("prepare with the mutated profile = %v, want the probe's conflict", err)
	}
	// The admission chain re-probes as well (a shape-valid packet reaches the
	// probe): the refusal is the probe's own error, not a crypto or journal
	// failure.
	cipher, aad, err := f.d.PrepareHostedInvocation(ctx, f.profile, invocation, promptBinding("probe refusal"))
	if err != nil {
		t.Fatal(err)
	}
	p := transport.FabricHostedInvocation{
		RequestID:           domain.NewID().String(),
		CommandID:           domain.NewID().String(),
		Ref:                 f.scope.Endpoint,
		Revision:            f.scope.ExpectedEndpointRevision,
		InvocationID:        invocation,
		NetworkID:           f.profile.NetworkID,
		InstanceID:          f.profile.Scope.InstanceID,
		OwnershipID:         f.profile.OwnershipID,
		OwnershipGeneration: f.profile.Scope.Generation,
		Envelope:            cipher,
		AAD:                 aad,
	}
	if _, err := f.d.AdmitHostedFabric(ctx, mutated, p); !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatalf("admit with the mutated profile = %v, want the probe's conflict", err)
	}
}

// TestDaemonHostedInvocationCommandID pins the deterministic command identity:
// ParseID-valid (both the journal and the wire validate it), canonical
// 8-4-4-4-12 UUID shape with the version/variant nibbles fixed, deterministic
// in (principal, invocation ID), and distinct for distinct inputs.
func TestDaemonHostedInvocationCommandID(t *testing.T) {
	f := newHostedGuardFixture(t)
	invocation := "invocation-1"

	id := HostedInvocationCommandID(f.principal, invocation)
	if _, err := domain.ParseID(id); err != nil {
		t.Fatalf("derived command ID %q is not ParseID-valid: %v", id, err)
	}
	if len(id) != 36 {
		t.Fatalf("command ID %q is %d chars, want 36", id, len(id))
	}
	for _, i := range []int{8, 13, 18, 23} {
		if id[i] != '-' {
			t.Fatalf("command ID %q is not 8-4-4-4-12 shaped", id)
		}
	}
	if id[14] != '4' {
		t.Fatalf("command ID %q version nibble = %c, want 4", id, id[14])
	}
	if v := id[19]; v != '8' && v != '9' && v != 'a' && v != 'b' {
		t.Fatalf("command ID %q variant nibble = %c, want 8/9/a/b", id, v)
	}
	// Deterministic.
	if again := HostedInvocationCommandID(f.principal, invocation); again != id {
		t.Fatalf("command ID is not deterministic: %q vs %q", id, again)
	}
	// Distinct in both inputs.
	if HostedInvocationCommandID(f.principal, "invocation-2") == id {
		t.Fatal("different invocation IDs derived the same command ID")
	}
	other := fabric.Principal{Ref: "other.actor", Kind: "actor.agent", Issuer: f.root.Namespace}
	if HostedInvocationCommandID(other, invocation) == id {
		t.Fatal("different principals derived the same command ID")
	}
}

// TestDaemonHostedInvocationReserveAdmitIdempotent is the daemon-level happy
// path: reserve seals and journals (record + co-committed original-dispatch
// claim), admit verifies the server's proof, an exact retry returns the
// retained receipt byte-identically and re-admits idempotently (the server
// sees the same CommandID under a fresh RequestID with the same proof), and a
// changed input / caller / plan is a named field-class conflict with no new
// record.
func TestDaemonHostedInvocationReserveAdmitIdempotent(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	srv := newHostedInvokeTestServer(t, f.ownerConn, f.d.bootID, f.admission)
	f.invokeServer.Store(srv)
	defer f.invokeServer.Store(nil)

	invocation := domain.NewID().String()
	prompt := "idempotent hosted prompt"

	p, receipt, fresh, original, finalized, err := f.sealAndReserve(t, f.principal, invocation, prompt, nil, nil, f.plan)
	if err != nil || !fresh {
		t.Fatalf("first reserve: %v fresh=%v", err, fresh)
	}
	if receipt.State != "reserved" || receipt.CommandID != p.CommandID || receipt.InvocationID != invocation || receipt.Ciphertext != p.Envelope || receipt.AAD != p.AAD {
		t.Fatalf("first receipt mismatch: %+v", receipt)
	}
	// The journal record exists and the original-dispatch claim was
	// co-committed in the same transaction.
	markers, claims := f.journalRecordCounts(t)
	if markers != 1 || claims != 1 {
		t.Fatalf("journal after first reserve = %d markers / %d claims, want 1/1", markers, claims)
	}
	// The unsealed marker carries the invocation and command IDs.
	owner, err := f.installation.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.installation.Store.ListGlobalAuthorityRecords(ctx, owner, registry.AuthorityNativeCheckpoint, "hosted/invocation/", "", 32)
	if err != nil {
		t.Fatal(err)
	}
	markerSeen := false
	for _, r := range page.Records {
		if strings.Contains(r.Key.ID, "/chunk/") || r.Key.ID == "hosted/invocation/capacity" {
			continue
		}
		var marker struct {
			InvocationID string `json:"invocationId"`
			CommandID    string `json:"commandId"`
		}
		if err := json.Unmarshal(r.Value, &marker); err != nil || marker.InvocationID != invocation || marker.CommandID != p.CommandID {
			t.Fatalf("journal marker = %+v / %v, want invocation %s command %s", marker, err, invocation, p.CommandID)
		}
		markerSeen = true
	}
	if !markerSeen {
		t.Fatal("no journal marker record for the reserved invocation")
	}

	// Admit: the server's proof is verified field by field.
	proof, err := f.d.AdmitHostedFabric(ctx, f.profile, p)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if proof.SourceCommandID != p.CommandID || proof.OwnershipID != p.OwnershipID || proof.OwnershipGeneration != p.OwnershipGeneration || proof.DispatchSequence != 1 || proof.InvocationSource == nil || proof.InvocationSource.InvocationID != invocation || proof.InvocationSource.InputAAD != p.AAD || proof.SourceBootID != f.d.bootID {
		t.Fatalf("admit proof mismatch: %+v", proof)
	}
	reqs := srv.requests()
	if len(reqs) != 1 || reqs[0].CommandID != p.CommandID {
		t.Fatalf("server saw %d requests, want exactly the one admit", len(reqs))
	}

	// Exact retry: byte-identical re-prepare, the retained receipt, and an
	// idempotent re-admit (fresh RequestID, same CommandID, same proof).
	retryCipher, retryAAD, err := f.d.PrepareHostedInvocation(ctx, f.profile, invocation, promptBinding(prompt))
	if err != nil {
		t.Fatal(err)
	}
	if retryCipher != p.Envelope || retryAAD != p.AAD {
		t.Fatal("the exact retry re-prepare is not byte-identical to the admitted seal")
	}
	p2, receipt2, fresh2, _, _, err := f.sealAndReserve(t, f.principal, invocation, prompt, original, finalized, f.plan)
	if err != nil || fresh2 {
		t.Fatalf("retry reserve: %v fresh=%v, want the retained receipt", err, fresh2)
	}
	// The retained receipt is byte-identical in every retained field.
	if receipt2.State != "reserved" || receipt2.CommandID != receipt.CommandID || receipt2.InvocationID != receipt.InvocationID || !bytes.Equal(receipt2.Original, receipt.Original) || !bytes.Equal(receipt2.Finalized, receipt.Finalized) || receipt2.Ciphertext != receipt.Ciphertext || receipt2.AAD != receipt.AAD || receipt2.BindingSHA != receipt.BindingSHA || receipt2.ProfileFingerprint != receipt.ProfileFingerprint || receipt2.AssociationRevision != receipt.AssociationRevision || receipt2.Scope != receipt.Scope {
		t.Fatal("retry returned a changed receipt: the retained bytes must be byte-identical")
	}
	if p2.CommandID != p.CommandID || p2.RequestID == p.RequestID || p2.Envelope != p.Envelope || p2.AAD != p.AAD || p2.InvocationID != p.InvocationID {
		t.Fatal("retry admit packet changed the retained identity (or kept the correlation RequestID)")
	}
	proof2, err := f.d.AdmitHostedFabric(ctx, f.profile, p2)
	if err != nil {
		t.Fatalf("retry admit: %v", err)
	}
	reqs = srv.requests()
	if len(reqs) != 2 || reqs[1].CommandID != p.CommandID || reqs[1].RequestID == p.RequestID || reqs[1].Envelope != reqs[0].Envelope || reqs[1].AAD != reqs[0].AAD || reqs[1].InvocationID != p.InvocationID {
		t.Fatalf("server retry view = %+v, want the same retained command/ciphertext/AAD under a fresh RequestID", reqs)
	}
	if proof2.SourceCommandID != proof.SourceCommandID || proof2.OwnershipID != proof.OwnershipID || proof2.OwnershipGeneration != proof.OwnershipGeneration || proof2.DispatchSequence != proof.DispatchSequence || proof2.SourceAdmissionID != proof.SourceAdmissionID || proof2.SourceRunnerID != proof.SourceRunnerID || proof2.SourceRunnerEpoch != proof.SourceRunnerEpoch || proof2.InvocationSource == nil || *proof2.InvocationSource != *proof.InvocationSource {
		t.Fatalf("retry proof = %+v, want the server's retained proof for the same command", proof2)
	}
	// The journal is untouched by the retry: same single record and claim.
	if markers, claims := f.journalRecordCounts(t); markers != 1 || claims != 1 {
		t.Fatalf("journal after retry = %d markers / %d claims, want 1/1 (the retry must not re-claim)", markers, claims)
	}

	// Changed input (same invocation, same retained bytes, different prompt):
	// the sealed ciphertext binding conflicts; no new record.
	if _, _, _, _, _, err := f.sealAndReserve(t, f.principal, invocation, "CHANGED prompt", original, finalized, f.plan); err == nil {
		t.Fatal("changed-input reserve succeeded, want the input field-class conflict")
	} else if msg := err.Error(); !strings.Contains(msg, "input changed") {
		t.Fatalf("changed-input conflict = %q, want the input field class", msg)
	}

	// Changed caller (the installation owner is not the hosted actor): the
	// caller-association witness refuses BEFORE any input comparison, with a
	// named caller-class error and no new record.
	ownerPrincipal := f.owner.PrincipalView()
	if _, _, _, _, _, err := f.sealAndReserve(t, ownerPrincipal, invocation, prompt, nil, nil, f.plan); err == nil {
		t.Fatal("owner-caller reserve succeeded, want the caller-class refusal")
	} else if !strings.Contains(err.Error(), "caller") {
		t.Fatalf("owner-caller refusal = %q, want the caller-class named error", err)
	}

	// Changed plan (same retained bytes, different plan fingerprint): the
	// plan field class conflicts; no new record.
	otherPlan := f.plan
	otherPlan[30] ^= 0x01
	if _, _, _, _, _, err := f.sealAndReserve(t, f.principal, invocation, prompt, original, finalized, otherPlan); err == nil {
		t.Fatal("changed-plan reserve succeeded, want the plan field-class conflict")
	} else if msg := err.Error(); !strings.Contains(msg, "plan changed") {
		t.Fatalf("changed-plan conflict = %q, want the plan field class", msg)
	}

	// All three conflicts left the journal at exactly the original record.
	if markers, claims := f.journalRecordCounts(t); markers != 1 || claims != 1 {
		t.Fatalf("journal after conflicts = %d markers / %d claims, want 1/1 (conflicts create no records)", markers, claims)
	}
}

// TestDaemonHostedInvocationAdmitFailureRetainsSeal proves the admit-failure
// contract: when the server refuses, the error is honest, the sealed journal
// record REMAINS (state reserved, claim intact), and the exact retry returns
// the retained receipt and retries the admission to the same command.
func TestDaemonHostedInvocationAdmitFailureRetainsSeal(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	srv := newHostedInvokeTestServer(t, f.ownerConn, f.d.bootID, f.admission)
	f.invokeServer.Store(srv)
	defer f.invokeServer.Store(nil)

	invocation := domain.NewID().String()
	prompt := "admit failure retains the seal"

	p, _, fresh, original, finalized, err := f.sealAndReserve(t, f.principal, invocation, prompt, nil, nil, f.plan)
	if err != nil || !fresh {
		t.Fatalf("first reserve: %v fresh=%v", err, fresh)
	}
	refusal := fabric.NewError(fabric.CodeTargetUnavailable, "host refused the admission")
	srv.setRefuse(refusal)

	if _, err := f.d.AdmitHostedFabric(ctx, f.profile, p); !errors.Is(err, refusal) {
		t.Fatalf("admit = %v, want the server's honest refusal", err)
	}
	// The sealed record REMAINS: the reservation is retained (state reserved)
	// and the original-dispatch claim survives the failed admission.
	markers, claims := f.journalRecordCounts(t)
	if markers != 1 || claims != 1 {
		t.Fatalf("journal after failed admit = %d markers / %d claims, want 1/1 (the seal is retained)", markers, claims)
	}
	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("server saw %d admits before the retry, want 1", len(reqs))
	}

	// Exact retry: the retained receipt (fresh=false), then the admission
	// succeeds under the SAME command (the server had not accepted before).
	srv.setRefuse(nil)
	p2, receipt2, fresh2, _, _, err := f.sealAndReserve(t, f.principal, invocation, prompt, original, finalized, f.plan)
	if err != nil || fresh2 {
		t.Fatalf("retry reserve after failed admit: %v fresh=%v, want the retained receipt", err, fresh2)
	}
	if p2.CommandID != p.CommandID {
		t.Fatalf("retry command = %s, want the retained %s", p2.CommandID, p.CommandID)
	}
	proof, err := f.d.AdmitHostedFabric(ctx, f.profile, p2)
	if err != nil {
		t.Fatalf("retry admit: %v", err)
	}
	if proof.SourceCommandID != p.CommandID || proof.DispatchSequence != 1 {
		t.Fatalf("retry proof = %+v, want the retained command's first accepted sequence", proof)
	}
	reqs = srv.requests()
	if len(reqs) != 2 || reqs[1].CommandID != p.CommandID {
		t.Fatalf("server saw %d admits after the retry, want the same command re-admitted", len(reqs))
	}
	if receipt2.CommandID != p.CommandID || receipt2.State != "reserved" {
		t.Fatalf("retry receipt = %+v, want the retained reserved record", receipt2)
	}
}

// TestDaemonHostedAdmitFabricConnectionAndReplyFailures pins the
// AdmitHostedFabric failure classes: a non-current or absent connection is a
// deferred (retryable, no effect), a session tenant/account mismatch is a
// conflict, and a reply whose command or proof contradicts the request is a
// conflict (never a silent misparse).
func TestDaemonHostedAdmitFabricConnectionAndReplyFailures(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	srv := newHostedInvokeTestServer(t, f.ownerConn, f.d.bootID, f.admission)
	f.invokeServer.Store(srv)
	defer f.invokeServer.Store(nil)

	invocation := domain.NewID().String()
	prompt := "connection and reply failures"
	p, _, fresh, _, _, err := f.sealAndReserve(t, f.principal, invocation, prompt, nil, nil, f.plan)
	if err != nil || !fresh {
		t.Fatalf("reserve: %v fresh=%v", err, fresh)
	}

	// (a) Non-current host connection: the exact authenticated connection is
	// gone, so the admission is deferred (retryable), never replaced.
	otherClient, _ := newMemWS(t)
	f.d.connMu.Lock()
	originalConn := f.d.curConn
	f.d.curConn = otherClient
	f.d.connMu.Unlock()
	t.Cleanup(func() {
		f.d.connMu.Lock()
		f.d.curConn = originalConn
		f.d.connMu.Unlock()
	})
	if _, err := f.d.AdmitHostedFabric(ctx, f.profile, p); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
		t.Fatalf("non-current connection admit = %v, want deferred", err)
	}
	f.d.connMu.Lock()
	f.d.curConn = originalConn
	f.d.connMu.Unlock()

	// (b) Absent observation connection: likewise deferred.
	f.d.connMu.Lock()
	savedNative := f.d.nativeConn
	f.d.nativeConn = nil
	f.d.connMu.Unlock()
	t.Cleanup(func() {
		f.d.connMu.Lock()
		f.d.nativeConn = savedNative
		f.d.connMu.Unlock()
	})
	if _, err := f.d.AdmitHostedFabric(ctx, f.profile, p); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
		t.Fatalf("absent connection admit = %v, want deferred", err)
	}
	f.d.connMu.Lock()
	f.d.nativeConn = savedNative
	f.d.connMu.Unlock()

	// (c) Session tenant/account mismatch: a second authenticated host
	// session admitted under a different tenant cannot admit this profile,
	// and nothing is sent on it (the check precedes the exchange).
	foreign := transport.HostSessionPayload{TenantID: domain.NewID().String(), AccountID: domain.NewID().String(), OwnershipScope: "personal", HostID: f.d.HostID, BootID: f.d.bootID, NativeAdmissionID: domain.NewID().String(), RunnerID: domain.NewID().String(), RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol, transport.NativeWorkerOwnershipProtocol, transport.FabricHostedProtocol}}
	foreignConn := NewNativeObservationConnection(f.d.ServerURL, f.d.HostID, f.d.bootID, func(_ context.Context, typ string, payload any) error {
		f.t.Errorf("foreign session received a message (%s); the tenant check must refuse before any send", typ)
		return nil
	})
	if err := foreignConn.Admit(foreign); err != nil {
		t.Fatal(err)
	}
	f.d.connMu.Lock()
	f.d.nativeConn = foreignConn
	f.d.connMu.Unlock()
	if _, err := f.d.AdmitHostedFabric(ctx, f.profile, p); !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatalf("foreign-tenant admit = %v, want the session conflict", err)
	}
	f.d.connMu.Lock()
	f.d.nativeConn = savedNative
	f.d.connMu.Unlock()

	// (d) Contradictory replies: the connection re-checks the reply against
	// the request field by field; any contradiction is a conflict. Each
	// corruption reserves under its own invocation (fresh command, fresh
	// RequestID per attempt).
	corruptions := map[string]func(transport.FabricHostedInvocation, *transport.FabricHostedResult){
		"result command": func(_ transport.FabricHostedInvocation, r *transport.FabricHostedResult) {
			r.CommandID = domain.NewID().String()
		},
		"proof source command": func(_ transport.FabricHostedInvocation, r *transport.FabricHostedResult) {
			r.Proof.SourceCommandID = domain.NewID().String()
		},
		"proof aad": func(_ transport.FabricHostedInvocation, r *transport.FabricHostedResult) {
			r.Proof.InvocationSource.InputAAD.CreatedAt = "2026-01-01T00:00:00Z"
		},
		"proof sequence": func(_ transport.FabricHostedInvocation, r *transport.FabricHostedResult) {
			r.Proof.DispatchSequence = 0
		},
	}
	for name, corrupt := range corruptions {
		sub := domain.NewID().String()
		p, _, fresh, _, _, err := f.sealAndReserve(t, f.principal, sub, prompt, nil, nil, f.plan)
		if err != nil || !fresh {
			t.Fatalf("%s reserve: %v fresh=%v", name, err, fresh)
		}
		srv.setCorrupt(corrupt)
		if _, err := f.d.AdmitHostedFabric(ctx, f.profile, p); !errors.Is(err, ErrNativeObservationConflict) {
			t.Fatalf("%s reply admit = %v, want the conflict", name, err)
		}
		srv.setCorrupt(nil)
	}
}
