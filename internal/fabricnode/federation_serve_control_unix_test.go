//go:build linux || darwin

package fabricnode

// Two-node acceptance for the installed federation product's destination
// CONTROL PATH (E1 slice-2c).
//
// Node B is a REAL OpenInstalled serve path: the installed service (a
// stateless MCP HTTP provider with an atomic effect counter) is set up through
// the operator setup path, and the relay listener serves both the one-way
// bundle-forward and one committed control unit per fresh connection. Node A
// is a real OpenInstalled source whose certified/pinned/link-declared
// controls go over the unix relay socket, signed through its real kernel
// session and retained root.
//
// Accepted: the genuine effect executes exactly once; status returns the
// retained head state without actuating; pull serves the retained final
// projection over record 6; ack advances the cursor only under a
// recomputed-and-compared frame digest (a forged digest gets no reply and
// moves nothing) and its replay returns the retained result; cancel commits
// the stop intent and its result digest independently recomputes to the
// committed head state.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricfederation"
)

// signControl builds, authenticates and signs one genuine fresh control
// request through the source's actual kernel session and retained root
// signer, targeting the exact retained admission (principal, invocation,
// receipt digest and derived attempt id).
func (s *federationServeSource) signControl(t *testing.T, ctx context.Context, principal fabric.Principal, invocationID string, receiptDigest [32]byte, attemptID, action, replayID string, payload []byte) federation.ControlRequest {
	t.Helper()
	localBinding, e := fabricfederation.Binding(s.local)
	if e != nil {
		t.Fatalf("local binding: %v", e)
	}
	remoteBinding, e := fabricfederation.Binding(s.remote)
	if e != nil {
		t.Fatalf("remote binding: %v", e)
	}
	now := time.Now().UTC()
	frame := fabric.ControlFrame{
		ProtocolVersion:              "1",
		SourceDomain:                 s.local.Authority.Namespace,
		SourceStoreID:                s.local.Authority.StoreID,
		SourceKeyRevision:            s.local.Authority.KeyRevision,
		DestinationDomain:            s.remote.Authority.Namespace,
		DestinationStoreID:           s.remote.Authority.StoreID,
		SourcePeerBindingDigest:      localBinding.BindingDigest,
		DestinationPeerBindingDigest: remoteBinding.BindingDigest,
		Principal:                    principal,
		OriginalPrincipal:            principal,
		InvocationID:                 invocationID,
		ReceiptDigest:                receiptDigest,
		AttemptID:                    attemptID,
		Action:                       action,
		PayloadDigest:                sha256.Sum256(payload),
		ReplayID:                     replayID,
		IssuedAt:                     now.Format(time.RFC3339Nano),
		ExpiresAt:                    now.Add(30 * time.Second).Format(time.RFC3339Nano),
		BindingProfile:               federation.Profile,
	}
	var signed fabric.SignedControlProof
	e = s.session.WithAuthenticatedControl(ctx, frame, payload, func(ctx context.Context, c fabric.ExecutionContext) error {
		g, e := NewSourceControlGate(s.gate, s.authority, c, localBinding, remoteBinding)
		if e != nil {
			return e
		}
		signed, e = s.node.Installation.Store.SignControlExact(ctx, s.owner, c, payload, frame, g)
		return e
	})
	if e != nil {
		t.Fatalf("source control signer (%s): %v", action, e)
	}
	return federation.ControlRequest{Proof: signed, Payload: payload}
}

// controlPayloadJSON encodes the closed action-specific payload union.
func controlPayloadJSON(t *testing.T, p federation.ControlPayload) []byte {
	t.Helper()
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestFederationServeControlTwoNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}

	// The destination's real paid effect: a stateless MCP HTTP provider with
	// an atomic effect counter.
	var effects atomic.Int32
	provider := sdk.NewServer(&sdk.Implementation{Name: "served-control", Version: "1"}, &sdk.ServerOptions{SupportedProtocolVersions: []string{"2025-11-25"}})
	provider.AddTool(&sdk.Tool{Name: "count", Description: "Count one served effect", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "counted"}}}, nil
	})
	server := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return provider }, &sdk.StreamableHTTPOptions{Stateless: true}))
	defer server.Close()

	// ---- Node B: the destination (real installed serve path). ----
	digestB := [32]byte{0xB0}
	dirB, socketB, rootB := federationServeBootstrap(t, ctx)
	refB, revB := federationServeSetupServices(t, ctx, dirB, binary, server.URL, digestB)
	relayB := filepath.Join(filepath.Dir(socketB), "federation.sock")
	nodeB := federationServeOpenProduct(t, ctx, dirB, binary, relayB, digestB)

	// ---- Node A: the source (real installed serve path). ----
	dirA, socketA, rootA := federationServeBootstrap(t, ctx)
	nodeA, e := OpenInstalled(ctx, InstalledConfig{Directory: dirA, Binary: binary, Federation: &InstalledFederationConfig{}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = nodeA.Close() })

	// ---- Trust + link + exposure declarations, all through the REAL private
	// admin sockets. ----
	callA := dialAdmin(t, ctx, socketA)
	callB := dialAdmin(t, ctx, socketB)

	certA := serveAdminCertify(t, callA, "serve-a-certify", 0)
	certB := serveAdminCertify(t, callB, "serve-b-certify", 0)
	serveAdminPin(t, callA, "serve-a-pin-b", 0, rootB.Owner, certB)
	serveAdminPin(t, callB, "serve-b-pin-a", 0, rootA.Owner, certA)

	// The shared channel + distinct receiver routes, declared on both nodes
	// (B as the destination link, A as the source link).
	channelAB := federation.ChannelBinding{
		ID:               [32]byte{0x52, 0x01},
		SourceRoute:      [32]byte{0x53, 0x01},
		DestinationRoute: [32]byte{0x54, 0x01},
	}
	serveAdminLinkPut(t, callB, "serve-b-link", 0, rootA.Namespace, rootA.StoreID, channelAB, false)
	serveAdminLinkPut(t, callA, "serve-a-link", 0, rootB.Namespace, rootB.StoreID, channelAB, true)

	// B publishes the exact offer view to A's domain.
	offers, _, e := nodeB.Installation.Store.ListOffers(ctx, refB, revB, "", 8)
	if e != nil || len(offers) != 1 {
		t.Fatalf("destination offer listing: %v (%d offers)", e, len(offers))
	}
	offerB := offers[0]
	exposureB := []FederationExposure{{RemoteDomain: rootA.Namespace, Target: offerB.Ref, Revision: offerB.Revision, BindingID: "mcp"}}
	if rev := serveAdminExposurePut(t, callB, "serve-b-exposure", 0, exposureB); rev == 0 {
		t.Fatal("the exposure declaration was not committed")
	}

	source := openFederationSource(t, ctx, nodeA, rootB.Namespace, rootB.StoreID)
	sourceCfg := serveSourceConfig(t, nodeA, source, channelAB)
	ctl := NewControlChannel(relayB, sourceCfg)

	// ---- 1. The genuine bundle-forward: the effect executes exactly once.
	bundle := source.buildForwardBundle(ctx, offerB.Ref, offerB.Revision, json.RawMessage(`{"n":1}`), "serve-control-original")
	before := serveGeneration(nodeB.relay, channelAB.ID)
	if e = sendForwardBundle(ctx, relayB, sourceCfg, bundle); e != nil {
		t.Fatalf("send original bundle: %v", e)
	}
	started := waitServeResult(t, ctx, nodeB.relay, channelAB.ID, before)
	if started.Error != nil {
		t.Fatalf("serving start: %v", started.Error)
	}
	if started.Association == nil {
		t.Fatal("serving start returned no final output association")
	}
	if got := effects.Load(); got != 1 {
		t.Fatalf("served effects = %d; want 1 (effect 0->1 once)", got)
	}

	// The exact retained admission coordinates, derived exactly as the source
	// kernel derives them (no round-trip credential).
	bundleRaw, e := federation.EncodeForwardBundle(bundle)
	if e != nil {
		t.Fatal(e)
	}
	receiptDigest := sha256.Sum256(bundleRaw)
	principal := bundle.Proof.Frame.Principal
	invocationID := bundle.Proof.Frame.InvocationID
	attemptID := federation.AttemptID(rootB, principal, invocationID, receiptDigest)
	if attemptID == "" {
		t.Fatal("no attempt id derived")
	}
	sign := func(action, replayID string, payload []byte) federation.ControlRequest {
		return source.signControl(t, ctx, principal, invocationID, receiptDigest, attemptID, action, replayID, payload)
	}

	// ---- 2. status: the retained head state, no actuation, no frames.
	reply, frames, e := ctl.Execute(ctx, sign("status", "ctrl-status-1", json.RawMessage(`{}`)))
	if e != nil {
		t.Fatalf("status control: %v", e)
	}
	if len(frames) != 0 {
		t.Fatal("status served frames")
	}
	if reply.Result != nil {
		t.Fatal("status returned an actuation result")
	}
	if !reply.Status.Attempted || reply.Status.CancelRequested {
		t.Fatalf("status head = %+v; want attempted, not cancelled", reply.Status)
	}
	if reply.Status.Cursor != (federation.ConsumerCursor{Ordinal: -1}) {
		t.Fatalf("status cursor = %+v; want the initial floor", reply.Status.Cursor)
	}
	if got := effects.Load(); got != 1 {
		t.Fatalf("status reran effects (%d)", got)
	}

	// ---- 3. pull (credit 4): the retained final projection over record 6.
	// The final drain settles shortly after the association commits; a real
	// consumer polls, so retry the fresh pull until the frames are served.
	pullFrames := func(replayID string, payload []byte) (federation.ControlReply, []fabric.InvocationFrame, error) {
		deadline := time.Now().Add(30 * time.Second)
		var lastErr error
		attempt := 0
		for {
			attempt++
			var reply federation.ControlReply
			var frames []fabric.InvocationFrame
			// Each retry signs a genuinely fresh control request (a new
			// replay id): a retried unit is a new committed control, never a
			// byte-identical replay of the previous attempt.
			reply, frames, lastErr = ctl.Execute(ctx, sign("pull", fmt.Sprintf("%s-%d", replayID, attempt), payload))
			if lastErr == nil || time.Now().After(deadline) {
				return reply, frames, lastErr
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	pullPayload := controlPayloadJSON(t, federation.ControlPayload{Cursor: &federation.ConsumerCursor{Ordinal: -1}, Credit: 4})
	reply, frames, e = pullFrames("ctrl-pull-1", pullPayload)
	if e != nil {
		t.Fatalf("pull control: %v", e)
	}
	if reply.Result != nil {
		t.Fatal("pull returned an actuation result")
	}
	if len(frames) == 0 {
		t.Fatal("pull served no frames")
	}
	if frames[0].Kind != fabric.FrameStart || frames[0].Sequence != 0 {
		t.Fatalf("first pull frame = %+v; want FrameStart at 0", frames[0])
	}
	for i, f := range frames {
		if f.Sequence != uint64(i) || f.InvocationID != invocationID {
			t.Fatalf("pull frame %d = %+v; want continuous exact-invocation frames", i, f)
		}
	}
	served := false
	for _, f := range frames {
		if f.Kind == fabric.FrameChunk && bytes.Contains(f.Data, []byte("counted")) {
			served = true
		}
	}
	if !served {
		t.Fatal("the pulled final projection does not carry the served result")
	}
	if got := effects.Load(); got != 1 {
		t.Fatalf("pull reran effects (%d)", got)
	}

	// ---- 4. FORGED ack digest: a genuine fresh ack advancing the initial
	// floor (-1 -> 0) but claiming a wrong frame-0 digest. The production
	// CursorVerifier must recompute the retained frame digest and refuse:
	// no reply, nothing committed, the cursor stays put, and the relay
	// retains the refusal.
	raw0, e := json.Marshal(frames[0])
	if e != nil {
		t.Fatal(e)
	}
	digest0 := sha256.Sum256(raw0)
	forgedDigest := digest0
	forgedDigest[0] ^= 1
	if _, _, e = ctl.Execute(ctx, sign("ack", "ctrl-ack-forged", controlPayloadJSON(t, federation.ControlPayload{
		Cursor:     &federation.ConsumerCursor{Ordinal: -1},
		NextCursor: &federation.ConsumerCursor{Ordinal: 0, FrameDigest: forgedDigest},
	}))); e == nil {
		t.Fatal("a forged ack digest was accepted")
	}
	if got, _, ok := nodeB.relay.latestControlResult(channelAB.ID); !ok || got.Action != "ack" || got.Error == nil {
		t.Fatalf("the relay retained no failure for the forged ack (%+v)", got)
	}
	after, _, e := ctl.Execute(ctx, sign("status", "ctrl-status-forged", json.RawMessage(`{}`)))
	if e != nil {
		t.Fatalf("status after forged ack: %v", e)
	}
	if after.Status.Cursor != (federation.ConsumerCursor{Ordinal: -1}) {
		t.Fatalf("a forged ack moved the cursor: %+v", after.Status.Cursor)
	}

	// ---- 5. ack frame 0 with its genuine digest: the cursor advances and
	// the result digest is the retained frame's own digest.
	nextCursor := federation.ConsumerCursor{Ordinal: 0, FrameDigest: digest0}
	ackRequest := sign("ack", "ctrl-ack-1", controlPayloadJSON(t, federation.ControlPayload{
		Cursor:     &federation.ConsumerCursor{Ordinal: -1},
		NextCursor: &nextCursor,
	}))
	reply, _, e = ctl.Execute(ctx, ackRequest)
	if e != nil {
		t.Fatalf("ack control: %v", e)
	}
	if reply.Result == nil {
		t.Fatal("ack returned no actuation result")
	}
	if reply.Result.State != "confirmed" {
		t.Fatalf("ack result state = %q; want confirmed", reply.Result.State)
	}
	if reply.Result.Cursor == nil || *reply.Result.Cursor != nextCursor {
		t.Fatalf("ack result cursor = %+v; want %+v", reply.Result.Cursor, nextCursor)
	}
	if reply.Result.ResponseDigest != digest0 {
		t.Fatalf("ack response digest = %x; want the retained frame digest %x", reply.Result.ResponseDigest, digest0)
	}
	if reply.Status.Cursor != nextCursor {
		t.Fatalf("ack reply cursor = %+v; want %+v", reply.Status.Cursor, nextCursor)
	}
	// Re-verify the cursor advanced (an independent status read).
	verify, _, e := ctl.Execute(ctx, sign("status", "ctrl-status-2", json.RawMessage(`{}`)))
	if e != nil {
		t.Fatalf("status re-verify: %v", e)
	}
	if verify.Status.Cursor != nextCursor {
		t.Fatalf("cursor did not advance: %+v", verify.Status.Cursor)
	}

	// ---- 6. ack replay (byte-identical request): the retained result comes
	// back, no re-actuation.
	replayed, _, e := ctl.Execute(ctx, ackRequest)
	if e != nil {
		t.Fatalf("ack replay: %v", e)
	}
	if replayed.Result == nil || !reflect.DeepEqual(*replayed.Result, *reply.Result) {
		t.Fatalf("ack replay result = %+v; want the retained %+v", replayed.Result, reply.Result)
	}

	// ---- 7. pull with a STALE cursor: the retained floor has advanced — no
	// reply (StaleContinuation), nothing served.
	stalePayload := controlPayloadJSON(t, federation.ControlPayload{Cursor: &federation.ConsumerCursor{Ordinal: -1}, Credit: 4})
	if _, staleFrames, e := ctl.Execute(ctx, sign("pull", "ctrl-pull-stale", stalePayload)); e == nil {
		t.Fatalf("a stale-cursor pull was served (%d frames)", len(staleFrames))
	}

	// ---- 8. cancel: the stop intent commits and the stop port's result
	// digest independently recomputes to the committed head state.
	cancelReply, _, e := ctl.Execute(ctx, sign("cancel", "ctrl-cancel-1", json.RawMessage(`{}`)))
	if e != nil {
		t.Fatalf("cancel control: %v", e)
	}
	if cancelReply.Result == nil || cancelReply.Result.State != "confirmed" || !cancelReply.Result.StopAcknowledged {
		t.Fatalf("cancel result = %+v; want a confirmed stop acknowledgment", cancelReply.Result)
	}
	if !cancelReply.Status.CancelRequested {
		t.Fatal("cancel did not commit the stop intent")
	}
	if got := effects.Load(); got != 1 {
		t.Fatalf("cancel reran effects (%d)", got)
	}
	// The destination independently recomputes the committed head-state digest
	// in a fresh transaction: the reply's ResponseDigest must equal it.
	serving := nodeB.relay.servingForChannel(channelAB.ID)
	if serving == nil {
		t.Fatal("the relay retained no serving stack")
	}
	owner, e := nodeB.Installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var headStatus federation.AdmissionStatus
	if e = nodeB.Installation.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
		var err error
		headStatus, err = serving.admissions.StatusTx(ctx, tx, principal, invocationID)
		return err
	}); e != nil {
		t.Fatalf("head state recompute: %v", e)
	}
	if !headStatus.CancelRequested || headStatus.Cursor != nextCursor {
		t.Fatalf("retained head state = %+v; want stop intent + advanced cursor", headStatus)
	}
	if controlHeadStateDigest(headStatus) != cancelReply.Result.ResponseDigest {
		t.Fatalf("cancel response digest %x does not recompute to the committed head state %x", cancelReply.Result.ResponseDigest, controlHeadStateDigest(headStatus))
	}

	// ---- 9. final status: the stop intent is durable.
	final, _, e := ctl.Execute(ctx, sign("status", "ctrl-status-4", json.RawMessage(`{}`)))
	if e != nil {
		t.Fatalf("final status: %v", e)
	}
	if !final.Status.CancelRequested || final.Status.Cursor != nextCursor {
		t.Fatalf("final status = %+v; want the committed stop intent + cursor", final.Status)
	}
	if got := effects.Load(); got != 1 {
		t.Fatalf("final served effects = %d; want exactly 1", got)
	}
}
