package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

var (
	// ErrHostedSourceNotFound: the daemon never consumed this invocation.
	ErrHostedSourceNotFound = errors.New("hosted invocation final output not retained")
	// ErrHostedSourceFailed: the retained final state is a committed native
	// failure/stopped terminal (the once-composed output is retained).
	ErrHostedSourceFailed = errors.New("hosted invocation final output retained as failed")
	// ErrHostedSourceUnavailable: the retained final state is truthfully
	// unavailable (the final output was never fully consumable).
	ErrHostedSourceUnavailable = errors.New("hosted invocation final output unavailable")
)

// HostedSourceFinalOutput is the truthful read-port view of a consumed hosted
// invocation's final output.
type HostedSourceFinalOutput struct {
	// State is the truthful retention state: streaming | complete | failed |
	// unavailable.
	State string
	// Output is the composed FINAL intercepted output plaintext — set only
	// for complete and failed rows (the once-generated retained output). It is
	// never a partial raw pre-interceptor fallback and never invented from
	// EOF, idle or an ack.
	Output []byte
	// Sealed / SealedAAD is the retained sealed ciphertext and its AAD
	// (complete and failed rows): the same protected shape the worker stream
	// uses, encrypted under the pinned source epoch of the network keyring.
	Sealed    e2ee.EncryptedPayloadV1
	SealedAAD e2ee.AAD
	// Terminal is the actual committed native terminal observation
	// (complete and failed rows only).
	Terminal *sessionworker.NativeObservation
	// Reason is the truthful reason (failed and unavailable rows).
	Reason string
	// DataBytes / CursorOrdinal are the in-progress evidence (streaming rows).
	DataBytes     int
	CursorOrdinal int64
}

// ConsumeHostedInvocationFinalOutput is the daemon-side CONSUMER of the
// original worker's invocation stream: it waits for the retained original
// source (the worker's readiness lane, never a polling timer), subscribes and
// reads verified pages, checkpoints the composed output in daemon state
// BEFORE acking each page, and composes + retains the full final output
// EXACTLY ONCE when the terminal observation arrives. It is IDEMPOTENT and
// RESTARTABLE: a re-entry for the same instance/command resumes from the
// persisted consumer state (the SAME retained original source — the worker
// outlives daemon restarts and controller replacement) and never re-runs or
// re-accepts paid work. EOF, idle and acks are NOT completion: only the
// terminal observation completes. Detaching the delivery connection changes
// nothing — consumption is bound to the daemon, not the host connection.
func (d *Daemon) ConsumeHostedInvocationFinalOutput(ctx context.Context, profile fabricagent.HostedProfile, proof transport.NativeDispatchProof) error {
	// Static authority validation BEFORE any retention row: a proof that does
	// not bind exactly to the profile (the same checks the readiness-lane wait
	// applies) is refused at the door — nothing is retained for a refused
	// proof, and no consumption can ever start under it.
	if d == nil || d.state == nil || ctx == nil || profile.Validate() != nil ||
		proof.InvocationSource == nil || proof.TaskSource != nil ||
		proof.DispatchSequence <= 0 || proof.SourceCommandID == "" || proof.SourceAdmissionID == "" ||
		proof.OwnershipID != profile.OwnershipID || proof.OwnershipGeneration != profile.Scope.Generation ||
		proof.InvocationSource.Validate() != nil ||
		proof.InvocationSource.InputAAD.NetworkID != profile.NetworkID ||
		proof.InvocationSource.InputAAD.Recipient != profile.Scope.InstanceID {
		return ErrNativeObservationConflict
	}
	instanceID := profile.Scope.InstanceID
	commandID := proof.SourceCommandID
	row, exists, err := d.state.LoadHostedSourceFinal(ctx, instanceID, commandID)
	if err != nil {
		return err
	}
	if exists && row.State != "streaming" {
		// A terminal row IS the once-composed retained final output: re-entry
		// returns it (idempotent), it never recomposes or overwrites.
		switch row.State {
		case "complete":
			return nil
		case "failed":
			return ErrHostedSourceFailed
		default:
			return ErrHostedSourceUnavailable
		}
	}
	if exists {
		// A streaming row resumes ONLY under its pinned authority: a different
		// profile/proof for the same key is a conflict, never an overwrite.
		profileJSON, err := json.Marshal(profile)
		if err != nil {
			return err
		}
		proofJSON, err := json.Marshal(proof)
		if err != nil {
			return err
		}
		if string(profileJSON) != row.Profile || string(proofJSON) != row.Proof {
			return ErrNativeObservationConflict
		}
	}
	// One live consumer per (instance, command): the startup-resume pass must
	// never double-launch a running consumption.
	key := instanceID + "\x00" + commandID
	holder := &hostedSourceConsumerHolder{}
	holder.ctx, holder.cancel = context.WithCancel(ctx)
	d.hostedSourceMu.Lock()
	if d.hostedSourceConsumers == nil {
		d.hostedSourceConsumers = map[string]*hostedSourceConsumerHolder{}
	}
	if _, live := d.hostedSourceConsumers[key]; live {
		d.hostedSourceMu.Unlock()
		holder.cancel()
		return nil
	}
	d.hostedSourceConsumers[key] = holder
	d.hostedSourceMu.Unlock()
	defer func() {
		d.hostedSourceMu.Lock()
		if d.hostedSourceConsumers[key] == holder {
			delete(d.hostedSourceConsumers, key)
		}
		d.hostedSourceMu.Unlock()
	}()
	return d.consumeHostedInvocation(holder.ctx, profile, proof, row, exists)
}

// hostedSourceConsumerHolder identifies one live consumption (pointer
// equality fences the double-launch check) and carries its cancel.
type hostedSourceConsumerHolder struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// StopHostedSourceConsumer stops an in-flight consumption (its context only:
// the worker's stream is NOT unsubscribed — detaching never stops the paid
// work, and only an explicit authenticated cancellation does). It reports
// whether a consumer was running.
func (d *Daemon) StopHostedSourceConsumer(instanceID, commandID string) bool {
	d.hostedSourceMu.Lock()
	defer d.hostedSourceMu.Unlock()
	holder, ok := d.hostedSourceConsumers[instanceID+"\x00"+commandID]
	if !ok {
		return false
	}
	holder.cancel()
	return true
}

// resumeHostedSourceConsumers re-enters consumption for every persisted
// in-flight row after a fresh host session: a daemon restart (or controller
// replacement) must retain the SAME original source, and the worker's
// retained FULL journal re-resolves it. Rows with a live consumer are skipped
// by the entry point's double-launch fence; deterministic conflicts finalize
// the row (it is no longer in-flight), transient failures are retried by the
// next recovery pass.
func (d *Daemon) resumeHostedSourceConsumers(conn *websocket.Conn) {
	if d == nil || d.state == nil {
		return
	}
	rows, err := d.state.InFlightHostedSourceFinals(d.turnCtx, 64)
	if err != nil {
		d.Log.Warn("list in-flight hosted source finals", "err", err)
		return
	}
	for _, row := range rows {
		var profile fabricagent.HostedProfile
		var proof transport.NativeDispatchProof
		if json.Unmarshal([]byte(row.Profile), &profile) != nil || profile.Validate() != nil ||
			json.Unmarshal([]byte(row.Proof), &proof) != nil || proof.SourceCommandID != row.CommandID {
			d.Log.Warn("skip in-flight hosted source final with unpinnable authority",
				"instance", row.InstanceID, "command", row.CommandID)
			continue
		}
		go func(profile fabricagent.HostedProfile, proof transport.NativeDispatchProof) {
			if err := d.ConsumeHostedInvocationFinalOutput(d.turnCtx, profile, proof); err != nil && !errors.Is(err, context.Canceled) {
				d.Log.Warn("hosted invocation final output consumption stopped",
					"instance", row.InstanceID, "command", row.CommandID, "err", err)
			}
		}(profile, proof)
	}
}

// hostedSourceReadBackoff spaces the sequential invocation_read rounds when
// the worker has no pending projection yet (its own 200 ms projection timer
// moves deltas into Pending). It is a bounded sequential wait inside the
// consumer — the source WAIT itself is the worker's readiness lane, never a
// timer.
const hostedSourceReadBackoff = 100 * time.Millisecond

// hostedSourceRenewWindow renews the worker subscription before half its TTL
// has elapsed, so a slow checkpoint can never let the stream expire under the
// consumer.
const hostedSourceRenewWindow = 2 * time.Second

// hostedSourceSubscriptionTTL mirrors the worker's invocationStreamTTL (5 s):
// a successful renew resets the subscription to now+TTL on the worker side.
const hostedSourceSubscriptionTTL = 5 * time.Second

// hostedSourceWorkerFailure maps a worker-side stream/source failure to the
// terminal unavailable reason when the condition is PERMANENT — the retained
// source or stream is gone, or irreversibly conflicts with the pinned
// authority. The worker's stream verbs surface their errors as plain IPC
// strings; the daemon must split permanent conditions (finalize the in-flight
// row as truthfully unavailable, exactly once) from transient ones
// (controller fencing, transport failures, an in-flight turn, a not-yet-ready
// worker link — return the error so the recovery pass retries the SAME row).
// Without this split a reclaimed worker state livelocks the resume loop
// forever (the row stays streaming and is re-entered on every pass).
func hostedSourceWorkerFailure(err error, streamVerb bool) (reason string, permanent bool) {
	switch {
	case strings.Contains(err.Error(), sessionworker.ErrInvocationStreamExpired.Error()):
		return "stream_expired", true
	case strings.Contains(err.Error(), sql.ErrNoRows.Error()):
		// The worker prunes its intent journal when the daemon acks the intent
		// (after the turn completes) while the invocation stream and turn
		// source remain retained: the readiness-lane source is then
		// unresolvable, and a pruned subscription/stream means the retained
		// window was reclaimed after consumer expiry/unclaim.
		if streamVerb {
			return "stream_expired", true
		}
		return "source_unavailable", true
	case strings.Contains(err.Error(), sessionworker.ErrConflict.Error()):
		if streamVerb {
			return "stream_conflict", true
		}
		return "source_conflict", true
	case strings.Contains(err.Error(), "original invocation completed without retained native source"):
		return "source_unavailable", true
	default:
		return "", false
	}
}

// finalizeHostedSourceUnavailable is the streaming→unavailable transition for
// a consumption that can never complete: exactly one caller wins the CAS (a
// competing finalize is an idempotent no-op), and the row's evidence
// (checkpointed prefix, cursor, pinned authority) is retained for the
// truthful read port.
func (d *Daemon) finalizeHostedSourceUnavailable(ctx context.Context, instanceID, commandID, reason string) error {
	if _, err := d.state.FinalizeHostedSourceFinal(ctx, instanceID, commandID, "unavailable", "", reason, nil); err != nil &&
		!errors.Is(err, sql.ErrNoRows) && !errors.Is(err, ErrHostedSourceConflict) {
		return err
	}
	return ErrHostedSourceUnavailable
}

func (d *Daemon) consumeHostedInvocation(ctx context.Context, profile fabricagent.HostedProfile, proof transport.NativeDispatchProof, row HostedSourceFinalRow, exists bool) error {
	instanceID := profile.Scope.InstanceID
	commandID := proof.SourceCommandID

	// (a) Pin the in-flight row FIRST: durable evidence that this
	// invocation's final output is being consumed, so any later failure —
	// transient or permanent — is restartable and truthful (a transient
	// failure leaves a streaming row the recovery pass re-enters). The
	// sealed-output AAD derives from the dispatch proof's invocation input
	// AAD (the worker verifies the retained source's input AAD is canonically
	// identical to the dispatch one) and is fixed for the row's life (one GCM
	// binding across every checkpoint and the final seal).
	var err error
	if !exists {
		outAAD := proof.InvocationSource.InputAAD
		outAAD.ObjectType = e2ee.ObjectTypeInvocationOutput
		outAAD.Sender = instanceID
		outAAD.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		row, err = d.state.EnsureHostedSourceFinal(ctx, instanceID, commandID, profile, proof, outAAD)
		if err != nil {
			return err
		}
	}
	var aad e2ee.AAD
	if err = json.Unmarshal([]byte(row.AAD), &aad); err != nil {
		return ErrNativeObservationConflict
	}
	keyring, err := crypto.LoadKeyring(d.StateDir, profile.NetworkID)
	if err != nil {
		return err
	}
	epoch, found := keyring.EpochByID(aad.KeyEpochID)
	if !found {
		return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "epoch_missing")
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return err
	}
	defer clear(key[:])

	// (b) The retained original source. A resumed row uses the source pinned
	// at first consumption: the worker prunes its intent journal when the
	// daemon acks the intent (after the turn completes) while the invocation
	// stream and turn source remain retained, so re-waiting the readiness
	// lane would fail on the pruned intent row even though the SAME source is
	// still resolvable through the retained stream (the worker re-verifies
	// the identity against the retained turn source on subscribe). A first
	// consumption — or a resume before any page was checkpointed — waits on
	// the worker's readiness lane, never a polling timer.
	var source sessionworker.NativeTurnSource
	if row.Source != "" {
		if err := json.Unmarshal([]byte(row.Source), &source); err != nil {
			return ErrNativeObservationConflict
		}
		if source.Sequence != proof.DispatchSequence || source.SourceCommandID != proof.SourceCommandID ||
			source.SourceAdmissionID != proof.SourceAdmissionID || source.SourceInvocation == nil ||
			source.SourceInvocation.InvocationID != proof.InvocationSource.InvocationID ||
			!bytes.Equal(source.SourceInvocation.InputAAD.CanonicalBytes(), proof.InvocationSource.InputAAD.CanonicalBytes()) {
			return ErrNativeObservationConflict
		}
	} else {
		source, err = d.WaitHostedOriginalSource(ctx, profile, proof)
		if err != nil {
			if reason, permanent := hostedSourceWorkerFailure(err, false); permanent {
				return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, reason)
			}
			if errors.Is(err, ErrNativeObservationConflict) {
				return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "source_conflict")
			}
			return err // transient: the in-flight row is retried by the recovery pass
		}
	}

	// (c) The daemon's shared original-worker proxy (readers never Close it).
	proxy, err := d.OriginalHostedWorker(ctx, profile)
	if err != nil {
		return err
	}

	// Resume evidence: the persisted checkpoint (a fresh row starts empty).
	buf := make([]byte, 0, row.DataBytes)
	if len(row.Ciphertext) > 0 {
		var env e2ee.EncryptedPayloadV1
		if err := json.Unmarshal(row.Ciphertext, &env); err != nil {
			return ErrNativeObservationConflict
		}
		plain, err := e2ee.Decrypt(env, key, aad)
		if err != nil {
			return ErrNativeObservationConflict
		}
		buf = plain
		defer clear(plain)
	}
	var sourceJSON, originJSON []byte
	if row.Source != "" {
		sourceJSON = []byte(row.Source)
	}
	if row.Origin != "" {
		originJSON = []byte(row.Origin)
	}

	identity := sessionworker.InvocationStreamIdentity{
		Sequence:          source.Sequence,
		NativeGeneration:  source.NativeGeneration,
		SourceCommandID:   source.SourceCommandID,
		SourceAdmissionID: source.SourceAdmissionID,
		InvocationID:      source.SourceInvocation.InvocationID,
	}
	// (d) Subscribe with the retained source identity. A closed/expired stream
	// (the retention window lapsed before a terminal was consumed) is a
	// truthful unavailability, never a completion.
	resp, err := proxy.InvocationStream(ctx, "invocation_subscribe", sessionworker.InvocationStreamRequest{Source: identity})
	if err == nil && resp.InvocationSubscription == nil {
		err = ErrNativeObservationConflict
	}
	if err != nil {
		if reason, permanent := hostedSourceWorkerFailure(err, true); permanent {
			return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, reason)
		}
		if errors.Is(err, ErrNativeObservationConflict) {
			return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "stream_conflict")
		}
		return err
	}
	sub := *resp.InvocationSubscription
	streamReq := func(ordinal int64, digest string) sessionworker.InvocationStreamRequest {
		return sessionworker.InvocationStreamRequest{Source: identity, SubscriptionID: sub.ID, ProjectionOrdinal: ordinal, Digest: digest}
	}
	// The ack is the ONLY worker side effect per page — and it is always
	// sent after the page's checkpoint is durable (checkpoint-before-ACK).
	ack := func(ordinal int64, digest string) error {
		_, aerr := proxy.InvocationStream(ctx, "invocation_ack", streamReq(ordinal, digest))
		return aerr
	}
	cursorOrdinal := row.CursorOrdinal
	cursorDigest := row.CursorDigest
	dataBytes := len(buf)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Until(sub.ExpiresAt) < hostedSourceRenewWindow {
			if _, err := proxy.InvocationStream(ctx, "invocation_renew", streamReq(0, "")); err != nil {
				if reason, permanent := hostedSourceWorkerFailure(err, true); permanent {
					return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, reason)
				}
				return err
			}
			sub.ExpiresAt = time.Now().Add(hostedSourceSubscriptionTTL)
		}
		resp, err := proxy.InvocationStream(ctx, "invocation_read", streamReq(0, ""))
		if err != nil {
			if reason, permanent := hostedSourceWorkerFailure(err, true); permanent {
				return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, reason)
			}
			return err
		}
		if resp.InvocationProjection == nil {
			// No pending projection yet (the worker's projection timer has not
			// moved a delta in, or all deltas are acked and the terminal is
			// still being committed). Sequential bounded wait — EOF/idle/ack
			// are NOT completion.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(hostedSourceReadBackoff):
			}
			continue
		}
		proj := *resp.InvocationProjection
		// (d) Decrypt + the shared decoder's source binding, then the
		// adapter's own per-page verification.
		rng, err := d.OpenHostedOriginalProjection(profile, source, proj)
		if err != nil {
			return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "projection_conflict")
		}
		// FRESH SAME-TX SOURCE AUTHORITY per page: re-resolve the profile
		// through the daemon's resolve port (the same port the delivery guard
		// uses); any mismatch is a conflict that stops consumption — never a
		// partial accept.
		if d.HostedInvocationGuard == nil {
			return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "source_authority_unavailable")
		}
		if _, current, err := d.HostedInvocationGuard.resolve(ctx, instanceID); err != nil {
			return err
		} else if current != profile {
			return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "source_authority_changed")
		}
		// Monotonic cursors, never blindly trusted from the wire: the worker
		// holds exactly ONE pending projection — either the last checkpointed
		// page (crash between its checkpoint and ack: re-read it idempotently)
		// or the strictly next one.
		switch proj.Ordinal {
		case cursorOrdinal:
			if cursorDigest == "" || proj.Digest != cursorDigest {
				return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "cursor_conflict")
			}
			if int64(len(rng.Data)) != 0 && (rng.ByteOffset+int64(len(rng.Data)) != int64(dataBytes) || !bytes.Equal(buf[rng.ByteOffset:], rng.Data)) {
				return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "cursor_conflict")
			}
		case cursorOrdinal + 1:
			if rng.ByteOffset != int64(dataBytes) {
				return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "cursor_conflict")
			}
			if len(rng.Data) > 0 {
				buf = append(buf, rng.Data...)
				dataBytes = len(buf)
			}
		default:
			return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "cursor_conflict")
		}
		// Retained origin: pinned on the first page, matched on every later
		// one (the origin is inside the GCM-protected page payload).
		if len(originJSON) == 0 {
			originJSON = append(json.RawMessage(nil), rng.Origin...)
		} else if !bytes.Equal(originJSON, rng.Origin) {
			return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "origin_conflict")
		}
		if len(sourceJSON) == 0 {
			if sourceJSON, err = json.Marshal(source); err != nil {
				return err
			}
		}
		// (e) CHECKPOINT BEFORE ACK: persist the consumed page (appended final
		// output ciphertext + cursor ordinal/digest) to daemon state BEFORE
		// sending invocation_ack. The order is load-bearing: the worker
		// truncates deltas below an acked cursor, so the daemon must already
		// retain the page. The capacity bound is enforced before acceptance.
		sealed, err := e2ee.Encrypt(buf, key, aad)
		if err != nil {
			return err
		}
		if err := d.state.CheckpointHostedSourceFinal(ctx, instanceID, commandID, sourceJSON, originJSON, sealed, dataBytes, proj.Ordinal, proj.Digest); err != nil {
			if errors.Is(err, ErrHostedSourceCapacity) {
				return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "capacity_exhausted")
			}
			return err
		}
		cursorOrdinal, cursorDigest = proj.Ordinal, proj.Digest
		// (f) Terminal semantics: only a genuine terminal observation completes.
		switch {
		case rng.Terminal != nil:
			if len(rng.Data) > 0 {
				// The worker never couples terminal and data on one page; a
				// page with both is a conflict, not a composition.
				return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "terminal_conflict")
			}
			terminalJSON, err := json.Marshal(rng.Terminal)
			if err != nil {
				return err
			}
			state, reason := "complete", ""
			switch rng.Terminal.Event.Type {
			case session.EventTurnCompleted:
			case session.EventTurnFailed, session.EventSessionStopped:
				state, reason = "failed", "terminal_" + rng.Terminal.Event.Type
			default:
				return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, "terminal_conflict")
			}
			var finalCipher *e2ee.EncryptedPayloadV1
			if dataBytes == 0 {
				// A terminal with no data pages seals the (empty) composed
				// output so every terminal row carries one sealed output.
				// (A data page always carries data, so zero accumulated bytes
				// means no page was ever checkpointed.)
				empty, err := e2ee.Encrypt(buf, key, aad)
				if err != nil {
					return err
				}
				finalCipher = &empty
			}
			// The streaming→terminal transition is ONE CAS: a crash-restart
			// can never compose the final output twice. Persist BEFORE the
			// terminal ack (checkpoint-before-ACK); a crash after the persist
			// and before the ack resumes over the terminal row (idempotent
			// return, the worker's stream self-expires) — never a second
			// effect.
			if _, err := d.state.FinalizeHostedSourceFinal(ctx, instanceID, commandID, state, string(terminalJSON), reason, finalCipher); err != nil &&
				!errors.Is(err, sql.ErrNoRows) && !errors.Is(err, ErrHostedSourceConflict) {
				return err
			}
			if err := ack(proj.Ordinal, proj.Digest); err != nil {
				// The row is terminal and retained; an ack failure only delays
				// the worker's own stream cleanup. Report the retained state —
				// the composition is never retried.
				if state == "complete" {
					return nil
				}
				return ErrHostedSourceFailed
			}
			if state == "complete" {
				return nil
			}
			return ErrHostedSourceFailed
		case rng.DeliveryError != "":
			// A delivery error WITHOUT a terminal: the truthful unavailable
			// state, exactly once. Never complete. Persist before the ack
			// (checkpoint-before-ACK): the ack truncates the worker's deltas.
			if _, err := d.state.FinalizeHostedSourceFinal(ctx, instanceID, commandID, "unavailable", "", rng.DeliveryError, nil); err != nil &&
				!errors.Is(err, sql.ErrNoRows) && !errors.Is(err, ErrHostedSourceConflict) {
				return err
			}
			_ = ack(proj.Ordinal, proj.Digest)
			return ErrHostedSourceUnavailable
		default:
			if err := ack(proj.Ordinal, proj.Digest); err != nil {
				// The page is already checkpointed (checkpoint-before-ACK); a
				// permanent stream loss means no terminal will ever arrive.
				if reason, permanent := hostedSourceWorkerFailure(err, true); permanent {
					return d.finalizeHostedSourceUnavailable(ctx, instanceID, commandID, reason)
				}
				return err
			}
		}
	}
}

// ReadHostedInvocationFinalOutput is the truthful read port over the retained
// final output (what step 6's node routing consumes): complete/failed rows
// decrypt the sealed output with the network keyring (pinned source epoch)
// and return the composed output + the actual terminal observation; streaming
// rows report the truthful in-progress state (NEVER a partial raw
// pre-interceptor output as the final, never EOF/idle as completion); unknown
// keys are a truthful not-found.
func (d *Daemon) ReadHostedInvocationFinalOutput(ctx context.Context, instanceID, commandID string) (HostedSourceFinalOutput, error) {
	if d == nil || d.state == nil {
		return HostedSourceFinalOutput{}, ErrHostedSourceNotFound
	}
	row, ok, err := d.state.LoadHostedSourceFinal(ctx, instanceID, commandID)
	if err != nil {
		return HostedSourceFinalOutput{}, err
	}
	if !ok {
		return HostedSourceFinalOutput{}, ErrHostedSourceNotFound
	}
	out := HostedSourceFinalOutput{State: row.State, Reason: row.Reason, DataBytes: row.DataBytes, CursorOrdinal: row.CursorOrdinal}
	if row.State != "complete" && row.State != "failed" {
		return out, nil
	}
	var aad e2ee.AAD
	if err := json.Unmarshal([]byte(row.AAD), &aad); err != nil {
		return HostedSourceFinalOutput{}, ErrNativeObservationConflict
	}
	out.SealedAAD = aad
	if len(row.Ciphertext) > 0 {
		var env e2ee.EncryptedPayloadV1
		if err := json.Unmarshal(row.Ciphertext, &env); err != nil {
			return HostedSourceFinalOutput{}, ErrNativeObservationConflict
		}
		out.Sealed = env
		keyring, err := crypto.LoadKeyring(d.StateDir, aad.NetworkID)
		if err != nil {
			return HostedSourceFinalOutput{}, err
		}
		epoch, found := keyring.EpochByID(aad.KeyEpochID)
		if !found {
			return HostedSourceFinalOutput{}, ErrNativeObservationConflict
		}
		key, err := epoch.KeyArray()
		if err != nil {
			return HostedSourceFinalOutput{}, err
		}
		defer clear(key[:])
		out.Output, err = e2ee.Decrypt(env, key, aad)
		if err != nil {
			return HostedSourceFinalOutput{}, err
		}
	} else {
		out.Output = []byte{}
	}
	if row.Terminal != "" {
		var term sessionworker.NativeObservation
		if err := json.Unmarshal([]byte(row.Terminal), &term); err != nil {
			return HostedSourceFinalOutput{}, ErrNativeObservationConflict
		}
		out.Terminal = &term
	}
	return out, nil
}
