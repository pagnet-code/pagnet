//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

// fakeFirstLine mirrors the fake runtime's input fold (one line, 80-byte cap)
// so the tests compute the worker-side output oracle exactly.
func fakeFirstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

// fakeEchoOutput is the fake persistent runtime's deterministic output for a
// single-line-hosted prompt (kind "invocation" is the dispatched InputKind).
func fakeEchoOutput(prompt string) string {
	return fmt.Sprintf("[fake-persist invocation] handled %s: %s", fakeFirstLine(prompt), fakeFirstLine(prompt))
}

// fakeFullOutput is the fake runtime's PAGNET_FAKE_FULL_OUTPUT_REPEAT output:
// the FULL input is repeated `repeat` times first, then echoed twice in the
// deterministic template (kind "invocation").
func fakeFullOutput(prompt string, repeat int) string {
	full := strings.Repeat(prompt, repeat)
	return fmt.Sprintf("[fake-persist invocation] handled %s: %s", full, full)
}

// waitForHostedSource polls the daemon state (test-side waiting on daemon
// state, not a production polling timer) until the row reaches wantState.
func waitForHostedSource(t *testing.T, f *hostedGuardFixture, commandID, wantState string, timeout time.Duration) HostedSourceFinalRow {
	t.Helper()
	ctx := t.Context()
	var last HostedSourceFinalRow
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		row, ok, err := f.d.state.LoadHostedSourceFinal(ctx, f.profile.Scope.InstanceID, commandID)
		if err != nil {
			t.Fatalf("load hosted source final: %v", err)
		}
		if ok {
			last = row
			if row.State == wantState {
				return row
			}
			if row.State != "streaming" {
				t.Fatalf("hosted source final settled in %q (reason %q), want %q: %+v", row.State, row.Reason, wantState, row)
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("hosted source final never reached %q (last: state=%q reason=%q pages=%d cursor=%d): %+v",
		wantState, last.State, last.Reason, last.Pages, last.CursorOrdinal, last)
	return last
}

// waitForHostedSourceStreamingPages waits for at least wantPages checkpointed
// pages while the row is still in-flight (mid-consumption).
func waitForHostedSourceStreamingPages(t *testing.T, f *hostedGuardFixture, commandID string, wantPages int, timeout time.Duration) HostedSourceFinalRow {
	t.Helper()
	ctx := t.Context()
	var last HostedSourceFinalRow
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		row, ok, err := f.d.state.LoadHostedSourceFinal(ctx, f.profile.Scope.InstanceID, commandID)
		if err != nil {
			t.Fatalf("load hosted source final: %v", err)
		}
		if ok {
			last = row
			if row.State != "streaming" {
				t.Fatalf("hosted source final settled in %q (reason %q) before %d pages were checkpointed: %+v", row.State, row.Reason, wantPages, row)
			}
			if row.Pages >= wantPages {
				return row
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("hosted source final never checkpointed %d pages while streaming (last: state=%q pages=%d): %+v",
		wantPages, last.State, last.Pages, last)
	return last
}

// resumeUntilTerminal drives the production startup-resume pass (the same
// entry point a daemon restart re-calls) until the row leaves streaming.
func resumeUntilTerminal(t *testing.T, f *hostedGuardFixture, commandID string, timeout time.Duration) HostedSourceFinalRow {
	t.Helper()
	ctx := t.Context()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f.d.resumeHostedSourceConsumers(f.conn)
		row, ok, err := f.d.state.LoadHostedSourceFinal(ctx, f.profile.Scope.InstanceID, commandID)
		if err != nil {
			t.Fatalf("load hosted source final: %v", err)
		}
		if ok && row.State != "streaming" {
			return row
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("resume never settled the hosted source final (command %s)", commandID)
	return HostedSourceFinalRow{}
}

func TestDaemonHostedSourceAdapterConsumesFinalOutput(t *testing.T) {
	f := newHostedGuardFixture(t)
	invocation := domain.NewID().String()
	prompt := "exact retained hosted prompt"
	delivered, proof := f.reserve(invocation, prompt, nil)

	p := transport.NetworkEventPayload{CommandID: delivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proof}
	if errMsg, _ := f.deliver(p)["error"].(string); errMsg != "" {
		t.Fatalf("canonical invocation delivery refused: %s", errMsg)
	}
	// The accepted turn executed the retained prompt verbatim (worker-side
	// session state is the execution oracle).
	f.waitForTurns(1, prompt)

	// The daemon-side consumer (triggered by the accepted delivery) composes
	// and retains the final output exactly once.
	row := waitForHostedSource(t, f, delivered.CommandID, "complete", 60*time.Second)
	if row.Terminal == "" {
		t.Fatalf("complete row has no terminal observation: %+v", row)
	}
	out, err := f.d.ReadHostedInvocationFinalOutput(t.Context(), f.profile.Scope.InstanceID, delivered.CommandID)
	if err != nil {
		t.Fatalf("read port: %v", err)
	}
	if out.State != "complete" {
		t.Fatalf("read port state = %q, want complete", out.State)
	}
	// Byte-exact against the worker-side deterministic output oracle.
	want := []byte(fakeEchoOutput(prompt))
	if !bytes.Equal(out.Output, want) {
		t.Fatalf("final output = %q (len %d), want %q (len %d)", out.Output, len(out.Output), want, len(want))
	}
	if out.Terminal == nil || out.Terminal.Event.Type != session.EventTurnCompleted {
		t.Fatalf("terminal observation = %+v, want a committed turn.completed", out.Terminal)
	}
	if out.SealedAAD.ObjectType != e2ee.ObjectTypeInvocationOutput {
		t.Fatalf("sealed AAD object type = %q, want %s", out.SealedAAD.ObjectType, e2ee.ObjectTypeInvocationOutput)
	}
	if out.Sealed.Ciphertext == "" || out.SealedAAD.CreatedAt == "" {
		t.Fatalf("sealed output not retained: %+v", out.Sealed)
	}

	// Idempotent re-entry over the complete row: returns the retained output,
	// never recomposes or overwrites.
	before := row
	if err := f.d.ConsumeHostedInvocationFinalOutput(t.Context(), f.profile, proof); err != nil {
		t.Fatalf("re-entry over complete row: %v", err)
	}
	after, _, err := f.d.state.LoadHostedSourceFinal(t.Context(), f.profile.Scope.InstanceID, delivered.CommandID)
	if err != nil {
		t.Fatal(err)
	}
	if after.State != "complete" || after.Terminal != before.Terminal || after.DataBytes != before.DataBytes || after.Pages != before.Pages {
		t.Fatalf("re-entry overwrote the retained final row: before=%+v after=%+v", before, after)
	}
	// Still exactly ONE turn for the source (no second effect).
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if turns, _ := f.fakeTurns(); turns != 1 {
			t.Fatalf("re-entry executed a second turn: %d", turns)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDaemonHostedSourceAdapterComposesMultiChunkByteExact(t *testing.T) {
	f := newHostedGuardFixture(t, withWorkerEnv("PAGNET_FAKE_OUTPUT_CHUNK_BYTES=1024", "PAGNET_FAKE_FULL_OUTPUT_REPEAT=3"))
	// A multi-KiB Unicode prompt with newlines; the fake echoes the FULL
	// input three times with 1 KiB chunks → ~264 KiB of output → several
	// 64 KiB projection pages.
	line := "ünïcode 日本語 ✓\nmixed lines and 中文\n"
	prompt := strings.Repeat(line, 1024)
	invocation := domain.NewID().String()
	delivered, proof := f.reserve(invocation, prompt, nil)

	p := transport.NetworkEventPayload{CommandID: delivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proof}
	if errMsg, _ := f.deliver(p)["error"].(string); errMsg != "" {
		t.Fatalf("canonical invocation delivery refused: %s", errMsg)
	}
	// The fake runtime folds the input to its first line for session state.
	f.waitForTurns(1, fakeFirstLine(prompt))

	row := waitForHostedSource(t, f, delivered.CommandID, "complete", 120*time.Second)
	if row.Pages < 2 {
		t.Fatalf("multi-chunk output produced %d projection pages, want > 1", row.Pages)
	}
	out, err := f.d.ReadHostedInvocationFinalOutput(t.Context(), f.profile.Scope.InstanceID, delivered.CommandID)
	if err != nil {
		t.Fatalf("read port: %v", err)
	}
	want := []byte(fakeFullOutput(prompt, 3))
	if !bytes.Equal(out.Output, want) {
		t.Fatalf("composed multi-chunk output diverges at len %d vs want %d (first diff around byte %d)",
			len(out.Output), len(want), firstDiffByte(out.Output, want))
	}
}

func firstDiffByte(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

func TestDaemonHostedSourceAdapterCheckpointBeforeAckResumesWithoutLoss(t *testing.T) {
	f := newHostedGuardFixture(t, withWorkerEnv("PAGNET_FAKE_OUTPUT_CHUNK_BYTES=1024", "PAGNET_FAKE_FULL_OUTPUT_REPEAT=3"))
	invocation := domain.NewID().String()
	prompt := strings.Repeat("restart ünïcode ✓\nmixed lines and 中文\n", 1024)
	delivered, proof := f.reserve(invocation, prompt, nil)

	p := transport.NetworkEventPayload{CommandID: delivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proof}
	if errMsg, _ := f.deliver(p)["error"].(string); errMsg != "" {
		t.Fatalf("canonical invocation delivery refused: %s", errMsg)
	}
	// Consume partway: at least two pages checkpointed (the daemon already
	// retains that prefix in sealed form).
	mid := waitForHostedSourceStreamingPages(t, f, delivered.CommandID, 2, 120*time.Second)
	t.Logf("crash point: state=%q pages=%d cursor=%d bytes=%d", mid.State, mid.Pages, mid.CursorOrdinal, mid.DataBytes)
	// Stop the consumption (the daemon-stop analogue): the worker keeps the
	// paid turn and its retained stream; only the daemon-side consumer stops.
	if !f.d.StopHostedSourceConsumer(f.profile.Scope.InstanceID, delivered.CommandID) {
		t.Fatal("no live consumer to stop mid-stream")
	}
	// Resume through the production startup-resume path (re-call of the SAME
	// entry point over the persisted in-flight row).
	row := resumeUntilTerminal(t, f, delivered.CommandID, 120*time.Second)
	if row.State != "complete" {
		t.Fatalf("resumed consumption settled in %q (reason %q), want complete", row.State, row.Reason)
	}
	out, err := f.d.ReadHostedInvocationFinalOutput(t.Context(), f.profile.Scope.InstanceID, delivered.CommandID)
	if err != nil {
		t.Fatalf("read port: %v", err)
	}
	// No loss: the exact full output — the mid-stream prefix was checkpointed
	// before its acks and the resume continued from it.
	want := []byte(fakeFullOutput(prompt, 3))
	if !bytes.Equal(out.Output, want) {
		t.Fatalf("resumed final output lost or duplicated data (len %d, want %d, diff at %d)",
			len(out.Output), len(want), firstDiffByte(out.Output, want))
	}
	// No second effect: the worker ran ONE turn for the source.
	if turns, _ := f.fakeTurns(); turns != 1 {
		t.Fatalf("resume executed a second turn: %d", turns)
	}
}

func TestDaemonHostedSourceAdapterDetachDoesNotStopConsumption(t *testing.T) {
	f := newHostedGuardFixture(t, withWorkerEnv("PAGNET_FAKE_OUTPUT_CHUNK_BYTES=1024", "PAGNET_FAKE_FULL_OUTPUT_REPEAT=3"))
	invocation := domain.NewID().String()
	prompt := strings.Repeat("detach ünïcode ✓\nmixed lines and 中文\n", 1024)
	delivered, proof := f.reserve(invocation, prompt, nil)

	p := transport.NetworkEventPayload{CommandID: delivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proof}
	if errMsg, _ := f.deliver(p)["error"].(string); errMsg != "" {
		t.Fatalf("canonical invocation delivery refused: %s", errMsg)
	}
	// Mid-consumption: at least two pages checkpointed.
	waitForHostedSourceStreamingPages(t, f, delivered.CommandID, 2, 120*time.Second)
	// DETACH: close the host's delivery connection while consumption is in
	// flight. Detaching never stops the paid work or its consumption.
	f.conn.Close()

	row := waitForHostedSource(t, f, delivered.CommandID, "complete", 120*time.Second)
	if row.Terminal == "" {
		t.Fatalf("complete row has no terminal observation after detach: %+v", row)
	}
	out, err := f.d.ReadHostedInvocationFinalOutput(t.Context(), f.profile.Scope.InstanceID, delivered.CommandID)
	if err != nil {
		t.Fatalf("read port: %v", err)
	}
	want := []byte(fakeFullOutput(prompt, 3))
	if !bytes.Equal(out.Output, want) {
		t.Fatalf("final output after detach diverges (len %d, want %d)", len(out.Output), len(want))
	}
	if turns, _ := f.fakeTurns(); turns != 1 {
		t.Fatalf("detach changed the turn count: %d", turns)
	}
}

func TestDaemonHostedSourceAdapterRefusesInvalidProofs(t *testing.T) {
	f := newHostedGuardFixture(t)
	invocation := domain.NewID().String()
	_, proof := f.reserve(invocation, "denial check prompt", nil)
	ctx := t.Context()

	cases := []struct {
		name   string
		mutate func(*transport.NativeDispatchProof)
	}{
		{"ownership id mismatch", func(p *transport.NativeDispatchProof) { p.OwnershipID = domain.NewID().String() }},
		{"ownership generation mismatch", func(p *transport.NativeDispatchProof) { p.OwnershipGeneration = domain.NewID().String() }},
		{"zero dispatch sequence", func(p *transport.NativeDispatchProof) { p.DispatchSequence = 0 }},
		{"negative dispatch sequence", func(p *transport.NativeDispatchProof) { p.DispatchSequence = -1 }},
		{"missing source command", func(p *transport.NativeDispatchProof) { p.SourceCommandID = "" }},
		{"missing source admission", func(p *transport.NativeDispatchProof) { p.SourceAdmissionID = "" }},
		{"task source set", func(p *transport.NativeDispatchProof) { p.TaskSource = &transport.NativeTaskSource{TaskID: domain.NewID().String()} }},
		{"invalid invocation source", func(p *transport.NativeDispatchProof) { p.InvocationSource.InvocationID = "mismatch" }},
		{"aad network mismatch", func(p *transport.NativeDispatchProof) { p.InvocationSource.InputAAD.NetworkID = domain.NewID().String() }},
		{"aad recipient mismatch", func(p *transport.NativeDispatchProof) { p.InvocationSource.InputAAD.Recipient = domain.NewID().String() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := proof
			tc.mutate(&p)
			err := f.d.ConsumeHostedInvocationFinalOutput(ctx, f.profile, p)
			if !errors.Is(err, ErrNativeObservationConflict) {
				t.Fatalf("invalid proof accepted or wrong error: err=%v", err)
			}
			if _, ok, _ := f.d.state.LoadHostedSourceFinal(ctx, f.profile.Scope.InstanceID, p.SourceCommandID); ok {
				t.Fatalf("a retention row was created for a refused proof")
			}
		})
	}
	// Nothing consumed: no turn ran for any of the refusals.
	if turns, _ := f.fakeTurns(); turns != 0 {
		t.Fatalf("a refused proof executed a turn: %d", turns)
	}
}

func TestDaemonHostedSourceAdapterRefusesProfileChangeBetweenPages(t *testing.T) {
	f := newHostedGuardFixture(t, withWorkerEnv("PAGNET_FAKE_OUTPUT_CHUNK_BYTES=1024", "PAGNET_FAKE_FULL_OUTPUT_REPEAT=2"))
	invocation := domain.NewID().String()
	prompt := strings.Repeat("authority ünïcode ✓\nmixed lines and 中文\n", 1024)
	delivered, proof := f.reserve(invocation, prompt, nil)

	p := transport.NetworkEventPayload{CommandID: delivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proof}
	if errMsg, _ := f.deliver(p)["error"].(string); errMsg != "" {
		t.Fatalf("canonical invocation delivery refused: %s", errMsg)
	}
	// Mid-stream: the first data page is checkpointed.
	waitForHostedSourceStreamingPages(t, f, delivered.CommandID, 1, 120*time.Second)
	// The re-resolve port now returns a CHANGED profile between pages: the
	// next page must conflict, never partially accept.
	tampered := f.profile
	tampered.NativeProfile[0] ^= 1
	f.d.HostedInvocationGuard = NewHostedInvocationGuard(f.journal,
		func(context.Context) (fabric.ExecutionContext, error) { return f.owner, nil },
		func(ctx context.Context, instanceID string) (registry.DescriptorBatchScope, fabricagent.HostedProfile, error) {
			return f.scope, tampered, nil
		})

	row := waitForHostedSource(t, f, delivered.CommandID, "unavailable", 60*time.Second)
	if row.Reason != "source_authority_changed" {
		t.Fatalf("unavailable reason = %q, want source_authority_changed", row.Reason)
	}
	out, err := f.d.ReadHostedInvocationFinalOutput(t.Context(), f.profile.Scope.InstanceID, delivered.CommandID)
	if err != nil {
		t.Fatalf("read port: %v", err)
	}
	if out.State != "unavailable" || len(out.Output) > 0 || out.Terminal != nil {
		t.Fatalf("read port exposed a partial/raw output after the authority conflict: %+v", out)
	}
	// The paid turn ran (it is unaffected) but nothing was accepted past the
	// conflict.
	if turns, _ := f.fakeTurns(); turns != 1 {
		t.Fatalf("turn count after authority conflict = %d, want 1", turns)
	}
}

func TestDaemonHostedSourceAdapterRefusesNonMonotonicCursor(t *testing.T) {
	f := newHostedGuardFixture(t, withWorkerEnv("PAGNET_FAKE_OUTPUT_CHUNK_BYTES=1024", "PAGNET_FAKE_FULL_OUTPUT_REPEAT=2"))
	invocation := domain.NewID().String()
	prompt := strings.Repeat("monotonic ünïcode ✓\nmixed lines and 中文\n", 1024)
	delivered, proof := f.reserve(invocation, prompt, nil)

	p := transport.NetworkEventPayload{CommandID: delivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proof}
	if errMsg, _ := f.deliver(p)["error"].(string); errMsg != "" {
		t.Fatalf("canonical invocation delivery refused: %s", errMsg)
	}
	waitForHostedSourceStreamingPages(t, f, delivered.CommandID, 1, 120*time.Second)
	if !f.d.StopHostedSourceConsumer(f.profile.Scope.InstanceID, delivered.CommandID) {
		t.Fatal("no live consumer to stop")
	}
	// Corrupt the persisted cursor AHEAD of the worker's pending projection:
	// the resumed consumer must refuse the now-behind page (cursors are never
	// blindly trusted from the wire), not accept it.
	row, _, err := f.d.state.LoadHostedSourceFinal(t.Context(), f.profile.Scope.InstanceID, delivered.CommandID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.state.db.Exec(`UPDATE hosted_source_finals SET cursor_ordinal=? WHERE instance_id=? AND command_id=?`,
		row.CursorOrdinal+10, f.profile.Scope.InstanceID, delivered.CommandID); err != nil {
		t.Fatal(err)
	}
	settled := resumeUntilTerminal(t, f, delivered.CommandID, 60*time.Second)
	if settled.State != "unavailable" || settled.Reason != "cursor_conflict" {
		t.Fatalf("non-monotonic cursor settled in %q (reason %q), want unavailable/cursor_conflict", settled.State, settled.Reason)
	}
}

func TestDaemonHostedSourceAdapterRefusesDuplicateOrdinalDigestMismatch(t *testing.T) {
	f := newHostedGuardFixture(t)
	invocation := domain.NewID().String()
	prompt := "digest mismatch prompt"
	delivered, proof := f.reserve(invocation, prompt, nil)

	p := transport.NetworkEventPayload{CommandID: delivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proof}
	if errMsg, _ := f.deliver(p)["error"].(string); errMsg != "" {
		t.Fatalf("canonical invocation delivery refused: %s", errMsg)
	}
	// Stop mid-stream (the single data page is checkpointed; the terminal
	// page — ordinal cursor+1 — is still unclaimed by the worker's stream).
	waitForHostedSourceStreamingPages(t, f, delivered.CommandID, 1, 60*time.Second)
	if !f.d.StopHostedSourceConsumer(f.profile.Scope.InstanceID, delivered.CommandID) {
		t.Fatal("no live consumer to stop")
	}
	f.waitForTurns(1, prompt) // the worker records its genuine terminal
	row, _, err := f.d.state.LoadHostedSourceFinal(t.Context(), f.profile.Scope.InstanceID, delivered.CommandID)
	if err != nil {
		t.Fatal(err)
	}
	// The worker's next pending projection is the terminal at ordinal
	// cursor+1. Claim that ordinal with a WRONG digest: the re-read must
	// conflict on the digest instead of accepting the duplicate blindly.
	if _, err := f.d.state.db.Exec(`UPDATE hosted_source_finals SET cursor_ordinal=?,cursor_digest='bogus' WHERE instance_id=? AND command_id=?`,
		row.CursorOrdinal+1, f.profile.Scope.InstanceID, delivered.CommandID); err != nil {
		t.Fatal(err)
	}
	settled := resumeUntilTerminal(t, f, delivered.CommandID, 60*time.Second)
	if settled.State != "unavailable" || settled.Reason != "cursor_conflict" {
		t.Fatalf("duplicate ordinal with mismatched digest settled in %q (reason %q), want unavailable/cursor_conflict", settled.State, settled.Reason)
	}
}

func TestDaemonHostedSourceAdapterFailedTerminalPersistsExactlyOnce(t *testing.T) {
	// The fake runtime's rate-limit failure mode emits a genuine
	// runtime.turn.failed terminal (no output): the failed final state must
	// persist exactly once and re-entry must never overwrite it.
	f := newHostedGuardFixture(t, withWorkerEnv("PAGNET_FAKE_RATELIMIT=5m"))
	invocation := domain.NewID().String()
	prompt := "rate limited hosted prompt"
	delivered, proof := f.reserve(invocation, prompt, nil)

	p := transport.NetworkEventPayload{CommandID: delivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proof}
	if errMsg, _ := f.deliver(p)["error"].(string); errMsg != "" {
		t.Fatalf("canonical invocation delivery refused: %s", errMsg)
	}
	row := waitForHostedSource(t, f, delivered.CommandID, "failed", 60*time.Second)
	if row.Reason != "terminal_runtime.turn.failed" {
		t.Fatalf("failed reason = %q, want terminal_runtime.turn.failed", row.Reason)
	}
	out, err := f.d.ReadHostedInvocationFinalOutput(t.Context(), f.profile.Scope.InstanceID, delivered.CommandID)
	if err != nil {
		t.Fatalf("read port: %v", err)
	}
	if out.State != "failed" || out.Terminal == nil || out.Terminal.Event.Type != session.EventTurnFailed {
		t.Fatalf("read port did not return the failed terminal: %+v", out)
	}
	if len(out.Output) != 0 {
		t.Fatalf("failed turn exposed output it never produced: %q", out.Output)
	}
	// Re-entry over the failed row: the retained failed state, verbatim.
	if err := f.d.ConsumeHostedInvocationFinalOutput(t.Context(), f.profile, proof); !errors.Is(err, ErrHostedSourceFailed) {
		t.Fatalf("re-entry over failed row: err=%v, want ErrHostedSourceFailed", err)
	}
	after, _, err := f.d.state.LoadHostedSourceFinal(t.Context(), f.profile.Scope.InstanceID, delivered.CommandID)
	if err != nil {
		t.Fatal(err)
	}
	if after.State != "failed" || after.Terminal != row.Terminal || !bytes.Equal(after.Ciphertext, row.Ciphertext) {
		t.Fatalf("re-entry overwrote the retained failed row: before=%+v after=%+v", row, after)
	}
}

func TestDaemonHostedSourceAdapterEnforcesCapacityBeforeAcceptance(t *testing.T) {
	f := newHostedGuardFixture(t, withWorkerEnv("PAGNET_FAKE_OUTPUT_CHUNK_BYTES=1024", "PAGNET_FAKE_FULL_OUTPUT_REPEAT=8"))
	// A 64 KiB prompt echoed 8x → ~1 MiB of output, beyond the 380 KiB
	// retention bound: the consumer must refuse the over-limit page before
	// acceptance and settle truthfully unavailable — never truncated.
	prompt := strings.Repeat("cap-test ünïcode ✓\n", 2894)
	if len(prompt) > 128<<10 {
		t.Fatalf("test prompt exceeds the invocation input bound: %d", len(prompt))
	}
	invocation := domain.NewID().String()
	delivered, proof := f.reserve(invocation, prompt, nil)

	p := transport.NetworkEventPayload{CommandID: delivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proof}
	if errMsg, _ := f.deliver(p)["error"].(string); errMsg != "" {
		t.Fatalf("canonical invocation delivery refused: %s", errMsg)
	}
	row := waitForHostedSource(t, f, delivered.CommandID, "unavailable", 120*time.Second)
	if row.Reason != "capacity_exhausted" {
		t.Fatalf("unavailable reason = %q, want capacity_exhausted", row.Reason)
	}
	if row.DataBytes > HostedSourceFinalMaxBytes {
		t.Fatalf("retained %d bytes beyond the %d bound", row.DataBytes, HostedSourceFinalMaxBytes)
	}
	out, err := f.d.ReadHostedInvocationFinalOutput(t.Context(), f.profile.Scope.InstanceID, delivered.CommandID)
	if err != nil {
		t.Fatalf("read port: %v", err)
	}
	if out.State != "unavailable" || len(out.Output) > 0 || out.Terminal != nil {
		t.Fatalf("read port exposed a truncated final output: %+v", out)
	}
	if turns, _ := f.fakeTurns(); turns != 1 {
		t.Fatalf("capacity refusal changed the turn count: %d", turns)
	}
}

func TestDaemonHostedSourceAdapterReadPortUnknownIsNotFound(t *testing.T) {
	f := newHostedGuardFixture(t)
	out, err := f.d.ReadHostedInvocationFinalOutput(t.Context(), f.profile.Scope.InstanceID, domain.NewID().String())
	if !errors.Is(err, ErrHostedSourceNotFound) {
		t.Fatalf("unknown key: err=%v, want ErrHostedSourceNotFound (out %+v)", err, out)
	}
}
