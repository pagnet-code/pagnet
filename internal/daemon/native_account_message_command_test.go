package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func accountMessageCommandFixture(t *testing.T) transport.AccountMessagePayload {
	t.Helper()
	var sealed struct {
		Envelope e2ee.EncryptedPayloadV1 `json:"envelope"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "accountmessage", "testdata", "account_message_v1.json"))
	if err != nil || json.Unmarshal(raw, &sealed) != nil {
		t.Fatalf("sealed fixture: %v", err)
	}
	var vector struct {
		SourceCanonical string `json:"sourceCanonical"`
	}
	raw, err = os.ReadFile(filepath.Join("..", "..", "transport", "testdata", "account_message_source_reply_v1.json"))
	if err != nil || json.Unmarshal(raw, &vector) != nil {
		t.Fatalf("source fixture: %v", err)
	}
	var source transport.NativeAccountMessageSource
	if err := json.Unmarshal([]byte(vector.SourceCanonical), &source); err != nil {
		t.Fatal(err)
	}
	epoch, err := time.Parse(time.RFC3339Nano, source.Descriptor.RunnerConnectedAt)
	if err != nil {
		t.Fatal(err)
	}
	return transport.AccountMessagePayload{CommandID: "original-command", InstanceID: source.Descriptor.TargetInstanceID,
		Envelope: sealed.Envelope, NativeDispatch: &transport.NativeDispatchProof{
			AccountMessageSource: &source, OwnershipID: "original-ownership", OwnershipGeneration: "original-generation",
			DispatchSequence: 1, SourceCommandID: "original-command", SourceAdmissionID: "original-admission",
			SourceRunnerID: source.Descriptor.RunnerID, SourceRunnerEpoch: epoch, SourceBootID: "original-boot",
		}}
}

func TestAccountMessageCommandProofAndCiphertext(t *testing.T) {
	base := accountMessageCommandFixture(t)
	if _, err := validateAccountMessagePayload(base); err != nil {
		t.Fatalf("valid original: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*transport.AccountMessagePayload)
	}{
		{"command", func(p *transport.AccountMessagePayload) { p.CommandID = "replacement" }},
		{"instance", func(p *transport.AccountMessagePayload) { p.InstanceID = "replacement" }},
		{"runner", func(p *transport.AccountMessagePayload) { p.NativeDispatch.SourceRunnerID = "replacement" }},
		{"runner epoch", func(p *transport.AccountMessagePayload) {
			p.NativeDispatch.SourceRunnerEpoch = p.NativeDispatch.SourceRunnerEpoch.Add(time.Nanosecond)
		}},
		{"admission", func(p *transport.AccountMessagePayload) { p.NativeDispatch.SourceAdmissionID = "" }},
		{"mixed source", func(p *transport.AccountMessagePayload) { p.NativeDispatch.TaskSource = &transport.NativeTaskSource{} }},
		{"ciphertext", func(p *transport.AccountMessagePayload) { p.Envelope.Ciphertext = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" }},
		{"epoch", func(p *transport.AccountMessagePayload) { p.Envelope.KeyEpochID = "replacement" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			proof := *base.NativeDispatch
			p.NativeDispatch = &proof
			tc.mutate(&p)
			if _, err := validateAccountMessagePayload(p); err == nil {
				t.Fatal("changed original was accepted")
			}
		})
	}
}

func TestAccountMessageCommandDefaultOff(t *testing.T) {
	d := &Daemon{}
	if _, err := d.preflightAccountMessageCommand(nil, accountMessageCommandFixture(t)); err != errAccountMessageCommand {
		t.Fatalf("default execution gate: %v", err)
	}
}

func TestAccountMessageResendRechecksWorkerAfterProcessed(t *testing.T) {
	d := newTestDaemon(t)
	const command = "original-account-command"
	if err := d.state.MarkProcessed(command, "", nil); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	d.enqueueAccountMessage("instance", command, func() {
		calls.Add(1)
		close(started)
		<-release
	})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("account command did not reach worker despite processed marker")
	}
	d.enqueueAccountMessage("instance", command, func() { calls.Add(1) })
	close(release)
	waitUntil(t, "account claim released", 2*time.Second, func() bool {
		d.seenMu.Lock()
		_, claimed := d.seen[command]
		d.seenMu.Unlock()
		return !claimed
	})
	if got := calls.Load(); got != 1 {
		t.Fatalf("in-flight duplicate reached worker %d times", got)
	}
	done := make(chan struct{})
	d.enqueueAccountMessage("instance", command, func() { calls.Add(1); close(done) })
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("resend did not recheck immutable worker input")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("resend reached worker %d times, want 2", got)
	}
}
