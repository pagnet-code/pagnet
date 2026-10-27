package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
)

func TestTextSenderFacadeScopeRevisionAndFence(t *testing.T) {
	f, state, saved := senderLifecycle(t)
	f.s.daemon.textServices = f.s
	ctx := context.Background()
	if _, err := f.s.daemon.TextSender(ctx, f.item.ID, managedSenderProject); !errors.Is(err, sender.ErrDisabled) {
		t.Fatal("unproved runtime exposed", err)
	}
	if err := f.s.reconcile(ctx, f.c); err != nil {
		t.Fatal(err)
	}
	awaitSenderSend(t, state, saved.AskID)
	handle, err := f.s.daemon.TextSender(ctx, f.item.ID, managedSenderProject)
	if err != nil {
		t.Fatal(err)
	}
	before, err := handle.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	operation, err := handle.Submit(ctx, id.String(), managedSenderRecipient, "another question")
	if err != nil {
		t.Fatal(err)
	}
	changedCtx, changedCancel := context.WithTimeout(ctx, time.Second)
	defer changedCancel()
	if revision, err := handle.Subscribe(changedCtx, before); err != nil || revision == before {
		t.Fatal("persisted submit did not change revision", revision, err)
	}
	duplicate, err := handle.Submit(ctx, id.String(), managedSenderRecipient, "another question")
	if err != nil || duplicate.AskID != operation.AskID {
		t.Fatal("stable submit changed identity", err)
	}
	if _, err := handle.Submit(ctx, id.String(), managedSenderRecipient, "changed"); !errors.Is(err, sender.ErrConflict) {
		t.Fatal("content conflict accepted", err)
	}
	awaitSenderSend(t, state, operation.AskID)
	rows, err := handle.List(ctx, "", 1)
	if err != nil || len(rows) != 1 || rows[0].AskID != saved.AskID {
		t.Fatal("list order or bound", rows, err)
	}
	rows, err = handle.List(ctx, saved.AskID, 100)
	if err != nil || len(rows) != 1 || rows[0].AskID != operation.AskID {
		t.Fatal("list cursor", rows, err)
	}
	if _, err := handle.List(ctx, "", 101); !errors.Is(err, sender.ErrInvalid) {
		t.Fatal("unbounded list accepted", err)
	}
	other, err := f.s.daemon.TextSender(ctx, f.item.ID, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := other.List(ctx, "", 100); err != nil || len(rows) != 0 {
		t.Fatal("project scope leaked", rows, err)
	}
	revision, err := handle.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := handle.Subscribe(cancelCtx, revision); !errors.Is(err, context.Canceled) {
		t.Fatal("subscription ignored cancellation", err)
	}
	// Snapshot after dispatch has settled; no work or timer is required to wake
	// this waiter when the native runtime is disconnected.
	ended := make(chan error, 1)
	go func() {
		for {
			next, err := handle.Subscribe(ctx, revision)
			if err != nil {
				ended <- err
				return
			}
			revision = next
		}
	}()
	f.s.disconnect()
	select {
	case err := <-ended:
		if !errors.Is(err, sender.ErrDisabled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fencing did not end subscription")
	}
	if _, err := handle.Read(ctx, saved.AskID); !errors.Is(err, sender.ErrDisabled) {
		t.Fatal("old runtime handle remained usable", err)
	}
}

func TestTextSenderProjectionExcludesTransportEvidence(t *testing.T) {
	raw, err := json.Marshal(textSenderProjection(sender.Operation{WireDigest: "private-wire", Reply: &sender.Reply{WireDigest: "private-reply-wire", Text: "answer"}}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "wire") || !strings.Contains(string(raw), "answer") {
		t.Fatal("unsafe projection", string(raw))
	}
}
