package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func deliveryFixture(t *testing.T, send func(context.Context, string, any) error) (*NativeObservationConnection, sessionworker.NativeObservation) {
	t.Helper()
	host := domain.NewID().String()
	boot := domain.NewID().String()
	c := NewNativeObservationConnection("https://control.test", host, boot, send)
	p := transport.HostSessionPayload{TenantID: domain.NewID().String(), AccountID: domain.NewID().String(), OwnershipScope: "personal", HostID: host, BootID: boot, RunnerID: domain.NewID().String(), NativeAdmissionID: domain.NewID().String(), RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol, transport.NativeContentProtocol}}
	if err := c.Admit(p); err != nil {
		t.Fatal(err)
	}
	origin := transport.NativeObservationOrigin{ID: domain.NewID().String(), InstanceID: domain.NewID().String(), HostID: host, Runtime: "qwen-code", NativeGeneration: "original-A", BootID: "original-boot-A", RunnerID: "original-runner-A"}
	raw, _ := json.Marshal(origin)
	return c, sessionworker.NativeObservation{ID: domain.NewID().String(), SourceDigest: string(bytes.Repeat([]byte("a"), 64)), Origin: raw, ObservedAt: time.Now().UTC().Add(-time.Minute), NativeGeneration: origin.NativeGeneration, NativeSessionID: "actual-session", SourceSequence: 1, Event: session.SessionEvent{Type: session.EventBusy}}
}

func TestNativeWorkerDrainACKOnlyMatchingCommit(t *testing.T) {
	for _, mode := range []string{"committed", "staged", "rejected", "wrong_digest", "disconnect", "write_failure"} {
		t.Run(mode, func(t *testing.T) {
			var c *NativeObservationConnection
			c, o := deliveryFixture(t, func(ctx context.Context, typ string, value any) error {
				if typ != transport.MsgNativeObservation {
					t.Fatalf("unexpected send %s", typ)
				}
				p := value.(transport.NativeObservationPayload)
				switch mode {
				case "write_failure":
					return errors.New("disconnect before write")
				case "disconnect":
					c.Close()
					return nil
				case "staged":
					c.NativeContentDisposition(transport.NativeContentStagedPayload{})
					return nil
				}
				disposition := "committed"
				digest := p.Digest
				frame := transport.MsgNativeObservationReceipt
				if mode == "rejected" {
					disposition = "stale_origin"
					frame = transport.MsgNativeObservationRejected
				}
				if mode == "wrong_digest" {
					digest = "wrong"
				}
				c.NativeWorkerObservationDisposition(frame, transport.NativeObservationReceiptPayload{ObservationID: p.ObservationID, OriginID: p.OriginID, Digest: digest, Disposition: disposition})
				return nil
			})
			ack := 0
			call := func(_ context.Context, r sessionworker.Request) (sessionworker.Response, error) {
				if r.Type == "observations" {
					return sessionworker.Response{Observations: []sessionworker.NativeObservation{o}}, nil
				}
				if r.Type == "observation_ack" {
					if r.SourceDigest != o.SourceDigest || r.ObservationID != o.ID {
						t.Fatal("worker ACK identity rewritten")
					}
					ack++
					return sessionworker.Response{}, nil
				}
				t.Fatalf("unexpected worker request %s", r.Type)
				return sessionworker.Response{}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			err := c.DrainNativeWorkerSources(ctx, call)
			if mode == "committed" {
				if err != nil || ack != 1 {
					t.Fatalf("commit did not ACK: %d %v", ack, err)
				}
			} else if err == nil || ack != 0 {
				t.Fatalf("%s prematurely retired evidence: %d %v", mode, ack, err)
			}
		})
	}
}

func TestNativeWorkerWireRetriesExactOriginalCiphertext(t *testing.T) {
	_, o := deliveryFixture(t, func(context.Context, string, any) error { return nil })
	o.Event = session.SessionEvent{Type: session.EventInteractionStarted, Interaction: &session.InteractionEvent{Kind: "question", NativeInteractionID: "native-question", Summary: "plaintext must not be copied", NativePayload: json.RawMessage(`{"secret":"protected"}`)}}
	o.InteractionID = domain.NewID().String()
	o.Inspection = &sessionworker.Inspection{DetailEnvelope: e2ee.EncryptedPayloadV1{Version: 1, Ciphertext: "original-ciphertext"}, DetailAAD: e2ee.AAD{ObjectID: o.InteractionID}}
	a, err := NativeWorkerWireObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NativeWorkerWireObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	ra, _ := json.Marshal(a)
	rb, _ := json.Marshal(b)
	if !bytes.Equal(ra, rb) || bytes.Contains(ra, []byte("plaintext must")) || bytes.Contains(ra, []byte("protected")) || !bytes.Contains(ra, []byte("original-ciphertext")) {
		t.Fatal("retry changed ciphertext or leaked native plaintext")
	}
	o.Event.Type = session.EventTurnCompleted
	if _, err = NativeWorkerWireObservation(o); !errors.Is(err, ErrNativeSourceUnsupported) {
		t.Fatal("unsupported turn invented a receipt path")
	}
}

func TestNativeWorkerDisconnectWakesReceiptWaiter(t *testing.T) {
	written := make(chan struct{})
	var once sync.Once
	c, o := deliveryFixture(t, func(context.Context, string, any) error { once.Do(func() { close(written) }); return nil })
	done := make(chan error, 1)
	go func() {
		p, _ := NativeWorkerWireObservation(o)
		_, err := c.deliverWorkerObservation(context.Background(), p)
		done <- err
	}()
	<-written
	c.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("disconnect retained pending waiter")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pendingObservations) != 0 {
		t.Fatal("disconnect leaked pending receipt")
	}
}

func TestNativeWorkerContentBudgetExactCiphertextAndCommitFence(t *testing.T) {
	var c *NativeObservationConnection
	stored := map[int][]byte{}
	var ref transport.NativeContentReference
	frames := 0
	observationWrites := 0
	ack := 0
	c, o := deliveryFixture(t, func(_ context.Context, typ string, value any) error {
		switch typ {
		case transport.MsgNativeContentBegin, transport.MsgNativeContentStatus:
			missing := []int{}
			more := false
			for i := 0; i < 20; i++ {
				if stored[i] == nil {
					if len(missing) < 16 {
						missing = append(missing, i)
					} else {
						more = true
					}
				}
			}
			c.NativeContentDisposition(transport.NativeContentStagedPayload{ContentID: ref.ContentID, CiphertextDigest: ref.CiphertextDigest, MissingOrdinals: missing, MoreMissing: more})
		case transport.MsgNativeContentFragment:
			f := value.(*transport.NativeContentFragment)
			raw, _ := json.Marshal(f)
			stored[f.Ordinal] = raw
			frames++
		case transport.MsgNativeObservation:
			if len(stored) != 20 {
				t.Fatal("published source before complete ciphertext staging")
			}
			observationWrites++
			p := value.(transport.NativeObservationPayload)
			c.NativeWorkerObservationDisposition(transport.MsgNativeObservationReceipt, transport.NativeObservationReceiptPayload{ObservationID: p.ObservationID, OriginID: p.OriginID, Digest: p.Digest, Disposition: "committed"})
		default:
			t.Fatalf("unexpected frame %s", typ)
		}
		return nil
	})
	var origin transport.NativeObservationOrigin
	json.Unmarshal(o.Origin, &origin)
	ref = transport.NativeContentReference{ContentID: domain.NewID().String(), ObservationID: o.ID, OriginID: origin.ID, FragmentCount: 20, CiphertextDigest: string(bytes.Repeat([]byte("b"), 64)), NativeGeneration: o.NativeGeneration, NativeSessionID: o.NativeSessionID}
	o.InteractionID = domain.NewID().String()
	o.Event = session.SessionEvent{Type: session.EventInteractionStarted, Interaction: &session.InteractionEvent{Kind: "question", NativeInteractionID: "actual-question"}}
	o.Inspection = &sessionworker.Inspection{DetailContent: &ref}
	fragments := make([]transport.NativeContentFragment, 20)
	for i := range fragments {
		fragments[i] = transport.NativeContentFragment{ContentID: ref.ContentID, Ordinal: i, Envelope: e2ee.EncryptedPayloadV1{Version: 1, Ciphertext: string(bytes.Repeat([]byte("c"), 90000))}}
	}
	call := func(_ context.Context, r sessionworker.Request) (sessionworker.Response, error) {
		switch r.Type {
		case "observations":
			return sessionworker.Response{Observations: []sessionworker.NativeObservation{o}}, nil
		case "content_fragment":
			return sessionworker.Response{ContentFragment: &fragments[r.ContentOrdinal]}, nil
		case "observation_ack":
			ack++
			return sessionworker.Response{}, nil
		}
		t.Fatal(r.Type)
		return sessionworker.Response{}, nil
	}
	if err := c.DrainNativeWorkerSources(context.Background(), call); err != nil {
		t.Fatal(err)
	}
	if frames != 16 || ack != 0 || observationWrites != 0 {
		t.Fatalf("fragment budget/staged receipt retired source: %d %d %d", frames, ack, observationWrites)
	}
	if err := c.DrainNativeWorkerSources(context.Background(), call); err != nil {
		t.Fatal(err)
	}
	if frames != 20 || ack != 1 || observationWrites != 1 {
		t.Fatalf("resumed transfer failed: %d %d %d", frames, ack, observationWrites)
	}
	for i, f := range fragments {
		raw, _ := json.Marshal(f)
		if !bytes.Equal(raw, stored[i]) {
			t.Fatal("retry regenerated ciphertext")
		}
	}
}

func TestNativeWorkerContentRejectsUnboundedOrInvalidProgress(t *testing.T) {
	for _, scenario := range []string{"duplicate", "out_of_range", "too_many", "empty_more", "wrong_digest", "oversized_fragment"} {
		t.Run(scenario, func(t *testing.T) {
			var c *NativeObservationConnection
			var ref transport.NativeContentReference
			c, o := deliveryFixture(t, func(_ context.Context, typ string, value any) error {
				if typ != transport.MsgNativeContentBegin {
					t.Fatal("invalid progress wrote ciphertext")
				}
				missing := []int{0}
				more := false
				digest := ref.CiphertextDigest
				switch scenario {
				case "duplicate":
					missing = []int{0, 0}
				case "out_of_range":
					missing = []int{20}
				case "too_many":
					missing = make([]int, 33)
				case "empty_more":
					missing = nil
					more = true
				case "wrong_digest":
					digest = "wrong"
				}
				c.NativeContentDisposition(transport.NativeContentStagedPayload{ContentID: ref.ContentID, CiphertextDigest: digest, MissingOrdinals: missing, MoreMissing: more})
				return nil
			})
			ref = transport.NativeContentReference{ContentID: domain.NewID().String(), ObservationID: o.ID, NativeGeneration: o.NativeGeneration, NativeSessionID: o.NativeSessionID, FragmentCount: 20, CiphertextDigest: "original"}
			budget := 16
			call := func(context.Context, sessionworker.Request) (sessionworker.Response, error) {
				if scenario != "oversized_fragment" {
					t.Fatal("invalid progress read worker ciphertext")
				}
				return sessionworker.Response{ContentFragment: &transport.NativeContentFragment{ContentID: ref.ContentID, Ordinal: 0, Envelope: e2ee.EncryptedPayloadV1{Ciphertext: string(bytes.Repeat([]byte("s"), 129<<10))}}}, nil
			}
			ready, err := c.stageWorkerContent(context.Background(), o, ref, call, &budget)
			if ready || err == nil {
				t.Fatal("invalid/unbounded staging accepted")
			}
		})
	}
}
