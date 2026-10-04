package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
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
					wire, wireErr := sessionworker.NativeBackendObservation(o)
					if wireErr != nil || r.SourceReceipt == nil || r.SourceReceipt.ObservationID != wire.ObservationID || r.SourceReceipt.OriginID != wire.OriginID || r.SourceReceipt.Digest != wire.Digest || r.SourceReceipt.Disposition != "committed" {
						t.Fatal("worker ACK lost the exact committed receipt", wireErr)
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

func TestNativeTaskContentCapabilityRequiredBeforeAnyBackendWrite(t *testing.T) {
	writes, acknowledgements := 0, 0
	c, o := deliveryFixture(t, func(context.Context, string, any) error { writes++; return nil })
	o.Event = session.SessionEvent{Type: session.EventTurnOutput, SessionID: o.NativeSessionID, TurnID: "pagnet-worker-turn-1", NativeOutput: true, Output: "private native text must never reach wire"}
	taskID := domain.NewID().String()
	admission, err := c.AuthenticatedNativeHostSession()
	if err != nil {
		t.Fatal(err)
	}
	// Model a structurally valid original task source. The missing backend
	// capability, not a missing source crypto scope, is the guard under test.
	o.TurnSource = &sessionworker.NativeTurnSource{Sequence: 1, LogicalTurnID: o.Event.TurnID, NativeGeneration: o.NativeGeneration, NativeSessionID: o.NativeSessionID, SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String(), InputKind: "task", SourceTask: &transport.NativeTaskSource{TaskID: taskID, InputAAD: e2ee.AAD{TenantID: admission.TenantID, NetworkID: domain.NewID().String(), ObjectType: e2ee.ObjectTypeTask, ObjectID: taskID, KeyEpochID: domain.NewID().String()}}}
	o.OutputContent = &transport.NativeContentReference{}
	a, err := NativeWorkerWireObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NativeWorkerWireObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := json.Marshal(a)
	second, _ := json.Marshal(b)
	if !bytes.Equal(first, second) || bytes.Contains(first, []byte("private native text")) || a.MessageType != transport.MsgRuntimeTurnOutput {
		t.Fatal("task wire retry changed or leaked plaintext")
	}
	call := func(_ context.Context, r sessionworker.Request) (sessionworker.Response, error) {
		switch r.Type {
		case "observations":
			return sessionworker.Response{Observations: []sessionworker.NativeObservation{o}}, nil
		case "observation_ack":
			acknowledgements++
		default:
			t.Fatalf("unsupported capability retrieved content via %s", r.Type)
		}
		return sessionworker.Response{}, nil
	}
	if err = c.DrainNativeWorkerSources(context.Background(), call); !errors.Is(err, ErrNativeOriginAdmissionDeferred) || writes != 0 || acknowledgements != 0 {
		t.Fatal("unsupported backend received task content or ACK", err, writes, acknowledgements)
	}
	o.Event.NativeOutput = false
	if _, err = NativeWorkerWireObservation(o); !errors.Is(err, ErrNativeSourceUnsupported) {
		t.Fatal("diagnostic became genuine task text", err)
	}
	o.Event.NativeOutput = true
	o.SourceContentUnavailable = true
	if _, err = NativeWorkerWireObservation(o); !errors.Is(err, ErrNativeSourceUnsupported) {
		t.Fatal("missing original encryption authority became supported", err)
	}
}

func TestNativeWorkerTerminalReceiptDurableMarkBeforeNextSource(t *testing.T) {
	for _, disposition := range []string{"expired", "stale_origin"} {
		t.Run(disposition, func(t *testing.T) {
			var c *NativeObservationConnection
			var written []string
			c, first := deliveryFixture(t, func(_ context.Context, typ string, value any) error {
				p := value.(transport.NativeObservationPayload)
				written = append(written, p.ObservationID)
				result := "committed"
				if len(written) == 1 {
					result = disposition
				}
				c.NativeWorkerObservationDisposition(transport.MsgNativeObservationReceipt, transport.NativeObservationReceiptPayload{ObservationID: p.ObservationID, OriginID: p.OriginID, Digest: p.Digest, Disposition: result})
				return nil
			})
			second := first
			second.ID = domain.NewID().String()
			second.SourceSequence++
			marked, acks := 0, 0
			call := func(_ context.Context, r sessionworker.Request) (sessionworker.Response, error) {
				switch r.Type {
				case "observations":
					return sessionworker.Response{Observations: []sessionworker.NativeObservation{first, second}}, nil
				case "source_disposition":
					if r.ObservationID != first.ID || r.SourceDigest != first.SourceDigest || r.SourceReceipt == nil || r.SourceReceipt.Disposition != disposition {
						t.Fatal("terminal provenance rewritten")
					}
					marked++
					return sessionworker.Response{}, nil
				case "observation_ack":
					if marked != 1 || r.ObservationID != second.ID {
						t.Fatal("ACK deleted terminal source or preceded durable mark")
					}
					acks++
					return sessionworker.Response{}, nil
				}
				t.Fatal("unexpected request", r.Type)
				return sessionworker.Response{}, nil
			}
			if err := c.DrainNativeWorkerSources(t.Context(), call); err != nil || marked != 1 || acks != 1 || len(written) != 2 {
				t.Fatal("terminal source blocked later commit", err)
			}
		})
	}
}

func TestNativeWorkerExpiredContentRequestsReceiptWithoutStaging(t *testing.T) {
	var c *NativeObservationConnection
	c, o := deliveryFixture(t, func(_ context.Context, typ string, value any) error {
		if typ != transport.MsgNativeObservation {
			t.Fatal("expired source staged unnecessary ciphertext", typ)
		}
		p := value.(transport.NativeObservationPayload)
		c.NativeWorkerObservationDisposition(transport.MsgNativeObservationReceipt, transport.NativeObservationReceiptPayload{ObservationID: p.ObservationID, OriginID: p.OriginID, Digest: p.Digest, Disposition: "expired"})
		return nil
	})
	o.ObservedAt = time.Now().UTC().Add(-8 * 24 * time.Hour)
	o.Event = session.SessionEvent{Type: session.EventInteractionStarted, Interaction: &session.InteractionEvent{Kind: "question", NativeInteractionID: "question"}}
	o.InteractionID = domain.NewID().String()
	o.Inspection = &sessionworker.Inspection{DetailContent: &transport.NativeContentReference{ContentID: domain.NewID().String()}}
	marked := false
	call := func(_ context.Context, r sessionworker.Request) (sessionworker.Response, error) {
		switch r.Type {
		case "observations":
			return sessionworker.Response{Observations: []sessionworker.NativeObservation{o}}, nil
		case "source_disposition":
			marked = true
			return sessionworker.Response{}, nil
		default:
			t.Fatal("expired source changed ciphertext/evidence", r.Type)
		}
		return sessionworker.Response{}, nil
	}
	if err := c.DrainNativeWorkerSources(t.Context(), call); err != nil || !marked {
		t.Fatal("expired evidence blocked on content staging", err)
	}
}

func TestNativeWorkerExplicitDeleteMetadataOnlyRetainsCiphertext(t *testing.T) {
	for _, mode := range []string{"supported", "unsupported", "invalid_job", "wrong_digest", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			var c *NativeObservationConnection
			job := domain.NewID().String()
			var original transport.NativeObservationPayload
			writes, marks := 0, 0
			c, o := deliveryFixture(t, func(_ context.Context, typ string, value any) error {
				if typ != transport.MsgNativeObservation {
					t.Fatal("deletion staged private content", typ)
				}
				p := value.(transport.NativeObservationPayload)
				if p.DeleteRequestID != job {
					t.Fatal("unbound delete job")
				}
				p.DeleteRequestID = ""
				if !reflect.DeepEqual(p, original) {
					t.Fatal("original metadata changed")
				}
				writes++
				if mode == "disconnect" {
					c.Close()
					return nil
				}
				digest := p.Digest
				if mode == "wrong_digest" {
					digest = "wrong"
				}
				c.NativeWorkerObservationDisposition(transport.MsgNativeObservationReceipt, transport.NativeObservationReceiptPayload{ObservationID: p.ObservationID, OriginID: p.OriginID, Digest: digest, Disposition: transport.NativeObservationDeleteQuarantined})
				return nil
			})
			// The absent task-content capability must not impede this explicitly
			// authorized metadata path, and the cipher reference remains unchanged.
			o.Event = session.SessionEvent{Type: session.EventInteractionStarted, Interaction: &session.InteractionEvent{Kind: "question", NativeInteractionID: "question"}}
			o.InteractionID = domain.NewID().String()
			o.Inspection = &sessionworker.Inspection{DetailContent: &transport.NativeContentReference{ContentID: domain.NewID().String()}}
			var err error
			original, err = NativeWorkerWireObservation(o)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "unsupported" {
				c.mu.Lock()
				c.session.ProtocolFeatures = append(c.session.ProtocolFeatures, transport.NativeOwnedDeletionProtocol)
				c.mu.Unlock()
			}
			if mode == "invalid_job" {
				job = "not-a-job"
			}
			call := func(_ context.Context, req sessionworker.Request) (sessionworker.Response, error) {
				switch req.Type {
				case "observations":
					return sessionworker.Response{Observations: []sessionworker.NativeObservation{o}}, nil
				case "source_disposition":
					if req.ObservationID != o.ID || req.SourceDigest != o.SourceDigest || req.SourceReceipt == nil || req.SourceReceipt.Disposition != transport.NativeObservationDeleteQuarantined {
						t.Fatal("wrong source quarantine")
					}
					marks++
					return sessionworker.Response{}, nil
				default:
					t.Fatal("deletion read/deleted ciphertext", req.Type)
					return sessionworker.Response{}, nil
				}
			}
			_, err = c.DrainDeletionSourcesPage(t.Context(), call, 0, job)
			if mode == "supported" {
				if err != nil || writes != 1 || marks != 1 {
					t.Fatal(err, writes, marks)
				}
			} else if err == nil || marks != 0 {
				t.Fatal("unsafe deletion accepted", err, marks)
			}
			if (mode == "unsupported" || mode == "invalid_job") && writes != 0 {
				t.Fatal("unauthorized deletion publication")
			}
		})
	}
}

func TestNativeResourceInterruptionCapabilityRequiredBeforeBackendWrite(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "authenticated"}[enabled], func(t *testing.T) {
			sends, acks := 0, 0
			var c *NativeObservationConnection
			c, o := deliveryFixture(t, func(ctx context.Context, typ string, value any) error {
				sends++
				if typ != transport.MsgNativeObservation {
					t.Fatal("unexpected resource source write", typ)
				}
				p := value.(transport.NativeObservationPayload)
				c.NativeWorkerObservationDisposition(transport.MsgNativeObservationReceipt, transport.NativeObservationReceiptPayload{ObservationID: p.ObservationID, OriginID: p.OriginID, Digest: p.Digest, Disposition: "committed"})
				return nil
			})
			if enabled {
				a, err := c.AuthenticatedNativeHostSession()
				if err != nil {
					t.Fatal(err)
				}
				a.ProtocolFeatures = append(a.ProtocolFeatures, transport.NativeResourceInterruptionProtocol)
				previous := c
				c = NewNativeObservationConnection(previous.serverURL, previous.hostID, previous.bootID, previous.send)
				previous.Close()
				if err = c.Admit(a); err != nil {
					t.Fatal(err)
				}
			}
			var origin transport.NativeObservationOrigin
			if err := json.Unmarshal(o.Origin, &origin); err != nil {
				t.Fatal(err)
			}
			o.Event.Type = session.EventSessionStopped
			o.ResourceInterruption = &transport.NativeResourceInterruption{Cause: transport.NativeResourceOutputLimit, Source: transport.NativeAgentSource{OriginID: origin.ID, NativeGeneration: o.NativeGeneration, SessionID: o.NativeSessionID, LogicalTurnID: "pagnet-worker-turn-1", NativeTurnSequence: 1, InputKind: "task", SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String()}}
			call := func(_ context.Context, r sessionworker.Request) (sessionworker.Response, error) {
				if r.Type == "observations" {
					return sessionworker.Response{Observations: []sessionworker.NativeObservation{o}}, nil
				}
				if r.Type == "observation_ack" {
					acks++
					return sessionworker.Response{}, nil
				}
				t.Fatal("unsupported resource worker call", r.Type)
				return sessionworker.Response{}, nil
			}
			err := c.DrainNativeWorkerSources(t.Context(), call)
			if enabled {
				if err != nil || sends != 1 || acks != 1 {
					t.Fatal("authenticated resource capability did not deliver", err, sends, acks)
				}
			} else if !errors.Is(err, ErrNativeOriginAdmissionDeferred) || sends != 0 || acks != 0 {
				t.Fatal("resource source wrote without authenticated capability", err, sends, acks)
			}
		})
	}
}
