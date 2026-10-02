package sessionworker

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/nativecontent"
)

// The factory runs before the endpoint reader starts. Each closure retains the
// original activation source even when subsequent delivery commands arrive.
func (o *SessionOwner) nativeSourceObserver(instanceID string, producer *nativeSourceProducer) session.NativeEventObserver {
	o.mu.Lock()
	generation := o.generation
	origin := append(json.RawMessage(nil), o.origin...)
	o.mu.Unlock()
	if producer != nil {
		generation = producer.generation
		origin = append(json.RawMessage(nil), producer.origin...)
	}
	return func(event session.SessionEvent) error {
		observedAt := time.Now().UTC()
		o.mu.Lock()
		if o.generation == generation {
			o.manager.ObserveNativeActivity(instanceID, event)
		}
		duplicate := false
		if native := event.Interaction; native != nil && !native.Resolved && event.Type == session.EventInteractionStarted {
			pending := o.pending[native.NativeInteractionID]
			duplicate = pending != nil && pending.committed && pending.inspection != nil && pending.inspection.NativeGeneration == generation && pending.inspection.NativeSessionID == event.SessionID && pending.inspection.Kind == native.Kind && slices.Equal(pending.inspection.Options, native.Options) && pending.payloadDigest == sha256.Sum256(native.NativePayload) && pending.summaryDigest == sha256.Sum256([]byte(native.Summary))
		}
		o.mu.Unlock()
		if duplicate {
			return o.ctx.Err()
		}
		if !durableNativeEvent(event) {
			o.recordLiveEvent(event, generation, origin)
			return o.ctx.Err()
		}
		originalEvent := event
		var transfers []nativecontent.Transfer
		observation := NativeObservation{ID: uuid.NewString(), NativeGeneration: generation, NativeSessionID: event.SessionID, Origin: origin, ObservedAt: observedAt}
		source, unavailable, err := o.journal.NativeEventSource(o.ctx, generation, event)
		if err != nil {
			return err
		}
		observation.TurnSource = source
		observation.SourceUnavailable = unavailable
		// Original private details are captured above; the journal projection is metadata only.
		event.Plan = nil
		event.Output = ""
		event.Error = ""
		var inspection *Inspection
		if event.Interaction != nil {
			if !event.Interaction.Resolved {
				o.prepareInspection(event, generation, observation)
			}
			o.mu.Lock()
			if pending := o.pending[event.Interaction.NativeInteractionID]; pending != nil && pending.inspection != nil && pending.inspection.NativeGeneration == generation {
				copy := *pending.inspection
				copy.Options = append(copy.Options[:0:0], pending.inspection.Options...)
				inspection = &copy
				if !event.Interaction.Resolved && pending.transfer != nil {
					transfers = append(transfers, *pending.transfer)
				}
			}
			if event.Interaction.Resolved {
				pending := o.pending[event.Interaction.NativeInteractionID]
				if pending != nil && inspection != nil && inspection.DetailContent != nil && pending.payloadDigest == sha256.Sum256(originalEvent.Interaction.NativePayload) {
					observation.OriginalNativePayloadContent = inspection.DetailContent
				}
			}
			if event.Interaction.Resolved && o.generation == generation {
				pending := o.pending[event.Interaction.NativeInteractionID]
				if pending != nil && pending.inspection != nil && pending.inspection.NativeGeneration == generation && pending.inspection.NativeSessionID == event.SessionID {
					delete(o.pending, event.Interaction.NativeInteractionID)
				}
			}
			o.mu.Unlock()
			copy := *event.Interaction
			copy.NativePayload = nil
			copy.Summary = ""
			copy.Answer = ""
			event.Interaction = &copy
		}
		captureSource := NativeSourceCapture{Format: NativeSourceCaptureFormat, Event: originalEvent, OriginalNativePayloadContent: observation.OriginalNativePayloadContent}
		if observation.OriginalNativePayloadContent != nil {
			copy := *originalEvent.Interaction
			copy.NativePayload = nil
			captureSource.Event.Interaction = &copy
		}
		ref, encrypted, err := sealNativeCapture(o.captureKey, o.journal.scope, o.journal.dir, observation, captureSource)
		if err != nil {
			return err
		}
		observation.Capture = ref
		eventRaw, err := json.Marshal(event)
		if err != nil {
			o.failPersistence(err)
			return err
		}
		var stableEvent session.SessionEvent
		if err := json.Unmarshal(eventRaw, &stableEvent); err != nil {
			o.failPersistence(err)
			return err
		}
		event = stableEvent
		observation.Event = event
		observation.Inspection = inspection
		if originalEvent.Interaction != nil && originalEvent.Interaction.Resolved {
			var answerTransfer *nativecontent.Transfer
			observation.Resolution, answerTransfer = o.encryptOriginalResolution(originalEvent, inspection, observation)
			if answerTransfer != nil {
				transfers = append(transfers, *answerTransfer)
			}
		}
		if event.Interaction != nil {
			observation.InteractionID = nativeInteractionIdentity(o.journal.scope, origin, generation, event.SessionID, event.Interaction.NativeInteractionID)
		}
		digest, err := observationDigest(observation)
		if err != nil {
			o.failPersistence(err)
			return err
		}
		observation.SourceDigest = digest
		if err = o.journal.pinSourceRetry(observation.ID, digest); err != nil {
			return err
		}
		defer o.journal.releaseSourceRetry(observation.ID, digest)
		backoff := 250 * time.Millisecond
		for {
			available := o.journal.ObservationCapacity()
			err = o.journal.journalCapturedObservation(o.ctx, producer, observation, encrypted, transfers...)
			if err == nil {
				break
			}
			o.mu.Lock()
			o.observationBlocked = err
			if o.observationWaiters == nil {
				o.observationWaiters = map[string]bool{}
			}
			o.observationWaiters[observation.ID] = true
			o.mu.Unlock()
			var retry <-chan time.Time
			var timer *time.Timer
			if !errors.Is(err, ErrFull) {
				timer = time.NewTimer(backoff)
				retry = timer.C
				if backoff < 5*time.Second {
					backoff *= 2
					if backoff > 5*time.Second {
						backoff = 5 * time.Second
					}
				}
			}
			select {
			case <-o.ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				o.mu.Lock()
				delete(o.observationWaiters, observation.ID)
				if len(o.observationWaiters) == 0 {
					o.observationBlocked = nil
				}
				o.mu.Unlock()
				return o.ctx.Err()
			case <-available:
				if timer != nil {
					timer.Stop()
				}
				backoff = 250 * time.Millisecond
			case <-retry:
			}
		}
		o.mu.Lock()
		if event.Interaction != nil && !event.Interaction.Resolved {
			if pending := o.pending[event.Interaction.NativeInteractionID]; pending != nil && pending.inspection != nil && pending.inspection.NativeGeneration == generation {
				// Complete ciphertext is now durable. Keep only local private commitments
				// for duplicate/source association, not another huge request/transfer copy.
				pending.committed = true
				pending.native = nil
				pending.summary = ""
				pending.transfer = nil
			}
		}
		delete(o.observationWaiters, observation.ID)
		if len(o.observationWaiters) == 0 {
			o.observationBlocked = nil
		}
		o.mu.Unlock()
		o.record("session", event, generation, origin)
		if o.ctx.Err() != nil {
			return o.ctx.Err()
		}
		return nil
	}
}

// Origin.ID is authority minted; fixed semantic fields avoid raw-JSON field
// ordering becoming a different interaction identity on reconnect.
func nativeInteractionIdentity(scope Scope, origin json.RawMessage, generation, nativeSession, nativeID string) string {
	var descriptor struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(origin, &descriptor) != nil || descriptor.ID == "" || generation == "" || nativeSession == "" || nativeID == "" {
		return ""
	}
	binding := struct {
		Domain              string
		Scope               Scope
		OriginID            string
		NativeGeneration    string
		NativeSessionID     string
		NativeInteractionID string
	}{"pagnet-native-interaction-identity-v1", scope, descriptor.ID, generation, nativeSession, nativeID}
	raw, _ := json.Marshal(binding)
	return uuid.NewHash(sha256.New(), uuid.NameSpaceOID, raw, 8).String()
}

// Transient output is not a published result or a durable transcript. Only
// explicit lifecycle/turn/plan/interaction evidence enters the source outbox.
func durableNativeEvent(event session.SessionEvent) bool {
	switch event.Type {
	case session.EventSessionStarted, session.EventSessionResumed, session.EventSessionLost, session.EventSessionIdentityChanged, session.EventBusy, session.EventIdle, session.EventTurnStarted, session.EventPlanUpdated, session.EventTurnCompleted, session.EventTurnFailed, session.EventInteractionStarted, session.EventInteractionResolved:
		return true
	default:
		return false
	}
}

func (o *SessionOwner) recordLiveEvent(event session.SessionEvent, generation string, origin json.RawMessage) {
	const chunkBytes = 64 << 10
	if len(event.Output) <= chunkBytes {
		o.record("session", event, generation, origin)
		return
	}
	remaining := event.Output
	for len(remaining) > 0 {
		end := len(remaining)
		if end > chunkBytes {
			end = chunkBytes
			for end > 0 && !utf8.RuneStart(remaining[end]) {
				end--
			}
			if end == 0 {
				end = chunkBytes
			} // Invalid native UTF-8 must not create an infinite loop.
		}
		fragment := event
		fragment.Output = remaining[:end]
		o.record("session", fragment, generation, origin)
		remaining = remaining[end:]
	}
}
