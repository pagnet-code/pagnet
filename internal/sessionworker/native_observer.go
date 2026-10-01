package sessionworker

import (
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/session"
)

// The factory runs before the endpoint reader starts. Each closure retains the
// original activation source even when subsequent delivery commands arrive.
func (o *SessionOwner) nativeEventObserver(instanceID string) session.NativeEventObserver {
	o.mu.Lock()
	generation := o.generation
	origin := append(json.RawMessage(nil), o.origin...)
	o.mu.Unlock()
	return func(event session.SessionEvent) error {
		observedAt := time.Now().UTC()
		o.mu.Lock()
		current := o.generation == generation
		o.mu.Unlock()
		if current {
			o.manager.ObserveNativeActivity(instanceID, event)
		}
		var inspection *Inspection
		if event.Interaction != nil {
			if event.Interaction.Resolved {
				o.mu.Lock()
				if current {
					delete(o.pending, event.Interaction.NativeInteractionID)
				}
				o.mu.Unlock()
			} else {
				o.prepareInspection(event, generation)
			}
			o.mu.Lock()
			if pending := o.pending[event.Interaction.NativeInteractionID]; pending != nil && pending.inspection != nil && pending.inspection.NativeGeneration == generation {
				copy := *pending.inspection
				copy.Options = append(copy.Options[:0:0], pending.inspection.Options...)
				inspection = &copy
			}
			o.mu.Unlock()
			copy := *event.Interaction
			copy.NativePayload = nil
			copy.Summary = ""
			copy.Answer = ""
			event.Interaction = &copy
		}
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
		observation := NativeObservation{ID: uuid.NewString(), NativeGeneration: generation, NativeSessionID: event.SessionID, Origin: origin, ObservedAt: observedAt, Event: event, Inspection: inspection}
		if event.Interaction != nil {
			observation.InteractionID = nativeInteractionIdentity(o.journal.scope, origin, generation, event.SessionID, event.Interaction.NativeInteractionID)
		}
		digest, err := observationDigest(observation)
		if err != nil {
			o.failPersistence(err)
			return err
		}
		observation.SourceDigest = digest
		for {
			err = o.journal.JournalObservation(o.ctx, observation)
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
			timer := time.NewTimer(25 * time.Millisecond)
			select {
			case <-o.ctx.Done():
				timer.Stop()
				o.mu.Lock()
				delete(o.observationWaiters, observation.ID)
				if len(o.observationWaiters) == 0 {
					o.observationBlocked = nil
				}
				o.mu.Unlock()
				return o.ctx.Err()
			case <-timer.C:
			}
		}
		o.mu.Lock()
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
