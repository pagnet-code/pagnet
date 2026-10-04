package sessionworker

import (
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/nativecontent"
)

// Build only at original source capture. The returned ciphertext must commit
// with that observation before a controller may retrieve or publish it.
func buildOriginalContent(observation NativeObservation, subjectID, purpose, mimeType string, plain []byte, key [32]byte, aad e2ee.AAD) (nativecontent.Transfer, error) {
	var origin struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(observation.Origin, &origin) != nil || origin.ID == "" || observation.ObservedAt.IsZero() || observation.NativeGeneration == "" || observation.NativeSessionID == "" || subjectID == "" {
		return nativecontent.Transfer{}, errors.New("original native content source binding is incomplete")
	}
	// A new answer is a distinct content identity, not the old inspection's
	// native_content AAD with a rewritten timestamp or purpose.
	aad.NativeContent = nil
	aad.CreatedAt = observation.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	aad.ObjectType = e2ee.ObjectTypeRuntimeInteraction
	aad.ObjectID = subjectID
	binding := e2ee.NativeContentBinding{ContentID: uuid.NewString(), ObservationID: observation.ID, OriginID: origin.ID, InstanceID: aad.Sender, NativeGeneration: observation.NativeGeneration, NativeSessionID: observation.NativeSessionID, SubjectType: e2ee.ObjectTypeRuntimeInteraction, SubjectID: subjectID, Purpose: purpose}
	return nativecontent.Build(plain, key, aad, binding, mimeType)
}

// Turn content binds the accepted task or invocation admission independently from
// the native origin's birth admission. A later accepted task can use its own
// original crypto epoch without giving reconnect delivery new authority.
func buildOriginalTurnContent(observation NativeObservation, instanceID, purpose, mimeType string, plain []byte, key [32]byte) (nativecontent.Transfer, error) {
	source := observation.TurnSource
	var origin struct {
		ID string `json:"id"`
	}
	if source == nil || sourceContentDescriptor(source) == "" || source.NativeGeneration != observation.NativeGeneration || source.NativeSessionID != observation.NativeSessionID || source.LogicalTurnID != logicalWorkerTurn(source.Sequence) || source.SourceCommandID == "" || source.SourceAdmissionID == "" || json.Unmarshal(observation.Origin, &origin) != nil || origin.ID == "" || observation.ObservedAt.IsZero() || (purpose != "native_turn_output" && purpose != "native_turn_plan") {
		return nativecontent.Transfer{}, errors.New("original native turn source binding is incomplete")
	}
	aad, valid := sourceContentAAD(source)
	if !valid || aad.NativeContent != nil || aad.ValidateScope() != nil || source.SourceTask != nil && (aad.ObjectType != e2ee.ObjectTypeTask || aad.ObjectID != source.SourceTask.TaskID) {
		return nativecontent.Transfer{}, errors.New("original input crypto descriptor is contradictory")
	}
	subject := uuid.NewSHA1(uuid.NameSpaceOID, []byte("pagnet-native-turn:"+origin.ID+":"+source.LogicalTurnID)).String()
	aad.Sender = instanceID
	aad.ObjectType = "runtime_turn"
	aad.ObjectID = subject
	aad.CreatedAt = observation.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	binding := e2ee.NativeContentBinding{ContentID: uuid.NewString(), ObservationID: observation.ID, OriginID: origin.ID, InstanceID: instanceID, NativeGeneration: observation.NativeGeneration, NativeSessionID: observation.NativeSessionID, SubjectType: "runtime_turn", SubjectID: subject, Purpose: purpose, SourceCommandID: source.SourceCommandID, SourceAdmissionID: source.SourceAdmissionID, LogicalTurnID: source.LogicalTurnID}
	return nativecontent.Build(plain, key, aad, binding, mimeType)
}

func (o *SessionOwner) captureOriginalTaskContent(event session.SessionEvent, observation *NativeObservation) *nativecontent.Transfer {
	source := observation.TurnSource
	if sourceContentDescriptor(source) == "" {
		return nil
	}
	var plain []byte
	purpose, mime := "", ""
	switch event.Type {
	case session.EventTurnOutput:
		if !event.NativeOutput || event.Output == "" {
			return nil
		}
		purpose, mime = "native_turn_output", "text/plain; charset=utf-8"
		plain = []byte(event.Output)
	case session.EventTurnCompleted, session.EventTurnFailed:
		if event.Output == "" {
			return nil
		}
		purpose, mime = "native_turn_output", "text/plain; charset=utf-8"
		plain = []byte(event.Output)
	case session.EventPlanUpdated:
		if session.ValidatePlan(event.Plan) != nil {
			observation.SourceContentUnavailable = true
			return nil
		}
		purpose, mime = "native_turn_plan", "application/json"
		var err error
		plain, err = canonicalNativeJSON(event.Plan)
		if err != nil {
			observation.SourceContentUnavailable = true
			return nil
		}
	default:
		return nil
	}
	defer clear(plain)
	key, available := o.originalTaskContentPin(source)
	if !available {
		observation.SourceContentUnavailable = true
		return nil
	}
	defer clear(key[:])
	transfer, err := buildOriginalTurnContent(*observation, o.journal.scope.InstanceID, purpose, mime, plain, key)
	if err != nil {
		observation.SourceContentUnavailable = true
		return nil
	}
	if purpose == "native_turn_output" {
		observation.OutputContent = &transfer.Reference
	} else {
		observation.PlanContent = &transfer.Reference
	}
	return &transfer
}
