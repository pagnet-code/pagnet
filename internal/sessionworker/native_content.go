package sessionworker

import (
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
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

// New task purposes bind the accepted command's admission independently from
// the native origin's birth admission. A later accepted task can use its own
// original crypto epoch without giving reconnect delivery new authority.
func buildOriginalTurnContent(observation NativeObservation, instanceID, purpose, mimeType string, plain []byte, key [32]byte) (nativecontent.Transfer, error) {
	source := observation.TurnSource
	var origin struct {
		ID string `json:"id"`
	}
	if source == nil || source.SourceTask == nil || source.InputKind != "task" || source.NativeGeneration != observation.NativeGeneration || source.NativeSessionID != observation.NativeSessionID || source.LogicalTurnID != logicalWorkerTurn(source.Sequence) || source.SourceCommandID == "" || source.SourceAdmissionID == "" || json.Unmarshal(observation.Origin, &origin) != nil || origin.ID == "" || observation.ObservedAt.IsZero() || (purpose != "native_turn_output" && purpose != "native_turn_plan") {
		return nativecontent.Transfer{}, errors.New("original native task source binding is incomplete")
	}
	aad := source.SourceTask.InputAAD
	if aad.ObjectType != e2ee.ObjectTypeTask || aad.ObjectID != source.SourceTask.TaskID || aad.NativeContent != nil || aad.ValidateScope() != nil {
		return nativecontent.Transfer{}, errors.New("original task crypto descriptor is contradictory")
	}
	subject := uuid.NewSHA1(uuid.NameSpaceOID, []byte("pagnet-native-turn:"+origin.ID+":"+source.LogicalTurnID)).String()
	aad.Sender = instanceID
	aad.ObjectType = "runtime_turn"
	aad.ObjectID = subject
	aad.CreatedAt = observation.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	binding := e2ee.NativeContentBinding{ContentID: uuid.NewString(), ObservationID: observation.ID, OriginID: origin.ID, InstanceID: instanceID, NativeGeneration: observation.NativeGeneration, NativeSessionID: observation.NativeSessionID, SubjectType: "runtime_turn", SubjectID: subject, Purpose: purpose, SourceCommandID: source.SourceCommandID, SourceAdmissionID: source.SourceAdmissionID, LogicalTurnID: source.LogicalTurnID}
	return nativecontent.Build(plain, key, aad, binding, mimeType)
}
