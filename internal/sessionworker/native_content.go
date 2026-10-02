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
