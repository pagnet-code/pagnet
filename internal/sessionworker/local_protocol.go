package sessionworker

import (
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

// LocalRequest is a distinct owner-private wire profile, never a Cloud request
// with fabricated tenant, host, session or dispatch proof fields. Exact native
// operation bytes are re-derived from the signed finalized admission.
type LocalRequest struct {
	ObservationID    string                         `json:"observationId,omitempty"`
	SourceDigest     string                         `json:"sourceDigest,omitempty"`
	CaptureOffset    int                            `json:"captureOffset,omitempty"`
	Cursor           int64                          `json:"cursor,omitempty"`
	Limit            int                            `json:"limit,omitempty"`
	Digest           string                         `json:"digest,omitempty"`
	Control          *nativeauthority.LocalControl  `json:"control,omitempty"`
	ActivationOrigin *LocalActivationOrigin         `json:"activationOrigin,omitempty"`
	Type             string                         `json:"type"`
	Intent           *nativeauthority.IntentRequest `json:"intent,omitempty"`
	Sequence         int64                          `json:"sequence,omitempty"`
}
type LocalResponse struct {
	Readiness    *ReadinessToken                     `json:"readiness,omitempty"`
	Observations []NativeObservation                 `json:"observations,omitempty"`
	Capture      *NativeCaptureChunk                 `json:"capture,omitempty"`
	Stream       *LocalInvocationPage                `json:"stream,omitempty"`
	Snapshot     *LocalNativeSnapshot                `json:"snapshot,omitempty"`
	Activation   *LocalActivationRequest             `json:"activation,omitempty"`
	Outcome      *Outcome                            `json:"outcome,omitempty"`
	Receipt      *fabricidentity.NativeIntentReceipt `json:"receipt,omitempty"`
	Code         string                              `json:"code,omitempty"`
	Error        string                              `json:"error,omitempty"`
}
