package transport

import "github.com/pagnet-code/pagnet/e2ee"

const NativeContentFormat = "pagnet.native-content.v1"
const NativeContentManifestFormat = "pagnet.native-content-manifest.v1"
const NativeContentFragmentPlaintextBytes = 64 << 10
const NativeContentMaxPlaintextBytes = 20 << 20
const NativeContentMaxCiphertextBytes = 30 << 20
const NativeContentMaxManifestPlaintextBytes = 64 << 10
const NativeContentMaxFragmentPage = 16
const NativeContentMaxPageWireBytes = 2 << 20

// Reference is published only together with the complete original observation
// transaction. CiphertextDigest authenticates ciphertext; plaintext digests are
// private and belong exclusively inside the encrypted manifest.
type NativeContentReference struct {
	Format           string                  `json:"format"`
	ContentID        string                  `json:"contentId"`
	ObservationID    string                  `json:"observationId"`
	OriginID         string                  `json:"originId"`
	InstanceID       string                  `json:"instanceId"`
	NativeGeneration string                  `json:"nativeGeneration"`
	NativeSessionID  string                  `json:"nativeSessionId"`
	SubjectType      string                  `json:"subjectType"`
	SubjectID        string                  `json:"subjectId"`
	Purpose          string                  `json:"purpose"`
	FragmentCount    int                     `json:"fragmentCount"`
	CiphertextBytes  int64                   `json:"ciphertextBytes"`
	CiphertextDigest string                  `json:"ciphertextDigest"`
	ManifestEnvelope e2ee.EncryptedPayloadV1 `json:"manifestEnvelope"`
	ManifestAAD      e2ee.AAD                `json:"manifestAAD"`
}

type NativeContentManifest struct {
	Format          string                          `json:"format"`
	ContentID       string                          `json:"contentId"`
	Purpose         string                          `json:"purpose"`
	MimeType        string                          `json:"mimeType"`
	PlaintextBytes  int64                           `json:"plaintextBytes"`
	PlaintextDigest string                          `json:"plaintextDigest"`
	Chunks          []NativeContentChunkDescription `json:"chunks"`
}

type NativeContentChunkDescription struct {
	Ordinal         int    `json:"ordinal"`
	Offset          int64  `json:"offset"`
	Length          int    `json:"length"`
	PlaintextDigest string `json:"plaintextDigest"`
}

type NativeContentFragment struct {
	ContentID string                  `json:"contentId"`
	Ordinal   int                     `json:"ordinal"`
	Envelope  e2ee.EncryptedPayloadV1 `json:"envelope"`
	AAD       e2ee.AAD                `json:"aad"`
}

type NativeContentFragmentPage struct {
	ContentID string                  `json:"contentId"`
	State     string                  `json:"state"`
	Fragments []NativeContentFragment `json:"fragments"`
	NextAfter *int                    `json:"nextAfter,omitempty"`
}

const NativeContentProtocol = "native-content-manifest-v1"
const (
	MsgNativeContentBegin    = "host.native_content_begin"
	MsgNativeContentFragment = "host.native_content_fragment"
	MsgNativeContentStatus   = "host.native_content_status"
	MsgNativeContentStaged   = "host.native_content_staged"
	MsgNativeContentRejected = "host.native_content_rejected"
)

// Staged acknowledges storage progress only. It is never a whole-source
// receipt and never authorizes removal of private worker source evidence.
type NativeContentStagedPayload struct {
	ContentID        string `json:"contentId"`
	CiphertextDigest string `json:"ciphertextDigest"`
	MissingOrdinals  []int  `json:"missingOrdinals"`
	MoreMissing      bool   `json:"moreMissing"`
	PublicError      string `json:"publicError,omitempty"`
	Retryable        bool   `json:"retryable,omitempty"`
}
type NativeContentStatusPayload struct {
	ContentID        string `json:"contentId"`
	CiphertextDigest string `json:"ciphertextDigest"`
}

// Authenticated GET responses expose content only after the source observation
// and its complete attachment commit. Staging is a separate host protocol.
type NativeContentDescriptor struct {
	State     string                 `json:"state"`
	Reference NativeContentReference `json:"reference"`
}
