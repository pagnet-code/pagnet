package transport

import "github.com/pagnet-code/pagnet/e2ee"

// MsgAccountMessage is a native-owner-only managed input. Its payload carries
// ciphertext and the original account source; it never carries prompt text.
const MsgAccountMessage = "host.account_message"

// AccountMessagePayload is sent only after the server commits the original
// account admission and immutable dispatch snapshot. NativeDispatch is the
// proof for that same command, not a permit to retarget another worker.
type AccountMessagePayload struct {
	CommandID      string                  `json:"commandId"`
	InstanceID     string                  `json:"instanceId"`
	Envelope       e2ee.EncryptedPayloadV1 `json:"envelope"`
	NativeDispatch *NativeDispatchProof    `json:"nativeDispatch"`
}
