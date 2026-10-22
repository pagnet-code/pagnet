package transport

import "github.com/pagnet-code/pagnet/e2ee"

const (
	OwnerMailboxProtocolV1   = "pagnet/owner-mailbox/v1"
	OwnerMailboxMaxWireBytes = 256 * 1024

	MsgOwnerMailboxOpen      = "host.owner_mailbox_open"
	MsgOwnerMailboxReady     = "host.owner_mailbox_ready"
	MsgOwnerMailboxOperation = "host.owner_mailbox_operation"
	MsgOwnerMailboxResult    = "host.owner_mailbox_result"
	MsgOwnerMailboxClose     = "host.owner_mailbox_close"
)

// Owner mailbox messages use Envelope with distinct message types above. Every
// receiver must reject an unsupported protocol marker and enforce the 256 KiB
// serialized envelope limit before decoding. The crypto plaintext limit remains
// e2ee.OwnerMailboxMaxPlaintext (64 KiB); the wire limit includes base64 overhead.
// These messages are live, session-scoped relays, never durable commands.

// OwnerMailboxOpenPayload is authored by the server from a locked owner pin and
// authenticated HTTPS admission, never from a browser-supplied descriptor. The
// admission response returns this same immutable descriptor. Generation uses a
// canonical decimal JSON string, including values above 2^53; admission times
// are whole Unix seconds with exactly 900 seconds between issue and expiry.
// The host must reject any mismatch with its identity, keys, or current pin.
type OwnerMailboxOpenPayload struct {
	Protocol   string                      `json:"protocol"`
	Descriptor e2ee.OwnerMailboxDescriptor `json:"descriptor"`
}

// OwnerMailboxReadyPayload echoes the open descriptor unchanged. The host signs
// the bootstrap transcript binding this descriptor and the HPKE bootstrap. The
// browser must compare the canonical descriptor bytes with authenticated HTTPS
// admission before verifying the signature and accepting the bootstrap.
type OwnerMailboxReadyPayload struct {
	Protocol   string                      `json:"protocol"`
	Descriptor e2ee.OwnerMailboxDescriptor `json:"descriptor"`
	Bootstrap  e2ee.OwnerMailboxBootstrap  `json:"bootstrap"`
}

// OwnerMailboxOperationPayload relays browser-to-host ciphertext only. RequestID
// binds the one outstanding operation to its result; it must be nonempty and
// echoed unchanged. Sequence is the explicit directional crypto sequence, with
// uniqueness and replay checks enforced by session state. Ciphertext uses JSON
// base64 encoding through []byte; decrypted operation data never enters Envelope.
type OwnerMailboxOperationPayload struct {
	Protocol   string `json:"protocol"`
	SessionID  string `json:"sessionId"`
	RequestID  string `json:"requestId"`
	Sequence   uint64 `json:"sequence"`
	Ciphertext []byte `json:"ciphertext"`
}

// OwnerMailboxResultPayload relays host-to-browser ciphertext only and echoes
// the outstanding operation's RequestID. Sequence is in the host-to-browser
// direction; request correlation does not replace crypto sequence checks.
type OwnerMailboxResultPayload struct {
	Protocol   string `json:"protocol"`
	SessionID  string `json:"sessionId"`
	RequestID  string `json:"requestId"`
	Sequence   uint64 `json:"sequence"`
	Ciphertext []byte `json:"ciphertext"`
}

// OwnerMailboxCloseCode is a finite public reason, never diagnostic text.
type OwnerMailboxCloseCode string

const (
	OwnerMailboxCloseClosed        OwnerMailboxCloseCode = "closed"
	OwnerMailboxCloseExpired       OwnerMailboxCloseCode = "expired"
	OwnerMailboxCloseRejected      OwnerMailboxCloseCode = "rejected"
	OwnerMailboxCloseUnavailable   OwnerMailboxCloseCode = "unavailable"
	OwnerMailboxCloseProtocolError OwnerMailboxCloseCode = "protocol_error"
)

// IsValid reports whether code is in the v1 vocabulary. Receivers must fail
// closed on unknown codes; they must not display them as diagnostic text.
func (code OwnerMailboxCloseCode) IsValid() bool {
	switch code {
	case OwnerMailboxCloseClosed, OwnerMailboxCloseExpired, OwnerMailboxCloseRejected,
		OwnerMailboxCloseUnavailable, OwnerMailboxCloseProtocolError:
		return true
	default:
		return false
	}
}

// OwnerMailboxClosePayload terminates a session without exposing private error
// details. A close in either direction invalidates the outstanding operation.
type OwnerMailboxClosePayload struct {
	Protocol  string                `json:"protocol"`
	SessionID string                `json:"sessionId"`
	Code      OwnerMailboxCloseCode `json:"code"`
}
