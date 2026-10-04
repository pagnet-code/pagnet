package fabric

import "unicode/utf8"

// ErrorCode is open for namespaced extension-specific errors. Consumers compare
// codes, never parse Message. Unknown codes are failures, not implicit success.
type ErrorCode string

const (
	CodeNotFound            ErrorCode = "NOT_FOUND"
	CodeStaleReference      ErrorCode = "STALE_REFERENCE"
	CodeInvalidInput        ErrorCode = "INVALID_INPUT"
	CodeUnauthenticated     ErrorCode = "UNAUTHENTICATED"
	CodeInterceptorRejected ErrorCode = "INTERCEPTOR_REJECTED"
	CodeInterceptorTimeout  ErrorCode = "INTERCEPTOR_TIMEOUT"
	CodeTargetUnavailable   ErrorCode = "TARGET_UNAVAILABLE"
	CodeDeadlineExceeded    ErrorCode = "DEADLINE_EXCEEDED"
	CodeCancelled           ErrorCode = "CANCELLED"
	CodeRedirectLoop        ErrorCode = "REDIRECT_LOOP"
	CodeExtensionCycle      ErrorCode = "EXTENSION_CYCLE"
	CodeInvalidMutation     ErrorCode = "INVALID_MUTATION"
	CodeStaleContinuation   ErrorCode = "STALE_CONTINUATION"
	CodeOfferRequired       ErrorCode = "OFFER_REQUIRED"
	CodeProtocolError       ErrorCode = "PROTOCOL_ERROR"
	CodeUnsupported         ErrorCode = "UNSUPPORTED"
)

// EffectState records evidence about endpoint effects. Unknown is the safe
// default: a transport error alone never authorizes destructive replay.
type EffectState string

const (
	EffectUnknown    EffectState = "unknown"
	EffectNotStarted EffectState = "not_started"
	EffectCompleted  EffectState = "completed"
)

// Error contains bounded public information only. Raw provider errors, input,
// credentials and private continuation capabilities must stay adapter-private.
type Error struct {
	Code    ErrorCode   `json:"code"`
	Message string      `json:"message"`
	Effect  EffectState `json:"effect"`
}

func NewError(code ErrorCode, message string) *Error {
	const maxMessage = 1024
	if !utf8.ValidString(message) {
		message = "Invalid error message"
	}
	if len(message) > maxMessage {
		message = message[:maxMessage]
		for !utf8.ValidString(message) {
			message = message[:len(message)-1]
		}
	}
	return &Error{Code: code, Message: message, Effect: EffectUnknown}
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return string(e.Code) + ": " + e.Message
}
