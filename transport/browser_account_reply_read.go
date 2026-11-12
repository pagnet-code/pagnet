package transport

import (
	"errors"
	"strconv"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/domain"
)

const BrowserAccountReplyReadProtocol = "browser-account-reply-read-v1"
const BrowserAccountReplyReadMaxWireBytes = 128 << 10
const BrowserAccountReplyReadChunkBytes = 32768

const (
	MsgAccountReplyRead         = "account.reply.read"
	MsgAccountReplyReadHello    = "account.reply.read.hello"
	MsgAccountReplyReadFragment = "account.reply.read.fragment"
	MsgAccountReplyReadCommit   = "account.reply.read.commit"
	MsgAccountReplyReadCancel   = "account.reply.read.cancel"
	MsgAccountReplyReadChunk    = "account.reply.read.chunk"
	MsgAccountReplyReadDone     = "account.reply.read.done"
	MsgAccountReplyReadError    = "account.reply.read.error"
)

type BrowserAccountReplyReadHelloPayload struct {
	V        int    `json:"v"`
	Protocol string `json:"protocol"`
}
type BrowserAccountReplyReadBeginPayload struct {
	V         int                    `json:"v"`
	MessageID string                 `json:"messageId"`
	Deadline  string                 `json:"deadline"`
	Reference NativeContentReference `json:"reference"`
	Proof     NativeDispatchProof    `json:"proof"`
}
type BrowserAccountReplyReadFragmentPayload struct {
	V        int                   `json:"v"`
	Fragment NativeContentFragment `json:"fragment"`
}
type BrowserAccountReplyReadVersionPayload struct {
	V int `json:"v"`
}
type BrowserAccountReplyReadChunkPayload struct {
	V        int    `json:"v"`
	Sequence int    `json:"sequence"`
	Data     string `json:"data"`
}
type BrowserAccountReplyReadDonePayload struct {
	V                int    `json:"v"`
	MessageID        string `json:"messageId"`
	ContentID        string `json:"contentId"`
	CiphertextDigest string `json:"ciphertextDigest"`
	ChunkCount       int    `json:"chunkCount"`
	PlaintextBytes   int64  `json:"plaintextBytes"`
	PlaintextDigest  string `json:"plaintextDigest"`
}
type BrowserAccountReplyReadErrorPayload struct {
	V    int    `json:"v"`
	Code string `json:"code"`
}

var errBrowserAccountReplyRead = errors.New("transport: invalid account reply read frame")

// DecodeBrowserAccountReplyReadFrame validates bounded, strictly named envelope
// metadata. Request authority and state transitions belong to the host handler.
func DecodeBrowserAccountReplyReadFrame(raw []byte) (Envelope, error) {
	var e Envelope
	if DecodeBrowserAccountReplyReadPayload(raw, &e) != nil || e.ProtocolVersion != ProtocolVersion || e.Timestamp.IsZero() || !browserReplyReadID(e.ID) || e.CausationID != nil {
		return Envelope{}, errBrowserAccountReplyRead
	}
	if e.CorrelationID != nil && !browserReplyReadID(*e.CorrelationID) {
		return Envelope{}, errBrowserAccountReplyRead
	}
	switch e.Type {
	case MsgAccountReplyRead, MsgAccountReplyReadHello:
		if e.CorrelationID != nil {
			return Envelope{}, errBrowserAccountReplyRead
		}
	case MsgAccountReplyReadFragment, MsgAccountReplyReadCommit, MsgAccountReplyReadCancel, MsgAccountReplyReadChunk, MsgAccountReplyReadDone, MsgAccountReplyReadError:
		if e.CorrelationID == nil {
			return Envelope{}, errBrowserAccountReplyRead
		}
	default:
		return Envelope{}, errBrowserAccountReplyRead
	}
	return e, nil
}

func browserReplyReadID(id string) bool {
	parsed, err := domain.ParseID(id)
	return err == nil && parsed.String() == id
}

func DecodeBrowserAccountReplyReadPayload(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > BrowserAccountReplyReadMaxWireBytes || !browserReplyReadUnicode(raw) || DecodeOwnerTextConsolePayload(raw, target) != nil {
		return errBrowserAccountReplyRead
	}
	return nil
}

func browserReplyReadUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
