package transport

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/domain"
)

const ManagedBrowserStandbyVersion = 1
const MaxManagedBrowserStandbyFrameBytes = 8 << 10

var errManagedBrowserStandby = errors.New("transport: invalid managed browser standby frame")
var managedBrowserStandbyTimestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)

// ManagedBrowserStandbyTuple identifies the exact managed assignment. Matching
// this tuple against authenticated state is the caller's responsibility.
type ManagedBrowserStandbyTuple struct {
	ConnectionID         string `json:"connectionId"`
	BindingID            string `json:"bindingId"`
	NetworkID            string `json:"networkId"`
	PrincipalID          string `json:"principalId"`
	HostID               string `json:"hostId"`
	Provider             string `json:"provider"`
	DesiredRevision      int64  `json:"desiredRevision"`
	LeaseID              string `json:"leaseId"`
	InstanceID           string `json:"instanceId"`
	LeaseGeneration      int64  `json:"leaseGeneration"`
	CredentialID         string `json:"credentialId"`
	CredentialGeneration int64  `json:"credentialGeneration"`
	PolicyFingerprint    string `json:"policyFingerprint"`
}

func (t ManagedBrowserStandbyTuple) Validate() error {
	for _, id := range []string{t.ConnectionID, t.BindingID, t.NetworkID, t.PrincipalID, t.HostID, t.LeaseID, t.InstanceID, t.CredentialID} {
		if !managedBrowserStandbyID(id) {
			return errManagedBrowserStandby
		}
	}
	digest, err := hex.DecodeString(t.PolicyFingerprint)
	if t.Provider == "" || t.DesiredRevision <= 0 || t.LeaseGeneration <= 0 || t.CredentialGeneration <= 0 || err != nil || len(digest) != 32 || hex.EncodeToString(digest) != t.PolicyFingerprint {
		return errManagedBrowserStandby
	}
	return nil
}

// ManagedBrowserStandbySession is the common versioned session identity.
type ManagedBrowserStandbySession struct {
	Version           int    `json:"version"`
	Type              string `json:"type"`
	SessionID         string `json:"sessionId"`
	SessionGeneration int64  `json:"sessionGeneration"`
}

func (s ManagedBrowserStandbySession) validate(kind string) error {
	if s.Version != ManagedBrowserStandbyVersion || s.Type != kind || s.SessionGeneration <= 0 {
		return errManagedBrowserStandby
	}
	if !managedBrowserStandbyID(s.SessionID) {
		return errManagedBrowserStandby
	}
	return nil
}

// ManagedBrowserStandbyFrame contains only standby protocol messages.
type ManagedBrowserStandbyFrame interface {
	Validate() error
	managedBrowserStandbyFrame()
}

type ManagedBrowserStandbyChallenge struct {
	ManagedBrowserStandbySession
	Tuple          ManagedBrowserStandbyTuple `json:"tuple"`
	Nonce          string                     `json:"nonce"`
	ValidForMs     int64                      `json:"validForMs"`
	ExecutionReady bool                       `json:"executionReady"`
}
type ManagedBrowserStandbyAck struct {
	ManagedBrowserStandbySession
	Nonce string `json:"nonce"`
}
type ManagedBrowserStandby struct {
	ManagedBrowserStandbySession
	Sequence            int64  `json:"sequence"`
	LeaseExpiresAt      string `json:"leaseExpiresAt"`
	CredentialExpiresAt string `json:"credentialExpiresAt"`
	ValidForMs          int64  `json:"validForMs"`
	ExecutionReady      bool   `json:"executionReady"`
}
type ManagedBrowserStandbyHeartbeat struct {
	ManagedBrowserStandbySession
	Sequence int64 `json:"sequence"`
}
type ManagedBrowserStandbyHeartbeatAck struct {
	ManagedBrowserStandbySession
	Sequence            int64  `json:"sequence"`
	LeaseExpiresAt      string `json:"leaseExpiresAt"`
	CredentialExpiresAt string `json:"credentialExpiresAt"`
	ValidForMs          int64  `json:"validForMs"`
	ExecutionReady      bool   `json:"executionReady"`
}

func (ManagedBrowserStandbyChallenge) managedBrowserStandbyFrame()    {}
func (ManagedBrowserStandbyAck) managedBrowserStandbyFrame()          {}
func (ManagedBrowserStandby) managedBrowserStandbyFrame()             {}
func (ManagedBrowserStandbyHeartbeat) managedBrowserStandbyFrame()    {}
func (ManagedBrowserStandbyHeartbeatAck) managedBrowserStandbyFrame() {}

func managedBrowserStandbyNonce(s string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == s
}
func managedBrowserStandbyID(s string) bool {
	id, err := domain.ParseID(s)
	return err == nil && string(id) == s && s != "00000000-0000-0000-0000-000000000000"
}
func managedBrowserStandbyTime(s string) bool {
	if !managedBrowserStandbyTimestamp.MatchString(s) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}
func managedBrowserStandbyValidity(lease, credential string, validity int64, ready bool) bool {
	return !ready && validity >= 1 && validity <= 10000 && managedBrowserStandbyTime(lease) && managedBrowserStandbyTime(credential)
}
func (f ManagedBrowserStandbyChallenge) Validate() error {
	if f.ManagedBrowserStandbySession.validate("challenge") != nil || f.Tuple.Validate() != nil || !managedBrowserStandbyNonce(f.Nonce) || f.ValidForMs < 1 || f.ValidForMs > 5000 || f.ExecutionReady {
		return errManagedBrowserStandby
	}
	return nil
}
func (f ManagedBrowserStandbyAck) Validate() error {
	if f.ManagedBrowserStandbySession.validate("ack") != nil || !managedBrowserStandbyNonce(f.Nonce) {
		return errManagedBrowserStandby
	}
	return nil
}
func (f ManagedBrowserStandby) Validate() error {
	if f.ManagedBrowserStandbySession.validate("standby") != nil || f.Sequence != 0 || !managedBrowserStandbyValidity(f.LeaseExpiresAt, f.CredentialExpiresAt, f.ValidForMs, f.ExecutionReady) {
		return errManagedBrowserStandby
	}
	return nil
}
func (f ManagedBrowserStandbyHeartbeat) Validate() error {
	if f.ManagedBrowserStandbySession.validate("heartbeat") != nil || f.Sequence <= 0 {
		return errManagedBrowserStandby
	}
	return nil
}
func (f ManagedBrowserStandbyHeartbeatAck) Validate() error {
	if f.ManagedBrowserStandbySession.validate("heartbeat_ack") != nil || f.Sequence <= 0 || !managedBrowserStandbyValidity(f.LeaseExpiresAt, f.CredentialExpiresAt, f.ValidForMs, f.ExecutionReady) {
		return errManagedBrowserStandby
	}
	return nil
}

func EncodeManagedBrowserStandbyFrame(f ManagedBrowserStandbyFrame) ([]byte, error) {
	if f == nil {
		return nil, errManagedBrowserStandby
	}
	// Decoding the encoding also verifies required fields and typed nil pointers.
	raw, err := json.Marshal(f)
	if err != nil {
		return nil, errManagedBrowserStandby
	}
	decoded, err := DecodeManagedBrowserStandbyFrame(1, raw)
	if err != nil {
		return nil, err
	}
	canonicalTime := func(value string) string {
		timestamp, _ := time.Parse(time.RFC3339Nano, value)
		return timestamp.UTC().Format(time.RFC3339Nano)
	}
	switch frame := decoded.(type) {
	case *ManagedBrowserStandby:
		frame.LeaseExpiresAt = canonicalTime(frame.LeaseExpiresAt)
		frame.CredentialExpiresAt = canonicalTime(frame.CredentialExpiresAt)
	case *ManagedBrowserStandbyHeartbeatAck:
		frame.LeaseExpiresAt = canonicalTime(frame.LeaseExpiresAt)
		frame.CredentialExpiresAt = canonicalTime(frame.CredentialExpiresAt)
	}
	return json.Marshal(decoded)
}

// DecodeManagedBrowserStandbyFrame accepts only WebSocket text messages (type 1).
// It validates syntax and values, without authorizing execution or checking
// session ordering, clock validity, or the authenticated assignment tuple.
func DecodeManagedBrowserStandbyFrame(messageType int, raw []byte) (ManagedBrowserStandbyFrame, error) {
	if messageType != 1 || len(raw) == 0 || len(raw) > MaxManagedBrowserStandbyFrameBytes || !utf8.Valid(raw) {
		return nil, errManagedBrowserStandby
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	object, err := managedBrowserStandbyJSON(dec)
	if err != nil {
		return nil, errManagedBrowserStandby
	}
	if _, err = dec.Token(); err != io.EOF {
		return nil, errManagedBrowserStandby
	}
	fields, ok := object.(map[string]any)
	if !ok {
		return nil, errManagedBrowserStandby
	}
	var f ManagedBrowserStandbyFrame
	switch fields["type"] {
	case "challenge":
		f = &ManagedBrowserStandbyChallenge{}
	case "ack":
		f = &ManagedBrowserStandbyAck{}
	case "standby":
		f = &ManagedBrowserStandby{}
	case "heartbeat":
		f = &ManagedBrowserStandbyHeartbeat{}
	case "heartbeat_ack":
		f = &ManagedBrowserStandbyHeartbeatAck{}
	default:
		return nil, errManagedBrowserStandby
	}
	template, _ := json.Marshal(f)
	var shape map[string]any
	if json.Unmarshal(template, &shape) != nil || !managedBrowserStandbyShape(fields, shape) || json.Unmarshal(raw, f) != nil || f.Validate() != nil {
		return nil, errManagedBrowserStandby
	}
	return f, nil
}

// Parse tokens before unmarshaling so duplicate fields and null cannot disappear.
func managedBrowserStandbyJSON(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil || token == nil {
		return nil, errManagedBrowserStandby
	}
	if delim, ok := token.(json.Delim); ok {
		if delim != '{' {
			return nil, errManagedBrowserStandby
		}
		object := make(map[string]any)
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return nil, errManagedBrowserStandby
			}
			name, ok := key.(string)
			if !ok {
				return nil, errManagedBrowserStandby
			}
			if _, exists := object[name]; exists {
				return nil, errManagedBrowserStandby
			}
			value, err := managedBrowserStandbyJSON(dec)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errManagedBrowserStandby
		}
		return object, nil
	}
	return token, nil
}
func managedBrowserStandbyShape(object, template map[string]any) bool {
	if len(object) != len(template) {
		return false
	}
	for key, expected := range template {
		actual, exists := object[key]
		if !exists {
			return false
		}
		if nested, ok := expected.(map[string]any); ok {
			child, ok := actual.(map[string]any)
			if !ok || !managedBrowserStandbyShape(child, nested) {
				return false
			}
		}
	}
	return true
}
