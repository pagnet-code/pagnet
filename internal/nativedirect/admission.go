// Package nativedirect defines dormant direct ASK reservation evidence.
// Evidence is data; it never authorizes a native prompt submission.
package nativedirect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/transport"
)

const Protocol = "pagnet-native-direct-ask-reservation-v1"

var ErrInvalid = errors.New("invalid native direct ASK source")

// NativeDirectASKSource is immutable provenance for exactly one encrypted ASK.
// Scope is the existing authenticated cloud worker scope, never a fabricated
// dispatch command, ordinal, or NativeDispatchProof.
type NativeDirectASKSource struct {
	Protocol            string                                    `json:"protocol"`
	AdmissionID         string                                    `json:"admissionId"`
	ServerOrigin        string                                    `json:"serverOrigin"`
	Scope               nativeauthority.CloudScope                `json:"scope"`
	Ownership           transport.NativeWorkerOwnership           `json:"ownership"`
	NativeSessionID     string                                    `json:"nativeSessionId"`
	NativeGeneration    string                                    `json:"nativeGeneration"`
	NativeStartIdentity string                                    `json:"nativeStartIdentity"`
	NativePID           int                                       `json:"nativePid"`
	EndpointIssueID     string                                    `json:"endpointIssueId"`
	EndpointLeaseID     string                                    `json:"endpointLeaseId"`
	EndpointGeneration  string                                    `json:"endpointGeneration"`
	ConsentRevision     int64                                     `json:"consentRevision"`
	Receipt             transport.DirectMessageAdmissionReceiptV2 `json:"receipt"`
	InputDigest         string                                    `json:"inputDigest"`
	Deadline            time.Time                                 `json:"deadline"`
}

func bounded(s string) bool { return s != "" && len(s) <= 256 && utf8.ValidString(s) }

func (s NativeDirectASKSource) Validate() error {
	origin, err := url.Parse(s.ServerOrigin)
	if err != nil || origin.Scheme != "https" && origin.Scheme != "http" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.String() != s.ServerOrigin || len(s.ServerOrigin) > 2048 || s.Scope.Validate() != nil || s.Protocol != Protocol {
		return ErrInvalid
	}
	for _, id := range []string{s.AdmissionID, s.NativeSessionID, s.NativeGeneration, s.NativeStartIdentity, s.EndpointIssueID, s.EndpointLeaseID, s.EndpointGeneration, s.Ownership.ID, s.Ownership.Runtime, s.Ownership.OriginalAdmissionID} {
		if !bounded(id) {
			return ErrInvalid
		}
	}
	workerURL, _ := url.Parse(s.Scope.ServerURL)
	if workerURL.Scheme+"://"+workerURL.Host != s.ServerOrigin || s.NativePID <= 0 || s.Ownership.InstanceID != s.Scope.InstanceID || s.Ownership.OwnershipGeneration != s.Scope.Generation || s.Ownership.State != "active" || s.Ownership.DeletionProof != nil || s.Ownership.LastDispatchSequence != 0 || s.Ownership.RetiredFloor != 0 || s.ConsentRevision <= 0 || len(s.Ownership.Profile) > 256 || !utf8.ValidString(s.Ownership.Profile) {
		return ErrInvalid
	}
	for _, digest := range []string{s.InputDigest, s.Ownership.ProfileFingerprint} {
		raw, err := hex.DecodeString(digest)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != digest {
			return ErrInvalid
		}
	}
	if _, err = s.Receipt.CanonicalBytes(); err != nil || s.Receipt.Binding.Recipient.Role != "P" {
		return ErrInvalid
	}
	admitted, _ := time.Parse(time.RFC3339Nano, s.Receipt.AdmittedAt)
	expires, _ := time.Parse(time.RFC3339Nano, s.Receipt.ExpiresAt)
	if s.Deadline.IsZero() || s.Deadline.Location() != time.UTC || !s.Deadline.After(admitted) || s.Deadline.After(expires) {
		return ErrInvalid
	}
	return nil
}

func (s NativeDirectASKSource) CanonicalBytes() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

func (s NativeDirectASKSource) Digest() ([32]byte, error) {
	raw, err := s.CanonicalBytes()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

// DeliveryKey includes the whole publication and both parties. Message IDs
// alone are not unique across publications, credentials, or channels.
func (s NativeDirectASKSource) DeliveryKey() ([32]byte, error) {
	if err := s.Validate(); err != nil {
		return [32]byte{}, err
	}
	b := s.Receipt.Binding
	raw, err := json.Marshal(struct {
		Scope             nativeauthority.CloudScope
		Origin            string
		Context           transport.DirectDeliveryContextV2
		Sender, Recipient transport.DirectDeliveryPartyV2
		MessageID         string
	}{s.Scope, s.ServerOrigin, b.Context, b.Sender, b.Recipient, b.MessageID})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

// ValidateWire binds the exact encrypted canonical wire to its full receipt.
func (s NativeDirectASKSource) ValidateWire(wire json.RawMessage) error {
	if err := s.Validate(); err != nil {
		return err
	}
	d := transport.DirectDeliveryV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/item", Admission: s.Receipt, DeliveryState: "pending", Wire: wire}
	if _, err := d.CanonicalBytes(); err != nil {
		return ErrInvalid
	}
	w, err := transport.DecodeDirectChannelMessageV2(wire)
	if err != nil || w.Header.Kind != "ASK" {
		return ErrInvalid
	}
	return nil
}
