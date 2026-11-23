package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/domain"
)

const ManagedEndpointBindingProtocol = "managed_native_endpoint_binding_v1"

var errManagedEndpointBinding = errors.New("transport: invalid closed managed endpoint binding")

// ManagedEndpointBindingIntent mirrors the immutable server enrollment subject.
// It conveys no authentication, endpoint key, or channel authority. The trusted
// control-plane origin is supplied separately by the local daemon.
type ManagedEndpointBindingIntent struct {
	ID                      domain.ID `json:"id"`
	DirectIntentID          domain.ID `json:"directIntentId"`
	ProtocolVersion         string    `json:"protocolVersion"`
	TenantID                domain.ID `json:"tenantId"`
	AccountID               domain.ID `json:"accountId"`
	OwnershipScope          string    `json:"ownershipScope"`
	PrincipalID             domain.ID `json:"principalId"`
	EndpointID              domain.ID `json:"endpointId"`
	InstanceID              domain.ID `json:"instanceId"`
	OriginID                domain.ID `json:"originId"`
	NativeGeneration        string    `json:"nativeGeneration"`
	NativeSessionID         string    `json:"nativeSessionId"`
	OwnershipID             domain.ID `json:"ownershipId"`
	OwnershipGeneration     string    `json:"ownershipGeneration"`
	NativeAdmissionID       domain.ID `json:"nativeAdmissionId"`
	ConnectionIncarnationID domain.ID `json:"connectionIncarnationId"`
	HostID                  domain.ID `json:"hostId"`
	HostCredentialID        domain.ID `json:"hostCredentialId"`
	RunnerID                domain.ID `json:"runnerId"`
	RunnerConnectedAt       time.Time `json:"runnerConnectedAt"`
	BootID                  string    `json:"bootId"`
	BindingGeneration       int64     `json:"bindingGeneration"`
	State                   string    `json:"state"`
	CreatedAt               time.Time `json:"createdAt"`
	ExpiresAt               time.Time `json:"expiresAt"`
}

func (p ManagedEndpointBindingIntent) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != ManagedEndpointBindingProtocol || p.OwnershipScope != "personal" || p.BindingGeneration != 1 || p.State != "pending_closed" || p.ConnectionIncarnationID != p.NativeAdmissionID {
		return nil, errManagedEndpointBinding
	}
	for _, id := range []domain.ID{p.ID, p.DirectIntentID, p.TenantID, p.AccountID, p.PrincipalID, p.EndpointID, p.InstanceID, p.OriginID, p.OwnershipID, p.NativeAdmissionID, p.ConnectionIncarnationID, p.HostID, p.HostCredentialID, p.RunnerID} {
		if !nativeShareBindingID(id) {
			return nil, errManagedEndpointBinding
		}
	}
	for _, value := range []string{p.NativeGeneration, p.NativeSessionID, p.OwnershipGeneration, p.BootID} {
		if !nativeShareOpaque(value) {
			return nil, errManagedEndpointBinding
		}
	}
	for _, value := range []time.Time{p.RunnerConnectedAt, p.CreatedAt, p.ExpiresAt} {
		if value.IsZero() || value.Year() < 1 || value.Year() > 9999 {
			return nil, errManagedEndpointBinding
		}
	}
	if !p.ExpiresAt.After(p.CreatedAt) || p.ExpiresAt.Sub(p.CreatedAt) > 5*time.Minute {
		return nil, errManagedEndpointBinding
	}
	p.RunnerConnectedAt = p.RunnerConnectedAt.UTC()
	p.CreatedAt = p.CreatedAt.UTC()
	p.ExpiresAt = p.ExpiresAt.UTC()
	return json.Marshal(p)
}

func DecodeManagedEndpointBindingIntent(raw []byte) (ManagedEndpointBindingIntent, error) {
	var p ManagedEndpointBindingIntent
	if len(raw) > 16*1024 || !utf8.Valid(raw) {
		return p, errManagedEndpointBinding
	}
	if _, err := nativeShareSourceObject(raw, "id", "directIntentId", "protocolVersion", "tenantId", "accountId", "ownershipScope", "principalId", "endpointId", "instanceId", "originId", "nativeGeneration", "nativeSessionId", "ownershipId", "ownershipGeneration", "nativeAdmissionId", "connectionIncarnationId", "hostId", "hostCredentialId", "runnerId", "runnerConnectedAt", "bootId", "bindingGeneration", "state", "createdAt", "expiresAt"); err != nil {
		return p, errManagedEndpointBinding
	}
	if json.Unmarshal(raw, &p) != nil {
		return p, errManagedEndpointBinding
	}
	_, err := p.CanonicalBytes()
	return p, err
}

// ManagedEndpointKeyReservation is public closed evidence only. EnrollmentDigest
// binds the complete server subject, configured origin, installation and key.
type ManagedEndpointKeyReservation struct {
	Subject          ManagedEndpointBindingIntent `json:"subject"`
	ServerURL        string                       `json:"serverUrl"`
	InstallationID   domain.ID                    `json:"installationId"`
	KeyGeneration    uint64                       `json:"keyGeneration"`
	X25519           string                       `json:"x25519"`
	EnrollmentDigest string                       `json:"enrollmentDigest"`
}

// Digest binds the canonical complete subject, origin, installation and public
// key. EnrollmentDigest itself is excluded. This is evidence, not authority.
func (p ManagedEndpointKeyReservation) Digest() (string, error) {
	subject, err := p.Subject.CanonicalBytes()
	if err != nil || json.Unmarshal(subject, &p.Subject) != nil || p.KeyGeneration != 1 || !nativeShareBindingID(p.InstallationID) || !nativeShareBindingHex(p.X25519) || !managedEndpointServerURL(p.ServerURL) {
		return "", errManagedEndpointBinding
	}
	p.EnrollmentDigest = ""
	raw, err := json.Marshal(p)
	if err != nil {
		return "", errManagedEndpointBinding
	}
	sum := sha256.Sum256(append([]byte("pagnet/closed-managed-endpoint-key/v1/"), raw...))
	return hex.EncodeToString(sum[:]), nil
}

func managedEndpointServerURL(value string) bool {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String() == value
}

// CanonicalBytes validates the reservation digest and emits UTC subject times.
func (p ManagedEndpointKeyReservation) CanonicalBytes() ([]byte, error) {
	digest, err := p.Digest()
	if err != nil || !nativeShareBindingHex(p.EnrollmentDigest) || p.EnrollmentDigest != digest {
		return nil, errManagedEndpointBinding
	}
	subject, _ := p.Subject.CanonicalBytes()
	if json.Unmarshal(subject, &p.Subject) != nil {
		return nil, errManagedEndpointBinding
	}
	return json.Marshal(p)
}

func DecodeManagedEndpointKeyReservation(raw []byte) (ManagedEndpointKeyReservation, error) {
	var p ManagedEndpointKeyReservation
	if len(raw) > 20*1024 || !utf8.Valid(raw) {
		return p, errManagedEndpointBinding
	}
	fields, err := nativeShareSourceObject(raw, "subject", "serverUrl", "installationId", "keyGeneration", "x25519", "enrollmentDigest")
	if err != nil {
		return p, errManagedEndpointBinding
	}
	subject, err := DecodeManagedEndpointBindingIntent(fields["subject"])
	if err != nil || json.Unmarshal(raw, &p) != nil {
		return ManagedEndpointKeyReservation{}, errManagedEndpointBinding
	}
	p.Subject = subject
	if _, err := p.CanonicalBytes(); err != nil {
		return ManagedEndpointKeyReservation{}, errManagedEndpointBinding
	}
	return p, nil
}

// VerifySubject compares every immutable field, using canonical UTC instants.
func (p ManagedEndpointKeyReservation) VerifySubject(expected ManagedEndpointBindingIntent) error {
	if _, err := p.CanonicalBytes(); err != nil {
		return errManagedEndpointBinding
	}
	actual, err := p.Subject.CanonicalBytes()
	retained, retainedErr := expected.CanonicalBytes()
	if err != nil || retainedErr != nil || !bytes.Equal(actual, retained) {
		return errManagedEndpointBinding
	}
	return nil
}
