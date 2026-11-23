package transport

import (
	"encoding/json"
	"errors"
	"time"

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
	if len(raw) > 16*1024 {
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
