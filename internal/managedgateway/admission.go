// Package managedgateway defines dormant owner-local gateway descriptors.
package managedgateway

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"
)

// Source identifies the local origin of an admission descriptor.
type Source string

const SourceGateway Source = "gateway"

// GatewayAdmission describes one bounded gateway operation. It is comparable
// and contains no executable capability or runtime activation behavior.
type GatewayAdmission struct {
	Source                      Source    `json:"source"`
	OperationID                 string    `json:"operation_id"`
	OwnerID                     string    `json:"owner_id"`
	TenantID                    string    `json:"tenant_id"`
	HostID                      string    `json:"host_id"`
	InstallationID              string    `json:"installation_id"`
	InstallationGeneration      string    `json:"installation_generation"`
	ExecutableGrantID           string    `json:"executable_grant_id"`
	ExecutableGrantVersion      string    `json:"executable_grant_version"`
	V2ProjectID                 string    `json:"v2_project_id"`
	PolicyHash                  string    `json:"policy_hash"`
	ServiceID                   string    `json:"service_id"`
	SenderID                    string    `json:"sender_id"`
	ASKID                       string    `json:"ask_id"`
	ASKWireDigest               string    `json:"ask_wire_digest"`
	InputDigest                 string    `json:"input_digest"`
	TargetDefinitionID          string    `json:"target_definition_id"`
	TargetDefinitionRevision    string    `json:"target_definition_revision"`
	TargetDefinitionFingerprint string    `json:"target_definition_fingerprint"`
	WorkerInstanceID            string    `json:"worker_instance_id"`
	WorkerIncarnation           string    `json:"worker_incarnation"`
	ConfigurationFingerprint    string    `json:"configuration_fingerprint"`
	IsolationFingerprint        string    `json:"isolation_fingerprint"`
	Deadline                    time.Time `json:"deadline"`
	MaxInputBytes               int64     `json:"max_input_bytes"`
	MaxResultBytes              int64     `json:"max_result_bytes"`
	MaxConcurrency              int       `json:"max_concurrency"`
}

// Validate checks descriptor structure only; it does not evaluate expiry.
func (a GatewayAdmission) Validate() error {
	if a.Source != SourceGateway {
		return fmt.Errorf("invalid gateway admission source")
	}
	identities := []struct{ name, value string }{
		{"operation_id", a.OperationID}, {"owner_id", a.OwnerID},
		{"tenant_id", a.TenantID}, {"host_id", a.HostID},
		{"installation_id", a.InstallationID}, {"installation_generation", a.InstallationGeneration},
		{"executable_grant_id", a.ExecutableGrantID}, {"executable_grant_version", a.ExecutableGrantVersion},
		{"v2_project_id", a.V2ProjectID}, {"service_id", a.ServiceID},
		{"sender_id", a.SenderID}, {"ask_id", a.ASKID},
		{"target_definition_id", a.TargetDefinitionID}, {"target_definition_revision", a.TargetDefinitionRevision},
		{"worker_instance_id", a.WorkerInstanceID}, {"worker_incarnation", a.WorkerIncarnation},
	}
	for _, identity := range identities {
		if len(identity.value) == 0 || len(identity.value) > 256 || !utf8.ValidString(identity.value) {
			return fmt.Errorf("invalid gateway admission %s", identity.name)
		}
	}
	digests := []struct{ name, value string }{
		{"policy_hash", a.PolicyHash}, {"ask_wire_digest", a.ASKWireDigest},
		{"input_digest", a.InputDigest}, {"target_definition_fingerprint", a.TargetDefinitionFingerprint},
		{"configuration_fingerprint", a.ConfigurationFingerprint}, {"isolation_fingerprint", a.IsolationFingerprint},
	}
	for _, digest := range digests {
		if !isSHA256(digest.value) {
			return fmt.Errorf("invalid gateway admission %s", digest.name)
		}
	}
	if a.Deadline.IsZero() || a.Deadline.Location() != time.UTC {
		return fmt.Errorf("gateway admission deadline must be nonzero UTC")
	}
	if a.MaxInputBytes <= 0 || a.MaxInputBytes > 1<<20 || a.MaxResultBytes <= 0 || a.MaxResultBytes > 1<<20 {
		return fmt.Errorf("gateway admission byte limits must be positive and at most 1 MiB")
	}
	if a.MaxConcurrency != 1 {
		return fmt.Errorf("gateway admission concurrency must be one")
	}
	return nil
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Digest hashes the canonical JSON field order of a validated descriptor.
func (a GatewayAdmission) Digest() ([32]byte, error) {
	if err := a.Validate(); err != nil {
		return [32]byte{}, err
	}
	data, err := json.Marshal(a)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// ReceiptState is a terminal operation outcome descriptor.
type ReceiptState string

const (
	ReceiptCompleted ReceiptState = "completed"
	ReceiptFailed    ReceiptState = "failed"
	ReceiptUnknown   ReceiptState = "unknown"
)

// GatewayReceipt is receipt data only. Authentication is an opaque descriptor
// field; this type neither authenticates receipts nor implements signing.
type GatewayReceipt struct {
	AdmissionDigest   [32]byte     `json:"admission_digest"`
	OperationID       string       `json:"operation_id"`
	ASKID             string       `json:"ask_id"`
	WorkerInstanceID  string       `json:"worker_instance_id"`
	WorkerIncarnation string       `json:"worker_incarnation"`
	InputDigest       string       `json:"input_digest"`
	State             ReceiptState `json:"state"`
	ResultDigest      string       `json:"result_digest"`
	ResultBytes       int64        `json:"result_bytes"`
	CompletedAt       time.Time    `json:"completed_at"`
	Authentication    [32]byte     `json:"authentication"`
}
